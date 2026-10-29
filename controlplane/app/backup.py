"""Nightly backups of the control plane's database.

    python -m app.backup --db /var/lib/whichports-controlplane/whichports.db \
                         --dest /var/backups/whichports --keep 14

Why this exists at all: the database holds every host document the fleet has
ever sent, which is the one thing here that cannot be rebuilt from the
repository. The lesson of an earlier project of the author's was that a
backup nobody has verified is a story rather than a backup (RECORD 4.10), so
this does three things rather
than one: it takes a consistent copy, it opens that copy and checks it, and
it says out loud how many hosts and documents it found. A snapshot that fails
its own check is deleted and the run fails, because a corrupt file sitting in
the backup directory is worse than no file, it reads as protection.

The copy is taken with SQLite's online backup API, not by copying the file.
The database runs in WAL mode with two processes on it, so a plain file copy
can catch a torn page or miss committed data still in the WAL.

**A snapshot leaves out the prober API's queued batches and its hour's
count** (docs/RECORD.md 4.444). A batch is kept fifteen minutes at most and a
snapshot fourteen nights, so a batch in flight when the copy is taken would
outlive its limit by two weeks. Both tables are emptied in the copy, before
the copy is checked and zipped (`leave_batches_out`). The database the box
runs on is opened read only here and nothing in it is touched. The abuse log
stays in: after a restore it is what answers which instance's batch could
reach an address.

**Who may read a snapshot.** The account that makes it, and nobody else:
the folder is 0700 and each file 0600. That is so on every instance. One
setting changes it, `WHICHPORTS_SNAPSHOT_GROUP`: where it names a group, the
folder becomes 0750 and each snapshot 0640 with that group, so that one more
account may read them and nothing else. Our own box sets it for the account
that copies the snapshots to two other machines (docs/RECORD.md 4.449). The
copy the snapshot is made from is the whole database unzipped, and it is
this account's alone whatever the setting says. A group that cannot be given
fails the run after the snapshot is made and kept, private: a night's
snapshot is worth more than who else can read it.

Written as Python and not shell so the logic that decides "this backup is
good" is testable, and it is, in controlplane/tests/test_backup.py.
"""

import argparse
import grp
import gzip
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# The snapshot name carries the moment it was taken, in UTC, sortable.
STAMP = "%Y%m%dT%H%M%SZ"

# The setting that names a group which may read the snapshots. Not set, or
# empty, on every instance but our own box: see the docstring.
GROUP_ENV = "WHICHPORTS_SNAPSHOT_GROUP"


# The tables whose rows never ride into a snapshot: the prober API's queued
# batches, the hour's charges and the hour's proof counts, and since
# 2026-10-26 the open signup's waiting codes and its claims, each an address
# and a hash for a day at most, and eight digits under SHA-256 are worked
# out from a copy in seconds (app/instancesignup.py). The prober API's log,
# `prober_api_log`, does ride. Written here by name and not imported, so this file needs
# nothing but the standard library, and a test holds the names to the
# schemas.
LEFT_OUT_OF_A_SNAPSHOT = ("prober_api_batches", "prober_api_charges", "prober_api_proof_uses", "instance_signups", "instance_signup_claims")


class BackupFailed(Exception):
    """The snapshot could not be taken or did not survive its own check."""


def clear_work(work_path: Path) -> None:
    """Remove the temp snapshot and its journal sidecars. The destination
    inherits WAL from the source, so a -wal and a -shm appear beside it, and
    a live run showed they can outlive the connection. Left behind they are
    clutter in a directory whose whole job is to be trustworthy."""
    for suffix in ("", "-wal", "-shm"):
        Path(str(work_path) + suffix).unlink(missing_ok=True)


def snapshot(db_path: Path, work_path: Path) -> None:
    """A consistent copy, taken through SQLite rather than the filesystem."""
    source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        dest = sqlite3.connect(work_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()


def leave_batches_out(work_path: Path) -> None:
    """Delete every queued batch and the hour's count from the copy, bytes
    and all. Only ever given the copy: the live database is never opened for
    writing in this file.

    Three things here do not show. The first two were measured on 2026-10-09
    by leaving each out, and docs/RECORD.md 4.444 has the first measurement
    of the overwrite:

      - `secure_delete = ON` makes SQLite write zeros over what the delete
        frees. Without it both tables had 0 rows and every batch's bytes were
        still in the file that gets zipped.
      - The copy is in WAL mode like the database it came from, so the
        deletes land in a -wal file beside it, and the zip takes the main
        file alone: after the commit the main file still held every batch.
        The checkpoint writes the deletes into it. Closing the connection
        did the same, but a close says nothing when it cannot, so the
        checkpoint is asked and a 1 in its answer fails the run.
      - A database that never served the prober API has neither table. That
        is nothing to take out, and no failure.

    What this does not do: a batch deleted earlier, on a connection that did
    not overwrite, can still be in pages the live file has free, and free
    pages are copied as they are. `db.forget_what_is_deleted` is what keeps
    the live file clean, on every connection that writes to it.
    """
    try:
        con = sqlite3.connect(work_path)
        try:
            con.execute("PRAGMA secure_delete = ON")
            present = {row[0] for row in con.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'")}
            for table in LEFT_OUT_OF_A_SNAPSHOT:
                if table in present:
                    con.execute(f"DELETE FROM {table}")
            con.commit()
            # The first number is 1 when the checkpoint could not finish.
            unfinished = con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
        finally:
            con.close()
    except sqlite3.Error as exc:
        raise BackupFailed(f"cannot take the batches out of the copy: {exc}") from exc
    if unfinished:
        raise BackupFailed("cannot take the batches out of the copy: its -wal"
                           " could not be written back into it")


def verify(path: Path) -> dict:
    """Open the snapshot and prove it is a database, not a file of the right
    size. Returns what it counted so the run can say it out loud."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        result = con.execute("PRAGMA integrity_check").fetchone()[0]
        if result != "ok":
            raise BackupFailed(f"integrity check said {result!r}")
        counts = {}
        for table in ("hosts", "reports"):
            try:
                counts[table] = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            except sqlite3.Error as exc:
                raise BackupFailed(f"cannot read {table}: {exc}") from exc
    finally:
        con.close()
    return counts


def compress(src: Path, dest: Path) -> None:
    with open(src, "rb") as raw, gzip.open(dest, "wb") as gz:
        shutil.copyfileobj(raw, gz)


def prune(dest_dir: Path, keep: int) -> list[Path]:
    """Keep the newest `keep` snapshots. Names sort chronologically because
    the stamp is zero-padded UTC, so sorting by name is sorting by age."""
    existing = sorted(dest_dir.glob("whichports-*.db.gz"))
    removed = []
    for old in existing[:-keep] if keep > 0 else []:
        old.unlink()
        removed.append(old)
    return removed


def give_to_the_group(dest_dir: Path, final: Path, name: str) -> None:
    """Let the named group read the folder and this snapshot, and nothing
    more: 0750 and 0640. The account that runs this has to be in the group,
    or the system refuses, which is said as a failed backup."""
    try:
        gid = grp.getgrnam(name).gr_gid
        for path, mode in ((final, 0o640), (dest_dir, 0o750)):
            os.chown(path, -1, gid)
            path.chmod(mode)
    except (KeyError, OSError) as exc:
        raise BackupFailed(
            f"the snapshot {final.name} is made and kept, readable by this account"
            f" alone: it could not be given to the group {name!r} ({exc})") from exc


def run(db_path: Path, dest_dir: Path, keep: int, now: datetime | None = None,
        environ=None) -> dict:
    now = now or datetime.now(timezone.utc)
    if not db_path.exists():
        raise BackupFailed(f"no database at {db_path}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    # 0700: the snapshot carries every host document, so it is no more
    # readable than the database it came from.
    dest_dir.chmod(0o700)

    stamp = now.strftime(STAMP)
    work = dest_dir / f".whichports-{stamp}.db"
    final = dest_dir / f"whichports-{stamp}.db.gz"
    # Every file made from here on is this account's alone, the work copy
    # above all: it is the whole database, unzipped, for as long as this runs.
    mask_before = os.umask(0o077)
    try:
        snapshot(db_path, work)
        leave_batches_out(work)
        counts = verify(work)
        compress(work, final)
    except Exception:
        # A snapshot that failed its own check must not survive: a bad file
        # in the backup directory reads as protection that is not there.
        clear_work(work)
        final.unlink(missing_ok=True)
        raise
    finally:
        clear_work(work)
        os.umask(mask_before)
    final.chmod(0o600)

    removed = prune(dest_dir, keep)
    # Last, so that a group that cannot be given costs no snapshot and no
    # pruning: the snapshot is there, private, and then the run says so.
    group = (os.environ if environ is None else environ).get(GROUP_ENV, "").strip()
    if group:
        give_to_the_group(dest_dir, final, group)
    return {
        "path": final,
        "bytes": final.stat().st_size,
        "hosts": counts["hosts"],
        "reports": counts["reports"],
        "pruned": len(removed),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", required=True, type=Path)
    parser.add_argument("--dest", required=True, type=Path)
    parser.add_argument("--keep", type=int, default=14,
                        help="snapshots to keep, 0 keeps everything")
    args = parser.parse_args(argv)
    try:
        result = run(args.db, args.dest, args.keep)
    except BackupFailed as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(f"{result['path'].name} {result['bytes']} bytes, "
          f"{result['hosts']} hosts, {result['reports']} documents, "
          f"{result['pruned']} pruned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
