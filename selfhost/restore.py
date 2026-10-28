"""Put a backup snapshot back as the live database.

    docker compose -f selfhost/compose.yaml stop
    docker compose -f selfhost/compose.yaml run --rm --no-deps worker \\
        /srv/controlplane/.venv/bin/python selfhost/restore.py whichports-20261001T031700Z.db.gz
    docker compose -f selfhost/compose.yaml up -d

These are the steps `ops/RUNBOOK.md` "Restoring the database" takes by hand on
our own box, in one command: unpack the snapshot beside the database, open it
and check it with the same check the nightly backup runs (`app/backup.py`),
set the current database aside under a name that says so, and only then put
the snapshot in its place. A snapshot that fails the check changes nothing.

**Stop the stack first.** The ingest and the worker hold the database open,
and this command cannot see whether they are running, because nothing in this
stack is given the Docker socket. `docker compose run --no-deps` starts this
in a container of its own and leaves the stopped ones stopped.

A bare file name is looked up in the backups volume. A snapshot kept
somewhere else is given on standard input, with `-` as its name:

    docker compose -f selfhost/compose.yaml run --rm --no-deps -T worker \\
        /srv/controlplane/.venv/bin/python selfhost/restore.py - < whichports-X.db.gz

It is not copied into the volume first, because `docker compose cp` leaves
the file owned by root with the snapshot's own 0600 mode, and the container's
unprivileged user cannot read that (measured 2026-10-01).

The database set aside keeps its WAL and shared memory files beside it under
the same new name, so it opens exactly as it was if the restore was a mistake.
"""
import argparse
import gzip
import os
import shutil
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DATABASE = Path("/var/lib/whichports-controlplane/whichports.db")
DEFAULT_BACKUPS = Path("/var/backups/whichports")
STAMP = "%Y%m%dT%H%M%SZ"


def _backup_module():
    """`app.backup` from the control plane beside this file: /srv/controlplane
    in the image, controlplane/ in a checkout. Its `verify` is the check the
    nightly snapshot already passed, so a restore asks the same question."""
    here = Path(__file__).resolve().parent.parent
    for root in (here, here / "controlplane"):
        if (root / "app" / "backup.py").is_file():
            if str(root) not in sys.path:
                sys.path.insert(0, str(root))
            from app import backup
            return backup
    raise RuntimeError(f"no control plane beside {here}")


class RestoreRefused(Exception):
    """Nothing was changed, for the reason given."""


STDIN = "-"


def resolve(snapshot: str, backups: Path) -> Path | None:
    """A bare name is a file in the backups directory, anything with a slash
    is a path, and `-` is standard input, which resolves to None."""
    if snapshot == STDIN:
        return None
    path = Path(snapshot) if "/" in snapshot else backups / snapshot
    if not path.is_file():
        raise RestoreRefused(f"no snapshot at {path}")
    if not path.name.endswith(".db.gz"):
        raise RestoreRefused(f"{path.name} is not a snapshot the backup wrote"
                             " (whichports-<time>.db.gz)")
    return path


def restore(snapshot, database: Path, now: datetime | None = None,
            name: str = "") -> dict:
    """`snapshot` is a path, or an open binary file for standard input."""
    backup = _backup_module()
    name = name or getattr(snapshot, "name", "the snapshot")
    stamp = (now or datetime.now(timezone.utc)).strftime(STAMP)
    work = database.parent / f".restore-{stamp}.db"
    try:
        with gzip.open(snapshot, "rb") as packed, open(work, "wb") as out:
            shutil.copyfileobj(packed, out)
        counts = backup.verify(work)
    # OSError covers a file that is not gzip, EOFError one cut short, and
    # sqlite3.Error one that unpacks into something that is not a database.
    except (OSError, EOFError, sqlite3.Error, backup.BackupFailed) as exc:
        backup.clear_work(work)
        raise RestoreRefused(f"{name} did not pass the check, so"
                             f" nothing was changed: {exc}") from None
    aside = database.with_name(f"{database.name}.before-restore-{stamp}")
    moved = []
    for suffix in ("", "-wal", "-shm"):
        current = Path(str(database) + suffix)
        if current.exists():
            os.replace(current, Path(str(aside) + suffix))
            moved.append(current.name)
    # The check opened the copy read-only, which in WAL mode leaves an empty
    # -wal and a -shm beside it. Every page is in the main file, which is what
    # the backup compressed, so they go before the copy takes its new name.
    for suffix in ("-wal", "-shm"):
        Path(str(work) + suffix).unlink(missing_ok=True)
    os.chmod(work, 0o644)
    os.replace(work, database)
    return {"hosts": counts["hosts"], "reports": counts["reports"],
            "aside": aside if moved else None}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("snapshot", help="a file name in the backups"
                        " directory, a path, or - for standard input")
    parser.add_argument("--database", type=Path, default=Path(
        os.environ.get("WHICHPORTS_DB") or DEFAULT_DATABASE))
    parser.add_argument("--backups", type=Path, default=DEFAULT_BACKUPS)
    args = parser.parse_args(argv)
    try:
        snapshot = resolve(args.snapshot, args.backups)
        if snapshot is None:
            name = "the snapshot on standard input"
            result = restore(sys.stdin.buffer, args.database, name=name)
        else:
            name = snapshot.name
            result = restore(snapshot, args.database, name=name)
    except RestoreRefused as exc:
        print(f"restore refused: {exc}", file=sys.stderr)
        return 1
    print(f"restored {name}: {result['hosts']} hosts,"
          f" {result['reports']} documents")
    if result["aside"]:
        print(f"the database it replaced is at {result['aside']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
