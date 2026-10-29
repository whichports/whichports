"""The backup: it must be consistent, checked, and honest when it fails."""

import gzip
import json
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app import authz, backup, db, instances, instancesignup, proberapi, store, vantages

NOW = datetime(2026, 8, 14, 3, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def live_db(tmp_path, monkeypatch):
    """A database with real shape: two hosts, three documents, WAL on."""
    path = tmp_path / "live.db"
    monkeypatch.setenv(db.DB_ENV, str(path))
    con = db.connect()
    db.init(con)
    for name in ("alpha", "beta"):
        host_id, _ = store.add_host(con, name)
        for i in range(2 if name == "alpha" else 1):
            store.insert_report(con, host_id, collected_at_unix=i, schema_version=1,
                                document=json.dumps({"schema_version": 1,
                                                     "hostname": name,
                                                     "collected_at_unix": i}))
    con.close()
    return path


def test_backup_is_verified_and_counts_are_reported(live_db, tmp_path):
    dest = tmp_path / "backups"
    result = backup.run(live_db, dest, keep=14, now=NOW)
    assert result["path"].name == "whichports-20260814T030000Z.db.gz"
    assert result["hosts"] == 2
    assert result["reports"] == 3
    assert result["bytes"] > 0


def test_the_snapshot_restores_to_a_working_database(live_db, tmp_path):
    dest = tmp_path / "backups"
    result = backup.run(live_db, dest, keep=14, now=NOW)
    restored = tmp_path / "restored.db"
    with gzip.open(result["path"], "rb") as gz:
        restored.write_bytes(gz.read())
    con = sqlite3.connect(restored)
    names = [r[0] for r in con.execute("SELECT name FROM hosts ORDER BY name")]
    docs = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    con.close()
    assert names == ["alpha", "beta"]
    assert docs == 3


def test_backup_catches_data_still_in_the_wal(tmp_path, monkeypatch):
    """A plain file copy can miss commits that are in the WAL and not yet in
    the main file. The online backup API must not."""
    path = tmp_path / "wal.db"
    monkeypatch.setenv(db.DB_ENV, str(path))
    con = db.connect()
    db.init(con)
    store.add_host(con, "written-and-left-in-wal")
    # deliberately not closed: the WAL still holds the commit
    dest = tmp_path / "backups"
    result = backup.run(path, dest, keep=14, now=NOW)
    assert result["hosts"] == 1
    con.close()


def test_a_corrupt_snapshot_is_deleted_and_the_run_fails(live_db, tmp_path, monkeypatch):
    dest = tmp_path / "backups"

    def broken_verify(_path):
        raise backup.BackupFailed("integrity check said 'malformed'")

    monkeypatch.setattr(backup, "verify", broken_verify)
    with pytest.raises(backup.BackupFailed):
        backup.run(live_db, dest, keep=14, now=NOW)
    # nothing may be left behind that could read as a good backup
    assert list(dest.glob("*")) == []


def test_missing_database_fails_loudly(tmp_path):
    with pytest.raises(backup.BackupFailed):
        backup.run(tmp_path / "absent.db", tmp_path / "backups", keep=14, now=NOW)


def test_retention_keeps_the_newest(live_db, tmp_path):
    dest = tmp_path / "backups"
    for day in range(6):
        backup.run(live_db, dest, keep=3, now=NOW + timedelta(days=day))
    kept = sorted(p.name for p in dest.glob("whichports-*.db.gz"))
    assert len(kept) == 3
    assert kept[0] == "whichports-20260817T030000Z.db.gz"   # the three newest
    assert kept[-1] == "whichports-20260819T030000Z.db.gz"


def test_keep_zero_keeps_everything(live_db, tmp_path):
    dest = tmp_path / "backups"
    for day in range(3):
        backup.run(live_db, dest, keep=0, now=NOW + timedelta(days=day))
    assert len(list(dest.glob("whichports-*.db.gz"))) == 3


def test_snapshots_are_not_world_readable(live_db, tmp_path):
    """The snapshot carries every host document, so it is no more readable
    than the database it came from."""
    dest = tmp_path / "backups"
    result = backup.run(live_db, dest, keep=14, now=NOW)
    assert result["path"].stat().st_mode & 0o077 == 0
    assert dest.stat().st_mode & 0o077 == 0


def a_group_of_mine() -> str:
    """A group this account is in, so the system lets it give a file to it.
    Not the account's own first group where there is another."""
    import grp
    import os
    mine = os.getgroups() or [os.getgid()]
    others = [gid for gid in mine if gid != os.getgid()]
    return grp.getgrgid((others or mine)[0]).gr_name


def test_with_a_group_named_it_may_read_the_folder_and_the_snapshot_and_no_more(
        live_db, tmp_path):
    """Our own box names the group of the account that copies the snapshots
    off it (docs/record 4.449). Read and list for that group, nothing for
    anybody else, and no write for the group."""
    import grp
    name = a_group_of_mine()
    dest = tmp_path / "backups"
    result = backup.run(live_db, dest, keep=14, now=NOW, environ={backup.GROUP_ENV: name})
    for path, mode in ((result["path"], 0o640), (dest, 0o750)):
        assert path.stat().st_mode & 0o777 == mode
        assert path.stat().st_gid == grp.getgrnam(name).gr_gid


def test_a_setting_that_is_empty_is_no_setting(live_db, tmp_path):
    dest = tmp_path / "backups"
    result = backup.run(live_db, dest, keep=14, now=NOW, environ={backup.GROUP_ENV: "  "})
    assert result["path"].stat().st_mode & 0o777 == 0o600
    assert dest.stat().st_mode & 0o777 == 0o700


def test_the_copy_a_snapshot_is_made_from_is_never_the_groups_to_read(
        live_db, tmp_path, monkeypatch):
    """It is the whole database, unzipped, and it lies in the folder the
    group may list for as long as the backup runs. Looked at in the moment
    it is zipped, with a mask that would let it be read by everybody."""
    import os
    seen = {}
    real_compress = backup.compress

    def looking(work, final):
        seen["work"] = work.stat().st_mode & 0o777
        real_compress(work, final)
        seen["zipped, before it is given"] = final.stat().st_mode & 0o777

    monkeypatch.setattr(backup, "compress", looking)
    before = os.umask(0o000)
    try:
        backup.run(live_db, tmp_path / "backups", keep=14, now=NOW,
                   environ={backup.GROUP_ENV: a_group_of_mine()})
        assert os.umask(0o000) == 0o000, "the run did not give the mask back"
    finally:
        os.umask(before)
    assert seen == {"work": 0o600, "zipped, before it is given": 0o600}


def test_a_group_that_cannot_be_given_fails_the_run_and_costs_no_snapshot(live_db, tmp_path):
    """A name no group has, or a group this account is not in. The snapshot
    is made first and kept, readable by this account alone, older ones are
    pruned as on any night, and then the run fails and says which."""
    dest = tmp_path / "backups"
    for day in range(3):
        backup.run(live_db, dest, keep=2, now=NOW - timedelta(days=3 - day))
    with pytest.raises(backup.BackupFailed, match="is made and kept"):
        backup.run(live_db, dest, keep=2, now=NOW,
                   environ={backup.GROUP_ENV: "no-group-has-this-name"})
    made = dest / "whichports-20260814T030000Z.db.gz"
    assert made.stat().st_mode & 0o777 == 0o600 and dest.stat().st_mode & 0o777 == 0o700
    assert gzip.open(made).read(16) == b"SQLite format 3\x00"
    assert len(list(dest.glob("whichports-*.db.gz"))) == 2


def test_the_cli_says_a_group_that_cannot_be_given_and_ends_one(
        live_db, tmp_path, capsys, monkeypatch):
    monkeypatch.setenv(backup.GROUP_ENV, "no-group-has-this-name")
    code = backup.main(["--db", str(live_db), "--dest", str(tmp_path / "backups")])
    said = capsys.readouterr().err
    assert code == 1 and "backup failed:" in said and "no-group-has-this-name" in said


def test_cli_reports_and_exits_zero(live_db, tmp_path, capsys):
    code = backup.main(["--db", str(live_db), "--dest", str(tmp_path / "b"), "--keep", "5"])
    out = capsys.readouterr().out
    assert code == 0
    assert "2 hosts" in out and "3 documents" in out


def test_cli_exits_nonzero_when_there_is_nothing_to_back_up(tmp_path, capsys):
    code = backup.main(["--db", str(tmp_path / "absent.db"), "--dest", str(tmp_path / "b")])
    assert code == 1
    assert "backup failed" in capsys.readouterr().err


def test_no_temporary_files_survive_a_good_run(live_db, tmp_path):
    """A live run left the work file's -wal and -shm sidecars behind. The
    backup directory must contain snapshots and nothing else."""
    dest = tmp_path / "backups"
    backup.run(live_db, dest, keep=14, now=NOW)
    leftovers = [p.name for p in dest.iterdir()
                 if not p.name.startswith("whichports-")]
    assert leftovers == [], f"left behind: {leftovers}"


# ------------------------------------------- what a snapshot leaves out
#
# A queued probe batch is kept fifteen minutes at most and the hour's count an
# hour, and a snapshot is kept fourteen nights. So the copy has both tables
# emptied before it is checked and zipped, on a connection that writes zeros
# over what it deletes, and the live database is only ever read
# (docs/RECORD.md 4.444). The abuse log stays in: after a restore it is what
# answers which instance's batch could reach an address.
#
# Counted as rows and as bytes. A stored batch is JSON with the key
# "tls_ports" (`proberapi.BatchRequest.to_json`), and the answer below is the
# only thing in the database with the key "measured_from".

V4 = "185.199.108.153"
OTHER_V4 = "185.199.108.154"
BATCH_BYTES = b'"tls_ports"'
ANSWER_BYTES = b'"measured_from"'
REQUEST = proberapi.BatchRequest(vantage="probe1", addresses=(V4,), ports=(22, 443),
                                 tls_ports=(443,), allowed=(V4,))
# Some 20 KB, so SQLite keeps it on pages of its own beside the row.
LONG_ANSWER = json.dumps({"measured_from": "probe1", "results": [
    {"address": V4, "port": port, "state": "open"} for port in range(1, 400)]})


def serve_the_prober_api(path: Path):
    """Make the database at `path` the one of a box that serves the prober
    API, as it stands when the backup runs. Returns the connection, open.

      - one batch long gone: queued twenty minutes ago and swept since
      - one in flight and still queued, for the instance "one"
      - one answered at length and not collected yet, for the instance "two"
      - the hour's count for all three
      - the abuse log: three rows, two addresses, two days
    """
    con = db.connect(str(path))
    for module in (db, authz, vantages, instances, proberapi):
        module.init(con)
    one = instances.add(con, "one", now=NOW, origin=authz.ORIGIN_INVITED).instance
    two = instances.add(con, "two", now=NOW, origin=authz.ORIGIN_INVITED).instance
    proberapi.submit(con, one.id, REQUEST, NOW - timedelta(minutes=20))
    # A submit sweeps first, so this one takes the batch above with it.
    proberapi.submit(con, one.id, REQUEST, NOW - timedelta(minutes=2))
    answered = proberapi.submit(con, two.id, REQUEST, NOW - timedelta(minutes=1))
    row = con.execute("SELECT * FROM prober_api_batches WHERE id = ?",
                      (answered,)).fetchone()
    proberapi.mark_started(con, answered, NOW - timedelta(minutes=1))
    proberapi.record_answer(con, row, LONG_ANSWER, NOW)
    proberapi.log_sent(con, one.id, "probe1", [V4], 3, NOW - timedelta(days=3))
    proberapi.log_sent(con, one.id, "probe1", [V4], 3, NOW - timedelta(minutes=2))
    proberapi.log_sent(con, two.id, "probe1", [OTHER_V4], 3, NOW - timedelta(minutes=1))
    return con


@pytest.fixture()
def api_db(live_db):
    """`live_db` with the prober API's tables filled, every connection
    closed, so the file holds all of it and nothing is in a -wal."""
    serve_the_prober_api(live_db).close()
    return live_db


def table_rows(path: Path, table: str) -> list:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return [tuple(row) for row in con.execute(f"SELECT * FROM {table} ORDER BY rowid")]
    finally:
        con.close()


def every_row(path: Path) -> dict:
    """Every table of the database with every row in it."""
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [row[0] for row in con.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")]
    finally:
        con.close()
    return {table: table_rows(path, table) for table in tables}


def times_in(path: Path, needle: bytes) -> int:
    path = Path(path)
    return path.read_bytes().count(needle) if path.exists() else 0


def unpacked(result: dict, tmp_path: Path) -> Path:
    """The snapshot as a restore gets it: the zip opened into a file in a
    directory of its own, with no -wal and nothing else beside it."""
    home = tmp_path / "unpacked"
    home.mkdir()
    restored = home / "whichports.db"
    with gzip.open(result["path"], "rb") as gz:
        restored.write_bytes(gz.read())
    return restored


def test_the_fixture_holds_what_a_snapshot_must_not(api_db):
    """What the tests below count is really there before a backup runs, or a
    0 afterwards would say nothing."""
    assert len(table_rows(api_db, "prober_api_batches")) == 2
    assert len(table_rows(api_db, "prober_api_charges")) == 3
    assert len(table_rows(api_db, "prober_api_log")) == 3
    assert times_in(api_db, BATCH_BYTES) == 2
    assert times_in(api_db, ANSWER_BYTES) == 1


def test_a_snapshot_holds_no_batch_and_no_hours_count_as_rows_or_as_bytes(api_db, tmp_path):
    result = backup.run(api_db, tmp_path / "backups", keep=14, now=NOW)
    restored = unpacked(result, tmp_path)
    found = {"batches": len(table_rows(restored, "prober_api_batches")),
             "charges": len(table_rows(restored, "prober_api_charges")),
             "request bytes": times_in(restored, BATCH_BYTES),
             "answer bytes": times_in(restored, ANSWER_BYTES)}
    print(f"\n    in the live database: 2 batches, 3 charges, a request's bytes"
          f" {times_in(api_db, BATCH_BYTES)} times, the answer's"
          f" {times_in(api_db, ANSWER_BYTES)} time. In the unpacked snapshot: {found}")
    assert found == {"batches": 0, "charges": 0, "request bytes": 0, "answer bytes": 0}


def test_lock_seconds_left_out_of_the_snapshot(live_db, tmp_path):
    """The seconds a batch held the pass lock are written on its charge row,
    so they leave the copy with the hour's count, and a number no other
    column holds is in the live file and not in the snapshot."""
    con = serve_the_prober_api(live_db)
    try:
        answered = con.execute("SELECT batch_id FROM prober_api_charges"
                               " WHERE batch_id IS NOT NULL").fetchall()
        assert answered
        for (batch_id,) in answered:
            assert proberapi.charge_lock_seconds(con, batch_id, 1234.5)
        held = con.execute("SELECT COUNT(*) FROM prober_api_charges"
                           " WHERE lock_seconds = 1234.5").fetchone()[0]
    finally:
        con.close()
    assert held == len(answered)
    # SQLite keeps a REAL as eight bytes, big-endian.
    seconds_bytes = struct.pack(">d", 1234.5)
    assert times_in(live_db, seconds_bytes) >= 1
    result = backup.run(live_db, tmp_path / "backups", keep=14, now=NOW)
    restored = unpacked(result, tmp_path)
    assert table_rows(restored, "prober_api_charges") == []
    assert times_in(restored, seconds_bytes) == 0


def test_a_batch_still_in_the_live_wal_is_not_in_the_snapshot_either(live_db, tmp_path):
    """The worker keeps a connection open on the box, so what was written
    last is in the -wal beside the database and not yet in its file. The copy
    reads through that, and then leaves the batch out all the same."""
    worker = serve_the_prober_api(live_db)
    try:
        assert times_in(str(live_db) + "-wal", BATCH_BYTES) >= 2
        result = backup.run(live_db, tmp_path / "backups", keep=14, now=NOW)
        still_live = worker.execute("SELECT COUNT(*) FROM prober_api_batches").fetchone()[0]
    finally:
        worker.close()
    restored = unpacked(result, tmp_path)
    assert still_live == 2
    assert table_rows(restored, "prober_api_batches") == []
    assert table_rows(restored, "prober_api_charges") == []
    assert times_in(restored, BATCH_BYTES) == 0
    assert times_in(restored, ANSWER_BYTES) == 0
    assert result["hosts"] == 2 and result["reports"] == 3


def test_what_is_zipped_is_the_emptied_file_with_nothing_left_beside_it(api_db, tmp_path):
    """The zip takes the copy's main file alone. So after the batches are
    taken out, that file by itself holds none, and no -wal beside it holds
    the deletes or the bytes."""
    work = tmp_path / "work.db"
    backup.snapshot(api_db, work)
    assert times_in(work, BATCH_BYTES) == 2, "the copy never held a batch"
    backup.leave_batches_out(work)
    wal = Path(str(work) + "-wal")
    assert not wal.exists() or wal.stat().st_size == 0
    assert times_in(work, BATCH_BYTES) == 0
    assert times_in(work, ANSWER_BYTES) == 0
    # Read with nothing beside it, as the zip holds it.
    alone = tmp_path / "alone" / "work.db"
    alone.parent.mkdir()
    alone.write_bytes(work.read_bytes())
    assert table_rows(alone, "prober_api_batches") == []
    assert table_rows(alone, "prober_api_charges") == []


def test_the_abuse_log_is_in_the_snapshot_whole_and_answers_for_an_address(api_db, tmp_path):
    before = table_rows(api_db, "prober_api_log")
    result = backup.run(api_db, tmp_path / "backups", keep=14, now=NOW)
    restored = unpacked(result, tmp_path)
    assert len(before) == 3
    assert table_rows(restored, "prober_api_log") == before
    con = db.connect(str(restored))
    answer = [(row["instance_name"], row["day"], row["batches"])
              for row in proberapi.log_for_target(con, V4)]
    con.close()
    assert answer == [("one", "2026-08-14", 1), ("one", "2026-08-11", 1)]


def test_a_backup_leaves_the_live_database_exactly_as_it_was(api_db, tmp_path):
    """The batches are taken out of the copy and never out of the database
    the box runs on: every row of every table is the same after a backup, the
    two in flight among them, and so is every byte of the file."""
    rows_before = every_row(api_db)
    bytes_before = api_db.read_bytes()
    backup.run(api_db, tmp_path / "backups", keep=14, now=NOW)
    assert every_row(api_db) == rows_before
    assert len(rows_before["prober_api_batches"]) == 2
    assert len(rows_before["prober_api_charges"]) == 3
    assert api_db.read_bytes() == bytes_before


def test_the_copy_is_emptied_before_it_is_checked_and_before_it_is_zipped(
        api_db, tmp_path, monkeypatch):
    """The check has to pass on the file that is kept, and not on the one
    from before the batches went."""
    seen = {}
    real_verify, real_compress = backup.verify, backup.compress

    def verify(path):
        seen["rows at the check"] = len(table_rows(path, "prober_api_batches"))
        return real_verify(path)

    def compress(src, dest):
        seen["bytes at the zip"] = times_in(src, BATCH_BYTES)
        return real_compress(src, dest)

    monkeypatch.setattr(backup, "verify", verify)
    monkeypatch.setattr(backup, "compress", compress)
    backup.run(api_db, tmp_path / "backups", keep=14, now=NOW)
    assert seen == {"rows at the check": 0, "bytes at the zip": 0}


def test_a_snapshot_without_batches_passes_the_check_and_the_app_starts_on_it(
        api_db, tmp_path):
    """The steps of a restore: unpack, check, open. Then the app's own start,
    which makes sure of every table, and the first thing each instance does,
    which is queue a batch: its slot is free and its hour is unspent."""
    result = backup.run(api_db, tmp_path / "backups", keep=14, now=NOW)
    restored = unpacked(result, tmp_path)
    assert backup.verify(restored) == {"hosts": 2, "reports": 3}
    con = db.connect(str(restored))
    for module in (db, authz, vantages, instances, proberapi):
        module.init(con)
    assert [i.name for i in instances.list_all(con)] == ["one", "two"]
    assert proberapi.sweep(con, NOW) == {"batches": 0, "charges": 0, "log": 0,
                                         "proof_uses": 0}
    for name in ("one", "two"):
        batch_id = proberapi.submit(con, instances.by_name(con, name).id, REQUEST, NOW)
        assert proberapi.fetch(con, instances.by_name(con, name).id, batch_id,
                               NOW) == {"state": "queued"}
    assert con.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    con.close()


def test_a_database_that_never_served_the_prober_api_is_backed_up_as_before(live_db, tmp_path):
    """Every database from before the prober API, and every self-hosted one
    whose worker has not made the tables: there is nothing to take out, and
    that is no failure."""
    assert "prober_api_batches" not in every_row(live_db)
    work = tmp_path / "work.db"
    backup.snapshot(live_db, work)
    backup.leave_batches_out(work)
    assert every_row(work) == every_row(live_db)
    result = backup.run(live_db, tmp_path / "backups", keep=14, now=NOW)
    assert result["hosts"] == 2 and result["reports"] == 3


def test_a_copy_that_cannot_be_emptied_fails_as_a_backup_and_not_as_a_traceback(tmp_path):
    """`main` turns a `BackupFailed` into one line and exit 1. Anything
    SQLite says while the batches are taken out has to arrive as one."""
    not_a_database = tmp_path / "work.db"
    not_a_database.write_bytes(b"this is not a database " * 200)
    with pytest.raises(backup.BackupFailed, match="batches"):
        backup.leave_batches_out(not_a_database)


def test_deletes_that_could_not_be_written_into_the_copy_fail_the_backup(
        api_db, tmp_path, monkeypatch):
    """The zip takes the copy's main file alone, so deletes left in the -wal
    beside it would make a snapshot with every batch still in it. Somebody
    reading the copy is what makes the checkpoint give up. Nobody reads it on
    the box, which is why this is a check and not a wait."""
    work = tmp_path / "work.db"
    backup.snapshot(api_db, work)
    reader = sqlite3.connect(work)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM prober_api_batches").fetchall()
    # Python waits five seconds on a busy database unless told otherwise,
    # and a twentieth of one is enough to hear the same answer.
    real_connect = sqlite3.connect
    monkeypatch.setattr(sqlite3, "connect",
                        lambda path, **kw: real_connect(path, timeout=0.05, **kw))
    try:
        with pytest.raises(backup.BackupFailed, match="could not be written back"):
            backup.leave_batches_out(work)
    finally:
        reader.rollback()
        reader.close()


def test_a_run_whose_copy_cannot_be_emptied_leaves_no_snapshot_behind(
        api_db, tmp_path, monkeypatch):
    """A snapshot that still held a batch would read as one that does not."""
    def refuses(_path):
        raise backup.BackupFailed("cannot take the batches out of the copy")

    monkeypatch.setattr(backup, "leave_batches_out", refuses)
    dest = tmp_path / "backups"
    with pytest.raises(backup.BackupFailed):
        backup.run(api_db, dest, keep=14, now=NOW)
    assert list(dest.glob("*")) == []


def test_every_table_the_prober_api_makes_is_left_out_or_kept_on_purpose():
    """A table more would ride into every snapshot without anybody having
    decided that it may. The names are read from the prober API's and the
    open signup's own schemas, so the day one is added this fails until it
    is put on one side. The signup's day counts hold no address and ride."""
    con = sqlite3.connect(":memory:")
    con.executescript(proberapi.SCHEMA)
    con.executescript(instancesignup.SCHEMA)
    made = {row[0] for row in con.execute(
        "SELECT name FROM sqlite_schema WHERE type = 'table'")}
    con.close()
    kept_on_purpose = {"prober_api_log", "instance_signup_days"}
    assert set(backup.LEFT_OUT_OF_A_SNAPSHOT) == {
        "prober_api_batches", "prober_api_charges", "prober_api_proof_uses",
        "instance_signups", "instance_signup_claims"}
    assert made == set(backup.LEFT_OUT_OF_A_SNAPSHOT) | kept_on_purpose


def test_claims_and_codes_are_in_no_snapshot(live_db, tmp_path, monkeypatch):
    """A waiting code and a claim are an address and a day at most, and
    eight digits under SHA-256 are worked out from a copy in seconds. They
    leave the copy, as rows and as bytes, and an instance's own address
    stays in it, as the privacy page says."""
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    # One instance made and one code waiting: room for both, whatever the
    # cap on live signup instances is.
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)
    made_claim, waiting_claim = "a1" * 32, "b2" * 32
    con = db.connect(str(live_db))
    try:
        for module in (authz, instances, instancesignup):
            module.init(con)
        made = instancesignup.request_code(con, "made@example.org", made_claim, NOW)
        assert instancesignup.collect(con, made_claim, made.code, NOW).answer == "made"
        waiting = instancesignup.request_code(con, "waiting@example.org",
                                              waiting_claim, NOW)
        assert waiting.code
        hashes = [row[0].encode() for row in con.execute(
            "SELECT code_hash FROM instance_signups UNION ALL"
            " SELECT claim_hash FROM instance_signup_claims")]
    finally:
        con.close()
    assert len(hashes) == 3
    assert times_in(live_db, b"waiting@example.org") >= 1
    result = backup.run(live_db, tmp_path / "backups", keep=14, now=NOW)
    restored = unpacked(result, tmp_path)
    assert table_rows(restored, "instance_signups") == []
    assert table_rows(restored, "instance_signup_claims") == []
    assert times_in(restored, b"waiting@example.org") == 0
    for value in hashes:
        assert times_in(restored, value) == 0
    assert times_in(restored, b"made@example.org") >= 1
