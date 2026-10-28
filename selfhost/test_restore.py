"""A snapshot goes back as the live database, or nothing changes.

Driven against real SQLite files made by the control plane's own schema and
its own nightly backup (app/backup.py), so what is restored here is exactly
what the worker writes at 03:17.
"""
import gzip
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

import restore

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "controlplane"))
from app import backup, db, store  # noqa: E402


def make_database(path: Path, hosts: list) -> None:
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    db.init(con)
    for name in hosts:
        store.add_host(con, name)
    con.commit()
    con.close()


def host_names(path: Path) -> list:
    con = sqlite3.connect(path)
    names = sorted(r[0] for r in con.execute("SELECT name FROM hosts"))
    con.close()
    return names


@pytest.fixture()
def stack(tmp_path):
    data = tmp_path / "data"
    backups = tmp_path / "backups"
    data.mkdir()
    database = data / "whichports.db"
    make_database(database, ["kept"])
    taken = backup.run(database, backups, keep=14,
                       now=datetime(2026, 10, 1, 3, 17, tzinfo=timezone.utc))
    # After the snapshot, the live database moves on.
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row
    store.add_host(con, "added-later")
    con.commit()
    con.close()
    return database, backups, taken["path"]


def test_a_snapshot_comes_back_and_the_old_database_is_set_aside(stack):
    database, backups, snapshot = stack
    result = restore.restore(snapshot, database,
                             now=datetime(2026, 10, 2, tzinfo=timezone.utc))
    assert host_names(database) == ["kept"]
    assert result["hosts"] == 1
    assert host_names(result["aside"]) == ["added-later", "kept"]
    assert not list(database.parent.glob(".restore-*"))


def test_no_sidecar_of_the_check_is_left_behind(stack, monkeypatch):
    """Measured on 2026-10-01 in the Linux container: the read-only check
    of a WAL-mode copy left `.restore-<time>.db-wal` and `-shm` behind."""
    database, _backups, snapshot = stack
    backup = restore._backup_module()
    real_verify = backup.verify

    def verify_leaving_sidecars(path):
        counts = real_verify(path)
        for suffix in ("-wal", "-shm"):
            Path(str(path) + suffix).write_bytes(b"")
        return counts

    monkeypatch.setattr(backup, "verify", verify_leaving_sidecars)
    restore.restore(snapshot, database)
    assert not list(database.parent.glob(".restore-*"))


def test_a_bare_name_is_looked_up_in_the_backups(stack):
    database, backups, snapshot = stack
    assert restore.resolve(snapshot.name, backups) == snapshot


def test_main_end_to_end(stack, capsys):
    database, backups, snapshot = stack
    code = restore.main([snapshot.name, "--database", str(database),
                         "--backups", str(backups)])
    assert code == 0
    out = capsys.readouterr().out
    assert "restored" in out and "1 hosts" in out and "before-restore" in out


@pytest.mark.parametrize("payload", [
    b"not gzip at all",
    gzip.compress(b"gzip, but not a database"),
    gzip.compress(b"SQLite format 3\x00" + b"\x00" * 200),
])
def test_a_bad_snapshot_changes_nothing(stack, payload):
    database, backups, _snapshot = stack
    bad = backups / "whichports-20261001T000000Z.db.gz"
    bad.write_bytes(payload)
    before = database.read_bytes()
    with pytest.raises(restore.RestoreRefused, match="nothing was changed"):
        restore.restore(bad, database)
    assert database.read_bytes() == before
    assert not list(database.parent.glob(".restore-*"))
    assert not list(database.parent.glob("*.before-restore-*"))


def test_a_cut_short_snapshot_changes_nothing(stack):
    database, backups, snapshot = stack
    cut = backups / "whichports-20261001T000001Z.db.gz"
    cut.write_bytes(snapshot.read_bytes()[:200])
    with pytest.raises(restore.RestoreRefused):
        restore.restore(cut, database)
    assert host_names(database) == ["added-later", "kept"]


def test_a_missing_snapshot_is_refused(stack):
    _database, backups, _snapshot = stack
    with pytest.raises(restore.RestoreRefused, match="no snapshot"):
        restore.resolve("whichports-19990101T000000Z.db.gz", backups)


def test_only_a_snapshot_the_backup_wrote(stack, tmp_path):
    _database, backups, _snapshot = stack
    other = backups / "notes.txt"
    other.write_text("x")
    with pytest.raises(restore.RestoreRefused, match="not a snapshot"):
        restore.resolve("notes.txt", backups)


def test_a_restore_onto_no_database_needs_nothing_set_aside(stack):
    database, _backups, snapshot = stack
    for suffix in ("", "-wal", "-shm"):
        Path(str(database) + suffix).unlink(missing_ok=True)
    result = restore.restore(snapshot, database)
    assert result["aside"] is None
    assert host_names(database) == ["kept"]


def test_the_wal_goes_aside_with_its_database(stack):
    database, _backups, snapshot = stack
    holder = sqlite3.connect(database)
    holder.execute("PRAGMA journal_mode=WAL")
    holder.execute("CREATE TABLE IF NOT EXISTS t (x)")
    holder.execute("INSERT INTO t VALUES (1)")
    holder.commit()
    assert Path(str(database) + "-wal").exists()
    holder.close()
    result = restore.restore(snapshot, database,
                             now=datetime(2026, 10, 3, tzinfo=timezone.utc))
    assert not Path(str(database) + "-wal").exists()
    con = sqlite3.connect(result["aside"])
    assert con.execute("SELECT x FROM t").fetchall() == [(1,)]
    con.close()


def test_a_snapshot_on_standard_input(stack, monkeypatch, capsys):
    """For a snapshot kept off the machine: `restore.py - < file`."""
    import io
    database, backups, snapshot = stack

    class Stdin:
        buffer = io.BytesIO(snapshot.read_bytes())

    monkeypatch.setattr(restore.sys, "stdin", Stdin)
    code = restore.main(["-", "--database", str(database),
                         "--backups", str(backups)])
    assert code == 0
    assert host_names(database) == ["kept"]
    assert "the snapshot on standard input" in capsys.readouterr().out


def test_rubbish_on_standard_input_changes_nothing(stack, monkeypatch, capsys):
    import io
    database, backups, _snapshot = stack

    class Stdin:
        buffer = io.BytesIO(b"not a snapshot")

    monkeypatch.setattr(restore.sys, "stdin", Stdin)
    before = database.read_bytes()
    assert restore.main(["-", "--database", str(database),
                         "--backups", str(backups)]) == 1
    assert database.read_bytes() == before
    assert "nothing was changed" in capsys.readouterr().err
