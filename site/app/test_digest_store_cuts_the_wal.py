"""The digest store cuts the -wal when it is the one to start it over.

`render_live.store_digests` opens the database by itself and writes, so it is
not a connection the control plane's `db.connect` made. The -wal file beside
the database is cut back by whichever connection writes first after SQLite
started it over, and by none of the later ones. So one writer without
`journal_size_limit = 0` is enough for a long -wal to keep its tail, and a
deleted probe batch sat in such a tail for as long as anybody counted
(docs/RECORD.md 4.444). The control plane's `db.forget_what_is_deleted` owns
the two settings and says why. This holds the renderer's writer to them.

What is measured is the length of the -wal file, read from the disk.
"""
import os
import pathlib
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    """The fixture schema in WAL mode, which is what the control plane's
    `db.connect` leaves every real database in."""
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.execute("PRAGMA journal_mode = WAL")
    con.executescript(trl.SCHEMA)
    con.execute("CREATE TABLE other_writes (id INTEGER PRIMARY KEY, body BLOB)")
    con.commit()
    con.close()
    return str(path)


def wal_bytes(db) -> int:
    return os.path.getsize(db + "-wal")


def a_long_wal_with_a_read_open(db):
    """Open a read and leave it open, then write until the -wal is longer
    than SQLite lets it get by itself. A read in progress keeps the file from
    starting over, so it grows instead. Returns the reading connection and
    the length an ordinary round ends at."""
    reader = sqlite3.connect(db)
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM other_writes").fetchall()
    ordinary = (reader.execute("PRAGMA wal_autocheckpoint").fetchone()[0]
                * reader.execute("PRAGMA page_size").fetchone()[0])
    for _ in range(60):
        con = sqlite3.connect(db)
        con.executemany("INSERT INTO other_writes (body) VALUES (?)",
                        [(os.urandom(3000),) for _ in range(20)])
        con.commit()
        con.close()
    assert wal_bytes(db) > ordinary, "the -wal is not long yet"
    return reader, ordinary


def test_the_digest_store_cuts_a_long_wal_when_it_starts_it_over(db):
    trl.add_host(db, "box", [(NOW - timedelta(minutes=2), trl.document(listening=[trl.SSHD]))])
    # One connection open throughout, as the worker keeps one on the box, so
    # the -wal is never removed by the last connection closing.
    keeper = sqlite3.connect(db)
    report_id = keeper.execute("SELECT id FROM reports").fetchone()[0]
    reader, ordinary = a_long_wal_with_a_read_open(db)
    long = wal_bytes(db)

    reader.execute("COMMIT")
    reader.close()
    # The first write after the read lets SQLite copy the whole -wal into the
    # database's file. The second starts the -wal over, and is the one that
    # cuts it or does not.
    for text in ("first", "second"):
        assert rl.store_digests(db, {report_id: text}) == 1
    now = wal_bytes(db)
    keeper.close()
    print(f"\n    the -wal was {long} bytes with the long read open and is {now} bytes"
          " after the digest store wrote twice")
    assert now < ordinary, (
        f"the -wal is still {now} bytes after the digest store started it over")


def test_the_digest_store_is_the_renderers_one_connection_that_writes():
    """Every other connection the renderer opens is read only, which deletes
    nothing and writes nothing to the -wal. This is a search of the text for
    `sqlite3.connect(` and no more: it cannot see what a connection does, only
    that a second one arrived that is not read only, which is the moment to
    give it the two settings as well."""
    source = pathlib.Path(rl.__file__).read_text(encoding="utf-8")
    opens = [line.strip() for line in source.splitlines()
             if "sqlite3.connect(" in line and "mode=ro" not in line]
    assert opens == ["con = sqlite3.connect(db_path)"], opens
    assert source.count('joinbridge.module("db").forget_what_is_deleted(con)') == 1
