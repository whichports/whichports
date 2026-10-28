"""A deleted batch is gone from the database's files, and not only as a row.

    python -m pytest tests/test_deleted_bytes.py -s

A queued probe batch is kept fifteen minutes at most
(`proberapi.BATCH_TTL_SECONDS`). The rows were always deleted on time. What
was measured on 2026-10-07 (docs/RECORD.md 4.444) is that a delete in SQLite
takes the row away and leaves its bytes where they were: in the database's
file until those pages are used again, and in the -wal file beside it, in one
case for as long as anybody counted. The nightly backup copies what is there.

`db.forget_what_is_deleted` is the answer, two settings on every connection
that writes. These tests count bytes, the way they were counted that day: a
stored batch is JSON with the key "tls_ports" (`BatchRequest.to_json`), and
nothing else in the database holds those bytes. Every count is in the test's
own output, so run with `-s` to read them.

What a count of 0 says: none of a batch's own bytes are in that file. It says
nothing of a disk under the file, which keeps what it likes.
"""
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import authz, db, instances, proberapi, vantages

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
PAST_THE_LIMIT = NOW + timedelta(seconds=proberapi.BATCH_TTL_SECONDS + 1)
V4 = "185.199.108.153"

# The bytes that say "a batch is here". Every stored request has this key.
BATCH_BYTES = b'"tls_ports"'
# And the bytes of an answer, which no request has. An answer is the runner's
# own JSON, kept verbatim, and a long one does not fit the row's page.
ANSWER_BYTES = b'"measured_from"'

REQUEST = proberapi.BatchRequest(vantage="probe1", addresses=(V4,), ports=(22, 443),
                                 tls_ports=(443,), allowed=(V4,))
# Some 20 KB, so SQLite stores it on pages of its own beside the row.
LONG_ANSWER = json.dumps({"measured_from": "probe1", "results": [
    {"address": V4, "port": port, "state": "open"} for port in range(1, 400)]})


def wal_of(path) -> Path:
    return Path(str(path) + "-wal")


def times_in(path, needle=BATCH_BYTES) -> int:
    """How often these bytes are in this file. A file that is not there holds
    them 0 times."""
    path = Path(path)
    return path.read_bytes().count(needle) if path.exists() else 0


def new_database(path):
    """The app's own tables through the real `db.connect`, a table for what
    everything else writes, and one instance to queue batches for. Returns
    the connection, still open, and what `instances.add` issued."""
    con = db.connect(str(path))
    for module in (db, authz, vantages, instances, proberapi):
        module.init(con)
    con.execute("CREATE TABLE other_writes (id INTEGER PRIMARY KEY, body BLOB)")
    con.commit()
    return con, instances.add(con, "one", now=NOW, origin=authz.ORIGIN_INVITED)


def other_writes(path, commits, rows=20):
    """What the rest of the app writes meanwhile: about a page a row, each
    commit on a connection of its own, as a request makes one."""
    for _ in range(commits):
        con = db.connect(str(path))
        con.executemany("INSERT INTO other_writes (body) VALUES (?)",
                        [(os.urandom(3000),) for _ in range(rows)])
        con.commit()
        con.close()


def queue_then_sweep(path, instance_id):
    """A batch comes and goes the real way, each half on its own connection."""
    con = db.connect(str(path))
    proberapi.submit(con, instance_id, REQUEST, NOW)
    con.close()
    con = db.connect(str(path))
    swept = proberapi.sweep(con, PAST_THE_LIMIT)
    left = con.execute("SELECT COUNT(*) FROM prober_api_batches").fetchone()[0]
    con.close()
    assert swept["batches"] == 1 and left == 0


def a_long_wal_with_a_read_open(path):
    """Open a read and leave it open, then write until the -wal is longer
    than SQLite lets it get by itself. Returns the reading connection.

    SQLite starts the -wal over from its first page once everything in it has
    been copied into the database's file, which it does every
    `wal_autocheckpoint` pages. A read in progress stops that: the pages it
    may still need stay, and the file grows instead."""
    reader = db.connect(str(path))
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM other_writes").fetchall()
    ordinary = (reader.execute("PRAGMA wal_autocheckpoint").fetchone()[0]
                * reader.execute("PRAGMA page_size").fetchone()[0])
    other_writes(path, 60)
    assert wal_of(path).stat().st_size > ordinary, "the -wal is not long yet"
    return reader


# ============================================================ the settings

def test_every_connection_overwrites_what_it_deletes_and_cuts_its_wal(tmp_path):
    """Asked of the connection, so it holds whatever this SQLite was built to
    do by itself. Both settings belong to a connection and not to the file,
    which is why a second connection to one file is asked too."""
    bare = sqlite3.connect(":memory:")
    print(f"\n    sqlite {sqlite3.sqlite_version} by itself: secure_delete"
          f" {bare.execute('PRAGMA secure_delete').fetchone()[0]},"
          f" journal_size_limit {bare.execute('PRAGMA journal_size_limit').fetchone()[0]}")
    bare.close()
    path = str(tmp_path / "cp.db")
    for where in (":memory:", path, path):
        con = db.connect(where)
        answers = (con.execute("PRAGMA secure_delete").fetchone()[0],
                   con.execute("PRAGMA journal_size_limit").fetchone()[0])
        con.close()
        print(f"    db.connect: secure_delete {answers[0]}, journal_size_limit {answers[1]}")
        assert answers == (1, 0), (
            f"secure_delete answers {answers[0]} and journal_size_limit {answers[1]}")


# ====================================================== the database's file

def test_a_swept_batch_leaves_none_of_its_bytes_in_the_database_file(tmp_path):
    path = tmp_path / "cp.db"
    con, issued = new_database(path)
    assert times_in(path) + times_in(wal_of(path)) == 0, (
        "something other than a batch holds these bytes, so they count nothing")
    proberapi.submit(con, issued.instance.id, REQUEST, NOW)
    con.close()
    # The last connection closing copies the -wal into the file and removes
    # it, so from here the file is all there is.
    assert not wal_of(path).exists()
    queued = times_in(path)
    assert queued == 1, "the count does not see a batch that is there"

    con = db.connect(str(path))
    assert proberapi.sweep(con, PAST_THE_LIMIT)["batches"] == 1
    con.close()
    assert not wal_of(path).exists()
    found = times_in(path)
    print(f"\n    a batch's bytes in the database file: {queued} time while queued,"
          f" {found} times after the sweep")
    assert found == 0, f"a swept batch's bytes are in the database file {found} times"


def test_a_collected_answer_goes_with_its_batch_long_as_it_is(tmp_path):
    """The other way a batch ends: the instance collects its answer and
    `fetch` deletes the row as it hands it over. The answer is long enough to
    sit on pages of its own, which a delete frees whole."""
    path = tmp_path / "cp.db"
    con, issued = new_database(path)
    one = issued.instance
    batch_id = proberapi.submit(con, one.id, REQUEST, NOW)
    row = proberapi.next_queued(con, NOW)
    proberapi.mark_started(con, batch_id, NOW)
    proberapi.record_answer(con, row, LONG_ANSWER, NOW)
    con.close()
    answered = (times_in(path), times_in(path, ANSWER_BYTES))
    assert answered == (1, 1), "the count does not see an answered batch"

    con = db.connect(str(path))
    handed = proberapi.fetch(con, one.id, batch_id, NOW)
    con.close()
    assert handed["state"] == "done"
    found = (times_in(path), times_in(path, ANSWER_BYTES))
    print(f"\n    the request's and the answer's bytes in the database file:"
          f" {answered} while it waited, {found} once collected")
    assert found == (0, 0), (
        f"a collected batch left its request {found[0]} times and its answer"
        f" {found[1]} times in the database file")


# ============================================================ the -wal file

def test_a_batch_written_into_a_long_wal_is_gone_soon_after_the_long_read_ends(tmp_path):
    """The case that had no end (4.444). A batch written while the -wal was
    longer than usual sat in its tail, because SQLite starts the file over
    without cutting it and an ordinary round never writes that far again.
    Counted 6000 commits later it was still there. Cut at every start over,
    it is gone at the first one."""
    path = tmp_path / "cp.db"
    worker, issued = new_database(path)   # stays open, as the worker's does,
    reader = a_long_wal_with_a_read_open(path)   # so the -wal is never removed
    queue_then_sweep(path, issued.instance.id)
    long_size = wal_of(path).stat().st_size
    while_reading = times_in(wal_of(path))
    assert while_reading >= 1, "the batch never was in the -wal, so this proves nothing"
    assert times_in(path) == 0

    reader.execute("COMMIT")
    reader.close()
    other_writes(path, 5, rows=2)
    found = times_in(wal_of(path))
    print(f"\n    a batch's bytes in the -wal: {while_reading} times with the long read"
          f" open and the file {long_size} bytes, {found} times five commits after"
          f" the read ended and the file {wal_of(path).stat().st_size} bytes")
    worker.close()
    assert found == 0, (
        f"a swept batch's bytes are still in the -wal {found} times, five commits"
        " after the long read ended")


def test_the_key_stamp_cuts_the_wal_too_when_it_is_the_one_to_start_it_over(tmp_path):
    """`instances.stamp_api_key_use` opens the database by itself and never
    through `db.connect`. Whether the -wal is cut is decided by the connection
    that happens to write first after it started over, so one writer without
    the setting is enough to leave a batch in the tail. Here the two commits
    after the long read are both stamps, which makes the stamp that one."""
    path = tmp_path / "cp.db"
    worker, issued = new_database(path)
    reader = a_long_wal_with_a_read_open(path)
    queue_then_sweep(path, issued.instance.id)
    assert times_in(wal_of(path)) >= 1

    reader.execute("COMMIT")
    reader.close()
    for minute in (1, 2):
        assert instances.stamp_api_key_use(str(path), issued.api_key,
                                           NOW + timedelta(minutes=minute))
    found = times_in(wal_of(path))
    print(f"\n    a batch's bytes in the -wal after two key stamps: {found} times,"
          f" the file {wal_of(path).stat().st_size} bytes")
    worker.close()
    assert found == 0, (
        f"a swept batch's bytes are still in the -wal {found} times after the"
        " key stamp started the file over")


# ================================================= nobody opens it unseen

APP = Path(__file__).resolve().parents[1] / "app"

# Every file of the app that opens a database without `db.connect` and not
# read only, how often, and why it may. A read-only connection is not here:
# it deletes nothing and writes nothing to the -wal.
OPENED_WITHOUT_DB_CONNECT = {
    "db.py": 1,          # `connect` itself, which sets the two
    "instances.py": 1,   # the key stamp, which sets them: the test above
    "backup.py": 2,      # the night's copy, written and then emptied of batches
                         # with the overwrite on. Never the live file
}


def test_no_writer_opens_the_database_without_being_listed_here():
    """One writer without the two settings is enough to leave a batch in the
    -wal, and nothing would say so. This is a search of the text for
    `sqlite3.connect(` and no more than that: it cannot see what a connection
    does, only that a new one arrived, which is the moment to give it
    `db.forget_what_is_deleted` and a line above."""
    found = {}
    for source in sorted(APP.rglob("*.py")):
        opens = [line for line in source.read_text().splitlines()
                 if "sqlite3.connect(" in line and "mode=ro" not in line]
        if opens:
            found[source.name] = len(opens)
    assert found == OPENED_WITHOUT_DB_CONNECT, (
        "the app opens a database somewhere new. If it writes to the live"
        " database it needs db.forget_what_is_deleted, and either way it is"
        " listed in OPENED_WITHOUT_DB_CONNECT with its reason")


# ===================================================== two processes at once

# The writer, in a process of its own, as the ingest is one process and the
# dashboard another. Every commit is on a new connection from the real
# `db.connect`, inserts and deletes, so both settings are at work. It says how
# often the -wal got shorter under it, which without the cut is never.
WRITER = """
import json, os, sys
from pathlib import Path
from app import db

path, commits = sys.argv[1], int(sys.argv[2])
wal = Path(path + "-wal")
shorter, last_size, settings = 0, 0, None
for _ in range(commits):
    con = db.connect(path)
    settings = (con.execute("PRAGMA secure_delete").fetchone()[0],
                con.execute("PRAGMA journal_size_limit").fetchone()[0])
    con.executemany("INSERT INTO other_writes (body) VALUES (?)",
                    [(os.urandom(3000),) for _ in range(10)])
    con.execute("DELETE FROM other_writes WHERE id IN"
                " (SELECT id FROM other_writes ORDER BY id LIMIT 5)")
    con.commit()
    newest = con.execute("SELECT MAX(id) FROM other_writes").fetchone()[0]
    con.close()
    size = wal.stat().st_size
    shorter += size < last_size
    last_size = size
print(json.dumps({"newest": newest, "wal_got_shorter": shorter, "settings": settings}))
"""


def test_a_second_process_reads_while_the_first_writes_deletes_and_cuts_the_wal(tmp_path):
    """The app runs in WAL mode so one process reads while another writes.
    Neither setting may cost that: every read here answers, never goes back
    in time, and ends on what the writer wrote last, while the writer cut the
    -wal under it more than once."""
    path = tmp_path / "cp.db"
    keeper, _issued = new_database(path)    # one connection open throughout
    writer = subprocess.Popen(
        [sys.executable, "-c", WRITER, str(path), "300"],
        cwd=Path(__file__).resolve().parents[1],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    seen = []
    try:
        while writer.poll() is None:
            reader = db.connect(str(path))
            seen.append(reader.execute("SELECT MAX(id) FROM other_writes").fetchall()[0][0] or 0)
            reader.close()
    finally:
        out, err = writer.communicate(timeout=120)
    assert writer.returncode == 0, err
    said = json.loads(out)

    reader = db.connect(str(path))
    last = reader.execute("SELECT MAX(id) FROM other_writes").fetchone()[0]
    check = reader.execute("PRAGMA integrity_check").fetchone()[0]
    reader.close()
    keeper.close()
    print(f"\n    {len(seen)} reads while another process made 300 commits, {len(set(seen))}"
          f" different answers, the -wal got shorter {said['wal_got_shorter']} times,"
          f" the writer's settings {said['settings']}")
    assert seen == sorted(seen), "a read went back in time"
    assert len(set(seen)) > 2, "no read fell between two writes, so this proves nothing"
    assert last == said["newest"]
    assert check == "ok"
    assert said["wal_got_shorter"] >= 1, (
        "the -wal never got shorter under the reads, so the cut was not tried")
