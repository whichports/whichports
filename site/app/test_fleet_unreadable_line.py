"""A Fleet row says what could not be read.

    Run from site/: python3 -m pytest app/test_fleet_unreadable_line.py

The outside review of 2026-10-06 found a row that read not readable and
nothing on it saying what (point 2, docs/RECORD.md 4.460). A server's row reads not
readable when the newest report its agent sent arrived and could not be
read, or its page could not be drawn from it. The state word stays, and a
line under the server's name says what: the newest report. It is an error
line and not the hostname line the page script redraws when a display name
is saved, so a save never takes it away.
"""
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import NOW, SSHD, _fleet_row, add_host, db, document  # noqa: E402,F401

LINE = "newest report could not be read"


def unreadable_report(db, name):
    add_host(db, name, [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    con = sqlite3.connect(db)
    con.execute("UPDATE reports SET document = ? WHERE host_id ="
                " (SELECT id FROM hosts WHERE name = ?)", ("[]", name))
    con.commit()
    con.close()


def words(row):
    return " ".join(re.sub(r"<[^>]+>", " ", row).split())


# ------------------------------------------------------------ edge cases

def test_a_server_whose_report_reads_has_no_such_line(db):
    add_host(db, "fine", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    assert LINE not in rl.render(db, now=NOW)


def test_a_server_that_never_reported_has_no_such_line(db):
    """Nothing arrived, which is a different fact from a report that would
    not read (docs/DESIGN.md section 3)."""
    add_host(db, "new", [])
    assert LINE not in _fleet_row(rl.render(db, now=NOW), "new")


def test_the_line_is_not_the_one_a_display_name_save_redraws(db):
    unreadable_report(db, "broken")
    row = _fleet_row(rl.render(db, now=NOW), "broken")
    line = re.search(rf'<small class="([^"]+)">{LINE}</small>', row)
    assert line and "fhost" not in line.group(1).split()


# --------------------------------------------------------- the usual case

def test_a_server_whose_newest_report_would_not_read_says_so_under_its_name(db):
    unreadable_report(db, "broken")
    row = _fleet_row(rl.render(db, now=NOW), "broken")
    assert words(row) == f"not readable broken {LINE}"


def test_the_samples_row_says_the_same():
    page = build.build_sample()
    row = re.search(r'<a class="row" href="/host/build-02".*?</a>', page, re.S).group(0)
    assert words(row) == f"not readable build-02 staging {LINE}"
