"""A paused server says so beside whatever worse it has to say.

    Run from site/: python3 -m pytest app/test_paused_mark.py

A server's State cell shows one word, the worse of what its ports say and
what the server itself says, and the other word is dropped (docs/DESIGN.md
section 3). On a paused server with a port nobody has answered for, the
dropped word was `paused`: the Fleet row and the server's header read
`unreviewed` and nothing on either said that the server is paused. Found on
the test fleet on 2026-10-01 with two alerts open on a paused server
(docs/RECORD.md 4.453). docs/PRODUCT.md 4c: a paused server shows as paused.

The dropped word is a slim mark beside the state now, in the neutral tone
the muted mark has, on the row and on the header alike. Where the state is
`paused` itself there is no mark: that would be one fact said twice.
"""
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_address_hosts_screen as tah  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
UVICORN = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
           "process_name": "uvicorn", "pid": 7}
MARK = re.compile(r'<span class="tag-mute"[^>]*data-mark="paused"[^>]*>([^<]*)</span>')


def paused_marks(markup):
    """The word inside every paused mark in this markup."""
    return MARK.findall(markup)


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    # the tables a proof of control lives in, made by their own module
    rw = sqlite3.connect(path)
    rw.row_factory = sqlite3.Row
    tah.registry().init(rw)
    rw.close()
    return path


def pause(db, name):
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET paused = 1 WHERE name = ?", (name,))
    con.commit()
    con.close()


def a_server_with_an_unanswered_port(db, name="box"):
    """An agent host whose port 8410 answers from outside and no rule names."""
    trl.reporting(db, name, trl.document(listening=[trl.SSHD, UVICORN]))
    trl.probe_result(db, name, 8410, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=5))


def header(html, name):
    """The server's own header, down to its buttons."""
    return trl.host_section(html, name).split('<div class="acts">', 1)[0]


# ------------------------------------------------- where there is no mark

def test_the_state_paused_carries_no_paused_mark():
    """One fact, said once: the word is the state already."""
    assert paused_marks(build.state_marks_html("box", "paused", False, "", paused=True)) == []
    assert paused_marks(build.state_set_html("box", ("off", "paused"), False, "", paused=True)) == []


@pytest.mark.parametrize("word", ["unreviewed", "conflict", "watched", "alert open", "paused"])
def test_a_server_that_is_not_paused_carries_no_paused_mark(word):
    assert paused_marks(build.state_marks_html("box", word, False, "")) == []
    assert paused_marks(build.state_marks_html("box", word, True, "5 Sep 09:12", rarely=True)) == []


def test_a_paused_server_with_nothing_worse_reads_paused_and_no_mark(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    pause(db, "box")
    html = rl.render(db, now=NOW)
    row = trl._fleet_row(html, "box")
    assert 'data-state="paused"' in row
    assert paused_marks(row) == [] and paused_marks(header(html, "box")) == []


def test_a_server_with_an_unanswered_port_that_is_not_paused_has_no_mark(db):
    a_server_with_an_unanswered_port(db)
    html = rl.render(db, now=NOW)
    assert 'data-state="unreviewed"' in trl._fleet_row(html, "box")
    assert paused_marks(html) == []


def test_the_sample_page_draws_no_paused_mark():
    """Its one paused server reads `paused` as its state."""
    assert paused_marks(build.build_sample()) == []


# ----------------------------------------------------- where the mark is

@pytest.mark.parametrize("word", ["unreviewed", "conflict", "unexplained", "alert open"])
def test_a_paused_server_under_a_worse_word_carries_one_mark(word):
    marks = build.state_marks_html("box", word, False, "", paused=True)
    assert paused_marks(marks) == ["paused"]
    assert 'title="paused"' in marks


def test_the_paused_mark_stands_first_and_is_not_the_mute_clicks_mark():
    """The mute click fills the mark that carries the server's name. The
    paused mark carries none, so a mute cannot write into it."""
    marks = build.state_marks_html("box", "unreviewed", True, "5 Sep 09:12", paused=True)
    paused = MARK.search(marks)
    assert paused and paused.start() == 0
    assert "data-mute-tag" not in paused.group(0)
    assert marks.count("data-mute-tag") == 1


def test_the_paused_mark_has_the_pause_glyph_in_the_stylesheet():
    selector = '.tag-mute[data-mark=paused]'
    assert build.MARK_ICONS[selector] == "pause"
    assert f"{selector}::before{{" in build.CSS


def test_a_paused_server_with_an_unanswered_port_says_paused_on_its_row(db):
    a_server_with_an_unanswered_port(db)
    pause(db, "box")
    row = trl._fleet_row(rl.render(db, now=NOW), "box")
    assert 'data-state="unreviewed"' in row
    assert paused_marks(row) == ["paused"]


def test_a_paused_server_with_an_unanswered_port_says_paused_on_its_header(db):
    a_server_with_an_unanswered_port(db)
    pause(db, "box")
    head = header(rl.render(db, now=NOW), "box")
    # the state group, as the header writes it: the word, then the mark
    assert '<span class="stset"><span class="st warn">unreviewed</span><span class="tag-mute" data-mark="paused"' in head
    assert paused_marks(head) == ["paused"]


def test_the_row_and_the_header_say_the_same_of_a_second_server(db):
    """Two servers on one page, one paused: the mark is on that one alone."""
    a_server_with_an_unanswered_port(db, "box")
    a_server_with_an_unanswered_port(db, "other")
    pause(db, "other")
    html = rl.render(db, now=NOW)
    assert paused_marks(trl._fleet_row(html, "box")) == []
    assert paused_marks(header(html, "box")) == []
    assert paused_marks(trl._fleet_row(html, "other")) == ["paused"]
    assert paused_marks(header(html, "other")) == ["paused"]


def test_a_paused_address_host_with_an_unanswered_port_says_paused(db):
    """A server with no agent takes the same word and the same mark."""
    tah.prove(db, tah.add_address_host(db, "edge", paused=True))
    trl.probe_result(db, "edge", 443, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=5))
    html = rl.render(db, now=NOW)
    row = trl._fleet_row(html, "edge")
    assert 'data-state="paused"' not in row
    assert paused_marks(row) == ["paused"]
    assert paused_marks(header(html, "edge")) == ["paused"]
