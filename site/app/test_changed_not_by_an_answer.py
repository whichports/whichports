"""An answer is not a change in what the internet reaches.

    Run from site/: python3 -m pytest app/test_changed_not_by_an_answer.py

Found on the test fleet on 2026-09-30 (docs/RECORD.md 4.220): a server's
Changed in 24h box read `none`, and after Yes on port 22, which had answered
from outside since its first measurement, it read `22/tcp became reachable`.

The control plane writes a change row when a port's state moves, and an
answer moves a state: `unreviewed` to `intended` is somebody typing. The
page counts a row only when its outside view differs from the row before it.
A port's first measurement writes no row, only a baseline, so the row an
answer wrote was the port's first, had nothing before it, and was read as a
port measured for the first time (docs/RECORD.md 4.453).

A first row now says what was before it through the state it left. Four
states mean the port answered, two mean it did not, and the row counts when
that differs from what the row measured. A row that left no state, which is
a port appearing on a server that has a history, counts as it did.
"""
import json
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_host_answers as tha  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
YES, SILENT, REFUSED = "connect_succeeded", "no_response", "connect_refused"
SSHD_ANY = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
            "process_name": "sshd", "pid": 811}


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[SSHD_ANY]))
    return path


def change(db, port, family, left, became, outside, minutes_ago):
    """One change row as the control plane leaves it, with what was measured."""
    trl.transition(db, "box", "tcp", port, family, left, became, "told",
                   seen_at=NOW - timedelta(minutes=minutes_ago))
    con = sqlite3.connect(db)
    con.execute("UPDATE finding_changes SET outside = ? WHERE id ="
                " (SELECT MAX(id) FROM finding_changes)", (outside,))
    con.commit()
    con.close()


def changed(db):
    """The ports the page counts as changed in the last 24 hours."""
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        hosts = con.execute("SELECT * FROM hosts").fetchall()
        return sorted(rl.load_reachability_changes(con, hosts, NOW - timedelta(hours=24)))
    finally:
        con.close()


def overview_line(html, name="box"):
    """The Changed in 24h box of one server: its number or word, and its line."""
    page = html.split(f'id="host-{name}"', 1)[1].split('<div class="wrap view"', 1)[0]
    text = re.sub(r"<[^>]+>", " ", page.split("Changed in 24h", 1)[1][:600])
    return " ".join(text.split())[:60]


# ------------------------------------------------ what a left state says

@pytest.mark.parametrize("state", ["conflict", "unreviewed", "intended", "unexplained"])
def test_four_states_mean_the_port_answered(state):
    assert rl.answered_before(state) is True


@pytest.mark.parametrize("state", ["not reachable", "stale rule"])
def test_two_states_mean_it_did_not(state):
    assert rl.answered_before(state) is False


@pytest.mark.parametrize("state", ["", None, "none", "x", "watched"])
def test_no_state_and_a_word_nobody_knows_say_nothing(state):
    assert rl.answered_before(state) is None


# ------------------------------------ first rows that count, as they did

@pytest.mark.parametrize("outside", [YES, SILENT, REFUSED])
def test_a_port_that_had_no_state_before_counts_whatever_was_measured(db, outside):
    """A port appearing on a server with a history: nobody knew it before."""
    change(db, 9000, "v4", "", "unreviewed", outside, 10)
    assert changed(db) == [("box", "tcp", 9000)]


def test_a_row_that_left_a_word_nobody_knows_counts_as_before(db):
    change(db, 9000, "v4", "none", "x", SILENT, 10)
    assert changed(db) == [("box", "tcp", 9000)]


def test_a_silent_port_that_began_answering_counts(db):
    change(db, 9000, "v4", "not reachable", "unreviewed", YES, 10)
    assert changed(db) == [("box", "tcp", 9000)]


def test_a_port_that_answered_and_went_silent_counts(db):
    change(db, 9000, "v4", "unreviewed", "not reachable", SILENT, 10)
    change(db, 9001, "v4", "intended", "not reachable", REFUSED, 10)
    assert changed(db) == [("box", "tcp", 9000), ("box", "tcp", 9001)]


def test_a_stale_rule_whose_port_began_answering_counts(db):
    change(db, 9000, "v4", "stale rule", "intended", YES, 10)
    assert changed(db) == [("box", "tcp", 9000)]


# ---------------------------------------- first rows that an answer wrote

@pytest.mark.parametrize("left,became", [
    ("unreviewed", "intended"),     # Yes
    ("unreviewed", "conflict"),     # No
    ("intended", "unreviewed"),     # an answer taken back
    ("conflict", "intended"),       # No turned into Yes
    ("unexplained", "intended"),
])
def test_an_answer_on_a_port_that_answered_all_along_is_no_change(db, left, became):
    change(db, 22, "v4", left, became, YES, 10)
    assert changed(db) == []


def test_an_answer_on_both_families_is_no_change(db):
    change(db, 22, "v4", "unreviewed", "intended", YES, 10)
    change(db, 22, "v6", "unreviewed", "intended", YES, 10)
    assert changed(db) == []


def test_a_rule_written_for_a_port_that_stays_silent_is_no_change(db):
    change(db, 9000, "v4", "not reachable", "stale rule", SILENT, 10)
    change(db, 9001, "v4", "stale rule", "not reachable", REFUSED, 10)
    assert changed(db) == []


# ------------------------------------------------ rows that have a past

def test_a_later_row_is_still_read_against_the_row_before_it(db):
    """The port began answering two hours ago and was answered for an hour
    ago. It is counted, for the first of the two."""
    change(db, 9000, "v4", "not reachable", "unreviewed", YES, 120)
    change(db, 9000, "v4", "unreviewed", "intended", YES, 60)
    assert changed(db) == [("box", "tcp", 9000)]


def test_an_answer_a_day_after_the_port_began_answering_is_no_change(db):
    change(db, 9000, "v4", "not reachable", "unreviewed", YES, 60 * 30)
    change(db, 9000, "v4", "unreviewed", "intended", YES, 60)
    assert changed(db) == []


# ------------------------------------------------- the Changes tab's lines

def tab_row(left, became, outside, before=None, minutes_ago=10):
    """A change row as `load_finding_changes` hands it to the Changes tab."""
    return {"protocol": "tcp", "port": 22, "family": "v4", "from_state": left,
            "to_state": became, "outside": outside, "before": before, "vantage": "probe1",
            "seen_at": (NOW - timedelta(minutes=minutes_ago)).isoformat()}


@pytest.mark.parametrize("left,became", [("unreviewed", "intended"), ("unreviewed", "conflict"),
                                         ("intended", "unreviewed")])
def test_the_changes_tab_has_no_line_for_an_answer_that_is_a_ports_first_row(left, became):
    assert rl.reachability_changes([tab_row(left, became, YES)]) == []


def test_the_changes_tab_keeps_the_line_of_a_port_that_began_answering():
    lines = rl.reachability_changes([tab_row("not reachable", "unreviewed", YES)])
    assert [(line.kind, line.port) for line in lines] == [("reachable", 22)]


def test_the_changes_tab_keeps_the_line_of_a_port_that_had_no_state_before():
    lines = rl.reachability_changes([tab_row("", "not reachable", SILENT)])
    assert [(line.kind, line.port) for line in lines] == [("unreachable", 22)]


def test_the_changes_tab_reads_a_row_with_a_past_against_that_past():
    assert rl.reachability_changes([tab_row("unreviewed", "intended", YES, before=YES)]) == []
    lines = rl.reachability_changes([tab_row("unreviewed", "not reachable", SILENT, before=YES)])
    assert [line.kind for line in lines] == ["unreachable"]


def test_a_row_in_the_older_shape_with_no_state_on_it_is_a_line_as_before():
    row = {"protocol": "tcp", "port": 22, "family": "v4", "outside": YES,
           "seen_at": (NOW - timedelta(minutes=10)).isoformat()}
    assert [line.kind for line in rl.reachability_changes([row])] == ["reachable"]


def changes_tab(html, name="box"):
    """The words of one server's Changes tab."""
    page = html.split(f'id="host-{name}"', 1)[1]
    tab = page.split(f'id="t-{name}-changes"', 1)[1].split(f'id="t-{name}-', 1)[0]
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", tab, flags=re.S)).split())


# ----------------------------------------------------------- on the page

def test_the_overview_says_none_after_yes_on_a_port_that_answered_all_along(db):
    trl.probe_result(db, "box", 22, "v4", YES, measured_at=NOW - timedelta(minutes=30))
    for family in ("v4", "v6"):
        tha.declare_intent(db, "box", "tcp", 22, family, "open")
    change(db, 22, "v4", "unreviewed", "intended", YES, 10)
    html = rl.render(db, now=NOW)
    assert overview_line(html).startswith("none")
    assert "became reachable" not in html
    # and the Changes tab does not list the answer as the prober's line
    assert "from outside" not in changes_tab(html)


def test_the_overview_still_names_a_port_that_began_answering(db):
    trl.probe_result(db, "box", 22, "v4", YES, measured_at=NOW - timedelta(minutes=30))
    change(db, 22, "v4", "not reachable", "unreviewed", YES, 10)
    assert overview_line(rl.render(db, now=NOW)).startswith("1 22/tcp became reachable")


# --------------------------- the same, with rows the control plane wrote

def test_the_control_planes_own_rows_after_a_yes_are_no_change(tmp_path):
    """Nothing here writes a change row by hand. The control plane's own
    pass over the findings writes a baseline for port 22 on its first look,
    the answer is declared through its own function, and its next pass
    writes the row an answer leaves. The page must count nothing."""
    path = str(tmp_path / "real.db")
    module = rl.joinbridge.module
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    for name in ("db", "prober", "intent", "vantages", "alerts", "finding_alerts"):
        module(name).init(con)
    host_id, _credential = module("store").add_host(con, "box")
    doc = trl.document(listening=[SSHD_ANY])
    module("store").insert_report(con, host_id, doc["collected_at_unix"], 1, json.dumps(doc))
    con.commit()
    prober = module("prober")

    def measure(moment):
        stamp = moment.isoformat()
        prober.store_measurement(con, host_id, prober.Run(
            id=None, vantage="probe1", started_at=stamp, finished_at=stamp,
            results=(prober.Result(family="v4", target="203.0.113.7", port=22, state=YES,
                                   connect_ms=14.0, measured_at=stamp),)))

    first, answered, after = (NOW - timedelta(minutes=m) for m in (90, 30, 20))
    measure(first)
    module("finding_alerts").evaluate(con, now=first)
    assert con.execute("SELECT COUNT(*) FROM finding_changes").fetchone()[0] == 0
    for family in ("v4", "v6"):
        module("intent").declare(con, "box", "tcp", 22, family, "open")
    measure(answered)
    module("finding_alerts").evaluate(con, now=answered)
    module("finding_alerts").evaluate(con, now=after)
    rows = [tuple(row) for row in con.execute(
        "SELECT family, from_state, to_state, outside FROM finding_changes ORDER BY id")]
    con.close()
    # the row this test is about is there, or everything under it proves nothing
    assert ("v4", "unreviewed", "intended", YES) in rows, rows
    assert changed(path) == []
    html = rl.render(path, now=NOW)
    assert overview_line(html).startswith("none")
    assert "from outside" not in changes_tab(html)
