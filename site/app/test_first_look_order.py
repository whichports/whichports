"""The first-look window is sorted so the ports most like a forgotten one
come first.

Decided on 2026-09-30 (`docs/RECORD.md` 4.221): a review of a server's ports
is offered once, never required, and sorted. The order is by what is measured
and by nothing else, in this order: a port no rule of the operator's answers,
a port on the list of ports that should rarely face the internet, a port whose
answer from outside has not moved since the server's first report, then the
port number. It is an order and never a score, and a fourth sign that was
named with these, "not one of the usual system services", is left out until
something sourced says what is usual.

    Run from site/: python3 -m pytest app/test_first_look_order.py
"""
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rarely_public_mark import allow, server, sock  # noqa: E402
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)

NOW = trl.NOW

CHANGES = """
CREATE TABLE IF NOT EXISTS finding_changes (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    protocol TEXT NOT NULL, port INTEGER NOT NULL, family TEXT NOT NULL,
    from_state TEXT NOT NULL, to_state TEXT NOT NULL, outside TEXT NOT NULL,
    vantage TEXT, measured_at TEXT, description TEXT NOT NULL,
    outcome TEXT NOT NULL, alert_id INTEGER, seen_at TEXT NOT NULL, settled_at TEXT);
"""


def change(db, name, port, outside, from_state="", to_state="unreviewed", family="v4"):
    """One stored change of one port, as the sweep writes it."""
    con = sqlite3.connect(db)
    con.executescript(CHANGES)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.execute(
        "INSERT INTO finding_changes (host_id, protocol, port, family, from_state,"
        " to_state, outside, description, outcome, seen_at)"
        " VALUES (?, 'tcp', ?, ?, ?, ?, ?, 'x', 'recorded', ?)",
        (host_id, port, family, from_state, to_state, outside, NOW.isoformat()))
    con.commit()
    con.close()


def window_ports(html, name):
    """The ports of one server's first-look window, in the order drawn, as
    [(group heading, port), ...]."""
    start = html.index(f'id="fv-{name}"')
    window = html[start:html.index('<div class="m-foot">', start)]
    out, heading = [], ""
    for piece in re.findall(r'<div class="fv-g">([^<]*)</div>|<div class="fv-r"[^>]*data-port="(\d+)"', window):
        if piece[0]:
            heading = piece[0]
        else:
            out.append((heading, int(piece[1])))
    return out


def row(port, **kw):
    base = dict(protocol="tcp", port=port, word="intended", lit="yes", decided="your rule",
                reach_open=True, state_families=("v4",))
    return build.PortRow(**{**base, **kw})


def waiting(port, **kw):
    return row(port, word="unreviewed", lit="", decided="no rule", **kw)


def order(rows, moved=()):
    return [(entry[0], entry[6]) for entry in rl.first_look_rows(rows, moved)]


# ----------------------------------------------------------------- the order

def test_a_port_no_rule_answers_comes_before_one_a_rule_answers():
    assert order([row(22), waiting(8080)]) == [("waiting", 8080), ("rule", 22)]


def test_within_a_group_a_listed_port_comes_first():
    rows = [waiting(8080), waiting(9000), waiting(27017, rarely=True)]
    assert order(rows) == [("waiting", 27017), ("waiting", 8080), ("waiting", 9000)]
    rows = [row(22), row(443), row(6379, rarely=True)]
    assert order(rows) == [("rule", 6379), ("rule", 22), ("rule", 443)]


def test_a_port_that_has_not_moved_comes_before_one_that_has():
    rows = [waiting(3000), waiting(8080), waiting(9000)]
    assert order(rows, moved={("tcp", 3000)}) == [
        ("waiting", 8080), ("waiting", 9000), ("waiting", 3000)]


def test_the_port_number_settles_the_rest():
    rows = [waiting(9000), waiting(80), waiting(8080)]
    assert order(rows) == [("waiting", 80), ("waiting", 8080), ("waiting", 9000)]


def test_the_four_signs_apply_in_their_order():
    """No rule beats listed, listed beats unmoved, unmoved beats the number."""
    rows = [row(22), row(6379, rarely=True), waiting(8080), waiting(3306, rarely=True),
            waiting(3000), row(443)]
    moved = {("tcp", 3306), ("tcp", 22)}
    assert order(rows, moved) == [
        ("waiting", 3306),    # no rule and listed, although it has moved
        ("waiting", 3000), ("waiting", 8080),
        ("rule", 6379),       # a rule answers it, and it is listed
        ("rule", 443),        # has not moved
        ("rule", 22)]         # has moved


def test_a_port_that_does_not_answer_from_outside_is_not_in_the_window():
    assert order([waiting(8080, reach_open=False), row(22)]) == [("rule", 22)]


def test_udp_and_tcp_on_one_number_are_two_ports_in_a_stable_order():
    rows = [waiting(53, protocol="udp"), waiting(53)]
    assert [(e[5], e[6]) for e in rl.first_look_rows(rows)] == [("tcp", 53), ("udp", 53)]


def test_the_order_does_not_depend_on_the_order_the_rows_arrive_in():
    rows = [row(22), waiting(8080), row(6379, rarely=True), waiting(3000)]
    assert order(rows) == order(list(reversed(rows)))


def test_no_rows_is_an_empty_window():
    assert rl.first_look_rows([]) == []
    assert rl.first_look_rows([], moved={("tcp", 22)}) == []


def test_the_groups_are_drawn_waiting_first():
    assert [key for key, _heading in build.FIRST_LOOK_GROUPS] == ["waiting", "rule"]


def test_the_window_gains_no_word_for_the_order():
    """An order, never a score (docs/PRODUCT.md 6), and no sentence that
    explains it: the headings are the two the window always had."""
    html = build.first_look_modal("box", "box", rl.first_look_rows([waiting(8080), row(22)]), 2)
    assert re.findall(r'<div class="fv-g">([^<]*)</div>', html) == [
        "waiting for you", "answered already"]
    for said in ("forgotten", "score", "risk", "sorted", "priority", "most likely"):
        assert said not in html.lower()


# ------------------------------------------------------------ what has moved

def test_a_port_whose_outside_answer_changed_has_moved(db):
    server(db, "box", [sock(8080, "caddy")], answers=(8080,))
    change(db, "box", 8080, "no_response", from_state="", to_state="not reachable")
    change(db, "box", 8080, "connect_succeeded", from_state="not reachable")
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con) == {"box": {("tcp", 8080)}}
    con.close()


def test_a_first_observation_alone_is_not_a_move(db):
    server(db, "box", [sock(8080, "caddy")], answers=(8080,))
    change(db, "box", 8080, "connect_succeeded")
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con) == {}
    con.close()


def test_an_answer_somebody_gave_is_not_a_move(db):
    """Declaring yes moves the state and leaves the outside view where it
    was, so the port is as unchanged as before the click."""
    server(db, "box", [sock(8080, "caddy")], answers=(8080,))
    change(db, "box", 8080, "connect_succeeded")
    change(db, "box", 8080, "connect_succeeded", from_state="unreviewed", to_state="intended")
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con) == {}
    con.close()


def test_one_family_moving_is_the_port_moving_and_the_other_family_is_its_own(db):
    server(db, "box", [sock(8080, "caddy")], answers=(8080,))
    change(db, "box", 8080, "connect_succeeded", family="v4")
    change(db, "box", 8080, "no_response", family="v6")      # two families, one answer each
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con) == {}
    con.close()
    change(db, "box", 8080, "connect_succeeded", family="v6", from_state="not reachable")
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con) == {"box": {("tcp", 8080)}}
    con.close()


def test_a_database_the_sweep_never_ran_against_has_nothing_moved(db):
    server(db, "box", [sock(8080, "caddy")], answers=(8080,))
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con) == {}
    con.close()
    assert window_ports(rl.render(db, now=NOW), "box") == [("waiting for you", 8080)]


def test_another_workspaces_changes_are_not_read(db):
    con = sqlite3.connect(db)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'w2', 'x')")
    con.commit(); con.close()
    server(db, "mine", [sock(8080, "caddy")], answers=(8080,))
    trl.add_host(db, "theirs", [(NOW, trl.document(listening=[sock(9000, "x")]))],
                 last_report_at=NOW.isoformat(), workspace_id=2)
    change(db, "theirs", 9000, "no_response")
    change(db, "theirs", 9000, "connect_succeeded", from_state="not reachable")
    con = sqlite3.connect(db); con.row_factory = sqlite3.Row
    assert rl.load_moved_ports(con, workspace_id=1) == {}
    assert rl.load_moved_ports(con, workspace_id=2) == {"theirs": {("tcp", 9000)}}
    con.close()


# ------------------------------------------------------------- the live page

def test_the_page_draws_the_window_in_that_order(db):
    doc = trl.document(listening=[sock(22, "sshd"), sock(443, "caddy"), sock(6379, "redis-server"),
                                  sock(3000, "node"), sock(8080, "java"), sock(3306, "mariadbd")])
    doc["nftables"] = allow(22, 443, 6379)
    trl.reporting(db, "box", doc)
    for port in (22, 443, 6379, 3000, 8080, 3306):
        trl.probe_result(db, "box", port, "v4", "connect_succeeded")
    change(db, "box", 3000, "no_response", to_state="not reachable")
    change(db, "box", 3000, "connect_succeeded", from_state="not reachable")
    assert window_ports(rl.render(db, now=NOW), "box") == [
        ("waiting for you", 3306),                   # no rule, and on the list
        ("waiting for you", 8080),                   # no rule, never moved
        ("waiting for you", 3000),                   # no rule, moved once
        ("answered already", 6379),      # a rule, and on the list
        ("answered already", 22),
        ("answered already", 443)]


def test_the_table_under_the_window_keeps_its_own_order(db):
    """The sort is the window's. The port table still reads worst first and
    then by number, as its spec says."""
    doc = trl.document(listening=[sock(22, "sshd"), sock(6379, "redis-server"), sock(8080, "java")])
    doc["nftables"] = allow(22, 6379)
    trl.reporting(db, "box", doc)
    for port in (22, 6379, 8080):
        trl.probe_result(db, "box", port, "v4", "connect_succeeded")
    section = trl.host_section(rl.render(db, now=NOW), "box")
    table = section.split('id="t-box-overview"', 1)[1]
    assert re.findall(r'<label class="pr" for="[^"]*" data-port="(\d+)/tcp"', table) == [
        "8080", "22", "6379"]


def test_load_hands_the_moved_ports_over_after_the_display_names(db):
    server(db, "box", [sock(8080, "caddy")], answers=(8080,))
    change(db, "box", 8080, "no_response")
    change(db, "box", 8080, "connect_succeeded", from_state="not reachable")
    assert rl.load(db, now=NOW)[-2] == {"box": {("tcp", 8080)}}
