"""Which family a port's row leads with, on a server's Overview.

    Run from site/: python3 -m pytest app/test_port_row_lead.py

A finding is per address family and a row is per port, so two findings become
one word. The rule, decided on 2026-10-02 (docs/RECORD.md 4.244) and stated in
docs/DESIGN.md section 3 and docs/screens/host-overview/SPEC.md:

- while a family asks for something (conflict, unreviewed, unexplained), the
  worse family wins, as it always did
- where neither asks, a family that answered from outside leads over one that
  did not, and the other family keeps its own mark

The two cases it was decided on are the first two tests. A web server that
listens on v4 alone behind a firewall rule for both families read STALE RULE
with "nothing bound on v6" as its service (4.203). A port open to every IPv4
address and silent on IPv6 read NOT REACHABLE, and the Changed box said it
"became not reachable" (4.237).
"""
import pathlib
import re
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import render_live as rl  # noqa: E402
from test_render_live import (  # noqa: E402
    NOW, db, declare_intent, document, probe_result, reporting)

__all__ = ["db"]


# ------------------------------------------------------------ the fixtures

def sock(port, family="v4", process="nginx"):
    return {"protocol": "tcp", "family": family,
            "bind_address": "0.0.0.0" if family == "v4" else "::",
            "port": port, "process_name": process, "pid": port}


def _rule(text):
    return {"text": text, "rendered": "full", "comment": ""}


def ufw_tables(v4_ports=(), v6_ports=()):
    """ufw's two tables, each with the permits `ufw allow` writes for it."""
    def one(family, prefix, match, ports):
        return {"family": family, "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop", "rules": [_rule(f"counter jump {prefix}-user-input")]},
            {"name": f"{prefix}-user-input",
             "rules": [_rule(f"{match} tcp tcp dport {port} counter accept")
                       for port in ports]}]}
    return {"status": "collected", "tables": [
        one("ip", "ufw", "ip protocol", v4_ports),
        one("ip6", "ufw6", "meta l4proto", v6_ports)]}


def box(db, listening, v4_ports=(), v6_ports=()):
    doc = document(listening=listening)
    doc["nftables"] = ufw_tables(v4_ports, v6_ports)
    reporting(db, "box", doc)


def row_of(db, port):
    """The closed row of one port on the server's Overview, as it is drawn."""
    html = rl.render(db, now=NOW)
    page = html.split('id="host-box"', 1)[1].split('<div class="wrap view"', 1)[0]
    return page.split(f'data-port="{port}/tcp"', 1)[1].split("</label>", 1)[0]


def word_of(row):
    state = re.search(r'<span class="prst">(.*?)</span><span class="prn">', row, re.S).group(1)
    return re.sub(r"<[^>]+>", "", state).strip()


def service_of(row):
    cell = re.search(r'<span class="prs(?: note)?">(.*?)</span>', row, re.S).group(1)
    return re.sub(r"<small.*", "", cell, flags=re.S)


def decided_of(row):
    return re.search(r'<span class="prw">(.*?)</span>', row, re.S).group(1)


def marks_of(row):
    return re.search(r'<span class="prf"><i class="([a-z]*)">v4</i><i class="([a-z]*)">v6</i>', row).groups()


# ----------------------------------------------- the two cases it was decided on

def test_a_port_served_on_v4_with_a_stale_rule_on_v6_leads_with_v4(db):
    """nginx listens on 0.0.0.0 alone, ufw allows both families, the probers
    connect on v4 and are refused on v6. The engine says intended on v4 and
    stale rule on v6, both true. The row used to show the v6 half."""
    box(db, [sock(80)], v4_ports=(80,), v6_ports=(80,))
    probe_result(db, "box", 80, "v4", "connect_succeeded")
    probe_result(db, "box", 80, "v6", "connect_refused")

    row = row_of(db, 80)
    assert word_of(row) == "intended"
    assert service_of(row) == "nginx"
    assert "nothing bound on" not in row
    assert decided_of(row) == "your rule"
    # The other family keeps its own mark: v4 in the answer's colour, v6 with
    # none, which is how a stale rule is marked.
    assert marks_of(row) == ("ok", "")


def test_a_port_that_answers_on_v4_and_is_silent_on_v6_leads_with_v4(db):
    """A listener on both families, a permit for v4 alone, the probers connect
    on v4 and get no response on v6: intended on v4, not reachable on v6. The
    first screen a person looks at said NOT REACHABLE."""
    box(db, [sock(8080), sock(8080, "v6")], v4_ports=(8080,))
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    probe_result(db, "box", 8080, "v6", "no_response")

    row = row_of(db, 8080)
    assert word_of(row) == "intended"
    assert service_of(row) == "nginx"
    assert decided_of(row) == "your rule"
    assert marks_of(row) == ("ok", "ok")


def test_the_mirror_leads_with_v6(db):
    box(db, [sock(8080), sock(8080, "v6")], v6_ports=(8080,))
    probe_result(db, "box", 8080, "v4", "no_response")
    probe_result(db, "box", 8080, "v6", "connect_succeeded")
    row = row_of(db, 8080)
    assert word_of(row) == "intended"
    assert decided_of(row) == "your rule"


# ------------------------------------------- a family that asks still wins

def test_a_family_that_asks_for_a_decision_is_not_hidden_behind_one_that_answers(db):
    """v4 is intended by a rule, v6 answers with no rule at all. The row is
    unreviewed, as before: the rule that an answer leads applies only where
    nobody is asked anything."""
    box(db, [sock(8080), sock(8080, "v6")], v4_ports=(8080,))
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    probe_result(db, "box", 8080, "v6", "connect_succeeded")
    row = row_of(db, 8080)
    assert word_of(row) == "unreviewed"
    assert decided_of(row) == "no rule"


def test_a_conflict_on_one_family_is_not_hidden_behind_an_intended_on_the_other(db):
    """Declared closed on v6 and answering there, intended on v4. The reason
    the worse family wins was always this row."""
    box(db, [sock(8080), sock(8080, "v6")], v4_ports=(8080,), v6_ports=(8080,))
    declare_intent(db, "box", "tcp", 8080, "v6", "closed")
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    probe_result(db, "box", 8080, "v6", "connect_succeeded")
    assert word_of(row_of(db, 8080)) == "conflict"


# ------------------------------------------------ nothing answers: as it was

def test_two_quiet_families_with_no_answer_read_as_they_did(db):
    """Not reachable on v4 and a stale rule on v6, neither answering. No
    family leads by answering, so the fleet's order decides as before and the
    row says stale rule. The loopback case of docs/RECORD.md 4.210 is this
    shape, and it is left for its own decision."""
    box(db, [sock(3032)], v4_ports=(3032,), v6_ports=(3032,))
    probe_result(db, "box", 3032, "v4", "connect_refused")
    probe_result(db, "box", 3032, "v6", "connect_refused")
    row = row_of(db, 3032)
    assert word_of(row) == "stale rule"
    assert decided_of(row) == "your rule", "stale rule beside it says what is behind it"


def test_one_family_alone_reads_as_it_did(db):
    box(db, [sock(8080)], v4_ports=(8080,))
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    assert word_of(row_of(db, 8080)) == "intended"


# ------------------------------------------------------------ the rule itself

ANSWERS = "answers"
SILENT = "silent"


@pytest.mark.parametrize("v4, v6, word, lead", [
    # One family answers and nobody asks: it leads.
    (("intended", ANSWERS), ("stale rule", SILENT), "intended", "v4"),
    (("intended", ANSWERS), ("not reachable", SILENT), "intended", "v4"),
    (("stale rule", SILENT), ("intended", ANSWERS), "intended", "v6"),
    (("not reachable", SILENT), ("intended", ANSWERS), "intended", "v6"),
    # Both answer: v4 is named first, as families always are.
    (("intended", ANSWERS), ("intended", ANSWERS), "intended", "v4"),
    # Somebody asks: the worse family, whatever answered.
    (("intended", ANSWERS), ("unreviewed", ANSWERS), "unreviewed", "v6"),
    (("intended", ANSWERS), ("conflict", ANSWERS), "conflict", "v6"),
    (("intended", ANSWERS), ("conflict", SILENT), "conflict", "v6"),
    (("unexplained", ANSWERS), ("intended", ANSWERS), "unexplained", "v4"),
    (("conflict", SILENT), ("unreviewed", ANSWERS), "conflict", "v4"),
    # Nobody answers: the fleet's order, as before.
    (("not reachable", SILENT), ("stale rule", SILENT), "stale rule", "v6"),
    (("stale rule", SILENT), ("stale rule", SILENT), "stale rule", "v4"),
    # Intended because it was declared closed and is silent: it did not
    # answer, so it does not lead.
    (("intended", SILENT), ("stale rule", SILENT), "stale rule", "v6"),
    (("intended", SILENT), ("not reachable", SILENT), "not reachable", "v6"),
    # One family with no state at all.
    (("intended", ANSWERS), (None, SILENT), "intended", "v4"),
    ((None, SILENT), ("stale rule", SILENT), "stale rule", "v6"),
    ((None, SILENT), (None, SILENT), "", None),
])
def test_the_word_and_the_family_it_comes_from(v4, v6, word, lead):
    states = {family: state for family, (state, _) in (("v4", v4), ("v6", v6)) if state}
    answered = {"v4": v4[1] == ANSWERS, "v6": v6[1] == ANSWERS}
    assert rl.port_row_word(states, answered) == (word, lead)


def test_the_fleets_own_ranking_is_untouched():
    """The exception is for a port's row. The one ranking the Fleet sorts
    servers by keeps the quiet states above intended."""
    assert rl.STATE_SEVERITY == ("conflict", "unreviewed", "unexplained",
                                 "stale rule", "not reachable", "intended")
    assert rl.worst_state({"intended": True, "stale rule": True}) == "stale rule"


# ------------------------------------------------------- the Changed in 24h line

def _change(port, family, outside, minutes_ago):
    return {"protocol": "tcp", "port": port, "family": family, "outside": outside,
            "seen_at": (NOW - timedelta(minutes=minutes_ago)).isoformat()}


def _moved(rows):
    changed = {("box", row["protocol"], row["port"]) for row in rows}
    # newest first, as load_finding_changes hands them over
    ordered = sorted(rows, key=lambda row: row["seen_at"], reverse=True)
    return rl.changed_ports("box", ordered, changed, NOW - timedelta(hours=24))


def test_a_port_that_began_answering_on_v4_became_reachable(db):
    """The measured case: v4 connected at 15:09:02 and v6 was silent five
    seconds later. The newest row was v6's, and the box said "became not
    reachable" about a port that had just opened to every IPv4 address."""
    rows = [_change(8080, "v4", "connect_succeeded", 10),
            _change(8080, "v6", "no_response", 9)]
    assert _moved(rows) == [("tcp", 8080, True, ("v4",))]


def test_a_family_that_stopped_answering_is_read_from_its_newest_row(db):
    """v4 answered an hour ago and stopped ten minutes ago. Its older row
    must not make the port read as reachable."""
    rows = [_change(8080, "v4", "connect_succeeded", 60),
            _change(8080, "v4", "no_response", 10)]
    assert _moved(rows) == [("tcp", 8080, False, ("v4",))]


def test_a_port_that_went_silent_on_both_families_became_not_reachable(db):
    rows = [_change(8080, "v4", "no_response", 10),
            _change(8080, "v6", "connect_refused", 9)]
    assert _moved(rows) == [("tcp", 8080, False, ("v4", "v6"))]


def test_two_ports_keep_their_order_newest_first(db):
    rows = [_change(8080, "v4", "connect_succeeded", 30),
            _change(22, "v4", "no_response", 5),
            _change(8080, "v6", "no_response", 29)]
    assert _moved(rows) == [("tcp", 22, False, ("v4",)), ("tcp", 8080, True, ("v4",))]


def test_a_row_that_names_no_family_is_read_as_before(db):
    """An older row shape, with no family on it: the newest row decides."""
    rows = [{"protocol": "tcp", "port": 8080, "outside": "connect_succeeded",
             "seen_at": (NOW - timedelta(minutes=10)).isoformat()}]
    assert _moved(rows) == [("tcp", 8080, True, ())]


def test_a_change_older_than_the_window_or_not_measured_is_left_out(db):
    rows = [_change(8080, "v4", "connect_succeeded", 60 * 25),
            _change(9090, "v4", "not_tested", 5)]
    assert _moved(rows) == []


# ------------------------------------------------- the Services tab's tag
#
# The Services tab takes each port's word from the Overview's row
# (`service_groups`), so that the two tabs cannot disagree about one port.
# So the tag on a service follows the row: the test fleet saw a running
# service tagged STALE RULE for its one port, served on v4 with a stale rule
# on v6 (docs/RECORD.md 4.210), and that tag was the row's old word.

def _service_rows(db):
    html = rl.render(db, now=NOW)
    page = html.split('id="host-box"', 1)[1]
    panel = page.split('id="t-box-services"', 1)[1].split('<div class="tab', 1)[0]
    rows = {}
    for row in panel.split('<div class="srow">')[1:]:
        name = re.search(r'<span class="snm"><b>(.*?)</b>', row, re.S).group(1)
        state = re.search(r'<span class="sst">(.*?)</span><span class="snm">', row, re.S).group(1)
        rows[name] = re.sub(r"<[^>]+>", "", state).strip()
    return rows


def test_a_service_answering_on_v4_is_not_tagged_with_its_v6_stale_rule(db):
    box(db, [sock(80)], v4_ports=(80,), v6_ports=(80,))
    probe_result(db, "box", 80, "v4", "connect_succeeded")
    probe_result(db, "box", 80, "v6", "connect_refused")
    assert _service_rows(db)["nginx"] == "intended"


def test_a_service_with_one_quiet_port_and_one_answering_keeps_the_worse_tag(db):
    """Across a service's ports the fleet's ranking still decides, as it does
    for a server: one port with a stale rule and nothing answering on it is
    the tag, beside a port that answers. The row rule is about the two
    families of one port, not about two ports."""
    box(db, [sock(80), sock(3032)], v4_ports=(80, 3032), v6_ports=(80, 3032))
    probe_result(db, "box", 80, "v4", "connect_succeeded")
    probe_result(db, "box", 80, "v6", "connect_refused")
    probe_result(db, "box", 3032, "v4", "connect_refused")
    probe_result(db, "box", 3032, "v6", "connect_refused")
    assert _service_rows(db)["nginx"] == "stale rule"


# ------------------------------------------- the line names the family

def _line(db):
    html = rl.render(db, now=NOW)
    page = html.split('id="host-box"', 1)[1].split('<div class="wrap view"', 1)[0]
    # The box is a few short cells: its title, the count, the line under it.
    text = re.sub(r"<[^>]+>", " ", page.split("Changed in 24h", 1)[1][:600])
    return " ".join(text.split())[:80]


def _transition(db, port, family, outside, minutes_ago):
    import sqlite3
    from test_render_live import transition
    when = NOW - timedelta(minutes=minutes_ago)
    transition(db, "box", "tcp", port, family, "none", "x", "told", seen_at=when)
    con = sqlite3.connect(db)
    con.execute("UPDATE finding_changes SET outside = ? WHERE id ="
                " (SELECT MAX(id) FROM finding_changes)", (outside,))
    con.commit()
    con.close()


def test_one_family_going_silent_is_said_of_that_family(db):
    """v4 answers as it has for weeks, v6 went silent today. The port did not
    become not reachable: v6 did, and the row above the line reads intended."""
    box(db, [sock(8080), sock(8080, "v6")], v4_ports=(8080,))
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    probe_result(db, "box", 8080, "v6", "no_response")
    _transition(db, 8080, "v6", "no_response", 30)
    assert "8080/tcp became not reachable on v6" in _line(db)


def test_both_families_moving_the_same_way_names_neither(db):
    box(db, [sock(8080), sock(8080, "v6")])
    probe_result(db, "box", 8080, "v4", "no_response")
    probe_result(db, "box", 8080, "v6", "no_response")
    _transition(db, 8080, "v4", "no_response", 30)
    _transition(db, 8080, "v6", "no_response", 29)
    line = _line(db)
    assert "8080/tcp became not reachable" in line
    assert " on v" not in line


def test_a_port_measured_on_one_family_names_none(db):
    """A server with one family measured has nothing to tell apart."""
    box(db, [sock(8080)], v4_ports=(8080,))
    probe_result(db, "box", 8080, "v4", "connect_succeeded")
    _transition(db, 8080, "v4", "connect_succeeded", 30)
    line = _line(db)
    assert "8080/tcp became reachable" in line
    assert " on v" not in line
