"""A port's card on the Overview names every vantage that measured it, each
with its own result and its own time (docs/RECORD.md 4.393, the vantages).

The Evidence tab said "vantages probe1, probe2" while every card named the
one vantage whose measurement was the newest, so the other read as a prober
that measured nothing. The prober line now names each vantage that measured
the port. A time stands once where it is every vantage's own, and beside each
name where they differ: a number on a screen comes from the measurement that
produced it. Where two vantages found different things the line says what
each found, and the state stays the engine's.

    Run from site/: python3 -m pytest app/test_card_names_every_vantage.py
"""
import html as html_mod
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
YES, SHUT, REFUSED = "connect_succeeded", "no_response", "connect_refused"
OTHER_ADDRESS = "185.199.108.154"


def minutes(n):
    return NOW - timedelta(minutes=n)


@pytest.fixture()
def db(tmp_path):
    """One reporting server with sshd on v4, and two vantages in the registry."""
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "box"
    trl.reporting(path, "box", doc)
    registry = rl.joinbridge.module("vantages")
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    registry.init(con)
    registry.add(con, "probe1", "root@probe1", ["185.199.110.1"])
    registry.add(con, "probe2", "root@probe2", ["185.199.110.2"])
    con.close()
    return path


def measured(db, vantage, state, minutes_ago):
    trl.probe_result(db, "box", 22, "v4", state, vantage=vantage,
                     measured_at=minutes(minutes_ago))


def text_of(html):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S))
    return " ".join(html_mod.unescape(bare).split()).replace(" ,", ",")


def card(db, family="v4"):
    """The lines of port 22's card for one family, label to words, and its
    lead under "lead"."""
    html = rl.render(db, now=NOW)
    part = html.split('id="t-box-overview"', 1)[1].split('for="pr-box-tcp-22"', 1)[1]
    part = part.split("</label>", 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]
    for one in part.split('<div class="prec">')[1:]:
        head = text_of(one.split('class="preh">', 1)[1].split('<span class="lead">', 1)[0])
        if head != family:
            continue
        lines = dict(re.findall(
            r'<span class="k">([a-z]+)</span><span class="v">(.*?)</span></div>', one, re.S))
        return {"lead": text_of(one.split('<span class="lead">', 1)[1].split("</span>", 1)[0]),
                **{k: text_of(v) for k, v in lines.items()}}
    raise AssertionError(f"no {family} card")


def finding(db):
    join = rl.joinbridge.load()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'box'").fetchone()[0]
    found = join.host_findings(con, host_id).findings
    con.close()
    return next(f for f in found if (f.port, f.family) == (22, "v4"))


# ------------------------------------------------------- they found the same

def test_two_vantages_that_connected_at_the_same_time_are_both_named_with_one_time(db):
    measured(db, "probe1", YES, 12)
    measured(db, "probe2", YES, 12)

    assert card(db)["prober"] == "connected from probe1, probe2, 12m ago"


def test_two_vantages_that_connected_at_different_times_each_carry_their_own(db):
    """The measured case: probe1 fourteen minutes ago, probe2 twelve."""
    measured(db, "probe1", YES, 14)
    measured(db, "probe2", YES, 12)

    assert card(db)["prober"] == "connected from probe1 14m ago, probe2 12m ago"


def test_no_time_on_the_line_is_another_vantages(db):
    measured(db, "probe1", YES, 26)
    measured(db, "probe2", YES, 12)
    line = card(db)["prober"]

    assert "probe1 26m ago" in line and "probe2 12m ago" in line
    assert line.count("ago") == 2


def test_two_vantages_that_got_no_answer_are_both_named(db):
    measured(db, "probe1", SHUT, 14)
    measured(db, "probe2", SHUT, 12)

    assert card(db)["prober"] == "no answer from probe1 14m ago, probe2 12m ago"


def test_two_vantages_that_were_refused_are_both_named(db):
    measured(db, "probe1", REFUSED, 12)
    measured(db, "probe2", REFUSED, 12)

    assert card(db)["prober"] == "refused from probe1, probe2, 12m ago"


def test_times_that_read_the_same_stand_once(db):
    """Thirty seconds apart, both read 12m: one time is each one's own."""
    trl.probe_result(db, "box", 22, "v4", YES, vantage="probe1",
                     measured_at=NOW - timedelta(minutes=12, seconds=40))
    trl.probe_result(db, "box", 22, "v4", YES, vantage="probe2",
                     measured_at=NOW - timedelta(minutes=12, seconds=10))

    assert card(db)["prober"] == "connected from probe1, probe2, 12m ago"


# ------------------------------------------------------ they found otherwise

def test_vantages_that_disagree_each_say_their_own_result_and_time(db):
    measured(db, "probe1", YES, 14)
    measured(db, "probe2", SHUT, 12)

    assert card(db)["prober"] == "connected from probe1 14m ago, no answer from probe2 12m ago"


def test_vantages_that_disagree_at_the_same_time_share_the_time(db):
    measured(db, "probe1", YES, 12)
    measured(db, "probe2", SHUT, 12)

    assert card(db)["prober"] == "connected from probe1, no answer from probe2, 12m ago"


def test_a_refusal_against_a_silence_names_both(db):
    measured(db, "probe1", SHUT, 12)
    measured(db, "probe2", REFUSED, 12)

    assert card(db)["prober"] == "no answer from probe1, refused from probe2, 12m ago"


def test_the_newer_silence_does_not_take_the_line_from_the_connect(db):
    """The engine's answer is the connect. The line still says what the
    newer vantage found, in its own words."""
    measured(db, "probe1", SHUT, 5)
    measured(db, "probe2", YES, 30)

    assert card(db)["prober"] == "no answer from probe1 5m ago, connected from probe2 30m ago"


def test_the_state_and_the_lead_stay_the_engines_when_vantages_disagree(db):
    measured(db, "probe1", YES, 14)
    measured(db, "probe2", SHUT, 12)
    found = finding(db)

    assert found.outside.disagree is True
    assert found.outside.connected is True
    assert found.state == "unreviewed"
    assert card(db)["lead"] == "reachable, no rule permits it"


# ------------------------------------------------------- what stays as it was

def test_one_vantage_reads_as_it_did(db):
    measured(db, "probe1", YES, 12)

    assert card(db)["prober"] == "connected from probe1, 12m ago"


def test_a_vantage_that_measured_nothing_is_not_named(db):
    """Its newest row is a refusal to probe, which is no measurement."""
    measured(db, "probe1", YES, 12)
    measured(db, "probe2", "not_tested", 5)

    assert card(db)["prober"] == "connected from probe1, 12m ago"


def test_a_vantage_switched_off_is_not_named(db):
    """The engine leaves its old rows out, so the card names what is left."""
    measured(db, "probe1", YES, 12)
    measured(db, "probe2", SHUT, 40)
    registry = rl.joinbridge.module("vantages")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    registry.set_enabled(con, "probe2", False)
    con.commit()
    con.close()

    assert card(db)["prober"] == "connected from probe1, 12m ago"


def test_a_port_nothing_probed_still_says_not_tested(db):
    assert card(db)["prober"] == "not tested, no probe result"


def test_a_server_probed_on_two_addresses_keeps_the_one_resolved_line(db):
    """Two addresses of one family give a vantage two measurements. Which of
    them is the vantage's own answer is the engine's to say, so the line stays
    the engine's one resolved answer, as before."""
    measured(db, "probe1", YES, 14)
    measured(db, "probe2", YES, 12)
    con = sqlite3.connect(db)
    run = con.execute("SELECT id FROM probe_runs WHERE vantage = 'probe1'").fetchone()[0]
    con.execute(
        "INSERT INTO probe_results (run_id, family, target, port, state, reason,"
        " connect_ms, os_errno, measured_at) VALUES (?, 'v4', ?, 22, ?, NULL, 1.0, NULL, ?)",
        (run, OTHER_ADDRESS, SHUT, minutes(9).isoformat()))
    con.commit()
    con.close()

    assert card(db)["prober"] == "connected from probe2, 12m ago"


def test_the_card_names_the_vantages_the_evidence_tab_names(db):
    """What the sweep saw: two names on one tab, one on the other."""
    measured(db, "probe1", YES, 14)
    measured(db, "probe2", YES, 12)
    html = rl.render(db, now=NOW)
    evidence = text_of(html.split('id="t-box-evidence"', 1)[1].split('id="t-box-', 1)[0])

    assert "vantages probe1, probe2" in evidence
    assert "probe1" in card(db)["prober"] and "probe2" in card(db)["prober"]
