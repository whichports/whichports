"""A stale rule is worth seeing and is a decision nobody owes.

The owner agreed on 2026-09-21 to the recommendation put with the numbers from
his own fleet (docs/RECORD.md 4.198). Five of his 59 ports were stale
rules, on two servers, each counted under "Needs a decision" and each turning
its server amber. His hard rule is that nothing should feel like homework,
and a fleet on firewalld's default permits would have opened amber on its
first day (docs/RECORD.md 4.198).

A stale rule is a rule that permits a port nothing listens on
(docs/PRODUCT.md 8a). It stays on its port's row, in grey, with the rule
quoted when the row is opened. It is never the word a server reads, it is in
no count of things to decide, and it never hides a finding that is one.
"""
import pathlib
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
import theme  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def fleet_row(html, name):
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    start = fleet.index(f'data-host="{name}"')
    return fleet[start:fleet.index("</a>", start)]


def a_server_with_only_a_stale_rule(db, name="media-01"):
    trl.reporting(db, name, trl.stale_rule_document())
    trl.probe_result(db, name, 22, "v4", "no_response")


def test_a_server_whose_only_finding_is_a_stale_rule_reads_watched(db):
    a_server_with_only_a_stale_rule(db)
    html = rl.render(db, now=NOW)
    row = fleet_row(html, "media-01")
    assert 'data-state="watched"' in row
    assert theme.status("ok", "watched") in row
    assert "stale" not in row, "no chip and no word for it on the Fleet"


def test_the_rule_is_still_on_its_row_in_grey_with_the_rule_quoted(db):
    a_server_with_only_a_stale_rule(db)
    overview = trl._overview_of(rl.render(db, now=NOW), "media-01")
    assert 'data-port="9200/tcp"' in overview
    assert theme.status("off", "stale rule") in overview
    assert theme.status("warn", "stale rule") not in overview
    assert "dport 9200 counter accept" in overview


def test_it_is_in_no_count_of_things_to_decide(db):
    a_server_with_only_a_stale_rule(db)
    html = rl.render(db, now=NOW)
    overview = trl._overview_of(html, "media-01")
    assert ('<div class="l">Needs a decision</div><div class="n">0</div>'
            '<div class="d">of 2 ports</div>') in overview
    assert "stale rule" not in build.NEEDS_DECISION
    assert "stale rule" not in rl.DECISION_WORDS


def test_a_stale_rule_never_hides_a_finding_that_is_one(db):
    """The reason it moved in the ranking and did not only change colour: a
    server with a stale rule and an unexplained port must read unexplained."""
    order = rl.STATE_SEVERITY
    assert order.index("stale rule") > order.index("unexplained")
    assert order.index("stale rule") > order.index("unreviewed")
    assert order.index("stale rule") > order.index("conflict")
    assert build.fleet_band("stale rule") == build.fleet_band("watched")


def test_a_server_with_a_stale_rule_and_a_port_waiting_reads_the_one_that_waits(db):
    """The same thing on a rendered page, which is where it would go wrong."""
    doc = trl.stale_rule_document()
    doc["sockets"]["listening"].append(
        {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
         "port": 8410, "process_name": "uvicorn", "pid": 4})
    trl.reporting(db, "media-01", doc)
    trl.probe_result(db, "media-01", 8410, "v4", "connect_succeeded")
    row = fleet_row(rl.render(db, now=NOW), "media-01")
    assert 'data-state="unreviewed"' in row
    assert "tcp/8410" in row
    assert "9200" not in row, "the stale rule's port is no chip"


def test_the_alert_rules_did_not_move(db):
    """This is what a screen calls it. A port going stale still means its
    listener went away, and what is mailed about that is the engine's
    business and was not touched (docs/PRODUCT.md 8c)."""
    join = rl.joinbridge.module("join")
    assert "stale rule" in join.STATES


def test_a_stale_rule_row_shows_no_answer_until_it_is_opened(db):
    """Like a port that is not reachable. Its one answer, LATER, and the way
    out beside it, "or remove the rule", wait for the row to be opened."""
    a_server_with_only_a_stale_rule(db)
    overview = trl._overview_of(rl.render(db, now=NOW), "media-01")
    row = overview.split('data-port="9200/tcp"')[1].split("</label>")[0]
    assert 'class="pra quiet"' in row or "pra quiet" in row
    assert build.REMOVE_THE_RULE in row
    assert ".pra.quiet .ans,.pra.quiet .or{visibility:hidden}" in build.CSS
    assert ".prsel:checked+.pr .pra.quiet .or{visibility:visible}" in build.CSS
