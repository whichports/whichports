"""The Overview of a Docker port that answered an address its host rule does
not permit (docs/PRODUCT.md 8d, docs/RECORD.md 4.358).

The engine calls such a port `unreviewed` and says which `unreviewed` it is
in one field, `answered_outside_the_rules_source`. The words every other
unreviewed port gets would be untrue here: "reachable, no rule permits it"
and "no rule", where the provider's rule does permit it. So the row and the
card have words of their own, and they read that one field and work nothing
out themselves.

The server is the one this was measured on (4.309), rebuilt from what its
page said: Docker publishing 8080 on both families, ufw permitting 8080 from
one address, the provider's firewall permitting it from everywhere, both
probers connected over v4 and neither got an answer over v6.

    Run from site/: python3 -m pytest app/test_overview_skipped_narrowing_rule.py
"""
import dataclasses
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
import test_integrations_live as til  # noqa: E402

NOW = trl.NOW
SOURCE_RULE = "ip saddr 203.0.113.7 ip protocol tcp tcp dport 8080 counter accept"
SSH_RULE = "ip protocol tcp tcp dport 22 counter accept"
LEAD = "reachable, your firewall rule permits less"
DECIDED = "your rules differ"


def docker_socket(family):
    return {"protocol": "tcp", "family": family, "port": 8080, "pid": 80,
            "bind_address": "0.0.0.0" if family == "v4" else "::",
            "process_name": "docker-proxy"}


def ufw_table(family, rules):
    """ufw's shape in the kernel: the base chain jumps, the rules a person
    wrote sit one chain down."""
    return {"family": family, "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
         "policy": "drop",
         "rules": [{"text": "counter jump ufw-user-input", "rendered": "full"}]},
        {"name": "ufw-user-input",
         "rules": [{"text": text, "rendered": "full"} for text in rules]}]}


def document(host_rules=(SSH_RULE, SOURCE_RULE)):
    doc = trl.document(listening=[trl.SSHD, trl.SSHD6, docker_socket("v4"),
                                  docker_socket("v6")])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [
        ufw_table("ip", host_rules),
        ufw_table("ip6", ["meta l4proto tcp tcp dport 22 counter accept"])]}
    doc["containers"] = {"status": "collected", "docker": [
        {"name": "office", "ports": [
            {"host_ip": ip, "host_port": 8080, "container_port": 8080, "protocol": "tcp"}
            for ip in ("0.0.0.0", "::")]}]}
    return doc


def provider_rule(port):
    return {"direction": "in", "protocol": "tcp", "port": str(port), "description": "",
            "source_ips": ["0.0.0.0/0", "::/0"], "destination_ips": []}


def measured_server(db, host_rules=(SSH_RULE, SOURCE_RULE), provider=True, v6_answers=False):
    """The server as it was measured, in a database a page can be drawn from."""
    trl.reporting(db, "box", document(host_rules))
    if provider:
        til.connect_project(
            db, "project-token-" + "a" * 50, server_id=1, server_name="box",
            ipv4="203.0.113.5", minutes_ago=12, attached=[3],
            firewalls=[{"id": 3, "name": "fw-box",
                        "applied_to": [{"type": "server", "server": {"id": 1}}],
                        "rules": [provider_rule(22), provider_rule(8080)]}])
    registry = rl.joinbridge.module("vantages")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    registry.init(con)
    registry.add(con, "probe1", "root@probe1", ["185.199.110.1", "2606:50c0:8000::1"])
    registry.add(con, "probe2", "root@probe2", ["185.199.110.2", "2606:50c0:8000::2"])
    con.close()
    then = NOW - timedelta(minutes=1)
    for vantage in ("probe1", "probe2"):
        for family in ("v4", "v6"):
            trl.probe_result(db, "box", 22, family, "connect_succeeded",
                             vantage=vantage, measured_at=then)
        trl.probe_result(db, "box", 8080, "v4", "connect_succeeded",
                         vantage=vantage, measured_at=then)
        trl.probe_result(db, "box", 8080, "v6",
                         "connect_succeeded" if v6_answers else "no_response",
                         vantage=vantage, measured_at=then)


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def text_of(html):
    """The words a browser would show: tags gone, entities read."""
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S))
    return " ".join(html_mod.unescape(bare).split())


def overview(html):
    return html.split('id="t-box-overview"', 1)[1].split('<div class="tab k-services"', 1)[0]


def row(html, port):
    """One port's row on the Overview: its cells, and its cards by family."""
    part = overview(html).split(f'for="pr-box-tcp-{port}"', 1)[1]
    label, rest = part.split("</label>", 1)
    rest = rest.split('<input type="checkbox" class="prsel"', 1)[0]
    cell = lambda cls: text_of(re.search(  # noqa: E731
        rf'<span class="{cls}[^"]*"[^>]*>(.*?)</span>', label, re.S).group(1))
    cards = {}
    for card in rest.split('<div class="prec">')[1:]:
        family = text_of(card.split('class="preh">', 1)[1].split('<span class="lead">', 1)[0])
        lines = dict(re.findall(
            r'<span class="k">([a-z]+)</span><span class="v">(.*?)</span></div>', card, re.S))
        cards[family] = {
            "lead": text_of(card.split('<span class="lead">', 1)[1].split("</span>", 1)[0]),
            **{k: text_of(v) for k, v in lines.items()}}
    return {"state": cell("prst"), "decided": cell("prw"),
            "answers": text_of("<span" + label.split('<span class="pra', 1)[1]),
            "cards": cards}


def findings(db, port=8080):
    """The engine's own findings for one port of the server, by family."""
    join = rl.joinbridge.load()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'box'").fetchone()[0]
    found = join.host_findings(con, host_id).findings
    con.close()
    return {f.family: f for f in found if (f.protocol, f.port) == ("tcp", port)}


# --------------------------------------------------------------- the measured case

def test_the_engine_marks_this_port_and_no_other_on_the_server(db):
    """What the rest of this file rests on."""
    measured_server(db)
    assert findings(db)["v4"].state == "unreviewed"
    assert findings(db)["v4"].answered_outside_the_rules_source is True
    assert findings(db)["v6"].answered_outside_the_rules_source is False
    assert findings(db, 22)["v4"].answered_outside_the_rules_source is False


def test_the_row_reads_unreviewed_with_its_own_decided_by_words(db):
    measured_server(db)
    got = row(rl.render(db, now=NOW), 8080)

    assert got["state"] == "unreviewed"
    assert got["decided"] == DECIDED
    assert got["answers"] == "yes no later"


def test_the_card_leads_with_its_own_words_and_quotes_both_rules(db):
    measured_server(db)
    card = row(rl.render(db, now=NOW), 8080)["cards"]["v4"]

    assert card["lead"] == LEAD
    assert card["firewall"].startswith(SOURCE_RULE)
    assert "8080" in card["provider"] and "0.0.0.0/0" in card["provider"]
    assert card["agent"] == "docker container office publishes it on 0.0.0.0"
    assert card["prober"].startswith("connected")


def test_the_server_counts_one_port_that_needs_a_decision(db):
    measured_server(db)
    said = text_of(overview(rl.render(db, now=NOW)).split('class="panel ptbl"', 1)[0])

    assert "Needs a decision 1 of" in said


def test_the_first_look_window_says_what_the_row_says(db):
    """It lists the same port under the ports that wait, and used to put "no
    rule" beside every one of those."""
    measured_server(db)
    html = rl.render(db, now=NOW)
    window = text_of(html.split('id="fv-box"', 1)[1].split('class="m-foot"', 1)[0])
    # The two headings are drawn in capitals by the stylesheet.
    waiting, answered = re.split("answered already", window.lower(), 1)
    waiting = waiting.split("waiting for you", 1)[1]

    assert "8080" in waiting and "office" in waiting
    assert DECIDED in waiting
    assert "22" in answered and "your rule" in answered
    assert "no rule" not in window


def test_the_window_keeps_no_rule_for_a_port_no_rule_permits(db):
    measured_server(db, provider=False)
    html = rl.render(db, now=NOW)
    window = text_of(html.split('id="fv-box"', 1)[1].split('class="m-foot"', 1)[0])

    assert "8080" in window and "no rule" in window
    assert DECIDED not in window


def test_every_other_unreviewed_port_keeps_no_rule_permits_it(db):
    """The same server with no provider connected: the port is `unreviewed`
    because a narrowed rule is no answer, as it always was, and it keeps the
    words it always had."""
    measured_server(db, provider=False)
    got = row(rl.render(db, now=NOW), 8080)

    assert got["state"] == "unreviewed"
    assert got["decided"] == "no rule"
    assert got["cards"]["v4"]["lead"] == "reachable, no rule permits it"


def test_a_port_the_rule_permits_for_everyone_keeps_your_rule(db):
    measured_server(db)
    got = row(rl.render(db, now=NOW), 22)

    assert got["state"] == "intended"
    assert got["decided"] == "your rule"
    assert got["cards"]["v4"]["lead"] == "reachable, your rule permits it"


def test_the_other_family_keeps_its_own_mark_and_its_own_card(db):
    """Where v6 answers too: the host's rule is about v4, so v6 is `intended`
    by the provider's rule, on a row that asks because v4 does."""
    measured_server(db, v6_answers=True)
    got = row(rl.render(db, now=NOW), 8080)

    assert got["state"] == "unreviewed"
    assert got["decided"] == DECIDED
    assert got["cards"]["v4"]["lead"] == LEAD
    assert got["cards"]["v6"]["lead"] == "reachable, your rule permits it"
    assert findings(db)["v6"].state == "intended"


def test_the_other_family_that_did_not_answer_says_so(db):
    """As measured: nothing answered over v6."""
    measured_server(db)
    got = row(rl.render(db, now=NOW), 8080)

    assert got["cards"]["v6"]["lead"] == "not reachable, no answer"


@pytest.mark.parametrize("word", ["skipped", "bypass", "went round", "not reached",
                                  "never met"])
def test_no_screen_says_skipped_bypassed_or_not_reached_about_the_rule(db, word):
    """The engine does not walk the path a forwarded packet takes, so nothing
    on the Fleet or the Overview says where the packet went."""
    measured_server(db)
    html = rl.render(db, now=NOW)
    fleet = html.split('id="fleet"', 1)[1].split('class="view', 1)[0]

    assert word not in text_of(overview(html)).lower()
    assert word not in text_of(fleet).lower()


def test_the_screens_read_the_typed_field_and_work_nothing_out(db):
    """The same finding with the field turned off gets the words of any
    unreviewed port, and with it on gets these. Nothing else is looked at."""
    measured_server(db)
    doc = document()
    marked = findings(db)["v4"]
    plain = dataclasses.replace(marked, answered_outside_the_rules_source=False)

    def said(finding):
        _family, _tone, lead, _lines = rl._card("v4", finding, doc, 8080, NOW, False)
        port_row = rl.host_port_row("box", ("tcp", 8080), {"v4": finding}, doc,
                                    {}, {}, None, frozenset(), NOW, False)
        return lead, port_row.decided

    assert said(marked) == (LEAD, DECIDED)
    assert said(plain) == ("reachable, no rule permits it", "no rule")
