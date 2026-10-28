"""The provider card on a server's Evidence counts the rules the Rules tab
lists for that provider (docs/RECORD.md 4.393, C10).

It said "1 inbound rules" beside a Rules tab that listed two, one in and one
out. The number was neither tab's: it counted the provider rules that matched
a port the page had a finding for. It is now counted from the stored firewall,
the way the Rules tab counts, and one rule is "1 rule".

    Run from site/: python3 -m pytest app/test_evidence_provider_rule_count.py
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
import test_integrations_live as til  # noqa: E402

NOW = trl.NOW


def rule(direction, protocol, port):
    everyone = ["0.0.0.0/0", "::/0"]
    return {"direction": direction, "protocol": protocol, "port": port, "description": "",
            "source_ips": everyone if direction == "in" else [],
            "destination_ips": everyone if direction == "out" else []}


IN_22 = rule("in", "tcp", "22")
OUT_443 = rule("out", "tcp", "443")
# No port, and a port the server has no socket on: neither has a finding.
IN_ICMP = rule("in", "icmp", None)
IN_RANGE = rule("in", "udp", "40000-40100")
MANY = [IN_22, OUT_443, IN_ICMP, IN_RANGE, rule("in", "tcp", "443")]


def server(db, *firewalls):
    """One reporting server the provider lists, with these firewalls on it,
    each a list of rules."""
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "box"
    trl.reporting(db, "box", doc)
    trl.probe_result(db, "box", 22, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=5))
    ids = list(range(3, 3 + len(firewalls)))
    til.connect_project(
        db, "project-token-" + "a" * 50, server_id=1, server_name="box",
        ipv4="203.0.113.5", minutes_ago=12, attached=ids,
        firewalls=[{"id": fid, "name": f"fw-{fid}",
                    "applied_to": [{"type": "server", "server": {"id": 1}}],
                    "rules": rules} for fid, rules in zip(ids, firewalls)])


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def text_of(html):
    return " ".join(html_mod.unescape(re.sub(r"<[^>]+>", " ", html)).split())


def provider_card(html):
    """The provider card's lines on the Evidence tab, label to words."""
    tab = html.split('id="t-box-evidence"', 1)[1]
    card = tab.split("<b>The provider</b>", 1)[1].split('<div class="evcard', 1)[0]
    return {text_of(k): text_of(v) for k, v in re.findall(
        r'<span class="evk">(.*?)</span><span>(.*?)</span></div>', card, re.S)}


def rules_tab_provider_rows(html):
    """How many rule rows the Rules tab draws in the provider's blocks."""
    tab = html.split('id="t-box-rules"', 1)[1].split('id="t-box-evidence"', 1)[0]
    return len(set(re.findall(r'id="(rr-box-prov\d+-\d+)"', tab)))


# --------------------------------------------------------------- the measured case

def test_one_rule_in_and_one_out_is_two_rules_as_the_rules_tab_lists(db):
    server(db, [IN_22, OUT_443])
    html = rl.render(db, now=NOW)

    assert provider_card(html)["saw"] == "box with 2 rules"
    assert rules_tab_provider_rows(html) == 2


def test_one_rule_is_one_rule_and_never_one_rules(db):
    server(db, [IN_22])

    assert provider_card(rl.render(db, now=NOW))["saw"] == "box with 1 rule"


def test_a_firewall_with_no_rule_is_counted_as_none(db):
    server(db, [])
    html = rl.render(db, now=NOW)

    assert provider_card(html)["saw"] == "box with 0 rules"
    assert rules_tab_provider_rows(html) == 0


def test_a_rule_no_port_of_the_server_matches_is_counted_too(db):
    """What the old number left out: an ICMP rule, a range nothing listens in."""
    server(db, MANY)

    assert provider_card(rl.render(db, now=NOW))["saw"] == "box with 5 rules"


def test_two_firewalls_on_the_server_are_counted_together(db):
    server(db, [IN_22, OUT_443], [IN_ICMP])

    assert provider_card(rl.render(db, now=NOW))["saw"] == "box with 3 rules"


@pytest.mark.parametrize("firewalls", [
    ([],), ([IN_22],), ([IN_22, OUT_443],), (MANY,), ([IN_22, OUT_443], [IN_ICMP], [])],
    ids=["none", "one", "one in one out", "many", "three firewalls"])
def test_the_card_and_the_rules_tab_say_the_same_number(db, firewalls):
    server(db, *firewalls)
    html = rl.render(db, now=NOW)
    said = int(re.search(r"with (\d+) rules?$", provider_card(html)["saw"]).group(1))

    assert said == rules_tab_provider_rows(html) == sum(len(f) for f in firewalls)


def test_the_word_inbound_is_gone_from_the_card(db):
    """The count is of every rule the firewall holds, so it is not called
    inbound."""
    server(db, [IN_22, OUT_443])

    assert "inbound" not in provider_card(rl.render(db, now=NOW))["saw"]


# ------------------------------------------------------- what stays as it was

def test_a_server_with_no_provider_connected_keeps_its_greyed_card(db):
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "box"
    trl.reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    tab = html.split('id="t-box-evidence"', 1)[1]

    assert '<div class="evcard off"><div class="evt"><b>The provider</b>' in tab


def test_the_count_function_knows_nothing_for_a_server_the_provider_does_not_list(db):
    server(db, [IN_22])
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    provider = rl.load_provider(con, 1)
    con.close()

    assert rl.provider_rule_count(provider, "box") == 1
    assert rl.provider_rule_count(provider, "another") is None
    assert rl.provider_rule_count(None, "box") is None
