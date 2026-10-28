"""A ufw rule for several ports names each of them on the Packet path.

    Run from site/: python3 -m pytest app/test_ufw_port_list.py

ufw writes `ufw allow 80,443/tcp` as one tuple whose port field is `80,443`,
and a range as `8000:8100`. The Packet path compared that field with the port
as one string, so its ufw box said "no rule for 443" above its own list of
ufw's rules, which showed "allow 80,443" (the sweep of 2026-09-21, C7 in
docs/RECORD.md 4.199). The match is ufw's own `_match_ports`.
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import render_live as rl  # noqa: E402
from test_render_live import NOW, db, document, probe_result, reporting  # noqa: E402

__all__ = ["db"]


@pytest.mark.parametrize("field, port, names", [
    ("443", 443, True),
    ("80,443", 443, True),
    ("80,443", 80, True),
    ("80,443", 8443, False),        # a list item is a whole port, never a substring
    ("80,443", 44, False),
    ("8000:8100", 8000, True),      # both ends of a range are in it
    ("8000:8100", 8100, True),
    ("8000:8100", 8050, True),
    ("8000:8100", 7999, False),
    ("8000:8100", 8101, False),
    ("22,8000:8100,9200", 9200, True),
    ("22,8000:8100,9200", 8080, True),
    ("22,8000:8100,9200", 23, False),
    ("22", 2222, False),
    ("any", 443, False),            # a rule for any port is read as it was before
    ("", 443, False),
    (None, 443, False),
    ("8100:8000", 8050, False),     # backwards: ufw refuses to write it, and its own match holds nothing
    ("80:", 80, False),             # a half range is nothing ufw writes
    ("abc:def", 80, False),
])
def test_a_port_field_names_a_port_the_way_ufw_matches_it(field, port, names):
    assert rl.ufw_port_names(field, port) is names


def ufw_box(db, rules, rules6=(), port=443, process="caddy"):
    doc = document(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                               "port": port, "process_name": process, "pid": port}])
    doc["firewalld"] = {"status": "not_present"}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                  "rules": list(rules), "rules6": list(rules6),
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    reporting(db, "box", doc)
    probe_result(db, "box", port, "v4", "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    path = page.split('id="t-box-path"', 1)[1].split('<div class="tab ', 1)[0]
    path = re.sub(r"<svg.*?</svg>", "", path, flags=re.S)
    return " ".join(re.sub(r"<[^>]+>", " ", path).split())


def test_a_rule_for_two_ports_is_the_rule_for_each(db):
    text = ufw_box(db, ["allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in"])
    assert "ufw allow 443, anywhere" in text
    assert "no rule for 443" not in text


def test_a_range_holding_the_port_is_its_rule(db):
    text = ufw_box(db, ["allow tcp 8000:8100 0.0.0.0/0 any 0.0.0.0/0 in"], port=8080)
    assert "ufw allow 8080, anywhere" in text


def test_a_list_without_the_port_is_still_no_rule_for_it(db):
    text = ufw_box(db, ["allow tcp 80,8443 0.0.0.0/0 any 0.0.0.0/0 in"])
    assert "no rule for 443" in text


def test_a_list_in_the_other_family_alone_is_no_rule_on_this_one(db):
    """The family check is untouched: a v6 rule says nothing on the v4 path."""
    text = ufw_box(db, [], rules6=["allow tcp 80,443 ::/0 any ::/0 in"])
    assert "no rule for 443" in text


# ------------------------------------------- the card beside a rule it cannot read

def _rule(text):
    return {"text": text, "rendered": "partial" if "[" in text else "full", "comment": ""}


def card_firewall_line(db, nft_rules, port=443):
    doc = document(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                               "port": port, "process_name": "caddy", "pid": port}])
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop", "rules": [_rule("counter jump ufw-user-input")]},
            {"name": "ufw-user-input", "rules": [_rule(t) for t in nft_rules]}]}]}
    reporting(db, "box", doc)
    probe_result(db, "box", port, "v4", "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    card = page.split('<div class="prec">', 1)[1]
    text = " ".join(re.sub(r"<[^>]+>", " ", card[:2000]).split())
    return text.split(" firewall ", 1)[1].split(" provider ", 1)[0]


def test_a_rule_the_agent_could_not_fully_read_is_not_said_to_be_no_rule(db):
    """iptables-nft writes `ufw allow 80,443/tcp` with the multiport match,
    which the agent renders as `[xt match multiport]`. Whether it names 443
    is what nobody read, so the card does not say no rule names it."""
    line = card_firewall_line(db, ["ip protocol tcp [xt match multiport] counter accept"])
    assert line == "1 rule not fully readable"


def test_two_unreadable_rules_are_counted_in_the_plural(db):
    line = card_firewall_line(db, ["ip protocol tcp [xt match multiport] counter accept",
                                   "ip protocol tcp [xt match multiport] counter drop"])
    assert line == "2 rules not fully readable"


def test_a_readable_permit_is_still_quoted_first(db):
    line = card_firewall_line(db, ["ip protocol tcp tcp dport 443 counter accept",
                                   "ip protocol tcp [xt match multiport] counter accept"])
    assert line == "ip protocol tcp tcp dport 443 counter accept"


def test_with_every_rule_readable_no_rule_is_still_said(db):
    line = card_firewall_line(db, ["ip protocol tcp tcp dport 80 counter accept"])
    assert line.startswith("no rule names 443")


def lead_and_decided(db, nft_rules, port=443):
    doc = document(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                               "port": port, "process_name": "caddy", "pid": port}])
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop", "rules": [_rule("counter jump ufw-user-input")]},
            {"name": "ufw-user-input", "rules": [_rule(t) for t in nft_rules]}]}]}
    reporting(db, "box", doc)
    probe_result(db, "box", port, "v4", "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    after = page.split(f'data-port="{port}/tcp"', 1)[1]
    row = " ".join(re.sub(r"<[^>]+>", " ", after.split("</label>", 1)[0]).split())
    card = " ".join(re.sub(r"<[^>]+>", " ", after.split('<div class="prec">', 1)[1][:600]).split())
    return card.split(" agent ", 1)[0], row


def test_the_lead_and_decided_by_do_not_say_no_rule_beside_an_unreadable_one(db):
    lead, row = lead_and_decided(db, ["ip protocol tcp [xt match multiport] counter accept"])
    assert lead == "v4 reachable, a rule could not be fully read"
    assert "rule not readable" in row
    assert " no rule " not in f" {row} "


def test_with_every_rule_readable_the_lead_and_decided_by_read_as_before(db):
    lead, row = lead_and_decided(db, ["ip protocol tcp tcp dport 80 counter accept"])
    assert lead == "v4 reachable, no rule permits it"
    assert "no rule" in row and "not readable" not in row


def test_a_narrowed_rule_beside_an_unreadable_one_keeps_no_rule_permits_it(db):
    """A narrowed rule is read and quoted, and it is no permit (8d). The
    lead says what it always said about it."""
    lead, _row = lead_and_decided(db, ["ip protocol tcp ip saddr 198.51.100.7 tcp dport 443 counter accept",
                                       "ip protocol tcp [xt match multiport] counter accept"])
    assert lead == "v4 reachable, no rule permits it"
