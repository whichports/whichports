"""A port's card says what the page can and cannot read of legacy iptables
rules, and never that no rule names the port beside them.

    Run from site/: python3 -m pytest app/test_card_legacy_rules.py

Measured in the second big test on 2026-10-25, case C5: a Debian 12 server
switched to iptables-legacy, 7 v4 and 5 v6 legacy rules with INPUT policy
DROP on both, one of them `-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT`, and
nftables empty. The agent stores a legacy rule by its match names, so the
page counts those rules and never places one on a port. The Packet path said
"12 legacy iptables rules, not placed on a port". The card of 22 said
"reachable, no rule permits it" and "no rule names 22", and the row's
Decided by said "no rule": a statement about rules the page had not read.

docs/screens/host-overview/SPEC.md section 7 decides the words where a rule
on the path could not be fully read: the lead "reachable, a rule could not
be fully read", and the firewall line says how many. A legacy rule is not
placed at all, so the line says so in the Packet path's own words. Each
family counts its own table: iptables for v4, ip6tables for v6.
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
from test_render_live import NOW, db, document, probe_result, reporting  # noqa: E402,F401

V4_LEGACY = ["-i lo accept", "[xt match conntrack] accept", "-p tcp [xt match tcp] accept",
             "-p tcp [xt match tcp] accept", "-p tcp [xt match tcp] accept",
             "-p tcp [xt match tcp] accept", "-p icmp accept"]
V6_LEGACY = ["-i lo accept", "[xt match conntrack] accept", "-p tcp [xt match tcp] accept",
             "-p tcp [xt match tcp] accept", "-p ipv6-icmp accept"]


def legacy_table(lines):
    return {"status": "collected", "tables": [{"name": "filter", "chains": [
        {"name": "INPUT", "builtin": True, "policy": "drop",
         "rules": [{"text": t, "rendered": "partial" if "[" in t else "full"}
                   for t in lines]}]}]}


def legacy_server(v4=V4_LEGACY, v6=V6_LEGACY, port=22):
    doc = document(listening=[
        {"protocol": "tcp", "family": family, "bind_address": address,
         "port": port, "process_name": "sshd", "pid": 700}
        for family, address in (("v4", "0.0.0.0"), ("v6", "::"))])
    doc["ufw"] = {"status": "not_present"}
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": []}
    if v4:
        doc["iptables"] = legacy_table(v4)
    if v6:
        doc["ip6tables"] = legacy_table(v6)
    return doc


def opened_row(db, doc, port=22, families=("v4", "v6")):
    """The row's Decided by, and each card's lead and firewall line."""
    reporting(db, "box", doc)
    for family in families:
        probe_result(db, "box", port, family, "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    after = page.split(f'data-port="{port}/tcp"', 1)[1]
    row = " ".join(re.sub(r"<[^>]+>", " ", after.split("</label>", 1)[0]).split())
    cards = []
    for card in after.split('<div class="prec">')[1:3]:
        text = " ".join(re.sub(r"<[^>]+>", " ", card[:2000]).split())
        lead = text.split(" agent ", 1)[0]
        firewall = text.split(" firewall ", 1)[1].split(" provider ", 1)[0]
        cards.append((lead, firewall))
    return row, cards


def test_the_card_counts_the_legacy_rules_and_never_says_no_rule_names_the_port(db):
    row, cards = opened_row(db, legacy_server())

    assert cards == [
        ("v4 reachable, a rule could not be fully read",
         "7 legacy iptables rules, not placed on a port"),
        ("v6 reachable, a rule could not be fully read",
         "5 legacy iptables rules, not placed on a port"),
    ]
    assert "rule not readable" in row
    assert " no rule " not in f" {row} "


def test_a_family_with_no_legacy_rule_of_its_own_reads_as_before(db):
    """ip6tables held nothing: the v6 card says what it said, and the v4
    card is not changed by it."""
    row, cards = opened_row(db, legacy_server(v6=()))

    assert cards[0] == ("v4 reachable, a rule could not be fully read",
                        "7 legacy iptables rules, not placed on a port")
    assert cards[1] == ("v6 reachable, no rule permits it", "no rule names 22")


def test_a_server_with_no_legacy_rule_still_says_no_rule(db):
    row, cards = opened_row(db, legacy_server(v4=(), v6=()))

    assert cards[0] == ("v4 reachable, no rule permits it", "no rule names 22")
    assert "no rule" in row and "not readable" not in row


def test_one_legacy_rule_is_said_in_the_singular(db):
    _row, cards = opened_row(db, legacy_server(v4=["-p tcp [xt match tcp] accept"], v6=()))

    assert cards[0][1] == "1 legacy iptables rule, not placed on a port"


def test_a_readable_nftables_permit_is_still_quoted_first(db):
    doc = legacy_server()
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "inet", "name": "filter", "chains": [
            {"name": "input", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop",
             "rules": [{"text": "tcp dport 22 accept", "rendered": "full"}]}]}]}
    _row, cards = opened_row(db, doc)

    assert cards[0] == ("v4 reachable, your rule permits it", "tcp dport 22 accept")
