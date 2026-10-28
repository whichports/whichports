"""The provider line on a card for a family the engine raised no finding for.

    Run from site/: python3 -m pytest app/test_card_other_family.py

An opened row draws both families. Where one has no finding, its card wrote
"provider: not connected" whatever the provider was, beside the other card
naming the same connected provider (the sweep of 2026-09-21, C5 in
docs/RECORD.md 4.199). The engine now hangs the provider's view of the
missing family on the finding it did raise, and the card reads it.
"""
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import NOW, db, document, probe_result, reporting  # noqa: E402

__all__ = ["db"]


def rule(port, sources):
    return {"direction": "in", "protocol": "tcp", "port": port, "description": None,
            "source_ips": list(sources), "destination_ips": []}


def provider(db, rules, server_name="box"):
    hetzner = joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    hetzner.init(con)
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at="2026-08-14T11:48:00+00:00",
        servers=({"id": 7, "name": server_name, "status": "running",
                  "public_net": {"ipv4": {"ip": "203.0.113.7"},
                                 "firewalls": [{"id": 1, "status": "applied"}]}},),
        firewalls=({"id": 1, "name": "fw-1", "rules": list(rules),
                    "applied_to": [{"type": "server", "server": {"id": 7}}]},)))
    con.close()


def provider_lines(db):
    """{family: the provider line} on the opened row of 443/tcp."""
    doc = document(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                               "port": 443, "process_name": "caddy", "pid": 443}])
    doc["hostname"] = "box"
    reporting(db, "box", doc)
    probe_result(db, "box", 443, "v4", "connect_succeeded")
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    after = page.split('data-port="443/tcp"', 1)[1]
    cards = after.split("</label>", 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]
    lines = {}
    for one in cards.split('<div class="prec">')[1:]:
        family = re.search(r">(v4|v6)</i>", one).group(1)
        text = " ".join(re.sub(r"<[^>]+>", " ", one).split())
        lines[family] = text.split(" provider ", 1)[1] if " provider " in text else ""
    return lines


def test_with_no_provider_both_cards_say_not_connected(db):
    lines = provider_lines(db)
    assert lines["v4"].startswith("not connected")
    assert lines["v6"].startswith("not connected")


def test_a_connected_provider_with_no_v6_rule_is_not_called_not_connected(db):
    """The C5 case."""
    provider(db, [rule("22", ["0.0.0.0/0", "::/0"])])
    lines = provider_lines(db)
    assert lines["v6"].startswith("no rule names 443")
    assert lines["v4"].startswith("no rule names 443")


def test_a_v6_range_covering_the_port_is_quoted_on_the_v6_card(db):
    provider(db, [rule("400-500", ["::/0"])])
    lines = provider_lines(db)
    assert "400-500" in lines["v6"]
    assert "not connected" not in lines["v6"]


def test_a_server_the_provider_does_not_list_says_server_not_found(db):
    provider(db, [], server_name="someone-else")
    lines = provider_lines(db)
    assert lines["v6"].startswith("server not found")
    assert lines["v4"].startswith("server not found")


def test_the_card_with_a_finding_reads_as_it_did(db):
    """The provider line moved into one helper both cards call, so the card
    that has a finding is held to its old words too."""
    provider(db, [rule("443", ["0.0.0.0/0"])])
    lines = provider_lines(db)
    assert "443" in lines["v4"] and not lines["v4"].startswith("no rule")
