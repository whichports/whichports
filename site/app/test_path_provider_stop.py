"""The provider's box ends the journey when it is drawn first and has no rule.

    Run from site/: python3 -m pytest app/test_path_provider_stop.py

The Packet path draws the provider first (SPEC.md, the owner's call of
2026-09-10), and a Hetzner firewall with no rule for a port denies it (its
own overview, read 2026-09-09, the box's "without a rule: deny"). For a
measured silence the path marked the host firewall behind it as where the
journey ended, a box the packet never reaches (the sweep of 2026-09-21, C6 in
docs/RECORD.md 4.199).
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


def provider(db, ports):
    hetzner = joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    hetzner.init(con)
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at="2026-08-14T11:48:00+00:00",
        servers=({"id": 7, "name": "box", "status": "running",
                  "public_net": {"ipv4": {"ip": "203.0.113.7"},
                                 "firewalls": [{"id": 1, "status": "applied"}]}},),
        firewalls=({"id": 1, "name": "fw-1", "rules": [
            {"direction": "in", "protocol": "tcp", "port": str(p), "description": None,
             "source_ips": ["0.0.0.0/0"], "destination_ips": []} for p in ports],
            "applied_to": [{"type": "server", "server": {"id": 7}}]},)))
    con.close()


def _rule(text):
    return {"text": text, "rendered": "full", "comment": ""}


def path_text(db, outcome, port=8080):
    """The Packet path for `port` on v4, ufw denying it, as words."""
    doc = document(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                               "port": port, "process_name": "app", "pid": port}])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                  "rules": [f"deny tcp {port} 0.0.0.0/0 any 0.0.0.0/0 in"], "rules6": [],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    doc["nftables"] = {"status": "collected", "tables": [{"family": "ip", "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter", "policy": "drop",
         "rules": [_rule("counter jump ufw-user-input")]},
        {"name": "ufw-user-input", "rules": [_rule(f"ip protocol tcp tcp dport {port} counter drop")]}]}]}
    reporting(db, "box", doc)
    probe_result(db, "box", port, "v4", outcome)
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1]
    path = page.split('id="t-box-path"', 1)[1].split('<div class="tab ', 1)[0]
    path = re.sub(r"<svg.*?</svg>", "", path, flags=re.S)
    return " ".join(re.sub(r"<[^>]+>", " ", path).split())


def test_a_provider_with_no_rule_ends_the_journey_of_a_silence(db):
    provider(db, ports=(22,))
    text = path_text(db, "no_response")
    assert "provider firewall ends its journey here" in text
    assert "ufw host firewall not reached" in text
    assert "ufw host firewall ends its journey here" not in text


def test_a_provider_rule_for_the_port_leaves_the_host_firewall_marked(db):
    provider(db, ports=(22, 8080))
    text = path_text(db, "no_response")
    assert "ufw host firewall ends its journey here" in text
    assert "provider firewall ends its journey here" not in text


def test_with_no_provider_the_host_firewall_is_marked_as_before(db):
    text = path_text(db, "no_response")
    assert "ufw host firewall ends its journey here" in text


def test_a_refusal_marks_no_box(db):
    """A refusal is an answer from somewhere on the host, never a stop this
    page attributes."""
    provider(db, ports=(22,))
    text = path_text(db, "connect_refused")
    assert "ends its journey here" not in text
