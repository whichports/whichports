"""A loopback-only listener's row names it, and a refused probe is not "no answer".

    Run from site/: python3 -m pytest app/test_loopback_row.py

4.210's 3032: a listener on 127.0.0.1 behind a ufw rule for both families,
both probers refused. The row read the v6 half and said "nothing bound on
v6", which hid the one socket the port has. The v4 card led "not reachable,
no answer" over its own prober line saying "refused".
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


def _rule(text):
    return {"text": text, "rendered": "full", "comment": ""}


def box(db, listening, ports, outcome="connect_refused"):
    doc = document(listening=listening)
    doc["nftables"] = {"status": "collected", "tables": [
        {"family": family, "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop", "rules": [_rule(f"counter jump {prefix}-user-input")]},
            {"name": f"{prefix}-user-input",
             "rules": [_rule(f"{match} tcp tcp dport {port} counter accept") for port in ports]}]}
        for family, prefix, match in (("ip", "ufw", "ip protocol"), ("ip6", "ufw6", "meta l4proto"))]}
    reporting(db, "box", doc)
    for port in {s["port"] for s in listening} | set(ports):
        probe_result(db, "box", port, "v4", outcome)
        probe_result(db, "box", port, "v6", outcome)


def sock(port, address, process="metrics"):
    family = "v6" if ":" in address else "v4"
    return {"protocol": "tcp", "family": family, "bind_address": address, "port": port,
            "process_name": process, "pid": port}


def row_and_cards(db, port):
    page = rl.render(db, now=NOW).split('id="host-box"', 1)[1].split('<div class="wrap view"', 1)[0]
    after = page.split(f'data-port="{port}/tcp"', 1)[1]
    row = " ".join(re.sub(r"<[^>]+>", " ", after.split("</label>", 1)[0]).split())
    cards = {}
    for one in after.split("</label>", 1)[1].split('<input type="checkbox" class="prsel"', 1)[0] \
            .split('<div class="prec">')[1:3]:
        # The two cards of this row. After the table's last row the page
        # goes on, so nothing past the second card is a card of this row.
        family = re.search(r">(v4|v6)</i>", one).group(1)
        cards[family] = " ".join(re.sub(r"<[^>]+>", " ", one).split())
    return row, cards


# ------------------------------------------------------------ the measured case

def test_a_listener_on_loopback_alone_is_named_on_its_row(db):
    box(db, [sock(3032, "127.0.0.1")], ports=(3032,))
    row, _ = row_and_cards(db, 3032)
    assert "metrics, loopback only" in row
    assert "nothing bound" not in row
    # The word and Decided by stay: nothing outside reaches a listener
    # through that rule on either family.
    assert "stale rule" in row and "your rule" in row and "nothing behind it" not in row


def test_a_listener_on_the_v6_loopback_alone_is_named_too(db):
    box(db, [sock(3033, "::1")], ports=(3033,))
    row, _ = row_and_cards(db, 3033)
    assert "metrics, loopback only" in row


# --------------------------------------------------------- what stays as it was

def test_a_listener_on_a_network_address_on_v4_alone_still_says_nothing_bound_on_v6(db):
    box(db, [sock(3031, "0.0.0.0")], ports=(3031,))
    row, _ = row_and_cards(db, 3031)
    assert "nothing bound on v6" in row
    assert "loopback" not in row


def test_a_listener_on_loopback_and_on_a_network_address_is_not_loopback_only(db):
    box(db, [sock(3034, "127.0.0.1"), sock(3034, "0.0.0.0")], ports=(3034,))
    row, _ = row_and_cards(db, 3034)
    assert "loopback only" not in row


def test_a_loopback_port_no_rule_names_still_says_loopback_once(db):
    """Without a rule both halves are not reachable, the row's word, and
    Decided by already says loopback. Service is not made to say it twice."""
    box(db, [sock(3035, "127.0.0.1")], ports=())
    row, _ = row_and_cards(db, 3035)
    assert row.count("loopback") == 1


# ------------------------------------------------------------- the card's lead

@pytest.mark.parametrize("outcome, lead", [
    ("connect_refused", "not reachable, refused"),
    ("no_response", "not reachable, no answer"),
])
def test_the_lead_says_what_the_prober_got(db, outcome, lead):
    box(db, [sock(3032, "127.0.0.1")], ports=(3032,), outcome=outcome)
    _, cards = row_and_cards(db, 3032)
    assert cards["v4"].split(" agent ", 1)[0] == f"v4 {lead}"


def test_a_lead_with_nothing_bound_reads_as_before(db):
    box(db, [sock(3032, "127.0.0.1")], ports=(3032,))
    _, cards = row_and_cards(db, 3032)
    assert cards["v6"].startswith("v6 not reachable, nothing is bound")
