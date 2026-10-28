"""A socket on the IPv6 wildcard, read on the v4 half of a port.

    Run from site/: python3 -m pytest app/test_wildcard_socket.py

One socket on `::` with bindv6only off takes v4 connections as well, and the
document cannot say whether this host's does, so docs/PRODUCT.md 8a counts it
as neither an owner nor an absence on v4. The engine says so in
`InsideView.owns_the_port`. The Overview read the sockets alone and wrote
"nothing bound on v4" on the row and "nothing bound" on the v4 card, beside a
prober that had connected over v4: the sweep of 2026-09-21 found it on four
servers (docs/RECORD.md 4.199), and the test fleet again on a port served by
one socket on `::` (4.210, case 5).
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import render_live as rl  # noqa: E402
from test_render_live import NOW, db, document, probe_result, reporting  # noqa: E402

__all__ = ["db"]


def on_wildcard(port, process="caddy"):
    return {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": port,
            "process_name": process, "pid": port}


def on_v4(port, process="caddy"):
    return {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": port,
            "process_name": process, "pid": port}


def _rule(text):
    return {"text": text, "rendered": "full", "comment": ""}


def box(db, listening, ports):
    doc = document(listening=listening)
    doc["nftables"] = {"status": "collected", "tables": [
        {"family": family, "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop", "rules": [_rule(f"counter jump {prefix}-user-input")]},
            {"name": f"{prefix}-user-input",
             "rules": [_rule(f"{match} tcp tcp dport {port} counter accept") for port in ports]}]}
        for family, prefix, match in (("ip", "ufw", "ip protocol"), ("ip6", "ufw6", "meta l4proto"))]}
    reporting(db, "box", doc)


def row_and_cards(db, port):
    html = rl.render(db, now=NOW)
    page = html.split('id="host-box"', 1)[1].split('<div class="wrap view"', 1)[0]
    after = page.split(f'data-port="{port}/tcp"', 1)[1]
    row = after.split("</label>", 1)[0]
    cards = after.split("</label>", 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]
    return row, cards


def card(cards, family):
    for one in cards.split('<div class="prec">')[1:]:
        if f">{family}</i>" in one.split("</div>", 1)[0]:
            return re.sub(r"<[^>]+>", "", one)
    raise AssertionError(f"no {family} card")


def service_of(row):
    cell = re.search(r'<span class="prs(?: note)?">(.*?)</span>', row, re.S).group(1)
    return re.sub(r"<small.*", "", cell, flags=re.S)


# ------------------------------------------------------------- the measured case

def test_one_socket_on_the_wildcard_answering_on_both_families_is_named_on_the_row(db):
    """The test fleet's case 5: one socket on `::`, v4 through it, a rule for
    both families, both probers connected on both. The row is caddy, never
    "nothing bound on v4"."""
    box(db, [on_wildcard(3030)], ports=(3030,))
    probe_result(db, "box", 3030, "v4", "connect_succeeded")
    probe_result(db, "box", 3030, "v6", "connect_succeeded")
    row, cards = row_and_cards(db, 3030)
    assert service_of(row) == "caddy"
    assert "nothing bound" not in row


def test_the_v4_card_names_the_socket_on_the_wildcard_with_its_own_address(db):
    box(db, [on_wildcard(3030)], ports=(3030,))
    probe_result(db, "box", 3030, "v4", "connect_succeeded")
    probe_result(db, "box", 3030, "v6", "connect_succeeded")
    _, cards = row_and_cards(db, 3030)
    v4 = card(cards, "v4")
    assert "caddy listens on [::]:3030" in v4
    assert "nothing bound" not in v4
    assert "connected" in v4
    # The v6 card says the same socket the same way, so one socket has one
    # spelling on the screen. It said `:::3030` until this change.
    assert "caddy listens on [::]:3030" in card(cards, "v6")
    assert ":::3030" not in card(cards, "v4") + card(cards, "v6")


def test_a_silent_v4_with_a_socket_on_the_wildcard_is_not_said_to_have_nothing_bound(db):
    """Measured silent on v4: the card's lead used to say "nothing is bound",
    which is the absence 8a says the document cannot claim."""
    box(db, [on_wildcard(3030)], ports=(3030,))
    probe_result(db, "box", 3030, "v4", "no_response")
    probe_result(db, "box", 3030, "v6", "connect_succeeded")
    _, cards = row_and_cards(db, 3030)
    v4 = card(cards, "v4")
    assert "nothing is bound" not in v4
    assert "nothing bound" not in v4


# --------------------------------------------- what must stay as it was

def test_a_socket_on_v4_alone_still_says_nothing_bound_on_v6(db):
    """The direction matters: a v4 socket never takes a v6 connection, so
    nothing on v6 is a fact and is said. The v6 half reads stale rule here,
    the rule allowing both families."""
    box(db, [on_v4(3031)], ports=(3031,))
    probe_result(db, "box", 3031, "v4", "connect_refused")
    probe_result(db, "box", 3031, "v6", "connect_refused")
    row, cards = row_and_cards(db, 3031)
    assert service_of(row) == "nothing bound on v6"
    assert "nothing bound" in card(cards, "v6")


def test_a_socket_on_one_v6_address_takes_nothing_on_v4(db):
    """Only the wildcard is ambiguous. A socket on one v6 address is not a
    v4 owner and the v4 card says so."""
    one = dict(on_wildcard(3032), bind_address="2001:db8::1")
    box(db, [one], ports=(3032,))
    probe_result(db, "box", 3032, "v4", "connect_refused")
    probe_result(db, "box", 3032, "v6", "connect_succeeded")
    _, cards = row_and_cards(db, 3032)
    assert "nothing bound" in card(cards, "v4")


def test_sockets_on_both_families_read_as_they_did(db):
    box(db, [on_v4(443), on_wildcard(443)], ports=(443,))
    probe_result(db, "box", 443, "v4", "connect_succeeded")
    probe_result(db, "box", 443, "v6", "connect_succeeded")
    row, cards = row_and_cards(db, 443)
    assert service_of(row) == "caddy"
    assert "caddy listens on 0.0.0.0:443" in card(cards, "v4")
    assert "[::]" not in card(cards, "v4")


def test_an_address_and_a_port_are_written_one_way():
    assert rl._address_and_port("::", 443) == "[::]:443"
    assert rl._address_and_port("2001:db8::1", 22) == "[2001:db8::1]:22"
    assert rl._address_and_port("0.0.0.0", 80) == "0.0.0.0:80"
    assert rl._address_and_port("", 80) == "80"
