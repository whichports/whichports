"""A ufw rule for outgoing traffic is said to be one, and is never the rule on
an incoming packet's way.

    Run from site/: python3 -m pytest app/test_ufw_outgoing_rule.py

`ufw allow out 443/tcp` lets this host open connections to port 443
elsewhere. ufw writes it as the tuple `allow tcp 443 0.0.0.0/0 any 0.0.0.0/0
out`: the last field starts with the direction, `in` or `out`, as ufw's own
writer puts it there (`src/backend_iptables.py` in ufw's source, read
2026-10-03, where the tuple is written from `r.direction`).

The page drew that rule like one for incoming traffic. The Rules tab showed
"ALLOW 443 anywhere" with nothing saying outgoing, and the Packet path named
it as the rule on the way of a packet coming in from the prober: "allow 443,
anywhere". A rule for what leaves says nothing about what may come in.

The word is the one a provider's outgoing rule already carries on the Rules
tab, "outgoing", and on the Packet path's list, "allow out".
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import render_live as rl  # noqa: E402
from test_host_rules import ufw_section  # noqa: E402
from test_render_live import db  # noqa: E402
from test_ufw_port_list import ufw_box  # noqa: E402

__all__ = ["db"]

IN = "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in"
OUT = "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 out"


def from_cells(rules, rules6=()):
    """Each row's from cell as (its text, its small grey note)."""
    block, _count = rl.ufw_block("box", ufw_section(rules, rules6), "")
    return re.findall(r'<span class="rfr[^"]*">([^<]*)(?:<small>([^<]*)</small>)?', block)


# ---------------------------------------------------------------- the Rules tab

def test_an_outgoing_rule_says_outgoing_on_the_rules_tab():
    assert from_cells([OUT]) == [("anywhere", "outgoing")]


def test_an_incoming_rule_reads_as_it_did():
    assert from_cells([IN]) == [("anywhere", "")]


def test_a_tuple_with_no_direction_is_incoming_as_ufw_reads_it():
    assert from_cells(["allow tcp 443 0.0.0.0/0 any 0.0.0.0/0"]) == [("anywhere", "")]


def test_an_outgoing_rule_on_one_interface_says_both():
    cells = from_cells(["allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 out_eth1"])
    assert cells == [("anywhere", "outgoing, on eth1")]


def test_a_forwarded_rule_is_forwarded_and_not_outgoing():
    cells = from_cells(["route:allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1"])
    assert cells == [("anywhere", "forwarded, on eth0, out on eth1")]


def test_the_same_port_in_and_out_is_two_rows():
    assert from_cells([IN, OUT]) == [("anywhere", ""), ("anywhere", "outgoing")]


# -------------------------------------------------------------- the Packet path

def test_an_outgoing_rule_is_not_the_rule_on_an_incoming_packets_way(db):
    text = ufw_box(db, [OUT])
    assert "ufw no rule for 443 reaches" in text
    assert "ufw allow 443, anywhere" not in text
    # the rule is still in the box's list, said to be outgoing
    assert "allow out 443 tcp/ v4 anywhere" in text


@pytest.mark.parametrize("rules", [[OUT, IN], [IN, OUT]])
def test_an_incoming_rule_beside_it_is_the_one_the_box_names(db, rules):
    text = ufw_box(db, rules)
    assert "ufw allow 443, anywhere reaches" in text


def test_an_outgoing_deny_does_not_stop_an_incoming_packet_on_the_page(db):
    text = ufw_box(db, ["deny tcp 443 0.0.0.0/0 any 0.0.0.0/0 out"])
    assert "ufw no rule for 443" in text
    assert "ufw deny 443" not in text
    assert "deny out 443 tcp/ v4 anywhere" in text


def test_an_outgoing_rule_for_a_port_list_is_not_a_hit_for_any_of_them(db):
    text = ufw_box(db, ["allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 out"])
    assert "ufw no rule for 443" in text


@pytest.mark.parametrize("last, outgoing", [
    ("in", False), ("out", True), ("in_wt0", False), ("out_eth1", True),
    ("in_eth0!out_eth1", False),
])
def test_which_last_fields_are_outgoing(last, outgoing):
    parts = rl.ufw_rule_parts(f"allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 {last}")
    assert (parts.direction == "out") is outgoing
