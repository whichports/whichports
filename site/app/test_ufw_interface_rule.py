"""A ufw rule written for one interface says which, on the Rules tab and on
the Packet path.

    Run from site/: python3 -m pytest app/test_ufw_interface_rule.py

`ufw allow in on wt0 to any port 443 proto tcp` holds for packets that come
in on wt0 and for no others. ufw writes the interface into the last field of
its tuple, `in_wt0`, `out_eth1`, or `in_eth0!out_eth1` for a route rule
(`src/backend_iptables.py` in ufw's source, read 2026-10-03, the reader of
that field around its line 795). The page read that field as a direction
alone, so such a rule was drawn "anywhere", like a rule for every interface
(the sweep of 2026-09-21, C7 in docs/RECORD.md 4.199).

This is about the drawing. Whether a rule for one interface counts for a
packet from outside is another question and is not answered here.
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

EVERYWHERE = "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in"
ON_WT0 = "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in_wt0"


# ------------------------------------------------------- the tuple's last field

@pytest.mark.parametrize("last, direction, coming_in, going_out", [
    ("in", "in", "", ""),
    ("out", "out", "", ""),
    ("in_wt0", "in", "wt0", ""),
    ("out_eth1", "out", "", "eth1"),
    ("in_eth0!out_eth1", "in", "eth0", "eth1"),
    ("in_br-1a2b3c", "in", "br-1a2b3c", ""),       # an interface name may hold a hyphen
    ("in_eth0.100", "in", "eth0.100", ""),         # and a dot, for a VLAN
])
def test_the_last_field_is_a_direction_and_the_interfaces_it_names(
        last, direction, coming_in, going_out):
    parts = rl.ufw_rule_parts(f"allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 {last}")
    assert (parts.direction, parts.interface_in, parts.interface_out) == (
        direction, coming_in, going_out)


def test_a_tuple_with_no_last_field_names_no_interface():
    parts = rl.ufw_rule_parts("allow tcp 443 0.0.0.0/0 any 0.0.0.0/0")
    assert (parts.direction, parts.interface_in, parts.interface_out) == ("in", "", "")


@pytest.mark.parametrize("rule, words", [
    (EVERYWHERE, ""),
    (ON_WT0, "on wt0"),
    # an outgoing rule is said to be outgoing beside this (test_ufw_outgoing_rule.py)
    ("allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 out_eth1", "on eth1"),
    ("route:allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 out_eth1", "out on eth1"),
    ("route:allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1", "on eth0, out on eth1"),
])
def test_the_words_for_a_rules_interfaces(rule, words):
    assert rl.ufw_interface_words(rl.ufw_rule_parts(rule)) == words


# ---------------------------------------------------------------- the Rules tab

def rules_text(rules, rules6=()):
    block, _count = rl.ufw_block("box", ufw_section(rules, rules6), "")
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", block, flags=re.S)).split())


def from_cells(rules, rules6=()):
    """Each row's from cell as (its text, its small grey note)."""
    block, _count = rl.ufw_block("box", ufw_section(rules, rules6), "")
    return [(text, note) for text, note in re.findall(
        r'<span class="rfr[^"]*">([^<]*)(?:<small>([^<]*)</small>)?', block)]


def test_a_rule_for_one_interface_says_so_on_the_rules_tab():
    assert from_cells([ON_WT0]) == [("anywhere", "on wt0")]


def test_a_rule_for_every_interface_reads_as_it_did():
    assert from_cells([EVERYWHERE]) == [("anywhere", "")]


def test_an_address_and_an_interface_are_both_said():
    cells = from_cells(["allow tcp 443 0.0.0.0/0 any 198.51.100.7 in_wt0"])
    assert cells == [("198.51.100.7", "on wt0")]


def test_a_forwarded_rule_keeps_its_word_and_gains_its_interfaces():
    cells = from_cells(["route:allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1"])
    assert cells == [("anywhere", "forwarded, on eth0, out on eth1")]


def test_the_same_rule_on_two_interfaces_is_two_rows():
    """The merge is on the rule. One for wt0 and one for eth0 are two rules."""
    cells = from_cells([ON_WT0, "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in_eth0"])
    assert cells == [("anywhere", "on wt0"), ("anywhere", "on eth0")]


def test_a_rule_for_one_interface_and_the_same_for_all_are_two_rows():
    assert from_cells([ON_WT0, EVERYWHERE]) == [("anywhere", "on wt0"), ("anywhere", "")]


def test_one_interface_rule_in_both_files_is_one_row_with_both_families():
    merged = rl.merged_ufw_rules(ufw_section(
        [ON_WT0], ["allow tcp 443 ::/0 any ::/0 in_wt0"]))
    assert len(merged) == 1
    assert merged[0][1] == ["v4", "v6"]
    assert from_cells([ON_WT0], ["allow tcp 443 ::/0 any ::/0 in_wt0"]) == [("anywhere", "on wt0")]


# -------------------------------------------------------------- the Packet path

def test_the_packet_paths_box_says_the_interface(db):
    """The box on the flow is narrow, so for a rule from anywhere it says the
    interface, which is what narrows the rule. The panel under the flow and
    the list of ufw's rules say both."""
    text = ufw_box(db, [ON_WT0])
    assert "ufw allow 443, on wt0 reaches" in text
    assert "for 443/tcp allow anywhere, on wt0" in text
    assert "allow 443 tcp/ v4 anywhere, on wt0" in text


def test_an_allow_for_one_source_on_one_interface_keeps_both_in_the_list(db):
    """The box says "permits some" for an allow that names a source
    (test_ufw_source_rule.py). The panel and the list say the address and the
    interface."""
    text = ufw_box(db, ["allow tcp 443 0.0.0.0/0 any 198.51.100.7 in_wt0"])
    assert "ufw permits some reaches" in text
    assert "for 443/tcp allow 198.51.100.7, on wt0" in text
    assert "allow 443 tcp/ v4 198.51.100.7, on wt0" in text


def test_a_deny_for_one_source_on_one_interface_is_written_out(db):
    text = ufw_box(db, ["deny tcp 443 0.0.0.0/0 any 198.51.100.7 in_wt0"])
    assert "ufw deny 443, 198.51.100.7, on wt0" in text


def test_a_rule_for_everybody_on_one_interface_outranks_a_rule_for_one_source(db):
    """The two rules of test_ufw_source_rule.py, with an interface on the one
    for everybody: it is still the one the box names."""
    text = ufw_box(db, ["allow tcp 443 0.0.0.0/0 any 198.51.100.7 in",
                        "allow tcp 443 0.0.0.0/0 any 0.0.0.0/0 in_wt0"])
    assert "ufw allow 443, on wt0 reaches" in text
    assert "permits some" not in text


def test_the_packet_paths_box_for_every_interface_reads_as_it_did(db):
    text = ufw_box(db, [EVERYWHERE])
    assert "ufw allow 443, anywhere reaches" in text
    assert ", on " not in text


def test_a_port_list_on_one_interface_says_both(db):
    text = ufw_box(db, ["allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in_wt0"])
    assert "ufw allow 443, on wt0 reaches" in text
    assert "allow 80,443 tcp/ v4 anywhere, on wt0" in text
