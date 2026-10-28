"""The Rules tab draws Docker's zone and the policy that forwards to it
(docs/RECORD.md 4.344).

On a server with firewalld and Docker two things let traffic through that the
tab did not draw at all (4.223):

  - the zone `docker`, in effect on Docker's bridge, which holds a target,
    ACCEPT, and no rule of its own
  - the policy `docker-forwarding`, which accepts what is forwarded to the
    bridge, and is how a published port passes firewalld whatever the zones
    say

Both are read from a Fedora 44 server's own document, firewalld 2.4.4,
2026-10-03: the zone's file and the lines of firewalld's table in the kernel.

    Run from site/: python3 -m pytest app/test_firewalld_docker_zone.py
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
from test_firewalld_zones_in_effect import (  # noqa: E402
    FEDORA_DISPATCH, FEDORA_ZONES, PUBLIC_ALONE, halves, notes_in, rows_in, rules,
    text_of, zone)

# filter_FORWARD_POLICIES on that server, line for line, and the policy's own
# chain.
FEDORA_FORWARD = [
    'iifname "docker0" oifname "docker0" jump filter_FWD_policy_docker-forwarding',
    'iifname "docker0" oifname "docker0" jump filter_FWD_docker',
    'iifname "docker0" oifname "docker0" accept',
    'iifname "docker0" oifname "eth0" jump filter_FWD_docker',
    'iifname "docker0" oifname "eth0" accept',
    'iifname "docker0" jump filter_FWD_docker',
    'iifname "docker0" accept',
    'iifname "eth0" oifname "docker0" jump filter_FWD_policy_docker-forwarding',
    'iifname "eth0" oifname "docker0" jump filter_FWD_public',
    'iifname "eth0" oifname "docker0" [reject]',
    'iifname "eth0" oifname "eth0" jump filter_FWD_public',
    'iifname "eth0" oifname "eth0" [reject]',
    'iifname "eth0" jump filter_FWD_public',
    'iifname "eth0" [reject]',
    'oifname "docker0" jump filter_FWD_policy_docker-forwarding',
    'oifname "docker0" jump filter_FWD_public',
    'oifname "docker0" [reject]',
    'oifname "eth0" jump filter_FWD_public',
    'oifname "eth0" [reject]',
    "jump filter_FWD_public",
    "[reject]",
]
POLICY_CHAIN = [
    "jump filter_FWD_policy_docker-forwarding_pre",
    "jump filter_FWD_policy_docker-forwarding_log",
    "jump filter_FWD_policy_docker-forwarding_deny",
    "jump filter_FWD_policy_docker-forwarding_allow",
    "jump filter_FWD_policy_docker-forwarding_post",
    "accept",
]


def chain(name, lines):
    return {"name": name, "rules": rules(lines)}


def document(zones=None, dispatch=FEDORA_DISPATCH, forward=FEDORA_FORWARD,
             policies=None, table=("inet", "firewalld")):
    """A host with firewalld: its zone files and its table in the kernel."""
    policies = {"docker-forwarding": POLICY_CHAIN} if policies is None else policies
    chains = [chain("filter_INPUT_POLICIES", dispatch or []),
              chain("filter_FORWARD_POLICIES", forward or [])]
    chains += [chain(f"filter_FWD_policy_{name}", lines) for name, lines in policies.items()]
    return {
        "firewalld": {"status": "collected", "conf": {"DefaultZone": "public"},
                      "sources": {"etc_zones": {"status": "collected"},
                                  "vendor_zones": {"status": "collected"}},
                      "zones": FEDORA_ZONES if zones is None else zones},
        "nftables": {"status": "collected", "tables": [
            {"family": table[0], "name": table[1], "chains": chains}]},
    }


def block(doc):
    return rl.firewalld_block("web-01", doc["firewalld"], "3m",
                              rl.firewalld_zones_in_effect(doc),
                              rl.firewalld_forward_policies(doc))


def row_words(html):
    """Each row as a person reads it across: action, port, from, note."""
    out = []
    for label in re.findall(r'<label class="fwr".*?</label>', html, flags=re.S):
        out.append(" ".join(text_of(label).split()[1:]))   # without its number
    return out


# ---------------------------------------------------- the Fedora server as a whole

def test_the_fedora_server_with_docker_reads_as_five_rows():
    html, count = block(document())
    shown, folded = halves(html)

    assert count == 5
    assert row_words(shown) == [
        "accept any port docker0 target, zone docker",
        "allow dhcpv6-client anywhere service, zone public on eth0",
        "allow mdns anywhere service, zone public on eth0",
        "allow ssh anywhere service, zone public on eth0",
        "accept any port anywhere policy docker-forwarding, forwarded to docker0",
    ]
    # Two zones are listed, so the block's own line names neither.
    assert "zone" not in text_of(html.split('class="rh"', 1)[0])
    # The fold is as it was: Docker's zone is in effect and is not in it.
    assert "8 zones not in effect" in text_of(folded) and rows_in(folded) == 24
    assert "zone docker" not in " ".join(notes_in(folded))


def test_every_row_keeps_a_number_and_an_id_of_its_own():
    html, _count = block(document())
    ids = re.findall(r'<input type="checkbox" class="rsel" id="([^"]+)"', html)
    numbers = re.findall(r'<span class="ix">(\d+)</span>', html)

    assert len(ids) == 29 and len(set(ids)) == 29
    assert numbers == [str(n) for n in range(1, 30)]


def test_the_strip_counts_the_target_and_the_policy():
    said = text_of(rl.rules_tab_body(document(), "web-01"))
    assert "Rules 5 across them" in said


# --------------------------------------------------- a zone that holds only a target

@pytest.mark.parametrize("target, word", [
    ("ACCEPT", "accept"), ("DROP", "drop"), ("%%REJECT%%", "reject")])
def test_a_zone_in_effect_with_a_target_and_no_rule_is_one_row_saying_its_target(target, word):
    doc = document([zone("guard", target=target)],
                   dispatch=['iifname "eth1" jump filter_IN_guard'], forward=[])
    html, count = block(doc)

    assert count == 1
    assert row_words(html) == [f"{word} any port eth1 target"]
    # One zone is listed, so the block's line names it, and the target is
    # said once: on the row and not again at the right.
    head = text_of(html.split('class="rh"', 1)[0])
    assert "zone guard on eth1" in head
    assert "incoming" not in head


def test_a_deny_target_takes_the_deny_tone():
    doc = document([zone("guard", target="DROP")],
                   dispatch=['iifname "eth1" jump filter_IN_guard'], forward=[])
    html, _count = block(doc)
    assert 'class="st off deny">drop<' in html


@pytest.mark.parametrize("target", ["default", "", "CONTINUE", "accept"])
def test_a_target_this_page_has_no_word_for_draws_no_row(target):
    z = zone("guard")
    if target:
        z["target"] = target
    doc = document([z, zone("work", services=("ssh",))],
                   dispatch=['iifname "eth1" jump filter_IN_guard'], forward=[])
    html, count = block(doc)
    assert count == 0 and row_words(halves(html)[0]) == []


def test_a_zone_with_rules_and_a_target_keeps_its_rules_and_gets_no_row_for_the_target():
    """nm-shared ships with three services and ACCEPT. Its target stays where
    it was, at the right of the block's line when it is the one zone listed."""
    doc = document([zone("nm-shared", services=("dhcp", "dns", "ssh"), target="ACCEPT")],
                   dispatch=['iifname "eth1" jump filter_IN_nm-shared'], forward=[])
    html, count = block(doc)

    assert count == 3
    assert not any("target" in words for words in row_words(html))
    assert "incoming accept" in text_of(html.split('class="rh"', 1)[0])


def test_a_target_only_zone_that_is_not_in_effect_draws_nothing_at_all():
    """`trusted`, `block` and `drop` ship with a target and no rule and
    nothing bound to them. Neither a row nor a place in the fold."""
    html, _count = block(document(dispatch=PUBLIC_ALONE, forward=[]))
    said = text_of(html)
    for name in ("trusted", "block", "drop", "docker"):
        assert f"zone {name}" not in said, name
    assert not any("target" in words for words in row_words(html))


def test_a_kernel_that_does_not_say_which_zones_apply_draws_no_target_as_a_rule():
    """A target is drawn as a rule that applies, so only where the kernel
    says the zone does. With no answer the tab is as it always was."""
    doc = document(dispatch=None, forward=[])
    html, count = block(doc)
    assert count == 27 and not any("target" in words for words in row_words(html))


def test_a_target_only_zone_that_takes_one_source_says_the_source():
    guard = zone("guard", target="ACCEPT")
    guard["source_addrs"] = ["192.0.2.0/24"]
    doc = document([guard], dispatch=["ip saddr 192.0.2.0/24 jump filter_IN_guard"], forward=[])
    html, _count = block(doc)
    assert row_words(html) == ["accept any port 192.0.2.0/24 target"]


# --------------------- where a target row's packets come from (the owner's pick, 4.344)
#
# A row that accepts every port and says "anywhere" reads as the server being
# open. The zone takes what arrives on its interface, so the interface stands
# in the from column.

def test_a_target_row_says_the_interface_where_its_packets_come_in():
    html, _count = block(document())
    shown = halves(html)[0]

    assert row_words(shown)[0] == "accept any port docker0 target, zone docker"
    # The interface is a machine's word, so it takes the machine's face, and
    # the note names the zone alone: the column has said the interface.
    assert '<span class="rfr addr">docker0<small>target, zone docker</small></span>' in shown
    assert "zone docker on docker0" not in shown.split('class="rev"')[0]


def test_the_rows_of_a_zone_with_rules_keep_anywhere_and_their_interface_in_the_note():
    """Only the target's row changes. A service's row is as it was approved
    with the zones: from anywhere, the zone and its interface beside it."""
    html, _count = block(document())
    assert row_words(halves(html)[0])[1:4] == [
        "allow dhcpv6-client anywhere service, zone public on eth0",
        "allow mdns anywhere service, zone public on eth0",
        "allow ssh anywhere service, zone public on eth0",
    ]


def test_a_target_only_zone_on_two_interfaces_names_both():
    doc = document([zone("guard", target="ACCEPT")],
                   dispatch=['iifname "eth1" jump filter_IN_guard',
                             'iifname "eth0" jump filter_IN_guard'], forward=[])
    html, _count = block(doc)
    assert row_words(html) == ["accept any port eth1, eth0 target"]


def test_a_target_only_zone_entered_as_the_default_alone_says_anywhere():
    """No interface is named for it, so there is none to put in the column."""
    doc = document([zone("guard", target="DROP")],
                   dispatch=["jump filter_IN_guard"], forward=[])
    html, _count = block(doc)
    assert row_words(html) == ["drop any port anywhere target"]


def test_a_target_only_zone_with_a_source_and_an_interface_says_the_source():
    """The zone's own source is who it takes, and that stays the from
    column. The interface then rides in the note with the zone's name, when
    rows are named."""
    guard = zone("guard", target="ACCEPT")
    guard["source_addrs"] = ["192.0.2.0/24"]
    doc = document([guard, zone("public", services=("ssh",))],
                   dispatch=["ip saddr 192.0.2.0/24 jump filter_IN_guard",
                             'iifname "eth1" jump filter_IN_guard',
                             'iifname "eth0" jump filter_IN_public'], forward=[])
    html, _count = block(doc)
    assert row_words(halves(html)[0])[0] == \
        "accept any port 192.0.2.0/24 target, zone guard on eth1"


def test_an_interface_in_the_from_column_is_text_and_never_markup():
    doc = document([zone("guard", target="ACCEPT")],
                   dispatch=['iifname "<b>x</b>" jump filter_IN_guard'], forward=[])
    html, _count = block(doc)
    assert "<b>x</b>" not in html
    assert '<span class="rfr addr">&lt;b&gt;x&lt;/b&gt;<small>target</small></span>' in html


def test_the_target_rows_card_says_where_it_was_read():
    html, _count = block(document())
    card = text_of(html.split('class="rev"', 2)[1])
    for words in ("read from docker.xml", "zone docker", "interface docker0",
                  "target ACCEPT", "origin etc", "read agent reported 3m"):
        assert words in card, words


# ---------------------------------------------------------- the forwarding policy

def test_the_fedora_servers_policy_is_read_with_where_it_forwards_to():
    assert rl.firewalld_forward_policies(document()) == [
        ("docker-forwarding", "accept", ("docker0",))]


def test_a_policy_sent_to_whatever_the_packet_leaves_on_names_no_interface():
    doc = document(forward=['oifname "docker0" jump filter_FWD_policy_docker-forwarding',
                            "jump filter_FWD_policy_docker-forwarding"])
    assert rl.firewalld_forward_policies(doc) == [("docker-forwarding", "accept", ())]
    assert row_words(halves(block(doc)[0])[0])[-1] == \
        "accept any port anywhere policy docker-forwarding, forwarded"


def test_a_policy_to_two_interfaces_names_both_once_in_the_kernels_order():
    doc = document(forward=['oifname "br1" jump filter_FWD_policy_docker-forwarding',
                            'iifname "eth0" oifname "docker0" jump filter_FWD_policy_docker-forwarding',
                            'oifname "br1" jump filter_FWD_policy_docker-forwarding'])
    assert rl.firewalld_forward_policies(doc) == [
        ("docker-forwarding", "accept", ("br1", "docker0"))]
    assert row_words(halves(block(doc)[0])[0])[-1] == \
        "accept any port anywhere policy docker-forwarding, forwarded to br1, docker0"


def test_a_policy_that_drops_is_listed_as_a_drop():
    doc = document(policies={"docker-forwarding": ["jump filter_FWD_policy_docker-forwarding_allow",
                                                   "drop"]})
    assert rl.firewalld_forward_policies(doc) == [("docker-forwarding", "drop", ("docker0",))]


@pytest.mark.parametrize("last", [
    "[reject]",                                      # a verdict the agent could not render
    "jump filter_FWD_policy_docker-forwarding_post",  # no verdict of its own
    "tcp dport 80 accept",                           # a rule, and not the policy's target
    "oifname \"docker0\" accept",
])
def test_a_policy_whose_own_verdict_is_not_plain_is_not_listed(last):
    doc = document(policies={"docker-forwarding": ["jump filter_FWD_policy_docker-forwarding_pre",
                                                   last]})
    assert rl.firewalld_forward_policies(doc) == []
    assert not any("policy" in words for words in row_words(block(doc)[0]))


def test_a_verdict_the_agent_did_not_render_in_full_is_not_taken_for_one():
    """The text reads accept and the agent says it rendered only part of the
    rule. What the rest was is not known, so neither is the verdict."""
    doc = document()
    own = [c for c in doc["nftables"]["tables"][0]["chains"]
           if c["name"] == "filter_FWD_policy_docker-forwarding"][0]
    own["rules"][-1] = {"text": "accept", "rendered": "partial"}
    assert rl.firewalld_forward_policies(doc) == []


def test_a_policy_with_no_chain_of_its_own_or_an_empty_one_is_not_listed():
    assert rl.firewalld_forward_policies(document(policies={})) == []
    assert rl.firewalld_forward_policies(document(policies={"docker-forwarding": []})) == []


def test_two_policies_are_listed_in_the_kernels_order():
    doc = document(forward=['oifname "br1" jump filter_FWD_policy_second',
                            'oifname "docker0" jump filter_FWD_policy_docker-forwarding'],
                   policies={"docker-forwarding": POLICY_CHAIN, "second": ["drop"]})
    assert rl.firewalld_forward_policies(doc) == [
        ("second", "drop", ("br1",)), ("docker-forwarding", "accept", ("docker0",))]


def test_a_policy_on_the_way_in_is_not_a_forwarding_policy():
    """filter_IN_policy_allow-host-ipv6 is on every firewalld 2 server. It is
    not forwarding and its chain ends on no verdict."""
    doc = document(forward=["jump filter_IN_policy_allow-host-ipv6",
                            "jump filter_FWD_public"], policies={})
    assert rl.firewalld_forward_policies(doc) == []


@pytest.mark.parametrize("table", [("ip", "firewalld"), ("inet", "filter")])
def test_only_firewallds_own_table_is_read_for_policies(table):
    assert rl.firewalld_forward_policies(document(table=table)) == []


@pytest.mark.parametrize("doc", [
    {},
    {"nftables": None},
    {"nftables": {"status": "permission_denied", "tables": []}},
    {"nftables": {"status": "collected", "tables": "none"}},
    {"nftables": {"status": "collected", "tables": [None, {"family": "inet", "name": "firewalld"}]}},
    {"nftables": {"status": "collected", "tables": [{"family": "inet", "name": "firewalld", "chains": [
        None, {"name": "filter_FORWARD_POLICIES", "rules": [None, {"text": None}, {"text": 7}]}]}]}},
])
def test_a_kernel_that_does_not_say_has_no_policies_and_never_raises(doc):
    assert rl.firewalld_forward_policies(doc) == []


def test_a_section_that_was_not_collected_has_no_policies_whatever_it_holds():
    doc = document()
    doc["nftables"]["status"] = "permission_denied"
    assert rl.firewalld_forward_policies(doc) == []


def test_the_policy_rows_card_says_what_the_kernel_holds():
    html, _count = block(document())
    cards = html.split("<details", 1)[0].split('class="rev"')[1:]
    card = text_of(cards[-1])
    assert "as it is enforced" in card
    for words in ("policy docker-forwarding", "forwarded to docker0", "read agent reported 3m"):
        assert words in card, words


def test_names_from_the_kernel_are_text_and_never_markup():
    doc = document(forward=['oifname "<i>x</i>" jump filter_FWD_policy_<b>p</b>'],
                   policies={"<b>p</b>": ["accept"]})
    html, _count = block(doc)
    assert "<b>p</b>" not in html and "<i>x</i>" not in html
    assert "&lt;b&gt;p&lt;/b&gt;" in html and "&lt;i&gt;x&lt;/i&gt;" in html
