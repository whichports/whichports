"""The Rules tab on a server whose only firewall is rules written straight
into the kernel: nftables by hand, no ufw and no firewalld.

    Run from site/: python3 -m pytest app/test_rules_raw_nftables.py

The first big server test, on a Debian 13 server (docs/RECORD.md 4.220). The
tab said "Firewalls active 1" beside "No firewall active", wrote "any port"
on rules whose port stands in a set, a range, or beside a limit or a reject,
and left the reject's action empty.

The twelve rules below are that server's, as the agent stored their text and
as the tab drew it that day, read off the shot of that tab. The table's and
the chain's names are made up here. The document itself was not kept.
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import packetpath as pp  # noqa: E402
import render_live as rl  # noqa: E402
import test_host_rules as thr  # noqa: E402
import test_render_live as trl  # noqa: E402

RAW_RULES = [
    ("ct state established,related accept", "full"),                    # 1
    ("meta 4 0x01000000 accept", "full"),                               # 2
    ("[lookup @__set0] accept", "partial"),                             # 3, a set
    ("meta l4proto tcp tcp dport 22 accept", "full"),                   # 4
    ("meta l4proto tcp tcp dport 4000 accept", "full"),                 # 5
    ("meta l4proto tcp [lookup @__set1] accept", "partial"),            # 6, ports in a set
    ("meta l4proto tcp [expr Range] accept", "partial"),                # 7, a port range
    ("meta nfproto ipv4 ip saddr 203.0.113.0/24 meta l4proto tcp tcp dport 4030 accept",
     "full"),                                                           # 8
    ("meta nfproto ipv4 meta l4proto tcp tcp dport 4040 accept", "full"),  # 9
    ("meta l4proto tcp tcp dport 4050 [limit] accept", "partial"),      # 10
    ("meta l4proto tcp tcp dport 4060 [reject]", "partial"),            # 11
    ("meta l4proto tcp tcp dport 4070 drop", "full"),                   # 12
]

# The legacy rules of the test's Debian 12 server, the four kinds its tab
# drew: the agent stores an x_tables match by its name alone.
LEGACY_RULES = [
    ("-i lo accept", "full"),
    ("[xt match conntrack] accept", "partial"),
    ("-p tcp [xt match tcp] accept", "partial"),
    ("-p icmp accept", "full"),
]


def document(rules=RAW_RULES, legacy=()):
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "app-03"
    doc["firewalld"] = {"status": "not_present"}
    doc["ufw"] = {"status": "not_present"}
    doc["containers"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [
        {"family": "inet", "name": "filter", "chains": [
            {"name": "input", "type": "filter", "hook": "input", "priority": 0,
             "policy": "drop",
             "rules": [{"text": text, "rendered": grade} for text, grade in rules]}]}]
        if rules else []}
    if legacy:
        doc["iptables"] = {"status": "collected", "tables": [
            {"name": "filter", "chains": [
                {"name": "INPUT", "builtin": True, "policy": "drop",
                 "rules": [{"text": text, "rendered": grade} for text, grade in legacy]}]}]}
    return doc


def kernel_rows(doc):
    """Every row of the kernel's own list as (action, port cell, tagged)."""
    html, _count = rl.kernel_leftovers_block("box", doc, "")
    rows = []
    for label in re.findall(r'<label class="fwr".*?</label>', html, re.S):
        action = re.search(r'<span class="st off[^"]*">([^<]*)</span>', label)
        port = re.search(r'<span class="rpn[^"]*">.*?</span>', label, re.S).group(0)
        rows.append((action.group(1) if action else "", port,
                     "not fully readable" in label))
    return rows


def strip(rules_tab):
    return dict(re.findall(r'<div class="l">([^<]+)</div><div class="n">([^<]*)</div>',
                           rules_tab))


NO_CLAIM = '<span class="rpn"></span>'
ANY_PORT = '<span class="rpn any">any port</span>'


# ------------------------------------------------------------ the port cell

def test_a_rule_whose_port_was_not_read_claims_no_port():
    """A set, a range, a limit and a reject: each is a token the agent wrote
    in brackets, so the page read no port out of the rule. "any port" there
    is a claim nobody read, on rules that do name ports."""
    rows = kernel_rows(document())
    for number in (3, 6, 7, 10, 11):
        _action, port, tagged = rows[number - 1]
        assert port == NO_CLAIM, (number, port)
        assert tagged, number


def test_a_port_match_this_page_cannot_read_is_not_any_port_either():
    """The agent graded it full and the port is written as a masked compare,
    which names no port in a form this page reads. The grade alone drew "any
    port" with no tag beside it."""
    rows = kernel_rows(document([("tcp dport & 0xff == 0x16 accept", "full")]))
    assert rows[0] == ("accept", NO_CLAIM, True)


def test_any_port_is_said_of_a_rule_read_in_full_that_names_none():
    rows = kernel_rows(document())
    assert rows[0] == ("accept", ANY_PORT, False)


@pytest.mark.parametrize("text,claim", [
    ("meta l4proto tcp tcp dport 22 accept", ("tcp/22", True)),
    ("meta nfproto ipv4 meta l4proto tcp tcp dport 4040 accept", ("tcp/4040", True)),
    ("meta mark 0x00000001 accept", ("", True)),
    ('iifname "lo" accept', ("", True)),
    ("ct state established,related accept", ("", True)),
    # the word and a number that are not a meta match
    ("counter jump meta-4", ("", True)),
    ("meta l4proto tcp tcp dport 4 accept", ("tcp/4", True)),
])
def test_a_meta_match_the_agent_named_is_read_as_before(text, claim):
    assert pp.rule_port_claim(text, "full") == claim


@pytest.mark.parametrize("text", [
    "meta 4 0x01000000 accept",
    "meta 5 0x02000000 drop",
    "meta 4 0x01000000 meta l4proto tcp tcp dport 22 accept",
    "meta l4proto tcp tcp dport 22 meta 17 0x00000001 accept",
    "meta 4 0x01000000",
])
def test_a_meta_match_the_agent_had_no_name_for_is_not_readable(text):
    """A key written as its number can select packets by something this page
    has no word for, so nothing is claimed of the rule, whatever else it
    names."""
    assert pp.rule_port_claim(text, "full") == ("", False)
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.UNREADABLE
    assert pp.readable_tokens(text, "full") is None


def test_iif_lo_as_the_agent_stored_it_says_not_fully_readable_and_no_port():
    """`iif lo accept` reached this page as `meta 4 0x01000000 accept`: the
    agent writes a meta key it has no name for as its number and the value
    as raw bytes, and grades the rule full, since it did decode the
    comparison. The row read "accept, any port", which is a rule that
    accepts everything, over a rule for the loopback interface alone
    (docs/RECORD.md 4.220, 4.454)."""
    rows = kernel_rows(document())
    assert rows[1] == ("accept", NO_CLAIM, True)


def test_a_port_a_rule_names_in_full_is_drawn_with_its_protocol():
    rows = kernel_rows(document())
    for number, port in ((4, "22"), (5, "4000"), (8, "4030"), (9, "4040"), (12, "4070")):
        _action, cell, tagged = rows[number - 1]
        assert cell == f'<span class="rpn">{port}<small>tcp</small></span>', number
        assert not tagged, number


def test_the_comment_match_is_still_looked_past():
    """The one bracket that cannot select a packet (docs/PRODUCT.md 4g)."""
    rows = kernel_rows(document(
        [("meta l4proto tcp tcp dport 22 [xt match comment] accept", "partial")]))
    assert rows[0][1] == '<span class="rpn">22<small>tcp</small></span>'


def test_a_legacy_rule_whose_match_is_a_name_claims_no_port():
    """The Debian 12 server of the same test: `-p tcp [xt match tcp] accept`
    is where `--dport` was, and it read "any port" on every row."""
    rows = kernel_rows(document(rules=(), legacy=LEGACY_RULES))
    assert rows[:4] == [("accept", ANY_PORT, False), ("accept", NO_CLAIM, True),
                        ("accept", NO_CLAIM, True), ("accept", ANY_PORT, False)]


# --------------------------------------------------------------- the action

@pytest.mark.parametrize("text,action", [
    ("meta l4proto tcp tcp dport 4060 [reject]", "reject"),
    ("[reject]", "reject"),
    ("meta l4proto tcp tcp dport 4070 drop", "drop"),
    ("ct state established,related accept", "accept"),
    # a jump to a chain whose name ends like a verdict is a jump
    ("counter jump to-reject", ""),
    ("counter jump [reject]", ""),
    # a bracket that is not the agent's reject, and one that is not last
    ("-p tcp [xt target REJECT]", ""),
    ("[reject] counter", ""),
    ("[limit]", ""),
    ("", ""),
])
def test_the_action_of_a_kernel_rule(text, action):
    assert rl.kernel_rule_action(text) == action


def test_a_reject_the_agent_wrote_in_brackets_is_the_rows_action():
    rows = kernel_rows(document())
    assert rows[10][0] == "reject"
    assert [action for action, _port, _tag in rows[:12]] == [
        "accept"] * 10 + ["reject", "drop"]


# ------------------------------------------------- no firewall active, or one

def test_no_firewall_active_is_not_said_over_rules_in_the_kernel():
    """The strip said one firewall and the card under it said none. Rules
    nobody named are a firewall in effect, so the card is not drawn."""
    html = rl.rules_tab_body(document(), "box")
    assert strip(html)["Firewalls active"] == "1"
    # the twelve rules and the chain's own policy, which is a row since 4.454
    assert strip(html)["Rules"] == "13"
    assert build.NO_FIREWALL not in html
    assert "In the kernel" in html


def test_it_is_not_said_over_legacy_rules_either():
    html = rl.rules_tab_body(document(rules=(), legacy=LEGACY_RULES), "box")
    assert strip(html)["Firewalls active"] == "1"
    assert build.NO_FIREWALL not in html


def test_an_empty_kernel_with_no_firewall_of_the_hosts_own_still_says_so():
    html = rl.rules_tab_body(document(rules=()), "box")
    assert strip(html)["Firewalls active"] == "0"
    assert html.count(build.NO_FIREWALL) == 1
    assert build.NOTHING_ELSE_IN_KERNEL in html


def test_a_provider_that_is_connected_with_no_firewall_here_leaves_the_card():
    """Nothing is counted, so the one depth that is called out still is."""
    html = rl.rules_tab_body(document(rules=()), "box", provider=thr.snapshot(attach=False))
    assert strip(html)["Firewalls active"] == "0"
    assert html.count(build.NO_FIREWALL) == 1


def test_it_is_not_said_beside_a_providers_firewall_that_is_counted():
    """A server whose only firewall is the provider's. The strip counted one
    and the card under the provider's own block said none
    (docs/RECORD.md 4.454)."""
    provider = thr.snapshot(rules=[thr.provider_rule()])
    html = rl.rules_tab_body(document(rules=()), "box", provider=provider)
    assert strip(html)["Firewalls active"] == "1"
    assert build.NO_FIREWALL not in html
    assert build.NOTHING_ELSE_IN_KERNEL in html


def test_it_is_not_said_beside_a_container_runtime_that_is_counted():
    doc = document(rules=())
    doc["containers"] = thr.containers()
    html = rl.rules_tab_body(doc, "box")
    assert strip(html)["Firewalls active"] == "1"
    assert build.NO_FIREWALL not in html


def test_ufw_switched_off_beside_a_providers_firewall_keeps_its_row_and_no_card():
    doc = document(rules=())
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "no"}, "defaults": {},
                  "rules": [], "rules6": []}
    provider = thr.snapshot(rules=[thr.provider_rule()])
    html = rl.rules_tab_body(doc, "box", provider=provider)
    assert strip(html)["Firewalls active"] == "1"
    assert build.NO_FIREWALL not in html
    assert "not enabled" in html


def test_the_card_stands_where_the_hosts_firewall_would():
    """After the provider's line and before the kernel's, the tab's order."""
    html = rl.rules_tab_body(document(rules=()), "box")
    assert (html.index(build.NO_PROVIDER_FIREWALL) < html.index(build.NO_FIREWALL)
            < html.index(build.NOTHING_ELSE_IN_KERNEL))


# ------------------------------------------------ a chain's policy is a row
#
# The Debian 12 server of the first big test ran iptables-legacy with the
# policy DROP on INPUT, and the tab showed that policy nowhere: four accepts
# and nothing saying that everything else is dropped. Its v4 and v6 rules
# stood in one list with nothing to tell them apart (docs/RECORD.md 4.220).
# A chain whose policy is not accept gets one row for it, after its rules,
# drawn like the row a firewalld zone's target gets (docs/RECORD.md 4.344,
# 4.454). A rule out of the older tables says which family it is.

def chain(name, policy, rules=(), hook="input"):
    return {"name": name, "type": "filter", "hook": hook, "priority": 0, "policy": policy,
            "rules": [{"text": text, "rendered": "full"} for text in rules]}


def legacy_chain(name, policy, rules=()):
    return {"name": name, "builtin": True, "policy": policy,
            "rules": [{"text": text, "rendered": "full"} for text in rules]}


def kernel_only(nft=(), v4=(), v6=()):
    """A server whose only rules are in the kernel: nftables chains, and the
    older tables' chains for each family."""
    doc = document(rules=())
    if nft:
        doc["nftables"] = {"status": "collected", "tables": [
            {"family": "inet", "name": "filter", "chains": list(nft)}]}
    if v4:
        doc["iptables"] = {"status": "collected", "tables": [{"name": "filter", "chains": list(v4)}]}
    if v6:
        doc["ip6tables"] = {"status": "collected", "tables": [{"name": "filter", "chains": list(v6)}]}
    return doc


def kernel_lines(doc, counted=()):
    """Every row of the kernel's list as its words: action, port, from, note."""
    html, _count = rl.kernel_leftovers_block("box", doc, "", counted)
    lines = []
    for label in re.findall(r'<label class="fwr".*?</label>', html, re.S):
        words = re.sub(r"<svg.*?</svg>", "", label, flags=re.S)
        lines.append(" ".join(re.sub(r"<[^>]+>", " ", words).split()))
    return lines


@pytest.mark.parametrize("policy", ["accept", "", None, "ACCEPT"])
def test_a_chain_that_accepts_what_no_rule_took_gets_no_policy_row(policy):
    doc = kernel_only(v4=[legacy_chain("INPUT", policy, ["-p icmp accept"])])
    assert kernel_lines(doc) == ["1 accept any port -p icmp accept v4"]


def test_a_chain_with_no_policy_of_its_own_gets_no_row():
    """A chain somebody made holds no policy: the kernel goes back to the
    chain that jumped."""
    made = {"name": "allowlist", "rules": [{"text": "-s 203.0.113.0/24 accept", "rendered": "full"}]}
    assert kernel_lines(kernel_only(v4=[made])) == ["1 accept any port -s 203.0.113.0/24 accept v4"]


def test_the_policy_of_a_chain_ufw_hangs_its_own_on_is_ufws_default():
    """ufw sets INPUT's policy itself and its block says it as incoming deny.
    Where ufw is counted the row is not drawn a second time, also when
    somebody put a rule of their own in the same chain."""
    doc = kernel_only(nft=[chain("INPUT", "drop", ["counter jump ufw-before-input"])])
    assert kernel_lines(doc, counted=("ufw",)) == []
    doc = kernel_only(nft=[chain("INPUT", "drop", ["counter jump ufw-before-input",
                                                   "tcp dport 8080 counter accept"])])
    assert kernel_lines(doc, counted=("ufw",)) == ["1 accept 8080 tcp dport 8080 counter accept"]


def test_where_ufw_is_not_counted_its_chains_policy_is_a_row_like_its_lines():
    doc = kernel_only(nft=[chain("INPUT", "drop", ["counter jump ufw-before-input"])])
    assert kernel_lines(doc) == ["1 any port counter jump ufw-before-input",
                                 "2 drop any port anywhere policy, chain INPUT"]


def test_the_real_ufw_server_still_lists_nothing_in_the_kernel():
    import test_rules_kernel_named_jump as jump
    assert rl.kernel_leftovers_block("box", jump.real_document(), "", ("ufw",)) == ("", 0)


def test_a_legacy_chain_that_drops_says_so_after_its_rules():
    doc = kernel_only(v4=[legacy_chain("INPUT", "drop", ["-i lo accept", "-p icmp accept"])])
    assert kernel_lines(doc) == ["1 accept any port -i lo accept v4",
                                 "2 accept any port -p icmp accept v4",
                                 "3 drop any port anywhere policy, chain INPUT, v4"]


def test_a_chain_that_drops_and_holds_no_rule_is_one_row():
    doc = kernel_only(v4=[legacy_chain("FORWARD", "drop")])
    assert kernel_lines(doc) == ["1 drop any port anywhere policy, chain FORWARD, v4"]
    html = rl.rules_tab_body(doc, "box")
    assert strip(html)["Firewalls active"] == "1"
    assert strip(html)["Rules"] == "1"
    assert build.NO_FIREWALL not in html


def test_each_family_of_the_older_tables_is_told_apart():
    doc = kernel_only(v4=[legacy_chain("INPUT", "drop", ["-p icmp accept"])],
                      v6=[legacy_chain("INPUT", "drop", ["-p ipv6-icmp accept"])])
    assert kernel_lines(doc) == ["1 accept any port -p icmp accept v4",
                                 "2 drop any port anywhere policy, chain INPUT, v4",
                                 "3 accept any port -p ipv6-icmp accept v6",
                                 "4 drop any port anywhere policy, chain INPUT, v6"]


def test_an_nftables_chain_that_drops_says_so_too_and_names_no_family():
    """Its table says which families it is for, in the opened row."""
    doc = kernel_only(nft=[chain("input", "drop", ["meta l4proto tcp tcp dport 22 accept"])])
    assert kernel_lines(doc) == ["1 accept 22 tcp meta l4proto tcp tcp dport 22 accept",
                                 "2 drop any port anywhere policy, chain input"]


def test_the_policy_rows_card_names_the_table_the_chain_and_the_policy():
    doc = kernel_only(v4=[legacy_chain("INPUT", "drop")])
    html, count = rl.kernel_leftovers_block("box", doc, "4m ago")
    assert count == 1
    card = html.split('<div class="rev">', 1)[1]
    for line in ("filter", "INPUT", "drop", "agent reported 4m ago"):
        assert line in card, line


def test_the_twelve_raw_rules_end_on_their_chains_policy():
    lines = kernel_lines(document())
    assert len(lines) == 13
    assert lines[12] == "13 drop any port anywhere policy, chain input"
