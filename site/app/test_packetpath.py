"""The packet path walk.

    Run from site/app: python3 -m pytest test_packetpath.py

These tests are the review. The owner reads every diff and has said he cannot be
relied on to catch a subtle bug in one, and the subtle
bugs available here are all of the same kind: claiming a rule selects a port
when it does not, or quietly dropping a rule that might. So the classifier gets
the boundary cases, the walk gets a cycle and a missing target, and the ordering
gets equal priorities and a hostile priority value.

The document shapes below follow agent/internal/hostdoc/hostdoc.go, and the rule
text follows what agent/internal/collect/nftrender_linux.go actually emits,
which is not always what nft would print.
"""
import pytest

import packetpath as pp


def rule(text, rendered="full", comment=""):
    out = {"text": text, "rendered": rendered}
    if comment:
        out["comment"] = comment
    return out


def chain(name, rules=(), hook=None, priority=None, policy=None, ctype=None):
    out = {"name": name, "rules": list(rules)}
    if hook:
        out["hook"] = hook
    if priority is not None:
        out["priority"] = priority
    if policy:
        out["policy"] = policy
    if ctype:
        out["type"] = ctype
    return out


def doc(tables=(), listening=(), docker=(), podman=(), nft_status="collected"):
    return {
        "schema_version": 1,
        "sockets": {"status": "collected", "listening": list(listening)},
        "nftables": {"status": nft_status, "tables": list(tables)},
        "containers": {"status": "collected", "docker": list(docker), "podman": list(podman)},
    }


# ------------------------------------------------------------- classify_rule

@pytest.mark.parametrize("text,expected", [
    # The plain case, in the renderer's own shorthand for equality.
    ("ip protocol tcp tcp dport 22 counter accept", pp.NAMES_PORT),
    # A different port is a different port, and is not shown on this page.
    ("ip protocol tcp tcp dport 80 counter accept", pp.OTHER_PORT),
    # No port match at all: evaluated whatever the port is.
    ("ct state established accept", pp.EVERY_PORT),
    ('iifname "lo" counter accept', pp.EVERY_PORT),
    # Inversion, both ways round.
    ("tcp dport != 22 accept", pp.OTHER_PORT),
    ("tcp dport != 80 accept", pp.NAMES_PORT),
    # Ranges through comparison operators, on both sides of the boundary.
    ("tcp dport >= 22 accept", pp.NAMES_PORT),
    ("tcp dport >= 23 accept", pp.OTHER_PORT),
    ("tcp dport > 21 accept", pp.NAMES_PORT),
    ("tcp dport > 22 accept", pp.OTHER_PORT),
    ("tcp dport <= 22 accept", pp.NAMES_PORT),
    ("tcp dport <= 21 accept", pp.OTHER_PORT),
    ("tcp dport < 23 accept", pp.NAMES_PORT),
    ("tcp dport < 22 accept", pp.OTHER_PORT),
    # The anonymous transport-header form, used when no l4proto was matched.
    ("th dport 22 accept", pp.NAMES_PORT),
])
def test_classifier_reads_what_the_text_says(text, expected):
    assert pp.classify_rule(text, "full", "tcp", 22) == expected


@pytest.mark.parametrize("text", [
    # A set: the port may well be in it, and the agent cannot read it.
    "meta l4proto tcp [lookup @addr-set-sshd] accept",
    # An x_tables match: iptables keeps --dport inside the match payload,
    # which the agent stores by name only. This is why a legacy rule can never
    # be shown as naming a port.
    "ip protocol tcp [xt match multiport] counter accept",
    # A raw transport-header offset. This one is real, from ufw's DHCP rule,
    # and it matches sport 67 dport 68 while naming neither.
    "ip protocol udp @th,0,32 0x00430044 counter accept",
    # A masked comparison on the port itself.
    "tcp dport & 0xff == 0x16 accept",
])
def test_a_match_the_agent_could_not_decode_is_never_called_readable(text):
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.UNREADABLE


# --------------------------------------------- raw payload loads and the port
#
# Every text below is taken verbatim from a real host document, the production
# copy of 2026-08-16, except where it is marked as constructed to probe a
# boundary the fleet does not happen to have.

@pytest.mark.parametrize("text", [
    # firewalld's policy rules on almabox: 33 loads at @nh,96,16 and 39 at
    # @nh,128,16 across its ruleset. Both are IPv4 address prefixes, the source
    # at byte 12 and the destination at byte 16 (RFC 791 section 3.1), and
    # 0x0a58 is 10.88, netavark's default subnet.
    "meta nfproto ipv4 @nh,96,16 0x0a58 jump mangle_PRE_trusted",
    "meta nfproto ipv4 @nh,96,16 0x0a58 @nh,128,16 0x0a58 return",
    # From a real Ubuntu server, a one-byte load at byte 16.
    "meta nfproto ipv4 @nh,128,8 0x0a counter accept",
    # The boundary itself, constructed: the last bit of the IPv4 fixed header.
    "meta nfproto ipv4 @nh,144,16 0x0000 accept",
])
def test_a_network_header_load_inside_the_fixed_header_is_not_a_port_match(text):
    """The finding this pair of tests exists for. The owner's own host showed 56
    rules "not fully readable" on tcp/22 and 43 of them were these, which made
    the flagship view look blind at the one host we look at most.

    A load ending at or before bit 160 is inside the IPv4 fixed header, which
    is five 32-bit words at minimum (RFC 791 section 3.1), and inside the first
    160 bits of the IPv6 header, which is a fixed 40 octets (RFC 8200 section
    3). Neither carries a transport port. So the rule carries no port match,
    which is a stronger and still true statement than "not fully readable".
    """
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.EVERY_PORT


@pytest.mark.parametrize("text", [
    # Real, from almabox: 64 bits at offset 192. On IPv6 that is half the
    # destination address, but nothing in this module knows the family, and on
    # IPv4 bit 160 onward is the transport header. It stays unreadable, and it
    # is the reason the bound is 160 and not 320.
    "meta nfproto ipv6 @nh,192,64 0xfd0000000000000 accept",
    # Constructed, one bit past the bound: on IPv4 with no options this is
    # exactly where the source port sits.
    "@nh,160,16 0x0016 accept",
    # The transport header is where ports live, whatever the offset.
    "ip protocol udp @th,0,32 0x00430044 counter accept",
    "ip protocol tcp @th,0,8 0x00 counter accept",
    # The link layer is deliberately not narrowed at all.
    "@ll,0,16 0x0806 drop",
])
def test_a_load_that_could_reach_a_port_stays_unreadable(text):
    """The other half, and the half that matters. Narrowing the rule far
    enough to be useful must not narrow it far enough to be wrong."""
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.UNREADABLE


def test_one_readable_load_beside_one_that_is_not_leaves_the_rule_unreadable():
    """A rule is only as readable as its least readable token."""
    text = "meta nfproto ipv4 @nh,96,16 0x0a58 @th,0,32 0x00430044 accept"
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.UNREADABLE


def test_a_readable_network_load_beside_a_real_dport_still_names_the_port():
    """The narrowing must not swallow a port match sitting next to it."""
    text = "meta nfproto ipv4 @nh,96,16 0x0a58 tcp dport 22 accept"
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.NAMES_PORT
    assert pp.classify_rule(text, "full", "tcp", 80) == pp.OTHER_PORT


def test_the_agents_grade_still_outranks_a_readable_network_load():
    """Narrowing the payload check must not let a rule the renderer itself
    called partial through the door."""
    text = "meta nfproto ipv4 @nh,96,16 0x0a58 accept"
    assert pp.classify_rule(text, "partial", "tcp", 22) == pp.UNREADABLE
    assert pp.classify_rule(text, "none", "tcp", 22) == pp.UNREADABLE


def test_the_comment_match_is_looked_past_because_the_kernel_says_it_always_matches():
    """The real rule from a real Ubuntu server. ufw writes `-m comment` on most
    of what it generates, which grades the rule partial, and treating that as
    an unreadable port match made the flagship view say it could not read the
    most common rule there is. net/netfilter/xt_comment.c returns true
    unconditionally, so it cannot select, and looking past it is sound."""
    text = "ip protocol tcp tcp dport 22 [xt match comment] counter accept"
    assert pp.classify_rule(text, "partial", "tcp", 22) == pp.NAMES_PORT
    assert pp.classify_rule(text, "partial", "tcp", 80) == pp.OTHER_PORT


def test_the_exception_is_only_for_comment_and_does_not_leak_to_other_matches():
    """A comment next to a match that can select leaves the rule unreadable,
    because the other match is still undecoded."""
    text = "ip protocol tcp [xt match comment] [xt match multiport] counter accept"
    assert pp.classify_rule(text, "partial", "tcp", 22) == pp.UNREADABLE
    recent = "ip protocol tcp tcp dport 22 [xt match comment] [xt match recent] counter"
    assert pp.classify_rule(recent, "partial", "tcp", 22) == pp.UNREADABLE


def test_a_rule_that_is_nothing_but_a_comment_is_not_called_readable():
    assert pp.classify_rule("[xt match comment]", "none", "tcp", 22) == pp.UNREADABLE


def test_the_agents_own_grade_outranks_the_text():
    """A rule graded below full may have lost a token the renderer never wrote
    down, so its text cannot be trusted even when it looks complete."""
    text = "ip protocol tcp tcp dport 22 counter accept"
    assert pp.classify_rule(text, "full", "tcp", 22) == pp.NAMES_PORT
    assert pp.classify_rule(text, "partial", "tcp", 22) == pp.UNREADABLE
    assert pp.classify_rule(text, "none", "tcp", 22) == pp.UNREADABLE


def test_a_rule_pinned_to_another_protocol_does_not_select_this_one():
    assert pp.classify_rule("ip protocol udp udp dport 22 accept", "full", "tcp", 22) \
        == pp.OTHER_PORT
    assert pp.classify_rule("meta l4proto udp udp dport 22 accept", "full", "udp", 22) \
        == pp.NAMES_PORT
    assert pp.classify_rule("ip6 nexthdr tcp tcp dport 22 accept", "full", "tcp", 22) \
        == pp.NAMES_PORT


def test_two_dport_comparisons_that_disagree_are_not_guessed_at():
    """The renderer does not emit this today. If it ever does, the honest
    answer is that this module does not know how they combine."""
    assert pp.classify_rule("tcp dport 22 tcp dport 80 accept", "full", "tcp", 22) \
        == pp.UNREADABLE


def test_a_port_number_elsewhere_in_the_text_is_not_a_dport():
    """An address, a mark or a counter that happens to contain 22 must not be
    read as a destination port."""
    assert pp.classify_rule("ip saddr 10.0.0.22 accept", "full", "tcp", 22) == pp.EVERY_PORT
    assert pp.classify_rule("tcp sport 22 accept", "full", "tcp", 22) == pp.EVERY_PORT


# ------------------------------------------------------------------ the walk

def test_the_walk_follows_jumps_and_keeps_evaluation_order():
    """ufw puts nothing in INPUT but jumps, so a walk that does not follow them
    shows an empty page on the most common firewall there is."""
    table = {"family": "ip", "name": "filter", "chains": [
        chain("INPUT", [rule("counter jump ufw-before-input")],
              hook="input", priority=0, policy="drop"),
        chain("ufw-before-input", [rule("counter jump ufw-user-input")]),
        chain("ufw-user-input", [rule("ip protocol tcp tcp dport 22 counter accept"),
                                 rule("ip protocol tcp tcp dport 80 counter accept")]),
    ]}
    steps, counts = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert [s[0] for s in steps] == ["INPUT", "ufw-before-input", "ufw-user-input"]
    assert [s[5] for s in steps] == [0, 1, 2]  # depth grows as jumps are followed
    assert steps[-1][4] == pp.NAMES_PORT
    assert counts[pp.OTHER_PORT] == 1  # tcp/80 counted, not shown


def test_rules_naming_another_port_are_counted_rather_than_silently_dropped():
    """Hiding them keeps the page readable. Not counting them would make the
    page a liar about how much it left out."""
    table = {"family": "ip", "name": "filter", "chains": [
        chain("INPUT", [rule("tcp dport 80 accept"), rule("tcp dport 443 accept"),
                        rule("tcp dport 22 accept")], hook="input", priority=0)]}
    steps, counts = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert len(steps) == 1
    assert counts[pp.OTHER_PORT] == 2


def test_a_jump_cycle_terminates():
    """nftables rejects loops. A document is not a kernel, and a page that
    hangs the render timer takes the dashboard down with it."""
    table = {"family": "ip", "name": "filter", "chains": [
        chain("A", [rule("counter jump B")], hook="input", priority=0),
        chain("B", [rule("counter jump A")]),
    ]}
    steps, _ = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert [s[0] for s in steps] == ["A", "B"]


def test_a_jump_to_a_chain_that_is_not_in_the_table_is_survived():
    table = {"family": "ip", "name": "filter", "chains": [
        chain("INPUT", [rule("counter jump nowhere")], hook="input", priority=0)]}
    steps, _ = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert len(steps) == 1


def test_the_same_chain_reached_twice_is_walked_twice():
    """Two jumps to one chain really are two traversals, and the packet meets
    those rules twice. Only a cycle is cut."""
    table = {"family": "ip", "name": "filter", "chains": [
        chain("INPUT", [rule("counter jump LOG"), rule("counter jump LOG")],
              hook="input", priority=0),
        chain("LOG", [rule("counter accept")]),
    ]}
    steps, _ = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert [s[0] for s in steps] == ["INPUT", "LOG", "INPUT", "LOG"]


def test_goto_is_followed_like_jump():
    table = {"family": "ip", "name": "filter", "chains": [
        chain("INPUT", [rule("counter goto OTHER")], hook="input", priority=0),
        chain("OTHER", [rule("tcp dport 22 accept")]),
    ]}
    steps, _ = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert steps[-1][4] == pp.NAMES_PORT


def test_a_rule_that_is_not_readable_is_still_followed():
    """The unreadable rule is the one most likely to be the one that matters,
    so its jump is taken rather than skipped."""
    table = {"family": "ip", "name": "filter", "chains": [
        chain("INPUT", [rule("[xt match recent] counter jump LIMIT", rendered="partial")],
              hook="input", priority=0),
        chain("LIMIT", [rule("counter [xt target REJECT]", rendered="partial")]),
    ]}
    steps, _ = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert [s[0] for s in steps] == ["INPUT", "LIMIT"]


# -------------------------------------------------------------- the ordering

def test_base_chains_come_back_in_the_kernels_priority_order():
    """Lower priority runs first, per net/netfilter/core.c. fail2ban at -1 and
    ufw's filter INPUT at 0 is the real pair this was built against."""
    tables = [
        {"family": "ip", "name": "filter",
         "chains": [chain("INPUT", hook="input", priority=0, policy="drop")]},
        {"family": "inet", "name": "f2b-table",
         "chains": [chain("f2b-chain", hook="input", priority=-1, policy="accept")]},
    ]
    groups = pp.base_chains(doc(tables), "v4", "input")
    assert [g[0] for g in groups] == [-1, 0]
    assert groups[0][1][0][1]["name"] == "f2b-chain"


def test_equal_priorities_are_grouped_rather_than_ordered():
    """The kernel breaks a priority tie by registration order, which a host
    document does not record. Grouping them is how the page says so instead of
    picking one."""
    tables = [
        {"family": "ip", "name": "filter",
         "chains": [chain("INPUT", hook="input", priority=0)]},
        {"family": "inet", "name": "netavark",
         "chains": [chain("INPUT", hook="input", priority=0)]},
    ]
    groups = pp.base_chains(doc(tables), "v4", "input")
    assert len(groups) == 1
    assert len(groups[0][1]) == 2


def test_a_priority_that_is_not_a_number_sorts_last_and_does_not_raise():
    """Sorting a string against an int raises, and a raised exception here
    takes out the whole dashboard render."""
    tables = [
        {"family": "ip", "name": "b", "chains": [chain("X", hook="input", priority="early")]},
        {"family": "ip", "name": "a", "chains": [chain("Y", hook="input", priority=0)]},
    ]
    groups = pp.base_chains(doc(tables), "v4", "input")
    assert [g[0] for g in groups] == [0, None]


def test_a_v4_packet_does_not_meet_ip6_chains_and_the_reverse():
    """iptables and ip6tables are separate rule sets and so are nft's ip and
    ip6 families. Nothing here infers one from the other (PRODUCT.md 4b)."""
    tables = [
        {"family": "ip", "name": "filter", "chains": [chain("INPUT", hook="input", priority=0)]},
        {"family": "ip6", "name": "filter", "chains": [chain("INPUT", hook="input", priority=0)]},
        {"family": "inet", "name": "both", "chains": [chain("INPUT", hook="input", priority=1)]},
    ]
    v4 = pp.base_chains(doc(tables), "v4", "input")
    v6 = pp.base_chains(doc(tables), "v6", "input")
    assert [t["name"] for _, members in v4 for t, _ in members] == ["filter", "both"]
    assert [t["name"] for _, members in v6 for t, _ in members] == ["filter", "both"]
    assert [t["family"] for _, members in v4 for t, _ in members] == ["ip", "inet"]
    assert [t["family"] for _, members in v6 for t, _ in members] == ["ip6", "inet"]


def test_families_off_the_ip_path_are_named_rather_than_dropped():
    tables = [{"family": "bridge", "name": "br", "chains": []},
              {"family": "ip", "name": "filter", "chains": []}]
    assert pp.excluded_families(doc(tables)) == ["bridge br"]


# ------------------------------------------------------------------ the path

SSHD_V4 = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
           "process_name": "sshd"}
SSHD_V6 = {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 22,
           "process_name": "sshd"}
JELLYFIN = {"id": "abc", "name": "jellyfin",
            "ports": [{"host_ip": "0.0.0.0", "host_port": 8096, "container_port": 8096,
                       "protocol": "tcp"}]}


def test_a_port_held_by_a_socket_takes_the_local_path():
    path = pp.path_for(doc(listening=[SSHD_V4]), "tcp", 22, "v4")
    assert path["delivery_local"] and not path["delivery_forwarded"]
    assert [s["hook"] for s in path["stages"]] == list(pp.LOCAL_HOOKS)


def test_a_published_container_port_also_takes_the_forwarded_path():
    path = pp.path_for(doc(podman=[JELLYFIN]), "tcp", 8096, "v4")
    assert path["delivery_forwarded"]
    assert "forward" in [s["hook"] for s in path["stages"]]
    assert "postrouting" in [s["hook"] for s in path["stages"]]


def test_a_proxied_publication_shows_both_paths_at_once():
    """Docker's userland proxy holds a real socket while a DNAT rule exists for
    the same port. Showing only one of the two would hide the more interesting
    half, which is the whole reason this product exists."""
    proxied = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8096,
               "process_name": "docker-proxy"}
    path = pp.path_for(doc(listening=[proxied], docker=[JELLYFIN]), "tcp", 8096, "v4")
    assert path["delivery_local"] and path["delivery_forwarded"]
    hooks = [s["hook"] for s in path["stages"]]
    assert "input" in hooks and "forward" in hooks


def test_the_v6_socket_is_never_read_as_the_v4_answer():
    d = doc(listening=[SSHD_V6])
    assert pp.path_for(d, "tcp", 22, "v6")["sockets"]
    assert pp.path_for(d, "tcp", 22, "v4")["sockets"] == []


def test_traced_ports_covers_sockets_and_publications_without_repeating_one():
    d = doc(listening=[SSHD_V4, SSHD_V6], podman=[JELLYFIN])
    assert [key for key, _ in pp.traced_ports(d)] == [("tcp", 22), ("tcp", 8096)]


def test_legacy_rules_are_counted_so_the_page_can_say_it_cannot_place_them():
    d = doc()
    d["iptables"] = {"status": "collected", "tables": [
        {"name": "filter", "chains": [{"name": "INPUT", "rules": [rule("-p tcp [xt match tcp]")]}]}]}
    d["ip6tables"] = {"status": "collected", "tables": [
        {"name": "filter", "chains": [{"name": "INPUT", "rules": [rule("-p tcp [xt match tcp]")]}]}]}
    assert pp.legacy_rule_count(d) == 2


# ---------------------------------------------------------- hostile documents

@pytest.mark.parametrize("broken", [
    {},
    {"nftables": None},
    # Wrong types, not just nulls. Every one of these below was measured to
    # raise AttributeError on 2026-08-16, while this test was passing, because
    # the cases above are all None and `x or []` catches None and nothing else.
    # A host document is stored verbatim on purpose (PRODUCT.md 4e) and the
    # ingest validates only the envelope, so any enrolled host can post one.
    {"nftables": {"tables": {"a": 1}}},
    {"nftables": {"tables": "oops"}},
    {"nftables": {"tables": [None]}},
    {"nftables": {"tables": [{"family": "ip", "name": "f", "chains": "oops"}]}},
    {"nftables": {"tables": [{"family": "ip", "name": "f", "chains": [None]}]}},
    {"nftables": {"tables": [{"family": "ip", "name": "f", "chains": [
        {"name": "c", "hook": "input", "priority": 0, "rules": "oops"}]}]}},
    {"nftables": {"tables": [{"family": "ip", "name": "f", "chains": [
        {"name": "c", "hook": "input", "priority": 0, "rules": [None]}]}]}},
    {"sockets": {"listening": [None]}},
    {"sockets": {"listening": "oops"}},
    {"sockets": "oops"},
    {"containers": {"docker": [None]}},
    {"containers": {"docker": [{"ports": [None]}]}},
    {"containers": {"docker": [{"ports": "oops"}]}},
    {"iptables": {"tables": [None]}},
    {"iptables": {"tables": [{"chains": [None]}]}},
    {"nftables": {"status": "collected", "tables": None}},
    {"nftables": {"status": "collected", "tables": [{"family": "ip", "name": "f", "chains": None}]}},
    {"nftables": {"status": "collected",
                  "tables": [{"family": "ip", "name": "f",
                              "chains": [{"name": "INPUT", "hook": "input", "rules": None}]}]}},
    {"sockets": None},
    {"containers": {"status": "collected", "docker": None}},
])
def test_a_malformed_document_renders_nothing_rather_than_raising(broken):
    """Every section of a host document can fail independently, and a null
    where a list belongs must not take the whole dashboard render down."""
    path = pp.path_for(broken, "tcp", 22, "v4")
    assert path["port"] == 22


def test_a_rule_with_no_text_at_all_is_survived():
    table = {"family": "ip", "name": "filter",
             "chains": [chain("INPUT", [{}, {"text": None, "rendered": None}],
                              hook="input", priority=0)]}
    steps, counts = pp.walk_chain(table, table["chains"][0], "tcp", 22)
    assert len(steps) == 2
    assert counts[pp.UNREADABLE] == 2


def test_a_port_that_is_not_an_integer_never_reaches_a_trace():
    d = doc(listening=[{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                        "port": "twenty-two"}])
    assert pp.traced_ports(d) == []


def test_deeply_nested_jumps_stop_at_the_depth_limit():
    chains = [chain("c0", [rule("counter jump c1")], hook="input", priority=0)]
    for i in range(1, 40):
        chains.append(chain(f"c{i}", [rule(f"counter jump c{i + 1}")]))
    table = {"family": "ip", "name": "filter", "chains": chains}
    steps, _ = pp.walk_chain(table, chains[0], "tcp", 22)
    assert len(steps) <= pp._MAX_DEPTH + 1

# ------------------------------------- the order of the checks inside a rule
#
# Sharing the readability reader with the Rules tab moved the destination-port
# check ahead of the protocol check, and that quietly changed an answer: a rule
# pinned to tcp, asked about a udp port, went from "names a different port" to
# "not fully readable". The control plane runs its own independent classifier
# and its cross-boundary test is what caught it. These pin the order here too,
# so the site suite catches it next time rather than CI.

MASKED_TCP = "meta l4proto tcp tcp dport & 0xff == 0x16 accept"


def test_a_rule_for_another_protocol_is_answered_by_the_protocol_alone():
    """Its port never has to be read, so a port match this module cannot decode
    does not weaken the answer. Saying "not fully readable" here would be
    saying less than the text supports."""
    assert pp.classify_rule(MASKED_TCP, "full", "udp", 137) == pp.OTHER_PORT


def test_a_masked_port_comparison_is_unreadable_for_its_own_protocol():
    """The same rule, asked about the protocol it is pinned to. Now the port
    does have to be read, and a masked comparison selects a port without ever
    writing it as a decimal."""
    assert pp.classify_rule(MASKED_TCP, "full", "tcp", 22) == pp.UNREADABLE


def test_the_port_claim_never_reads_a_masked_comparison():
    """The Rules tab has no protocol to short-circuit on, so it asks the port
    question directly and must refuse this rule."""
    assert pp.rule_port_claim(MASKED_TCP, "full") == ("", False)


# ============================================ the outward half, 2026-08-22
#
# `docs/RECORD.md` 4.91. It narrows where to look and does not answer the
# question, so the tests are mostly about what it refuses to say.


def table(family, name, chains):
    return {"family": family, "name": name, "chains": list(chains)}


def ufw_like(policy="drop", rules=()):
    """A base chain on input with a policy and some rules, the ufw shape."""
    return table("ip", "filter", [
        chain("INPUT", list(rules), hook="input", priority=0,
              policy=policy, ctype="filter")])


def path_for_port(tables, port=443, listening=None):
    listening = listening if listening is not None else [
        {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
         "port": port, "process_name": "caddy", "pid": 1}]
    return pp.path_for(doc(tables=tables, listening=listening), "tcp", port, "v4")


# ------------------------------------------------------- reading a verdict

@pytest.mark.parametrize("text,ends", [
    ("ip protocol tcp tcp dport 443 counter drop", True),
    ("ip protocol tcp tcp dport 443 counter reject", True),
    ("ip protocol tcp tcp dport 443 reject with icmpx port-unreachable", True),
    ("ip protocol tcp tcp dport 443 counter accept", False),
    ("counter jump ufw-user-input", False),
    ("counter return", False),
    # queue hands the packet to userspace, which may do anything. Calling that
    # stopped would be stating an outcome this module cannot see.
    ("ip protocol tcp tcp dport 443 counter queue num 0", False),
])
def test_only_drop_and_reject_end_a_journey(text, ends):
    assert pp.rule_ends_the_journey(text) is ends


@pytest.mark.parametrize("text,passes", [
    ("ip protocol tcp tcp dport 443 counter accept", True),
    # The trap this test is for. ufw's commonest rule is a jump to a chain
    # whose NAME ends in the letters of a verdict, and an unanchored pattern
    # reads it as one. The port here is 443 so that the only thing that could
    # make it True is the verdict being misread.
    ("ip protocol tcp tcp dport 443 counter jump ufw-user-limit-accept", False),
    ("counter jump ufw-not-local", False),
    ("ip protocol tcp tcp dport 443 counter drop", False),
])
def test_a_chain_named_after_a_verdict_is_not_a_verdict(text, passes):
    """Only the anchoring. Whether an accept is unconditional is a different
    question and `test_only_an_unconditional_accept_counts` owns it."""
    assert pp.rule_lets_it_pass(text, "tcp", 443) is passes


# --------------------------------------------- when there is no view at all

def test_a_port_nobody_probed_gets_no_outward_view():
    """docs/PRODUCT.md 4b. The alternative is a page reasoning about a silence
    nobody observed."""
    path = path_for_port([ufw_like()])
    assert pp.outward_path(path, "not_tested", measured=False) is None


def test_a_port_that_answered_marks_no_checkpoint():
    """Something on this path let it through and the document cannot say
    which, so marking any of them is the same guess pointing the other way."""
    path = path_for_port([ufw_like(rules=[rule("ip protocol tcp tcp dport 443 counter drop")])])
    view = pp.outward_path(path, "connect_succeeded")
    assert view["answered"] is True
    assert view["checkpoints"] == []


# ------------------------------------------------ what a silence points at

def test_a_drop_naming_this_port_is_pointed_at_and_quoted():
    text = "ip protocol tcp tcp dport 443 counter drop"
    path = path_for_port([ufw_like(policy="accept", rules=[rule(text)])])
    view = pp.outward_path(path, "no_response")
    notes = view["checkpoints"][0]["notes"]
    assert (pp.ENDS_ON_THIS_PORT, text) in notes


def test_a_drop_policy_with_nothing_naming_the_port_is_pointed_at():
    path = path_for_port([ufw_like(policy="drop", rules=[
        rule("ip protocol tcp tcp dport 80 counter accept")])])
    view = pp.outward_path(path, "no_response")
    keys = [k for k, _q in view["checkpoints"][0]["notes"]]
    assert pp.POLICY_ENDS in keys


def test_an_accept_on_this_port_means_the_policy_is_not_reached():
    """A policy only decides when nothing before it did."""
    path = path_for_port([ufw_like(policy="drop", rules=[
        rule("ip protocol tcp tcp dport 443 counter accept")])])
    view = pp.outward_path(path, "no_response")
    keys = [k for entry in view["checkpoints"] for k, _q in entry["notes"]]
    assert pp.POLICY_ENDS not in keys


def test_a_rule_we_could_not_read_is_neither_ruled_in_nor_out():
    path = path_for_port([ufw_like(policy="accept", rules=[
        rule("ip protocol tcp [xt match multiport] counter drop", rendered="partial")])])
    view = pp.outward_path(path, "no_response")
    keys = [k for k, _q in view["checkpoints"][0]["notes"]]
    assert pp.CANNOT_RULE_OUT in keys


def test_a_chain_that_says_nothing_is_not_pointed_at():
    """An empty list is not a claim that the packet got through. The screen
    says that once rather than on every row."""
    path = path_for_port([ufw_like(policy="accept", rules=[
        rule("ip protocol tcp tcp dport 80 counter drop")])])
    assert pp.outward_path(path, "no_response")["checkpoints"] == []


def test_a_refused_connect_points_at_the_same_things_a_timeout_does():
    """The two are different measurements and the ruleset reading of them is
    the same one. Telling them apart is the prober's job and it already did."""
    text = "ip protocol tcp tcp dport 443 counter drop"
    path = path_for_port([ufw_like(policy="accept", rules=[rule(text)])])
    refused = pp.outward_path(path, "connect_refused")
    timed_out = pp.outward_path(path, "no_response")
    assert refused["checkpoints"] == timed_out["checkpoints"]
    assert refused["state"] != timed_out["state"]


def test_the_outward_view_states_no_outcome():
    """docs/PRODUCT.md 4g's last paragraph, held here as well as on the inside
    half. This module emits keys and quotes, never sentences, and the words
    below are the ones it may not produce."""
    path = path_for_port([ufw_like(policy="drop", rules=[
        rule("ip protocol tcp tcp dport 443 counter drop")])])
    view = pp.outward_path(path, "no_response")
    emitted = " ".join(
        [view["state"]] +
        [k for e in view["checkpoints"] for k, _q in e["notes"]] +
        [e["hook"] + e["table"] + e["chain"] for e in view["checkpoints"]])
    for word in ("reachable", "unreachable", "allowed", "blocked"):
        assert word not in emitted.lower(), f"the outward view said {word}"


def test_a_conditional_accept_does_not_hide_a_drop_policy():
    """Found by reading the rendered page rather than by a test. `ct state
    established accept` carries no port match, so it is evaluated for this
    port, and treating it as an accept said a drop policy was never reached.
    A new inbound connection is not established, so for the packet this page is
    about that rule matches nothing."""
    path = path_for_port([ufw_like(policy="drop", rules=[
        rule("ct state established accept")])])
    view = pp.outward_path(path, "no_response")
    keys = [k for entry in view["checkpoints"] for k, _q in entry["notes"]]
    assert pp.POLICY_ENDS in keys


def test_an_interface_match_does_not_hide_a_drop_policy_either():
    path = path_for_port([ufw_like(policy="drop", rules=[
        rule('iifname "lo" counter accept')])])
    view = pp.outward_path(path, "no_response")
    keys = [k for entry in view["checkpoints"] for k, _q in entry["notes"]]
    assert pp.POLICY_ENDS in keys


def test_an_unconditional_accept_on_this_port_does_hide_it():
    """The other side of the same rule. `ufw allow 443` writes exactly this,
    and a chain where it sits is not a chain whose policy decides."""
    path = path_for_port([ufw_like(policy="drop", rules=[
        rule("ip protocol tcp tcp dport 443 counter accept")])])
    view = pp.outward_path(path, "no_response")
    keys = [k for entry in view["checkpoints"] for k, _q in entry["notes"]]
    assert pp.POLICY_ENDS not in keys


@pytest.mark.parametrize("text,unconditional", [
    ("ip protocol tcp tcp dport 443 counter accept", True),
    ("tcp dport 443 accept", True),
    ("ct state established accept", False),
    ('iifname "lo" counter accept', False),
    ("ip saddr 10.0.0.0/8 ip protocol tcp tcp dport 443 counter accept", False),
    ("ip protocol tcp tcp dport 443 counter drop", False),
])
def test_only_an_unconditional_accept_counts(text, unconditional):
    assert pp.rule_lets_it_pass(text, "tcp", 443) is unconditional


# ------------------------------------------------------- the verdict a rule says
#
# The Rules tab lists rules and asks what each one says. The walk asks the far
# harder question of what happens to one packet, and the two must not be
# confused for each other.

@pytest.mark.parametrize("text,word", [
    ("tcp dport 22 counter accept", "accept"),
    ("ct state invalid counter drop", "drop"),
    ("tcp dport 25 reject with icmpx port-unreachable", "reject"),
    # a jump is not a verdict, however its target chain is spelled
    ("counter jump ufw-user-limit-accept", ""),
    ("counter jump ufw-user-input", ""),
    ("tcp dport 22 counter return", ""),
    ("", ""),
])
def test_a_rules_own_verdict_word(text, word):
    assert pp.rule_verdict(text) == word


def test_the_verdict_a_rule_says_is_not_a_claim_about_a_packet():
    """`ct state established accept` says accept and lets no new inbound
    connection through, so the two questions have to answer differently."""
    text = "ct state established,related counter accept"
    assert pp.rule_verdict(text) == "accept"
    assert pp.rule_lets_it_pass(text, "tcp", 22) is False
