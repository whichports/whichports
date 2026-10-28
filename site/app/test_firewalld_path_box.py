"""The Packet path's firewalld box says what firewalld does with the port
(docs/RECORD.md 4.343).

Read from the zone files alone, the box got two things wrong, both on a real
Fedora 44 server's document:

  - it said "no rule for 22" where firewalld's ssh service is the way in. A
    zone file names a service, and which port that is stands in firewalld's
    own service files, which the agent does not read. The same for a port
    opened at runtime, which is in no file
  - it read every zone firewalld ships, so a zone nothing is bound to could
    be the one it named

The kernel's ruleset is in the same document. It says which zones are in
effect (test_firewalld_zones_in_effect.py) and it holds the port either way.

    Run from site/: python3 -m pytest app/test_firewalld_path_box.py
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import packetpath as pp  # noqa: E402
import render_live as rl  # noqa: E402
from test_firewalld_zones_in_effect import FEDORA_ZONES, rules, text_of, zone  # noqa: E402

# The zone's own chain on the Fedora 44 server, and what its allow chain held:
# the three services of public.xml as ports, and a port opened at runtime.
PUBLIC_ALLOW = [
    "meta l4proto tcp tcp dport 22 accept",
    "meta nfproto ipv4 ip daddr 224.0.0.251 meta l4proto udp udp dport 5353 accept",
    "meta nfproto ipv6 ip6 daddr ff02::fb meta l4proto udp udp dport 5353 accept",
    "meta nfproto ipv6 ip6 daddr fe80::/64 meta l4proto udp udp dport 546 accept",
    "meta l4proto tcp tcp dport 9000 accept",
]


def chain(name, lines, **base):
    return {"name": name, "rules": rules(lines), **base}


def zone_chains(name, allow):
    return [chain(f"filter_IN_{name}", [f"jump filter_IN_{name}_pre",
                                        f"jump filter_IN_{name}_deny",
                                        f"jump filter_IN_{name}_allow",
                                        f"jump filter_IN_{name}_post"]),
            chain(f"filter_IN_{name}_pre", []),
            chain(f"filter_IN_{name}_deny", []),
            chain(f"filter_IN_{name}_allow", allow),
            chain(f"filter_IN_{name}_post", [])]


def document(zones=None, dispatch=None, allow=None, extra=()):
    """A host with firewalld: its zone files, and its table in the kernel
    with the zones in `allow` entered the way `dispatch` says."""
    allow = {"public": PUBLIC_ALLOW} if allow is None else allow
    dispatch = ['iifname "eth0" jump filter_IN_public',
                "jump filter_IN_public", "[reject]"] if dispatch is None else dispatch
    chains = [chain("filter_INPUT", ["ct state { established, related } accept",
                                     'iifname "lo" accept',
                                     "jump filter_INPUT_POLICIES", "[reject]"],
                    type="filter", hook="input", priority=10, policy="accept"),
              chain("filter_INPUT_POLICIES", dispatch)]
    for name, lines in allow.items():
        chains += zone_chains(name, lines)
    chains += list(extra)
    return {
        "sockets": {"status": "collected", "listening": []},
        "containers": {"status": "collected"},
        "firewalld": {"status": "collected", "conf": {"DefaultZone": "public"},
                      "sources": {"etc_zones": {"status": "collected"},
                                  "vendor_zones": {"status": "collected"}},
                      "zones": FEDORA_ZONES if zones is None else zones},
        "nftables": {"status": "collected", "tables": [
            {"family": "inet", "name": "firewalld", "chains": chains}]},
    }


def box(doc, port, protocol="tcp", family="v4"):
    """The firewalld box as the Packet path builds it for one port."""
    return rl.firewalld_path_tool(doc["firewalld"], protocol, port, family,
                                  rl.firewalld_zones_in_effect(doc),
                                  pp.path_for(doc, protocol, port, family))


def fact(tool):
    """The box's own line for the port, as a person reads it."""
    return text_of(tool["facts"][0][1])


# ------------------------------------------------- the two faults that were measured

@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_service_is_a_rule_for_its_port(family):
    """public.xml says `ssh`. The kernel says tcp dport 22 accept in that
    zone's chain. The box said "no rule for 22"."""
    tool = box(document(), 22, family=family)

    assert tool["finding"] == "allow 22, anywhere"
    assert tool["where"] == "zone public"
    assert tool["facts"][0][0] == "for 22/tcp"
    assert fact(tool) == "allow anywhere"


def test_a_port_opened_at_runtime_is_a_rule_though_no_file_holds_it():
    tool = box(document(), 9000)

    assert tool["finding"] == "allow 9000, anywhere"
    assert tool["where"] == "zone public"


def test_a_port_nothing_names_still_has_no_rule_and_says_of_which_zone():
    # The Fedora server's own dispatch: Docker's zone is in effect too, on
    # docker0. It holds a target and no rule, so "no rule" is not said about
    # it.
    doc = document(dispatch=['iifname "docker0" jump filter_IN_docker',
                             'iifname "eth0" jump filter_IN_public',
                             "jump filter_IN_public", "[reject]"],
                   allow={"public": PUBLIC_ALLOW, "docker": []})
    assert rl.firewalld_zones_in_effect(doc) == {"docker": ["docker0"], "public": ["eth0"]}
    tool = box(doc, 7000)

    assert tool["finding"] == "no rule for 7000"
    assert fact(tool) == "no rule"
    assert tool["where"] == "zone public"


def test_the_other_protocol_on_the_same_number_is_not_the_rule():
    assert box(document(), 22, protocol="udp")["finding"] == "no rule for 22"
    assert box(document(), 5353, protocol="udp")["finding"] == "names 5353"
    assert box(document(), 5353, protocol="tcp")["finding"] == "no rule for 5353"


def test_only_the_zones_in_effect_are_listed():
    tool = box(document(), 22)

    assert [(r["action"], r["port"]) for r in tool["rules"]] == [
        ("allow", "dhcpv6-client"), ("allow", "mdns"), ("allow", "ssh")]
    assert not any(r["port"] == "1025-65535" for r in tool["rules"])


def test_a_zone_nothing_is_bound_to_is_never_the_one_that_decides():
    """`work` holds 8443/tcp in its file and nothing is bound to it. The box
    named it as the rule for the port."""
    zones = [zone("public", services=("ssh",)), zone("work", ports=(("8443", "tcp"),))]
    doc = document(zones, allow={"public": ["tcp dport 22 accept"]})
    tool = box(doc, 8443)

    assert tool["finding"] == "no rule for 8443"
    assert tool["where"] == "zone public"
    assert not any(r["hit"] for r in tool["rules"])
    # And read the old way, with nothing known about which zones apply:
    old = rl.firewalld_path_tool(doc["firewalld"], "tcp", 8443, "v4")
    assert (old["finding"], old["where"]) == ("allow 8443, anywhere", "zone work")


# ------------------------------------------------------ what stays as it was

def test_a_port_in_the_file_of_a_zone_in_effect_is_the_rule_and_its_row_is_marked():
    zones = [zone("public", services=("ssh",), ports=(("8080", "tcp"),))]
    doc = document(zones, allow={"public": ["tcp dport 22 accept", "tcp dport 8080 accept"]})
    tool = box(doc, 8080)

    assert tool["finding"] == "allow 8080, anywhere"
    assert [r["port"] for r in tool["rules"] if r["hit"]] == ["8080"]


def test_a_kernel_that_does_not_say_leaves_the_box_as_it_was():
    """No table of firewalld's to read: every zone's file is read, as before,
    and the kernel is not asked about the port."""
    doc = document()
    doc["nftables"] = {"status": "collected", "tables": []}
    tool = box(doc, 22)

    assert tool["finding"] == "no rule for 22" and tool["where"] == ""
    assert len(tool["rules"]) == 27


def test_a_table_whose_way_into_its_zones_is_not_known_still_has_its_rule_quoted():
    """firewalld's table is there and holds the port, and the chain that
    enters its zones has a name this page does not know. Which zones are in
    effect is then not said, so every zone's file is listed as before. The
    kernel's rule for the port is still a fact: it is quoted, in no zone."""
    doc = document()
    table = doc["nftables"]["tables"][0]["chains"]
    table[0]["rules"] = rules(["jump filter_INPUT_SOMETHING_NEW"])
    table[1]["name"] = "filter_INPUT_SOMETHING_NEW"
    assert rl.firewalld_zones_in_effect(doc) is None
    tool = box(doc, 22)

    assert tool["finding"] == "names 22"
    assert fact(tool) == "meta l4proto tcp tcp dport 22 accept"
    assert tool["where"] == ""
    assert len(tool["rules"]) == 27


# --------------------------------------------- who a rule lets in, and the limits

def test_a_zone_entered_for_a_source_permits_some():
    """The zone takes one network. A rule in it lets that network in and
    nobody else, so it is not the rule that let the prober's packet through
    (the same reading as ufw's box, docs/RECORD.md 4.320)."""
    internal = zone("internal", services=("samba",))
    internal["source_addrs"] = ["192.0.2.0/24"]
    doc = document([zone("public", services=("ssh",)), internal],
                   dispatch=["ip saddr 192.0.2.0/24 jump filter_IN_internal",
                             'iifname "eth0" jump filter_IN_public', "jump filter_IN_public"],
                   allow={"public": ["tcp dport 22 accept"],
                          "internal": ["tcp dport 445 accept"]})
    tool = box(doc, 445)

    assert tool["finding"] == rl.PERMITS_SOME
    assert tool["where"] == "zone internal"
    assert fact(tool) == "allow 192.0.2.0/24"


def source_zone_server(zones_chain="filter_INPUT_ZONES", verb="goto"):
    """The AlmaLinux 9.8 server of the second big test, firewalld 1.3.4
    (docs/RECORD.md 4.467's run, case C7): zone public on eth0 with ssh,
    zone internal entered only for 192.0.2.0/24 with ssh and 9100/tcp. The
    kernel's way into the zones, as nft listed it there, puts the source line
    first."""
    public = zone("public", services=("ssh", "cockpit", "dhcpv6-client"))
    internal = zone("internal", services=("ssh",), ports=(("9100", "tcp"),))
    internal["source_addrs"] = ["192.0.2.0/24"]
    doc = document([public, internal],
                   dispatch=[f"ip saddr 192.0.2.0/24 {verb} filter_IN_internal",
                             f'iifname "eth0" {verb} filter_IN_public',
                             f"{verb} filter_IN_public"],
                   allow={"public": ["meta l4proto tcp tcp dport 22 accept"],
                          "internal": ["meta l4proto tcp tcp dport 22 accept",
                                       "meta l4proto tcp tcp dport 9100 accept"]})
    chains = doc["nftables"]["tables"][0]["chains"]
    chains[0]["rules"] = rules(["ct state { established, related } accept",
                                'iifname "lo" accept', f"jump {zones_chain}", "[reject]"])
    chains[1]["name"] = zones_chain
    return doc


@pytest.mark.parametrize("zones_chain, verb", [("filter_INPUT_ZONES", "goto"),
                                               ("filter_INPUT_POLICIES", "jump")])
@pytest.mark.parametrize("family", ["v4", "v6"])
def test_the_zone_everybody_enters_answers_for_the_port_and_not_the_first_rule_found(
        zones_chain, verb, family):
    """Both zones open 22. The source line stands first in the kernel's way
    into the zones, so the box took zone internal's rule and said firewalld
    lets 22 in from 192.0.2.0/24 only, on v6 too, on a server that answered
    both probers on both families through zone public (second big test,
    2026-10-25, case C7). A jump's own condition counts with the rule behind
    it (docs/PRODUCT.md 8d): zone internal's rule is narrowed, and an `ip
    saddr` jump is never taken by a v6 packet."""
    tool = box(source_zone_server(zones_chain, verb), 22, family=family)

    assert tool["finding"] == "allow 22, anywhere"
    assert tool["where"] == "zone public"
    assert fact(tool) == "allow anywhere"


def test_a_port_only_a_source_zone_opens_permits_some_on_v4():
    tool = box(source_zone_server(), 9100, family="v4")

    assert tool["finding"] == rl.PERMITS_SOME
    assert tool["where"] == "zone internal"
    assert fact(tool) == "allow 192.0.2.0/24"


def test_on_v6_a_zone_entered_only_for_a_v4_source_is_not_there():
    """9100 is in zone internal's file and in its chain. A v6 packet never
    takes `ip saddr 192.0.2.0/24 goto filter_IN_internal`, so on v6 the rule
    is not there at all (docs/PRODUCT.md 8d). The box drew it on v6 too."""
    tool = box(source_zone_server(), 9100, family="v6")

    assert tool["finding"] == "no rule for 9100"
    assert tool["where"] == "zone public"
    assert not any(r["hit"] for r in tool["rules"])
    assert [r["port"] for r in tool["rules"]] == ["ssh", "cockpit", "dhcpv6-client"]


def test_on_v6_a_kernel_rule_behind_a_v4_source_jump_is_not_quoted():
    """The same when only the kernel names the port: a service of zone
    internal's, reached by v6 through no line at all."""
    doc = source_zone_server()
    internal_allow = next(c for c in doc["nftables"]["tables"][0]["chains"]
                          if c["name"] == "filter_IN_internal_allow")
    internal_allow["rules"] = rules(["meta l4proto tcp tcp dport 445 accept"])

    assert box(doc, 445, family="v4")["finding"] == rl.PERMITS_SOME
    v6 = box(doc, 445, family="v6")
    assert v6["finding"] == "no rule for 445"
    assert v6["where"] == "zone public"


@pytest.mark.parametrize("line", [
    "ip saddr 10.0.0.0/8 tcp dport 22 accept",        # a rich rule for one network
    "tcp dport 22 ct state established accept",       # not a first packet
    "tcp dport 22 drop",
    "tcp dport 22 [reject]",
    "tcp dport 22 log accept",
])
def test_a_rule_with_more_on_it_is_quoted_and_not_put_into_words(line):
    doc = document([zone("public", services=("ssh",))], allow={"public": [line]})
    tool = box(doc, 22)
    if "[" in line:
        # A rule the agent could not fully render names no port for the walk.
        assert tool["finding"] == "no rule for 22"
        return
    assert tool["finding"] == "names 22"
    assert fact(tool) == line
    assert tool["where"] == "zone public"


def test_the_way_firewalld_0_9_writes_a_port_is_a_plain_allow():
    """firewalld 0.9.11 opens every port as ct state { new, untracked }
    (docs/RECORD.md 4.244)."""
    doc = document([zone("public", services=("ssh",))],
                   dispatch=['iifname "eth0" goto filter_IN_public', "goto filter_IN_public"],
                   allow={"public": ["tcp dport 6000 ct state { new, untracked } accept"]})
    doc["nftables"]["tables"][0]["chains"][0]["rules"] = rules(["jump filter_INPUT_ZONES"])
    doc["nftables"]["tables"][0]["chains"][1]["name"] = "filter_INPUT_ZONES"

    assert box(doc, 6000)["finding"] == "allow 6000, anywhere"


def test_a_policys_rule_for_the_port_is_quoted():
    """A rule in one of firewalld's policy chains is firewalld's and is no
    zone's. It is not ignored and not credited to a zone."""
    policy = [chain("filter_IN_policy_allow-host-ipv6", ["jump filter_IN_policy_allow-host-ipv6_allow"]),
              chain("filter_IN_policy_allow-host-ipv6_allow", ["tcp dport 4000 accept"])]
    doc = document([zone("public", services=("ssh",))],
                   dispatch=["jump filter_IN_policy_allow-host-ipv6", "jump filter_IN_public"],
                   allow={"public": ["tcp dport 22 accept"]}, extra=policy)
    tool = box(doc, 4000)

    assert tool["finding"] == "names 4000"
    assert fact(tool) == "tcp dport 4000 accept"
    assert tool["where"] == "zone public"


def test_a_rule_on_another_hook_is_not_the_rule_on_the_way_in():
    """A forwarded port names its port in firewalld's prerouting chain. That
    is not firewalld accepting it on the way in."""
    nat = [chain("nat_PREROUTING", ["jump nat_PRE_public_allow"],
                 type="nat", hook="prerouting", priority=-90, policy="accept"),
           chain("nat_PRE_public_allow", ["tcp dport 8081 redirect to :80"])]
    doc = document([zone("public", services=("ssh",))],
                   allow={"public": ["tcp dport 22 accept"]}, extra=nat)

    assert box(doc, 8081)["finding"] == "no rule for 8081"


def test_another_tables_rule_for_the_port_is_not_firewallds():
    doc = document([zone("public", services=("ssh",))], allow={"public": []})
    doc["nftables"]["tables"].append({"family": "inet", "name": "filter", "chains": [
        chain("input", ["jump filter_IN_public_allow"],
              type="filter", hook="input", priority=0, policy="accept"),
        chain("filter_IN_public_allow", ["tcp dport 22 accept"])]})

    assert box(doc, 22)["finding"] == "no rule for 22"


@pytest.mark.parametrize("chain_name, zones, want", [
    ("filter_IN_public", ["public"], "public"),
    ("filter_IN_public_allow", ["public"], "public"),
    ("filter_IN_work_allow_allow", ["work", "work_allow"], "work_allow"),
    ("filter_IN_work_allow_allow", ["work_allow", "work"], "work_allow"),
    ("filter_IN_publication_allow", ["public"], ""),
    ("filter_IN_policy_allow-host-ipv6_allow", ["public", "docker"], ""),
    ("filter_FWD_public_allow", ["public"], ""),
    ("filter_IN_public_allow", [], ""),
])
def test_a_chain_belongs_to_the_longest_zone_name_that_fits(chain_name, zones, want):
    assert rl.firewalld_zone_of_chain(chain_name, zones) == want


def test_a_quoted_rule_is_text_and_never_markup():
    doc = document([zone("public", services=("ssh",))],
                   allow={"public": ['tcp dport 22 log prefix "<b>x</b>" accept']})
    tool = box(doc, 22)
    assert "<b>x</b>" not in tool["facts"][0][1]
    assert "&lt;b&gt;x&lt;/b&gt;" in tool["facts"][0][1]


# ---------------------------------------------------------------- on the page

def test_the_page_draws_it(tmp_path):
    """Through the tab's own builder, a listener on 22 and one on 7000."""
    doc = document()
    doc["sockets"]["listening"] = [
        {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": port,
         "process_name": name, "pid": port}
        for port, name in ((22, "sshd"), (7000, "app"))]
    html = rl.path_tab_body(doc, "web-01")
    walks = html.split('<div class="walk">')[1:]
    assert len(walks) == 2
    said = [text_of(w) for w in walks]

    assert "firewalld allow 22, anywhere" in said[0]
    assert "firewalld no rule for 7000" in said[1]
    assert not re.search(r"FedoraWorkstation|1025-65535", html)


def test_a_zone_for_everybody_answers_before_a_source_zone_whose_file_comes_first():
    """The same order fault in the files: both zones' files name 8080, and
    the source zone's file is read first."""
    internal = zone("internal", ports=(("8080", "tcp"),))
    internal["source_addrs"] = ["192.0.2.0/24"]
    doc = document([internal, zone("public", ports=(("8080", "tcp"),))],
                   dispatch=["ip saddr 192.0.2.0/24 jump filter_IN_internal",
                             'iifname "eth0" jump filter_IN_public', "jump filter_IN_public"],
                   allow={"public": ["tcp dport 8080 accept"],
                          "internal": ["tcp dport 8080 accept"]})
    tool = box(doc, 8080)

    assert tool["finding"] == "allow 8080, anywhere"
    assert tool["where"] == "zone public"
