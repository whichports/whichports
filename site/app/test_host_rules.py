"""The Rules tab: what each firewall's own words become on the screen.

    Run from site/app: python3 -m pytest test_host_rules.py

`docs/screens/host-rules/SPEC.md` is the design and `test_render_live.py`
covers the tab inside a whole page. This file is the parts: the ufw tuple
parser, what merges and what does not, which firewall wrote a kernel chain,
and the four empty answers.

**The parser is the reason this file exists.** ufw's rules are lines of text
and every field has to be read out of them by position, so a field read one
place along is a rule this page reports wrongly and nothing else notices.
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402


# ------------------------------------------------------------- the ufw parser
#
# ufw's own backend writes the tuple as
#
#     action protocol dport dst sport src [dapp sapp] [direction and interface]
#
# (`git.launchpad.net/ufw/plain/src/backend_iptables.py`, read 2026-09-10), and
# the agent's own note records one observed verbatim on Ubuntu 26.04:
# `allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in`.

def test_the_source_is_read_from_the_source_field_and_not_the_destination():
    """The field that matters most and the one easiest to get wrong. Both are
    0.0.0.0/0 on the common rule, so reading field 3 instead of field 5 looks
    right until somebody writes a rule naming an address."""
    parts = rl.ufw_rule_parts("allow tcp 8410 0.0.0.0/0 any 10.0.0.0/8 in")
    assert parts.source == "10.0.0.0/8"
    assert parts.port == "8410"
    assert parts.protocol == "tcp"
    assert parts.action == "allow"
    assert parts.direction == "in"


def test_a_tuple_without_a_direction_field_is_read_as_incoming():
    """Six fields is ufw's older format, which carried no direction. ufw reads
    those as incoming and so does this."""
    parts = rl.ufw_rule_parts("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0")
    assert parts.direction == "in" and parts.source == "0.0.0.0/0"


@pytest.mark.parametrize("action,expected", [
    ("allow", "allow"), ("deny", "deny"), ("reject", "reject"), ("limit", "limit"),
    # the log type rides on the action after an underscore and is not a fact
    # about which packets the rule matches
    ("allow_log", "allow"), ("deny_log-all", "deny"),
])
def test_ufw_actions_and_their_log_types(action, expected):
    parts = rl.ufw_rule_parts(f"{action} tcp 22 0.0.0.0/0 any 0.0.0.0/0 in")
    assert parts.action == expected and parts.forwarded is False


def test_a_route_rule_keeps_its_action_and_says_it_is_forwarded():
    parts = rl.ufw_rule_parts("route:allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in")
    assert parts.action == "allow" and parts.forwarded is True


@pytest.mark.parametrize("line", [
    "",
    "allow tcp 22",                                        # too few fields
    "-A ufw-user-input -p tcp --dport 22 -j ACCEPT",       # an iptables rule
    "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0",  # the marker left on
    "Status: active",                                      # ufw status output
])
def test_a_line_ufw_did_not_write_is_refused_rather_than_read(line):
    """Refusing is the whole point. A field count alone reads an iptables line
    as a tuple and prints `-A` as an action, which is a wrong rule stated
    confidently, and the caller shows the text and says it could not read it
    instead."""
    assert rl.ufw_rule_parts(line) is None


# ----------------------------------------------------------------- the merge

def ufw_section(rules=(), rules6=(), enabled="yes", sources=None):
    return {"status": "collected", "conf": {"ENABLED": enabled},
            "defaults": {}, "rules": list(rules), "rules6": list(rules6),
            "sources": sources or {"ufw.conf": {"status": "collected"},
                                   "user.rules": {"status": "collected"},
                                   "user6.rules": {"status": "collected"}}}


def test_the_same_rule_in_both_files_is_one_row_carrying_both_families():
    """`ufw allow 22` writes one tuple into each file, the two differing only
    in which any-address they name. One rule was written, so one row."""
    merged = rl.merged_ufw_rules(ufw_section(
        ["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"],
        ["allow tcp 22 ::/0 any ::/0 in"]))
    assert len(merged) == 1
    parts, families, lines, _comment = merged[0]
    assert families == ["v4", "v6"]
    assert [f for f, _text in lines] == ["v4", "v6"]
    assert parts.port == "22"


def test_two_rules_that_name_different_addresses_never_merge():
    """The merge is on the rule, not on a resemblance. Two rules that let
    different networks in are two rules and always read as two."""
    merged = rl.merged_ufw_rules(ufw_section(
        ["allow tcp 22 0.0.0.0/0 any 10.0.0.0/8 in",
         "allow tcp 22 0.0.0.0/0 any 192.168.0.0/16 in"]))
    assert len(merged) == 2
    assert {m[0].source for m in merged} == {"10.0.0.0/8", "192.168.0.0/16"}


def test_a_rule_on_one_family_only_says_that_family():
    merged = rl.merged_ufw_rules(ufw_section(["allow tcp 8410 0.0.0.0/0 any 10.0.0.0/8 in"]))
    assert merged[0][1] == ["v4"]


def test_an_unreadable_line_keeps_its_own_row_and_never_merges():
    merged = rl.merged_ufw_rules(ufw_section(["nonsense", "nonsense"]))
    assert len(merged) == 2
    assert all(parts is None for parts, _f, _l, _c in merged)


def test_a_comment_travels_with_the_rule_it_was_written_on():
    """ufw stores a comment hex encoded and the decode already exists. The
    merge must not lose it: it is the one part of a rule a person wrote for
    another person to read."""
    hexed = "726f62696e"  # robin
    merged = rl.merged_ufw_rules(ufw_section(
        [f"allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment={hexed}"]))
    assert merged[0][3] == "robin"


# -------------------------------------------------- what ufw's state says
#
# The refusal case is docs/RECORD.md 4.72 and it has a whole-page test in
# test_render_live.py. These are the states beside it.

@pytest.mark.parametrize("enabled,expected", [
    ("yes", ("ok", "active")),
    ("no", ("off", "not enabled")),
    ("", ("warn", "did not say")),
])
def test_ufw_says_whether_it_is_on_in_its_own_word(enabled, expected):
    assert rl.ufw_state(ufw_section(enabled=enabled)) == expected


def test_a_refused_rules_file_outranks_whatever_the_conf_said():
    """ufw.conf is world readable and the rules files are not, so a host can
    say enabled and hand over no rules at all. The block has to say it could
    not read them, because an empty list under the word active is the claim
    this guard exists to stop."""
    section = ufw_section(enabled="yes", sources={
        "ufw.conf": {"status": "collected"},
        "user.rules": {"status": "permission_denied", "cause": "permission"},
        "user6.rules": {"status": "permission_denied", "cause": "permission"}})
    assert rl.ufw_state(section) == ("fail", "not readable")


# ------------------------------------------- which firewall wrote which chain

@pytest.mark.parametrize("table,chain,author", [
    ("firewalld", "filter_IN_public", "firewalld"),
    ("firewalld_policy_drop", "filter_FWD", "firewalld"),
    ("filter", "ufw-user-input", "ufw"),
    ("filter", "ufw6-before-input", "ufw"),
    ("filter", "DOCKER-USER", "docker"),
    ("nat", "DOCKER", "docker"),
    # nobody has written a name for these, so they belong to nobody and their
    # rules are what the kernel's own list holds
    ("filter", "INPUT", ""),
    ("netavark", "FORWARD", ""),
    ("filter", "f2b-sshd", ""),
])
def test_a_kernel_chain_belongs_to_the_firewall_that_names_it(table, chain, author):
    assert rl.kernel_chain_author(table, chain) == author


# --------------------------------------------------------- the empty answers

def test_no_firewall_draws_the_slashed_wall_and_three_words():
    html = build.no_firewall_html()
    assert build.NO_FIREWALL in html
    assert "<line" in html and "stroke-linecap" in html   # the slash
    # A shield is the one picture this product may not draw, whatever the
    # slash says about it (docs/DESIGN.md section 3).
    assert "shield" not in html.lower()


@pytest.mark.parametrize("words", [build.NO_PROVIDER_FIREWALL,
                                   build.NOTHING_ELSE_IN_KERNEL])
def test_a_layer_with_nothing_in_it_is_one_grey_line(words):
    html = build.firewall_line_html(words)
    assert words in html and html.count("<div") == 2


def test_no_empty_answer_explains_itself():
    """The rule for customer screens. A line when a section is empty is allowed. A line saying
    why, or when it might fill, is not."""
    for html in (build.no_firewall_html(),
                 build.firewall_line_html(build.NO_PROVIDER_FIREWALL),
                 build.firewall_line_html(build.NOTHING_ELSE_IN_KERNEL)):
        words = re.sub(r"<[^>]+>", " ", html).lower()
        for banned in ("because", "will be", "not yet", "once you", "connect a",
                       "planned", "coming"):
            assert banned not in words, html


# ------------------------------------------------------------ the row itself

def test_a_rule_row_opens_on_a_checkbox_and_needs_no_script():
    """The same mechanism the port table uses, so the tab still works with
    JavaScript switched off."""
    row = build.rule_row_html("box", "ufw", 1, "allow",
                              build.rule_port_html(22, "tcp", ("v4",)),
                              build.rule_from_html("anywhere"),
                              build.rule_card_html("ufw", "as you wrote it", []))
    assert 'type="checkbox" class="rsel" id="rr-box-ufw-1"' in row
    assert 'for="rr-box-ufw-1"' in row
    assert "onclick" not in row and "<script" not in row


def test_the_port_cell_says_nothing_at_all_for_a_rule_it_could_not_read():
    """"any port" is a claim, and a rule nobody could read is exactly the one
    to make no claim about."""
    assert build.rule_port_html(None, "", (), unreadable=True) == '<span class="rpn"></span>'
    assert "any port" in build.rule_port_html(None, "", ())


def test_an_address_is_mono_and_our_own_words_are_not():
    """docs/DESIGN.md section 1: what a machine said takes the mono face."""
    assert "addr" in build.rule_from_html("10.0.0.0/8", machine=True)
    assert "addr" not in build.rule_from_html("anywhere")


def test_a_rule_read_in_part_carries_the_tag_and_keeps_its_text():
    html = build.rule_from_html("tcp dport [unmodelled] drop", machine=True, unread=True)
    assert "not fully readable" in html
    assert "tcp dport [unmodelled] drop" in html


# ------------------------------------------------- the provider's own firewall

def snapshot(server_name="box", rules=(), status="applied", attach=True):
    """A provider snapshot in the shape Hetzner's API returns it, parsed the
    way the control plane parses it."""
    hetzner = joinbridge.module("hetzner")
    firewalls = [{"id": 1, "name": "hetzner-fw-1", "rules": list(rules),
                  "applied_to": [{"type": "server", "server": {"id": 7}}]}]
    servers = [{"id": 7, "name": server_name, "status": "running",
                "public_net": {"ipv4": {"ip": "203.0.113.7"},
                               "firewalls": ([{"id": 1, "status": status}]
                                             if attach else [])}}]
    snap = hetzner.Snapshot(fetched_at="2026-08-14T11:48:00+00:00",
                            servers=servers, firewalls=firewalls)
    # One project, the shape `load_provider` hands over per token.
    return {"projects": [{"snapshot": snap, "inventory": hetzner.parse_snapshot(snap),
                          "fetch": None}]}


def provider_rule(protocol="tcp", port="22", sources=("0.0.0.0/0", "::/0"),
                  description=None, direction="in"):
    return {"direction": direction, "protocol": protocol, "port": port,
            "source_ips": list(sources), "destination_ips": [],
            "description": description}


def test_a_provider_firewall_is_matched_to_the_host_by_name_only():
    """Exactly and case-insensitively, the way the join engine matches it. A
    looser match would attach one account's firewall to another's server."""
    provider = snapshot(server_name="Almabox")
    assert rl.provider_server(provider, "almabox") is not None
    assert rl.provider_server(provider, "almabox2") is None
    assert rl.provider_server(provider, "lmabox") is None
    assert rl.provider_server(provider, "") is None


def test_a_provider_rule_draws_its_port_families_and_source():
    html, rules, firewalls = rl.provider_blocks(
        "box", snapshot(rules=[provider_rule()]), "box", "")
    assert (rules, firewalls) == (1, 1)
    assert ">22<" in html
    assert '<i class="v4">v4</i>+<i class="v6">v6</i>' in html
    assert "anywhere" in html


def test_a_provider_rule_that_names_one_network_says_which():
    html, _rules, _fw = rl.provider_blocks(
        "box", snapshot(rules=[provider_rule(port="9100", sources=("203.0.113.0/24",),
                                             description="office")]), "box", "")
    assert "203.0.113.0/24" in html and "office" in html
    assert '<i class="v4">v4</i>' in html and "v6" not in html


def test_a_provider_rule_with_no_port_says_any_port():
    """icmp and the other protocols Hetzner lists carry no port at all."""
    html, _rules, _fw = rl.provider_blocks(
        "box", snapshot(rules=[provider_rule(protocol="icmp", port=None)]), "box", "")
    assert "any port" in html


@pytest.mark.parametrize("protocol, description, direction, note", [
    ("icmp", None, "in", "ICMP"),
    ("esp", None, "in", "ESP"),
    ("icmp", "ping", "in", "ICMP, ping"),
    ("icmp", None, "out", "ICMP, outgoing"),
])
def test_a_provider_rule_with_no_ports_is_named_by_its_protocol(protocol, description,
                                                                 direction, note):
    """It draws as "any port", and without the protocol beside it the row
    reads as a rule that opens every port (the sweep of 2026-09-21, the
    Hetzner icmp rule, docs/RECORD.md 4.199). The spec's from column names
    ICMP as one of the notes."""
    html, _rules, _fw = rl.provider_blocks(
        "box", snapshot(rules=[provider_rule(protocol=protocol, port=None,
                                             description=description,
                                             direction=direction)]), "box", "")
    assert note in html


def test_a_tcp_rule_carries_no_protocol_note():
    html, _rules, _fw = rl.provider_blocks(
        "box", snapshot(rules=[provider_rule(protocol="tcp", port="22")]), "box", "")
    assert "TCP," not in html and ">TCP<" not in html


def test_a_pending_attachment_is_never_drawn_as_applied():
    html, _rules, _fw = rl.provider_blocks(
        "box", snapshot(rules=[provider_rule()], status="pending"), "box", "")
    assert "pending" in html and ">active<" not in html


def test_a_host_the_provider_does_not_list_gets_no_block():
    html, rules, firewalls = rl.provider_blocks(
        "box", snapshot(server_name="other"), "box", "")
    assert (html, rules, firewalls) == ("", 0, 0)


# ---------------------------------- the one grey line when no block is drawn
#
# The owner, 2026-09-20: a Hetzner token was connected and read six servers, and
# this tab said "No provider connected". It said that for three different
# facts. Each has its own line now, and each is a fact and not a reason.

def provider_line(provider, host="box"):
    html = rl.rules_tab_body({}, host, provider)
    return [words for words in (build.NO_PROVIDER_FIREWALL, build.PROVIDER_SERVER_NOT_FOUND,
                                build.NO_FIREWALL_AT_PROVIDER) if words in html]


def test_no_provider_at_all_says_no_provider_connected():
    assert provider_line(None) == [build.NO_PROVIDER_FIREWALL]
    assert provider_line({"projects": [{"snapshot": None, "inventory": None}]}) == [
        build.NO_PROVIDER_FIREWALL]


def test_a_connected_provider_that_does_not_list_the_server_says_so():
    assert provider_line(snapshot(server_name="other")) == [
        build.PROVIDER_SERVER_NOT_FOUND]


def test_a_listed_server_with_no_firewall_attached_says_so():
    assert provider_line(snapshot(attach=False)) == [build.NO_FIREWALL_AT_PROVIDER]


def test_a_listed_server_with_a_firewall_draws_the_block_and_none_of_the_lines():
    assert provider_line(snapshot(rules=[provider_rule()])) == []


def test_the_three_lines_are_facts_and_never_reasons():
    for words in (build.NO_PROVIDER_FIREWALL, build.PROVIDER_SERVER_NOT_FOUND,
                  build.NO_FIREWALL_AT_PROVIDER):
        lowered = words.lower()
        for banned in ("because", "will be", "not yet", "once you", "connect a",
                       "planned", "coming", "rename", "must"):
            assert banned not in lowered, words
        assert "." not in words and len(words.split()) <= 6, words


# --------------------------------------------- what a container runtime opens

def containers(runtime="podman", host_ip="0.0.0.0", name="jellyfin"):
    return {"status": "collected", runtime: [
        {"id": "abc123456789", "name": name, "image": f"{name}:latest",
         "ports": [{"host_ip": host_ip, "host_port": 8096,
                    "container_port": 8096, "protocol": "tcp"}]}]}


def test_a_published_port_is_its_own_rule_with_the_container_named():
    html, count = rl.container_block("box", containers(), "podman", "Podman", "4m ago")
    assert count == 1
    assert ">publish<" in html and ">8096<" in html
    assert "to jellyfin" in html and "anywhere" in html


def test_a_runtime_that_published_nothing_draws_no_block():
    html, count = rl.container_block("box", {"status": "collected", "podman": []},
                                     "podman", "Podman", "")
    assert (html, count) == ("", 0)


def test_a_runtime_that_did_not_say_where_is_not_read_as_anywhere():
    """An empty host_ip is the runtime not saying, never a wildcard
    (`hostdoc.PublishedPort`). Drawing it as anywhere would state a binding
    nobody reported."""
    html, _count = rl.container_block("box", containers(host_ip=""), "podman",
                                      "Podman", "")
    assert "not fully readable" in html
    assert "anywhere" not in html


def test_the_two_runtimes_are_never_merged_into_one_list():
    """docs/PRODUCT.md 4d: two runtimes on one host are two answers, and each
    gets its own list saying which runtime published what."""
    both = {"status": "collected",
            "docker": containers("docker", name="caddy")["docker"],
            "podman": containers("podman", name="jellyfin")["podman"]}
    docker, docker_count = rl.container_block("box", both, "docker", "Docker", "")
    podman, podman_count = rl.container_block("box", both, "podman", "Podman", "")
    assert docker_count == 1 and podman_count == 1
    assert "caddy" in docker and "caddy" not in podman
    assert "jellyfin" in podman and "jellyfin" not in docker
