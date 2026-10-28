"""The Packet path tab: which tools a packet meets, and what may be drawn.

    Run from site/app: python3 -m pytest test_host_path.py

`docs/screens/host-packet-path/SPEC.md` is the design. This file is the parts
that carry judgement, because the tab's whole risk is stating a cause that was
not measured:

  - the fate, which may only be what the prober measured or what the document
    itself marks
  - the stop, which may only be attributed to a tool the chain actually
    belongs to, and must refuse to blame anyone otherwise
  - which family a container publication is on, and which tool the packet
    never meets at all
"""
import pathlib
import re
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
document, add_host, probe_result = trl.document, trl.add_host, trl.probe_result

SSHD = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
        "process_name": "sshd", "pid": 812}
PG = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 5432,
      "process_name": "postgres", "pid": 2210}
LOOP = {"protocol": "udp", "family": "v4", "bind_address": "127.0.0.1", "port": 323,
        "process_name": "chronyd", "pid": 402}


@pytest.fixture()
def db(tmp_path):
    import sqlite3
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def ufw_section(rules=(), rules6=(), incoming="DROP"):
    return {"status": "collected", "conf": {"ENABLED": "yes"},
            "defaults": {"DEFAULT_INPUT_POLICY": incoming},
            "rules": list(rules), "rules6": list(rules6),
            "sources": {"ufw.conf": {"status": "collected"},
                        "user.rules": {"status": "collected"},
                        "user6.rules": {"status": "collected"}}}


def nft_with_ufw(port_drop=None):
    """A ruleset shaped the way ufw writes one: a base chain that jumps into
    ufw's own chain, where the rules live."""
    ufw_rules = [{"text": "tcp dport 22 counter accept", "rendered": "full"}]
    if port_drop:
        ufw_rules.append({"text": f"tcp dport {port_drop} counter drop",
                          "rendered": "full"})
    return {"status": "collected", "tables": [{
        "family": "inet", "name": "filter", "chains": [
            {"name": "input", "type": "filter", "hook": "input", "priority": 0,
             "policy": "drop", "rules": [
                 {"text": "counter jump ufw-user-input", "rendered": "full"}]},
            {"name": "ufw-user-input", "rules": ufw_rules}]}]}


def path_of(db, port=22, family="v4", doc=None, states=()):
    """One rendered Packet path tab for a host, and the flow markers in it."""
    doc = doc or document(listening=[SSHD])
    add_host(db, "box", [(NOW - timedelta(minutes=4), doc)],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    for a_port, a_family, state in states:
        probe_result(db, "box", a_port, a_family, state)
    html = rl.render(db, now=NOW)
    body = trl.tab_body(trl.host_section(html, "box"), "box", "path")
    return body


def flows(body):
    """(fate, stop index) per flow, in the order the tab draws them."""
    return [(m.group(1), int(m.group(2)))
            for m in re.finditer(r'data-fate="(\w+)" data-stop="(-?\d+)"', body)]


# ------------------------------------------------------------------ the fates

@pytest.mark.parametrize("state,fate,word", [
    ("connect_succeeded", "reach", "answered"),
    ("connect_refused", "refused", "refused"),
    ("no_response", "lost", "no answer"),
    ("not_tested", "none", "not probed yet"),
])
def test_the_fate_is_what_the_prober_measured(db, state, fate, word):
    """Each fate is measured or is what the document marks, never inferred.
    With no rule accounting for a silence the fate is `lost`, not a tool
    blamed for it."""
    body = path_of(db, states=[(22, "v4", state)])
    assert flows(body) == [(fate, -1)]
    assert word in body


def test_a_port_nobody_probed_says_so_and_draws_no_packets(db):
    """A page rendered before the prober ever ran is the state of a real box,
    and it has to say that rather than draw a journey."""
    body = path_of(db)
    assert flows(body) == [("none", -1)]
    assert "not probed yet" in body


def test_the_refused_fate_is_its_own_and_not_a_silence(db):
    """The spec named four fates and a refusal is none of them: the packet
    arrived and something said no, so the packets run the whole way and
    nothing rings. Drawing it as `lost` would fade them away over a port that
    did answer."""
    body = path_of(db, states=[(22, "v4", "connect_refused")])
    assert flows(body) == [("refused", -1)]
    assert "refused from probe1" in body
    assert "pt-reach" not in body


# ------------------------------------------------------------------- the stop

def test_a_rule_that_ends_the_journey_is_attributed_to_the_tool_that_wrote_it(db):
    """ufw's drop lives in `ufw-user-input` and is only reached through the
    base chain, so the tool is ufw and not the kernel."""
    doc = document(listening=[SSHD, PG])
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
                              "deny tcp 5432 0.0.0.0/0 any 0.0.0.0/0 in"])
    doc["nftables"] = nft_with_ufw(port_drop=5432)
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded"),
                                        (5432, "v4", "no_response")])
    fate = dict(zip([f[0] for f in flows(body)], [f[1] for f in flows(body)]))
    assert ("stop", 0) in flows(body) or ("stop", 1) in flows(body), flows(body)
    assert "ends its journey here" in body


def test_a_drop_in_a_chain_nobody_named_blames_nobody(db):
    """The rule this whole builder is written around. A chain belonging to no
    named tool leaves the fate `lost`, because nothing came back and any
    checkpoint named as the cause would be a guess wearing a fact's clothes.
    """
    doc = document(listening=[PG])
    doc["ufw"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "inet", "name": "mangle", "chains": [
            {"name": "prerouting", "type": "filter", "hook": "prerouting",
             "priority": -150, "policy": "accept", "rules": [
                 {"text": "tcp dport 5432 counter drop", "rendered": "full"}]}]}]}
    body = path_of(db, doc=doc, states=[(5432, "v4", "no_response")])
    assert [f[0] for f in flows(body)] == ["lost"]
    assert "ends its journey here" not in body


@pytest.mark.parametrize("table,chain,tool", [
    ("firewalld", "filter_IN_public", "firewalld"),
    ("filter", "ufw-user-input", "ufw"),
    ("nat", "DOCKER", "docker"),
    ("crowdsec", "crowdsec-input", "crowdsec"),
    ("f2b-table", "f2b-sshd", "f2b-table"),
    # a plain kernel table belongs to nobody
    ("filter", "input", ""),
    ("nat", "prerouting", ""),
])
def test_which_tool_owns_a_kernel_chain(table, chain, tool):
    assert rl.kernel_tool_name(table, chain) == tool


# --------------------------------------------------- a tool never reached

def test_a_docker_published_port_leaves_ufw_a_ghost(db):
    """Docker accepts a published port in the forward chain ahead of ufw's
    rules and an accept ends the walk there (docs/PRODUCT.md 4d).

    The document holds Docker's own rule for the port, as a real server's
    does, in the words the agent sends it. Until 2026-10-11 this fixture had
    none, and the page drew Docker's port the same with or without one. A
    kernel that was read and holds no rule of Docker's for the port is now
    drawn as what it is, see test_path_docker_family.py."""
    doc = document(listening=[])
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"])
    doc["containers"] = {"status": "collected", "docker": [
        {"id": "abc", "name": "web", "image": "nginx:1.27",
         "ports": [{"host_ip": "0.0.0.0", "host_port": 8080,
                    "container_port": 80, "protocol": "tcp"}]}]}
    doc["nftables"]["tables"].append({"family": "ip", "name": "nat", "chains": [
        {"name": "PREROUTING", "type": "nat", "hook": "prerouting", "priority": -100,
         "policy": "accept", "rules": [
             {"text": "[xt match addrtype] counter jump DOCKER", "rendered": "partial"}]},
        {"name": "DOCKER", "rules": [
            {"text": 'iifname != "docker0" ip protocol tcp tcp dport 8080'
                     " counter [xt target DNAT]", "rendered": "partial"}]}]})
    body = path_of(db, doc=doc, states=[(8080, "v4", "connect_succeeded")])
    assert "pt-ghost" in body
    assert "not reached" in body


def test_a_podman_published_port_leaves_ufw_deciding(db):
    """The opposite, and also docs/PRODUCT.md 4d: netavark's accept cannot
    override ufw, so ufw is a real box on a Podman port."""
    doc = document(listening=[])
    doc["ufw"] = ufw_section(["allow tcp 8096 0.0.0.0/0 any 0.0.0.0/0 in"])
    doc["containers"] = {"status": "collected", "podman": [
        {"id": "abc", "name": "jellyfin", "image": "jellyfin/jellyfin",
         "ports": [{"host_ip": "0.0.0.0", "host_port": 8096,
                    "container_port": 8096, "protocol": "tcp"}]}]}
    body = path_of(db, doc=doc, states=[(8096, "v4", "connect_succeeded")])
    assert "pt-ghost" not in body
    assert "allow 8096" in body


def test_a_publication_is_only_on_the_family_the_runtime_published_on(db):
    """0.0.0.0 is v4, which is the reading join._publication_family and the
    Rules tab already use. A v6 path for a v4 publication would draw a path
    that does not exist."""
    doc = document(listening=[])
    doc["containers"] = {"status": "collected", "podman": [
        {"id": "abc", "name": "jellyfin", "image": "x",
         "ports": [{"host_ip": "0.0.0.0", "host_port": 8096,
                    "container_port": 8096, "protocol": "tcp"}]}]}
    body = path_of(db, doc=doc)
    chips = re.findall(r'<label for="pp-box-c-\d+">([^<]+)</label>', body)
    assert chips == ["8096/tcp v4"]


def test_a_runtime_that_did_not_say_where_gets_both_families(db):
    """An empty host_ip is the runtime not saying, and choosing one family
    would be the inference docs/PRODUCT.md 4b forbids."""
    doc = document(listening=[])
    doc["containers"] = {"status": "collected", "podman": [
        {"id": "abc", "name": "jellyfin", "image": "x",
         "ports": [{"host_ip": "", "host_port": 8096,
                    "container_port": 8096, "protocol": "tcp"}]}]}
    body = path_of(db, doc=doc)
    chips = re.findall(r'<label for="pp-box-c-\d+">([^<]+)</label>', body)
    assert chips == ["8096/tcp v4", "8096/tcp v6"]


def test_a_loopback_only_port_has_no_path_from_outside(db):
    """No packet from outside reaches it at all, so there is nothing to draw
    and it is not on the picker."""
    doc = document(listening=[LOOP, SSHD])
    body = path_of(db, doc=doc)
    chips = re.findall(r'<label for="pp-box-c-\d+">([^<]+)</label>', body)
    assert chips == ["22/tcp v4"]


# ------------------------------------------------------- the provider's rules

def provider_rule(protocol="tcp", port="22", sources=("0.0.0.0/0",), direction="in"):
    hetzner = joinbridge.module("hetzner")
    return hetzner.FirewallRule(
        direction=direction, protocol=protocol, port=port, description=None,
        source_ips=hetzner.AddressSet.from_list(sources)
        if hasattr(hetzner.AddressSet, "from_list") else hetzner.AddressSet(
            v4=tuple(a for a in sources if ":" not in a),
            v6=tuple(a for a in sources if ":" in a), unparsed=()),
        destination_ips=hetzner.AddressSet(v4=(), v6=(), unparsed=()))


@pytest.mark.parametrize("port,protocol,family,covers", [
    ("22", "tcp", "v4", True),
    ("22", "tcp", "v6", False),          # the rule's sources are v4 only
    ("80", "tcp", "v4", False),          # a different port
    ("22", "udp", "v4", False),          # a different protocol
    ("1024-5000", "tcp", "v4", False),   # a range that does not hold 22
    ("20-30", "tcp", "v4", True),        # a range that does
    (None, "icmp", "v4", False),         # icmp names no port
])
def test_when_a_provider_rule_is_about_this_port(port, protocol, family, covers):
    rule = provider_rule(protocol=protocol, port=port)
    # Always asked about tcp/22, so a rule for another protocol is a rule that
    # is not about this packet.
    assert rl.provider_rule_covers(rule, "tcp", 22, family) is covers


def test_an_outbound_provider_rule_is_never_about_an_inbound_packet():
    rule = provider_rule(direction="out")
    assert rl.provider_rule_covers(rule, "tcp", 22, "v4") is False


# ------------------------------------------------------- where it came from

@pytest.mark.parametrize("vantage,family,starts", [
    ("probe1", "v4", "78."), ("probe1", "v6", "2a05:"),
    ("probe2", "v4", "172."),
])
def test_the_left_end_names_the_vantages_own_address_on_this_family(vantage, family, starts):
    got = rl.vantage_address(vantage, family)
    assert got.startswith(starts), (vantage, family, got)


def test_a_vantage_with_no_published_address_on_this_family_shows_none():
    """Never the other family's, which would say the packet came from an
    address it did not come from."""
    # probe1 and probe2 both publish on both families, so the absent case is a
    # vantage the list does not carry at all.
    assert rl.vantage_address("probe9", "v4") == ""
    assert rl.vantage_address("", "v4") == ""


# ------------------------------------------------------------ what it may say

def test_the_tab_explains_nothing(db):
    """The rule for customer screens. Labels, values, findings and one line when a section is
    empty. No teaching how the product works and no naming our machinery."""
    doc = document(listening=[SSHD, PG])
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"])
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    words = re.sub(r"<[^>]+>", " ", body).lower()
    for banned in ("because", "this means", "in order to", "you should",
                   "render", "timer", "sweep", "control plane", "will be"):
        assert banned not in words, banned


def test_the_words_the_module_may_not_produce_stay_out(db):
    """docs/PRODUCT.md 4g: the view states no outcome. Not reachable, not
    allowed, not blocked, not accepted, as our own claim."""
    doc = document(listening=[SSHD])
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"])
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    words = re.sub(r"<[^>]+>", " ", body).lower()
    for claim in ("is reachable", "is blocked", "is allowed", "was accepted",
                  "is secure", "is protected"):
        assert claim not in words, claim


def test_the_selection_is_radios_and_css_so_it_works_without_a_script(db):
    """The wire needs a script, because only the browser knows where a wrapped
    row landed. Picking a box does not."""
    doc = document(listening=[SSHD])
    body = path_of(db, doc=doc)
    assert 'type="radio"' in body and "ptsel" in body
    assert "onclick" not in body


def test_a_box_past_the_cap_is_drawn_and_is_not_a_label():
    """Every tool is drawn, because leaving one off the path would be the
    worse lie. A box the selection CSS does not cover simply does not open a
    panel, rather than carrying a `for` that reaches nothing."""
    assert build.path_node_html("", build.PATH_CAP + 1, "linux-logo", "x", "y"
                                ).startswith("<div class=\"pt-nd")
    assert "for=" not in build.path_node_html("", build.PATH_CAP + 1, "linux-logo",
                                              "x", "y")
    assert build.path_node_html("u-1", 1, "linux-logo", "x", "y").startswith("<label")


def test_an_unknown_fate_is_refused_rather_than_drawn():
    """The fates are the only outcomes the drawing may show, so a caller with
    a fifth word gets an error and not a page."""
    with pytest.raises(ValueError):
        build.path_flow_html("u", "", "", "", "probably fine", -1)


# ------------------------------------- properties the Gates design held first
#
# These were tests of the tab the sketch replaced on 2026-09-10. Each one
# guards something that is still true of the new drawing, so it is re-expressed
# here rather than deleted with the design. One of them found a real gap while
# this tab was being built: a tool whose rule could not be read was saying "no
# rule", which is a measurement nobody took.

def test_a_rule_nobody_could_read_never_reads_as_no_rule(db):
    """The gap the old suite caught. A chain holding a rule this page could
    not fully read says so, because "no rule" over an unreadable one is a
    claim about what a firewall permits."""
    doc = document(listening=[PG])
    doc["ufw"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "inet", "name": "crowdsec", "chains": [
            {"name": "crowdsec-input", "type": "filter", "hook": "input",
             "priority": -10, "policy": "accept", "rules": [
                 {"text": "tcp dport [unmodelled] counter drop",
                  "rendered": "partial"}]}]}]}
    body = path_of(db, doc=doc, states=[(5432, "v4", "no_response")])
    # Scoped to crowdsec's own box: firewalld is on this host too and holds no
    # rule for the port, which is a different and honest thing to say.
    box = next(chunk.split("</label>")[0]
               for chunk in body.split('<label class="pt-nd')
               if "crowdsec" in chunk.split("</label>")[0])
    # The box is 204px wide, so its line is the short form and the panel under
    # it carries the whole sentence.
    assert "not fully read" in box
    assert "no rule" not in box
    assert "a rule was not fully read" in body


def test_no_family_is_inferred_from_the_other(db):
    """docs/PRODUCT.md 4b. A v6 socket may or may not take v4 traffic and the
    document does not carry which, so each family is its own flow."""
    doc = document(listening=[
        SSHD, {"protocol": "tcp", "family": "v6", "bind_address": "::",
               "port": 22, "process_name": "sshd", "pid": 812}])
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    chips = re.findall(r'<label for="pp-box-c-\d+">([^<]+)</label>', body)
    assert chips == ["22/tcp v4", "22/tcp v6"]
    # the measured family answered, the unmeasured one says nobody looked
    assert [f[0] for f in flows(body)] == ["reach", "none"]


def test_a_family_nobody_measured_says_so_rather_than_borrowing_the_other(db):
    doc = document(listening=[
        SSHD, {"protocol": "tcp", "family": "v6", "bind_address": "::",
               "port": 22, "process_name": "sshd", "pid": 812}])
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    assert "not probed yet" in body


def test_legacy_iptables_rules_are_counted_and_never_placed_on_a_port(db):
    """The agent stores those by match name only, so they can be counted and
    never shown as naming a port (site/app/packetpath.py)."""
    doc = document(listening=[SSHD])
    doc["iptables"] = {"status": "collected", "tables": [{
        "name": "filter", "chains": [{"name": "INPUT", "builtin": True,
                                      "policy": "accept", "rules": [
            {"text": "-A INPUT -m set --match-set banned src -j DROP",
             "rendered": "none"}]}]}]}
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    assert "legacy iptables rule" in body
    assert "not placed on a port" in body


def test_a_ruleset_that_was_not_collected_says_so(db):
    doc = document(listening=[SSHD])
    doc["nftables"] = {"status": "permission_denied"}
    body = path_of(db, doc=doc)
    assert "permission denied" in body
    assert 'class="pt-flow"' not in body


def test_a_host_whose_sockets_could_not_be_read_is_not_a_host_with_nothing_bound(db):
    """The two are different facts and only one of them is a problem."""
    doc = document(listening=[])
    doc["sockets"] = {"status": "collected", "listening": "not a list"}
    body = path_of(db, doc=doc)
    assert "could not be read" in body
    assert "nothing is bound" not in body


def test_a_name_you_gave_the_port_is_preferred_at_the_end_and_says_it_is_yours(db):
    """docs/PRODUCT.md 8b: the page prefers the name and always says it was
    given rather than measured."""
    doc = document(listening=[SSHD])
    add_host(db, "box", [(NOW - timedelta(minutes=4), doc)],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    trl.declare_name(db, "box", "tcp", 22, "the jump box")
    body = trl.tab_body(trl.host_section(rl.render(db, now=NOW), "box"), "box", "path")
    assert "the jump box" in body
    assert "you named it" in body


def test_a_socket_with_no_process_name_is_named_by_where_it_is_bound(db):
    """A limited agent reads no process name, and the end says what it has
    rather than inventing one."""
    doc = document(listening=[{"protocol": "tcp", "family": "v4",
                               "bind_address": "0.0.0.0", "port": 22}])
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    assert "0.0.0.0:22" in body


def test_an_answering_port_marks_no_tool_as_a_cause(db):
    """Nothing stopped it, so nothing is marked. The only thing the drawing
    shows is the prober's own answer at the end."""
    doc = document(listening=[SSHD])
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"])
    doc["nftables"] = nft_with_ufw()
    body = path_of(db, doc=doc, states=[(22, "v4", "connect_succeeded")])
    assert flows(body) == [("reach", -1)]
    assert "ends its journey here" not in body
    assert "pt-stop" not in body
