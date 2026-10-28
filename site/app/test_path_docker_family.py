"""The Packet path of a port Docker publishes, one address family at a time.

    Run from site/: python3 -m pytest app/test_path_docker_family.py

Docker carries a published port past the host firewall where it rewrites the
packet's destination in the kernel, in the stage before routing
(docs/PRODUCT.md 4a, 4d). It does that per address family. A container on a
bridge with no IPv6 is still published on the host's IPv6 addresses, by
Docker's userland proxy: a plain socket on the host, which the host
firewall's input rules apply to. On a real server that port answered over v4
and was silent over v6, and the path drew v4's picture for both: Docker
"publishes 8080", and ufw "not reached" on the rail with "ends its journey
here" in its own panel (docs/RECORD.md 4.237). On a network made with IPv6
Docker does rewrite on v6 as well, and that port answered past ufw on both
families (docs/RECORD.md 4.210, case 1b). So the family alone does not say
which it is. The kernel's own rules do.

What is held here, the edges first:

  - reading the port out of a rule of Docker's that the agent rendered in
    part, and refusing every rule it cannot read a single port from
  - the three answers for a family: Docker rewrites this port, Docker
    rewrites nothing for it, and the document cannot say. A rule that could
    not be read, a walk that stopped early and legacy rules, which are never
    placed on a port, all leave it at "cannot say", never at "nothing"
  - a box the packet never meets is never the box that ends its journey
  - what is drawn for each answer, the Overview saying the same of the same
    port and family, and v4 as it was

Docker's rules are written here in the words the agent sent from a real
server with Docker 29.8.2 and one port published on its default bridge, read
2026-10-11: the rule that rewrites the destination stands in `ip nat DOCKER`,
partly rendered, and `ip6 nat DOCKER` is empty. **The rule of an IPv6 network
is not from a document.** No stored document holds one, so it is written the
way the agent renders the same rule on v4 and the way it renders a protocol
match on v6, and the case it stands for was not measured again.
"""
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import packetpath as pp  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
import test_overview_skipped_narrowing_rule as case  # noqa: E402

NOW = trl.NOW


def rule(text, rendered="full"):
    return {"text": text, "rendered": rendered}


def rewrite4(port, bridge="docker0"):
    """Docker's rule for one published port on v4, as a real server's agent
    sent it: the target is not rendered, the port is."""
    return rule(f'iifname != "{bridge}" ip protocol tcp tcp dport {port}'
                " counter [xt target DNAT]", "partial")


def rewrite6(port, bridge):
    """The same rule on v6. Written by hand, see the note at the top."""
    return rule(f'iifname != "{bridge}" meta l4proto tcp tcp dport {port}'
                " counter [xt target DNAT]", "partial")


def docker_nat(family, rules):
    """Docker's side of the nat table, as the agent rendered it."""
    return {"family": family, "name": "nat", "chains": [
        {"name": "PREROUTING", "type": "nat", "hook": "prerouting",
         "priority": -100, "policy": "accept",
         "rules": [rule("[xt match addrtype] counter jump DOCKER", "partial")]},
        {"name": "DOCKER", "rules": rules}]}


def ufw_section(rules, rules6):
    return {"status": "collected", "conf": {"ENABLED": "yes"},
            "defaults": {"DEFAULT_INPUT_POLICY": "DROP",
                         "DEFAULT_OUTPUT_POLICY": "ACCEPT"},
            "rules": list(rules), "rules6": list(rules6),
            "sources": {"ufw.conf": {"status": "collected"},
                        "user.rules": {"status": "collected"},
                        "user6.rules": {"status": "collected"}}}


def legacy_section(count=1):
    """A legacy table as the agent stores one: its rules by match name only,
    so none of them can be placed on a port."""
    return {"status": "collected", "tables": [{"name": "nat", "chains": [
        {"name": "DOCKER", "rules": [
            {"text": "-A DOCKER [xt match tcp] [xt target DNAT]", "rendered": "none"}
        ] * count}]}]}


def a_docker_server(nat4=None, nat6=None, rules6=("allow tcp 22 ::/0 any ::/0 in",)):
    """The repository's own server for this case, one container publishing
    8080 on both families, with ufw's own section and Docker's nat tables."""
    doc = case.document()
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
                              "allow tcp 8080 0.0.0.0/0 any 203.0.113.7 in"], rules6)
    if nat4 is not None:
        doc["nftables"]["tables"].append(docker_nat("ip", nat4))
    if nat6 is not None:
        doc["nftables"]["tables"].append(docker_nat("ip6", nat6))
    return doc


def said(doc, family, port=8080):
    """The answer for one family, asked the way the tab asks it."""
    return rl.docker_rewrite(doc, pp.path_for(doc, "tcp", port, family), "tcp", port, family)


def read_paths(page, host="box"):
    """Each path of a server as the tab draws it: its fate, its boxes as
    (name, state, words), each box's panel head, and its end."""
    body = trl.tab_body(trl.host_section(page, host), host, "path")
    chips = re.findall(rf'<label for="pp-{host}-c-\d+">([^<]+)</label>', body)
    read = {}
    for chip, flow in zip(chips, body.split('<div class="pt-meas">')[1:]):
        boxes = re.findall(
            r'<label class="pt-nd n\d+( pt-\w+)?"[^>]*>.*?<span class="pt-nn">([^<]*)</span>'
            r'<span class="pt-nc">([^<]*)</span>', flow, flags=re.S)
        panels = {name: case.text_of(rest) for name, rest in re.findall(
            r'<div class="pt-under u\d+"><div class="pt-uh">.*?<h3>([^<]*)</h3>(.*?)'
            r'(?=<div class="pt-under|$)', flow, flags=re.S)}
        end = re.search(
            r'pt-endR.*?<span class="pt-l">([^<]*)</span><span class="pt-v">([^<]*)</span>'
            r'<span class="pt-s">([^<]*)</span>', flow, flags=re.S).groups()
        read[chip] = {
            "fate": re.search(r'data-fate="(\w+)"', flow).group(1),
            "word": case.text_of(flow.split('<div class="pt-flow', 1)[0]),
            "boxes": [(name, state.strip(), words) for state, name, words in boxes],
            "panels": panels, "end": end}
    return read


def drawn(tmp_path, doc, states):
    """A server with this document and these probe results, its paths read."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", doc)
    for port, family, state in states:
        trl.probe_result(db, "box", port, family, state,
                         measured_at=NOW - timedelta(minutes=1))
    return read_paths(rl.render(db, now=NOW))


# ------------------------------------- reading the port out of Docker's rule

def test_the_port_is_read_out_of_a_rule_the_agent_rendered_in_part():
    """The walk files this rule as not fully readable for every port, because
    its target is not rendered. Which port it is about is in its text."""
    assert pp.named_dport(rewrite4(8080)["text"]) == ("tcp", 8080)
    assert pp.named_dport(rewrite6(3051, "br-0f3a")["text"]) == ("tcp", 3051)
    assert pp.classify_rule(rewrite4(8080)["text"], "partial", "tcp", 22) == pp.UNREADABLE


@pytest.mark.parametrize("text", [
    'iifname "docker0" counter return',              # names no port at all
    "tcp dport >= 1024 counter [xt target DNAT]",    # not an equality
    "tcp dport != 22 counter [xt target DNAT]",
    "tcp dport & 0xff == 0x16 counter accept",       # a masked comparison
    "tcp dport 8000-8010 counter [xt target DNAT]",  # a range
    "tcp dport 80 tcp dport 443 counter accept",     # more than one
    "[xt match multiport] counter [xt target DNAT]",  # the port not rendered
    "counter jump DOCKER",
    "", None, 8080, ["tcp dport 8080"],
])
def test_a_rule_that_names_no_single_port_is_read_as_none(text):
    assert pp.named_dport(text) is None


def test_a_port_with_no_protocol_beside_it_is_read_with_none():
    assert pp.named_dport("th dport 8080 counter accept") == ("", 8080)
    assert pp.named_dport("meta l4proto udp th dport 53 counter accept") == ("udp", 53)


# ------------------------------------------------- the three answers, per family

def test_a_rule_that_could_not_be_read_is_cannot_say_and_never_nothing():
    """The rule may be about this port. Reading it as "Docker rewrites
    nothing" would put ufw on the way of a packet that never meets it."""
    doc = a_docker_server(nat4=[rewrite4(8080)],
                          nat6=[rule("[xt match multiport] counter [xt target DNAT]", "partial")])
    assert said(doc, "v6") == rl.DOCKER_CANNOT_SAY


def test_a_walk_that_stopped_early_is_cannot_say(monkeypatch):
    """The walk has a limit on the rules it examines, for a document made to
    hang the page. What it did not get to was not read."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[])
    monkeypatch.setattr(pp, "MAX_RULES_WALKED", 1)
    assert said(doc, "v6") == rl.DOCKER_CANNOT_SAY


def test_legacy_rules_of_the_family_are_cannot_say_and_the_other_familys_are_not():
    """A legacy rule is stored by match name only, so Docker's rule may be
    among them and no port can be read from it."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[])
    doc["ip6tables"] = legacy_section()
    assert said(doc, "v6") == rl.DOCKER_CANNOT_SAY
    doc["ip6tables"] = {"status": "not_present"}
    doc["iptables"] = legacy_section()
    assert said(doc, "v6") == rl.DOCKER_REWRITES_NOTHING
    assert said(doc, "v4") == rl.DOCKER_REWRITES


def test_legacy_rules_on_v4_with_nothing_read_in_the_kernel_are_cannot_say():
    doc = a_docker_server()
    doc["iptables"] = legacy_section()
    assert said(doc, "v4") == rl.DOCKER_CANNOT_SAY


def test_a_rule_for_another_port_or_another_protocol_is_not_this_ports():
    doc = a_docker_server(nat4=[rewrite4(9090)], nat6=[])
    assert said(doc, "v4") == rl.DOCKER_REWRITES_NOTHING
    udp = rule('iifname != "docker0" ip protocol udp udp dport 8080'
               " counter [xt target DNAT]", "partial")
    assert said(a_docker_server(nat4=[udp]), "v4") == rl.DOCKER_REWRITES_NOTHING


def test_a_rule_outside_dockers_own_chains_is_not_dockers():
    """Somebody's own rule for the port in the nat table says nothing of
    what Docker does."""
    doc = a_docker_server(nat6=[])
    doc["nftables"]["tables"].append({"family": "ip6", "name": "mine", "chains": [
        {"name": "pre", "type": "nat", "hook": "prerouting", "priority": -90,
         "policy": "accept", "rules": [rule("tcp dport 8080 counter accept")]}]})
    assert said(doc, "v6") == rl.DOCKER_REWRITES_NOTHING


def test_a_rule_in_dockers_own_table_is_dockers_whatever_its_chain_is_called():
    """Docker's nftables backend writes into tables of its own, `ip
    docker-bridges` and `ip6 docker-bridges` (Docker's own page, read
    2026-10-11). No document from that backend was read, so the rule here is
    a stand-in this page cannot read a port from, and the answer is the one
    such a rule always gets."""
    doc = a_docker_server()
    doc["nftables"]["tables"].append({"family": "ip6", "name": "docker-bridges", "chains": [
        {"name": "nat-PREROUTING", "type": "nat", "hook": "prerouting", "priority": -100,
         "policy": "accept", "rules": [rule("[unmodelled] counter accept", "partial")]}]})
    assert said(doc, "v6") == rl.DOCKER_CANNOT_SAY
    assert said(doc, "v4") == rl.DOCKER_REWRITES_NOTHING


def test_a_ruleset_that_was_read_and_holds_no_chain_of_dockers_is_nothing():
    doc = a_docker_server()
    assert said(doc, "v4") == rl.DOCKER_REWRITES_NOTHING
    assert said(doc, "v6") == rl.DOCKER_REWRITES_NOTHING


def test_the_real_servers_two_families_get_two_answers():
    """Docker's rule in `ip nat DOCKER` and an empty `ip6 nat DOCKER`."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[])
    assert said(doc, "v4") == rl.DOCKER_REWRITES
    assert said(doc, "v6") == rl.DOCKER_REWRITES_NOTHING


# ----------------------------- a box never met is never the box that ends it

def test_a_docker_port_silent_on_v4_leaves_ufw_not_reached_and_marks_nobody(tmp_path):
    """The other half of the same fault. The only chain the document marks
    for a silence here is ufw's own input chain, and a packet Docker
    rewrites is forwarded past it. So ufw stays "not reached", no box ends
    the journey, and the packets fade: nothing came back and nothing on the
    packet's way accounts for it."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[])
    v4 = drawn(tmp_path, doc, [(8080, "v4", "no_response")])["8080/tcp v4"]
    assert ("Docker", "", "publishes 8080") in v4["boxes"], v4["boxes"]
    assert ("ufw", "pt-ghost", "not reached") in v4["boxes"], v4["boxes"]
    assert v4["fate"] == "lost", v4
    assert not any("ends its journey here" in head for head in v4["panels"].values()), v4


def test_where_the_document_cannot_say_the_path_stays_as_it_was(tmp_path):
    """Legacy rules on v4: Docker's box, ufw "not reached", and still no
    box that is both not reached and the end of the journey."""
    doc = a_docker_server()
    doc["iptables"] = legacy_section()
    paths = drawn(tmp_path, doc, [(8080, "v4", "connect_succeeded")])
    assert ("Docker", "", "publishes 8080") in paths["8080/tcp v4"]["boxes"]
    assert ("ufw", "pt-ghost", "not reached") in paths["8080/tcp v4"]["boxes"]
    silent = drawn(tmp_path / "silent", doc, [(8080, "v4", "no_response")])["8080/tcp v4"]
    assert ("ufw", "pt-ghost", "not reached") in silent["boxes"], silent["boxes"]
    assert silent["fate"] == "lost", silent


# -------------------------------------------- what is drawn for each answer

def test_on_an_ipv6_network_the_v6_path_is_dockers_as_v4_is(tmp_path):
    """docs/RECORD.md 4.210, case 1b: a network made with IPv6, the port
    answered on both families with no ufw rule for it. The fixture is
    written from that record, not from a document, and was not measured
    again."""
    doc = case.document()
    for socket in doc["sockets"]["listening"]:
        if socket["port"] == 8080:
            socket["port"] = 3051
    doc["containers"]["docker"][0]["ports"] = [
        {"host_ip": ip, "host_port": 3051, "container_port": 3051, "protocol": "tcp"}
        for ip in ("0.0.0.0", "::")]
    doc["ufw"] = ufw_section(["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"],
                             ["allow tcp 22 ::/0 any ::/0 in"])
    doc["nftables"]["tables"] += [docker_nat("ip", [rewrite4(3051, "br-0f3a")]),
                                  docker_nat("ip6", [rewrite6(3051, "br-0f3a")])]
    paths = drawn(tmp_path, doc, [(3051, "v4", "connect_succeeded"),
                                  (3051, "v6", "connect_succeeded")])
    for family, address in (("v4", "0.0.0.0"), ("v6", "::")):
        path = paths[f"3051/tcp {family}"]
        assert path["fate"] == "reach", path
        assert ("Docker", "", "publishes 3051") in path["boxes"], path["boxes"]
        assert ("ufw", "pt-ghost", "not reached") in path["boxes"], path["boxes"]
        # each family's own publication, never the other's
        assert f"published on {address} " in path["panels"]["Docker"] + " ", path["panels"]


def test_where_docker_rewrites_nothing_and_ufw_permits_the_port_ufw_says_so(tmp_path):
    """The same bridge with ufw permitting 8080 on v6. ufw is an ordinary
    box in its own words, and nothing is marked on a port that answered."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[],
                          rules6=("allow tcp 22 ::/0 any ::/0 in",
                                  "allow tcp 8080 ::/0 any ::/0 in"))
    v6 = drawn(tmp_path, doc, [(8080, "v6", "connect_succeeded")])["8080/tcp v6"]
    assert v6["boxes"] == [("ufw", "", "allow 8080, anywhere")], v6["boxes"]
    assert v6["fate"] == "reach", v6


def test_the_end_is_the_socket_docker_holds_and_its_panel_names_the_container(tmp_path):
    """No Docker box stands on this path, so the end is where the container
    is named: the socket by what holds it, the container among its facts."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[])
    v6 = drawn(tmp_path, doc, [(8080, "v6", "no_response")])["8080/tcp v6"]
    assert v6["end"] == ("listening", "docker-proxy", "[::]:8080"), v6["end"]
    panel = v6["panels"]["docker-proxy"]
    assert "on [::]:8080" in panel and "container office" in panel, panel


def test_no_socket_and_nothing_rewritten_is_a_port_nothing_listens_on(tmp_path):
    """Docker lists the port for v6, holds no socket there and rewrites
    nothing: on this family the publication reaches nothing, and the end
    does not say it reaches the container."""
    doc = a_docker_server(nat4=[rewrite4(8080)], nat6=[])
    doc["sockets"]["listening"] = [s for s in doc["sockets"]["listening"]
                                   if not (s["port"] == 8080 and s["family"] == "v6")]
    v6 = drawn(tmp_path, doc, [(8080, "v6", "no_response")])["8080/tcp v6"]
    assert v6["end"][0] == "nothing listens", v6["end"]
    assert "Docker" not in [name for name, _state, _words in v6["boxes"]], v6["boxes"]


def test_a_publication_of_the_other_family_only_draws_no_docker_box(tmp_path):
    """Docker publishing on 0.0.0.0 alone, and a socket of somebody's on the
    same port on v6: the v6 path is not Docker's, and no box on it says what
    Docker published on v4."""
    doc = a_docker_server(nat4=[rewrite4(8080)])
    doc["containers"]["docker"][0]["ports"] = [
        {"host_ip": "0.0.0.0", "host_port": 8080, "container_port": 8080,
         "protocol": "tcp"}]
    v6 = drawn(tmp_path, doc, [(8080, "v6", "no_response")])["8080/tcp v6"]
    assert "Docker" not in [name for name, _state, _words in v6["boxes"]], v6["boxes"]
    assert "0.0.0.0" not in " ".join(v6["panels"].values()), v6["panels"]


# ------------------------------------------------- the server it was found on

def the_server(db):
    doc = case.document()
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP",
                               "DEFAULT_OUTPUT_POLICY": "ACCEPT"},
                  "rules": ["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in",
                            "allow tcp 8080 0.0.0.0/0 any 203.0.113.7 in"],
                  "rules6": ["allow tcp 22 ::/0 any ::/0 in"],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    doc["nftables"]["tables"] += [
        docker_nat("ip", [rule('iifname != "docker0" ip protocol tcp tcp dport 8080'
                               " counter [xt target DNAT]", "partial")]),
        docker_nat("ip6", [])]
    real = case.document
    case.document = lambda host_rules=None: doc
    try:
        case.measured_server(db)
    finally:
        case.document = real


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    the_server(path)
    return path


@pytest.fixture()
def paths(db):
    """Each path of the server as the tab draws it: its fate, its boxes as
    (name, state, words), and each box's panel tag."""
    return read_paths(rl.render(db, now=NOW))


def test_on_v6_the_box_that_ends_the_journey_is_not_also_not_reached(paths):
    v6 = paths["8080/tcp v6"]
    assert v6["fate"] == "stop", v6
    assert "ends its journey here" in v6["panels"]["ufw"], v6
    ufw = next(box for box in v6["boxes"] if box[0] == "ufw")
    assert ufw[2] != "not reached", v6["boxes"]


def test_on_v6_no_box_says_docker_publishes_what_its_bridge_does_not_carry(paths):
    v6 = paths["8080/tcp v6"]
    assert "publishes 8080" not in [words for _name, _state, words in v6["boxes"]], v6["boxes"]


def test_on_v4_the_path_stays_as_it_was_drawn(paths):
    v4 = paths["8080/tcp v4"]
    assert v4["fate"] == "reach", v4
    assert ("Docker", "", "publishes 8080") in v4["boxes"], v4["boxes"]
    assert ("ufw", "pt-ghost", "not reached") in v4["boxes"], v4["boxes"]


def test_on_v6_the_whole_path_is_the_provider_ufw_and_the_socket(paths):
    v6 = paths["8080/tcp v6"]
    assert v6["boxes"] == [("Hetzner Cloud", "", "allow 8080, anywhere"),
                           ("ufw", "pt-stop", "no rule for 8080")], v6["boxes"]
    assert v6["end"] == ("listening", "docker-proxy", "[::]:8080"), v6["end"]


def test_the_overview_and_the_path_say_the_same_of_each_family(db, paths):
    """One port, two screens. Per family: the prober's word, the provider's
    rule, and which container publishes the port on which address.

    The card's firewall line is not compared. It is the engine's count of
    kernel rules, and with Docker's partly rendered jump in the ruleset it
    reads "1 rule not fully readable" on this server, beside a ufw box that
    reads ufw's own files."""
    cards = case.row(rl.render(db, now=NOW), 8080)["cards"]

    v6, card = paths["8080/tcp v6"], cards["v6"]
    assert card["lead"] == "not reachable, no answer" and "no answer" in v6["word"]
    assert card["provider"] == "in tcp 8080 from 0.0.0.0/0, ::/0"
    assert ("Hetzner Cloud", "", "allow 8080, anywhere") in v6["boxes"]
    assert card["agent"] == "docker container office publishes it on ::"
    assert "on [::]:8080" in v6["panels"]["docker-proxy"]
    assert "container office" in v6["panels"]["docker-proxy"]

    v4, card = paths["8080/tcp v4"], cards["v4"]
    assert card["prober"].startswith("connected") and "answered" in v4["word"]
    assert card["provider"] == "in tcp 8080 from 0.0.0.0/0, ::/0"
    assert ("Hetzner Cloud", "", "allow 8080, anywhere") in v4["boxes"]
    assert card["agent"] == "docker container office publishes it on 0.0.0.0"
    assert "to office" in v4["panels"]["Docker"]
    assert "published on 0.0.0.0" in v4["panels"]["Docker"]
