"""A provider's permit is not the answer for a Docker port that answers an
address its host rule does not permit (docs/PRODUCT.md 8d, docs/RECORD.md
4.358).

    Run from controlplane/: python -m pytest tests/test_join_skipped_narrowing_rule.py

Measured on a real server (4.309): the provider's firewall open to every
address on tcp 8080, ufw `8080/tcp from` one address, Docker publishing 8080,
and both probers connected from other addresses. The engine called the port
`intended` by the provider firewall. Docker carries a published port past
ufw's input chain (docs/PRODUCT.md 4d), so the person had said who may reach
the port and somebody else got an answer.

Four things have to hold, and every test below either builds that case or
takes exactly one of them away:

1. Docker publishes the port in this family.
2. The host's ruleset was read and no rule read in it permits the port for
   everyone.
3. Every narrowed host permit for the port is a plain narrowing by source
   address: on the input hook, behind jumps that leave no condition, with one
   address or one prefix and nothing else left over.
4. A prober whose own addresses are all outside every such source connected.

The port is then `unreviewed`, and the finding says so in one field,
`answered_outside_the_rules_source`, for every screen to read.
"""
import pytest

from app import alerts, finding_alerts, intent, join, prober, store
from app import vantages as vantage_registry
from tests.test_join import (add_host, chain, con, document, find, finding_for,  # noqa: F401
                             hetzner_snapshot, probe_run, report, rule, socket_row,
                             table, ufw_v4, ufw_v6)

__all__ = ["con"]

PORT = 8080
TARGET_V4 = "203.0.113.5"
TARGET_V6 = "2001:db8::5"
# The one address the host's rule permits. Nobody probes from it.
SOURCE = "203.0.113.7"
SOURCE_V6 = "2001:db8:7::7"
# Where the two probers probe from, as the registry holds them.
PROBE1 = "185.199.110.1"
PROBE2 = "185.199.110.2"
PROBE1_V6 = "2606:50c0:8000::1"


def from_source(source=SOURCE, port=PORT):
    """What `ufw allow from <source> to any port <port> proto tcp` writes."""
    return f"ip saddr {source} ip protocol tcp tcp dport {port} counter accept"


def from_source_v6(source=SOURCE_V6, port=PORT):
    return f"ip6 saddr {source} meta l4proto tcp tcp dport {port} counter accept"


OPEN_TO_ALL = f"ip protocol tcp tcp dport {PORT} counter accept"


def provider_rule(sources=("0.0.0.0/0", "::/0"), port=PORT):
    return {"direction": "in", "protocol": "tcp", "port": str(port),
            "description": None, "source_ips": list(sources), "destination_ips": []}


def published(runtime="docker", host_ips=("0.0.0.0",), port=PORT):
    return {"status": "collected", runtime: [
        {"name": "office", "ports": [
            {"host_ip": ip, "host_port": port, "container_port": port,
             "protocol": "tcp"} for ip in host_ips]}]}


# The socket Docker holds on the host for a published port, as the agent
# reports it on that server.
DOCKER_SOCKET = socket_row(PORT, process="docker-proxy")
DOCKER_SOCKET_V6 = socket_row(PORT, family="v6", process="docker-proxy", bind_address="::")


def probers(con, **addresses):
    """The registry: each prober by name with the addresses it probes from."""
    vantage_registry.init(con)
    for name, held in addresses.items():
        vantage_registry.add(con, name, f"root@{name}", list(held))


def answers(con, host_id, *, connected=("probe1", "probe2"), silent=(),
            family="v4", port=PORT):
    """Each prober's newest measurement of the port."""
    target = TARGET_V4 if family == "v4" else TARGET_V6
    for name in connected:
        probe_run(con, host_id, [(family, port, prober.STATE_CONNECTED, None, target)],
                  vantage=name)
    for name in silent:
        probe_run(con, host_id, [(family, port, prober.STATE_NO_RESPONSE,
                                  "timeout_expired", target)], vantage=name)


def server(con, *, tables=None, containers="docker", sockets=None,
           provider=(provider_rule(),), registry=True, connected=("probe1", "probe2"),
           silent=(), nftables_status="collected", iptables=None, family="v4"):
    """The measured server, with whatever the test changes about it, and the
    host's id. By default: Docker publishes the port, ufw permits it from one
    address, the provider's firewall permits it from everywhere, and two
    probers connected from addresses of their own."""
    host_id = add_host(con)
    if tables is None:
        tables = [ufw_v4([from_source()])]
    if containers == "docker":
        containers = published()
    if sockets is None:
        sockets = [DOCKER_SOCKET]
    report(con, host_id, document(sockets=sockets, tables=tables, containers=containers,
                                  nftables_status=nftables_status, iptables=iptables))
    if provider is not None:
        hetzner_snapshot(con, rules=list(provider))
    if registry:
        probers(con, probe1=[PROBE1, PROBE1_V6], probe2=[PROBE2])
    answers(con, host_id, connected=connected, silent=silent, family=family)
    return host_id


def port_finding(con, host_id, family="v4", **kw):
    return finding_for(join.host_findings(con, host_id, **kw), "tcp", PORT, family)


def the_case(con, **changes):
    return port_finding(con, server(con, **changes), family=changes.get("family", "v4"))


def asks(finding):
    """The port is `unreviewed` by this rule and by nothing else."""
    return (finding.state == join.STATE_UNREVIEWED
            and finding.cause.layer == join.LAYER_SERVICE
            and finding.answered_outside_the_rules_source is True)


def as_before(finding):
    """What the engine said until this rule: `intended`, by the provider."""
    return (finding.state == join.STATE_INTENDED
            and finding.cause.layer == join.LAYER_PROVIDER
            and finding.answered_outside_the_rules_source is False)


# ------------------------------------------------------------------ the case

def test_round_11s_port_is_unreviewed_and_no_longer_intended(con):
    finding = the_case(con)

    assert finding.outside.state == prober.STATE_CONNECTED
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.cause.layer == join.LAYER_SERVICE
    assert finding.intent is None
    # What it was read from, each as the measured server had it.
    assert [p.runtime for p in finding.inside.publications] == ["docker"]
    assert finding.inside.permit_rules == ()
    assert [q.text for q in finding.inside.narrowed_rules] == [from_source()]
    assert len(finding.provider.rules) == 1
    assert join.NOTE_RULE_IS_NARROWED in finding.cause.notes


def test_its_quotes_are_the_publication_the_narrowed_host_rule_and_the_providers_rule(con):
    finding = the_case(con)
    quotes = list(finding.cause.quotes)

    publication = next(i for i, q in enumerate(quotes)
                       if q.text == "publishes this port on 0.0.0.0")
    host_rule = next(i for i, q in enumerate(quotes) if q.text == from_source())
    providers = next(i for i, q in enumerate(quotes) if q.layer == join.LAYER_PROVIDER)
    assert publication < host_rule < providers
    assert quotes[host_rule].layer == join.LAYER_HOST_FIREWALL
    # Nothing after the provider's rule, and each of the three once.
    assert providers == len(quotes) - 1
    assert sum(q.text == from_source() for q in quotes) == 1


def test_the_typed_field_is_true_in_this_case_and_in_no_other(con):
    host_id = server(con)
    found = join.host_findings(con, host_id).findings

    marked = [(f.protocol, f.port, f.family) for f in found
              if f.answered_outside_the_rules_source]
    assert marked == [("tcp", PORT, "v4")]
    assert isinstance(port_finding(con, host_id).answered_outside_the_rules_source, bool)


def test_a_source_prefix_that_holds_no_prober_address_asks_as_one_address_does(con):
    assert asks(the_case(con, tables=[ufw_v4([from_source("203.0.113.0/24")])]))


def test_a_v6_source_rule_on_a_v6_port_asks_the_same_way(con):
    finding = the_case(
        con, family="v6", tables=[ufw_v6([from_source_v6()])],
        containers=published(host_ips=("::",)), sockets=[DOCKER_SOCKET_V6],
        connected=("probe1",))

    assert asks(finding)
    assert [q.text for q in finding.inside.narrowed_rules] == [from_source_v6()]


# ------------------------------------------------- what the rule has to be

def test_a_rule_narrowed_by_interface_is_as_before(con):
    text = f'iifname "wg0" ip protocol tcp tcp dport {PORT} counter accept'
    finding = the_case(con, tables=[ufw_v4([text])])

    assert [q.text for q in finding.inside.narrowed_rules] == [text]
    assert as_before(finding)


def test_a_rule_narrowed_by_destination_address_is_as_before(con):
    text = f"ip daddr 203.0.113.5 ip protocol tcp tcp dport {PORT} counter accept"
    finding = the_case(con, tables=[ufw_v4([text])])

    assert [q.text for q in finding.inside.narrowed_rules] == [text]
    assert as_before(finding)


@pytest.mark.parametrize("source", ["@office", "{ 203.0.113.7, 203.0.113.8 }"],
                         ids=["a named set", "a set written out"])
def test_a_rule_narrowed_by_a_set_of_addresses_is_as_before(con, source):
    text = f"ip saddr {source} ip protocol tcp tcp dport {PORT} counter accept"
    finding = the_case(con, tables=[ufw_v4([text])])

    assert [q.text for q in finding.inside.narrowed_rules] == [text]
    assert as_before(finding)


@pytest.mark.parametrize("source", ["203.0.113.7/255.255.255.0", "office.example",
                                    "203.0.113.999", ""],
                         ids=["a mask written out", "a name", "no address", "nothing"])
def test_a_rule_the_engine_cannot_take_apart_is_as_before(con, source):
    text = f"ip saddr {source} ip protocol tcp tcp dport {PORT} counter accept"
    finding = the_case(con, tables=[ufw_v4([text])])

    assert len(finding.inside.narrowed_rules) == 1
    assert as_before(finding)


@pytest.mark.parametrize("extra", ['iifname "eth0"', "ip daddr 203.0.113.5",
                                   "meta mark 0x1", "ct state established"])
def test_a_source_with_a_second_condition_beside_it_is_as_before(con, extra):
    text = f"ip saddr {SOURCE} {extra} ip protocol tcp tcp dport {PORT} counter accept"
    finding = the_case(con, tables=[ufw_v4([text])])

    assert [q.text for q in finding.inside.narrowed_rules] == [text]
    assert as_before(finding)


@pytest.mark.parametrize("source", [f"!= {SOURCE}", "203.0.113.7-203.0.113.9"],
                         ids=["negated", "a range"])
def test_a_negated_source_and_a_range_of_addresses_are_as_before(con, source):
    text = f"ip saddr {source} ip protocol tcp tcp dport {PORT} counter accept"
    finding = the_case(con, tables=[ufw_v4([text])])

    assert len(finding.inside.narrowed_rules) == 1
    assert as_before(finding)


def test_a_rule_narrowed_by_the_jump_that_leads_to_it_is_as_before(con):
    """firewalld's way into a zone that has a source: the jump carries the
    source and the rule behind it is a plain accept. Not this case, because
    Docker beside firewalld was not measured for it."""
    zones = table("inet", "firewalld", [
        chain("filter_INPUT", [rule(f"ip saddr {SOURCE} jump filter_IN_office")],
              hook="input", priority=10, type_="filter", policy="accept"),
        chain("filter_IN_office", [rule(f"tcp dport {PORT} accept")]),
    ])
    finding = the_case(con, tables=[zones])

    assert [q.text for q in finding.inside.narrowed_rules] == [f"tcp dport {PORT} accept"]
    assert as_before(finding)


def test_a_narrowed_rule_of_another_kind_beside_the_source_rule_is_as_before(con):
    """What the second rule permits the prober is not known, so nothing is
    said about the first."""
    other = f'iifname "wg0" ip protocol tcp tcp dport {PORT} counter accept'
    finding = the_case(con, tables=[ufw_v4([from_source(), other])])

    assert [q.text for q in finding.inside.narrowed_rules] == [from_source(), other]
    assert as_before(finding)


def test_a_source_rule_on_the_prerouting_hook_is_as_before(con):
    """A forwarded packet passes prerouting, so that rule was on its way."""
    early = table("ip", "early", [
        chain("pre", [rule(from_source())],
              hook="prerouting", priority=-150, type_="filter", policy="accept")])
    finding = the_case(con, tables=[early])

    assert [q.text for q in finding.inside.narrowed_rules] == [from_source()]
    assert as_before(finding)


# --------------------------------------------------------------- the prober

def test_a_prober_inside_the_rules_source_is_as_before(con):
    """Both probers are in the range the rule permits, so nothing measured
    says an address outside it got an answer."""
    finding = the_case(con, tables=[ufw_v4([from_source("185.199.110.0/24")])])

    assert [q.text for q in finding.inside.narrowed_rules] == [
        from_source("185.199.110.0/24")]
    assert as_before(finding)


def test_one_prober_outside_the_source_that_connected_is_enough(con):
    assert asks(the_case(con, tables=[ufw_v4([from_source(PROBE1)])]))


def test_a_prober_that_did_not_connect_is_not_compared(con):
    """probe1 is the address the rule permits, and it connected. probe2 is
    outside the rule, and it got no answer."""
    finding = the_case(con, tables=[ufw_v4([from_source(PROBE1)])],
                       connected=("probe1",), silent=("probe2",))

    assert finding.outside.state == prober.STATE_CONNECTED
    assert as_before(finding)


def test_a_vantage_with_no_address_in_the_registry_is_as_before(con):
    """The runs name a prober the registry does not hold, so where it probes
    from is not known."""
    finding = the_case(con, registry=False)

    assert finding.outside.state == prober.STATE_CONNECTED
    assert as_before(finding)


def test_a_vantage_with_no_address_of_this_family_is_as_before(con):
    """probe2 holds a v4 address alone. A v6 connection stored under its name
    came from an address the registry does not hold."""
    finding = the_case(
        con, family="v6", tables=[ufw_v6([from_source_v6()])],
        containers=published(host_ips=("::",)), sockets=[DOCKER_SOCKET_V6],
        connected=("probe2",))

    assert finding.outside.state == prober.STATE_CONNECTED
    assert as_before(finding)


def test_a_vantage_with_one_address_inside_the_source_and_one_outside_is_as_before(con):
    """Which of its two addresses it probed from is not stored."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[DOCKER_SOCKET], containers=published(),
                                  tables=[ufw_v4([from_source(PROBE1)])]))
    hetzner_snapshot(con, rules=[provider_rule()])
    probers(con, probe1=[PROBE1, PROBE2])
    answers(con, host_id, connected=("probe1",))

    assert as_before(port_finding(con, host_id))


def test_two_source_rules_ask_only_when_the_prober_is_outside_both(con):
    both = [from_source(), from_source("203.0.113.99")]
    assert asks(the_case(con, tables=[ufw_v4(both)]))


def test_two_source_rules_one_of_which_holds_every_prober_are_as_before(con):
    both = [from_source(), from_source("185.199.110.0/24")]
    assert as_before(the_case(con, tables=[ufw_v4(both)]))


# --------------------------------------------------------- what stays as it is

def test_an_unconditional_host_rule_beside_the_narrowed_one_keeps_it_intended(con):
    finding = the_case(con, tables=[ufw_v4([from_source(), OPEN_TO_ALL])])

    assert [q.text for q in finding.inside.permit_rules] == [OPEN_TO_ALL]
    assert as_before(finding)


def test_a_rate_limited_rule_for_everyone_keeps_it_intended(con):
    """`ufw limit`: the rule that permits names the port and jumps to a chain
    that holds a bare accept (docs/PRODUCT.md 8d)."""
    limited = table("ip", "filter", [
        chain("INPUT", [rule("counter jump ufw-user-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw-user-input", [
            rule(from_source()),
            rule(f"ip protocol tcp tcp dport {PORT} counter jump ufw-user-limit-accept")]),
        chain("ufw-user-limit-accept", [rule("counter accept")]),
    ])
    finding = the_case(con, tables=[limited])

    assert len(finding.inside.permit_rules) == 1
    assert as_before(finding)


def test_a_docker_port_with_no_host_rule_for_it_stays_intended_by_the_provider(con):
    finding = the_case(con, tables=[ufw_v4(["ip protocol tcp tcp dport 22 counter accept"])])

    assert finding.inside.narrowed_rules == () and finding.inside.permit_rules == ()
    assert as_before(finding)


def test_a_port_served_by_the_hosts_own_process_is_unchanged(con):
    finding = the_case(con, containers=None, sockets=[socket_row(PORT, process="caddy")])

    assert finding.inside.publications == ()
    assert [q.text for q in finding.inside.narrowed_rules] == [from_source()]
    assert as_before(finding)


def test_a_rootful_podman_port_is_unchanged(con):
    finding = the_case(con, containers=published(runtime="podman"),
                       sockets=[socket_row(PORT, process="conmon")])

    assert [p.runtime for p in finding.inside.publications] == ["podman"]
    assert as_before(finding)


@pytest.mark.parametrize("provider", [None, ()], ids=["not connected", "no rule"])
def test_with_no_provider_rule_it_is_unreviewed_as_before(con, provider):
    """Already `unreviewed`, by the rule that a narrowed rule is no answer.
    The field is about a provider's permit that was not taken, and there is
    none here."""
    finding = the_case(con, provider=provider)

    assert finding.state == join.STATE_UNREVIEWED
    assert finding.cause.layer == join.LAYER_SERVICE
    assert finding.answered_outside_the_rules_source is False
    assert all(q.layer != join.LAYER_PROVIDER for q in finding.cause.quotes)


def test_a_provider_rule_that_is_itself_narrowed_is_as_before(con):
    finding = the_case(con, provider=(provider_rule(sources=("198.51.100.0/24",)),))

    assert finding.provider.rules == () and len(finding.provider.narrowed) == 1
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.answered_outside_the_rules_source is False


@pytest.mark.parametrize("declared, state", [("open", join.STATE_INTENDED),
                                             ("closed", join.STATE_CONFLICT)])
def test_declared_open_it_is_intended_and_declared_closed_it_is_a_conflict(con, declared, state):
    host_id = server(con)
    finding = port_finding(con, host_id, intent={("tcp", PORT, "v4"): declared})

    assert finding.state == state
    assert finding.cause.layer == join.LAYER_SERVICE
    assert finding.answered_outside_the_rules_source is False


def test_each_family_is_decided_by_itself(con):
    """Docker publishes on both families and both answer. The host's rule is
    about v4. On v6 there is no host rule, so the provider's permit for ::/0
    is the answer there, as it is for any Docker port with no host rule."""
    host_id = server(con, containers=published(host_ips=("0.0.0.0", "::")),
                     sockets=[DOCKER_SOCKET, DOCKER_SOCKET_V6])
    answers(con, host_id, connected=("probe1",), family="v6")

    assert asks(port_finding(con, host_id, "v4"))
    v6 = port_finding(con, host_id, "v6")
    assert v6.outside.state == prober.STATE_CONNECTED
    assert v6.inside.narrowed_rules == ()
    assert as_before(v6)


def test_a_host_ruleset_that_was_not_read_changes_nothing(con):
    finding = the_case(con, nftables_status="permission_denied")

    assert as_before(finding)


def test_rules_not_fully_read_are_no_permit_and_the_port_asks_with_its_note(con):
    """A rule that could not be fully read may be the permit for everyone.
    It is never counted as one anywhere in the engine, so the port asks, and
    the finding says a rule was not fully read. The measured server's own
    finding carried that note."""
    unread = "ip protocol tcp [xt match multiport] counter accept"
    finding = the_case(con, tables=[ufw_v4([from_source(), unread])])

    assert finding.inside.unreadable_rule_count == 1
    assert asks(finding)
    assert join.NOTE_RULES_NOT_FULLY_READABLE in finding.cause.notes
    assert join.NOTE_RULE_IS_NARROWED in finding.cause.notes


def test_legacy_rules_not_placed_are_no_permit_and_the_port_asks_with_its_note(con):
    legacy = {"status": "collected", "tables": [table("", "filter", [
        chain("INPUT", [rule("-p tcp --dport 8080 -j ACCEPT")])])]}
    finding = the_case(con, iptables=legacy)

    assert finding.inside.legacy_rule_count == 1
    assert asks(finding)
    assert join.NOTE_LEGACY_RULES_NOT_PLACED in finding.cause.notes


def test_a_port_that_did_not_answer_is_not_reachable_as_before(con):
    finding = the_case(con, connected=(), silent=("probe1", "probe2"))

    assert finding.outside.state == prober.STATE_NO_RESPONSE
    assert finding.state == join.STATE_NOT_REACHABLE
    assert finding.answered_outside_the_rules_source is False


def test_nothing_listening_is_a_stale_rule_as_before(con):
    """Nothing publishes the port and nothing listens. The provider's permit
    names a port with nothing behind it."""
    finding = the_case(con, containers=None, sockets=[socket_row(22)],
                       connected=(), silent=("probe1", "probe2"))

    assert finding.state == join.STATE_STALE_RULE
    assert finding.cause.layer == join.LAYER_PROVIDER
    assert finding.answered_outside_the_rules_source is False


def test_a_server_with_no_agent_is_unchanged(con):
    """Watched by its address alone: there is no ruleset to have read."""
    host_id = store.add_address_host(con, "edge")
    probers(con, probe1=[PROBE1], probe2=[PROBE2])
    answers(con, host_id)
    finding = port_finding(con, host_id)

    assert finding.inside.absent is True
    # What it reads today, with nothing declared: reachable, and nothing
    # inside to say whose rule that is.
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.answered_outside_the_rules_source is False


def test_the_change_is_told_once_as_any_change_of_state(con):
    """A port that read `intended` by the provider while the host held no
    rule for it. Then somebody writes the rule for one address: the port is
    `unreviewed`, that is told once, and a second look tells nothing more."""
    intent.init(con)
    alerts.init(con)
    finding_alerts.init(con)
    host_id = add_host(con)
    unruled = document(sockets=[DOCKER_SOCKET], containers=published(), tables=[ufw_v4([])])
    report(con, host_id, unruled, received_at="2026-08-16T11:00:00+00:00")
    hetzner_snapshot(con, rules=[provider_rule()])
    probers(con, probe1=[PROBE1], probe2=[PROBE2])
    answers(con, host_id)
    finding_alerts.evaluate(con)
    assert as_before(port_finding(con, host_id))

    ruled = document(sockets=[DOCKER_SOCKET], containers=published(),
                     tables=[ufw_v4([from_source()])])
    con.execute("DELETE FROM reports WHERE host_id = ?", (host_id,))
    report(con, host_id, ruled, received_at="2026-08-16T13:00:00+00:00")
    assert asks(port_finding(con, host_id))
    finding_alerts.evaluate(con)
    finding_alerts.evaluate(con)

    told = [(row["from_state"], row["to_state"]) for row in con.execute(
        "SELECT from_state, to_state FROM finding_changes WHERE port = ? AND family = 'v4'"
        " ORDER BY id", (PORT,))]
    assert told[-1] == (join.STATE_INTENDED, join.STATE_UNREVIEWED)
    assert told.count((join.STATE_INTENDED, join.STATE_UNREVIEWED)) == 1
