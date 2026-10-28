"""Tests for the join engine.

Written before `app/join.py` existed and run red first, which is the method
`docs/RECORD.md` 4.46 and 4.48 argue for: a guard nobody has tried to break is
not evidence.

The mutations these are built to catch, in the order they matter:

  1. **Claiming an outside measurement we do not have.** Every test that names
     a state also asserts the outside *state*, not only its reason. That is the
     exact hole `docs/RECORD.md` 4.48 found in the prober, where replacing
     `not_tested` with `no_response` on the unauthorised path left all 112
     tests green because they asserted the reason and never the state.
  2. **Reading one address family's answer as the other's.** v4 and v6 are
     separate findings and a probe row carries its own family.
  3. **Reading a TCP measurement as a UDP one.** `probe_results` has no
     protocol column and the prober is TCP connect only, so the join has to
     refuse to apply a row to a UDP port.
  4. **Inventing a state.** A port with no outside measurement and no stale
     rule evidence has no state at all, and the honest default is not
     `unreviewed`.
"""

import json
import pathlib

import pytest

from app import db, hetzner, join, prober, store

# --------------------------------------------------------------- the fixtures

def rule(text, rendered="full", comment=""):
    return {"text": text, "rendered": rendered, "comment": comment}


def chain(name, rules=(), hook=None, priority=None, type_=None, policy=None):
    out = {"name": name, "rules": list(rules)}
    if hook is not None:
        out["hook"] = hook
    if priority is not None:
        out["priority"] = priority
    if type_ is not None:
        out["type"] = type_
    if policy is not None:
        out["policy"] = policy
    return out


def table(family, name, chains=()):
    return {"family": family, "name": name, "chains": list(chains)}


def socket_row(port, family="v4", protocol="tcp", process="sshd",
               bind_address="0.0.0.0", pid=1):
    return {"protocol": protocol, "family": family, "bind_address": bind_address,
            "port": port, "process_name": process, "pid": pid}


def document(*, hostname="almabox", sockets=(), tables=(), containers=None,
             sockets_status="collected", nftables_status="collected",
             collected_at_unix=1_700_000_000, iptables=None, ip6tables=None):
    doc = {
        "schema_version": 1,
        "hostname": hostname,
        "collected_at_unix": collected_at_unix,
        "sockets": {"status": sockets_status, "listening": list(sockets)},
        "nftables": {"status": nftables_status, "tables": list(tables)},
    }
    if containers is not None:
        doc["containers"] = containers
    if iptables is not None:
        doc["iptables"] = iptables
    if ip6tables is not None:
        doc["ip6tables"] = ip6tables
    return doc


def ufw_v4(rules):
    """A ufw-shaped v4 ruleset: the base chain holds nothing but jumps and
    every rule a person wrote lives two chains deeper. `docs/RECORD.md` 4.42
    point 2: without following jumps the screen is empty on the commonest
    firewall there is, and the same is true of this engine."""
    return table("ip", "filter", [
        chain("INPUT", [rule("counter jump ufw-before-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw-before-input", [rule("counter jump ufw-user-input")]),
        chain("ufw-user-input", [rule(text) for text in rules]),
    ])


def ufw_v6(rules):
    return table("ip6", "filter", [
        chain("INPUT", [rule("counter jump ufw6-before-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw6-before-input", [rule("counter jump ufw6-user-input")]),
        chain("ufw6-user-input", [rule(text) for text in rules]),
    ])


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "test.db"))
    db.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


def add_host(con, name="almabox"):
    host_id, _ = store.add_host(con, name)
    return host_id


def report(con, host_id, doc, received_at=None):
    store.insert_report(con, host_id, doc.get("collected_at_unix", 0),
                        doc.get("schema_version", 1), json.dumps(doc))
    if received_at is not None:
        con.execute("UPDATE reports SET received_at = ? WHERE host_id = ?",
                    (received_at, host_id))
        con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                    (received_at, host_id))
        con.commit()


def probe_run(con, host_id, results, started_at="2026-08-16T12:00:00+00:00",
              finished_at="2026-08-16T12:00:05+00:00", vantage="test-vantage"):
    """One probe run written the way `app/prober.py` writes one. Results are
    (family, port, state, reason, target) tuples."""
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, vantage, started_at, finished_at))
    run_id = cur.lastrowid
    for family, port, state, reason, target in results:
        con.execute(
            "INSERT INTO probe_results (run_id, target, family, port, state,"
            " reason, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, target, family, port, state, reason, started_at))
    con.commit()
    return run_id


def find(result, protocol, port, family):
    """The finding, or None when the engine produced none for that port."""
    for finding in result.findings:
        if (finding.protocol, finding.port, finding.family) == (protocol, port, family):
            return finding
    return None


def finding_for(result, protocol, port, family):
    finding = find(result, protocol, port, family)
    if finding is None:
        raise AssertionError(
            f"no finding for {protocol}/{port} on {family}, have "
            f"{[(f.protocol, f.port, f.family) for f in result.findings]}")
    return finding


# ------------------------------------------------- the rule that matters most

def test_no_probe_result_reads_not_tested_and_says_so(con):
    """The single most important rule: with no probe row the outside view is
    not tested, and it is never inferred from the inside view."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))

    result = join.host_findings(con, host_id)
    finding = finding_for(result, "tcp", 22, "v4")

    assert finding.outside.state == prober.STATE_NOT_TESTED
    assert finding.outside.word == "not tested"
    assert finding.outside.reason == join.REASON_NOT_PROBED
    assert finding.outside.connected is False


def test_a_listening_socket_alone_produces_no_state(con):
    """A host that says it is listening tells us nothing about what the
    internet can reach. Mutating the engine to call this `unreviewed` is the
    mutation this test exists for."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 22 counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")

    assert finding.state is None
    assert finding.outside.state == prober.STATE_NOT_TESTED
    assert join.NOTE_OUTSIDE_NOT_MEASURED in finding.cause.notes


def test_every_state_except_stale_rule_needs_a_measurement(con):
    """**The invariant that survived a change to the rule around it.**

    This test used to say those four states may only appear beside a connect
    that *succeeded*. The owner changed that on 2026-08-16 (RECORD 4.55): a port
    the outside view measured as silent earns a word of its own too, with
    reality inverted. Since 2026-08-28 the undeclared half of that inversion
    is `not reachable` rather than a second meaning for `unreviewed`
    (RECORD 4.112), and this test is where the pairing is pinned.

    What did not change, and is the half that was always doing the work, is
    that a state may never sit beside `not_tested`. A state compares reality
    against a declaration, and with nothing measured there is no reality to
    compare, so naming one would state a finding nobody made.

    So the assertion is now split rather than loosened. `not_tested` is held to
    exactly what it was held to before. The two measured-and-silent states are
    asserted positively, which is stricter than the old test was about them: it
    only said they were absent, and now it says which one has to be there.
    Pinned across the whole vocabulary at once so a sixth path cannot appear
    without this failing.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))

    def sweep(state, reason):
        # The newest-result table first: a result it still names cannot be
        # deleted, by design (`prober.LATEST_SCHEMA`).
        con.execute("DELETE FROM probe_latest")
        con.execute("DELETE FROM probe_results")
        con.execute("DELETE FROM probe_runs")
        probe_run(con, host_id, [("v4", 22, state, reason, "203.0.113.5")])
        finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
        assert finding.outside.state == state
        return finding

    # Nothing measured. Unchanged, and this is the accuracy rule itself.
    finding = sweep(prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)
    assert finding.state not in join.STATES, (
        "a state was named beside not_tested, which states a finding nobody made")
    assert finding.state is None

    # Measured and silent, both ways the far side can be silent. With nothing
    # declared the answer is `not reachable`, and asserting it positively is
    # what makes this stricter than the test it replaces. It is deliberately
    # not `unreviewed`: that word means the internet reached this port, and a
    # measured silence is the opposite fact.
    for state, reason in ((prober.STATE_REFUSED, None),
                          (prober.STATE_NO_RESPONSE, prober.REASON_TIMEOUT_EXPIRED)):
        assert sweep(state, reason).state == join.STATE_NOT_REACHABLE


# ------------------------------------------------------- the families and TCP

def test_a_v4_measurement_is_never_read_as_a_v6_one(con):
    """PRODUCT.md 4b, the retraction this project already had to publish."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22, family="v4"), socket_row(22, family="v6",
                                                         bind_address="::")]))
    probe_run(con, host_id, [
        ("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")])

    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 22, "v4").outside.state == prober.STATE_CONNECTED
    v6 = finding_for(result, "tcp", 22, "v6")
    assert v6.outside.state == prober.STATE_NOT_TESTED
    assert v6.outside.reason == join.REASON_NOT_PROBED
    assert v6.state is None


def test_a_tcp_measurement_is_never_read_as_a_udp_one(con):
    """`probe_results` carries no protocol column and `app/prober.py` opens
    SOCK_STREAM sockets only, so every row in that table is a TCP answer. A
    join that matched on the port alone would report a UDP port as measured on
    the strength of a TCP connect."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[
        socket_row(53, protocol="tcp", process="named"),
        socket_row(53, protocol="udp", process="named")]))
    probe_run(con, host_id, [
        ("v4", 53, prober.STATE_CONNECTED, None, "203.0.113.5")])

    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 53, "v4").outside.state == prober.STATE_CONNECTED
    udp = finding_for(result, "udp", 53, "v4")
    assert udp.outside.state == prober.STATE_NOT_TESTED
    assert udp.outside.reason == join.REASON_NOT_PROBED


def test_a_port_on_v4_and_absent_on_v6_answers_both_separately(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(8096, family="v4")]))
    probe_run(con, host_id, [
        ("v4", 8096, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 8096, prober.STATE_NOT_TESTED, prober.REASON_NO_ADDRESS_IN_FAMILY,
         None)])

    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 8096, "v4").state == join.STATE_UNREVIEWED
    v6 = finding_for(result, "tcp", 8096, "v6")
    assert v6.outside.state == prober.STATE_NOT_TESTED
    assert v6.outside.reason == prober.REASON_NO_ADDRESS_IN_FAMILY
    assert v6.state is None


# ------------------------------------------------------------- the five states

def test_reachable_and_attributed_with_no_declared_intent_is_unreviewed(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22, process="sshd")]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")])

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.cause.layer == join.LAYER_SERVICE
    assert join.NOTE_NO_INTENT_DECLARED in finding.cause.notes


def test_declared_closed_and_reachable_is_conflict(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")])

    result = join.host_findings(
        con, host_id, intent={("tcp", 22, "v4"): join.INTENT_CLOSED})
    assert finding_for(result, "tcp", 22, "v4").state == join.STATE_CONFLICT


def test_declared_open_and_reachable_is_intended(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")])

    result = join.host_findings(
        con, host_id, intent={("tcp", 22, "v4"): join.INTENT_OPEN})
    assert finding_for(result, "tcp", 22, "v4").state == join.STATE_INTENDED


def test_reachable_and_nothing_on_the_host_owns_it_is_unexplained(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [
        ("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v4", 8080, prober.STATE_CONNECTED, None, "203.0.113.5")])

    finding = finding_for(join.host_findings(con, host_id), "tcp", 8080, "v4")
    assert finding.state == join.STATE_UNEXPLAINED
    assert finding.cause.layer == join.LAYER_NOT_DETERMINED
    assert join.NOTE_NOTHING_ON_THE_HOST_OWNS_IT in finding.cause.notes


def test_an_unconditional_accept_with_nothing_behind_it_is_a_stale_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 22 counter accept",
                        "ip protocol tcp tcp dport 80 counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.state == join.STATE_STALE_RULE
    assert finding.cause.layer == join.LAYER_HOST_FIREWALL
    quote = finding.cause.quotes[0]
    assert quote.text == "ip protocol tcp tcp dport 80 counter accept"
    assert quote.source == "ip filter ufw-user-input"


def test_the_six_states_are_the_only_states(con):
    """`not reachable` joined the set on 2026-08-28 (RECORD 4.112). The count
    is asserted as well as the set so that adding a word without deciding its
    tone, its sort band and its row in `docs/DESIGN.md` section 3 fails here
    first."""
    assert set(join.STATES) == {"conflict", "unreviewed", "intended",
                                "stale rule", "unexplained", "not reachable"}
    assert len(join.STATES) == 6
    text = pathlib.Path(join.__file__).read_text(encoding="utf-8")
    for retired in ("you said no", "never reviewed"):
        assert retired not in text, f"retired vocabulary {retired!r} is back"


# ------------------------------------------------------- what stale rule needs

def test_a_narrowed_accept_is_not_a_stale_rule(con):
    """ufw writes `ip daddr 239.255.255.250 ip protocol udp udp dport 1900
    counter accept` on every host it is installed on. It names a port and
    accepts, and it is scoped to a multicast address, so calling it a stale
    rule would put the same two rows on every ufw host forever. Measured on the
    production copy 2026-08-16: this exact rule is on two of the three hosts.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[ufw_v4([
        "ip daddr 239.255.255.250 ip protocol udp udp dport 1900 counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "udp", 1900, "v4")
    assert finding.state is None
    assert join.NOTE_RULE_IS_NARROWED in finding.cause.notes


def test_a_jump_is_not_an_accept(con):
    """ufw's after-input chains jump every SMB port to the policy. A jump is
    not a permit and it raises no stale-rule question, so no finding is
    produced at all. Measured on the production copy 2026-08-16: rules of this
    exact shape name tcp/139, tcp/445, udp/137 and udp/138 on two hosts."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[ufw_v4([
        "ip protocol tcp tcp dport 139 counter jump ufw-skip-to-policy-input"])]))
    assert find(join.host_findings(con, host_id), "tcp", 139, "v4") is None


@pytest.mark.parametrize("verdict", ["drop", "reject", "return", "queue num 0",
                                     "log prefix \"x\""])
def test_a_verdict_that_is_not_accept_is_not_a_permit(con, verdict):
    """Written after a mutation survived.

    `test_a_jump_is_not_an_accept` looked like it guarded this and did not:
    `_is_accept` refuses a jump twice over, once on the verdict token and once
    on the `jump` before it, so deleting the first check left that test green.
    Nothing anywhere asked whether a `drop` was being read as a permit, and
    `ip protocol tcp tcp dport 80 counter drop` strips down to nothing exactly
    the way an accept does. `docs/RECORD.md` 4.50: a guard written against the
    wrong property is not a guard.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[ufw_v4([
        f"ip protocol tcp tcp dport 80 counter {verdict}"])]))
    assert find(join.host_findings(con, host_id), "tcp", 80, "v4") is None


def test_a_listening_socket_behind_the_rule_is_not_a_stale_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 22 counter accept"])]))
    assert finding_for(join.host_findings(con, host_id), "tcp", 22, "v4").state is None


def test_a_container_publication_behind_the_rule_is_not_a_stale_rule(con):
    """No socket in the document, but podman publishes the port. Calling that
    stale would be the join engine not knowing what PRODUCT.md 4d already
    says about how a runtime publishes."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[],
        tables=[ufw_v4(["ip protocol tcp tcp dport 8096 counter accept"])],
        containers={"status": "collected", "podman": [
            {"name": "jellyfin", "ports": [
                {"host_ip": "0.0.0.0", "host_port": 8096, "protocol": "tcp"}]}]}))
    assert finding_for(join.host_findings(con, host_id), "tcp", 8096, "v4").state is None


def test_no_stale_rule_when_the_sockets_could_not_be_read(con):
    """"Nothing is listening" is half the claim, so a sockets section that did
    not collect makes the claim unsayable rather than true."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[], sockets_status="permission_denied",
        tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.state is None
    assert join.NOTE_SOCKETS_NOT_READ in finding.cause.notes


def test_no_stale_rule_when_the_ruleset_could_not_be_read(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)], nftables_status="permission_denied",
        tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.state is None
    assert join.NOTE_HOST_FIREWALL_NOT_READ in finding.cause.notes


def test_a_v4_rule_does_not_make_a_v6_stale_rule(con):
    """iptables and ip6tables are separate rule sets and so are `ip` and `ip6`
    nftables tables (PRODUCT.md 4b). A v4-only accept says nothing about v6."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[], tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 80, "v4").state == join.STATE_STALE_RULE
    assert find(result, "tcp", 80, "v6") is None


def test_an_inet_rule_carrying_nfproto_answers_for_the_family_it_names_only(con):
    """An `inet` table sees both families, and `meta nfproto ipv4` inside one
    pins the rule to v4. Treating it as unconditional for both would put a v4
    rule on a v6 finding, which is the 4b mistake with the families swapped.

    Until 2026-10-02 this test held the rule to `narrowed` on both families.
    The owner's delegated decision of 2026-09-30 (docs/RECORD.md 4.216,
    docs/PRODUCT.md 8d) is that the pin is no narrowing for the family it
    names: it is the same rule as `tcp dport 8443 accept` in an `ip` table. So
    on v4 this is a permit with nothing behind it, and on v6 it is no rule at
    all, and with nothing else raising the port there is no v6 row.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[table("inet", "firewalld", [
        chain("filter_INPUT", [rule("counter jump filter_IN_public_allow")],
              hook="input", priority=10, type_="filter", policy="accept"),
        chain("filter_IN_public_allow", [
            rule("meta nfproto ipv4 meta l4proto tcp tcp dport 8443 accept")])])]))
    result = join.host_findings(con, host_id)
    v4 = finding_for(result, "tcp", 8443, "v4")
    assert v4.state == join.STATE_STALE_RULE
    assert join.NOTE_RULE_IS_NARROWED not in v4.cause.notes
    assert find(result, "tcp", 8443, "v6") is None


# ------------------------------------- a rule pinned to one address family
#
# Round 2 of the test fleet, 2026-09-30, a Debian 13 server with nftables
# written by hand (docs/RECORD.md 4.220): `meta nfproto ipv4 tcp dport 4040
# accept` in an inet table, a listener behind it. v4 read unreviewed, "no
# rule", and mailed an alert. The text below is what the agent writes for
# that line, measured on 2026-10-02 (4.244).
PINNED_V4 = "meta nfproto ipv4 meta l4proto tcp tcp dport 4040 accept"
PINNED_V6 = "meta nfproto ipv6 meta l4proto tcp tcp dport 4040 accept"


def _handwritten(*rules):
    return table("inet", "filter", [
        chain("input", [rule(text) for text in rules],
              hook="input", priority=0, type_="filter", policy="drop")])


def _both_listeners(port):
    return [socket_row(port), socket_row(port, family="v6", bind_address="::")]


def test_a_rule_pinned_to_v4_is_your_rule_on_v4_and_no_rule_on_v6(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040),
                                  tables=[_handwritten(PINNED_V4)]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_NO_RESPONSE, "timeout", "2001:db8::5")])
    result = join.host_findings(con, host_id)

    v4 = finding_for(result, "tcp", 4040, "v4")
    assert v4.state == join.STATE_INTENDED
    assert v4.cause.layer == join.LAYER_HOST_FIREWALL
    assert [quote.text for quote in v4.inside.permit_rules] == [PINNED_V4]
    assert v4.inside.narrowed_rules == ()

    # Nothing about v4 answers v6 (docs/PRODUCT.md 4b): the v6 half carries
    # neither the rule nor a note about it.
    v6 = finding_for(result, "tcp", 4040, "v6")
    assert v6.state == join.STATE_NOT_REACHABLE
    assert v6.inside.permit_rules == ()
    assert v6.inside.narrowed_rules == ()
    assert join.NOTE_RULE_IS_NARROWED not in v6.cause.notes
    assert PINNED_V4 not in [quote.text for quote in v6.cause.quotes]


def test_a_v4_rule_is_not_the_answer_for_a_v6_port_that_answers(con):
    """The port answers on v6 as well, by some path this document does not
    explain. The v4 rule is still not v6's answer: v6 is unreviewed."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040),
                                  tables=[_handwritten(PINNED_V4)]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 4040, "v4").state == join.STATE_INTENDED
    v6 = finding_for(result, "tcp", 4040, "v6")
    assert v6.state == join.STATE_UNREVIEWED
    assert v6.inside.permit_rules == ()


def test_the_same_holds_the_other_way_round(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040),
                                  tables=[_handwritten(PINNED_V6)]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    v6 = finding_for(result, "tcp", 4040, "v6")
    assert v6.state == join.STATE_INTENDED
    assert [quote.text for quote in v6.inside.permit_rules] == [PINNED_V6]
    v4 = finding_for(result, "tcp", 4040, "v4")
    assert v4.state == join.STATE_UNREVIEWED
    assert v4.inside.permit_rules == ()
    assert v4.inside.narrowed_rules == ()


def test_a_pinned_rule_with_nothing_behind_it_is_stale_on_its_own_family_only(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[_handwritten(PINNED_V6)]))
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 4040, "v6").state == join.STATE_STALE_RULE
    assert find(result, "tcp", 4040, "v4") is None


def test_one_rule_per_family_is_an_answer_on_each(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040),
                                  tables=[_handwritten(PINNED_V4, PINNED_V6)]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    for family, text in (("v4", PINNED_V4), ("v6", PINNED_V6)):
        finding = finding_for(result, "tcp", 4040, family)
        assert finding.state == join.STATE_INTENDED, family
        assert [quote.text for quote in finding.inside.permit_rules] == [text], family


@pytest.mark.parametrize("text", [
    # The pin and a source range: a real narrowing on the family it names.
    "meta nfproto ipv4 ip saddr 203.0.113.0/24 meta l4proto tcp tcp dport 4040 accept",
    # A source address alone pins the family too, and narrows it.
    "ip saddr 203.0.113.7 meta l4proto tcp tcp dport 4040 accept",
    # The pin and an interface.
    'meta nfproto ipv4 iifname "eth1" meta l4proto tcp tcp dport 4040 accept',
])
def test_a_pin_with_something_else_beside_it_is_narrowed_on_its_family(con, text):
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040), tables=[_handwritten(text)]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    v4 = finding_for(result, "tcp", 4040, "v4")
    assert v4.state == join.STATE_UNREVIEWED, text
    assert [quote.text for quote in v4.inside.narrowed_rules] == [text], text
    assert v4.inside.permit_rules == (), text
    v6 = finding_for(result, "tcp", 4040, "v6")
    assert v6.inside.narrowed_rules == () and v6.inside.permit_rules == (), text


def test_a_rule_that_names_both_families_is_not_taken_apart(con):
    """`_rule_family` answers None for a rule naming both, which this engine
    does not understand, so the pin is left over and the rule stays narrowed
    on both families: the answer that claims less."""
    text = "meta nfproto ipv4 ip6 daddr 2001:db8::1 meta l4proto tcp tcp dport 4040 accept"
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040), tables=[_handwritten(text)]))
    probe_run(con, host_id, [("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5")])
    v4 = finding_for(join.host_findings(con, host_id), "tcp", 4040, "v4")
    assert v4.state == join.STATE_UNREVIEWED
    assert v4.inside.permit_rules == ()


@pytest.mark.parametrize("text, answers", [
    ("ip protocol tcp tcp dport 4040 accept", "v4"),
    ("ip6 nexthdr tcp tcp dport 4040 accept", "v6"),
])
def test_a_protocol_match_on_one_ip_header_pins_the_rule_inside_an_inet_table(con, text, answers):
    """`ip protocol tcp` can only be read from an IPv4 header and `ip6
    nexthdr tcp` from an IPv6 one, so in an `inet` table each is a pin. Until
    2026-10-02 both read as unconditional on both families there."""
    other = "v6" if answers == "v4" else "v4"
    host_id = add_host(con)
    report(con, host_id, document(sockets=_both_listeners(4040), tables=[_handwritten(text)]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 4040, answers).state == join.STATE_INTENDED
    assert finding_for(result, "tcp", 4040, other).state == join.STATE_UNREVIEWED
    assert finding_for(result, "tcp", 4040, other).inside.permit_rules == ()


def test_an_unpinned_inet_rule_still_answers_for_both_families(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=_both_listeners(4040),
        tables=[_handwritten("meta l4proto tcp tcp dport 4040 accept")]))
    probe_run(con, host_id, [
        ("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4040, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        assert finding_for(result, "tcp", 4040, family).state == join.STATE_INTENDED, family


def test_ufws_own_tables_read_as_they_did(con):
    """ufw writes v4 into `ip filter` and v6 into `ip6 filter`, each with its
    own protocol match. Neither table is seen by the other family, so the pin
    changes nothing there."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=_both_listeners(443),
        tables=[ufw_v4(["ip protocol tcp tcp dport 443 counter accept"]),
                ufw_v6(["meta l4proto tcp tcp dport 443 counter accept"])]))
    probe_run(con, host_id, [
        ("v4", 443, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 443, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 443, family)
        assert finding.state == join.STATE_INTENDED, family
        assert len(finding.inside.permit_rules) == 1, family


def test_an_unreadable_rule_is_counted_and_never_treated_as_an_accept(con):
    """`[lookup @__set0]` and the raw loads are the rules PRODUCT.md 4g says
    may select a port without saying so. They are shown, never concluded from.
    """
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4([("ip protocol tcp tcp dport 22 [xt match conntrack]"
                         " [xt match recent] counter jump ufw-user-limit")])]))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.inside.unreadable_rule_count >= 1
    assert join.NOTE_RULES_NOT_FULLY_READABLE in finding.cause.notes
    assert finding.state is None


def test_the_comment_match_is_looked_past_like_the_packet_path_does(con):
    """RECORD 4.42 point 4. Without this the most ordinary rule ufw writes
    reads as one whose port we cannot make out."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[ufw_v4([
        "ip protocol tcp tcp dport 80 [xt match comment] counter accept"])]))
    assert finding_for(join.host_findings(con, host_id), "tcp", 80,
                       "v4").state == join.STATE_STALE_RULE


def test_legacy_rules_are_counted_and_never_placed(con):
    """PRODUCT.md 4g: the agent stores an x_tables match by name only, so a
    legacy rule can never be shown as naming a port. Their number is a caveat
    on every finding for this host rather than a silent absence."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        iptables={"status": "collected", "tables": [table("", "filter", [
            chain("INPUT", [rule("[xt match tcp] -j ACCEPT")])])]}))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.inside.legacy_rule_count == 1
    assert join.NOTE_LEGACY_RULES_NOT_PLACED in finding.cause.notes


def test_a_v6_wildcard_bind_stops_the_v4_stale_rule_claim(con):
    """Found by running the engine against the production copy on 2026-08-16.

    `app-01` has `ufw allow 80` on v4 and caddy bound to `::`, and the
    first version of this engine called that a stale rule on v4. Whether a `::`
    socket also takes v4 traffic depends on IPV6_V6ONLY, **which the host
    document does not carry**, so "nothing is listening on v4" is not something
    this document can say. `site/app/packetpath.sockets_on` already says the
    same thing about the same field.

    Three ports on two of the three production hosts were affected:
    `app-01` tcp/80 and tcp/443, and `almabox` tcp/9090.
    """
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(80, family="v6", bind_address="::", process="caddy")],
        tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.state is None
    assert join.NOTE_V6_WILDCARD_MAY_SERVE_V4 in finding.cause.notes


def test_a_v6_bind_on_one_address_does_not_stop_the_v4_claim(con):
    """Only the wildcard is ambiguous. A socket bound to one v6 address takes
    nothing on v4 and says nothing about it."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(80, family="v6", bind_address="2001:db8::1")],
        tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.state == join.STATE_STALE_RULE
    assert join.NOTE_V6_WILDCARD_MAY_SERVE_V4 not in finding.cause.notes


def test_a_v4_wildcard_bind_does_not_stop_the_v6_claim(con):
    """The ambiguity runs one way only. A v4 socket never accepts a v6
    connection, so `0.0.0.0` is not evidence about v6. Measured on the
    production copy: `almabox` publishes tcp/8096 on `0.0.0.0` through
    podman, firewalld permits it on both families, and nothing serves it on
    v6."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(8096, family="v4", bind_address="0.0.0.0")],
        tables=[table("inet", "firewalld", [
            chain("filter_INPUT", [rule("counter jump filter_IN_public_allow")],
                  hook="input", priority=10, type_="filter", policy="accept"),
            chain("filter_IN_public_allow", [
                rule("meta l4proto tcp tcp dport 8096 accept")])])]))
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 8096, "v4").state is None
    assert finding_for(result, "tcp", 8096, "v6").state == join.STATE_STALE_RULE


def test_one_rule_reached_by_two_paths_is_quoted_once(con):
    """firewalld's `filter_IN_public_allow` is reached twice from
    `filter_INPUT_POLICIES` on the production copy, so the same accept came out
    as two identical quotes. The packet is evaluated against it once on
    whichever path it takes, and printing the rule twice tells the reader
    nothing."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[table("inet", "firewalld", [
        chain("filter_INPUT", [rule("counter jump policies")],
              hook="input", priority=10, type_="filter", policy="accept"),
        chain("policies", [rule("counter jump allow"), rule("counter jump allow")]),
        chain("allow", [rule("meta l4proto tcp tcp dport 9090 accept")])])]))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 9090, "v4")
    assert finding.state == join.STATE_STALE_RULE
    assert len(finding.cause.quotes) == 1


# ---------------------------------------------------------------- a rate limit
#
# `docs/RECORD.md` 4.36. The production box dropped tcp/22 for a burst of
# connections while 443 stayed up and cleared after 75 quiet seconds, which is
# ufw's `limit`. The rule text says the port is allowed and says nothing about
# the window just used up, so this is a rule the product has to name for what it
# is and may never blame for a silence.
#
# Every rule text below was read off the fleet on 2026-08-19, out of the host
# documents the agent had already sent: `ufw status` and `/etc/ufw/user.rules`
# on `whichports` for what ufw wrote, and the stored document for what the agent
# renders that as. The mutations these are built to catch:
#
#   1. Blaming it. A rate limit becoming a cause, a layer, or the thing a
#      measured silence is attributed to.
#   2. Marking the whole fleet. ufw's logging rate limiters sit on every port's
#      walked path on every ufw host, so a detection that ignores the port turns
#      every finding into a rate-limited one. Measured: 13 such rules in the
#      `ubuntu-vps` document, which has no limit rule at all.
#   3. Guessing. A rule with none of the tokens, or one whose comment or chain
#      name merely says limit, being filed as a rate limit anyway.
#   4. Changing something else. A plain allow, a plain deny and a narrowed
#      accept all have to come out exactly as they did before.

# ufw 0.36.2 `backend_iptables.py` replaces ` -j LIMIT` with three rules, and
# these are the three as the agent renders them. Read out of the
# `app-01` document on 2026-08-19.
UFW_LIMIT_V4 = [
    "ip protocol tcp tcp dport 22 [xt match conntrack] [xt match recent] counter",
    ("ip protocol tcp tcp dport 22 [xt match conntrack] [xt match recent]"
     " counter jump ufw-user-limit"),
    "ip protocol tcp tcp dport 22 counter jump ufw-user-limit-accept",
]

UFW_LIMIT_V6 = [
    "meta l4proto tcp tcp dport 22 [xt match conntrack] [xt match recent] counter",
    ("meta l4proto tcp tcp dport 22 [xt match conntrack] [xt match recent]"
     " counter jump ufw6-user-limit"),
    "meta l4proto tcp tcp dport 22 counter jump ufw6-user-limit-accept",
]

# ufw writes these whatever rules you gave it, they are on the walked path of
# every port, and they limit the log rather than the connection. Verbatim from
# the same documents.
UFW_LOG_LIMITERS = [
    "[limit] counter [xt target LOG]",
    "[xt match conntrack] [limit] counter return",
    "[limit] counter jump ufw-logging-deny",
]


def ufw_v4_with_limit_chains(rules):
    """A ufw v4 ruleset carrying the chains a `limit` rule jumps into and the
    logging chains, so the walk meets everything a real ufw host has. Without
    the logging chains the commonest false positive there is cannot happen in a
    test at all."""
    return table("ip", "filter", [
        chain("INPUT", [rule("counter jump ufw-before-input"),
                        rule("counter jump ufw-after-logging-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw-after-logging-input",
              [rule(UFW_LOG_LIMITERS[0], rendered="partial")]),
        chain("ufw-before-input", [
            rule(UFW_LOG_LIMITERS[1], rendered="partial"),
            rule("[xt match conntrack] counter jump ufw-logging-deny",
                 rendered="partial"),
            rule("counter jump ufw-not-local"),
            rule("counter jump ufw-user-input")]),
        chain("ufw-logging-deny", [rule(UFW_LOG_LIMITERS[0], rendered="partial")]),
        chain("ufw-not-local", [rule(UFW_LOG_LIMITERS[2], rendered="partial")]),
        chain("ufw-user-input", [rule(text, rendered=(
            "partial" if "[" in text else "full")) for text in rules]),
        chain("ufw-user-limit", [rule(UFW_LOG_LIMITERS[0], rendered="partial"),
                                 rule("counter [xt target REJECT]",
                                      rendered="partial")]),
        chain("ufw-user-limit-accept", [rule("counter accept")]),
    ])


def ufw_v6_with_limit_chains(rules):
    return table("ip6", "filter", [
        chain("INPUT", [rule("counter jump ufw6-before-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw6-before-input", [rule("counter jump ufw6-user-input")]),
        chain("ufw6-user-input", [rule(text, rendered=(
            "partial" if "[" in text else "full")) for text in rules]),
        chain("ufw6-user-limit", [rule(UFW_LOG_LIMITERS[0], rendered="partial")]),
        chain("ufw6-user-limit-accept", [rule("counter accept")]),
    ])


def limit_modules(finding):
    return [quote.limit_module for quote in finding.inside.rate_limit_rules]


def test_ufws_limit_rule_is_read_as_a_rate_limit_on_both_families(con):
    """The form the dogfooding finding was actually made of, on v4 and on v6.

    ufw's `limit` is `-m conntrack --ctstate NEW -m recent --update --seconds 30
    --hitcount 6`, and the agent stores an x_tables match by name only, so it
    arrives as `[xt match recent]` with the numbers gone. The module is what can
    be read and the module is what is named.
    """
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22), socket_row(22, family="v6", bind_address="::")],
        tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4),
                ufw_v6_with_limit_chains(UFW_LIMIT_V6)]))

    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 22, family)
        assert limit_modules(finding) == ["recent", "recent"], family
        assert join.NOTE_RULE_LIMITS_THE_RATE in finding.cause.notes, family


def test_the_iptables_limit_module_is_read_as_a_rate_limit(con):
    """`man iptables-extensions`: limit "Matches at a limited rate using a token
    bucket filter." The agent renders every nftables limit expression as a bare
    `[limit]`, so this is the shape a `-m limit` on a port arrives in."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains(
            ["ip protocol tcp tcp dport 22 [limit] counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert limit_modules(finding) == ["limit"]


def test_the_hashlimit_module_is_read_as_a_rate_limit(con):
    """`man iptables-extensions`: hashlimit "uses hash buckets to express a rate
    limiting match (like the limit match)". No host in this fleet has one, so
    the token shape comes from the agent's renderer rather than a measurement,
    and this test is what pins it."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains(
            ["ip protocol tcp tcp dport 22 [xt match hashlimit] counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert limit_modules(finding) == ["hashlimit"]


def test_ufws_logging_rate_limiters_are_not_read_as_this_ports_rate_limit(con):
    """**The mutation that would have marked the whole fleet.**

    `[limit] counter [xt target LOG]` is in `ufw-logging-deny` and in
    `ufw-after-logging-input` on every ufw host there is, both are on the walked
    path of every port, and both limit how often ufw writes a log line rather
    than how often a connection may be made. Measured on 2026-08-19: the
    `ubuntu-vps` document holds 13 rules carrying one of these tokens and
    not one limit rule, and the engine attached none of them.

    A rate limit is attached only to the port its own rule text plainly names,
    and this is that rule under test.
    """
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(80)],
        tables=[ufw_v4_with_limit_chains(
            ["ip protocol tcp tcp dport 80 counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.inside.rate_limit_rules == ()
    assert join.NOTE_RULE_LIMITS_THE_RATE not in finding.cause.notes
    assert "how often" not in join.describe(finding)


def test_a_limit_on_one_port_leaves_a_plain_allow_on_another_alone(con):
    """The production box's own shape: `ufw limit 22` beside `ufw allow 80`. The
    limit belongs to 22 and 80 comes out exactly as it would on a host with no
    limit rule anywhere."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains(
            UFW_LIMIT_V4 + ["ip protocol tcp tcp dport 80 counter accept"])]))

    result = join.host_findings(con, host_id)
    limited = finding_for(result, "tcp", 22, "v4")
    plain = finding_for(result, "tcp", 80, "v4")

    assert limit_modules(limited) == ["recent", "recent"]
    assert plain.inside.rate_limit_rules == ()
    # 80 is still a stale rule off an unconditional permit, unchanged.
    assert plain.state == join.STATE_STALE_RULE
    assert [q.text for q in plain.inside.permit_rules] == [
        "ip protocol tcp tcp dport 80 counter accept"]


def test_a_plain_allow_is_not_read_as_a_rate_limit(con):
    """`ufw allow 80` writes one accept and nothing else. Reading it as
    conditional would be the opposite failure to the one this work is about."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[], tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 80, "v4")
    assert finding.inside.rate_limit_rules == ()
    assert finding.state == join.STATE_STALE_RULE


def test_a_plain_deny_is_not_read_as_a_rate_limit(con):
    """`ufw deny 8080` writes a drop. It carries no rate limit and it is not a
    permit either, so nothing about it changes."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(8080)],
        tables=[ufw_v4_with_limit_chains(
            ["ip protocol tcp tcp dport 8080 counter drop"])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 8080, "v4")
    assert finding.inside.rate_limit_rules == ()
    assert finding.inside.permit_rules == ()
    assert finding.state is None


def test_limit_words_a_host_supplied_never_drive_the_detection(con):
    """A rule comment and a chain name are text the host wrote, so neither may
    decide anything. Three shapes in one document, and all three are plain
    accepts that happen to talk about limiting:

      - a decoded ufw comment saying it rate limits ssh
      - `[xt match comment]`, which is looked past because
        `net/netfilter/xt_comment.c` cannot select (`docs/PRODUCT.md` 4g)
      - a jump into a chain called `ufw-user-limit-accept`, which is the third
        rule ufw's own `limit` writes and is the one part of it that carries no
        token at all
    """
    host_id = add_host(con)
    # A socket on 9443 so that port is raised and the assertion below is a real
    # one. Without it nothing raises the port and the test would pass by
    # asserting nothing, which is `docs/RECORD.md` 4.50's lesson.
    report(con, host_id, document(
        sockets=[socket_row(9443)],
        tables=[table("ip", "filter", [
            chain("INPUT", [rule("counter jump ufw-user-input")],
                  hook="input", priority=0, type_="filter", policy="drop"),
            chain("ufw-user-input", [
                rule("ip protocol tcp tcp dport 8443 [xt match comment] counter accept",
                     rendered="partial",
                     comment="rate limit ssh here, recent hitcount 6 seconds 30"),
                rule("ip protocol tcp tcp dport 9443 counter jump ufw-user-limit-accept"),
            ]),
            chain("ufw-user-limit-accept", [rule("counter accept")])])]))

    result = join.host_findings(con, host_id)
    commented = finding_for(result, "tcp", 8443, "v4")
    assert commented.inside.rate_limit_rules == ()
    # And the comment did not stop it being read as the plain permit it is.
    assert commented.state == join.STATE_STALE_RULE

    jumped = finding_for(result, "tcp", 9443, "v4")
    assert jumped.inside.rate_limit_rules == ()
    assert join.NOTE_RULE_LIMITS_THE_RATE not in jumped.cause.notes


def test_a_rule_that_cannot_be_parsed_stays_unrecognised(con):
    """An unrecognised rule stays unrecognised rather than being guessed into a
    category. Every one of these carries a rate limit token and none of them
    states a port this engine can pin, so none of them is attached to anything.
    """
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains([
            # No port at all.
            "[limit] counter accept",
            # A port behind a set the agent did not decode.
            "ip protocol tcp [lookup @__set0] [xt match recent] counter accept",
            # A range and a negation, neither of which names one port.
            "ip protocol tcp tcp dport >= 1024 [limit] counter accept",
            "ip protocol tcp tcp dport != 22 [limit] counter accept",
            # A `dport` the regex cannot take apart.
            "ip protocol tcp tcp dport & 0xff == 0x16 [limit] counter accept",
            # No protocol stated.
            "tcp dport 22 [limit] counter accept",
            # The wrong protocol for this finding.
            "ip protocol udp udp dport 22 [limit] counter accept",
            # Empty.
            "",
        ])]))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.inside.rate_limit_rules == ()
    assert join.NOTE_RULE_LIMITS_THE_RATE not in finding.cause.notes


def test_a_v4_limit_is_not_read_onto_the_v6_finding(con):
    """iptables and ip6tables are separate rule sets and so are `ip` and `ip6`
    tables (`docs/PRODUCT.md` 4b). ufw writes the limit twice, once per family,
    and a host that has it on one side only has it on one side only."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22), socket_row(22, family="v6", bind_address="::1")],
        tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4),
                ufw_v6_with_limit_chains(
                    ["meta l4proto tcp tcp dport 22 counter accept"])]))

    result = join.host_findings(con, host_id)
    assert limit_modules(finding_for(result, "tcp", 22, "v4")) == ["recent", "recent"]
    assert finding_for(result, "tcp", 22, "v6").inside.rate_limit_rules == ()


def test_a_rate_limit_is_never_the_cause_and_never_explains_a_silence(con):
    """**The rule this whole change exists to hold.**

    The agent cannot see the window and the prober cannot know whether it hit
    it, so a measured silence on a rate-limited port is attributed to nothing.
    The state is the one `docs/PRODUCT.md` 8b already gives a measured silence,
    the layer stays undetermined, and the rate limit is not in the cause quotes,
    which is what `app/join_cli.py` prints under "decided at".
    """
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4)]))
    probe_run(con, host_id,
              [("v4", 22, prober.STATE_NO_RESPONSE, "timeout", "203.0.113.5")])

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")

    assert finding.outside.state == prober.STATE_NO_RESPONSE
    assert finding.state == join.STATE_NOT_REACHABLE
    assert finding.cause.layer == join.LAYER_NOT_DETERMINED
    assert limit_modules(finding) == ["recent", "recent"]
    for quote in finding.cause.quotes:
        assert "[xt match recent]" not in quote.text
        assert quote.limit_module == ""


def test_a_rate_limit_changes_no_state_at_all(con):
    """The same document with and without ufw's limit on 22, compared state for
    state. `docs/RECORD.md` 4.50's five words are the owner's and this change is not
    allowed to move a port between any two of them, or to invent a sixth.
    """
    # `ufw limit 22` against `ufw allow 22`. Since 2026-09-29 a rate-limited
    # permit is an answer like a plain one (docs/PRODUCT.md 8d, RECORD 4.209),
    # so the two documents must read the same on every port: the limit adds a
    # mark beside the state and moves nothing. From 2026-09-05 until then
    # this compared against no rule on 22 at all, because the limit form was
    # not counted and both sides read unreviewed.
    plain = ["ip protocol tcp tcp dport 22 counter accept",
             "ip protocol tcp tcp dport 80 counter accept"]
    limited = UFW_LIMIT_V4 + ["ip protocol tcp tcp dport 80 counter accept"]

    def states(name, rules):
        host_id = add_host(con, name=name)
        report(con, host_id, document(
            hostname=name, sockets=[socket_row(22)],
            tables=[ufw_v4_with_limit_chains(rules)]))
        probe_run(con, host_id,
                  [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")])
        result = join.host_findings(con, host_id)
        return {(f.protocol, f.port, f.family): f.state for f in result.findings}

    without = states("without-limit", plain)
    with_limit = states("with-limit", limited)

    # The same ports, each with the same word. tcp/22 is measured and
    # permitted either way and tcp/80 is permitted unconditionally either way.
    assert with_limit == without
    assert with_limit[("tcp", 22, "v4")] == join.STATE_INTENDED
    assert with_limit[("tcp", 80, "v4")] == join.STATE_STALE_RULE
    assert set(with_limit.values()) <= set(join.STATES) | {None}


def test_the_rate_limit_rules_are_marks_and_the_rule_beside_them_is_the_permit(con):
    """ufw's `limit` is three rules. The two that match on `recent` are a
    third thing and stay a third thing: never a permit, and never a narrowed
    rule, because "narrowed beyond the port" describes an address or an
    interface match and not a rate.

    The third, the jump to `ufw-user-limit-accept`, is the permit
    (docs/PRODUCT.md 8d). Until 2026-09-29 this test held all three out of
    `permit_rules`, on the ground that a rate-limited port with nothing behind
    it would then read as a stale rule. That is now the decided answer: the
    rule permits the port, and nothing is behind it.
    """
    host_id = add_host(con)
    # Reported the day it was probed. A silence only the probe names stops
    # being a row a day before the newest document (4.207), and a report
    # stamped with the wall clock would put this one six weeks behind it.
    report(con, host_id, document(
        sockets=[], tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4)]),
        received_at="2026-08-16T12:10:00+00:00")
    probe_run(con, host_id,
              [("v4", 22, prober.STATE_REFUSED, "refused", "203.0.113.5")])

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert limit_modules(finding) == ["recent", "recent"]
    assert [quote.text for quote in finding.inside.permit_rules] == [UFW_LIMIT_V4[2]]
    assert finding.inside.narrowed_rules == ()
    assert finding.state == join.STATE_STALE_RULE
    assert finding.cause.layer == join.LAYER_HOST_FIREWALL
    assert join.NOTE_RULE_IS_NARROWED not in finding.cause.notes
    for quote in finding.inside.permit_rules:
        assert "[xt match recent]" not in quote.text

    probe_run(con, host_id, [("v4", 8080, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 8080, "v4")
    assert finding.state == join.STATE_UNEXPLAINED


def test_the_sentence_names_the_module_and_quotes_the_rule(con):
    """What the product may now say, in the words it says it in."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4)]))

    sentence = join.describe(
        finding_for(join.host_findings(con, host_id), "tcp", 22, "v4"))

    assert ("host firewall matches this port on how recently and how often a "
            "connection was made, through the recent module: ip protocol tcp "
            "tcp dport 22 [xt match conntrack] [xt match recent] counter in "
            "ip filter ufw-user-input." in sentence)
    # It states no outcome, which is the same restraint `docs/PRODUCT.md` 4g
    # puts on the packet path and for the same measurement.
    for word in ("blocked", "blocks", "dropped", "drops", "denied", "reachable",
                 "unreachable"):
        assert word not in sentence.lower(), word
    # And it is held to the two rules every other sentence here is held to,
    # because the tests that own those (BANNED and the dash test) build their own
    # documents and neither of them carries a limit rule.
    for word in BANNED:
        assert word not in sentence.lower(), word
    assert "—" not in sentence and "–" not in sentence and ";" not in sentence


def test_non_limit_rules_produce_exactly_the_sentence_they_produced_before(con):
    """The regression guard. Four rule shapes with no rate limit anywhere, each
    pinned to its whole sentence, so a change to the rule reading that leaks
    into an ordinary rule fails here rather than on a screen."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443)],
        tables=[ufw_v4([
            "ip protocol tcp tcp dport 80 counter accept",
            "ip saddr 10.0.0.0/8 ip protocol tcp tcp dport 8443 counter accept",
            "ip protocol tcp tcp dport 9000 counter drop",
        ])]))

    result = join.host_findings(con, host_id)

    assert join.describe(finding_for(result, "tcp", 80, "v4")) == (
        "tcp/80 on v4: stale rule. The outside view is not tested. Nothing on "
        "this host is listening on it and no container publishes it. host "
        "firewall permits it: ip protocol tcp tcp dport 80 counter accept in "
        "ip filter ufw-user-input.")
    assert join.describe(finding_for(result, "tcp", 8443, "v4")) == (
        "tcp/8443 on v4: The outside view is not tested. Nothing on this host "
        "is listening on it and no container publishes it. host firewall names "
        "this port in a rule that is narrowed beyond the port: ip saddr "
        "10.0.0.0/8 ip protocol tcp tcp dport 8443 counter accept in ip filter "
        "ufw-user-input.")
    assert join.describe(finding_for(result, "tcp", 443, "v4")) == (
        "tcp/443 on v4: The outside view is not tested. The host is listening: "
        "sshd on 0.0.0.0.")
    assert find(result, "tcp", 9000, "v4") is None


# ------------------------------------------------------------- the provider leg

def hetzner_snapshot(con, *, server_name="almabox", rules=(), firewall_name="fw-1"):
    hetzner.init(con)
    snapshot = hetzner.Snapshot(
        fetched_at="2026-08-16T11:00:00+00:00",
        servers=({"id": 7, "name": server_name, "status": "running",
                  "public_net": {"ipv4": {"ip": "203.0.113.5"},
                                 "ipv6": {"ip": "2001:db8::/64"},
                                 "firewalls": [{"id": 3, "status": "applied"}]}},),
        firewalls=({"id": 3, "name": firewall_name, "rules": list(rules),
                    "applied_to": [{"type": "server", "server": {"id": 7}}]},))
    hetzner.store_snapshot(con, snapshot)


def test_the_provider_view_is_the_hosts_own_workspaces_and_never_anothers(con):
    """A customer's cloud firewall is read with their token and stored under
    their workspace (record 4.178). A host in workspace 1 gets nothing from a
    snapshot workspace 2 read, even one naming a server with its hostname."""
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'two', '2026-09-14T00:00:00+00:00')")
    con.commit()
    mine, _ = store.add_host(con, "almabox")
    theirs, _ = store.add_host(con, "almabox-two", workspace_id=2)
    report(con, mine, document(sockets=[socket_row(22)]))
    report(con, theirs, document(sockets=[socket_row(22)]))
    hetzner.init(con)
    snapshot = hetzner.Snapshot(
        fetched_at="2026-09-14T11:00:00+00:00",
        servers=({"id": 7, "name": "almabox", "status": "running",
                  "public_net": {"ipv4": {"ip": "203.0.113.5"}, "ipv6": {"ip": "2001:db8::/64"},
                                 "firewalls": [{"id": 3, "status": "applied"}]}},),
        firewalls=({"id": 3, "name": "fw-1", "rules": [],
                    "applied_to": [{"type": "server", "server": {"id": 7}}]},))
    hetzner.store_snapshot(con, snapshot, workspace_id=2)
    one = finding_for(join.host_findings(con, mine), "tcp", 22, "v4")
    assert one.provider.configured is False
    assert join.NOTE_PROVIDER_ABSENT in one.cause.notes
    two = finding_for(join.host_findings(con, theirs), "tcp", 22, "v4")
    assert two.provider.configured is True


def test_the_provider_view_says_absent_rather_than_guessing(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.configured is False
    assert finding.provider.matched is False
    assert join.NOTE_PROVIDER_ABSENT in finding.cause.notes


def test_a_provider_rule_permitting_a_port_nothing_serves_is_a_stale_rule(con):
    """The provider's own spec calls `source_ips` the "List of permitted
    IPv4/IPv6 addresses for incoming traffic", so an inbound rule is a permit
    in the provider's own words. Nothing here concludes that the absence of a
    rule blocks anything, because no source was read for that."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    hetzner_snapshot(con, rules=[
        {"direction": "in", "protocol": "tcp", "port": "8443",
         "description": "old dashboard", "source_ips": ["0.0.0.0/0"],
         "destination_ips": []}])

    finding = finding_for(join.host_findings(con, host_id), "tcp", 8443, "v4")
    assert finding.state == join.STATE_STALE_RULE
    assert finding.cause.layer == join.LAYER_PROVIDER
    assert "8443" in finding.cause.quotes[0].text
    assert finding.cause.quotes[0].source == "hetzner firewall fw-1"


def test_a_provider_rule_with_no_v6_source_says_nothing_about_v6(con):
    """PRODUCT.md 4b: one flat list carries both families and a rule with
    `0.0.0.0/0` and no `::/0` says nothing at all about IPv6."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[]))
    hetzner_snapshot(con, rules=[
        {"direction": "in", "protocol": "tcp", "port": "8443",
         "description": None, "source_ips": ["0.0.0.0/0"], "destination_ips": []}])

    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 8443, "v4").state == join.STATE_STALE_RULE
    assert find(result, "tcp", 8443, "v6") is None


def test_a_v4_only_provider_rule_is_absent_from_the_v6_view(con):
    """Written after a mutation survived.

    The family split is enforced in two places, the enumeration and the view,
    and the test above reached only the enumeration one: with no v6 entry the
    port was never proposed for v6, so a view that answered for v6 anyway was
    invisible. Here the v6 finding exists because something is listening on it,
    so the view is asked directly.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[
        socket_row(8443, family="v4"),
        socket_row(8443, family="v6", bind_address="2001:db8::1")]))
    hetzner_snapshot(con, rules=[
        {"direction": "in", "protocol": "tcp", "port": "8443",
         "description": None, "source_ips": ["0.0.0.0/0"], "destination_ips": []}])

    result = join.host_findings(con, host_id)
    assert len(finding_for(result, "tcp", 8443, "v4").provider.rules) == 1
    assert finding_for(result, "tcp", 8443, "v6").provider.rules == ()


def test_a_pending_provider_firewall_is_not_a_permit(con):
    """Written after a mutation survived. Nothing tested `pending` at all.

    The spec's own values for a server's attached firewall are `applied` and
    `pending`, and `app/hetzner.py` keeps them apart rather than reading both
    as "has a firewall". A pending rule has not landed, so quoting it as a
    permit would be quoting something that is not in force.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(9443)]))
    hetzner.init(con)
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at="2026-08-16T11:00:00+00:00",
        servers=({"id": 7, "name": "almabox", "status": "running",
                  "public_net": {"ipv4": {"ip": "203.0.113.5"},
                                 "ipv6": {"ip": "2001:db8::/64"},
                                 "firewalls": [{"id": 3, "status": "pending"}]}},),
        firewalls=({"id": 3, "name": "fw-pending",
                    "rules": [{"direction": "in", "protocol": "tcp",
                               "port": "9443", "description": None,
                               "source_ips": ["0.0.0.0/0"], "destination_ips": []}],
                    "applied_to": [{"type": "server", "server": {"id": 7}}]},)))

    finding = finding_for(join.host_findings(con, host_id), "tcp", 9443, "v4")
    assert finding.provider.rules == ()
    assert join.NOTE_PROVIDER_FIREWALL_PENDING in finding.cause.notes


def test_a_pending_provider_firewall_never_raises_a_port_on_its_own(con):
    """The other half of the same guard, in the enumeration rather than the
    view. A port nothing serves and only a pending rule names is not a
    finding."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[]))
    hetzner.init(con)
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at="2026-08-16T11:00:00+00:00",
        servers=({"id": 7, "name": "almabox", "status": "running",
                  "public_net": {"ipv4": {"ip": "203.0.113.5"},
                                 "ipv6": {"ip": "2001:db8::/64"},
                                 "firewalls": [{"id": 3, "status": "pending"}]}},),
        firewalls=({"id": 3, "name": "fw-pending",
                    "rules": [{"direction": "in", "protocol": "tcp",
                               "port": "9443", "description": None,
                               "source_ips": ["0.0.0.0/0"], "destination_ips": []}],
                    "applied_to": [{"type": "server", "server": {"id": 7}}]},)))
    assert find(join.host_findings(con, host_id), "tcp", 9443, "v4") is None


def test_an_outbound_provider_rule_is_not_an_inbound_permit(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[]))
    hetzner_snapshot(con, rules=[
        {"direction": "out", "protocol": "tcp", "port": "8443",
         "description": None, "source_ips": [], "destination_ips": ["0.0.0.0/0"]}])
    assert find(join.host_findings(con, host_id), "tcp", 8443, "v4") is None


def test_a_provider_port_range_covers_the_ports_inside_it(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(2000, protocol="tcp")]))
    hetzner_snapshot(con, rules=[
        {"direction": "in", "protocol": "tcp", "port": "1024-5000",
         "description": None, "source_ips": ["0.0.0.0/0"], "destination_ips": []}])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 2000, "v4")
    assert finding.provider.matched is True
    assert len(finding.provider.rules) == 1
    assert join.NOTE_PROVIDER_RANGE_NOT_ENUMERATED in finding.cause.notes


def test_the_provider_server_matches_the_hostname_ignoring_case(con):
    """The production fleet's own documents carry `Almabox` while the control
    plane knows the host as `almabox`, so an exactly case-sensitive match
    would miss the one host the provider view is most likely to hold. Case is
    the only thing relaxed. Everything else is an exact match, because a fuzzy
    one here attaches somebody else's firewall to this host."""
    host_id = add_host(con, "almabox")
    report(con, host_id, document(hostname="Almabox", sockets=[socket_row(22)]))
    hetzner_snapshot(con, server_name="almabox")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.matched is True
    assert finding.provider.server_name == "almabox"


def test_a_provider_snapshot_with_no_matching_server_says_so(con):
    host_id = add_host(con, "almabox")
    report(con, host_id, document(hostname="almabox", sockets=[socket_row(22)]))
    hetzner_snapshot(con, server_name="somebody-elses-box")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.configured is True
    assert finding.provider.matched is False
    assert join.NOTE_PROVIDER_NO_MATCH in finding.cause.notes


def test_a_malformed_provider_snapshot_does_not_take_the_findings_down(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    hetzner.init(con)
    con.execute("INSERT INTO provider_snapshots (provider, fetched_at,"
                " servers_json, firewalls_json) VALUES (?, ?, ?, ?)",
                ("hetzner", "2026-08-16T11:00:00+00:00", '[{"id": "seven"}]', "[]"))
    con.commit()
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.matched is False
    assert join.NOTE_PROVIDER_UNREADABLE in finding.cause.notes


# ------------------------------------ one token per project (docs/RECORD.md 4.206)

def _project(con, token, *, server_id, server_name, ipv4, firewall_id=3,
             firewall_name="fw-1", rules=()):
    """One Hetzner project as a workspace holds it since 2026-09-27: the token
    that reads it and the snapshot that token read. Two of these are two
    projects, each with its own server, firewall and ids."""
    hetzner.init(con)
    token_id, _hint = hetzner.add_token(con, token, workspace_id=1)
    hetzner.store_snapshot(con, hetzner.Snapshot(
        fetched_at="2026-09-29T11:00:00+00:00",
        servers=({"id": server_id, "name": server_name, "status": "running",
                  "public_net": {"ipv4": {"ip": ipv4}, "ipv6": {"ip": None},
                                 "firewalls": [{"id": firewall_id, "status": "applied"}]}},),
        firewalls=({"id": firewall_id, "name": firewall_name, "rules": list(rules),
                    "applied_to": [{"type": "server", "server": {"id": server_id}}]},)),
        workspace_id=1, token_id=token_id)
    return token_id


ALLOW_8443 = {"direction": "in", "protocol": "tcp", "port": "8443", "description": "",
              "source_ips": ["0.0.0.0/0"], "destination_ips": []}


def test_a_host_in_the_second_project_is_found_there(con):
    """The engine read the first token's snapshot only, so a server in the
    second project was "no matching server" however plainly it was listed."""
    host_id = add_host(con, "mattermost")
    report(con, host_id, document(hostname="mattermost", sockets=[socket_row(22)]))
    _project(con, "first-project-token-aaaa", server_id=1, server_name="student-net",
             ipv4="203.0.113.10", firewall_name="fw-acme")
    _project(con, "second-project-token-bbbb", server_id=9, server_name="mattermost",
             ipv4="203.0.113.20", firewall_name="fw-mattermost", rules=[ALLOW_8443])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 8443, "v4")
    assert finding.provider.matched is True
    assert finding.provider.server_name == "mattermost"
    assert finding.cause.layer == join.LAYER_PROVIDER
    assert finding.cause.quotes[0].source == "hetzner firewall fw-mattermost"


def test_a_servers_firewall_is_read_in_the_project_that_listed_it(con):
    """Firewall ids are the provider's per project, so two projects can each
    have a firewall 3. The server's own project's firewall 3 is the one that
    applies, never the first project's."""
    host_id = add_host(con, "mattermost")
    report(con, host_id, document(hostname="mattermost", sockets=[socket_row(22)]))
    _project(con, "first-project-token-aaaa", server_id=1, server_name="student-net",
             ipv4="203.0.113.10", firewall_id=3, firewall_name="fw-acme",
             rules=[ALLOW_8443])
    _project(con, "second-project-token-bbbb", server_id=9, server_name="mattermost",
             ipv4="203.0.113.20", firewall_id=3, firewall_name="fw-mattermost")
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 22, "v4").provider.server_name == "mattermost"
    # fw-mattermost has no rule, so nothing names 8443. The first project's
    # firewall 3 would, and a stale-rule row quoting fw-acme is that mistake.
    assert find(result, "tcp", 8443, "v4") is None


def test_a_host_matched_by_its_proof_in_one_project_outranks_a_name_in_another(con):
    host_id = add_host(con, "mattermost")
    report(con, host_id, document(hostname="mattermost", sockets=[socket_row(22)]))
    _project(con, "first-project-token-aaaa", server_id=1, server_name="mattermost",
             ipv4="203.0.113.10")
    _project(con, "second-project-token-bbbb", server_id=9, server_name="ubuntu-4gb-hel1-1",
             ipv4="203.0.113.20")
    _prove(con, host_id, "203.0.113.20", "v4")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.server_name == "ubuntu-4gb-hel1-1"


def test_one_name_in_two_projects_is_no_match(con):
    """The rule `hetzner.match_in_projects` holds: one machine cannot be two
    servers, and the order of the tokens does not break the tie."""
    host_id = add_host(con, "web")
    report(con, host_id, document(hostname="web", sockets=[socket_row(22)]))
    _project(con, "first-project-token-aaaa", server_id=1, server_name="web",
             ipv4="203.0.113.10")
    _project(con, "second-project-token-bbbb", server_id=9, server_name="web",
             ipv4="203.0.113.20")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.configured is True
    assert finding.provider.matched is False
    assert join.NOTE_PROVIDER_NO_MATCH in finding.cause.notes


def test_an_unreadable_project_is_not_read_as_a_project_without_the_host(con):
    """A snapshot that cannot be parsed might hold the host, so a host no
    readable project lists says unreadable, not no matching server. A host a
    readable project does list is found there all the same."""
    here = add_host(con, "mattermost")
    lost = add_host(con, "elsewhere")
    report(con, here, document(hostname="mattermost", sockets=[socket_row(22)]))
    report(con, lost, document(hostname="elsewhere", sockets=[socket_row(22)]))
    broken = _project(con, "first-project-token-aaaa", server_id=1,
                      server_name="student-net", ipv4="203.0.113.10")
    con.execute("UPDATE provider_snapshots SET servers_json = ? WHERE token_id = ?",
                ('[{"id": "seven"}]', broken))
    con.commit()
    _project(con, "second-project-token-bbbb", server_id=9, server_name="mattermost",
             ipv4="203.0.113.20")
    found = finding_for(join.host_findings(con, here), "tcp", 22, "v4")
    assert found.provider.matched is True
    missing = finding_for(join.host_findings(con, lost), "tcp", 22, "v4")
    assert missing.provider.matched is False
    assert join.NOTE_PROVIDER_UNREADABLE in missing.cause.notes
    assert join.NOTE_PROVIDER_NO_MATCH not in missing.cause.notes


# --------------------------------------------------------------- the timestamps

def test_a_probe_run_older_than_the_document_is_flagged(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]),
           received_at="2026-08-16T12:00:00+00:00")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")],
              started_at="2026-08-16T09:00:00+00:00",
              finished_at="2026-08-16T09:00:05+00:00")

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.outside.precedes_document is True
    assert join.NOTE_OUTSIDE_PRECEDES_DOCUMENT in finding.cause.notes
    assert finding.state == join.STATE_UNREVIEWED


def test_a_probe_run_newer_than_the_document_is_not_flagged(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]),
           received_at="2026-08-16T09:00:00+00:00")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")],
              started_at="2026-08-16T12:00:00+00:00",
              finished_at="2026-08-16T12:00:05+00:00")

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.outside.precedes_document is False
    assert join.NOTE_OUTSIDE_PRECEDES_DOCUMENT not in finding.cause.notes


def test_an_unparseable_probe_timestamp_is_named_rather_than_assumed(con):
    """`docs/RECORD.md` 4.51: a `last_report_at` that could not be parsed used
    to fall back to another column, which put a number nobody observed into a
    sentence. Unmeasurable is its own answer."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]),
           received_at="2026-08-16T12:00:00+00:00")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")],
              started_at="whenever", finished_at="whenever")

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.outside.precedes_document is None
    assert join.NOTE_OUTSIDE_AGE_UNREADABLE in finding.cause.notes


def test_the_newest_measurement_for_an_address_wins_across_runs(con):
    """One address, one port, two runs. The newer run's answer wins, which used
    to be true because the engine read only the newest run and is now true
    because it reads the newest measurement per port. The assertion is the same,
    the mechanism underneath it changed, and the tests below pin the mechanism."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_REFUSED, None, "203.0.113.5")],
              started_at="2026-08-16T09:00:00+00:00")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")],
              started_at="2026-08-16T12:00:00+00:00")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.outside.state == prober.STATE_CONNECTED


# ------------------------------------------------- the engine reads every run
#
# Two probing lanes are planned (`docs/PRODUCT.md` section 5): a fast lane over
# the joined port set, and a broad sweep of ports nothing reports, each stored
# as its own run over its own port set. The engine reads the newest measurement
# per (family, port) across every run, so a port only one lane covers stays
# visible instead of vanishing the moment the other lane's run is newer. These
# tests are that promise, and the first is the bug the whole card names.

OLDER = "2026-08-16T09:00:00+00:00"
NEWER = "2026-08-16T12:00:00+00:00"
ADDR_A = "203.0.113.5"
ADDR_B = "203.0.113.6"


def test_a_port_only_an_older_run_measured_is_still_read(con):
    """The original bug. A broad sweep (older run) measures a port nothing
    reports, and a fast lane (newer run) measures a different set. Reading only
    the newest run made the swept port read `not tested` and drop off the list
    entirely, because nothing in the document raises it either. Reading across
    runs keeps its measurement. This test cannot pass on the single-run read:
    there is no finding for 9100 at all under it, so `finding_for` raises."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    # The broad sweep, older, over a port the document never mentions.
    probe_run(con, host_id, [("v4", 9100, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=OLDER, vantage="sweep")
    # The fast lane, newer, over the joined set, which does not include 9100.
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=NEWER, vantage="fast")

    result = join.host_findings(con, host_id)
    swept = finding_for(result, "tcp", 9100, "v4")
    assert swept.outside.state == prober.STATE_CONNECTED
    # Reachable and nothing on the host owns it: the exact "what is open that I
    # do not know about" case the broad sweep exists to find (8a).
    assert swept.state == join.STATE_UNEXPLAINED
    # Its provenance is the run that measured it, not the newest run.
    assert swept.outside.vantage == "sweep"
    assert swept.outside.measured_at == OLDER
    # And the fast lane's port is here too, from its own run.
    fast = finding_for(result, "tcp", 22, "v4")
    assert fast.outside.state == prober.STATE_CONNECTED
    assert fast.outside.vantage == "fast"


def test_a_port_in_both_runs_takes_the_newer_measurement_by_time(con):
    """A port both lanes cover shows whichever was measured last, decided by
    `measured_at` and not by which state ranks higher. The older run connected
    and the newer was refused, so the answer is refused: the port stopped
    answering. A read that let a connect always win would report it reachable."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443)]))
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=OLDER)
    probe_run(con, host_id, [("v4", 443, prober.STATE_REFUSED, None, ADDR_A)],
              started_at=NEWER)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert finding.outside.state == prober.STATE_REFUSED
    assert finding.outside.measured_at == NEWER


def test_a_port_no_run_measured_is_not_tested_and_borrows_nothing(con):
    """A (family, port) absent from every run stays `not tested` and gets no
    state, even when other ports on the same host were measured. That is
    `docs/PRODUCT.md` 4b's not-tested rule: no port borrows a neighbour's
    answer."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22), socket_row(8080)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=NEWER)

    finding = finding_for(join.host_findings(con, host_id), "tcp", 8080, "v4")
    assert finding.outside.state == prober.STATE_NOT_TESTED
    assert finding.outside.reason == join.REASON_NOT_PROBED
    assert finding.state is None
    assert join.NOTE_OUTSIDE_NOT_MEASURED in finding.cause.notes


def test_a_connect_on_one_address_outlives_a_later_silence_on_another(con):
    """The family merge, now across runs. A completed connect on any address is
    a completed connect for the family (8a), because the question is whether the
    internet reached this host on this port. An older run connected on one
    address, a newer run measured a second address as silent, and the connect
    stands: the two addresses answer for themselves, and one falling silent does
    not undo the other. Both addresses are named."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=OLDER)
    probe_run(con, host_id,
              [("v4", 22, prober.STATE_NO_RESPONSE, "timeout", ADDR_B)],
              started_at=NEWER)

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.outside.state == prober.STATE_CONNECTED
    assert finding.state == join.STATE_UNREVIEWED
    assert set(finding.outside.targets) == {ADDR_A, ADDR_B}


def test_an_address_own_later_silence_supersedes_its_earlier_connect(con):
    """The other half of the merge, and the reason it is decided per address by
    `measured_at`. The SAME address connected in an older run and was silent in
    a newer one, so its own newer measurement wins and the family is silent. A
    measured silence on a listening port earns a state, `not reachable` with
    no declaration (`docs/RECORD.md` 4.55 and 4.112)."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=OLDER)
    probe_run(con, host_id,
              [("v4", 22, prober.STATE_NO_RESPONSE, "timeout", ADDR_A)],
              started_at=NEWER)

    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.outside.state == prober.STATE_NO_RESPONSE
    assert finding.state == join.STATE_NOT_REACHABLE


def test_each_port_names_the_run_and_vantage_that_measured_it(con):
    """Provenance is per port, not per host. `HostFindings` no longer carries a
    single run, because two lanes can each own some of a host's ports. Each
    port's outside view names the run and vantage that took its own newest
    measurement, so two ports on one host can name two different runs."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22), socket_row(9100)]))
    old_run = probe_run(
        con, host_id, [("v4", 9100, prober.STATE_CONNECTED, None, ADDR_A)],
        started_at=OLDER, vantage="sweep")
    new_run = probe_run(
        con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
        started_at=NEWER, vantage="fast")

    result = join.host_findings(con, host_id)
    swept = finding_for(result, "tcp", 9100, "v4")
    fast = finding_for(result, "tcp", 22, "v4")
    assert swept.outside.run_id == old_run
    assert swept.outside.vantage == "sweep"
    assert fast.outside.run_id == new_run
    assert fast.outside.vantage == "fast"


def test_two_lanes_reach_the_states_the_rules_prescribe(con):
    """A fuller two-lane scene, each port landing on the state 8a and 8b give
    it. A declaration turns a reachable owned port into `conflict` or
    `intended`, a reachable unowned port is `unexplained`, an owned port nobody
    measured has no state, and every answer is drawn from whichever run measured
    that port last."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[
        socket_row(22), socket_row(443), socket_row(8080)]))
    # Broad sweep, older: an unowned reachable port and a port the fast lane
    # will re-measure.
    probe_run(con, host_id, [
        ("v4", 9100, prober.STATE_CONNECTED, None, ADDR_A),
        ("v4", 443, prober.STATE_CONNECTED, None, ADDR_A)],
        started_at=OLDER, vantage="sweep")
    # Fast lane, newer: the joined set. 443 is re-measured, 8080 is not covered
    # by either lane on the wire (listening but never probed).
    probe_run(con, host_id, [
        ("v4", 22, prober.STATE_CONNECTED, None, ADDR_A),
        ("v4", 443, prober.STATE_CONNECTED, None, ADDR_A)],
        started_at=NEWER, vantage="fast")

    result = join.host_findings(
        con, host_id, intent={("tcp", 443, "v4"): join.INTENT_CLOSED})
    # Owned, reachable, no declaration: unreviewed.
    assert finding_for(result, "tcp", 22, "v4").state == join.STATE_UNREVIEWED
    # Owned, reachable, declared closed: conflict.
    assert finding_for(result, "tcp", 443, "v4").state == join.STATE_CONFLICT
    # Reachable, nothing owns it: unexplained, and it only exists because the
    # older run is still read.
    assert finding_for(result, "tcp", 9100, "v4").state == join.STATE_UNEXPLAINED
    # Owned but measured by nobody: not tested, no state.
    eight = finding_for(result, "tcp", 8080, "v4")
    assert eight.outside.state == prober.STATE_NOT_TESTED
    assert eight.state is None


# ------------------------------------------------------------ the hostile cases

def test_a_document_with_no_sockets_at_all(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[]))
    result = join.host_findings(con, host_id)
    assert result.findings == ()
    assert result.document_readable is True


def test_a_malformed_document_is_reported_not_raised(con):
    host_id = add_host(con)
    store.insert_report(con, host_id, 0, 1, "{not json")
    result = join.host_findings(con, host_id)
    assert result.document_readable is False
    assert result.findings == ()


@pytest.mark.parametrize("body", ["[]", '"a string"', "null", "123",
                                  '{"sockets": "not a dict"}',
                                  '{"sockets": {"listening": [null, 3, {}]}}',
                                  '{"nftables": {"tables": [{"chains": "no"}]}}'])
def test_a_document_shaped_wrong_does_not_raise(con, body):
    host_id = add_host(con)
    store.insert_report(con, host_id, 0, 1, body)
    result = join.host_findings(con, host_id)
    assert isinstance(result.findings, tuple)


def test_a_host_that_never_reported(con):
    host_id = add_host(con)
    result = join.host_findings(con, host_id)
    assert result.document_readable is False
    assert result.findings == ()
    assert result.received_at is None


def test_a_revoked_host_is_flagged_on_its_findings(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    store.revoke_host(con, "almabox")
    result = join.host_findings(con, host_id)
    assert result.revoked_at is not None
    finding = finding_for(result, "tcp", 22, "v4")
    assert join.NOTE_HOST_REVOKED in finding.cause.notes


def test_an_unknown_host_id_is_none(con):
    assert join.host_findings(con, 4242) is None


def test_an_empty_database_yields_nothing(tmp_path):
    connection = db.connect(str(tmp_path / "empty.db"))
    db.init(connection)
    assert join.fleet_findings(connection) == []
    connection.close()


def test_missing_probe_tables_read_as_not_tested_not_as_an_error(tmp_path):
    """The production database on 2026-08-16 has no `probe_results` table at
    all, because nothing has run the prober yet. The engine has to answer that
    with `not tested` and not with a traceback."""
    connection = db.connect(str(tmp_path / "noprobe.db"))
    db.init(connection)
    host_id, _ = store.add_host(connection, "almabox")
    store.insert_report(connection, host_id, 0, 1,
                        json.dumps(document(sockets=[socket_row(22)])))
    result = join.host_findings(connection, host_id)
    finding = finding_for(result, "tcp", 22, "v4")
    assert finding.outside.state == prober.STATE_NOT_TESTED
    assert finding.outside.reason == join.REASON_NOT_PROBED
    connection.close()


def test_fleet_findings_covers_every_host(con):
    first = add_host(con, "one")
    second = add_host(con, "two")
    report(con, first, document(hostname="one", sockets=[socket_row(22)]))
    report(con, second, document(hostname="two", sockets=[socket_row(443)]))
    names = [result.host_name for result in join.fleet_findings(con)]
    assert names == ["one", "two"]


# ---------------------------------------------------------------- the sentence

BANNED = ("secure", "protected", "safe", "compliant", "guaranteed", "certified",
          "vulnerable", "risk", "score", "grade")


def every_sentence(con):
    return [join.describe(finding)
            for result in join.fleet_findings(con)
            for finding in result.findings]


def test_no_sentence_uses_a_word_we_are_not_allowed_to_use(con):
    """The writing rules. The engine reports reachability and cause and then
    stops, and it does not explain that posture either."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 22 counter accept",
                        "ip protocol tcp tcp dport 80 counter accept"])]))
    probe_run(con, host_id, [
        ("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v4", 9000, prober.STATE_CONNECTED, None, "203.0.113.5")])

    sentences = every_sentence(con)
    assert sentences
    for sentence in sentences:
        lowered = sentence.lower()
        for word in BANNED:
            assert word not in lowered, f"{word!r} in {sentence!r}"


def test_no_sentence_uses_a_dash_or_a_semicolon(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))
    for sentence in every_sentence(con):
        assert "—" not in sentence and "–" not in sentence
        assert ";" not in sentence


def test_the_sentence_names_the_layer_and_quotes_the_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[], tables=[ufw_v4(["ip protocol tcp tcp dport 80 counter accept"])]))
    sentence = join.describe(
        finding_for(join.host_findings(con, host_id), "tcp", 80, "v4"))
    assert "host firewall" in sentence
    assert "ip protocol tcp tcp dport 80 counter accept" in sentence
    assert "ufw-user-input" in sentence


def test_the_sentence_says_not_tested_when_nothing_measured(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    sentence = join.describe(
        finding_for(join.host_findings(con, host_id), "tcp", 22, "v4"))
    assert "not tested" in sentence


# -------------------------------------------------- agreement with the site view

def test_this_engine_and_the_packet_path_agree_on_which_rules_name_a_port():
    """`site/app/packetpath.py` walks the same rules for the same screen. The
    two are separate implementations on either side of the control plane and
    the site boundary, and the one thing they may never do is disagree about
    whether a rule names a port. Loaded by path rather than imported, so
    nothing in `app/` depends on the site."""
    packetpath = _load_packetpath()
    if packetpath is None:
        pytest.skip("site/app/packetpath.py is not in this checkout")

    texts = [
        "ip protocol tcp tcp dport 22 counter accept",
        "meta l4proto tcp tcp dport 8096 accept",
        "ip protocol tcp tcp dport 22 [xt match comment] counter accept",
        ("ip protocol tcp tcp dport 22 [xt match conntrack] [xt match recent]"
         " counter jump ufw-user-limit"),
        ("meta nfproto ipv4 @nh,96,16 0x0a58 meta l4proto tcp tcp dport 8096"
         " jump NETAVARK-HOSTPORT-SETMARK"),
        "meta nfproto ipv4 @nh,96,16 0x0a58 [lookup @__set0] th dport 53 accept",
        "ip daddr 239.255.255.250 ip protocol udp udp dport 1900 counter accept",
        "meta l4proto udp udp dport 137 [expr Objref]",
        "ct status & 0x20000000 != 0x00000000 accept",
        "iifname \"lo\" accept",
        "tcp dport != 22 accept",
        "tcp dport >= 1024 accept",
        "meta l4proto tcp tcp dport & 0xff == 0x16 accept",
        "@th,0,32 0x16 accept",
        "meta nfproto ipv6 @nh,192,64 0x20010db8 accept",
        "",
    ]
    for text in texts:
        for rendered in ("full", "partial"):
            for protocol, port in (("tcp", 22), ("udp", 137), ("tcp", 8096)):
                mine = join.classify_rule(text, rendered, protocol, port)
                theirs = packetpath.classify_rule(text, rendered, protocol, port)
                assert mine == theirs, (text, rendered, protocol, port, mine, theirs)


def module_level_names(path):
    """Every name this module assigns at module level, from its source.

    Read from the source rather than from `vars()` so that what both modules
    happen to import cannot pad the comparison. What is being asked is which
    facts each module *states*, not which objects it can see.
    """
    import ast
    import pathlib
    tree = ast.parse(pathlib.Path(path).read_text())
    names = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            names.add(node.target.id)
    return names


def comparable(value):
    """A value in a form two modules can be compared on.

    A compiled pattern compares by identity, so two identical regexes in two
    files are never equal until they are reduced to what they actually say.
    """
    import re as _re
    if isinstance(value, _re.Pattern):
        return ("regex", value.pattern, value.flags)
    return value


# The facts that live on both sides of the boundary, and may never drift.
#
# `site/app/packetpath.py` and this engine are separate implementations of the
# same reading of a ruleset, because the site cannot import the control plane
# except through `site/app/joinbridge.py`. That duplication is deliberate and
# it is also the shape that has now produced two defects: the plain chain names
# nearly shipped twice (RECORD 4.82, caught by a test) and loopback did ship
# twice and disagreed with itself on two of the three hosts in the fleet
# (RECORD 4.85, caught by reading a real page).
#
# Only `classify_rule` was covered. Fourteen constants and six more functions
# were not, including the hook order, the four verdict words, every regex that
# decides what a rule says, and the 160 bit bound on where a port can hide.
#
# The shared set is discovered rather than listed, so a constant copied across
# tomorrow is covered the day it appears rather than the day someone remembers
# to add it here.
def test_every_shared_constant_says_the_same_thing_on_both_sides():
    packetpath = _load_packetpath()
    if packetpath is None:
        pytest.skip("site/app/packetpath.py is not in this checkout")
    import pathlib
    here = pathlib.Path(__file__).resolve()
    site = next(p / "site" / "app" / "packetpath.py" for p in here.parents
                if (p / "site" / "app" / "packetpath.py").exists())
    cp = next(p / "controlplane" / "app" / "join.py" for p in here.parents
              if (p / "controlplane" / "app" / "join.py").exists())

    shared = sorted(module_level_names(site) & module_level_names(cp))
    shared = [n for n in shared
              if not callable(getattr(join, n, None))
              and not callable(getattr(packetpath, n, None))]
    # A vacuous pass is the failure mode of a discovered set. If the two
    # modules stop sharing anything this test has stopped testing, and that is
    # itself a change somebody should have to look at.
    assert len(shared) >= 12, f"only {len(shared)} shared constants found: {shared}"

    for name in shared:
        mine = comparable(getattr(join, name))
        theirs = comparable(getattr(packetpath, name))
        assert mine == theirs, (
            f"{name} says {mine!r} in the engine and {theirs!r} on the site. "
            "One fact, two spellings, and nothing else would have noticed.")


def test_the_two_sides_agree_on_where_a_port_can_hide():
    """`_raw_load_can_hide_a_port` is the trickiest reasoning either module
    does: a load from the network header that ends inside the fixed header
    cannot reach a transport port, and the bound is 160 bits because an `inet`
    table sees both families and neither module may infer one from the other.

    Getting this wrong in one place only would put a rule that does select a
    port into the pile the reader is told to ignore, on one screen and not the
    other."""
    packetpath = _load_packetpath()
    if packetpath is None:
        pytest.skip("site/app/packetpath.py is not in this checkout")
    for base in ("th", "nh", "ll"):
        for offset in (0, 32, 96, 128, 144, 159, 160, 161, 192, 320):
            for length in (8, 16, 32, 64):
                mine = join._raw_load_can_hide_a_port(base, offset, length)
                theirs = packetpath._raw_load_can_hide_a_port(base, offset, length)
                assert mine == theirs, (base, offset, length, mine, theirs)


def test_the_two_sides_agree_on_which_dport_comparisons_select_a_port():
    """The operator table under `dport`. A rule matching `dport >= 1024` selects
    22 on neither side or on both."""
    packetpath = _load_packetpath()
    if packetpath is None:
        pytest.skip("site/app/packetpath.py is not in this checkout")
    for op in (None, "", "!=", ">=", "<=", ">", "<"):
        for value in (0, 21, 22, 23, 1024, 65535):
            for port in (22, 1024, 8096):
                mine = join._dport_selects(op, value, port)
                theirs = packetpath._dport_selects(op, value, port)
                assert mine == theirs, (op, value, port, mine, theirs)


def test_the_two_sides_agree_on_what_is_unreadable_in_a_rule():
    packetpath = _load_packetpath()
    if packetpath is None:
        pytest.skip("site/app/packetpath.py is not in this checkout")
    texts = ["ip protocol tcp tcp dport 22 accept", "@th,0,32 0x16 accept",
             "meta nfproto ipv4 @nh,96,16 0x0a58 accept",
             "meta nfproto ipv6 @nh,192,64 0x20010db8 accept",
             "@ll,0,48 0x001122334455 accept", "", "iifname \"lo\" accept"]
    for text in texts:
        assert join._has_unreadable_payload(text) == \
            packetpath._has_unreadable_payload(text), text


def _load_packetpath():
    import importlib.util
    import pathlib
    here = pathlib.Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "site" / "app" / "packetpath.py"
        if candidate.exists():
            spec = importlib.util.spec_from_file_location("packetpath_site", candidate)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            return module
    return None


# --------------------- a silent port earns a state, decided by the owner 2026-08-16
#
# RECORD 4.55. A port listening inside that the outside view MEASURED as silent
# gets the same three rules as one that answered: declared closed is `intended`,
# declared open is `conflict`, nothing declared is `unreviewed`. Reality
# inverted, not a sixth word.
#
# The distinction that carries all of it: **measured silent is not the same as
# not tested.** Nothing tried still yields no state, because there is nothing to
# compare a declaration against, and that half of the old branch stays.

_silent_seq = iter(range(1, 99))


def _silent(con, declared=None, outside=None, sockets_status="collected"):
    """One host listening on tcp/443 v4, with the outside view as given. Each
    call gets its own host so a test can compare several declarations."""
    host_id = add_host(con, f"box{next(_silent_seq)}")
    report(con, host_id, document(sockets=[socket_row(443)],
                                  sockets_status=sockets_status))
    if outside is not None:
        probe_run(con, host_id, [("v4", 443, outside, None, "203.0.113.5")])
    intents = {("tcp", 443, "v4"): declared} if declared else {}
    result = join.host_findings(con, host_id, intent=intents)
    return finding_for(result, "tcp", 443, "v4")


def test_measured_silent_with_nothing_declared_is_not_reachable(con):
    """It was `unreviewed` until 2026-08-28 and that was one word for two
    opposite facts (RECORD 4.112). `unreviewed` is the queue of ports the
    internet reached that nobody has ruled on. A port that is shut and
    undeclared is not in that queue, and the pair below is the whole point:
    the same undeclared port reads differently depending on what was
    measured, which is what makes the word worth reading."""
    finding = _silent(con, outside=prober.STATE_NO_RESPONSE)
    assert finding.outside.state == prober.STATE_NO_RESPONSE
    assert finding.state == join.STATE_NOT_REACHABLE

    answered = _silent(con, outside=prober.STATE_CONNECTED)
    assert answered.state == join.STATE_UNREVIEWED


def test_measured_silent_and_declared_closed_is_intended(con):
    """The operator meant it shut and it is. The row that should stop
    bothering anybody."""
    assert _silent(con, declared=join.INTENT_CLOSED,
                   outside=prober.STATE_NO_RESPONSE).state == join.STATE_INTENDED


def test_measured_silent_and_declared_open_is_a_conflict(con):
    """The finding worth a mail. You said this port should be open, the host is
    listening on it, and nothing reaches it. Something between the two is
    dropping the packet."""
    assert _silent(con, declared=join.INTENT_OPEN,
                   outside=prober.STATE_NO_RESPONSE).state == join.STATE_CONFLICT


def test_a_refused_connect_is_measured_too_and_earns_the_same_states(con):
    """`connect_refused` is a reset coming back, as much a measurement as a
    drop. The outside view keeps the two words apart and they earn the same
    state, because the state is intent against reality and both are reality."""
    assert _silent(con, declared=join.INTENT_OPEN,
                   outside=prober.STATE_REFUSED).state == join.STATE_CONFLICT


def test_not_tested_still_earns_no_state_at_all(con):
    """The half of the old branch that stays, and the most important test here.
    Nothing was measured, so there is nothing to compare a declaration against,
    and naming a state would state a finding nobody made. The accuracy rule.
    """
    finding = _silent(con, declared=join.INTENT_OPEN, outside=None)
    assert finding.outside.state == prober.STATE_NOT_TESTED
    assert finding.state is None, (
        "a port nobody probed was given a state, which states a finding nobody made")


def test_a_silent_port_never_names_the_service_as_the_layer_that_decided(con):
    """Found by mutation, and it is the "do not blame the wrong layer" card in
    miniature.

    The service is listening. Something between the internet and that socket
    dropped the packet, and the host document does not say what. Naming the
    service as the layer that decided would tell the operator to go and look at
    the one component that is demonstrably working, which is worse than saying
    nothing.

    Changing all four returns in that branch from `not determined` to `service`
    left every other test in the suite green, which is why this one exists.
    """
    for declared, expected in ((None, join.STATE_NOT_REACHABLE),
                               (join.INTENT_OPEN, join.STATE_CONFLICT),
                               (join.INTENT_CLOSED, join.STATE_INTENDED)):
        finding = _silent(con, declared=declared, outside=prober.STATE_NO_RESPONSE)
        assert finding.state == expected
        assert finding.cause.layer == join.LAYER_NOT_DETERMINED, (
            f"a silent port with intent {declared!r} blamed"
            f" {finding.cause.layer!r} for dropping the packet")
        # The listening socket is still quoted, because that it is listening is
        # the evidence the reader needs to see the disagreement at all.
        assert any(q.text for q in finding.cause.quotes), (
            "the evidence that the host owns the port went missing with the layer")


# ============================== a rate limit belongs to one family at a time
#
# `docs/RECORD.md` 4.79. An `inet` table is shown to both families, so a rule
# inside one that restricts itself to v4 has to be read from its own text or
# not at all. Every existing test here builds `ip` or `ip6` tables, where
# `_base_chains` does the filtering, so this shape had never been exercised.


def inet_with_limit_chains(rules):
    """A ufw-shaped ruleset in an `inet` table, which both families see.

    `table inet netavark` on almabox and firewalld's own tables are this
    shape, so it is not a hypothetical.
    """
    return table("inet", "filter", [
        chain("INPUT", [rule("counter jump ufw-user-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw-user-input", [rule(text, rendered=(
            "partial" if "[" in text else "full")) for text in rules]),
        chain("ufw-user-limit-accept", [rule("counter accept")]),
    ])


def both_families_listening(port=22):
    return [socket_row(port),
            socket_row(port, family="v6", bind_address="2001:db8::1")]


LIMIT_V4_IN_INET = ("meta nfproto ipv4 meta l4proto tcp tcp dport 22"
                    " [xt match hashlimit] counter jump ufw-user-limit-accept")
LIMIT_V6_IN_INET = ("meta nfproto ipv6 meta l4proto tcp tcp dport 22"
                    " [xt match hashlimit] counter jump ufw-user-limit-accept")
LIMIT_UNPINNED_IN_INET = ("meta l4proto tcp tcp dport 22 [xt match hashlimit]"
                          " counter jump ufw-user-limit-accept")


def test_a_v4_limit_in_an_inet_table_is_not_read_onto_the_v6_finding(con):
    """The defect this section exists for, measured on 2026-08-21 before the
    fix: both families read one hashlimit, and the rule's own text says v4."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=both_families_listening(),
                                  tables=[inet_with_limit_chains([LIMIT_V4_IN_INET])]))
    result = join.host_findings(con, host_id)
    assert limit_modules(finding_for(result, "tcp", 22, "v4")) == ["hashlimit"]
    assert finding_for(result, "tcp", 22, "v6").inside.rate_limit_rules == ()


def test_a_v6_limit_in_an_inet_table_is_not_read_onto_the_v4_finding(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=both_families_listening(),
                                  tables=[inet_with_limit_chains([LIMIT_V6_IN_INET])]))
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 22, "v4").inside.rate_limit_rules == ()
    assert limit_modules(finding_for(result, "tcp", 22, "v6")) == ["hashlimit"]


def test_a_limit_naming_no_family_still_counts_on_both(con):
    """The fix narrows and never widens. A rule in an `inet` table that pins
    itself to nothing applies to whatever the table carries, which is both."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=both_families_listening(),
        tables=[inet_with_limit_chains([LIMIT_UNPINNED_IN_INET])]))
    result = join.host_findings(con, host_id)
    assert limit_modules(finding_for(result, "tcp", 22, "v4")) == ["hashlimit"]
    assert limit_modules(finding_for(result, "tcp", 22, "v6")) == ["hashlimit"]


def test_the_note_follows_the_rule_and_not_the_port(con):
    """`_notes_for` keys off the same field, so the wrong answer was on screen
    as a note as well as in the data."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=both_families_listening(),
                                  tables=[inet_with_limit_chains([LIMIT_V4_IN_INET])]))
    result = join.host_findings(con, host_id)
    assert join.NOTE_RULE_LIMITS_THE_RATE in finding_for(
        result, "tcp", 22, "v4").cause.notes
    assert join.NOTE_RULE_LIMITS_THE_RATE not in finding_for(
        result, "tcp", 22, "v6").cause.notes


def test_a_payload_expression_pins_the_family_too(con):
    """`ip daddr` can only be evaluated against an IPv4 header, so it pins the
    rule exactly as `meta nfproto ipv4` does."""
    host_id = add_host(con)
    text = ("ip daddr 10.0.0.1 meta l4proto tcp tcp dport 22"
            " [xt match hashlimit] counter jump ufw-user-limit-accept")
    report(con, host_id, document(sockets=both_families_listening(),
                                  tables=[inet_with_limit_chains([text])]))
    result = join.host_findings(con, host_id)
    assert limit_modules(finding_for(result, "tcp", 22, "v4")) == ["hashlimit"]
    assert finding_for(result, "tcp", 22, "v6").inside.rate_limit_rules == ()


def test_ip6_is_not_read_as_ip(con):
    """`ip6 nexthdr` starts with the two letters `ip` and is not an `ip`
    expression. Reading it as one would pin every v6 rule to v4."""
    assert join._rule_family("ip6 nexthdr tcp tcp dport 22") == "v6"
    assert join._rule_family("ip protocol tcp tcp dport 22") == "v4"
    assert join._rule_family("meta l4proto tcp tcp dport 22") is None


def test_a_rule_naming_both_families_is_pinned_to_neither(con):
    """Not a shape nft writes, and the answer that claims less is still the
    right one: something we do not understand is not evidence about a family."""
    assert join._rule_family("meta nfproto ipv4 ip6 daddr 2001:db8::1") is None


def test_ufws_own_v4_limit_still_reads_on_v4(con):
    """The regression guard on the other side. ufw writes `ip protocol tcp` in
    an `ip` table, which pins to v4, and v4 is the family that table is read
    for, so nothing about the real fleet finding changes."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(22)],
        tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4)]))
    result = join.host_findings(con, host_id)
    assert limit_modules(finding_for(result, "tcp", 22, "v4")) == ["recent", "recent"]


# ------------------------------------------- a rule you wrote is your answer
#
# The owner, 2026-09-04, on sight of the Host Overview sketch (docs/PRODUCT.md
# 8d): a reachable port that an unconditional permit rule names is intended
# without anyone clicking, and the rule is the layer that decided.

def test_a_reachable_port_an_unconditional_rule_permits_is_intended_by_the_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443, process="caddy")],
        tables=[ufw_v4(["ip protocol tcp tcp dport 443 counter accept"])]))
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None, "203.0.113.5")])

    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert finding.state == join.STATE_INTENDED
    assert finding.intent is None, "nobody declared anything, the rule answered"
    assert finding.cause.layer == join.LAYER_HOST_FIREWALL
    # the socket is quoted as the owner and the rule as the answer
    assert any(q.layer == join.LAYER_SERVICE for q in finding.cause.quotes)
    assert any("tcp dport 443 counter accept" in q.text for q in finding.cause.quotes)
    assert "host firewall permits it" in join.describe(finding)


def test_a_narrowed_rule_is_not_an_answer(con):
    """8a's strict test: a permit scoped to a source is not a rule that says
    the internet may reach this port, so the port stays a question."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443)],
        tables=[ufw_v4(["ip saddr 10.0.0.0/8 ip protocol tcp tcp dport 443 counter accept"])]))
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.cause.layer == join.LAYER_SERVICE


def test_a_provider_rule_answers_too_and_is_the_layer_named(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 443 counter accept"])]))
    hetzner_snapshot(con, rules=[
        {"direction": "in", "protocol": "tcp", "port": "443",
         "description": "web", "source_ips": ["0.0.0.0/0"], "destination_ips": []}])
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert finding.state == join.STATE_INTENDED
    assert finding.cause.layer == join.LAYER_PROVIDER
    # both permits are quoted, the provider's first
    layers = [q.layer for q in finding.cause.quotes if q.layer != join.LAYER_SERVICE]
    assert layers == [join.LAYER_PROVIDER, join.LAYER_HOST_FIREWALL]


def test_a_declaration_of_closed_beats_the_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 443 counter accept"])]))
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None, "203.0.113.5")])
    result = join.host_findings(con, host_id, intent={("tcp", 443, "v4"): join.INTENT_CLOSED})
    assert finding_for(result, "tcp", 443, "v4").state == join.STATE_CONFLICT
    # and what the row would say under each answer reads the rule for none
    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert join.state_if_declared(finding, None) == join.STATE_INTENDED
    assert join.state_if_declared(finding, join.INTENT_CLOSED) == join.STATE_CONFLICT
    assert join.state_if_declared(finding, join.INTENT_OPEN) == join.STATE_INTENDED


def test_the_rule_answers_only_for_a_reachable_port(con):
    """A permitted port that measured silent is `not reachable`, as before:
    8b's inverted table is about what a person declared, and a rule is not a
    declaration of what should happen when the port is shut."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443)],
        tables=[ufw_v4(["ip protocol tcp tcp dport 443 counter accept"])]))
    probe_run(con, host_id, [("v4", 443, prober.STATE_NO_RESPONSE, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert finding.state == join.STATE_NOT_REACHABLE
    assert finding.cause.layer == join.LAYER_NOT_DETERMINED


def test_a_reachable_port_nothing_owns_stays_unexplained_whatever_the_rule_says(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[],
        tables=[ufw_v4(["ip protocol tcp tcp dport 8080 counter accept"])]))
    probe_run(con, host_id, [("v4", 8080, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 8080, "v4")
    assert finding.state == join.STATE_UNEXPLAINED


def test_a_rate_limited_permit_is_read_as_an_answer(con):
    """`ufw limit 22/tcp` permits the port through a jump to a chain that
    accepts, so the rule the agent renders on the port is a jump and never a
    bare accept. Until 2026-09-29 this test pinned that port as `unreviewed`
    and called the other reading a decision for the owner (docs/RECORD.md 4.144).
    He delegated it and it was taken (4.209, docs/PRODUCT.md 8d): a permit
    that names the port and jumps to a chain holding nothing but an
    unconditional accept counts as that accept. A server that opens ssh
    with `limit 22/tcp` reads `intended`, "your rule"."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)],
                                  tables=[ufw_v4_with_limit_chains(UFW_LIMIT_V4)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_INTENDED
    assert finding.cause.layer == join.LAYER_HOST_FIREWALL
    assert finding.rate_limited is True
    # Quoted as the host wrote it, the jump and all, never as the accept it
    # is read as.
    assert [quote.text for quote in finding.inside.permit_rules] == [UFW_LIMIT_V4[2]]
    assert UFW_LIMIT_V4[2] in [quote.text for quote in finding.cause.quotes]


# ------------------------------------- the condition on the jump itself
#
# Wave 3 of the test fleet, case 12, 2026-09-30 (docs/RECORD.md
# 4.213). firewalld 2.4.0, runtime only: the internal zone got source
# 192.0.2.0/24 and ports 38012 and 38013, a listener on 38013 and none on
# 38012. firewalld wrote `ip saddr 192.0.2.0/24 jump filter_IN_internal` in
# filter_INPUT_POLICIES and `tcp dport 38012 accept` in
# filter_IN_internal_allow. Expected: no row for 38012, "no rule" for 38013.
# Measured: 38012 a stale rule on both families, 38013 "your rule" on both.
#
# Those two rule texts are the round's. The family pin in front of the source
# match is what the agent writes for an `ip saddr` rule in an inet table,
# measured on 2026-10-02 (4.244). The chains around them are the shape, not a
# copy of that box.
ZONE_BY_SOURCE = "meta nfproto ipv4 ip saddr 192.0.2.0/24 jump filter_IN_internal"
ZONE_BY_INTERFACE = 'iifname "eno1" jump filter_IN_public'


def _firewalld_zones(policies, internal=(), public=()):
    return table("inet", "firewalld", [
        chain("filter_INPUT", [rule("ct state established,related accept"),
                               rule("jump filter_INPUT_POLICIES")],
              hook="input", priority=10, type_="filter", policy="accept"),
        chain("filter_INPUT_POLICIES", [rule(text) for text in policies]),
        chain("filter_IN_internal", [rule("jump filter_IN_internal_allow")]),
        chain("filter_IN_internal_allow", [rule(text) for text in internal]),
        chain("filter_IN_public", [rule("jump filter_IN_public_allow")]),
        chain("filter_IN_public_allow", [rule(text) for text in public]),
    ])


CASE_12 = dict(
    policies=[ZONE_BY_SOURCE, ZONE_BY_INTERFACE],
    internal=["meta l4proto tcp tcp dport 38012 accept",
              "meta l4proto tcp tcp dport 38013 accept"],
    public=["meta l4proto tcp tcp dport 8096 accept"])


def test_a_port_opened_only_in_a_zone_entered_for_a_source_range_has_no_row(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[_firewalld_zones(**CASE_12)]))
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        assert find(result, "tcp", 38012, family) is None, family
        assert find(result, "tcp", 38013, family) is None, family
    # The zone that faces the interface still reads as it did.
    for family in ("v4", "v6"):
        assert finding_for(result, "tcp", 8096, family).state == join.STATE_STALE_RULE, family


def test_a_listener_behind_a_source_scoped_zone_is_not_your_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(38013, process="whichports-test-zone"),
                 socket_row(38013, family="v6", bind_address="::",
                            process="whichports-test-zone")],
        tables=[_firewalld_zones(**CASE_12)]))
    # That server's v4 is behind a router and never probed. Its v6 is proved
    # and times out at the router.
    probe_run(con, host_id, [("v6", 38013, prober.STATE_NO_RESPONSE, "timeout", "2001:db8::5")])
    result = join.host_findings(con, host_id)

    v6 = finding_for(result, "tcp", 38013, "v6")
    assert v6.state == join.STATE_NOT_REACHABLE
    # An `ip saddr` jump cannot be taken by a v6 packet, so on v6 the rule is
    # neither a permit nor a narrowed one. It is not there (docs/PRODUCT.md 4b).
    assert v6.inside.permit_rules == ()
    assert v6.inside.narrowed_rules == ()
    assert join.NOTE_RULE_IS_NARROWED not in v6.cause.notes

    v4 = finding_for(result, "tcp", 38013, "v4")
    assert v4.state is None
    assert v4.inside.permit_rules == ()
    assert [quote.text for quote in v4.inside.narrowed_rules] == [
        "meta l4proto tcp tcp dport 38013 accept"]


def test_a_source_scoped_zone_is_no_answer_for_a_port_that_answers(con):
    """Reachable, and the only rule naming the port is in a zone entered for
    192.0.2.0/24. Something else let the packet in. The port is unreviewed
    and the rule is quoted as narrowed, never as the operator's answer."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(38013)],
                                  tables=[_firewalld_zones(**CASE_12)]))
    probe_run(con, host_id, [("v4", 38013, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 38013, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.cause.layer == join.LAYER_SERVICE
    assert finding.inside.permit_rules == ()
    assert join.NOTE_RULE_IS_NARROWED in finding.cause.notes


def test_the_zone_entered_on_the_interface_goes_on_counting(con):
    """The constraint the fix had to keep: firewalld's public zone is entered
    through a conditional jump too, on the interface, and that is how every
    firewalld permit on the fleet reaches its port."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(8096), socket_row(8096, family="v6", bind_address="::")],
        tables=[_firewalld_zones(policies=[ZONE_BY_INTERFACE],
                                 public=["meta l4proto tcp tcp dport 8096 accept"])]))
    probe_run(con, host_id, [
        ("v4", 8096, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 8096, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 8096, family)
        assert finding.state == join.STATE_INTENDED, family
        assert finding.cause.layer == join.LAYER_HOST_FIREWALL, family
        assert finding.inside.narrowed_rules == (), family


def test_a_port_open_in_both_zones_is_a_permit_and_not_also_narrowed(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(38013)],
        tables=[_firewalld_zones(
            policies=[ZONE_BY_SOURCE, ZONE_BY_INTERFACE],
            internal=["meta l4proto tcp tcp dport 38013 accept"],
            public=["meta l4proto tcp tcp dport 38013 accept"])]))
    probe_run(con, host_id, [("v4", 38013, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 38013, "v4")
    assert finding.state == join.STATE_INTENDED
    assert [quote.source for quote in finding.inside.permit_rules] == [
        "inet firewalld filter_IN_public_allow"]
    assert [quote.source for quote in finding.inside.narrowed_rules] == [
        "inet firewalld filter_IN_internal_allow"]
    assert join.NOTE_RULE_IS_NARROWED not in finding.cause.notes


def test_one_chain_reached_by_an_open_path_and_a_narrow_one_is_a_permit(con):
    """firewalld enters the default zone twice, once on the interface and once
    for everything else. A second, narrower way into the same chain takes
    nothing away from the open one."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(8096)],
        tables=[_firewalld_zones(
            policies=["meta nfproto ipv4 ip saddr 192.0.2.0/24 jump filter_IN_public",
                      ZONE_BY_INTERFACE, "jump filter_IN_public"],
            public=["meta l4proto tcp tcp dport 8096 accept"])]))
    probe_run(con, host_id, [("v4", 8096, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 8096, "v4")
    assert finding.state == join.STATE_INTENDED
    assert len(finding.inside.permit_rules) == 1
    assert finding.inside.narrowed_rules == ()


@pytest.mark.parametrize("jump, why", [
    ("meta nfproto ipv4 ip saddr 192.0.2.0/24 jump zone", "a v4 source range"),
    ("ip saddr 192.0.2.0/24 jump zone", "the same, as an agent wrote it without the pin"),
    ("meta nfproto ipv4 ip saddr 192.0.2.7 goto zone", "one address, by goto"),
    ('iifname "lo" jump zone', "the loopback interface"),
    ('iifname != "lo" jump zone', "an interface match that is not the plain form"),
    ('iifname "eno1" ip saddr 10.0.0.0/8 jump zone', "an interface and a source range"),
    ("ct state established,related jump zone", "replies only"),
    ("meta mark 0x1 jump zone", "a packet mark"),
    ("[xt match conntrack] counter jump zone", "a condition the agent could not read"),
    ("meta l4proto udp jump zone", "another protocol"),
    ("meta l4proto tcp tcp dport 22 jump zone", "another port"),
])
def test_a_jump_with_a_condition_narrows_what_is_behind_it(con, jump, why):
    tables = [table("inet", "filter", [
        chain("input", [rule(jump, rendered="partial" if "[" in jump else "full")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("zone", [rule("meta l4proto tcp tcp dport 4040 accept")])])]
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(4040)], tables=tables))
    probe_run(con, host_id, [("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 4040, "v4")
    assert finding.inside.permit_rules == (), why
    assert finding.state == join.STATE_UNREVIEWED, why


@pytest.mark.parametrize("jump, why", [
    ("jump zone", "no condition"),
    ("counter jump zone", "a counter"),
    ("goto zone", "a goto"),
    ('iifname "eno1" jump zone', "the interface, as firewalld enters a zone"),
    ("iif eno1 counter goto zone", "the interface by index form"),
    ("meta l4proto tcp jump zone", "this protocol"),
    ("meta l4proto tcp tcp dport 4040 jump zone", "this port"),
    ("meta nfproto ipv4 jump zone", "this family"),
    ("ct state new jump zone", "new connections"),
    ("ct state { new, untracked } jump zone", "new connections, the set form"),
    ('iifname "eno1" meta l4proto tcp ct state new counter jump zone', "all of them"),
])
def test_a_jump_whose_condition_narrows_nothing_goes_on_counting(con, jump, why):
    tables = [table("inet", "filter", [
        chain("input", [rule(jump)],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("zone", [rule("meta l4proto tcp tcp dport 4040 accept")])])]
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(4040)], tables=tables))
    probe_run(con, host_id, [("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 4040, "v4")
    assert finding.state == join.STATE_INTENDED, why
    assert finding.cause.layer == join.LAYER_HOST_FIREWALL, why


def test_a_jump_pinned_to_one_family_does_not_reach_the_other(con):
    tables = [table("inet", "filter", [
        chain("input", [rule("meta nfproto ipv6 jump zone")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("zone", [rule("meta l4proto tcp tcp dport 4040 accept")])])]
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=tables))
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 4040, "v6").state == join.STATE_STALE_RULE
    assert find(result, "tcp", 4040, "v4") is None


@pytest.mark.parametrize("chains", [
    # The condition is on the first of two jumps.
    [("input", ["meta nfproto ipv4 ip saddr 192.0.2.0/24 jump middle"]),
     ("middle", ["jump zone"])],
    # The condition is on the second.
    [("input", ["jump middle"]),
     ("middle", ["meta nfproto ipv4 ip saddr 192.0.2.0/24 jump zone"])],
])
def test_a_condition_anywhere_on_the_way_narrows(con, chains):
    built = [chain(name, [rule(text) for text in rules],
                   **(dict(hook="input", priority=0, type_="filter", policy="drop")
                      if name == "input" else {}))
             for name, rules in chains]
    built.append(chain("zone", [rule("meta l4proto tcp tcp dport 4040 accept")]))
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(4040)],
                                  tables=[table("inet", "filter", built)]))
    probe_run(con, host_id, [("v4", 4040, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 4040, "v4")
    assert finding.inside.permit_rules == ()
    assert finding.state == join.STATE_UNREVIEWED


def test_ufws_own_jumps_carry_no_condition(con):
    """ufw reaches its user chain through plain `counter jump` rules, so every
    `ufw allow` reads exactly as it did. The full ufw shape, logging chains
    and all."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(443)],
        tables=[ufw_v4_with_limit_chains(["ip protocol tcp tcp dport 443 counter accept"])]))
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 443, "v4")
    assert finding.state == join.STATE_INTENDED
    assert finding.inside.narrowed_rules == ()


# ----------------------------------- a rule that accepts new connections
#
# Round 4 of the test fleet, 2026-09-30, Rocky 8 with firewalld 0.9.11
# (docs/RECORD.md 4.220): every port firewalld opens is written `tcp dport
# 6000 ct state { new, untracked } accept`, and each read unreviewed, "no
# rule", and alerted. Decided on 2026-10-02 (4.244, docs/PRODUCT.md 8d): a
# state match that includes new is no narrowing. The texts are what the agent
# writes, measured that day on nftables 1.1.3: the set form since 0.1.12, and
# a bare lookup before it.
FIREWALLD_09_ACCEPT = "meta l4proto tcp tcp dport 6000 ct state { new, untracked } accept"
FIREWALLD_09_BEFORE_0112 = "meta l4proto tcp tcp dport 6000 [lookup @__set0] accept"


def _firewalld_09(text):
    return table("inet", "firewalld", [
        chain("filter_INPUT", [rule("ct state established,related accept"),
                               rule("jump filter_IN_public")],
              hook="input", priority=10, type_="filter", policy="accept"),
        chain("filter_IN_public", [rule("jump filter_IN_public_allow")]),
        chain("filter_IN_public_allow", [
            rule(text, rendered="partial" if "[" in text else "full")]),
    ])


def test_firewalld_on_rhel_8_opening_a_port_is_your_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(6000), socket_row(6000, family="v6", bind_address="::")],
        tables=[_firewalld_09(FIREWALLD_09_ACCEPT)]))
    probe_run(con, host_id, [
        ("v4", 6000, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 6000, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 6000, family)
        assert finding.state == join.STATE_INTENDED, family
        assert finding.cause.layer == join.LAYER_HOST_FIREWALL, family
        assert [quote.text for quote in finding.inside.permit_rules] == [FIREWALLD_09_ACCEPT], family
        assert finding.inside.narrowed_rules == (), family


def test_the_same_rule_from_an_agent_before_0_1_12_is_still_not_readable(con):
    """An older agent writes the set as a bare lookup, and a lookup can be a
    list of addresses. Nothing here may guess that it is not."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(6000)], tables=[_firewalld_09(FIREWALLD_09_BEFORE_0112)]))
    probe_run(con, host_id, [("v4", 6000, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 6000, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.inside.permit_rules == ()
    assert join.NOTE_RULES_NOT_FULLY_READABLE in finding.cause.notes


def test_a_new_connection_rule_with_nothing_behind_it_is_a_stale_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[_firewalld_09(FIREWALLD_09_ACCEPT)]))
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        assert finding_for(result, "tcp", 6000, family).state == join.STATE_STALE_RULE, family


@pytest.mark.parametrize("state_match", [
    "ct state new",
    "ct state new,untracked",
    "ct state { new }",
    "ct state { new, untracked }",
    # Replies beside new: still met by every first packet.
    "ct state established,related,new",
    "ct state { established, related, new }",
    "ct state invalid,new",
])
def test_a_state_match_that_includes_new_is_no_narrowing(con, state_match):
    text = f"meta l4proto tcp tcp dport 6000 {state_match} counter accept"
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(6000)], tables=[_firewalld_09(text)]))
    probe_run(con, host_id, [("v4", 6000, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 6000, "v4")
    assert finding.state == join.STATE_INTENDED, state_match
    assert [quote.text for quote in finding.inside.permit_rules] == [text], state_match


@pytest.mark.parametrize("state_match", [
    # Opens nothing to a first packet.
    "ct state established",
    "ct state established,related",
    "ct state { established, related }",
    "ct state untracked",
    "ct state invalid",
    # Everything but new.
    "ct state != new",
    "ct state != { new, untracked }",
    # new, and a state this engine does not know.
    "ct state new,0x80",
    "ct state { new, 0x80 }",
    "ct state new,reply",
    # new, and a real narrowing beside it.
    "ip saddr 203.0.113.0/24 ct state new",
    'iifname "eth1" ct state { new, untracked }',
    "ct state new ct status dnat",
    # Another conntrack key that happens to say new.
    "ct direction new",
])
def test_a_state_match_that_is_not_plain_new_stays_narrowed(con, state_match):
    text = f"meta l4proto tcp tcp dport 6000 {state_match} accept"
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(6000)], tables=[_firewalld_09(text)]))
    probe_run(con, host_id, [("v4", 6000, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 6000, "v4")
    assert finding.inside.permit_rules == (), state_match
    assert finding.state == join.STATE_UNREVIEWED, state_match
    assert [quote.text for quote in finding.inside.narrowed_rules] == [text], state_match


def test_firewalld_2_4s_bare_accept_reads_as_it_did(con):
    """firewalld 2.4 writes a bare accept (docs/RECORD.md 4.223). It
    was your rule before this and it is your rule after."""
    text = "meta l4proto tcp tcp dport 6000 accept"
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(6000)], tables=[_firewalld_09(text)]))
    probe_run(con, host_id, [("v4", 6000, prober.STATE_CONNECTED, None, "203.0.113.5")])
    assert finding_for(join.host_findings(con, host_id), "tcp", 6000, "v4").state == join.STATE_INTENDED


# ------------------------ the test fleet's case 3, and what stands next to it
#
# Wave 1, case 3, 2026-09-29, on a server with ufw (docs/RECORD.md 4.210):
# `ufw limit 3020/tcp` with a listener on 0.0.0.0 and on ::. Both probers
# connected on both families, and the engine said unreviewed, layer service,
# "no rule", and two alerts were mailed about a port opened on purpose.

def _limit_3020(v4_rules=None, v6_rules=None, sockets=None):
    v4 = [text.replace("dport 22", "dport 3020") for text in UFW_LIMIT_V4]
    v6 = [text.replace("dport 22", "dport 3020") for text in UFW_LIMIT_V6]
    if sockets is None:
        sockets = [socket_row(3020, process="whichports-test"),
                   socket_row(3020, family="v6", bind_address="::",
                              process="whichports-test")]
    return document(sockets=sockets, tables=[
        ufw_v4_with_limit_chains(v4 if v4_rules is None else v4_rules),
        ufw_v6_with_limit_chains(v6 if v6_rules is None else v6_rules)])


def test_ufw_limit_on_a_port_that_answers_is_your_rule_on_both_families(con):
    host_id = add_host(con)
    report(con, host_id, _limit_3020())
    probe_run(con, host_id, [
        ("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 3020, prober.STATE_CONNECTED, None, "2001:db8::5")])

    result = join.host_findings(con, host_id)
    for family, permit in (("v4", "ip protocol tcp tcp dport 3020 counter jump ufw-user-limit-accept"),
                           ("v6", "meta l4proto tcp tcp dport 3020 counter jump ufw6-user-limit-accept")):
        finding = finding_for(result, "tcp", 3020, family)
        assert finding.state == join.STATE_INTENDED, family
        assert finding.cause.layer == join.LAYER_HOST_FIREWALL, family
        assert [quote.text for quote in finding.inside.permit_rules] == [permit], family
        assert finding.rate_limited is True, family
        assert limit_modules(finding) == ["recent", "recent"], family


def test_ufw_limit_answers_only_for_a_port_that_answers(con):
    """docs/PRODUCT.md 8d: the rule answers only for a reachable port. Silent
    with a listener is `not reachable`, and with nothing behind it the rule is
    a `stale rule`, exactly as for `ufw allow`."""
    host_id = add_host(con, name="silent")
    report(con, host_id, _limit_3020())
    probe_run(con, host_id, [("v4", 3020, prober.STATE_NO_RESPONSE, "timeout", "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 3020, "v4")
    assert finding.state == join.STATE_NOT_REACHABLE
    assert finding.cause.layer == join.LAYER_NOT_DETERMINED

    host_id = add_host(con, name="nothing-behind-it")
    report(con, host_id, _limit_3020(sockets=[]))
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 3020, family)
        assert finding.state == join.STATE_STALE_RULE, family
        assert finding.cause.layer == join.LAYER_HOST_FIREWALL, family


def test_a_declaration_still_wins_over_a_rate_limited_permit(con):
    """Declared closed, permitted by `ufw limit` and answering: a conflict,
    because the person said so after the rule (docs/PRODUCT.md 8d)."""
    host_id = add_host(con)
    report(con, host_id, _limit_3020())
    probe_run(con, host_id, [("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5")])
    result = join.host_findings(
        con, host_id, intent={("tcp", 3020, "v4"): join.INTENT_CLOSED})
    assert finding_for(result, "tcp", 3020, "v4").state == join.STATE_CONFLICT


@pytest.mark.parametrize("name, accept_chain", [
    ("an accept and something after it", ["counter accept", "counter return"]),
    ("a log before the accept", ["[limit] counter [xt target LOG]", "counter accept"]),
    ("an accept for some addresses", ["ip saddr 10.0.0.0/8 counter accept"]),
    ("an accept for one interface", ['iifname "eth1" counter accept']),
    ("a drop", ["counter drop"]),
    ("a jump onward", ["counter jump ufw-user-limit"]),
    ("nothing at all", []),
])
def test_a_jump_to_a_chain_that_is_not_only_accepts_is_no_permit(con, name, accept_chain):
    """The jump counts as an accept only when the chain it names holds
    nothing but accepts. Anything else in that chain, and the rule that jumps
    there is what it was before: a jump, and no permit."""
    tables = [table("ip", "filter", [
        chain("INPUT", [rule("counter jump ufw-user-input")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("ufw-user-input", [
            rule("ip protocol tcp tcp dport 3020 counter jump ufw-user-limit-accept")]),
        chain("ufw-user-limit", [rule("counter [xt target REJECT]", rendered="partial")]),
        chain("ufw-user-limit-accept", [
            rule(text, rendered="partial" if "[" in text else "full")
            for text in accept_chain]),
    ])]
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(3020)], tables=tables))
    probe_run(con, host_id, [("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 3020, "v4")
    assert finding.inside.permit_rules == (), name
    assert finding.state == join.STATE_UNREVIEWED, name


def test_an_accept_chain_the_agent_could_not_fully_read_is_no_permit(con):
    """A rule whose text reads `counter accept` and whose grade says part of
    it was not understood is not a bare accept."""
    tables = [table("ip", "filter", [
        chain("INPUT", [rule("ip protocol tcp tcp dport 3020 counter jump allow")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("allow", [rule("counter accept", rendered="partial")]),
    ])]
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(3020)], tables=tables))
    probe_run(con, host_id, [("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 3020, "v4")
    assert finding.inside.permit_rules == ()
    assert finding.state == join.STATE_UNREVIEWED


def test_a_jump_to_a_chain_the_document_does_not_hold_is_no_permit(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(3020)], tables=[ufw_v4([
        "ip protocol tcp tcp dport 3020 counter jump ufw-user-limit-accept"])]))
    probe_run(con, host_id, [("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 3020, "v4")
    assert finding.inside.permit_rules == ()
    assert finding.state == join.STATE_UNREVIEWED


def test_a_narrowed_jump_to_the_accept_chain_is_narrowed_not_a_permit(con):
    """`ufw limit from 203.0.113.7 to any port 3020`: the jump names the port
    and a source, so it is an answer for one address and not for the
    internet."""
    v4 = ["ip saddr 203.0.113.7 ip protocol tcp tcp dport 3020 counter"
          " jump ufw-user-limit-accept"]
    host_id = add_host(con)
    report(con, host_id, _limit_3020(v4_rules=v4))
    probe_run(con, host_id, [("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 3020, "v4")
    assert finding.inside.permit_rules == ()
    assert [quote.text for quote in finding.inside.narrowed_rules] == v4
    assert finding.state == join.STATE_UNREVIEWED


def test_a_goto_to_the_accept_chain_counts_like_a_jump(con):
    tables = [table("inet", "filter", [
        chain("input", [rule("meta l4proto tcp tcp dport 3020 goto allow")],
              hook="input", priority=0, type_="filter", policy="drop"),
        chain("allow", [rule("accept")]),
    ])]
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(3020)], tables=tables))
    probe_run(con, host_id, [("v4", 3020, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 3020, "v4")
    assert finding.state == join.STATE_INTENDED
    assert finding.cause.layer == join.LAYER_HOST_FIREWALL


# nftables' own rate limit, seen on a test server on 2026-09-30 (docs/RECORD.md
# 4.220): `tcp dport 4050 limit rate 10/second burst 5 packets accept` in a
# hand-written inet table. The text is what the agent writes for that line,
# measured on 2026-10-02 (4.244).
NFT_LIMIT_ACCEPT = "meta l4proto tcp tcp dport 4050 [limit] accept"


def _inet(*rules):
    return table("inet", "filter", [
        chain("input", [rule(text, rendered="partial" if "[" in text else "full")
                        for text in rules],
              hook="input", priority=0, type_="filter", policy="drop")])


def test_an_nftables_limit_on_an_accept_is_your_rule_and_carries_the_mark(con):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(4050), socket_row(4050, family="v6", bind_address="::")],
        tables=[_inet(NFT_LIMIT_ACCEPT)]))
    probe_run(con, host_id, [
        ("v4", 4050, prober.STATE_CONNECTED, None, "203.0.113.5"),
        ("v6", 4050, prober.STATE_CONNECTED, None, "2001:db8::5")])
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 4050, family)
        assert finding.state == join.STATE_INTENDED, family
        assert finding.cause.layer == join.LAYER_HOST_FIREWALL, family
        assert finding.rate_limited is True, family
        assert limit_modules(finding) == ["limit"], family
        # Quoted with its bracket, as the agent wrote it.
        assert [quote.text for quote in finding.inside.permit_rules] == [NFT_LIMIT_ACCEPT], family


def test_an_nftables_limit_with_nothing_behind_it_is_a_stale_rule(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[], tables=[_inet(NFT_LIMIT_ACCEPT)]))
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        assert finding_for(result, "tcp", 4050, family).state == join.STATE_STALE_RULE, family


@pytest.mark.parametrize("text", [
    # Another part the agent could not read sits beside the limit.
    "meta l4proto tcp tcp dport 4050 [limit] [lookup @allowed] accept",
    "meta l4proto tcp tcp dport 4050 [limit] [xt match conntrack] accept",
    # A source range beside the limit: narrowed.
    "ip saddr 10.0.0.0/8 meta l4proto tcp tcp dport 4050 [limit] accept",
    # The limit and no accept.
    "meta l4proto tcp tcp dport 4050 [limit] drop",
    "meta l4proto tcp tcp dport 4050 [limit] counter",
    # The other two modules are marks and never permits.
    "meta l4proto tcp tcp dport 4050 [xt match hashlimit] accept",
    "meta l4proto tcp tcp dport 4050 [xt match recent] accept",
])
def test_a_limit_that_is_not_a_plain_permit_stays_out_of_the_permits(con, text):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(4050)], tables=[_inet(text)]))
    probe_run(con, host_id, [("v4", 4050, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 4050, "v4")
    assert finding.inside.permit_rules == (), text
    assert finding.state == join.STATE_UNREVIEWED, text


def test_a_limit_over_the_rate_is_named_and_is_never_a_permit(con):
    """`limit rate over 10/second accept` accepts only the packets above the
    rate, so an ordinary connection is not let in by it. The agent writes it
    as `[limit over]` since 0.1.12 (measured on nftables 1.1.3, 2026-10-02).
    It is a rate limit, so the port carries the mark, and it is not the rule
    that opened the port."""
    text = "meta l4proto tcp tcp dport 4050 [limit over] accept"
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(4050)], tables=[_inet(text)]))
    probe_run(con, host_id, [("v4", 4050, prober.STATE_CONNECTED, None, "203.0.113.5")])
    finding = finding_for(join.host_findings(con, host_id), "tcp", 4050, "v4")
    assert limit_modules(finding) == ["limit"]
    assert finding.rate_limited is True
    assert finding.inside.permit_rules == ()
    assert finding.inside.narrowed_rules == ()
    assert finding.state == join.STATE_UNREVIEWED

    # And with nothing behind it, it proposes no row: it is not a permit, so
    # there is no rule for it to be stale.
    host_id = add_host(con, name="nothing-behind-it")
    report(con, host_id, document(sockets=[], tables=[_inet(text)]))
    assert find(join.host_findings(con, host_id), "tcp", 4050, "v4") is None


def test_ufws_logging_limiters_never_become_a_permit(con):
    """They carry `[limit]` and sit on every port's path. With the limit set
    aside they still name no port, so they propose no row and permit nothing."""
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket_row(80)],
        tables=[ufw_v4_with_limit_chains([])]))
    probe_run(con, host_id, [("v4", 80, prober.STATE_CONNECTED, None, "203.0.113.5")])
    result = join.host_findings(con, host_id)
    finding = finding_for(result, "tcp", 80, "v4")
    assert finding.inside.permit_rules == ()
    assert finding.state == join.STATE_UNREVIEWED
    assert [(f.protocol, f.port) for f in result.findings if f.family == "v4"] == [("tcp", 80)]


def test_a_provider_rule_from_some_addresses_only_is_narrowed_and_not_a_permit(con):
    """docs/PRODUCT.md 8d, on the provider's side. A rule permitting a port
    from one network is quoted as narrowed and counts as no permit: a port
    the world cannot reach through it is not a port somebody opened."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    hetzner_snapshot(con, rules=[
        {"direction": "in", "protocol": "tcp", "port": "22",
         "description": "office", "source_ips": ["203.0.113.0/24"],
         "destination_ips": []},
        {"direction": "in", "protocol": "tcp", "port": "8443",
         "description": "office only", "source_ips": ["203.0.113.0/24"],
         "destination_ips": []}])
    findings = join.host_findings(con, host_id)
    ssh = finding_for(findings, "tcp", 22, "v4")
    assert ssh.provider.rules == ()
    assert len(ssh.provider.narrowed) == 1
    assert "203.0.113.0/24" in ssh.provider.narrowed[0].text
    # and a narrowed rule alone is no stale rule for a port nothing serves:
    # the port is raised, quoted, and has no state
    idle = finding_for(findings, "tcp", 8443, "v4")
    assert idle.state is None and idle.provider.rules == ()
    assert len(idle.provider.narrowed) == 1


# ============================== two outside views, decided 2026-09-08 (8e)
#
# The owner handed the logic over (docs/RECORD.md 4.157). The choice: a
# completed connect from any
# vantage is a completed connect, disagreement is a mark beside the state and
# never a sixth state, and a vantage that measured nothing is not a second
# opinion. Every test above runs with one vantage name per port and is the
# proof the single-vantage answers did not move.

from app import vantages as vantage_registry  # noqa: E402

T0 = "2026-09-08T10:00:00+00:00"
T1 = "2026-09-08T10:05:00+00:00"


def registry(con, *names, off=()):
    vantage_registry.init(con)
    for n, name in enumerate(names):
        vantage_registry.add(con, name, f"root@{name}", [f"185.199.110.{n + 1}"])
    for name in off:
        vantage_registry.set_enabled(con, name, False)


def outside(con, host_id, port=22, family="v4"):
    return finding_for(join.host_findings(con, host_id), "tcp", port, family).outside


def test_two_vantages_agreeing_is_one_answer_with_two_views(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T1, vantage="probe2")
    view = outside(con, host_id)
    assert view.state == prober.STATE_CONNECTED
    assert view.disagree is False
    assert [(v.vantage, v.state) for v in view.views] == [
        ("probe1", prober.STATE_CONNECTED), ("probe2", prober.STATE_CONNECTED)]


def test_a_connect_from_either_vantage_is_a_connect_and_the_silence_is_a_disagreement(con):
    """The case the second vantage exists for. Amsterdam ran last and saw
    nothing, London saw the port. The port is reachable, from London, and the
    two are marked as disagreeing rather than the newer one winning."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="probe2")
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T1, vantage="probe1")
    view = outside(con, host_id)
    assert view.state == prober.STATE_CONNECTED
    assert view.vantage == "probe2"
    assert view.disagree is True
    assert [(v.vantage, v.state) for v in view.views] == [
        ("probe1", prober.STATE_NO_RESPONSE), ("probe2", prober.STATE_CONNECTED)]


def test_each_vantages_view_carries_the_word_the_resolved_answer_uses(con):
    """A screen that lists what each vantage said under the resolved word
    spells both from one table, so `probe1 no response` under `connect
    succeeded` cannot drift into a second vocabulary."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="probe2")
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T1, vantage="probe1")
    view = outside(con, host_id)
    assert [(v.vantage, v.word, v.measured) for v in view.views] == [
        ("probe1", "no response", True), ("probe2", "connect succeeded", True)]
    assert view.word == "connect succeeded"


def test_the_newest_vantage_silently_winning_is_what_this_stops(con):
    """The same two runs the other way round in time: London ran last. The
    answer and the mark are the same, because the order the boxes ran in is
    not evidence of anything."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T0, vantage="probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T1, vantage="probe2")
    view = outside(con, host_id)
    assert (view.state, view.vantage, view.disagree) == (
        prober.STATE_CONNECTED, "probe2", True)


def test_a_refusal_against_a_silence_is_a_disagreement_and_the_newest_names_the_cell(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_REFUSED, None, ADDR_A)],
              started_at=T0, vantage="probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T1, vantage="probe2")
    view = outside(con, host_id)
    assert view.state == prober.STATE_NO_RESPONSE
    assert view.vantage == "probe2"
    assert view.disagree is True


def test_a_vantage_that_measured_nothing_is_not_a_second_opinion(con):
    """probe2's newest row is not_tested. Silence from a box is not evidence
    against what the other box measured, so there is no disagreement."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_NOT_TESTED,
                              prober.REASON_NO_AUTHORIZATION, ADDR_A)],
              started_at=T1, vantage="probe2")
    view = outside(con, host_id)
    assert view.state == prober.STATE_CONNECTED
    assert view.disagree is False
    assert len(view.views) == 2


def test_the_five_states_rest_on_the_resolved_answer(con):
    """A port reachable from one vantage and silent from the other gets the
    state a reachable port gets. The mark rides beside it."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="probe2")
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T1, vantage="probe1")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.outside.disagree is True


def test_a_vantage_switched_off_does_not_stand_against_a_live_one(con):
    """probe2 is off in the registry and its last row is an old silence.
    probe1 measured a refusal since. Nothing disagrees, because a box we
    stopped driving is not a current view."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    registry(con, "probe1", "probe2", off=("probe2",))
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T0, vantage="probe2")
    probe_run(con, host_id, [("v4", 22, prober.STATE_REFUSED, None, ADDR_A)],
              started_at=T1, vantage="probe1")
    view = outside(con, host_id)
    assert (view.state, view.vantage, view.disagree) == (
        prober.STATE_REFUSED, "probe1", False)
    assert [v.vantage for v in view.views] == ["probe1"]


def test_rows_under_a_name_the_registry_does_not_know_still_count_when_nothing_else_does(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    registry(con, "probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="laptop")
    view = outside(con, host_id)
    assert (view.state, view.vantage) == (prober.STATE_CONNECTED, "laptop")


def test_one_vantage_across_runs_keeps_its_own_newest_answer_and_no_mark(con):
    """The single-vantage behaviour, with the registry holding that one name:
    a later silence supersedes an earlier connect, as it always has."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    registry(con, "probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, ADDR_A)],
              started_at=T0, vantage="probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_NO_RESPONSE,
                              prober.REASON_TIMEOUT_EXPIRED, ADDR_A)],
              started_at=T1, vantage="probe1")
    view = outside(con, host_id)
    assert (view.state, view.disagree) == (prober.STATE_NO_RESPONSE, False)
    assert [(v.vantage, v.state) for v in view.views] == [
        ("probe1", prober.STATE_NO_RESPONSE)]


def test_two_addresses_in_one_family_each_carry_their_own_vantage_views(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_REFUSED, None, ADDR_A),
                             ("v4", 22, prober.STATE_REFUSED, None, ADDR_B)],
              started_at=T0, vantage="probe1")
    probe_run(con, host_id, [("v4", 22, prober.STATE_REFUSED, None, ADDR_A),
                             ("v4", 22, prober.STATE_CONNECTED, None, ADDR_B)],
              started_at=T1, vantage="probe2")
    view = outside(con, host_id)
    assert view.state == prober.STATE_CONNECTED
    assert view.disagree is True, "ADDR_B refused from one box and reached from the other"
    assert [(v.target, v.vantage, v.state) for v in view.views] == [
        (ADDR_A, "probe1", prober.STATE_REFUSED), (ADDR_A, "probe2", prober.STATE_REFUSED),
        (ADDR_B, "probe1", prober.STATE_REFUSED), (ADDR_B, "probe2", prober.STATE_CONNECTED)]


# ------------------------------------------- what the kernel said about a socket
#
# Agent 0.1.10 sends no process name. It sends the systemd unit the kernel
# names for the socket and the socket's owner (docs/RECORD.md 4.169). The
# engine's socket record carried neither, so every reader of a finding said
# "an unnamed process" about a socket the Services tab named correctly from
# the same document. The owner saw it on 2026-09-20: the Services tab named the
# services and the evidence named none of them.

def _kernel_socket(**extra):
    entry = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
             "port": 22, "owner_uid": 0, "owner_name": "root"}
    entry.update(extra)
    return entry


def test_a_socket_carries_the_unit_and_the_owner_the_document_gave():
    doc = document(sockets=[_kernel_socket(unit="ssh.socket")])
    (sock,) = join._listening(doc, "tcp", 22, "v4")
    assert (sock.process_name, sock.unit, sock.owner_name, sock.owner_uid) == (
        "", "ssh.socket", "root", 0)


def test_the_unit_is_what_a_socket_with_no_process_name_is_called():
    doc = document(sockets=[_kernel_socket(unit="ssh.socket")])
    (sock,) = join._listening(doc, "tcp", 22, "v4")
    assert sock.text == "ssh.socket on 0.0.0.0"


def test_a_measured_process_name_still_comes_first():
    doc = document(sockets=[_kernel_socket(unit="ssh.socket", process_name="sshd")])
    (sock,) = join._listening(doc, "tcp", 22, "v4")
    assert sock.text == "sshd on 0.0.0.0"


def test_a_socket_the_kernel_named_nothing_for_is_still_unnamed():
    doc = document(sockets=[_kernel_socket()])
    (sock,) = join._listening(doc, "tcp", 22, "v4")
    assert sock.unit == "" and sock.text == "an unnamed process on 0.0.0.0"


@pytest.mark.parametrize("bad", [None, ["ssh.socket"], {"a": 1}, True, 1.5])
def test_a_unit_or_an_owner_of_the_wrong_type_is_read_as_absent(bad):
    """True is left out of the uids on purpose: bool is an int in Python, and
    a document saying `"owner_uid": true` does not mean uid 1."""
    doc = document(sockets=[_kernel_socket(unit=bad, owner_name=bad, owner_uid=bad)])
    (sock,) = join._listening(doc, "tcp", 22, "v4")
    assert (sock.unit, sock.owner_name, sock.owner_uid) == ("", "", None)


def test_a_number_where_a_name_belongs_is_absent_and_a_uid_stays_a_uid():
    doc = document(sockets=[_kernel_socket(unit=7, owner_name=7, owner_uid=7)])
    (sock,) = join._listening(doc, "tcp", 22, "v4")
    assert (sock.unit, sock.owner_name, sock.owner_uid) == ("", "", 7)


# ------------------------------------------- the provider's server, by address
#
# tests/test_provider_match.py holds the rule. These hold that the engine
# reaches it with the host's own proved addresses, which is what makes a
# Hetzner server found when it is not called what the host is called
# (docs/RECORD.md 4.190).

def _prove(con, host_id, target, family, expires="2099-01-01T00:00:00+00:00"):
    from app import authz
    authz.init(con)
    con.execute(
        "INSERT INTO authorizations (target, family, method, evidence, account,"
        " host_id, verified_at, expires_at) VALUES (?, ?, 'agent', 'test', 'default',"
        " ?, '2026-09-20T00:00:00+00:00', ?)", (target, family, host_id, expires))
    con.commit()


def test_a_host_is_found_at_the_provider_by_the_address_it_proved(con):
    host_id = add_host(con, "student-net")
    report(con, host_id, document(hostname="Student-Net", sockets=[socket_row(22)]))
    hetzner_snapshot(con, server_name="ubuntu-4gb-nbg1-2")
    _prove(con, host_id, "2001:db8::1", "v6")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.matched is True
    assert finding.provider.server_name == "ubuntu-4gb-nbg1-2"


def test_a_proof_that_has_expired_names_no_server(con):
    host_id = add_host(con, "student-net")
    report(con, host_id, document(hostname="Student-Net", sockets=[socket_row(22)]))
    hetzner_snapshot(con, server_name="ubuntu-4gb-nbg1-2")
    _prove(con, host_id, "203.0.113.5", "v4", expires="2020-01-01T00:00:00+00:00")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.matched is False


def test_another_hosts_proof_names_nothing_for_this_one(con):
    host_id = add_host(con, "student-net")
    other = add_host(con, "neighbour")
    report(con, host_id, document(hostname="Student-Net", sockets=[socket_row(22)]))
    hetzner_snapshot(con, server_name="ubuntu-4gb-nbg1-2")
    _prove(con, other, "203.0.113.5", "v4")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.provider.matched is False


# ------------------------------- a v4 port served on the v6 wildcard, named
#
# `_ambiguous_binds` read the process name alone, so under agent 0.1.10 every
# v4 port a service took through `::` was quoted "an unnamed process on ::"
# beside a Services tab that named it (docs/RECORD.md 4.200). And the finding
# alerts need the socket itself to name the program behind such a port.

def test_a_wildcard_socket_on_v4_is_named_by_its_unit():
    doc = document(sockets=[_kernel_socket(family="v6", bind_address="::",
                                           port=3000, unit="porttest-a.service")])
    (quote,) = join._ambiguous_binds(doc, "tcp", 3000, "v4")
    assert quote.text == "porttest-a.service on ::"
    (sock,) = join._wildcard_sockets(doc, "tcp", 3000, "v4")
    assert sock.unit == "porttest-a.service"


def test_a_wildcard_socket_still_prefers_the_process_name():
    doc = document(sockets=[_kernel_socket(family="v6", bind_address="::",
                                           port=3000, unit="porttest-a.service",
                                           process_name="python3")])
    (quote,) = join._ambiguous_binds(doc, "tcp", 3000, "v4")
    assert quote.text == "python3 on ::"


def test_the_v6_half_has_no_wildcard_sockets():
    doc = document(sockets=[_kernel_socket(family="v6", bind_address="::",
                                           port=3000, unit="porttest-a.service")])
    assert join._wildcard_sockets(doc, "tcp", 3000, "v6") == ()
    assert join._ambiguous_binds(doc, "tcp", 3000, "v6") == ()


# ------------------------------------ a container is named, not docker.service
#
# Case A2 of 2026-09-26 (docs/RECORD.md 4.200): the mail about tcp/3001 said
# "The host is listening: docker.service on 0.0.0.0" while the Services tab
# named the container porttest-c. The sentence is `describe`, so it is held
# here.

def _docker_published(con, socket):
    host_id = add_host(con)
    report(con, host_id, document(
        sockets=[socket],
        containers={"status": "collected", "docker": [
            {"name": "porttest-c", "ports": [
                {"host_ip": "0.0.0.0", "host_port": 3001, "container_port": 3001,
                 "protocol": "tcp"}]}]}))
    probe_run(con, host_id, [("v4", 3001, prober.STATE_CONNECTED, None, "203.0.113.9")])
    return finding_for(join.host_findings(con, host_id), "tcp", 3001, "v4")


@pytest.mark.parametrize("socket", [
    _kernel_socket(port=3001, unit="docker.service"),
    socket_row(3001, process="docker-proxy"),
], ids=["unit", "process"])
def test_a_docker_published_port_is_described_by_its_container(con, socket):
    sentence = join.describe(_docker_published(con, socket))
    assert "The host publishes this port: docker container porttest-c on 0.0.0.0." in sentence
    assert "docker.service" not in sentence
    assert "docker-proxy" not in sentence


def test_another_socket_beside_a_publication_is_still_named(con):
    """Only Docker's own socket is left out. A socket some other program holds
    on the same port is still said."""
    sentence = join.describe(_docker_published(
        con, socket_row(3001, process="rootlessport")))
    assert "docker container porttest-c" in sentence
    assert "The host is listening: rootlessport on 0.0.0.0." in sentence


# ------------------------- a silence only the probe names stops being a row
#
# The owner, 2026-09-27 (docs/RECORD.md 4.207). fart's Overview carried 1000 and
# 6767 as "nothing listening" rows for a month. The fast lane now lets such a
# port go after a day with no state, and this is the other half: once its
# newest measurement is a silence more than a day older than the newest
# document, it is not a row.

def _only_probed(con, measured_at, received_at, state=prober.STATE_NO_RESPONSE,
                 sockets=()):
    host_id = add_host(con)
    report(con, host_id, document(sockets=list(sockets)), received_at=received_at)
    probe_run(con, host_id, [("v4", 6767, state, None, "203.0.113.9")],
              started_at=measured_at, finished_at=measured_at)
    return join.host_findings(con, host_id).findings


def test_a_silence_only_the_probe_names_goes_after_a_day(con):
    findings = _only_probed(con, "2026-09-25T11:00:00+00:00",
                            "2026-09-27T12:00:00+00:00")
    assert [(f.port, f.family) for f in findings] == []


def test_a_silence_inside_the_day_is_still_a_row(con):
    findings = _only_probed(con, "2026-09-26T13:00:00+00:00",
                            "2026-09-27T12:00:00+00:00")
    assert [(f.port, f.family) for f in findings] == [(6767, "v4")]


def test_an_old_connect_nothing_owns_is_never_forgotten(con):
    """That is `unexplained`, a finding, however old."""
    findings = _only_probed(con, "2026-09-01T11:00:00+00:00",
                            "2026-09-27T12:00:00+00:00",
                            state=prober.STATE_CONNECTED)
    assert [(f.port, f.state) for f in findings] == [(6767, join.STATE_UNEXPLAINED)]


def test_a_port_the_document_names_stays_however_old_its_silence(con):
    findings = _only_probed(con, "2026-09-01T11:00:00+00:00",
                            "2026-09-27T12:00:00+00:00",
                            sockets=[socket_row(6767)])
    assert [(f.port, f.state) for f in findings] == [(6767, join.STATE_NOT_REACHABLE)]
