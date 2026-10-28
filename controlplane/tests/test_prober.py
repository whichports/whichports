"""The TCP connect engine.

    python -m pytest tests/test_prober.py

The prober is the thing that puts packets on somebody else's network, so the
tests that matter most here are the ones about **not** sending, and about
refusing to turn an error into a finding:

  - no packet leaves without a live authorisation for that exact address and
    that exact family, checked again before every single connect
  - a family with no address, or with no authorisation, is `not_tested` with a
    reason, and never a state that reads as a finding
  - an outcome this module does not positively recognise is `not_tested`, so a
    kernel we have not met cannot invent a measurement
  - SI-7: no byte is transferred in either direction

Most of the suite injects the connect primitive, so it is deterministic and
fast. A short section at the end points the real primitive at real loopback
sockets, on both families, because a mapping from exceptions to states is only
worth what a real socket says. **If this machine has no IPv6 the skip is loud**,
a warning in pytest's summary and a banner on stderr, because a v6 half that
quietly did not run is exactly the failure `docs/RECORD.md` 4.45 is about.

No test here connects to anything but 127.0.0.1 and ::1.
"""

import ast
import asyncio
import errno
import pathlib
import socket
import sqlite3
import sys
import warnings
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, prober, store

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)

# Globally routable addresses, because the authorisation registry refuses
# anything else and is right to. Nothing in this file ever connects to one:
# every run below is given an injected connect primitive.
V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.109.153"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


def document(addresses):
    """A host document that reports binding exactly these addresses."""
    import json
    listening = [{"protocol": "tcp", "family": "v6" if ":" in a else "v4",
                  "bind_address": a, "port": 443} for a in addresses]
    return json.dumps({"schema_version": 1, "hostname": "box",
                       "collected_at_unix": 0,
                       "sockets": {"status": "ok", "listening": listening}})


def authorise(con, *addresses, name="box", now=NOW):
    """Authorise each address the way an agent does, which is the only proof
    that needs no network. Returns the host id."""
    host_id, _ = store.add_host(con, name)
    for address in addresses:
        result = authz.record_agent_proof(con, host_id, address,
                                         document([address]), now=now)
        assert result.recorded, result.reason
    return host_id


# ------------------------------------------------------------ fake primitives

class FakeConnect:
    """Stands in for the connect primitive and records every call.

    `answers` maps a port to what that port does: a float is how long the
    connect took, an exception instance is raised. Anything not named uses
    `default`.
    """

    def __init__(self, answers=None, default=0.002):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    async def __call__(self, target, family, port):
        self.calls.append((target, family, port))
        answer = self.answers.get(port, self.default)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    @property
    def ports(self):
        return [port for _target, _family, port in self.calls]

    def families(self):
        return {family for _target, family, _port in self.calls}


class RefusingConnect:
    """A primitive that must never be called. Used wherever the point of the
    test is that no packet leaves."""

    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port):
        self.calls.append((target, family, port))
        raise AssertionError(
            f"a packet was sent to {target} port {port} ({family}) and the test"
            " exists because it must not be")


def os_error(name, message="injected"):
    """An OSError carrying a real platform errno, by name, because the numbers
    differ between Linux and macOS."""
    return OSError(getattr(errno, name), message)


def run(coro):
    """The suite has no async plugin on purpose, because that would be a new
    dependency for something one stdlib call already does."""
    return asyncio.run(coro)


def probe(con, addresses, ports, **kwargs):
    connect = kwargs.pop("connect", None) or FakeConnect()
    gate_clock = kwargs.pop("gate_clock", NOW)
    host_id = kwargs.pop("host_id", None)
    prober_object = prober.Prober(connect=connect, **kwargs)
    result = run(prober_object.run(con, addresses, ports, host_id=host_id,
                                  gate_clock=gate_clock))
    return result, connect


def states(run_result):
    return {(r.family, r.port): r.state for r in run_result.results}


def reasons(run_result):
    return {(r.family, r.port): r.reason for r in run_result.results}


def family_rows(run_result, family):
    return [r for r in run_result.results if r.family == family]


# ================================================================ the vocabulary

def test_every_state_and_reason_the_module_can_produce_is_in_its_own_sets():
    """A state or reason that is not in the declared set is a value the
    dashboard has never been told about."""
    for state, reason in prober._ERRNO_STATES.values():
        assert state in prober.STATES
        assert reason is None or reason in prober.REASONS
    assert set(prober.MEASURED_STATES) < set(prober.STATES)
    assert prober.STATE_NOT_TESTED not in prober.MEASURED_STATES


def test_the_two_reason_sets_exhaust_every_reason():
    """A reason added later must be declared measured or unmeasured. Without
    this, forgetting to classify a new reason is silent, and the pairing test
    below then simply never sees it."""
    assert prober.UNMEASURED_REASONS | prober.MEASURED_ONLY_REASONS == prober.REASONS
    assert not (prober.UNMEASURED_REASONS & prober.MEASURED_ONLY_REASONS)


def test_a_reason_that_measured_nothing_never_arrives_with_a_measured_state():
    """The accuracy rule, asserted over the errno table rather than one case at
    a time.

    This exists because of a mutation that survived. The suite checked the
    *reason* on the unauthorised path and never the *state*, so swapping
    not_tested for no_response there kept all 112 tests green while the product
    reported a reachability finding for a target it had refused to probe.
    """
    for state, reason in prober._ERRNO_STATES.values():
        if reason in prober.UNMEASURED_REASONS:
            assert state == prober.STATE_NOT_TESTED, (
                f"{reason} measured nothing but arrived as {state}")
        if reason in prober.MEASURED_ONLY_REASONS:
            assert state in prober.MEASURED_STATES, (
                f"{reason} is something the target did but arrived as {state}")


def test_an_unauthorised_port_measured_nothing_and_says_so(con):
    """The one that the surviving mutation walked through. Assert the state and
    the measured flag, not only the reason: a reason is a label, and it is the
    state the rest of the product reads."""
    authorise(con, V4)
    result, connect = probe(con, [V4, OTHER_V4], [80])
    refused = [r for r in result.results if r.target == OTHER_V4]
    assert refused, "the unauthorised target vanished from the results instead"
    for row in refused:
        assert row.reason == prober.REASON_NO_AUTHORIZATION
        assert row.state == prober.STATE_NOT_TESTED
        assert not row.measured
        assert row.connect_ms is None


def test_no_result_anywhere_pairs_an_unmeasured_reason_with_a_finding(con):
    """The same invariant over a whole run rather than one row, so a future
    path that builds a Result by hand is covered too."""
    authorise(con, V4)
    result, _ = probe(con, [V4, OTHER_V4, "not-an-address", "::1"],
                      [80, 0, 70000, "eighty"], connect=RefusingConnect())
    for row in result.results:
        if row.reason in prober.UNMEASURED_REASONS:
            assert row.state == prober.STATE_NOT_TESTED, (
                f"{row.target} {row.family} port {row.port}: "
                f"{row.reason} measured nothing but reads as {row.state}")
            assert not row.measured


def test_no_state_name_is_a_conclusion():
    """`docs/PRODUCT.md` section 5 and the writing rules. A state says what
    was observed. There is no filtered, no open, no secure."""
    for state in prober.STATES:
        assert state not in {"open", "closed", "filtered", "secure", "blocked",
                             "reachable", "unreachable"}


def test_the_errno_table_did_not_lose_an_entry_to_a_missing_platform_name():
    """The table is built with `hasattr`, so a name this platform does not
    define is skipped. That is the safe direction, but losing ECONNREFUSED
    quietly would turn every refusal into an unclassified not_tested and
    nobody would notice. So the ones that decide a state are pinned."""
    for name in ("ECONNREFUSED", "ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH",
                 "EACCES", "EPERM", "EAFNOSUPPORT", "EADDRNOTAVAIL"):
        assert hasattr(errno, name), f"{name} is missing on {sys.platform}"
        assert getattr(errno, name) in prober._ERRNO_STATES, name
    assert prober._ERRNO_STATES[errno.ECONNREFUSED][0] == prober.STATE_REFUSED


# =========================================================== what a connect saw

def test_a_completed_connect_is_the_only_thing_called_succeeded(con):
    authorise(con, V4)
    result, connect = probe(con, [V4], [443], connect=FakeConnect({443: 0.010}))
    row = [r for r in result.results if r.family == "v4"][0]
    assert row.state == prober.STATE_CONNECTED
    assert row.reason is None
    assert row.connect_ms == pytest.approx(10.0)
    assert connect.calls == [(V4, "v4", 443)]


def test_a_refusal_is_a_refusal(con):
    authorise(con, V4)
    result, _ = probe(con, [V4], [443],
                      connect=FakeConnect({443: ConnectionRefusedError(
                          errno.ECONNREFUSED, "refused")}))
    row = family_rows(result, "v4")[0]
    assert row.state == prober.STATE_REFUSED
    assert row.reason is None
    assert row.os_errno == errno.ECONNREFUSED
    assert row.connect_ms is None


def test_our_timeout_and_the_kernels_are_both_no_response_and_still_distinct(con):
    """Both mean nothing came back. Which clock gave up is in the reason, so
    the record can tell a five second wait from a kernel that spent two
    minutes on SYN retries."""
    authorise(con, V4)

    async def hangs(target, family, port):
        await asyncio.Event().wait()

    result, _ = probe(con, [V4], [80], connect=hangs, timeout=0.05)
    ours = family_rows(result, "v4")[0]
    assert (ours.state, ours.reason) == (prober.STATE_NO_RESPONSE,
                                        prober.REASON_TIMEOUT_EXPIRED)
    assert ours.os_errno is None

    result, _ = probe(con, [V4], [80],
                      connect=FakeConnect({80: os_error("ETIMEDOUT")}))
    kernels = family_rows(result, "v4")[0]
    assert (kernels.state, kernels.reason) == (prober.STATE_NO_RESPONSE,
                                              prober.REASON_OS_TIMEOUT)
    assert kernels.os_errno == errno.ETIMEDOUT
    assert ours.reason != kernels.reason


@pytest.mark.parametrize("name,reason", [
    ("EHOSTUNREACH", prober.REASON_HOST_UNREACHABLE),
    ("ENETUNREACH", prober.REASON_NETWORK_UNREACHABLE),
    ("EHOSTDOWN", prober.REASON_HOST_UNREACHABLE),
    ("ENETDOWN", prober.REASON_NETWORK_UNREACHABLE),
])
def test_an_unreachable_error_is_not_tested_and_never_a_finding(con, name, reason):
    """The rule that keeps this honest. An ICMP unreachable and a missing route
    on our own side arrive here as the same errno, so promoting either to a
    measurement would state something about a customer's host on the strength
    of our own network. `docs/PRODUCT.md` 4b is a retraction of that shape."""
    authorise(con, V4)
    result, _ = probe(con, [V4], [80], connect=FakeConnect({80: os_error(name)}))
    row = family_rows(result, "v4")[0]
    assert row.state == prober.STATE_NOT_TESTED
    assert row.reason == reason
    assert row.measured is False


def test_our_own_packet_filter_dropping_the_packet_is_not_a_finding_about_them(con):
    """EPERM is our own machine. The kernel returns it when one of its own
    packet filter's hooks drops the packet on the way out (`nf_hook_slow` in
    net/netfilter/core.c, "-EPERM for NF_DROP", read 2026-10-12). Reporting
    the target as refused would be reporting our own firewall as theirs."""
    authorise(con, V4)
    result, _ = probe(con, [V4], [80], connect=FakeConnect({80: os_error("EPERM")}))
    row = family_rows(result, "v4")[0]
    assert row.state == prober.STATE_NOT_TESTED
    assert row.reason == prober.REASON_LOCAL_PERMISSION_DENIED


@pytest.mark.parametrize("target,family", [(V6, "v6"), (V4, "v4")])
def test_a_permission_error_on_connect_names_nobodys_side(con, target, family):
    """EACCES is not ours alone. The kernel hands a socket EACCES for an
    ICMPv6 destination unreachable whose code is administratively prohibited,
    policy failed or reject route (`tab_unreach` in net/ipv6/icmp.c, read
    2026-10-12), whoever on the way sent it. A server whose firewall rejects
    that way answers a v6 connect so, and the row said
    local_permission_denied: our own side, for a refusal the target sent
    (docs/RECORD.md 4.220, 4.454).

    Still no finding. The same errno is a policy on our own machine saying
    no, so the reason says what the kernel said and whose side it was is not
    said at all."""
    authorise(con, target)
    result, _ = probe(con, [target], [80], connect=FakeConnect({80: os_error("EACCES")}))
    row = family_rows(result, family)[0]
    assert row.state == prober.STATE_NOT_TESTED
    assert row.measured is False
    assert row.reason == prober.REASON_PERMISSION_DENIED
    assert "local" not in row.reason


def test_the_permission_reason_is_one_of_the_closed_set_and_never_measured():
    assert prober.REASON_PERMISSION_DENIED == "permission_denied"
    assert prober.REASON_PERMISSION_DENIED in prober.REASONS
    assert prober.REASON_PERMISSION_DENIED in prober.UNMEASURED_REASONS
    assert prober.REASON_PERMISSION_DENIED not in prober.MEASURED_ONLY_REASONS
    assert prober.REASON_PERMISSION_DENIED != prober.REASON_LOCAL_PERMISSION_DENIED


@pytest.mark.parametrize("name,reason", [
    ("EAFNOSUPPORT", prober.REASON_LOCAL_FAMILY_UNSUPPORTED),
    ("EPFNOSUPPORT", prober.REASON_LOCAL_FAMILY_UNSUPPORTED),
    ("EADDRNOTAVAIL", prober.REASON_LOCAL_ADDRESS_UNAVAILABLE),
])
def test_a_vantage_point_with_no_address_in_a_family_reports_not_tested(
        con, name, reason):
    """The case this project has already been burned by. A prober with no IPv6
    must report not tested for every v6 port, never a state a UI could colour.
    The v4 half of the same run is unaffected, which is the point."""
    authorise(con, V4, V6)
    connect = FakeConnect({})

    async def v6_fails_locally(target, family, port):
        if family == "v6":
            raise os_error(name)
        return await connect(target, family, port)

    result, _ = probe(con, [V4, V6], [80, 443], connect=v6_fails_locally)
    for row in family_rows(result, "v6"):
        assert row.state == prober.STATE_NOT_TESTED
        assert row.reason == reason
    assert all(r.state == prober.STATE_CONNECTED for r in family_rows(result, "v4"))


@pytest.mark.parametrize("problem", [
    OSError(errno.EINVAL, "invalid"),
    OSError(999999, "a number no table has"),
    OSError(None, "an OSError with no errno at all"),
    ValueError("the primitive itself has a bug"),
    RuntimeError("something unexpected"),
])
def test_anything_unrecognised_fails_closed_to_not_tested(con, problem):
    """The default has to be not tested. A kernel or a bug we have not met must
    not be able to invent a measurement."""
    authorise(con, V4)
    result, _ = probe(con, [V4], [80], connect=FakeConnect({80: problem}))
    row = family_rows(result, "v4")[0]
    assert row.state == prober.STATE_NOT_TESTED
    assert row.reason == prober.REASON_UNCLASSIFIED_ERROR


def test_a_resolver_error_is_not_read_through_the_errno_table(con):
    """socket.gaierror is an OSError whose number is a getaddrinfo code, not a
    system errno, and the two spaces collide. Without the explicit branch,
    gaierror(1) would be read as EPERM and reported as our own machine denying
    the packet, which is a different and wrong answer."""
    collision = socket.gaierror(errno.EPERM, "a getaddrinfo code, not an errno")
    state, reason, os_errno = prober.classify(collision)
    assert (state, reason) == (prober.STATE_NOT_TESTED,
                              prober.REASON_RESOLVER_INVOLVED)
    assert os_errno is None
    assert prober._ERRNO_STATES[errno.EPERM][1] == prober.REASON_LOCAL_PERMISSION_DENIED


def test_a_cancellation_is_not_swallowed_as_a_result(con):
    """CancelledError is a BaseException and has to keep travelling, or a run
    being torn down would report a wall of not_tested rows as if it had
    finished."""
    authorise(con, V4)

    async def cancelled(target, family, port):
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        probe(con, [V4], [80], connect=cancelled)


# ==================================================== v4 and v6 are never mixed

@pytest.mark.parametrize("addresses", [[], [V4], [V6], [V4, V6]])
def test_both_families_always_appear_in_the_output(con, addresses):
    """The property the whole module is shaped around: a consumer can never
    find a family missing and fill it in from the other one."""
    authorise(con, *addresses)
    result, _ = probe(con, addresses, [80, 443])
    for family in prober.FAMILIES:
        assert family_rows(result, family), f"{family} has no answer at all"


def test_a_host_with_no_address_in_a_family_is_not_tested_there(con):
    authorise(con, V4)
    result, connect = probe(con, [V4], [80, 443])
    for row in family_rows(result, "v6"):
        assert row.state == prober.STATE_NOT_TESTED
        assert row.reason == prober.REASON_NO_ADDRESS_IN_FAMILY
        assert row.target is None
    assert connect.families() == {"v4"}


def test_authorising_one_family_never_probes_the_other(con):
    """`app/authz.py` keeps v4 and v6 in separate rows. This is that fact
    reaching the socket: the v6 address is refused by the gate and no packet
    leaves for it."""
    host_id, _ = store.add_host(con, "box")
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    result, connect = probe(con, [V4, V6], [80])
    assert states(result)[("v4", 80)] == prober.STATE_CONNECTED
    assert states(result)[("v6", 80)] == prober.STATE_NOT_TESTED
    assert reasons(result)[("v6", 80)] == prober.REASON_NO_AUTHORIZATION
    assert connect.families() == {"v4"}


def test_each_address_is_probed_on_its_own_family(con):
    authorise(con, V4, V6)
    _result, connect = probe(con, [V4, V6], [80])
    assert sorted(connect.calls) == sorted([(V4, "v4", 80), (V6, "v6", 80)])


def test_the_primitive_refuses_a_family_that_disagrees_with_its_address():
    """Measured on 2026-08-15, and it is the reason this guard exists: an
    AF_INET6 socket handed the text 127.0.0.1 resolves it to the v4-mapped
    form and returns a real answer. A v4 measurement would have been filed
    under v6, silently."""
    with pytest.raises(prober.TargetMismatch):
        run(prober.tcp_connect("127.0.0.1", "v6", 9))
    with pytest.raises(prober.TargetMismatch):
        run(prober.tcp_connect("::1", "v4", 9))


@pytest.mark.parametrize("target", ["localhost", "example.com", "", "not an address",
                                    None, 12345, b"127.0.0.1"])
def test_the_primitive_refuses_anything_that_is_not_a_literal_address(target):
    """A name would be resolved by the connect call itself, so a packet could
    leave for an address the gate never saw."""
    with pytest.raises(prober.TargetMismatch):
        run(prober.tcp_connect(target, "v4", 9))


def test_a_hostname_target_is_not_tested_and_never_resolved(con):
    """It appears under an unknown family, so it can never be read as either
    family's answer, and both real families still get their own row."""
    result, connect = probe(con, ["example.com"], [80], connect=RefusingConnect())
    unknown = [r for r in result.results if r.family == prober.FAMILY_UNKNOWN]
    assert [r.reason for r in unknown] == [prober.REASON_TARGET_NOT_AN_ADDRESS]
    assert unknown[0].state == prober.STATE_NOT_TESTED
    assert connect.calls == []
    for family in prober.FAMILIES:
        assert family_rows(result, family)


@pytest.mark.parametrize("address", [
    "", " ", "not an address", "1.2.3.4.5", "185.199.108.153/32",
    "10.0.0.1", "127.0.0.1", "::1", "0.0.0.0", "100.64.0.1",
    "::ffff:185.199.108.153", None, 12345, ["1.2.3.4"],
])
def test_a_target_that_cannot_be_probed_sends_nothing_and_still_appears(con, address):
    """Including our own loopback and private ranges, so the prober cannot be
    aimed at the network it runs on."""
    result, connect = probe(con, [address], [80], connect=RefusingConnect())
    assert connect.calls == []
    assert all(r.state == prober.STATE_NOT_TESTED for r in result.results)
    assert any(r.family == prober.FAMILY_UNKNOWN for r in result.results)


def test_one_address_given_twice_is_probed_once(con):
    authorise(con, V4)
    _result, connect = probe(con, [V4, V4, "185.199.108.153"], [80])
    assert connect.calls == [(V4, "v4", 80)]


def test_a_bare_string_where_a_list_belongs_is_refused_loudly(con):
    """It would iterate into characters and answer nothing about anything,
    which is the quiet failure shape `docs/RECORD.md` 4.45 is about."""
    with pytest.raises(TypeError):
        run(prober.Prober(connect=RefusingConnect()).run(con, V4, [80]))
    with pytest.raises(TypeError):
        run(prober.Prober(connect=RefusingConnect()).run(con, [V4], "80"))
    with pytest.raises(TypeError):
        run(prober.Prober(connect=RefusingConnect()).run(con, [V4], 80))


# ====================================================== the authorisation gate

def test_an_unauthorised_target_sends_nothing_and_says_so(con):
    result, connect = probe(con, [V4], [80, 443], connect=RefusingConnect())
    assert connect.calls == []
    for row in family_rows(result, "v4"):
        assert row.state == prober.STATE_NOT_TESTED
        assert row.reason == prober.REASON_NO_AUTHORIZATION
    assert len(result.results) == 4


def test_a_lapsed_authorisation_sends_nothing(con):
    authorise(con, V4)
    lapsed = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS + 60)
    result, connect = probe(con, [V4], [80], connect=RefusingConnect(),
                            gate_clock=lapsed)
    assert connect.calls == []
    assert reasons(result)[("v4", 80)] == prober.REASON_NO_AUTHORIZATION


def test_a_revoked_authorisation_sends_nothing(con):
    authorise(con, V4)
    authz.revoke(con, V4, now=NOW)
    _result, connect = probe(con, [V4], [80], connect=RefusingConnect())
    assert connect.calls == []


def test_revoking_a_host_stops_its_probes(con):
    host_id = authorise(con, V4)
    store.revoke_host(con, "box")
    assert host_id is not None
    _result, connect = probe(con, [V4], [80], connect=RefusingConnect())
    assert connect.calls == []


def test_the_gate_is_asked_again_before_every_connect(con):
    """The per-port choice, proved rather than asserted. The authorisation is
    revoked from inside the third connect, so a run that checked once at the
    start would keep sending for the remaining ports.

    Run against a version that checked once per run, this fails with all
    twenty ports connected and no not_tested row.
    """
    authorise(con, V4)
    ports = list(range(1, 21))
    sent = []

    async def revoke_part_way(target, family, port):
        sent.append(port)
        if len(sent) == 3:
            authz.revoke(con, V4, now=NOW)
        return 0.001

    result, _ = probe(con, [V4], ports, connect=revoke_part_way, concurrency=1)
    assert len(sent) == 3, f"packets kept leaving after the revocation: {sent}"
    stopped = [r for r in family_rows(result, "v4")
               if r.reason == prober.REASON_NO_AUTHORIZATION]
    assert len(stopped) == len(ports) - 3
    # The state, not only the reason. This is the line a mutation walked
    # through: swapping not_tested for no_response here left the reason intact
    # and the whole suite green, while every port refused by the gate was
    # reported as a target that stayed silent. The reason is a label and the
    # state is what the rest of the product reads.
    for row in stopped:
        assert row.state == prober.STATE_NOT_TESTED
        assert not row.measured
        assert row.connect_ms is None
    # And nothing vanished: every port still has an answer.
    assert len(family_rows(result, "v4")) == len(ports)


def test_the_gate_refusing_one_target_does_not_take_the_run_down(con):
    """One address authorised, one not. The unauthorised one is answered, not
    raised, and the authorised one is still measured."""
    host_id, _ = store.add_host(con, "box")
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    result, connect = probe(con, [V4, OTHER_V4], [80])
    assert connect.calls == [(V4, "v4", 80)]
    by_target = {r.target: r for r in family_rows(result, "v4")}
    assert by_target[V4].state == prober.STATE_CONNECTED
    assert by_target[OTHER_V4].reason == prober.REASON_NO_AUTHORIZATION


def test_the_address_probed_is_the_one_the_gate_returned(con):
    """The gate canonicalises. A run given the long spelling of a v6 address
    must connect to, and record, the canonical one, or two spellings of one
    address become two histories."""
    authorise(con, V6)
    long_form = "2606:50c0:8000:0000:0000:0000:0000:0153"
    _result, connect = probe(con, [long_form], [443])
    assert connect.calls == [(V6, "v6", 443)]


def test_the_prober_never_queries_the_authorisation_tables_itself():
    """`tests/test_authz.py` scans the whole repository for this, and this is
    the same rule stated where a reader of the prober will see it."""
    source = pathlib.Path(prober.__file__).read_text(encoding="utf-8")
    assert "authorizations" not in source
    assert "authz_challenges" not in source

    # The prober asks an authority and never the database. Since the gate
    # became something that can travel to a vantage host, "it calls
    # require_probe_authorization" stopped being the shape to look for, and
    # this is the shape that replaced it.
    assert "authority.require(" in source

    # And it may not reach past the authority to the non-raising form. That
    # returns a Decision, so a caller can read `.allowed` and throw away the
    # canonical target, which is how the address probed stops being the
    # address approved. The one place that wants a boolean goes through
    # `_allows`, which asks the authority.
    assert "may_probe" not in source


# ================================================================ ports

def test_an_empty_port_list_sends_nothing_and_records_the_run(con):
    authorise(con, V4)
    result, connect = probe(con, [V4], [], connect=RefusingConnect())
    assert connect.calls == []
    assert result.results == ()
    row = con.execute("SELECT * FROM probe_runs WHERE id = ?", (result.id,)).fetchone()
    assert row["finished_at"] is not None


def test_a_duplicated_port_is_probed_once(con):
    authorise(con, V4)
    _result, connect = probe(con, [V4], [80, 80, 443, 80])
    assert connect.ports == [80, 443]


@pytest.mark.parametrize("port", [0, -1, 65536, 70000, 2 ** 31])
def test_a_port_outside_the_range_is_not_tested_and_never_reaches_a_socket(
        con, port):
    """Verified on 2026-08-15 rather than assumed: the socket layer raises
    OverflowError for 65536 and EADDRNOTAVAIL for 0. Neither is a
    measurement, so both are refused before a socket exists."""
    authorise(con, V4)
    result, connect = probe(con, [V4], [port], connect=RefusingConnect())
    assert connect.calls == []
    row = family_rows(result, "v4")[0]
    assert row.state == prober.STATE_NOT_TESTED
    assert row.reason == prober.REASON_PORT_OUT_OF_RANGE
    assert row.port == port


@pytest.mark.parametrize("port", ["80", None, 1.5, True, False, [80], b"80"])
def test_something_that_is_not_a_port_is_not_tested(con, port):
    """True is an int in Python and would otherwise become port 1."""
    authorise(con, V4)
    result, connect = probe(con, [V4], [port], connect=RefusingConnect())
    assert connect.calls == []
    row = family_rows(result, "v4")[0]
    assert row.reason == prober.REASON_PORT_NOT_AN_INTEGER
    assert row.port is None


@pytest.mark.parametrize("port", [1, 65535])
def test_the_ends_of_the_range_are_probeable(con, port):
    authorise(con, V4)
    _result, connect = probe(con, [V4], [port])
    assert connect.ports == [port]


def test_a_refused_port_still_gets_an_answer_in_both_families(con):
    """Nothing goes missing between the request and the answer."""
    authorise(con, V4)
    result, _ = probe(con, [V4], [80, 0])
    assert states(result)[("v4", 0)] == prober.STATE_NOT_TESTED
    assert states(result)[("v6", 0)] == prober.STATE_NOT_TESTED
    assert reasons(result)[("v4", 0)] == prober.REASON_PORT_OUT_OF_RANGE
    # In a family with no address the port's own problem is still the reason,
    # because a port that is not a port is not one in either family.
    assert reasons(result)[("v6", 0)] == prober.REASON_PORT_OUT_OF_RANGE


def test_the_order_of_the_output_is_deterministic(con):
    authorise(con, V4)
    first, _ = probe(con, [V4], [443, 80, 0, "x"])
    second, _ = probe(con, [V4], [80, "x", 443, 0])
    assert [(r.family, r.port) for r in first.results] == \
           [(r.family, r.port) for r in second.results]


def test_the_ports_are_probed_in_ascending_order(con):
    authorise(con, V4)
    _result, connect = probe(con, [V4], [443, 22, 80], concurrency=1)
    assert connect.ports == [22, 80, 443]


# ============================================================== the pace

class FakeTime:
    """A clock the pacing can be measured against, and a sleep that moves it.

    The real pace is 40 a second and a test that waited for it would take
    minutes, so the clock is fake and the sleep advances it. `asyncio.sleep(0)`
    still yields, so the other coroutines interleave exactly as they would.
    """

    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    async def sleep(self, seconds):
        self.now += seconds
        await asyncio.sleep(0)


def test_every_connect_takes_a_token_from_the_pace(con):
    """40 a second, from `docs/PRODUCT.md` section 5, and no burst: the
    bucket holds one token at birth and one more every 25 ms, so 120 connects
    cannot happen in less than 119 intervals of clock. If the pacing were
    skipped the clock would not move at all, which is what this measures.
    Until 2026-09-12 the bucket started full, forty at once, and this line
    allowed it."""
    authorise(con, V4)
    clock = FakeTime()
    ports = list(range(1, 121))
    prober_object = prober.Prober(connect=FakeConnect(), clock=clock.monotonic,
                                 sleep=clock.sleep, rate_per_second=40.0)
    run(prober_object.run(con, [V4], ports, gate_clock=NOW))
    assert clock.now >= (len(ports) - 1) / 40.0


def test_two_runs_against_one_host_share_the_pace_rather_than_doubling_it(con):
    """Concurrent runs are the case a per-run limiter gets wrong. The bucket
    lives on the Prober and is keyed by the host, so the second run does not
    get its own 40 a second."""
    authorise(con, V4)
    clock = FakeTime()
    connect = FakeConnect()
    prober_object = prober.Prober(connect=connect, clock=clock.monotonic,
                                  sleep=clock.sleep, rate_per_second=40.0)
    ports = list(range(1, 41))

    async def both():
        return await asyncio.gather(
            prober_object.run(con, [V4], ports, host_id=1, gate_clock=NOW),
            prober_object.run(con, [V4], ports, host_id=1, gate_clock=NOW))

    first, second = run(both())
    assert len(connect.calls) == 80
    assert clock.now >= (80 - 1) / 40.0
    # Both runs are complete records, not two halves of one.
    for result in (first, second):
        assert len(family_rows(result, "v4")) == len(ports)


def test_the_pace_is_counted_against_the_host_not_the_address():
    """A host's v4 and v6 addresses are one host, so they share one bucket.
    `docs/PRODUCT.md` section 5 says per host."""
    assert prober.Prober.pace_key(7, [V4]) == prober.Prober.pace_key(7, [V6])
    assert prober.Prober.pace_key(7, [V4]) != prober.Prober.pace_key(8, [V4])
    # With no host id the addresses are the key, in a stable order.
    assert prober.Prober.pace_key(None, [V4, V6]) == \
           prober.Prober.pace_key(None, [V6, V4])


def test_a_rate_or_concurrency_that_makes_no_sense_is_refused_at_the_door():
    for kwargs in ({"concurrency": 0}, {"concurrency": -1},
                   {"rate_per_second": 0}, {"rate_per_second": -5}):
        with pytest.raises(ValueError):
            prober.Prober(**kwargs)


# ========================================================== the concurrency bound

def test_the_number_of_connects_in_flight_never_passes_the_bound(con):
    authorise(con, V4)
    state = {"in_flight": 0, "peak": 0}

    async def watched(target, family, port):
        state["in_flight"] += 1
        state["peak"] = max(state["peak"], state["in_flight"])
        # Two yields, so the loop has every chance to start more than it should.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        state["in_flight"] -= 1
        return 0.001

    # The pace is deliberately out of the way here, because this test is about
    # the other bound. The pace has its own tests above.
    prober_object = prober.Prober(connect=watched, concurrency=4,
                                  rate_per_second=1_000_000.0)
    run(prober_object.run(con, [V4], list(range(1, 41)), gate_clock=NOW))
    assert state["peak"] <= 4


def test_a_silent_port_does_not_stall_the_others(con):
    """The reason the connects are concurrent at all. Port 80 answers nothing
    and holds a slot until the timeout, and the other ports still finish."""
    authorise(con, V4)

    async def one_hangs(target, family, port):
        if port == 80:
            await asyncio.Event().wait()
        return 0.001

    prober_object = prober.Prober(connect=one_hangs, concurrency=2, timeout=0.05,
                                 rate_per_second=1_000_000.0)
    result = run(prober_object.run(con, [V4], [22, 80, 443, 8080],
                                   gate_clock=NOW))
    got = states(result)
    assert got[("v4", 80)] == prober.STATE_NO_RESPONSE
    for port in (22, 443, 8080):
        assert got[("v4", port)] == prober.STATE_CONNECTED


# ================================================================== SI-7

# Every name that would transfer a byte, negotiate TLS, or resolve a name. The
# scan below walks the prober's syntax tree, so a name in a comment does not
# match and a name in code cannot hide.
#
# **This list was file-wide until the certificate read landed on 2026-08-16.**
# It carried a note saying the TLS card would not relax it, on the reading that
# a handshake belongs in its own module. The handshake was built here instead,
# so the guard is now scoped rather than deleted: the whole list still applies
# to the whole file except the three functions named below, and those three are
# checked in `tests/test_prober_tls.py` against the same list minus the four
# TLS names they need. Nowhere in the prober may transfer a byte, and exactly
# three named functions may say ssl. A test there asserts the two scans between
# them cover every name in the file, so nothing can fall between them.
BANNED_NAMES = {
    "send", "sendall", "sendto", "sendmsg", "sendfile", "write", "writelines",
    "recv", "recv_into", "recvfrom", "recvmsg", "read", "readline", "readinto",
    "sock_recv", "sock_recv_into", "sock_sendall", "sock_sendfile",
    "wrap_socket", "start_tls", "SSLContext", "ssl", "getpeercert",
    "open_connection", "create_connection", "getaddrinfo", "gethostbyname",
}

# The only three functions in the prober allowed to name TLS at all: the one
# that builds the context, the one that does the handshake, and the one that
# reads an SSLError's type to turn it into a typed reason. Everything else in
# the file, the engine and the storage included, stays connect only.
TLS_FUNCTIONS = {"_certificate_reading_context", "_read_certificate_der",
                 "classify_tls"}


def _names_in(path, skip=()):
    """Every identifier the file actually uses: attributes, plain names and the
    functions it defines.

    `skip` names functions not to descend into, so one guard can cover a file
    except for the parts another guard covers more tightly.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    skipped = []

    def walk(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef,
                                  ast.ClassDef)):
                names.add(child.name)
                if child.name in skip:
                    skipped.append(child.name)
                    continue
            if isinstance(child, ast.Attribute):
                names.add(child.attr)
            elif isinstance(child, ast.Name):
                names.add(child.id)
            walk(child)

    walk(tree)
    return names, set(skipped)


def test_the_scan_below_actually_reads_the_prober():
    """`docs/RECORD.md` 4.46: a ban list nothing reads is not a guard. This is
    the canary, so a scan that has stopped seeing the file fails here rather
    than passing silently."""
    names, _skipped = _names_in(pathlib.Path(prober.__file__))
    for expected in ("sock_connect", "socket", "close", "tcp_connect",
                     "require", "NotAuthorized"):
        assert expected in names, f"the walk did not find {expected}"
    assert len(names) > 50


def test_the_prober_names_nothing_that_transfers_a_byte():
    """SI-7 as a structural fact rather than a promise."""
    names, _skipped = _names_in(pathlib.Path(prober.__file__),
                                skip=TLS_FUNCTIONS)
    found = names & BANNED_NAMES
    assert found == set(), (
        f"the prober names {sorted(found)}, which would transfer bytes,"
        " negotiate TLS or resolve a name")


def test_the_two_tls_functions_are_still_there_to_be_skipped():
    """The half that makes the scoping honest. If a TLS function is renamed or
    deleted the scan would silently start covering nothing, or silently start
    letting a whole file say ssl."""
    _names, skipped = _names_in(pathlib.Path(prober.__file__),
                                skip=TLS_FUNCTIONS)
    assert skipped == TLS_FUNCTIONS, (
        f"the scan skipped {sorted(skipped)} and not {sorted(TLS_FUNCTIONS)}")


def test_the_scoped_scan_would_still_catch_ssl_outside_those_two_functions(tmp_path):
    """Prove the narrowing did not turn the guard off. A file that says ssl in
    a third function still fails."""
    offender = tmp_path / "offender.py"
    offender.write_text("import ssl\n"
                        "def _certificate_reading_context():\n"
                        "    return ssl.SSLContext()\n"
                        "def somewhere_else():\n"
                        "    return ssl.SSLContext()\n", encoding="utf-8")
    names, _skipped = _names_in(offender, skip=TLS_FUNCTIONS)
    assert names & BANNED_NAMES == {"ssl", "SSLContext"}


def test_the_ban_list_would_catch_a_violation(tmp_path):
    """And the other half of 4.46: prove the scan can fail. A scanner that
    matches nothing passes forever."""
    offender = tmp_path / "offender.py"
    offender.write_text("import socket\n"
                        "def go(s):\n"
                        "    s.sendall(b'GET / HTTP/1.0\\r\\n')\n"
                        "    return s.recv(64)\n", encoding="utf-8")
    names, _skipped = _names_in(offender)
    assert names & BANNED_NAMES == {"sendall", "recv"}


def test_a_socket_that_screams_when_touched_still_completes_a_probe():
    """The behavioural half. If anything in the primitive transferred a byte
    this socket would raise, and the connect below would not return a
    duration."""
    touched = []

    class LoudSocket(socket.socket):
        def send(self, *args, **kwargs):
            touched.append("send")
            raise AssertionError("the prober sent bytes")

        sendall = send
        sendto = send

        def recv(self, *args, **kwargs):
            touched.append("recv")
            raise AssertionError("the prober read bytes")

        recv_into = recv

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    original = prober.socket.socket
    prober.socket.socket = LoudSocket
    try:
        elapsed = run(prober.tcp_connect("127.0.0.1", "v4", port))
    finally:
        prober.socket.socket = original
        listener.close()
    assert elapsed >= 0.0
    assert touched == []


# ======================================================= the real loopback tests

def _ipv6_loopback_problem():
    """Why ::1 cannot be used here, or None when it can. Actually binding it,
    because `socket.has_ipv6` says the build supports IPv6 and not that this
    machine has a working loopback."""
    if not socket.has_ipv6:
        return "python was built without IPv6 support"
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError as exc:
        return f"creating an AF_INET6 socket failed: errno {exc.errno}"
    try:
        sock.bind(("::1", 0))
        sock.listen(1)
    except OSError as exc:
        return f"binding ::1 failed: errno {exc.errno}"
    finally:
        sock.close()
    return None


BANNER = "!" * 72


def announce_no_ipv6(problem: str) -> str:
    """Say it twice and say it loudly.

    A skipped test is one grey letter in pytest's output and nobody reads it.
    The v6 half of a prober's suite not running is the same shape of quiet
    failure as the `.exists()` guard that hid a missing favicon for weeks
    (`docs/RECORD.md` 4.45), so it goes in the warnings summary, which pytest
    always prints, and on stderr as a banner.
    """
    message = ("THE IPv6 HALF OF THE PROBER SUITE DID NOT RUN ON THIS MACHINE: "
               + problem + ". The v4 results below say nothing about v6.")
    warnings.warn(message, stacklevel=2)
    print(f"\n{BANNER}\n{message}\n{BANNER}", file=sys.stderr)
    return message


def require_ipv6_loopback():
    problem = _ipv6_loopback_problem()
    if problem is None:
        return
    pytest.skip(announce_no_ipv6(problem))


def test_the_ipv6_skip_is_loud(recwarn, capsys):
    """The guard on the guard. This one always runs, on a machine with IPv6 or
    without, so the loudness cannot rot unnoticed."""
    message = announce_no_ipv6("forced, so that this test can watch it happen")
    assert "IPv6" in message
    assert [str(w.message) for w in recwarn] == [message]
    assert BANNER in capsys.readouterr().err


def test_this_machine_says_whether_it_has_an_ipv6_loopback():
    """Either answer is fine and both are assertions. A detector that returns
    something unusable would otherwise make every v6 test skip forever."""
    problem = _ipv6_loopback_problem()
    if problem is None:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.close()
    else:
        assert isinstance(problem, str) and problem


class Listener:
    """A real TCP listener on loopback, and what it received."""

    def __init__(self, family):
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def accept_and_read(self, timeout=1.0):
        self.sock.settimeout(timeout)
        accepted, _peer = self.sock.accept()
        accepted.settimeout(timeout)
        try:
            return accepted.recv(64)
        finally:
            accepted.close()

    def close(self):
        self.sock.close()


def closed_loopback_port(family):
    """A port nothing is listening on: bind it, note it, let it go."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def observe(target, family, port, timeout=2.0):
    """The production path from the socket to the state, minus the gate. The
    gate refuses loopback and is right to, so a real socket can only be
    exercised on this side of it."""
    return run(prober._measure(prober.tcp_connect, target, family, port, timeout))


def test_a_real_listener_on_127_0_0_1_is_connect_succeeded():
    listener = Listener(socket.AF_INET)
    try:
        state, reason, connect_ms, os_errno = observe("127.0.0.1", "v4",
                                                      listener.port)
    finally:
        listener.close()
    assert (state, reason, os_errno) == (prober.STATE_CONNECTED, None, None)
    assert connect_ms is not None and connect_ms >= 0.0


def test_a_real_listener_receives_no_bytes_before_the_close():
    """SI-7 measured from the other end of the wire. The listener reads until
    EOF and must see nothing at all."""
    listener = Listener(socket.AF_INET)
    try:
        state, _reason, _ms, _errno = observe("127.0.0.1", "v4", listener.port)
        assert state == prober.STATE_CONNECTED
        assert listener.accept_and_read() == b""
    finally:
        listener.close()


def test_a_closed_port_on_127_0_0_1_is_connect_refused():
    port = closed_loopback_port(socket.AF_INET)
    state, reason, _ms, os_errno = observe("127.0.0.1", "v4", port)
    assert (state, reason) == (prober.STATE_REFUSED, None)
    assert os_errno == errno.ECONNREFUSED


def test_a_real_listener_on_ipv6_loopback_is_connect_succeeded():
    require_ipv6_loopback()
    listener = Listener(socket.AF_INET6)
    try:
        state, reason, connect_ms, _errno = observe("::1", "v6", listener.port)
        assert (state, reason) == (prober.STATE_CONNECTED, None)
        assert connect_ms is not None
        assert listener.accept_and_read() == b""
    finally:
        listener.close()


def test_a_closed_port_on_ipv6_loopback_is_connect_refused():
    require_ipv6_loopback()
    port = closed_loopback_port(socket.AF_INET6)
    state, _reason, _ms, os_errno = observe("::1", "v6", port)
    assert state == prober.STATE_REFUSED
    assert os_errno == errno.ECONNREFUSED


def test_the_two_families_are_measured_by_two_separate_sockets():
    """Both loopbacks at once, so a v6 answer that was really a v4 socket
    cannot pass. The ports are different by construction and each family only
    listens on its own."""
    require_ipv6_loopback()
    v4 = Listener(socket.AF_INET)
    v6 = Listener(socket.AF_INET6)
    try:
        assert observe("127.0.0.1", "v4", v4.port)[0] == prober.STATE_CONNECTED
        assert observe("::1", "v6", v6.port)[0] == prober.STATE_CONNECTED
        # The other family's port is not listening on this family, so it is
        # refused rather than quietly answered by the wrong socket.
        assert observe("127.0.0.1", "v4", v6.port)[0] == prober.STATE_REFUSED
        assert observe("::1", "v6", v4.port)[0] == prober.STATE_REFUSED
    finally:
        v4.close()
        v6.close()


def test_a_real_connect_reaches_no_resolver(monkeypatch):
    """Measured on 2026-08-15: a literal address that matches its socket family
    never reaches getaddrinfo. That is what makes "no name to rebind" a fact
    rather than an intention."""
    listener = Listener(socket.AF_INET)

    def refuse(*args, **kwargs):
        raise AssertionError("the prober resolved something")

    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    try:
        state, _reason, _ms, _errno = observe("127.0.0.1", "v4", listener.port)
    finally:
        listener.close()
    assert state == prober.STATE_CONNECTED


# macOS's number for the socket option that ties a socket to one interface,
# from netinet/in.h in the macOS 27.0 SDK. Python's socket module has no name
# for it.
IP_BOUND_IF = 25


def held_to_loopback(listener):
    """On macOS, tie the listener to the loopback interface, so that a full
    backlog drops a new SYN again rather than answering it.

    On macOS 27.0.1 a full backlog answers with a SYN cookie: the connect
    completes without a place in the queue, and the ACK that follows finds no
    place either and is reset. That Mac reads net.inet.tcp.syncookie as 1,
    where the published source of macOS 26 sets it to 0 (xnu-12377.121.6,
    tcp_input.c, read 2026-10-28). The same source turns cookies off for a
    listener tied to the loopback interface (TCP_SYN_COOKIE_DISABLED in
    tcp_var.h). Measured on 2026-10-28 with this test's twelve connects: not
    tied, 42 probes of 100 were reset and none went unanswered. Tied, 100 of
    100 went unanswered, and with no connect waiting 100 of 100 connected.
    Linux dropped the SYN 100 times of 100 without it, so it is left out
    there."""
    if sys.platform == "darwin":
        listener.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF,
                            socket.if_nametoindex("lo0"))


def test_a_real_timeout_against_a_socket_that_never_answers():
    """A listen backlog that is full does not answer a new SYN, which is the
    closest thing to a dropped packet that loopback offers. If it answers
    anyway the assertion below says so rather than pretending."""
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    held_to_loopback(listener)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    held = []
    try:
        # Fill the backlog without ever accepting.
        for _ in range(12):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            try:
                sock.connect_ex(("127.0.0.1", port))
            except OSError:
                pass
            held.append(sock)
        state, reason, _ms, _errno = observe("127.0.0.1", "v4", port,
                                             timeout=0.25)
        assert state in (prober.STATE_CONNECTED, prober.STATE_NO_RESPONSE)
        if state == prober.STATE_NO_RESPONSE:
            assert reason == prober.REASON_TIMEOUT_EXPIRED
    finally:
        for sock in held:
            sock.close()
        listener.close()


# ================================================================== storage

def test_a_run_is_stored_with_one_row_per_family_and_port(con):
    host_id = authorise(con, V4, V6)
    result, _ = probe(con, [V4, V6], [80, 443], host_id=host_id)
    rows = prober.run_results(con, result.id)
    assert len(rows) == len(result.results) == 4
    stored = {(r["family"], r["port"]): r["state"] for r in rows}
    assert stored == {("v4", 80): prober.STATE_CONNECTED,
                      ("v4", 443): prober.STATE_CONNECTED,
                      ("v6", 80): prober.STATE_CONNECTED,
                      ("v6", 443): prober.STATE_CONNECTED}
    for row in rows:
        assert row["measured_at"]
        assert row["state"] in prober.STATES
        assert row["reason"] is None or row["reason"] in prober.REASONS


def test_the_run_row_names_the_host_the_time_and_the_vantage(con):
    host_id = authorise(con, V4)
    result, _ = probe(con, [V4], [80], host_id=host_id, vantage="dev-laptop")
    row = con.execute("SELECT * FROM probe_runs WHERE id = ?", (result.id,)).fetchone()
    assert row["host_id"] == host_id
    assert row["vantage"] == "dev-laptop"
    assert row["started_at"] and row["finished_at"]
    assert prober.latest_run(con, host_id)["id"] == result.id


def test_the_vantage_comes_from_the_environment_and_says_when_nobody_named_it(
        monkeypatch):
    monkeypatch.delenv(prober.VANTAGE_ENV, raising=False)
    assert prober.default_vantage() == prober.UNNAMED_VANTAGE
    monkeypatch.setenv(prober.VANTAGE_ENV, "ams-1")
    assert prober.default_vantage() == "ams-1"


def test_a_not_tested_row_is_stored_with_its_reason_and_no_measurement(con):
    result, _ = probe(con, [V4], [80], connect=RefusingConnect())
    rows = prober.run_results(con, result.id)
    for row in rows:
        assert row["state"] == prober.STATE_NOT_TESTED
        assert row["reason"] in prober.REASONS
        assert row["connect_ms"] is None


def test_a_run_that_dies_half_way_does_not_read_as_measurements(con):
    """finished_at stays NULL and no result rows land, so a crashed run is
    visibly a crashed run rather than a short list of findings."""
    authorise(con, V4)

    async def dies(target, family, port):
        raise KeyboardInterrupt("the operator pressed ctrl-c")

    with pytest.raises(KeyboardInterrupt):
        probe(con, [V4], [80, 443, 8080], connect=dies)
    row = con.execute("SELECT * FROM probe_runs ORDER BY id DESC LIMIT 1").fetchone()
    assert row["finished_at"] is None
    assert prober.run_results(con, row["id"]) == []


def test_two_runs_are_two_runs(con):
    host_id = authorise(con, V4)
    first, _ = probe(con, [V4], [80], host_id=host_id)
    second, _ = probe(con, [V4], [80], host_id=host_id)
    assert first.id != second.id
    assert prober.latest_run(con, host_id)["id"] == second.id
    assert len(prober.run_results(con, first.id)) == 2


def test_concurrent_runs_against_one_target_both_land_completely(con):
    """One connection, two runs. Each writes its own rows and neither loses
    any, which is the thing to check before a scheduler ever overlaps two."""
    host_id = authorise(con, V4)
    connect = FakeConnect()
    prober_object = prober.Prober(connect=connect, rate_per_second=1_000_000.0)
    ports = [80, 443, 8080]

    async def both():
        return await asyncio.gather(
            prober_object.run(con, [V4], ports, host_id=host_id, gate_clock=NOW),
            prober_object.run(con, [V4], ports, host_id=host_id, gate_clock=NOW))

    first, second = run(both())
    assert first.id != second.id
    for result in (first, second):
        assert len(prober.run_results(con, result.id)) == 2 * len(ports)
    assert len(connect.calls) == 2 * len(ports)


def test_the_host_reference_is_enforced(con):
    """The same rule authz has: a run cannot name a host that does not exist."""
    with pytest.raises(sqlite3.IntegrityError):
        probe(con, [V4], [80], host_id=4242)


def test_a_run_without_a_host_is_allowed(con):
    """An address can be authorised by DNS or by a token file with no agent and
    no host row, so a run has to be able to exist without one."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       resolver=lambda name: [challenge.token])
    result, connect = probe(con, [V4], [80])
    assert connect.calls == [(V4, "v4", 80)]
    assert con.execute("SELECT host_id FROM probe_runs WHERE id = ?",
                       (result.id,)).fetchone()["host_id"] is None


def test_init_is_idempotent(con):
    prober.init(con)
    prober.init(con)
    authorise(con, V4)
    result, _ = probe(con, [V4], [80])
    assert len(prober.run_results(con, result.id)) == 2


def test_a_target_that_could_not_be_read_is_stored_bounded(con):
    """Whatever we were asked to probe is kept so an operator can see what was
    refused, and it is kept bounded, because an address is 45 characters at
    most and this field is not a place to put a caller's blob."""
    result, _ = probe(con, ["x" * 500], [80], connect=RefusingConnect())
    rows = [r for r in prober.run_results(con, result.id)
            if r["family"] == prober.FAMILY_UNKNOWN]
    assert rows
    assert len(rows[0]["target"]) <= prober.MAX_TARGET_TEXT


# ========================== the gate is asked per connect, wherever it lives
#
# `measure` can now run where there is no database. These pin the property that
# makes that safe: the authority is asked before every single connect, not once
# at the start, and the address connected to is the one it approved.


class CountingAuthority:
    """Wraps a real authority and counts. Answers exactly as it does."""

    def __init__(self, inner):
        self.inner = inner
        self.asked = []

    def require(self, address, now=None):
        self.asked.append(address)
        return self.inner.require(address, now=now)


class RevokingAuthority:
    """Allows the first `allow_first` questions and refuses afterwards, which
    is what a revocation landing mid-run looks like from inside the engine."""

    def __init__(self, target, allow_first):
        self.target = target
        self.allow_first = allow_first
        self.asked = 0

    def require(self, address, now=None):
        self.asked += 1
        if self.asked > self.allow_first:
            raise authz.NotAuthorized("revoked partway through")
        return self.target


def test_the_authority_is_asked_once_per_port_and_not_once_per_run(con):
    """The sentence SI-6 rests on. If this ever counts one, the gate has become
    a formality at the start of a run."""
    authorise(con, V4)
    authority = CountingAuthority(authz.DatabaseAuthority(con))
    connect = FakeConnect()
    engine = prober.Prober(connect=connect)
    run(engine.measure(authority, [V4], [80, 443, 8080], gate_clock=NOW))
    # One pre-flight refusal check for the target, then one per port.
    assert len(connect.calls) == 3
    assert authority.asked.count(V4) == 4


def test_a_refusal_partway_through_stops_the_remaining_connects(con):
    """What the per-connect question buys, stated as behaviour rather than as
    a comment. The ports already sent stay sent, and nothing after leaves."""
    authority = RevokingAuthority(V4, allow_first=3)
    connect = FakeConnect()
    engine = prober.Prober(connect=connect, concurrency=1)
    result = run(engine.measure(authority, [V4], [80, 443, 8080, 8443],
                                gate_clock=NOW))
    assert len(connect.calls) == 2, connect.calls
    refused = [r for r in result.results
               if r.reason == prober.REASON_NO_AUTHORIZATION]
    assert refused, "the ports after the refusal say why they were not tested"


def test_measure_needs_no_database_at_all(con):
    """The whole point. A snapshot built on the control plane is carried to a
    machine with no database, and the engine measures from it."""
    authorise(con, V4)
    snapshot = authz.build_snapshot(con, [V4], now=NOW)
    connect = FakeConnect()
    engine = prober.Prober(connect=connect)
    result = run(engine.measure(snapshot, [V4], [80, 443], gate_clock=NOW))
    assert connect.ports == [80, 443]
    assert result.id is None, "nothing stored it, so it has no row"
    assert {r.state for r in result.results if r.target == V4} == {
        prober.STATE_CONNECTED}


def test_a_stale_snapshot_sends_no_packet_at_all(con):
    """The bound on the revocation window, as behaviour at the socket."""
    authorise(con, V4)
    snapshot = authz.build_snapshot(con, [V4], now=NOW)
    connect = RefusingConnect()
    engine = prober.Prober(connect=connect)
    later = NOW + timedelta(seconds=authz.SNAPSHOT_TTL_SECONDS + 1)
    result = run(engine.measure(snapshot, [V4], [80, 443], gate_clock=later))
    assert connect.calls == [], "a stale snapshot must not reach the network"
    assert all(r.state == prober.STATE_NOT_TESTED for r in result.results)


def test_measuring_stores_nothing_while_running_stores_a_row(con):
    """The split, pinned from both sides."""
    authorise(con, V4)
    before = con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"]
    run(prober.Prober(connect=FakeConnect()).measure(
        authz.DatabaseAuthority(con), [V4], [80], gate_clock=NOW))
    assert con.execute(
        "SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == before
    result, _connect = probe(con, [V4], [80])
    assert result.id is not None
    assert con.execute(
        "SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == before + 1


def test_a_non_canonical_spelling_is_probed_and_recorded_canonically(con):
    """One address must never become two rows, so the spelling that reaches
    the socket and the results is the canonical one however it was written.

    This also explains a mutation that survives: swapping the gate's canonical
    answer for the caller's text changes nothing, because `_group_by_family`
    has already put every address through the same `normalise_target` the gate
    uses. The two are equal by construction. Using the gate's answer is kept
    because it stays correct if that ever stops being true.
    """
    authorise(con, V6)
    expanded = "2606:50c0:8000:0000:0000:0000:0000:0153"
    connect = FakeConnect()
    engine = prober.Prober(connect=connect)
    result = run(engine.measure(authz.DatabaseAuthority(con), [expanded], [443],
                                gate_clock=NOW))
    assert [t for t, _f, _p in connect.calls] == [V6], connect.calls
    probed = [r.target for r in result.results if r.state != prober.STATE_NOT_TESTED]
    assert probed == [V6]
