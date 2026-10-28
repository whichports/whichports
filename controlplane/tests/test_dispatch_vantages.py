"""One pass, every vantage in the registry, and the three rules that come with
a second vantage point.

  - **the pace rule** (`docs/PRODUCT.md` 5d): a host never has two of our
    runners against it at once, so the 40 a second it receives is the total
  - **our own addresses are never targets**, and each leaves a typed row
  - **a dead vantage does not blind the others**, and a refused batch on one
    host does not stop the next host from the same vantage

Nothing here runs ssh or opens a socket. The far end is the real runner in
process against a fake socket, the same shape `tests/test_dispatch.py` uses.
"""
import json
import os
import stat
from datetime import datetime, timezone

import pytest

from app import (authz, db, dispatch, probe_runner, prober, prober_cli, store,
                 vantages)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
PROBE1_V4 = "78.141.210.130"
PROBE1_V6 = "2a05:f480:1400:2015:5400:6ff:fe94:df5"
PROBE2_V4 = "185.199.110.7"


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    vantages.init(connection)
    yield connection
    connection.close()


def authorise(con, addresses, name="box"):
    host_id, _ = store.add_host(con, name)
    for address in addresses:
        document = json.dumps({
            "sockets": {"listening": []},
            "interface_addresses": {"addresses": [
                {"interface": "eth0",
                 "family": "v6" if ":" in address else "v4",
                 "address": address, "global": True}]}})
        result = authz.record_agent_proof(con, host_id, address, document,
                                          now=datetime.now(timezone.utc))
        assert result.recorded, result.reason
    return host_id


def plan(con, host_id, name, targets, ports):
    return prober_cli.Plan(host_id, name, tuple(targets), tuple(ports))


class FakeProber:
    """The far end for one vantage. Runs the real runner in process."""

    def __init__(self, name="far", log=None):
        self.name = name
        self.batches = []
        self.connects = []
        self.log = log if log is not None else []

    def __call__(self, payload):
        batch = json.loads(payload)
        self.batches.append(batch)
        parsed = probe_runner.parse_batch(batch)
        outer = self

        async def connect(target, family, port):
            outer.connects.append((target, port))
            outer.log.append((outer.name, target, port))
            return 0.002

        return json.dumps(probe_runner.measure_batch(parsed, connect=connect))


def two_vantages(con):
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4, PROBE1_V6])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    return vantages.enabled(con)


def rows_of(con, run_id):
    return [(r["family"], r["target"], r["port"], r["state"], r["reason"])
            for r in prober.run_results(con, run_id)]


# ------------------------------------------------------------ own addresses


def test_a_vantage_address_is_never_sent_and_leaves_a_typed_row(con):
    host_id = authorise(con, [V4, PROBE2_V4])
    far = FakeProber()
    run = dispatch.run_host(con, plan(con, host_id, "box", [V4, PROBE2_V4],
                                      [80, 443]),
                            far, "probe1", exclude={PROBE2_V4})
    assert far.connects == [(V4, 80), (V4, 443)]
    assert all(PROBE2_V4 not in b["addresses"] for b in far.batches)
    ours = [r for r in rows_of(con, run.id) if r[1] == PROBE2_V4]
    assert sorted(ours) == [
        ("v4", PROBE2_V4, 80, prober.STATE_NOT_TESTED, prober.REASON_VANTAGE_ADDRESS),
        ("v4", PROBE2_V4, 443, prober.STATE_NOT_TESTED, prober.REASON_VANTAGE_ADDRESS),
    ]
    measured = [r for r in rows_of(con, run.id) if r[1] == V4]
    assert {r[3] for r in measured} == {prober.STATE_CONNECTED}


def test_a_host_whose_only_address_is_ours_is_stored_and_not_sent(con):
    """Nothing leaves, and the family is not called address-less: the host
    has an address there, it is ours."""
    host_id = authorise(con, [PROBE1_V6])
    far = FakeProber()
    run = dispatch.run_host(con, plan(con, host_id, "box", [PROBE1_V6], [22]),
                            far, "probe2", exclude={PROBE1_V4, PROBE1_V6})
    assert far.batches == []
    assert sorted(rows_of(con, run.id)) == [
        ("v4", None, 22, prober.STATE_NOT_TESTED, prober.REASON_NO_ADDRESS_IN_FAMILY),
        ("v6", PROBE1_V6, 22, prober.STATE_NOT_TESTED, prober.REASON_VANTAGE_ADDRESS),
    ]


def test_the_exclusion_compares_canonical_spellings(con):
    host_id = authorise(con, [PROBE1_V6])
    far = FakeProber()
    spelled_differently = authz.normalise_target(PROBE1_V6.upper())[0]
    run = dispatch.run_host(con, plan(con, host_id, "box", [PROBE1_V6], [22]),
                            far, "probe2", exclude={spelled_differently})
    assert far.batches == []
    assert rows_of(con, run.id)[1][4] == prober.REASON_VANTAGE_ADDRESS


def test_a_port_that_is_not_a_port_keeps_its_own_reason_on_our_address(con):
    host_id = authorise(con, [PROBE2_V4])
    run = dispatch.run_host(con, plan(con, host_id, "box", [PROBE2_V4],
                                      [80, "eighty"]),
                            FakeProber(), "probe1", exclude={PROBE2_V4})
    reasons = {r[2]: r[4] for r in rows_of(con, run.id) if r[1] == PROBE2_V4}
    assert reasons == {80: prober.REASON_VANTAGE_ADDRESS,
                       None: prober.REASON_PORT_NOT_AN_INTEGER}


def test_the_new_reason_is_typed_and_unmeasured():
    assert prober.REASON_VANTAGE_ADDRESS in prober.REASONS
    assert prober.REASON_VANTAGE_ADDRESS in prober.UNMEASURED_REASONS
    assert prober.REASON_VANTAGE_ADDRESS not in prober.MEASURED_ONLY_REASONS


def test_with_nothing_registered_run_host_is_unchanged(con):
    """The single-vantage behaviour, byte for byte in the rows."""
    host_id = authorise(con, [V4])
    p = plan(con, host_id, "box", [V4], [80, 443])
    before = dispatch.run_host(con, p, FakeProber(), "probe1")
    after = dispatch.run_host(con, p, FakeProber(), "probe1", exclude=frozenset())
    assert rows_of(con, before.id) == rows_of(con, after.id)


# ------------------------------------------------------------------ the pass


def test_run_pass_measures_every_host_from_every_vantage(con):
    first = authorise(con, [V4], "one")
    second = authorise(con, [V6], "two")
    chosen = two_vantages(con)
    fars = {}

    def factory(destination):
        fars[destination] = FakeProber(destination)
        return fars[destination]

    outcomes = dispatch.run_pass(
        con, [plan(con, first, "one", [V4], [80]), plan(con, second, "two", [V6], [22])],
        chosen, transport_factory=factory)
    assert [(o.host_name, o.vantage, o.measured) for o in outcomes] == [
        ("one", "probe1", True), ("one", "probe2", True),
        ("two", "probe1", True), ("two", "probe2", True)]
    stored = con.execute("SELECT host_id, vantage FROM probe_runs ORDER BY id").fetchall()
    assert [(r["host_id"], r["vantage"]) for r in stored] == [
        (first, "probe1"), (first, "probe2"), (second, "probe1"), (second, "probe2")]
    assert set(fars) == {"root@" + PROBE1_V4, "root@" + PROBE2_V4}
    assert fars["root@" + PROBE1_V4].connects == [(V4, 80), (V6, 22)]
    assert fars["root@" + PROBE2_V4].connects == [(V4, 80), (V6, 22)]


def test_each_run_names_the_vantage_that_took_it(con):
    host_id = authorise(con, [V4])
    chosen = two_vantages(con)
    outcomes = dispatch.run_pass(con, [plan(con, host_id, "one", [V4], [80])],
                                 chosen, transport_factory=lambda d: FakeProber(d))
    assert [o.run.vantage for o in outcomes] == ["probe1", "probe2"]


def test_no_two_vantages_are_ever_in_flight_against_one_host(con):
    """The pace rule as a tripwire. Each transport call is entered and left in
    order, and a second call for the same addresses while one is open fails
    the test. Sequential code passes this trivially, which is the point: a
    future refactor towards concurrency turns it red."""
    first = authorise(con, [V4], "one")
    second = authorise(con, [OTHER_V4], "two")
    chosen = two_vantages(con)
    in_flight = set()
    order = []

    class Guarded(FakeProber):
        def __call__(self, payload):
            key = tuple(json.loads(payload)["addresses"])
            assert key not in in_flight, f"two vantages on {key} at once"
            in_flight.add(key)
            order.append((self.name, key))
            try:
                return super().__call__(payload)
            finally:
                in_flight.discard(key)

    dispatch.run_pass(con, [plan(con, first, "one", [V4], [80]),
                            plan(con, second, "two", [OTHER_V4], [80])],
                      chosen, transport_factory=Guarded)
    assert order == [("root@" + PROBE1_V4, (V4,)), ("root@" + PROBE2_V4, (V4,)),
                     ("root@" + PROBE1_V4, (OTHER_V4,)),
                     ("root@" + PROBE2_V4, (OTHER_V4,))]


def test_a_host_is_finished_from_one_vantage_before_the_next_starts(con):
    """Batches too: with two batches per host, both of probe1's go before
    probe2's first, so a slow first vantage never overlaps the second."""
    host_id = authorise(con, [V4])
    chosen = two_vantages(con)
    log = []
    dispatch.run_pass(con, [plan(con, host_id, "one", [V4], [1, 2, 3, 4])],
                      chosen, transport_factory=lambda d: FakeProber(d, log),
                      batch_size=2)
    assert [entry[0] for entry in log] == ["root@" + PROBE1_V4] * 4 + \
        ["root@" + PROBE2_V4] * 4


def test_one_vantage_being_unreachable_does_not_blind_the_other(con):
    first = authorise(con, [V4], "one")
    second = authorise(con, [OTHER_V4], "two")
    chosen = two_vantages(con)
    tried = {"probe2": 0}

    def factory(destination):
        if destination == "root@" + PROBE2_V4:
            def dead(payload):
                tried["probe2"] += 1
                raise dispatch.VantageUnreachable("ssh could not reach it")
            return dead
        return FakeProber(destination)

    outcomes = dispatch.run_pass(
        con, [plan(con, first, "one", [V4], [80]),
              plan(con, second, "two", [OTHER_V4], [80])],
        chosen, transport_factory=factory)
    assert [(o.host_name, o.vantage, o.measured, o.skipped) for o in outcomes] == [
        ("one", "probe1", True, False), ("one", "probe2", False, False),
        ("two", "probe1", True, False), ("two", "probe2", False, True)]
    assert tried["probe2"] == 1, "a dead vantage is tried once per pass"
    assert outcomes[3].failure == outcomes[1].failure
    stored = con.execute("SELECT vantage FROM probe_runs").fetchall()
    assert [r["vantage"] for r in stored] == ["probe1", "probe1"]


def test_a_refused_batch_on_one_host_does_not_stop_the_next_host(con):
    """A runner that refuses one host's batch is a fact about that host from
    that vantage. It is not the vantage being down."""
    first = authorise(con, [V4], "one")
    second = authorise(con, [OTHER_V4], "two")
    chosen = two_vantages(con)

    def factory(destination):
        far = FakeProber(destination)
        if destination != "root@" + PROBE2_V4:
            return far

        def picky(payload):
            if V4 in json.loads(payload)["addresses"]:
                raise dispatch.DispatchFailed("the prober exited 2: refused")
            return far(payload)
        return picky

    outcomes = dispatch.run_pass(
        con, [plan(con, first, "one", [V4], [80]),
              plan(con, second, "two", [OTHER_V4], [80])],
        chosen, transport_factory=factory)
    assert [(o.host_name, o.vantage, o.measured, o.skipped) for o in outcomes] == [
        ("one", "probe1", True, False), ("one", "probe2", False, False),
        ("two", "probe1", True, False), ("two", "probe2", True, False)]


def test_a_failed_vantage_stores_nothing_for_that_host(con):
    """Nothing, rather than a run of not_tested rows. A stored run would reset
    the dead-man clock for that vantage, which is the thing that has to
    notice it is dead."""
    host_id = authorise(con, [V4])
    chosen = two_vantages(con)

    def factory(destination):
        if destination == "root@" + PROBE2_V4:
            def dead(payload):
                raise dispatch.VantageUnreachable("down")
            return dead
        return FakeProber(destination)

    dispatch.run_pass(con, [plan(con, host_id, "one", [V4], [80])], chosen,
                      transport_factory=factory)
    stored = con.execute("SELECT vantage FROM probe_runs").fetchall()
    assert [r["vantage"] for r in stored] == ["probe1"]


def test_a_pass_with_one_vantage_stores_what_run_host_stored(con):
    """The single-vantage behaviour is unchanged: driving the registry with
    one entry stores exactly the rows the old one-vantage path stores."""
    host_id = authorise(con, [V4, V6])
    p = plan(con, host_id, "box", [V4, V6], [22, 80])
    old = dispatch.run_host(con, p, FakeProber(), "probe1")
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    outcomes = dispatch.run_pass(con, [p], vantages.enabled(con),
                                 transport_factory=lambda d: FakeProber(d))
    assert len(outcomes) == 1 and outcomes[0].measured
    assert rows_of(con, outcomes[0].run.id) == rows_of(con, old.id)
    assert outcomes[0].run.vantage == old.vantage == "probe1"


def test_no_vantages_means_no_outcomes_and_no_runs(con):
    host_id = authorise(con, [V4])
    outcomes = dispatch.run_pass(con, [plan(con, host_id, "one", [V4], [80])],
                                 [], transport_factory=lambda d: FakeProber(d))
    assert outcomes == []
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 0


def test_the_pass_excludes_every_registered_address(con):
    """probe1 never probes probe2 and probe2 never probes probe1, even when a
    customer has, somehow, proved one of our addresses."""
    host_id = authorise(con, [V4, PROBE1_V4, PROBE2_V4])
    chosen = two_vantages(con)
    fars = {}

    def factory(destination):
        fars[destination] = FakeProber(destination)
        return fars[destination]

    dispatch.run_pass(con, [plan(con, host_id, "one",
                                 [V4, PROBE1_V4, PROBE2_V4], [80])],
                      chosen, transport_factory=factory,
                      exclude=vantages.all_addresses(con))
    for far in fars.values():
        assert far.connects == [(V4, 80)]


# ---------------------------------------------------------------- transport


def test_ssh_argv_carries_a_connect_timeout():
    argv = dispatch.SshTransport("root@198.51.100.7").argv()
    assert f"ConnectTimeout={dispatch.SSH_CONNECT_TIMEOUT_SECONDS}" in argv
    assert argv.index("root@198.51.100.7") < argv.index("--")


def fake_ssh(tmp_path, exit_code):
    script = tmp_path / f"ssh-{exit_code}"
    script.write_text(f"#!/bin/sh\necho nope >&2\nexit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def test_ssh_exiting_255_is_the_vantage_being_unreachable(tmp_path):
    transport = dispatch.SshTransport("root@198.51.100.7",
                                      ssh=fake_ssh(tmp_path, 255))
    with pytest.raises(dispatch.VantageUnreachable) as raised:
        transport("{}")
    assert "could not reach" in str(raised.value)


def test_the_runner_refusing_is_not_the_vantage_being_unreachable(tmp_path):
    transport = dispatch.SshTransport("root@198.51.100.7",
                                      ssh=fake_ssh(tmp_path, 2))
    with pytest.raises(dispatch.DispatchFailed) as raised:
        transport("{}")
    assert not isinstance(raised.value, dispatch.VantageUnreachable)


def test_a_missing_ssh_programme_is_the_vantage_being_unreachable():
    transport = dispatch.SshTransport("root@198.51.100.7",
                                      ssh="/nonexistent/ssh-programme")
    with pytest.raises(dispatch.VantageUnreachable):
        transport("{}")
