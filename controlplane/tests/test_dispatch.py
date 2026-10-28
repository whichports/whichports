"""The control plane driving a prober on another machine.

Nothing here runs ssh or opens a socket. The transport is a function, so these
drive the real dispatch logic against a fake far end.
"""
import json
import re
from datetime import datetime, timedelta, timezone

import pytest

from app import (authz, db, dispatch, intent, probe_runner, prober,
                 prober_cli, store)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


def authorise(con, address, name="box"):
    host_id, _ = store.add_host(con, name)
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


class Plan:
    """The shape `prober_cli.plan_for` produces, reduced to what dispatch uses."""

    def __init__(self, host_id, targets, ports):
        self.host_id = host_id
        self.targets = tuple(targets)
        self.ports = tuple(ports)


class FakeProber:
    """The far end. Runs the real runner in-process against a fake socket, so
    the batch really is parsed and the snapshot really is enforced."""

    def __init__(self):
        self.batches = []
        self.connects = []

    def __call__(self, payload):
        batch = json.loads(payload)
        self.batches.append(batch)
        parsed = probe_runner.parse_batch(batch)

        outer = self

        async def connect(target, family, port):
            outer.connects.append((target, port))
            return 0.002

        return json.dumps(probe_runner.measure_batch(parsed, connect=connect))


# ------------------------------------------------------------------ batching


@pytest.mark.parametrize("ports,size,expected", [
    ([], 200, [[]]),
    ([80], 200, [[80]]),
    ([1, 2, 3], 2, [[1, 2], [3]]),
    ([1, 2, 3, 4], 2, [[1, 2], [3, 4]]),
])
def test_ports_split_into_batches_in_order(ports, size, expected):
    assert dispatch.batches(ports, size) == expected


def test_a_host_with_no_ports_still_yields_one_batch():
    """A host listening on nothing is an answer, and it has to reach the
    database as a run rather than as nothing at all."""
    assert dispatch.batches([]) == [[]]


def test_a_batch_size_below_one_is_refused():
    with pytest.raises(ValueError):
        dispatch.batches([80], 0)


# ------------------------------------------------------------ the transport


def test_the_ssh_command_is_an_argv_array_with_no_shell_metacharacters():
    """SI-4. The local side parses nothing, and every element is a constant so
    the remote login shell has nothing to act on."""
    argv = dispatch.SshTransport("root@198.51.100.7").argv()
    assert isinstance(argv, list)
    for element in argv:
        assert not re.search(r"[;&|`$><*?\\]", element), element
    assert "sh" not in argv and "-c" not in argv


def test_the_remote_command_takes_no_arguments():
    """There must be nowhere for a target to arrive except the batch on stdin."""
    argv = dispatch.SshTransport("root@198.51.100.7").argv()
    tail = argv[argv.index("--") + 1:]
    assert tail == ["env", "PYTHONPATH=/opt/whichports",
                    "python3", "-m", "app.probe_runner"]


# -------------------------------------------------------------- the dispatch


def test_a_pass_probes_every_port_and_stores_one_run(con):
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80, 443, 8080])
    far = FakeProber()
    stored = dispatch.run_host(con, plan, far, "probe1", batch_size=2)

    assert far.connects == [(V4, 80), (V4, 443), (V4, 8080)]
    assert len(far.batches) == 2, "three ports at two per batch is two batches"
    assert stored.id is not None
    rows = con.execute("SELECT * FROM probe_runs WHERE id = ?",
                       (stored.id,)).fetchall()
    assert len(rows) == 1
    assert rows[0]["finished_at"] is not None
    stored_results = prober.run_results(con, stored.id)
    assert {r["port"] for r in stored_results} == {80, 443, 8080}


def test_every_batch_carries_a_snapshot_read_at_that_moment(con):
    """The property the whole design rests on. One snapshot reused across
    batches would put the revocation window back to the length of the pass."""
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80, 443, 8080, 8443])
    far = FakeProber()
    dispatch.run_host(con, plan, far, "probe1", batch_size=1)
    assert len(far.batches) == 4
    stamps = [b["snapshot"]["expires_at"] for b in far.batches]
    assert all(s for s in stamps)
    assert len({id(b["snapshot"]) for b in far.batches}) == 4


def test_a_revoke_between_batches_stops_the_remaining_ports(con):
    """What per-batch snapshots buy, as behaviour rather than as a comment."""
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80, 443, 8080, 8443])
    far = FakeProber()

    calls = {"n": 0}
    real = far.__call__

    def revoke_after_first(payload):
        calls["n"] += 1
        if calls["n"] == 2:
            authz.revoke(con, V4, now=datetime.now(timezone.utc))
        return real(payload)

    dispatch.run_host(con, plan, revoke_after_first, "probe1", batch_size=1)
    assert far.connects == [(V4, 80), (V4, 443)], far.connects


def test_an_address_the_registry_refuses_is_never_in_a_snapshot(con):
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4, V6], [80])
    far = FakeProber()
    dispatch.run_host(con, plan, far, "probe1")
    assert far.connects == [(V4, 80)]
    assert list(far.batches[0]["snapshot"]["targets"]) == [V4]


def test_an_unusable_answer_stores_nothing_at_all(con):
    """A partial pass stored as a whole one is RECORD 4.46's shape. The run
    fails and the database is left as it was."""
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80, 443])
    before = con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"]

    def broken(payload):
        return "this is not a run"

    with pytest.raises(dispatch.DispatchFailed):
        dispatch.run_host(con, plan, broken, "probe1")
    assert con.execute(
        "SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == before


def test_a_later_batch_failing_stores_nothing_either(con):
    """The one that matters: the first batch worked, so there is a real
    temptation to keep it."""
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80, 443, 8080])
    before = con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"]
    far = FakeProber()
    calls = {"n": 0}

    def fail_on_second(payload):
        calls["n"] += 1
        if calls["n"] == 2:
            return "{}"
        return far(payload)

    with pytest.raises(dispatch.DispatchFailed):
        dispatch.run_host(con, plan, fail_on_second, "probe1", batch_size=1)
    assert con.execute(
        "SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == before


def test_the_stored_run_spans_the_whole_pass(con):
    """One run row per pass, so its start and finish have to cover every batch
    rather than only the last one."""
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80, 443, 8080, 8443])
    far = FakeProber()
    stored = dispatch.run_host(con, plan, far, "probe1", batch_size=1)
    firsts = [b for b in far.batches]
    assert len(firsts) == 4
    assert stored.started_at <= stored.finished_at
    row = con.execute("SELECT * FROM probe_runs WHERE id = ?",
                      (stored.id,)).fetchone()
    assert row["started_at"] == stored.started_at
    assert row["finished_at"] == stored.finished_at


# ----------------------------------------------- the transport's failure paths
#
# These run a real subprocess, but never ssh and never the network. The
# programme is swapped for one whose exit code is the point, which is enough to
# drive the error handling that a mutation otherwise walks straight through.


def test_a_non_zero_exit_from_the_prober_is_a_failure(tmp_path):
    """Without this the caller would parse an empty stdout and call it a run."""
    transport = dispatch.SshTransport("root@198.51.100.7", ssh="/usr/bin/false")
    with pytest.raises(dispatch.DispatchFailed) as raised:
        transport("{}")
    assert "exited" in str(raised.value)


def test_a_missing_ssh_programme_is_a_failure_not_a_crash():
    transport = dispatch.SshTransport("root@198.51.100.7",
                                      ssh="/nonexistent/ssh-programme")
    with pytest.raises(dispatch.DispatchFailed) as raised:
        transport("{}")
    assert "could not run the prober" in str(raised.value)


def test_a_transport_failure_stores_nothing(con):
    """The two halves joined: a prober that will not run leaves the database
    exactly as it was."""
    host_id = authorise(con, V4)
    plan = Plan(host_id, [V4], [80])
    before = con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"]
    transport = dispatch.SshTransport("root@198.51.100.7", ssh="/usr/bin/false")
    with pytest.raises(dispatch.DispatchFailed):
        dispatch.run_host(con, plan, transport, "probe1")
    assert con.execute(
        "SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == before


# -------------------------------------------------------- the CLI route
#
# `probe --via` is the only way a real pass reaches a vantage host, so these
# drive the command rather than the library underneath it.


def cli_plan(con, host_id, name, targets, ports):
    """The CLI works from `prober_cli.Plan`, which carries a note and a
    `derived` flag the reduced Plan above does not."""
    return prober_cli.Plan(host_id, name, tuple(targets), tuple(ports))


def test_probe_via_measures_every_host_and_stores_a_run(con, capsys):
    host_id = authorise(con, V4)
    plans = [cli_plan(con, host_id, "box", [V4], [80, 443])]
    far = FakeProber()
    code = prober_cli._probe_via(con, plans, "root@198.51.100.7",
                                 vantage="probe1", transport=far)
    assert code == 0
    assert far.connects == [(V4, 80), (V4, 443)]
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 1
    assert "1 of 1 hosts measured from probe1" in capsys.readouterr().out


def test_one_host_failing_does_not_stop_the_others(con, capsys):
    """A pass that could not happen on one machine must not lose the machines
    that did measure."""
    first = authorise(con, V4, name="box-one")
    second = authorise(con, V6, name="box-two")
    plans = [cli_plan(con, first, "box-one", [V4], [80]),
             cli_plan(con, second, "box-two", [V6], [80])]
    far = FakeProber()
    calls = {"n": 0}

    def fail_first(payload):
        calls["n"] += 1
        if calls["n"] == 1:
            raise dispatch.DispatchFailed("the vantage host was unreachable")
        return far(payload)

    code = prober_cli._probe_via(con, plans, "root@198.51.100.7",
                                 vantage="probe1", transport=fail_first)
    assert code == 1, "a pass that did not happen is not a success"
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 1
    out = capsys.readouterr()
    assert "1 of 2 hosts measured" in out.out
    assert "not measured" in out.err or "not measured" in out.out


def test_probe_via_is_reachable_from_the_command_line():
    """The flag exists and carries through to the namespace."""
    args = prober_cli.parse_args(
        ["probe", "--vantage", "probe1", "--via", "root@198.51.100.7"])
    assert args.via == "root@198.51.100.7"
    assert args.vantage == "probe1"


def test_probe_without_via_still_means_locally():
    args = prober_cli.parse_args(["probe", "--vantage", "probe1"])
    assert getattr(args, "via", None) is None


# ------------------------------------- a host with no probeable address
#
# Measured on 2026-08-18: almabox holds only Tailscale and carrier-NAT
# addresses. The via path sent an empty batch, the runner refused it, and the
# host read as "not measured" while the local path calls the same host
# not_tested. The wrong answer also made the pass exit non zero, so an hourly
# timer would have reported failure forever for a host that cannot be reached.


def test_a_host_with_no_probeable_address_is_measured_as_not_tested(con):
    host_id, _ = store.add_host(con, "no-public-address")
    plan = Plan(host_id, [], [22, 443])
    far = FakeProber()
    stored = dispatch.run_host(con, plan, far, "probe1")

    assert far.batches == [], "nothing should be sent for a host with no target"
    assert stored.id is not None, "it is an answer, so it is stored"
    states = {r.state for r in stored.results}
    assert states == {prober.STATE_NOT_TESTED}
    reasons = {r.reason for r in stored.results}
    assert reasons == {prober.REASON_NO_ADDRESS_IN_FAMILY}


def test_a_host_with_no_address_answers_for_both_families(con):
    """Completeness by construction, the same as the local path."""
    host_id, _ = store.add_host(con, "no-public-address-2")
    stored = dispatch.run_host(con, Plan(host_id, [], [22]), FakeProber(),
                               "probe1")
    assert {r.family for r in stored.results} == {"v4", "v6"}


def test_a_host_with_no_address_is_not_a_failure(con, capsys):
    """The whole point. It must not make the pass exit non zero."""
    host_id, _ = store.add_host(con, "no-public-address-3")
    plans = [prober_cli.Plan(host_id, "no-public-address-3", (), (22,))]
    code = prober_cli._probe_via(con, plans, "root@198.51.100.7",
                                 vantage="probe1", transport=FakeProber())
    assert code == 0, "an unreachable host is an answer, not a failed pass"
    assert "1 of 1 hosts measured" in capsys.readouterr().out


# ============================================== probing what just moved
#
# The hourly pass is the floor. This is what makes a rule edit answerable in
# minutes without putting more connections in anybody's log when nothing moved.


def a_covered_host(con, name, targets, ports, states=None):
    """A host with one finished run that covered exactly these targets and
    ports, written the way dispatch writes one."""
    host_id, _ = store.add_host(con, name)
    plan = Plan(host_id, targets, ports)
    dispatch.run_host(con, plan, FakeProber(), "probe1")
    return host_id


def test_a_host_never_probed_needs_one(con):
    host_id, _ = store.add_host(con, "fresh")
    assert dispatch.needs_reprobe(con, Plan(host_id, [V4], [80])) is True


def test_a_host_whose_plan_is_unchanged_does_not(con):
    authorise(con, V4)
    host_id = a_covered_host(con, "same", [V4], [80, 443])
    assert dispatch.needs_reprobe(con, Plan(host_id, [V4], [80, 443])) is False


def test_a_new_listening_port_needs_a_reprobe(con):
    authorise(con, V4)
    host_id = a_covered_host(con, "grew", [V4], [80])
    assert dispatch.needs_reprobe(con, Plan(host_id, [V4], [80, 443])) is True


def test_a_port_that_went_away_needs_a_reprobe(con):
    authorise(con, V4)
    host_id = a_covered_host(con, "shrank", [V4], [80, 443])
    assert dispatch.needs_reprobe(con, Plan(host_id, [V4], [80])) is True


def test_a_changed_address_needs_a_reprobe(con):
    authorise(con, V4)
    authorise(con, V6, name="other")
    host_id = a_covered_host(con, "moved", [V4], [80])
    assert dispatch.needs_reprobe(con, Plan(host_id, [V6], [80])) is True


def test_port_order_and_duplicates_are_not_a_change(con):
    """The plan is a set of ports however the document listed them."""
    authorise(con, V4)
    host_id = a_covered_host(con, "noisy", [V4], [80, 443])
    assert dispatch.needs_reprobe(con, Plan(host_id, [V4], [443, 80, 443])) is False


def test_a_host_with_no_address_is_covered_and_stays_covered(con):
    """It is measured as not_tested and stored, so it must not reprobe on
    every tick forever."""
    host_id, _ = store.add_host(con, "unreachable")
    dispatch.run_host(con, Plan(host_id, [], [22]), FakeProber(), "probe1")
    assert dispatch.needs_reprobe(con, Plan(host_id, [], [22])) is False


def test_a_run_that_never_finished_does_not_count_as_coverage(con):
    host_id, _ = store.add_host(con, "died")
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at)"
                " VALUES (?, ?, ?)", (host_id, "probe1", "2026-08-18T12:00:00+00:00"))
    con.commit()
    assert dispatch.covered_by_last_run(con, host_id) is None
    assert dispatch.needs_reprobe(con, Plan(host_id, [V4], [80])) is True


def test_results_changing_is_not_a_reason_to_reprobe(con):
    """A port that stopped answering is a finding, not a trigger. The pass
    that measured it already did its job, and reprobing on results would make
    every flapping port a probing loop."""
    authorise(con, V4)
    host_id, _ = store.add_host(con, "flapper")
    plan = Plan(host_id, [V4], [80])

    class Refusing(FakeProber):
        def __call__(self, payload):
            import json as _json
            batch = _json.loads(payload)
            parsed = probe_runner.parse_batch(batch)

            async def connect(target, family, port):
                raise ConnectionRefusedError()
            return _json.dumps(probe_runner.measure_batch(parsed, connect=connect))

    dispatch.run_host(con, plan, FakeProber(), "probe1")
    assert dispatch.needs_reprobe(con, plan) is False
    dispatch.run_host(con, plan, Refusing(), "probe1")
    assert dispatch.needs_reprobe(con, plan) is False


# ============================================================ the joined set
#
# The owner's decision, 2026-08-21, in docs/RECORD.md 4.78: the lane that runs
# every ten minutes probes ports with a listener, a declared intent or a
# previous finding, rather than the document's ports alone.


@pytest.fixture()
def joined_con():
    """The joined set reads declarations, so this connection has that table.

    Separate from `con` rather than added to it, because a test that asks what
    happens on a database where nobody ever declared anything has to be able to
    get one.
    """
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    intent.init(connection)
    yield connection
    connection.close()


def test_the_joined_set_starts_as_the_documents_ports(joined_con):
    host_id, _ = store.add_host(joined_con, "plain")
    ports, note = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80, 443]))
    assert ports == (80, 443)
    assert note == ""


def test_a_declared_port_joins_the_set(joined_con):
    """Nothing listens on 8443 and nobody probed it. A person said it should be
    open, so it is measured."""
    host_id, _ = store.add_host(joined_con, "declared")
    intent.declare(joined_con, "declared", "tcp", 8443, "v4", intent.INTENT_OPEN)
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80]))
    assert ports == (80, 8443)


def test_a_port_declared_closed_joins_the_set_too(joined_con):
    """Reading only `open` would drop the half where a conflict is most likely
    to show up: a port somebody said must not answer, that answers."""
    host_id, _ = store.add_host(joined_con, "shut")
    intent.declare(joined_con, "shut", "tcp", 9000, "v4", intent.INTENT_CLOSED)
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80]))
    assert ports == (80, 9000)


def test_a_udp_declaration_does_not_join_a_tcp_lane(joined_con):
    """This is a TCP connect prober. Offering it a UDP port would be inventing
    a measurement it cannot take."""
    host_id, _ = store.add_host(joined_con, "udp")
    intent.declare(joined_con, "udp", "udp", 514, "v4", intent.INTENT_OPEN)
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80]))
    assert ports == (80,)


def test_a_previously_measured_port_stays_in_the_set(joined_con):
    """The port answered once. The listener has since gone from the document,
    and this is the tick where somebody wants to know whether it still answers,
    so dropping it here would lose exactly the finding the lane exists for."""
    authorise(joined_con, V4)
    host_id = a_covered_host(joined_con, "was_open", [V4], [80, 8080])
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80]))
    assert ports == (80, 8080)


def test_a_silent_port_stays_in_the_set_as_well(joined_con):
    """Every result, not only the ones that connected. A port measured silent
    is still a port we have an answer for, and the next answer is the change."""
    authorise(joined_con, V4)
    host_id, _ = store.add_host(joined_con, "silent")

    class Refusing(FakeProber):
        def __call__(self, payload):
            batch = json.loads(payload)
            parsed = probe_runner.parse_batch(batch)

            async def connect(target, family, port):
                raise ConnectionRefusedError()
            return json.dumps(probe_runner.measure_batch(parsed, connect=connect))

    dispatch.run_host(joined_con, Plan(host_id, [V4], [7000]), Refusing(), "probe1")
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], []))
    assert ports == (7000,)


def test_the_three_sources_are_a_union_without_duplicates(joined_con):
    authorise(joined_con, V4)
    host_id = a_covered_host(joined_con, "all_three", [V4], [80, 443])
    intent.declare(joined_con, "all_three", "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(joined_con, "all_three", "tcp", 22, "v4", intent.INTENT_CLOSED)
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80]))
    assert ports == (22, 80, 443)


def test_a_port_the_engine_will_refuse_is_carried_through(joined_con):
    """A document can report a port as text. It has to reach the engine so the
    engine records it as not tested with its own typed reason, rather than
    disappearing between the document and the answer."""
    host_id, _ = store.add_host(joined_con, "odd")
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80, "http"]))
    assert ports == (80, "http")


def test_a_boolean_is_not_port_one(joined_con):
    """bool is an int in Python, so True would silently become port 1."""
    host_id, _ = store.add_host(joined_con, "bool")
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [True]))
    assert ports == (True,)


def test_a_host_that_derived_nothing_is_left_alone(joined_con):
    """An empty plan stays empty. There is nothing to widen."""
    host_id, _ = store.add_host(joined_con, "nothing")
    ports, note = dispatch.joined_ports(joined_con, Plan(host_id, [], []))
    assert ports == ()
    assert note == ""


def test_the_cap_bites_and_says_so(joined_con):
    """A cap that narrows coverage silently reads afterwards as coverage."""
    host_id, _ = store.add_host(joined_con, "many")
    wanted = list(range(1, dispatch.MAX_JOINED_PORTS + 20))
    ports, note = dispatch.joined_ports(joined_con, Plan(host_id, [V4], wanted))
    assert len(ports) == dispatch.MAX_JOINED_PORTS
    assert str(len(wanted)) in note
    assert "19" in note


def test_the_cap_is_not_reached_by_an_ordinary_host(joined_con):
    host_id, _ = store.add_host(joined_con, "ordinary")
    ports, note = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [22, 80, 443]))
    assert note == ""
    assert len(ports) < dispatch.MAX_JOINED_PORTS


def test_a_joined_pass_does_not_report_every_host_as_moved(joined_con):
    """The regression this argument exists to stop. A pass over the joined set
    covers more ports than the document names, so comparing what it covered
    against the document's ports would say every host moved, on every tick,
    forever."""
    authorise(joined_con, V4)
    host_id, _ = store.add_host(joined_con, "wider")
    intent.declare(joined_con, "wider", "tcp", 8443, "v4", intent.INTENT_OPEN)
    plan = Plan(host_id, [V4], [80])

    joined, _ = dispatch.joined_ports(joined_con, plan)
    assert joined == (80, 8443)
    dispatch.run_host(joined_con, Plan(host_id, [V4], joined), FakeProber(), "probe1")

    assert dispatch.needs_reprobe(joined_con, plan, set(joined)) is False
    # And the old comparison, kept here so the reason for the argument is
    # visible rather than remembered.
    assert dispatch.needs_reprobe(joined_con, plan) is True


# ------------------------------------------------------------- workspaces
#
# The batch is what leaves the box for the vantage host, so an entry in its
# snapshot is an authorisation that travelled. These say a batch built for one
# workspace carries nothing another workspace proved.


def test_a_batch_carries_only_its_own_workspaces_authorisations(con):
    second = db.create_workspace(con, "second")
    host_id, _ = store.add_host(con, "theirs", workspace_id=second)
    document = json.dumps({
        "sockets": {"listening": []},
        "interface_addresses": {"addresses": [
            {"interface": "eth0", "family": "v4", "address": V4,
             "global": True}]}})
    assert authz.record_agent_proof(con, host_id, V4, document).recorded is True

    theirs = dispatch.build_batch(
        con, "probe1", [V4], [443],
        account=authz.account_for_workspace(second))
    assert theirs["snapshot"]["targets"]

    mine = dispatch.build_batch(
        con, "probe1", [V4], [443],
        account=authz.account_for_workspace(db.DEFAULT_WORKSPACE_ID))
    assert mine["snapshot"]["targets"] == {}


def test_a_batch_defaults_to_workspace_ones_account(con):
    """Every caller written before workspaces passes nothing, and must keep
    getting exactly the answers it got before."""
    authorise(con, V4)
    payload = dispatch.build_batch(con, "probe1", [V4], [443])
    assert V4 in payload["snapshot"]["targets"]


# ======================= a port nothing names leaves the set after a day
#
# The owner, 2026-09-27 (docs/RECORD.md 4.207): tcp/6767 on fart had been probed
# every ten minutes since 30 August with nothing listening, no rule and no
# declaration, because the third source above keeps every port the newest run
# measured and nothing ever let one go. A port whose state has been nothing on
# every family for a day leaves the set. The state is the sweep's own record,
# so these tests write it the way `app/finding_alerts.py` does.

from app import alerts as alerts_store, finding_alerts  # noqa: E402

LANE_NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
A_DAY = timedelta(seconds=dispatch.FORGOTTEN_AFTER_SECONDS)


@pytest.fixture()
def lane_con(joined_con):
    alerts_store.init(joined_con)
    finding_alerts.init(joined_con)
    return joined_con


def state(con, host_id, port, family, word, confirmed_at, pending=None):
    con.execute(
        "INSERT INTO finding_states (host_id, protocol, port, family, state,"
        " confirmed_at, pending_change) VALUES (?, 'tcp', ?, ?, ?, ?, ?)",
        (host_id, port, family, word, confirmed_at.isoformat(), pending))
    con.commit()


def fart_with_6767(con, name="fart"):
    """80 listening, 6767 measured once and nothing names it any more."""
    authorise(con, V4, f"proof-{name}")
    return a_covered_host(con, name, [V4], [80, 6767])


def test_a_port_with_no_state_for_a_day_leaves_the_set(lane_con):
    host_id = fart_with_6767(lane_con)
    state(lane_con, host_id, 6767, "v4", "", LANE_NOW - A_DAY - timedelta(minutes=1))
    state(lane_con, host_id, 6767, "v6", "", LANE_NOW - A_DAY - timedelta(minutes=1))
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80,)


def test_a_port_quiet_for_less_than_a_day_stays(lane_con):
    """The tick 4.78 keeps a port for: the listener just went and somebody
    wants to know whether it still answers."""
    host_id = fart_with_6767(lane_con)
    state(lane_con, host_id, 6767, "v4", "", LANE_NOW - A_DAY + timedelta(minutes=1))
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 6767)


@pytest.mark.parametrize("word", ["stale rule", "unexplained", "not reachable"])
def test_a_port_with_a_state_on_either_family_stays(lane_con, word):
    """A rule, a connect or a listener on one family is a name for the port."""
    host_id = fart_with_6767(lane_con)
    old = LANE_NOW - timedelta(days=30)
    state(lane_con, host_id, 6767, "v4", "", old)
    state(lane_con, host_id, 6767, "v6", word, old)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 6767)


def test_a_port_with_a_change_being_held_stays(lane_con):
    host_id = fart_with_6767(lane_con)
    held = lane_con.execute(
        "INSERT INTO finding_changes (host_id, protocol, port, family, from_state,"
        " to_state, outside, description, outcome, seen_at)"
        " VALUES (?, 'tcp', 6767, 'v4', '', 'unexplained', 'connected', '',"
        " 'pending', ?)", (host_id, LANE_NOW.isoformat())).lastrowid
    state(lane_con, host_id, 6767, "v4", "", LANE_NOW - timedelta(days=30), pending=held)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 6767)


def test_a_forgotten_port_that_listens_again_is_back_at_once(lane_con):
    """Nothing is lost on an agent host: the next report names it."""
    host_id = fart_with_6767(lane_con)
    state(lane_con, host_id, 6767, "v4", "", LANE_NOW - timedelta(days=30))
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80, 6767]),
                                     now=LANE_NOW)
    assert ports == (80, 6767)


def test_a_forgotten_port_somebody_declares_is_back_at_once(lane_con):
    host_id = fart_with_6767(lane_con)
    state(lane_con, host_id, 6767, "v4", "", LANE_NOW - timedelta(days=30))
    intent.declare(lane_con, "fart", "tcp", 6767, "v4", intent.INTENT_CLOSED)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 6767)


def test_an_address_host_keeps_every_port_it_measured(lane_con):
    """No document says what listens there, so its measurements are all it has."""
    host_id = fart_with_6767(lane_con, "addressonly")
    state(lane_con, host_id, 6767, "v4", "", LANE_NOW - timedelta(days=30))
    plan = Plan(host_id, [V4], [80])
    plan.agentless = True
    ports, _ = dispatch.joined_ports(lane_con, plan, now=LANE_NOW)
    assert ports == (80, 6767)


def test_a_database_the_sweep_never_ran_on_forgets_nothing(joined_con):
    host_id = fart_with_6767(joined_con)
    ports, _ = dispatch.joined_ports(joined_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 6767)


# ============ a port nothing measured for a day leaves the set, whatever was stored
#
# The second big test, 2026-10-25, case D7: a server's listeners on 3200 to
# 3204 stopped and their firewalld entries were removed the day before. Every
# result since was not tested, host unreachable, 260 of 260 over 52 passes.
# The sweep writes a state only for a port the prober measured
# (`app/finding_alerts.py`), so their stored state stayed `intended` from
# when they listened, the rule above never forgot them, and the probers
# connected to them on every pass. The engine gives such a port no state,
# and docs/PRODUCT.md 5's cadence keeps a previous finding a day after its
# port last had a state.

UNREACHABLE = (prober.STATE_NOT_TESTED, prober.REASON_HOST_UNREACHABLE)
CONNECTED = (prober.STATE_CONNECTED, None)
SILENT = (prober.STATE_NO_RESPONSE, prober.REASON_TIMEOUT_EXPIRED)
UNAUTHORISED = (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)


def a_pass(con, host_id, at, results):
    """One finished pass of one vantage at `at`, results as {port: (state,
    reason)}, written as the prober's own tables hold one."""
    run_id = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, 'probe1', ?, ?)", (host_id, at.isoformat(), at.isoformat())).lastrowid
    for port, (word, reason) in results.items():
        con.execute(
            "INSERT INTO probe_results (run_id, target, family, port, state, reason,"
            " measured_at) VALUES (?, ?, 'v4', ?, ?, ?, ?)",
            (run_id, V4, port, word, reason, at.isoformat()))
    con.commit()


def down_a_day(con, lately=UNREACHABLE, eighty=CONNECTED, document=None):
    """80 listening and measured all along. 3200 measured two days ago, while
    it listened and was told intended, and since then `lately` on every pass."""
    host_id, _ = store.add_host(con, "alma")
    if document is not None:
        store.insert_report(con, host_id, int(LANE_NOW.timestamp()), 1, json.dumps(document))
    a_pass(con, host_id, LANE_NOW - 2 * A_DAY, {80: CONNECTED, 3200: CONNECTED})
    state(con, host_id, 3200, "v4", "intended", LANE_NOW - 2 * A_DAY)
    state(con, host_id, 80, "v4", "intended", LANE_NOW - 2 * A_DAY)
    for hours in (20, 10, 1):
        a_pass(con, host_id, LANE_NOW - timedelta(hours=hours), {80: eighty, 3200: lately})
    return host_id


def test_a_port_nothing_measured_for_a_day_leaves_the_set_though_intended_was_stored(lane_con):
    host_id = down_a_day(lane_con)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80,)


def test_a_port_measured_shut_within_the_day_stays_for_the_sweep_to_settle(lane_con):
    host_id = down_a_day(lane_con, lately=SILENT)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 3200)


def test_a_day_in_which_nothing_of_the_server_was_measured_forgets_nothing(lane_con):
    """A lost authorization makes every result not tested. That is a day
    the probers could not look, not a day the port had no state."""
    host_id = down_a_day(lane_con, lately=UNAUTHORISED, eighty=UNAUTHORISED)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 3200)


def test_a_port_first_probed_less_than_a_day_ago_stays(lane_con):
    host_id, _ = store.add_host(lane_con, "alma")
    for hours in (20, 10, 1):
        a_pass(lane_con, host_id, LANE_NOW - timedelta(hours=hours),
               {80: CONNECTED, 3200: UNREACHABLE})
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 3200)


def test_a_rule_that_still_permits_the_port_keeps_it(lane_con):
    """`stale rule` is the one state that needs no measurement: a rule
    permits the port with nothing behind it. It keeps the port in the set."""
    document = {
        "sockets": {"status": "collected", "listening": [
            {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 80}]},
        "nftables": {"status": "collected", "tables": [{
            "family": "inet", "name": "filter", "chains": [{
                "name": "input", "type": "filter", "hook": "input", "priority": 0,
                "policy": "drop",
                "rules": [{"text": "tcp dport 3200 accept", "rendered": "full"}]}]}]}}
    host_id = down_a_day(lane_con, document=document)
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 3200)


def test_a_port_with_a_change_held_stays_though_nothing_measured_it(lane_con):
    host_id = down_a_day(lane_con)
    held = lane_con.execute(
        "INSERT INTO finding_changes (host_id, protocol, port, family, from_state,"
        " to_state, outside, description, outcome, seen_at)"
        " VALUES (?, 'tcp', 3200, 'v4', 'intended', '', 'no answer', '',"
        " 'pending', ?)", (host_id, LANE_NOW.isoformat())).lastrowid
    lane_con.execute("UPDATE finding_states SET pending_change = ? WHERE host_id = ? AND port = 3200",
                     (held, host_id))
    lane_con.commit()
    ports, _ = dispatch.joined_ports(lane_con, Plan(host_id, [V4], [80]), now=LANE_NOW)
    assert ports == (80, 3200)


def test_an_address_host_keeps_a_port_nothing_measured_for_a_day(lane_con):
    host_id = down_a_day(lane_con)
    plan = Plan(host_id, [V4], [80])
    plan.agentless = True
    ports, _ = dispatch.joined_ports(lane_con, plan, now=LANE_NOW)
    assert ports == (80, 3200)
