"""The worker that drives our probers for self-hosted instances
(`app/proberapi_worker.py`).

The far end is the real runner in process against a fake socket, the shape
`tests/test_dispatch_vantages.py` uses, so "refused" below means the runner
itself refused to connect because the snapshot we built did not allow it.
What these hold:

  - an address is probed only when **this** instance proved it to **us**:
    unproved, expired, proved by another instance and proved by a hosted
    workspace are all refused, with no connect made
  - the instance's own snapshot narrows ours and cannot widen it
  - a revoked instance's queued batch is never sent
  - every way the prober can fail comes back as a class
  - the abuse log is written before a batch is sent
  - the pass lock is held for every batch, and not asked for when idle
  - **the per-target pace holds across two instances, both vantages, our own
    timer and a second worker, all at once**, measured at the target
"""
import argparse
import json
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import (authz, db, dispatch, instances, probelock, probe_runner,
                 prober, prober_cli, proberapi, proberapi_worker, vantages)

from test_probe_lock import (RATE, FakeVantage, RefusingConnect, Target,
                             make_box, probe_args)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"


def now():
    return datetime.now(timezone.utc)


@pytest.fixture()
def path(tmp_path):
    """A control plane database on disk, because the pass lock lives beside
    it and an in-memory database has nowhere to put one."""
    where = str(tmp_path / "cp.db")
    con = db.connect(where)
    for module in (db, authz, prober, vantages, instances, proberapi):
        module.init(con)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    con.close()
    return where


@pytest.fixture()
def con(path):
    connection = db.connect(path)
    yield connection
    connection.close()


def presence(con, instance, address, moment=None):
    result = authz.record_presence_claim(con, instance.account, address,
                                         [address], now=moment or now(),
                                         origin=instance.origin)
    assert result.recorded, result.reason


def their_snapshot(targets):
    moment = now()
    return authz.snapshot_to_json(authz.SnapshotAuthority(
        {t: moment + timedelta(days=1) for t in targets},
        moment + timedelta(minutes=15)))


def queue(con, instance, addresses, ports=(22, 80), vantage="probe1",
          allowed=None, tls_ports=()):
    payload = {"version": dispatch.BATCH_VERSION, "vantage": vantage,
               "addresses": list(addresses), "ports": list(ports),
               "tls_ports": list(tls_ports),
               "snapshot": their_snapshot(addresses if allowed is None else allowed)}
    registry = vantages.list_all(con)
    parsed = proberapi.parse_batch(payload, {v.name for v in registry if v.enabled},
                                   vantages.all_addresses(con))
    return proberapi.submit(con, instance.id, parsed, now())


class Far:
    """One vantage host: the real runner in process, recording every batch it
    received and every connect it made."""

    def __init__(self):
        self.destinations = []
        self.batches = []
        self.connects = []

    def factory(self, destination):
        self.destinations.append(destination)
        return self

    def __call__(self, payload):
        batch = json.loads(payload)
        self.batches.append(batch)
        parsed = probe_runner.parse_batch(batch)
        outer = self

        async def connect(target, family, port):
            outer.connects.append((target, port))
            return 0.002

        return json.dumps(probe_runner.measure_batch(parsed, connect=connect))


def run(con, far):
    return proberapi_worker.run_round(con, transport_factory=far.factory,
                                      lock_wait_seconds=5)


def answer_of(con, instance, batch_id):
    state = proberapi.fetch(con, instance.id, batch_id, now())
    assert state["state"] == "done", state
    return prober.run_from_json(state["answer"])


def reasons(measured, target):
    return {(r.port, r.state, r.reason) for r in measured.results if r.target == target}


# ============================================ what may be probed, and by whom

def test_an_address_the_instance_proved_is_measured(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4])
    far = Far()
    assert run(con, far) == ["done"]
    assert far.connects == [(V4, 22), (V4, 80)]
    assert far.destinations == ["root@" + PROBE1_V4]
    measured = answer_of(con, one, batch_id)
    assert {r.state for r in measured.results if r.target == V4} == {
        prober.STATE_CONNECTED}
    # The runner answers under our vantage's name.
    assert measured.vantage == "probe1"


def test_the_snapshot_the_runner_gets_is_ours_under_the_instances_account(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    queue(con, one, [V4])
    far = Far()
    run(con, far)
    sent = far.batches[0]["snapshot"]
    assert set(sent["targets"]) == {V4}
    # Built now, by us, fifteen minutes long, whatever theirs said.
    expires = datetime.fromisoformat(sent["expires_at"])
    assert timedelta(minutes=14) < expires - now() <= timedelta(minutes=15)


def test_an_unproved_address_is_refused_by_the_runner_and_never_touched(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4, OTHER_V4])
    far = Far()
    run(con, far)
    assert all(target == V4 for target, _ in far.connects)
    measured = answer_of(con, one, batch_id)
    assert reasons(measured, OTHER_V4) == {
        (22, prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION),
        (80, prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


def test_an_expired_proof_is_refused(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4, moment=now() - timedelta(
        seconds=authz.AGENT_TTL_SECONDS + 60))
    batch_id = queue(con, one, [V4])
    far = Far()
    run(con, far)
    assert far.connects == []
    assert reasons(answer_of(con, one, batch_id), V4) == {
        (22, prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION),
        (80, prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


def test_another_instances_proof_does_not_help(con):
    """One instance's proof is never another's. Since 2026-10-20 the second
    could not prove the address either while the first holds it
    (docs/PRODUCT.md 5)."""
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    two = instances.add(con, "two", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, two, [V4])
    far = Far()
    run(con, far)
    assert far.connects == []
    assert {r.reason for r in answer_of(con, two, batch_id).results
            if r.target == V4} == {prober.REASON_NO_AUTHORIZATION}


def test_a_hosted_workspaces_proof_does_not_help_an_instance(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=now())
    authz.verify_proof(con, challenge.id, now=now(),
                       resolver=lambda name: [challenge.token])
    assert authz.may_probe(con, V4).allowed
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    queue(con, one, [V4])
    far = Far()
    run(con, far)
    assert far.connects == []


def test_their_snapshot_narrows_ours(con):
    """Proved to us, but their own registry no longer allows it, which is a
    revoke on their dashboard. It stops at once."""
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    presence(con, one, V6)
    queue(con, one, [V4, V6], allowed=[V6])
    far = Far()
    run(con, far)
    assert {target for target, _ in far.connects} == {V6}
    assert set(far.batches[0]["snapshot"]["targets"]) == {V6}


def test_their_snapshot_cannot_widen_ours(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    queue(con, one, [V4, OTHER_V4], allowed=[V4, OTHER_V4])
    far = Far()
    run(con, far)
    assert {target for target, _ in far.connects} == {V4}
    assert set(far.batches[0]["snapshot"]["targets"]) == {V4}


def test_a_revoked_instances_queued_batch_is_never_sent(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    queue(con, one, [V4])
    instances.revoke(con, "one")
    far = Far()
    assert run(con, far) == ["dropped"]
    assert far.batches == []
    assert con.execute("SELECT COUNT(*) FROM prober_api_batches").fetchone()[0] == 0


def test_a_revoked_instance_proves_nothing_any_more(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    instances.revoke(con, "one")
    assert not authz.may_probe(con, V4, account=one.account).allowed


# ============================================================ the failures

def test_a_vantage_switched_off_while_queued_fails_without_sending(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4])
    vantages.set_enabled(con, "probe1", False)
    far = Far()
    assert run(con, far) == ["vantage_unreachable"]
    assert far.batches == []
    assert proberapi.fetch(con, one.id, batch_id, now()) == {
        "state": "failed", "error": "vantage_unreachable"}


def test_an_address_that_became_ours_while_queued_is_never_sent(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4])
    vantages.add(con, "probe3", "root@" + V4, [V4])
    far = Far()
    assert run(con, far) == ["names_a_vantage_address"]
    assert far.batches == []
    assert proberapi.fetch(con, one.id, batch_id, now())["error"] == \
        "names_a_vantage_address"


@pytest.mark.parametrize("raised, failure", [
    (dispatch.VantageUnreachable("ssh could not reach it"), "vantage_unreachable"),
    (dispatch.DispatchFailed("the prober exited 2: the batch cannot be used"),
     "prober_refused"),
])
def test_a_transport_failure_is_handed_back_as_a_class(con, raised, failure):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4])

    def transport(payload):
        raise raised

    assert proberapi_worker.run_round(
        con, transport_factory=lambda d: transport, lock_wait_seconds=5) == [failure]
    state = proberapi.fetch(con, one.id, batch_id, now())
    # The class and nothing else: the sentence stays in our journal.
    assert state == {"state": "failed", "error": failure}


@pytest.mark.parametrize("raw", ["", "not json", "[]", '{"vantage": "probe1"}'])
def test_an_answer_that_is_not_a_measurement_is_never_handed_over(con, raw):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4])
    assert proberapi_worker.run_round(
        con, transport_factory=lambda d: (lambda payload: raw),
        lock_wait_seconds=5) == ["prober_answer_unreadable"]
    assert proberapi.fetch(con, one.id, batch_id, now())["error"] == \
        "prober_answer_unreadable"


def test_the_abuse_log_is_written_before_the_batch_is_sent(con):
    """An abuse report does not care whether we collected the answer."""
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    queue(con, one, [V4, OTHER_V4])
    seen = []

    def transport(payload):
        seen.extend(proberapi.log_for_target(con, V4))
        raise dispatch.VantageUnreachable("gone")

    proberapi_worker.run_round(con, transport_factory=lambda d: transport,
                               lock_wait_seconds=5)
    assert len(seen) == 1
    # Only the address the snapshot allowed could receive a packet.
    assert proberapi.log_for_target(con, OTHER_V4) == []
    assert seen[0]["instance_name"] == "one"
    assert seen[0]["connects"] == 2


def test_nothing_queued_is_nothing_run(con):
    far = Far()
    assert run(con, far) == []
    assert far.destinations == []


# One address belongs to one instance since 2026-10-20, so where several
# instances queue at once each holds an address of its own.
OWN_ADDRESSES = {"one": V4, "two": OTHER_V4, "three": "185.199.108.155"}


def test_the_queue_is_emptied_in_one_round(con):
    for name, address in OWN_ADDRESSES.items():
        instance = instances.add(con, name, origin=authz.ORIGIN_INVITED).instance
        presence(con, instance, address)
        queue(con, instance, [address])
    far = Far()
    assert run(con, far) == ["done", "done", "done"]


# ================================================================= the lock

def hold_the_lock(path):
    lock = probelock.ProbeLock(probelock.lock_path_for(db.connect(path)))
    lock.acquire()
    return lock


def test_a_batch_waits_for_a_pass_and_is_not_sent_while_one_runs(path, con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    queue(con, one, [V4])
    held = hold_the_lock(path)
    far = Far()
    try:
        with pytest.raises(probelock.ProbeLockHeld):
            proberapi_worker.run_round(con, transport_factory=far.factory,
                                       lock_wait_seconds=0.3)
        assert far.batches == []
    finally:
        held.release()
    # Still queued, and the next round sends it.
    assert run(con, far) == ["done"]


def test_an_idle_worker_never_asks_for_the_lock(path, con):
    """Held by a pass, and the worker with nothing queued returns at once
    rather than waiting its turn for nothing."""
    held = hold_the_lock(path)
    try:
        started = time.monotonic()
        assert proberapi_worker.run_round(con, transport_factory=Far().factory,
                                          lock_wait_seconds=30) == []
        assert time.monotonic() - started < 1
    finally:
        held.release()


def test_the_lock_is_let_go_after_the_hold(con):
    """A full queue does not keep our own timers out for longer than the
    hold: the round stops between batches and the rest wait for the next."""
    for name, address in OWN_ADDRESSES.items():
        instance = instances.add(con, name, origin=authz.ORIGIN_INVITED).instance
        presence(con, instance, address)
        queue(con, instance, [address])
    # Every batch takes twenty seconds on this clock, however often it is read.
    far = Far()
    outcomes = proberapi_worker.run_round(
        con, transport_factory=far.factory, lock_wait_seconds=5,
        hold_seconds=30.0, clock=lambda: 20.0 * len(far.batches))
    assert outcomes == ["done", "done"]
    assert proberapi.next_queued(con, now()) is not None


def test_serve_keeps_going_when_a_pass_holds_the_lock(path, con, monkeypatch):
    calls = []

    def round_that_waits_too_long(connection, keep_going):
        calls.append(1)
        raise probelock.ProbeLockHeld("held for the whole wait")

    monkeypatch.setattr(proberapi_worker, "run_round", round_that_waits_too_long)
    proberapi_worker.serve(con, rounds=3)
    assert len(calls) == 3


def test_a_stop_lets_the_running_batch_finish_and_starts_no_other(con):
    for name in ("one", "two"):
        instance = instances.add(con, name, origin=authz.ORIGIN_INVITED).instance
        presence(con, instance, OWN_ADDRESSES[name])
        queue(con, instance, [OWN_ADDRESSES[name]])
    stop = threading.Event()
    far = Far()

    def stopping_during_the_first(payload):
        stop.set()
        return far(payload)

    outcomes = proberapi_worker.run_round(
        con, transport_factory=lambda d: stopping_during_the_first,
        lock_wait_seconds=5, keep_going=lambda: not stop.is_set())
    assert outcomes == ["done"]
    assert len(far.batches) == 1


def test_a_batch_cut_off_by_the_last_stop_is_closed_when_the_worker_starts(con):
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    batch_id = queue(con, one, [V4])
    proberapi.mark_started(con, batch_id, now())
    stop = threading.Event()
    stop.set()
    proberapi_worker.serve(con, stop=stop)
    assert proberapi.fetch(con, one.id, batch_id, now()) == {
        "state": "failed", "error": "interrupted"}
    # And the slot is free.
    queue(con, one, [V4])


def test_the_yield_is_long_enough_for_a_waiting_pass_to_get_in():
    assert proberapi_worker.YIELD_SECONDS > probelock.POLL_SECONDS


# ============================================================ the promise

def an_instance(path, name, codes):
    """What a self-hosted instance's pass does, from its own connection: one
    host, one vantage after the other, each batch queued and then waited for.
    The routes do exactly this with a request each."""
    con = db.connect(path)
    try:
        instance = instances.by_name(con, name)
        for vantage in ("probe1", "probe2"):
            batch_id = queue(con, instance, [V4], ports=tuple(range(1, 31)),
                             vantage=vantage)
            deadline = time.monotonic() + 60
            while True:
                state = proberapi.fetch(con, instance.id, batch_id, now())
                if state["state"] in ("done", "failed"):
                    codes.append(state["state"])
                    break
                assert time.monotonic() < deadline, "the batch never finished"
                time.sleep(0.05)
    finally:
        con.close()


def a_worker(path, target, stop):
    """What the worker unit does, from its own connection. Two of these run,
    which production never does, so the lock is shown to hold even then."""
    con = db.connect(path)
    try:
        while not stop.is_set():
            proberapi_worker.run_round(
                con, transport_factory=lambda d: FakeVantage(target),
                lock_wait_seconds=60)
            time.sleep(0.02)
    finally:
        con.close()


def our_timer(path, target, codes):
    con = db.connect(path)
    try:
        codes.append(prober_cli.run(
            con, probe_args(transport_factory=lambda d: FakeVantage(target)),
            connect=RefusingConnect()))
    finally:
        con.close()


def test_two_instances_both_vantages_and_our_timer_never_overlap_on_a_target(tmp_path):
    """The per-target pace of docs/PRODUCT.md 5d, measured where it is
    promised. Two self-hosted instances watch the same address our own fleet
    watches, which since one address belongs to one instance is a database
    from before that rule. Each runs a pass from both vantages while our timer runs its own
    pass from both, and two workers serve the queue. The target sees one
    runner at a time and never more than one runner's pace.

    The bound is the one `tests/test_probe_lock.py` derives: a bucket of one
    token and RATE a second lets at most RATE + 2 into a one-second window
    across a batch boundary, and one more is slack for when the clock is read.
    That file's second test is the canary that this harness does see an
    overlap when nothing prevents one.
    """
    path = str(tmp_path / "cp.db")
    make_box(path)
    con = db.connect(path)
    for module in (instances, proberapi):
        module.init(con)
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    # The second instance on the same address can only be a proof written
    # before one address belonged to one instance (docs/PRODUCT.md 5,
    # 2026-10-20), which a database carries for up to an hour after the
    # deploy. It is the most the lock has to hold against, so it is written
    # here the way such a row sits in the table.
    two = instances.add(con, "two", origin=authz.ORIGIN_INVITED).instance
    con.execute(
        "INSERT INTO authorizations (target, family, method, evidence, account,"
        " host_id, verified_at, expires_at) VALUES (?, 'v4', 'agent', '{}', ?,"
        " NULL, ?, ?)", (V4, two.account, now().isoformat(),
                         (now() + timedelta(hours=1)).isoformat()))
    con.commit()
    con.close()

    target = Target()
    codes, stop = [], threading.Event()
    workers = [threading.Thread(target=a_worker, args=(path, target, stop))
               for _ in range(2)]
    passes = [threading.Thread(target=an_instance, args=(path, "one", codes)),
              threading.Thread(target=an_instance, args=(path, "two", codes)),
              threading.Thread(target=our_timer, args=(path, target, codes))]
    for thread in workers + passes:
        thread.start()
    for thread in passes:
        thread.join()
    stop.set()
    for thread in workers:
        thread.join()

    assert sorted(map(str, codes)) == ["0", "done", "done", "done", "done"]
    # Three passes, two vantages each, thirty ports each.
    assert len(target.stamps) == 3 * 2 * 30
    assert target.worst_in_flight == 1
    assert target.worst_second() <= RATE + 3, target.worst_second()


def test_main_once_runs_a_round_and_exits(path, monkeypatch, capsys):
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setattr(proberapi_worker, "run_round", lambda con: ["done"])
    assert proberapi_worker.main(["--once"]) == 0
    assert "1 batches: done" in capsys.readouterr().out


def test_main_once_says_so_when_a_pass_held_the_lock(path, monkeypatch, capsys):
    def held(con):
        raise probelock.ProbeLockHeld("held")

    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setattr(proberapi_worker, "run_round", held)
    assert proberapi_worker.main(["--once"]) == probelock.EXIT_HELD


def test_the_worker_parses_no_argument_that_could_name_a_target():
    """Every target arrives in a batch and is governed by a snapshot."""
    assert vars(proberapi_worker.parse_args([])) == {"once": False}
    with pytest.raises(SystemExit):
        proberapi_worker.parse_args(["--target", V4])
    assert isinstance(argparse.Namespace(), argparse.Namespace)


def test_the_journal_says_what_each_batch_cost(con, caplog):
    """What one batch costs decides how many instances one lock carries, and
    it is read off the box's journal before invites (ops/RUNBOOK.md)."""
    one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
    presence(con, one, V4)
    queue(con, one, [V4])
    with caplog.at_level("INFO", logger="app.proberapi_worker"):
        run(con, Far())
    assert any("from probe1: done in" in message for message in caplog.messages)
