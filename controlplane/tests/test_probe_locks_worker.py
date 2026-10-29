"""The prober API's worker on the finer locks (docs/SPEC-probe-locks.md,
points 3 to 5): one thread per prober, each holding its prober's lock across
batches for up to a hold and letting go for a yield, and each batch taking
the stripes of the addresses our registry allows its instance.

  - both probers serve instances at once, one batch each at a time
  - a batch's stripes are only of addresses our registry allows its
    instance, and its snapshot is built from that locked set after them
  - a revoke during the wait for a prober or an address holds
  - our pass gets its prober within one hold and one yield
  - one worker at a time, and a second one closes nothing
  - a locked database ends no thread
  - across every source at once, one runner per target and today's worst
    second, and a dual-stack machine held by two holders is per address

The far end is the real runner in process. The clock and the sleeps are
real, because the property is what a target receives per second of wall time.
"""
import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import (authz, db, dispatch, instances, probelock, prober, prober_cli,
                 proberapi, proberapi_worker, scan, scan_cli, store, vantages)

from test_probe_lock import (RATE, FakeVantage, RefusingConnect, Target,
                             drain_args, make_box, probe_args, request_scan)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"


def now():
    return datetime.now(timezone.utc)


@pytest.fixture(autouse=True)
def no_real_ssh(monkeypatch):
    """Nothing here may reach a real server."""
    real = dispatch.SshTransport.__call__

    def guarded(self, payload):
        assert self.ssh != "ssh", f"a test reached for real ssh to {self.destination}"
        return real(self, payload)

    monkeypatch.setattr(dispatch.SshTransport, "__call__", guarded)


@pytest.fixture()
def path(tmp_path):
    """Our box: server `box` on V4 proved by its agent, probe1 and probe2,
    and the tables the prober API keeps."""
    where = str(tmp_path / "cp.db")
    make_box(where)
    con = db.connect(where)
    for module in (instances, proberapi):
        module.init(con)
    con.close()
    return where


@pytest.fixture()
def con(path):
    connection = db.connect(path)
    yield connection
    connection.close()


def an_instance(con, name, address=None):
    instance = instances.add(con, name, origin=authz.ORIGIN_INVITED).instance
    if address is not None:
        result = authz.record_presence_claim(con, instance.account, address,
                                             [address], now=now(),
                                             origin=instance.origin)
        assert result.recorded, result.reason
    return instance


def queue(con, instance, addresses, vantage="probe1", ports=(22, 80), allowed=None):
    moment = now()
    theirs = authz.snapshot_to_json(authz.SnapshotAuthority(
        {a: moment + timedelta(days=1) for a in (allowed or addresses)},
        moment + timedelta(minutes=15)))
    parsed = proberapi.parse_batch(
        {"version": dispatch.BATCH_VERSION, "vantage": vantage,
         "addresses": list(addresses), "ports": list(ports), "tls_ports": [],
         "snapshot": theirs},
        {v.name for v in vantages.enabled(con)}, vantages.all_addresses(con))
    return proberapi.submit(con, instance.id, parsed, moment)


def row(con, name):
    return vantages.by_name(con, name)


def is_free(lock_path):
    import fcntl
    if not os.path.exists(lock_path):
        return True
    fd = os.open(lock_path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


class Far(FakeVantage):
    """A vantage host on a target, with something to run inside each batch."""

    def __init__(self, target, during=None):
        super().__init__(target)
        self.during = during
        self.sent = []

    def __call__(self, payload):
        self.sent.append(payload)
        if self.during is not None:
            self.during(payload)
        return super().__call__(payload)


def state_of(con, instance, batch_id):
    return proberapi.fetch(con, instance.id, batch_id, now())


# ============================================= one thread per prober


def test_the_worker_runs_both_probers_at_once(path, con):
    """Two instances, one on each prober. Each batch waits inside the runner
    for the other, so they pass only when both are in flight together."""
    one = an_instance(con, "one", V4)
    two = an_instance(con, "two", OTHER_V4)
    ids = (queue(con, one, [V4], "probe1"), queue(con, two, [OTHER_V4], "probe2"))
    both = threading.Barrier(2, timeout=5)
    target = Target()
    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory":
                                      lambda d: Far(target, lambda p: both.wait())})
    server.start()
    try:
        deadline = time.monotonic() + 10
        reader = db.connect(path)
        try:
            states = []
            while time.monotonic() < deadline:
                states = [reader.execute(
                    "SELECT finished_at, failure FROM prober_api_batches WHERE id = ?",
                    (i,)).fetchone() for i in ids]
                if all(s["finished_at"] for s in states):
                    break
                time.sleep(0.05)
        finally:
            reader.close()
    finally:
        stop.set()
        server.join(10)
    assert all(s["finished_at"] for s in states), "the worker never served them"
    assert [s["failure"] for s in states] == [None, None]
    assert not both.broken


def test_never_two_batches_on_one_prober_from_the_worker(path):
    """Two rounds on one prober at once, which only two workers could do and
    the life lock stops: the prober's lock still keeps them one at a time."""
    con = db.connect(path)
    for name, address in (("one", V4), ("two", OTHER_V4), ("three", "185.199.108.155")):
        queue(con, an_instance(con, name, address), [address], "probe1")
    con.close()
    in_flight, worst, lock = [0], [0], threading.Lock()

    def slow(payload):
        with lock:
            in_flight[0] += 1
            worst[0] = max(worst[0], in_flight[0])
        time.sleep(0.2)
        with lock:
            in_flight[0] -= 1

    def a_round():
        c = db.connect(path)
        try:
            proberapi_worker.run_round(
                c, transport_factory=lambda d: Far(Target(), slow),
                lock_wait_seconds=10)
        finally:
            c.close()

    threads = [threading.Thread(target=a_round) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert worst[0] == 1


# ===================================== the stripes, and the snapshot after them


def test_an_address_the_instance_does_not_hold_takes_no_stripe(path, con):
    """Its batch names OTHER_V4, which it never proved to us, beside V4,
    which it did. Another batch holds OTHER_V4's stripe, and this one runs
    at once all the same, holding V4's alone."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4, OTHER_V4])
    directory = os.path.dirname(path)
    other = probelock.Locks(directory, addresses=[OTHER_V4], pass_lock=False)
    assert other.try_acquire() is None
    seen = []
    try:
        far = Far(Target(), lambda p: seen.append(
            is_free(probelock.stripe_path(directory, probelock.stripe_of(V4)))))
        assert proberapi_worker.run_round(con, transport_factory=lambda d: far,
                                          lock_wait_seconds=5) == ["done"]
    finally:
        other.release()
    assert seen == [False]
    assert state_of(con, one, batch_id)["state"] == "done"


def test_the_worker_builds_its_snapshot_after_its_locks(path, con, monkeypatch):
    one = an_instance(con, "one", V4)
    queue(con, one, [V4])
    directory = os.path.dirname(path)
    theirs = [probelock.prober_path(directory, row(con, "probe1").id),
              probelock.stripe_path(directory, probelock.stripe_of(V4))]
    seen = []
    real = authz.build_snapshot

    def watched(*args, **kwargs):
        seen.append([is_free(p) for p in theirs])
        return real(*args, **kwargs)

    monkeypatch.setattr(authz, "build_snapshot", watched)
    assert proberapi_worker.run_round(
        con, transport_factory=lambda d: Far(Target()), lock_wait_seconds=5) == ["done"]
    assert seen == [[False, False]]


def test_a_revoke_while_the_worker_waits_for_an_address_is_honoured(path, con):
    """The address is busy, so the batch is passed over and stays queued.
    Its proof is revoked meanwhile. When the address is free the snapshot is
    built then, says no, and nothing connects to it."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4])
    directory = os.path.dirname(path)
    other = probelock.Locks(directory, addresses=[V4], pass_lock=False)
    assert other.try_acquire() is None
    far = Far(Target())
    try:
        assert proberapi_worker.run_round(con, transport_factory=lambda d: far,
                                          lock_wait_seconds=5) == []
        assert far.sent == []
        assert authz.revoke(con, V4, account=one.account) == 1
    finally:
        other.release()
    assert proberapi_worker.run_round(con, transport_factory=lambda d: far,
                                      lock_wait_seconds=5) == ["done"]
    assert far.target.stamps == []
    answer = prober.run_from_json(state_of(con, one, batch_id)["answer"])
    assert {r.reason for r in answer.results if r.target == V4} == {
        prober.REASON_NO_AUTHORIZATION}


def test_an_instance_revoked_while_its_batch_waits_for_its_prober_sends_nothing(path, con):
    one = an_instance(con, "one", V4)
    queue(con, one, [V4])
    directory = os.path.dirname(path)
    ours = probelock.Locks(directory, prober=row(con, "probe1").id)
    assert ours.try_acquire() is None
    far = Far(Target())
    kept = {}

    def a_round():
        c = db.connect(path)
        try:
            kept["outcomes"] = proberapi_worker.run_round(
                c, transport_factory=lambda d: far, lock_wait_seconds=10)
        finally:
            c.close()

    worker = threading.Thread(target=a_round)
    try:
        worker.start()
        time.sleep(0.3)
        assert far.sent == []
        instances.revoke(con, "one")
    finally:
        ours.release()
    worker.join(10)
    assert kept["outcomes"] == ["dropped"]
    assert far.sent == []


# ============================================ our pass, within a hold and a yield


def test_our_pass_gets_its_prober_within_one_hold_and_one_yield(path, monkeypatch):
    """probe1's queue stays full the whole time. Our pass asks for probe1
    once a poll, as flock lets it, and gets in during the worker's yield."""
    monkeypatch.setattr(proberapi_worker, "HOLD_SECONDS", 1.0)
    con = db.connect(path)
    for n in range(1, 41):
        address = f"185.199.109.{n}"
        queue(con, an_instance(con, f"i{n}", address), [address], "probe1")
    con.close()

    def slow(payload):
        time.sleep(0.2)

    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory":
                                      lambda d: Far(Target(), slow)})
    server.start()
    try:
        time.sleep(0.5)
        reached = []
        started = time.monotonic()
        our = db.connect(path)
        try:
            code = prober_cli.run(our, probe_args(
                vantage="probe1",
                transport_factory=lambda d: Far(Target(), lambda p: reached.append(
                    time.monotonic() - started))), connect=RefusingConnect())
        finally:
            our.close()
        left = db.connect(path)
        try:
            queued = left.execute("SELECT COUNT(*) FROM prober_api_batches"
                                  " WHERE started_at IS NULL").fetchone()[0]
        finally:
            left.close()
    finally:
        stop.set()
        server.join(30)
    assert code == 0
    # The queue was still full when ours ran.
    assert queued > 0
    bound = (proberapi_worker.HOLD_SECONDS + proberapi_worker.YIELD_SECONDS
             + probelock.POLL_SECONDS + 0.2 + 1.0)
    assert reached and reached[0] <= bound, (reached, bound)


def _serve_from_path(path, stop, **kwargs):
    con = db.connect(path)
    try:
        proberapi_worker.serve(con, stop=stop, **kwargs)
    finally:
        con.close()


# ================================================ one worker, and its database


def test_a_second_worker_exits_and_closes_nothing(path, con, caplog):
    """The first worker's batch is running. A second worker started by hand
    finds the first one's lock, exits at once, and the running batch is
    still running, not closed as interrupted."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4])
    assert proberapi.mark_started(con, batch_id, now())
    first = proberapi_worker.WorkerLock.for_connection(con)
    assert first.try_acquire()
    try:
        started = time.monotonic()
        with caplog.at_level("WARNING", logger="app.proberapi_worker"):
            code = proberapi_worker.serve(con, stop=threading.Event())
        assert time.monotonic() - started < 2
    finally:
        first.release()
    assert code == probelock.EXIT_HELD
    assert state_of(con, one, batch_id) == {"state": "running"}
    assert any("another worker" in m for m in caplog.messages)


def test_the_worker_closes_what_the_last_one_left_only_once_it_holds_its_lock(path, con):
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4])
    assert proberapi.mark_started(con, batch_id, now())
    stop = threading.Event()
    stop.set()
    assert proberapi_worker.serve(con, stop=stop) == 0
    assert state_of(con, one, batch_id) == {"state": "failed", "error": "interrupted"}


def test_a_locked_database_ends_no_worker_thread(path, con, monkeypatch, caplog):
    """The first round of each thread meets "database is locked". The thread
    says the class in the journal and goes on, and the batch is served."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4])
    real = proberapi_worker.run_prober_round
    met = set()

    def locked_once(connection, vantage, **kwargs):
        if vantage.name not in met:
            met.add(vantage.name)
            raise sqlite3.OperationalError("database is locked")
        return real(connection, vantage, **kwargs)

    monkeypatch.setattr(proberapi_worker, "run_prober_round", locked_once)
    stop = threading.Event()
    with caplog.at_level("WARNING", logger="app.proberapi_worker"):
        server = threading.Thread(target=_serve_from_path, args=(path, stop),
                                  kwargs={"transport_factory": lambda d: Far(Target())})
        server.start()
        try:
            deadline = time.monotonic() + 10
            reader = db.connect(path)
            try:
                while time.monotonic() < deadline:
                    done = reader.execute(
                        "SELECT finished_at FROM prober_api_batches WHERE id = ?",
                        (batch_id,)).fetchone()["finished_at"]
                    if done:
                        break
                    time.sleep(0.05)
            finally:
                reader.close()
        finally:
            stop.set()
            server.join(10)
    assert done
    assert met == {"probe1", "probe2"}
    assert any("OperationalError" in m for m in caplog.messages)


def quick_to_refuse(monkeypatch):
    """Every connection the worker opens gives up on a lock after 0.2 s, not
    5 s, and an idle round comes every 0.1 s, so a write held past the busy
    timeout takes a second to show and not half a minute."""
    real = db.connect

    def connect(where=None):
        connection = real(where)
        connection.execute("PRAGMA busy_timeout = 200")
        return connection

    monkeypatch.setattr(proberapi_worker.db, "connect", connect)
    monkeypatch.setattr(proberapi_worker, "IDLE_POLL_SECONDS", 0.1)


def hold_the_write_lock(path, seconds):
    """What an erase's VACUUM does to everybody else: one writer holds the
    database for longer than the busy timeout, then commits."""
    writer = sqlite3.connect(path, isolation_level=None)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("CREATE TABLE IF NOT EXISTS held (x)")
        writer.executemany("INSERT INTO held VALUES (?)", [(b"x" * 4000,)] * 100)
        time.sleep(seconds)
        writer.execute("COMMIT")
    finally:
        writer.close()


def every_frame_checkpoints(path):
    """Write some frames, give the worker a few rounds, then checkpoint.
    A connection inside an old read transaction keeps the checkpoint from
    copying the frames written after its snapshot, and keeps the -wal file
    from being emptied, so it grows for as long as that connection lives."""
    other = sqlite3.connect(path)
    try:
        other.execute("CREATE TABLE IF NOT EXISTS later (x)")
        for i in range(20):
            other.execute("INSERT INTO later VALUES (?)", (i,))
            other.commit()
        time.sleep(0.5)
        _busy, frames, copied = other.execute(
            "PRAGMA wal_checkpoint(PASSIVE)").fetchone()
        other.execute("PRAGMA busy_timeout = 2000")
        busy, _frames, _copied = other.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        return frames == copied and busy == 0, (frames, copied, busy)
    finally:
        other.close()


def test_a_write_held_past_the_busy_timeout_leaves_no_thread_in_an_old_snapshot(
        path, con, monkeypatch):
    """A round's first write is the sweep's DELETE, and Python opens a
    transaction for it. Refused by a writer that held the database past the
    busy timeout, it left that transaction open, the next round read inside
    it, and the thread kept that snapshot for good: no checkpoint past it,
    every write after refused, and no batch queued later ever seen. Measured
    on the box on 2026-10-28 after an erase's VACUUM."""
    one = an_instance(con, "one", V4)
    quick_to_refuse(monkeypatch)
    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory": lambda d: Far(Target())})
    server.start()
    try:
        time.sleep(0.5)
        hold_the_write_lock(path, 1.5)
        time.sleep(1.0)
        checkpointed, numbers = every_frame_checkpoints(path)
        batch_id = queue(con, one, [V4])
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            finished = con.execute(
                "SELECT finished_at FROM prober_api_batches WHERE id = ?",
                (batch_id,)).fetchone()["finished_at"]
            if finished:
                break
            time.sleep(0.05)
    finally:
        stop.set()
        server.join(10)
    assert checkpointed, numbers
    assert finished, "a batch queued after the write was never served"


def test_a_refused_look_at_the_registry_leaves_the_worker_in_no_old_snapshot(
        path, con, monkeypatch):
    """The worker's own loop writes when it closes a batch for a prober taken
    out of the registry. The same refusal there left the worker's main
    connection inside the old snapshot, and the batch never closed."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4], "probe2")
    vantages.remove(con, "probe2")
    quick_to_refuse(monkeypatch)
    # The loop's first close waits for the writer to hold the database, so
    # the close is refused as it was on the box. Every later one runs as is.
    held = threading.Event()
    real = proberapi_worker.close_unserved

    def after_the_writer(connection, moment):
        held.wait(5)
        return real(connection, moment)

    monkeypatch.setattr(proberapi_worker, "close_unserved", after_the_writer)
    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop))
    server.start()
    try:
        time.sleep(0.3)
        writer = threading.Thread(target=hold_the_write_lock, args=(path, 1.5))
        writer.start()
        time.sleep(0.2)
        held.set()
        writer.join(10)
        time.sleep(1.0)
        checkpointed, numbers = every_frame_checkpoints(path)
    finally:
        stop.set()
        server.join(10)
    assert checkpointed, numbers
    assert state_of(con, one, batch_id) == {"state": "failed",
                                            "error": "vantage_unreachable"}


def test_a_batch_for_a_vantage_taken_out_of_the_registry_fails_at_once(path, con):
    """It was queued while the vantage was there. No thread serves a row
    that is gone, so the batch is closed rather than left to wait out its
    fifteen minutes."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4], "probe2")
    vantages.remove(con, "probe2")
    assert proberapi_worker.run_round(con, transport_factory=lambda d: Far(Target()),
                                      lock_wait_seconds=5) == ["vantage_unreachable"]
    assert state_of(con, one, batch_id) == {"state": "failed",
                                            "error": "vantage_unreachable"}


# ============================================== every source at once, at the target


class LocalOnTarget:
    """The local mode's connect, counted at the target. Each host the local
    mode probes is one runner, so `Prober.run` marks it in flight."""

    def __init__(self, target):
        self.target = target

    async def __call__(self, address, family, port):
        self.target.connected()
        return 0.002


def every_source(path, target, monkeypatch, ports_note=""):
    """Our fast lane and hourly lane from both probers, a Scan now drain, a
    pass --via probe1, the local mode, and the worker serving an instance
    whose batches name the same address, all landing together on V4."""
    con = db.connect(path)
    one = an_instance(con, "one")
    # The instance on the address our server holds, written as a row from
    # before one address belonged to one instance, the most the locks have
    # to hold against (as tests/test_proberapi_worker.py does).
    con.execute(
        "INSERT INTO authorizations (target, family, method, evidence, account,"
        " host_id, verified_at, expires_at) VALUES (?, 'v4', 'agent', '{}', ?,"
        " NULL, ?, ?)", (V4, one.account, now().isoformat(),
                         (now() + timedelta(hours=1)).isoformat()))
    con.commit()
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'box'").fetchone()[0]
    con.close()
    request_scan(path, host_id)

    real_run = prober.Prober.run

    async def counted_run(self, *args, **kwargs):
        target.batch_started()
        try:
            return await real_run(self, *args, **kwargs)
        finally:
            target.batch_ended()

    monkeypatch.setattr(prober.Prober, "run", counted_run)
    factory = lambda d: FakeVantage(target)  # noqa: E731
    codes = []

    def lane(kind):
        c = db.connect(path)
        try:
            if kind == "scan":
                codes.append(scan_cli.run(c, drain_args(transport_factory=factory)))
            elif kind == "via":
                codes.append(prober_cli.run(c, probe_args(
                    registry=False, vantage="probe1", via="root@" + PROBE1_V4,
                    transport_factory=factory), connect=RefusingConnect()))
            elif kind == "local":
                codes.append(prober_cli.run(c, probe_args(
                    registry=False, vantage="laptop"), connect=LocalOnTarget(target)))
            elif kind == "instance":
                instance = instances.by_name(c, "one")
                for vantage in ("probe1", "probe2"):
                    batch_id = queue(c, instance, [V4], vantage, ports=range(1, 31))
                    deadline = time.monotonic() + 60
                    while True:
                        state = state_of(c, instance, batch_id)
                        if state["state"] in ("done", "failed"):
                            codes.append(state["state"])
                            break
                        assert time.monotonic() < deadline
                        time.sleep(0.05)
            else:
                codes.append(prober_cli.run(c, probe_args(transport_factory=factory),
                                            connect=RefusingConnect()))
        finally:
            c.close()

    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory": factory})
    lanes = [threading.Thread(target=lane, args=(kind,))
             for kind in ("fast", "hourly", "scan", "via", "local", "instance")]
    server.start()
    for thread in lanes:
        thread.start()
    for thread in lanes:
        thread.join()
    stop.set()
    server.join(30)
    return codes


def test_two_batches_sharing_an_address_never_overlap_from_any_source(path, monkeypatch):
    target = Target()
    codes = every_source(path, target, monkeypatch)
    assert sorted(map(str, codes)) == ["0", "0", "0", "0", "0", "done", "done"]
    # Two lanes from two vantages, a drain from two, a via pass, the local
    # mode and the instance from two: ten runners of thirty ports each.
    assert len(target.stamps) == 10 * 30
    assert target.worst_in_flight == 1


def test_the_worst_second_at_a_target_stays_within_today_s_ceiling(path, monkeypatch):
    """The bound tests/test_probe_lock.py derives for today's lock: a bucket
    of one token and RATE a second lets at most RATE + 2 into a one-second
    window across a batch boundary, and one more is slack for the clock."""
    target = Target()
    every_source(path, target, monkeypatch)
    assert target.worst_second() <= RATE + 3, target.worst_second()


# ================================== 5d, per batch's addresses, as point 9 accepts


def test_a_dual_stack_host_in_two_batches_from_two_holders(path, con):
    """One machine with V4 and V6. Instance one holds V4 and instance two
    holds V6, which two instances can, since one address belongs to one
    instance and not one machine. Their two batches name one address each,
    so they run at once from the two probers: the machine receives two
    runners, one on each address. That is what point 9 of the spec accepts,
    and docs/PRODUCT.md 5d says so: the 40 a second is per address of a
    batch, and no address ever has two runners at once."""
    one = an_instance(con, "one", V4)
    two = an_instance(con, "two", V6)
    queue(con, one, [V4], "probe1")
    queue(con, two, [V6], "probe2")
    both = threading.Barrier(2, timeout=5)
    per_address = {V4: Target(), V6: Target()}

    def at_once(payload):
        both.wait()

    def factory(destination):
        class OnItsAddress(Far):
            def __call__(self, payload):
                import json
                (address,) = json.loads(payload)["addresses"]
                self.target = per_address[address]
                return super().__call__(payload)
        return OnItsAddress(Target(), at_once)

    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory": factory})
    server.start()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not all(
                t.stamps for t in per_address.values()):
            time.sleep(0.05)
    finally:
        stop.set()
        server.join(10)
    assert not both.broken, "the two addresses' batches did not run at once"
    for address, target in per_address.items():
        assert target.stamps, address
        assert target.worst_in_flight == 1
        assert target.worst_second() <= RATE + 3


# ========================================== the code challenge, 2026-10-28


def test_a_thread_that_meets_any_other_error_ends_the_worker_for_systemd(path, con, caplog):
    """Finding 1. Before phase 1 an error of no known kind ended the worker,
    systemd started it again 5 s later, and the batch it cut off was closed
    as interrupted. A thread that died quietly would lose its prober for
    every instance until somebody restarted the unit. So the worker ends,
    says which prober and which class, and its next start closes the batch."""
    one = an_instance(con, "one", V4)
    batch_id = queue(con, one, [V4], "probe1")

    def factory(destination):
        def broken(payload):
            raise ValueError("not a transport's failure")
        return broken

    stop, kept = threading.Event(), {}

    def serving():
        connection = db.connect(path)
        try:
            kept["code"] = proberapi_worker.serve(connection, stop=stop,
                                                  transport_factory=factory)
        finally:
            connection.close()

    server = threading.Thread(target=serving)
    with caplog.at_level("WARNING", logger="app.proberapi_worker"):
        server.start()
        server.join(10)
        ended_by_itself = not server.is_alive()
        stop.set()
        server.join(10)
    assert ended_by_itself, "the worker kept running with a dead thread"
    assert kept["code"] == 1
    assert any("probe1" in m and "ValueError" in m for m in caplog.messages)
    assert state_of(con, one, batch_id) == {"state": "running"}
    # What systemd does next: the worker starts again, and its first act
    # closes the batch the dead thread had claimed.
    stop = threading.Event()
    stop.set()
    assert proberapi_worker.serve(con, stop=stop) == 0
    assert state_of(con, one, batch_id) == {"state": "failed", "error": "interrupted"}


def add_server(path, name, address):
    con = db.connect(path)
    try:
        host_id, _ = store.add_host(con, name)
        document = json.dumps({
            "sockets": {"listening": [
                {"protocol": "tcp", "port": port, "bind_address": "0.0.0.0",
                 "family": "v4"} for port in (22, 80)]},
            "interface_addresses": {"addresses": [
                {"interface": "eth0", "family": "v4", "address": address,
                 "global": True}]}})
        store.insert_report(con, host_id, 1, 1, document)
        proof = authz.record_agent_proof(con, host_id, address, document, now=now())
        assert proof.recorded, proof.reason
        con.commit()
    finally:
        con.close()


def test_our_pass_waits_once_and_not_per_host_under_full_queues(path, monkeypatch):
    """Finding 3. Both probers' queues stay full. A pass of four servers
    once waited about one hold and one yield of the worker for every server
    on every prober, because it lets go of a prober between its batches.
    The worker steps aside while a pass of ours holds `probe.ours`, so the
    pass waits for at most the batch each thread is running when it starts."""
    monkeypatch.setattr(proberapi_worker, "HOLD_SECONDS", 3.0)
    for n, address in enumerate(("185.199.108.154", "185.199.108.155",
                                 "185.199.108.156"), start=2):
        add_server(path, f"box{n}", address)
    con = db.connect(path)
    for n in range(1, 121):
        address = f"185.199.109.{n}"
        vantage = "probe1" if n % 2 else "probe2"
        queue(con, an_instance(con, f"i{n}", address), [address], vantage)
    con.close()

    def theirs(destination):
        pause = 0.5 if destination.endswith(PROBE1_V4) else 0.7
        return Far(Target(), lambda p: time.sleep(pause))

    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory": theirs})
    server.start()
    try:
        time.sleep(1.0)
        ours = 1.0
        started = time.monotonic()
        our = db.connect(path)
        try:
            code = prober_cli.run(our, probe_args(
                transport_factory=lambda d: Far(Target(), lambda p: time.sleep(ours))),
                connect=RefusingConnect())
        finally:
            our.close()
        took = time.monotonic() - started
        left = db.connect(path)
        try:
            queued = left.execute("SELECT COUNT(*) FROM prober_api_batches"
                                  " WHERE started_at IS NULL").fetchone()[0]
        finally:
            left.close()
    finally:
        stop.set()
        server.join(30)
    assert code == 0
    assert queued > 0, "the queues were not full while our pass ran"
    # Our eight batches, then at most one batch of theirs and one poll of
    # ours before the first, and slack for the reads of the database.
    bound = 8 * ours + 0.7 + probelock.POLL_SECONDS + 2.0
    assert took <= bound, (took, bound)


def test_a_prober_taken_out_and_added_again_is_served_by_its_new_row(path, con):
    """Finding 5. Taken out of the registry and added again, probe1 has a
    new row and a new lock. The thread of its old row ends, the new row gets
    a thread, and every batch for probe1 is served, none closed as the
    vantage being unreachable."""
    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory": lambda d: Far(Target())})
    server.start()
    try:
        time.sleep(0.5)
        old = row(con, "probe1")
        vantages.remove(con, "probe1")
        vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
        assert row(con, "probe1").id != old.id
        time.sleep(2.5)
        ids = []
        for n in range(1, 6):
            address = f"185.199.109.{n}"
            ids.append(queue(con, an_instance(con, f"i{n}", address), [address],
                             "probe1"))
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            rows = [con.execute("SELECT finished_at, failure FROM prober_api_batches"
                                " WHERE id = ?", (i,)).fetchone() for i in ids]
            if all(r["finished_at"] for r in rows):
                break
            time.sleep(0.1)
        threads = sorted(t.name for t in threading.enumerate()
                         if t.name.startswith("prober-"))
    finally:
        stop.set()
        server.join(15)
    assert [r["failure"] for r in rows] == [None] * 5
    assert f"prober-{old.id}" not in threads


def test_a_stop_is_seen_while_a_thread_waits_for_its_prober(path, con):
    """Finding 6. A pass of ours holds probe1 and a batch waits for it. A
    stop ends the worker within about a poll, not when the pass lets go."""
    one = an_instance(con, "one", V4)
    queue(con, one, [V4], "probe1")
    ours = probelock.Locks(os.path.dirname(path), prober=row(con, "probe1").id)
    assert ours.try_acquire() is None
    stop = threading.Event()
    server = threading.Thread(target=_serve_from_path, args=(path, stop),
                              kwargs={"transport_factory": lambda d: Far(Target())})
    try:
        server.start()
        time.sleep(1.5)
        stop.set()
        stopped = time.monotonic()
        server.join(10)
        took = time.monotonic() - stopped
        alive = server.is_alive()
    finally:
        ours.release()
        server.join(10)
    assert not alive
    assert took < 2.5, took


def test_a_batch_is_never_run_without_its_prober_and_its_locked_addresses(path, con):
    """Finding 7. `run_batch` builds a snapshot, so it is never called
    without the row whose lock is held and the addresses whose stripes are."""
    one = an_instance(con, "one", V4)
    queue(con, one, [V4])
    batch = proberapi.next_queued(con, now())
    with pytest.raises(TypeError):
        proberapi_worker.run_batch(con, batch, lambda d: Far(Target()), now())
