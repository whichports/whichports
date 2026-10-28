"""One probing pass at a time from this machine (app/probelock.py).

The far end is the real runner in process, a fresh Prober per batch exactly as
on a vantage host, against a fake socket that records the moment it was asked.
**The clock is real and so are the sleeps.** The property under test is what
one target receives per second of wall time from three commands that are three
processes in production, and a fake clock shared across threads would measure
the fake. The tests are therefore slow by a few seconds and that is the point.

Two threads stand in for two processes, and that is a faithful stand-in: each
opens the lock file itself, and flock(2) treats separate descriptors on one
file independently, so they exclude each other as two processes would.
"""
import argparse
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

import pytest

from app import (authz, db, probelock, probe_runner, prober, prober_cli, scan,
                 scan_cli, store, vantages)

V4 = "185.199.108.153"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"
# The engine's own pace, so the numbers below are the production numbers.
RATE = prober.CONNECTS_PER_SECOND_PER_TARGET
PORTS = tuple(range(1, 31))


# ------------------------------------------------------------------ a box


def make_box(path: str) -> int:
    """A control plane database with one reporting host, one proved address,
    and two vantages. Returns the host id."""
    con = db.connect(path)
    try:
        db.init(con)
        authz.init(con)
        prober.init(con)
        scan.init(con)
        vantages.init(con)
        host_id, _ = store.add_host(con, "box")
        document = json.dumps({
            "sockets": {"listening": [
                {"protocol": "tcp", "port": port, "bind_address": "0.0.0.0",
                 "family": "v4"} for port in PORTS]},
            "interface_addresses": {"addresses": [
                {"interface": "eth0", "family": "v4", "address": V4,
                 "global": True}]}})
        store.insert_report(con, host_id, 1, 1, document)
        proof = authz.record_agent_proof(con, host_id, V4, document,
                                         now=datetime.now(timezone.utc))
        assert proof.recorded, proof.reason
        vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
        vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
        con.commit()
    finally:
        con.close()
    return host_id


@pytest.fixture()
def box(tmp_path):
    path = str(tmp_path / "cp.db")
    host_id = make_box(path)
    return path, host_id


# ------------------------------------------------------------- the target


class Target:
    """The far side's view of one host: every connect with the moment it
    arrived, and how many of our runners were against it at once."""

    def __init__(self):
        self._lock = threading.Lock()
        self.stamps = []
        self.in_flight = 0
        self.worst_in_flight = 0

    def batch_started(self):
        with self._lock:
            self.in_flight += 1
            self.worst_in_flight = max(self.worst_in_flight, self.in_flight)

    def batch_ended(self):
        with self._lock:
            self.in_flight -= 1

    def connected(self):
        with self._lock:
            self.stamps.append(time.monotonic())

    def worst_second(self) -> int:
        """The most connects inside any one-second window, the window closed
        at both ends, which is the pessimistic reading."""
        stamps = sorted(self.stamps)
        worst = start = 0
        for end, moment in enumerate(stamps):
            while stamps[start] < moment - 1.0:
                start += 1
            worst = max(worst, end - start + 1)
        return worst


class FakeVantage:
    """One vantage host. Every call is one batch, which on the real box is one
    fresh process with one fresh Prober, so the runner is built per call."""

    def __init__(self, target: Target):
        self.target = target
        self.batches = 0

    def __call__(self, payload):
        parsed = probe_runner.parse_batch(json.loads(payload))
        target = self.target
        self.batches += 1
        target.batch_started()
        try:
            async def connect(address, family, port):
                target.connected()
                return 0.002
            return json.dumps(probe_runner.measure_batch(parsed, connect=connect))
        finally:
            target.batch_ended()


class RefusingConnect:
    async def __call__(self, target, family, port):
        raise AssertionError("nothing may connect from this machine here")


def factory_for(target):
    return lambda destination: FakeVantage(target)


# ---------------------------------------------------------------- the lanes


def probe_args(**overrides):
    base = dict(command="probe", host=None, dry_run=False, tls_ports=None,
                vantage=None, registry=True, via=None, joined=False,
                changed=False)
    base.update(overrides)
    return argparse.Namespace(**base)


def drain_args(**overrides):
    base = dict(command="drain", vantage=None, via=None, registry=True,
                tls_known=False)
    base.update(overrides)
    return argparse.Namespace(**base)


def probe_lane(path, target, codes, **overrides):
    """What one probe timer does: its own process and its own connection."""
    con = db.connect(path)
    try:
        codes.append(prober_cli.run(
            con, probe_args(transport_factory=factory_for(target), **overrides),
            connect=RefusingConnect()))
    finally:
        con.close()


def scan_lane(path, target, codes, **overrides):
    """What the scan responder does after a click."""
    con = db.connect(path)
    try:
        codes.append(scan_cli.run(
            con, drain_args(transport_factory=factory_for(target), **overrides)))
    finally:
        con.close()


def request_scan(path, host_id):
    con = db.connect(path)
    try:
        result = scan.request_scan(con, host_id, datetime.now(timezone.utc))
        assert result.accepted, result.sentence
        con.commit()
    finally:
        con.close()


def run_together(lanes):
    """Start every lane at once and wait for all of them."""
    threads = [threading.Thread(target=fn, args=args) for fn, args in lanes]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


# ============================================================ the property


def test_both_lanes_and_a_scan_at_once_never_put_two_runners_on_a_host(box):
    """The fast lane, the hourly lane and a scan land on the same host in the
    same moment, from two vantages each. What the host sees is one runner at
    a time, which is the pace rule of docs/PRODUCT.md 5d measured where it is
    promised, at the target, rather than inside any one process."""
    path, host_id = box
    request_scan(path, host_id)
    target = Target()
    codes = []
    run_together([
        (probe_lane, (path, target, codes)),
        (probe_lane, (path, target, codes)),
        (scan_lane, (path, target, codes)),
    ])
    assert codes == [0, 0, 0]
    # Three passes, two vantages each, one batch per vantage.
    assert len(target.stamps) == 3 * 2 * len(PORTS)
    assert target.worst_in_flight == 1
    # And the number the promise is about. A bucket with one token and RATE
    # refills a second lets at most RATE + 1 connects into a window one second
    # long, closed at both ends, and every fresh batch under the lock starts
    # after the last one ended with its own single token, so the ceiling for
    # a window that straddles a batch boundary is RATE + 2. The third is slack
    # for the clock reads happening after the sleep rather than at it. Real
    # sleeps only ever run late, which lowers this number, never raises it.
    assert target.worst_second() <= RATE + 3, target.worst_second()


def test_the_harness_sees_an_overlap_when_there_is_one(tmp_path):
    """The test above is only worth something if the same harness reports the
    overlap when nothing prevents it. Two databases in two directories are two
    machines: each pass locks beside its own database and neither can see the
    other, which is the honest limit app/probelock.py states."""
    boxes = [str(tmp_path / f"machine{n}" / "cp.db") for n in (1, 2)]
    for path in boxes:
        os.makedirs(os.path.dirname(path))
        make_box(path)
    target = Target()
    codes = []
    run_together([(probe_lane, (path, target, codes)) for path in boxes])
    assert codes == [0, 0]
    assert target.worst_in_flight >= 2
    assert target.worst_second() > RATE + 3


# ===================================================== every command takes it


def held(path):
    """The lock as another pass would hold it: its own descriptor."""
    lock = probelock.ProbeLock(probelock.lock_path_for(db.connect(path)))
    lock.acquire()
    return lock


def test_a_registry_pass_waits_and_then_gives_up_without_sending(box, capsys):
    """`probe.lock` held whole, as a pass of the code before the finer locks
    held it. Every batch of ours takes it shared, waits, and gives up, and
    the pass says the host was not measured from either vantage."""
    path, _ = box
    other = held(path)
    try:
        target = Target()
        codes = []
        probe_lane(path, target, codes, lock_wait_seconds=0.3)
    finally:
        other.release()
    assert codes == [1]
    assert target.stamps == []
    assert "was not sent" in capsys.readouterr().err


def test_a_via_pass_takes_the_same_lock(box, capsys):
    path, _ = box
    other = held(path)
    target = Target()
    con = db.connect(path)
    try:
        code = prober_cli.run(
            con, probe_args(registry=False, vantage="probe1",
                            via="root@" + PROBE1_V4, lock_wait_seconds=0.3,
                            transport_factory=lambda d: FakeVantage(target)),
            connect=RefusingConnect())
    finally:
        con.close()
        other.release()
    assert code == 1
    assert target.stamps == []


def test_the_local_pass_takes_the_same_lock(box):
    """The laptop's path. `RefusingConnect` raises if anything connects, so a
    pass that slipped past the lock would error rather than pass."""
    path, _ = box
    other = held(path)
    con = db.connect(path)
    try:
        code = prober_cli.run(
            con, probe_args(registry=False, vantage="laptop",
                            lock_wait_seconds=0.3),
            connect=RefusingConnect())
    finally:
        con.close()
        other.release()
    assert code == 1


def test_a_scan_drain_takes_the_same_lock_and_keeps_the_request(box, capsys):
    """A drain that could not run leaves the request pending, so the next
    drain or the next fast-lane pass still covers it."""
    path, host_id = box
    request_scan(path, host_id)
    other = held(path)
    try:
        target = Target()
        codes = []
        scan_lane(path, target, codes, lock_wait_seconds=0.3)
    finally:
        other.release()
    assert codes == [1]
    assert target.stamps == []
    con = db.connect(path)
    try:
        assert scan.pending_requests(con) == [host_id]
    finally:
        con.close()


def test_the_dry_run_never_waits_for_the_lock(box, capsys):
    """A dry run sends nothing, so it has no business queueing behind a pass.
    With the lock held and no wait allowed it still prints its plan."""
    path, _ = box
    other = held(path)
    con = db.connect(path)
    try:
        code = prober_cli.run(con, probe_args(dry_run=True, lock_wait_seconds=0),
                              connect=RefusingConnect())
    finally:
        con.close()
        other.release()
    assert code == 0
    assert "box" in capsys.readouterr().out


# ============================================================ the lock itself


def test_two_holders_of_one_file_exclude_each_other(tmp_path):
    path = str(tmp_path / "probe.lock")
    first = probelock.ProbeLock(path)
    first.acquire()
    try:
        second = probelock.ProbeLock(path, wait_seconds=0.2, poll_seconds=0.05)
        started = time.monotonic()
        with pytest.raises(probelock.ProbeLockHeld) as caught:
            second.acquire()
        assert time.monotonic() - started >= 0.2
        assert path in str(caught.value)
    finally:
        first.release()
    # Released, the next holder walks straight in.
    with probelock.ProbeLock(path, wait_seconds=0):
        pass


def test_a_waiting_holder_gets_in_when_the_first_lets_go(tmp_path):
    path = str(tmp_path / "probe.lock")
    first = probelock.ProbeLock(path)
    first.acquire()
    got_in = threading.Event()

    def wait_then_hold():
        with probelock.ProbeLock(path, wait_seconds=5, poll_seconds=0.02):
            got_in.set()

    waiter = threading.Thread(target=wait_then_hold)
    waiter.start()
    time.sleep(0.15)
    assert not got_in.is_set()
    first.release()
    waiter.join(timeout=5)
    assert got_in.is_set()


def test_the_lock_sits_beside_the_database(tmp_path):
    path = str(tmp_path / "deep" / "cp.db")
    os.makedirs(os.path.dirname(path))
    con = db.connect(path)
    try:
        assert probelock.lock_path_for(con) == str(tmp_path / "deep" / "probe.lock")
        with probelock.ProbeLock.for_connection(con) as lock:
            assert not lock.guards_nothing
            assert os.path.exists(lock.path)
    finally:
        con.close()


def test_a_database_in_memory_gets_a_lock_that_guards_nothing_and_says_so():
    con = db.connect(":memory:")
    try:
        assert probelock.lock_path_for(con) is None
        with probelock.ProbeLock.for_connection(con) as lock:
            assert lock.guards_nothing
    finally:
        con.close()


def test_the_lock_file_is_never_truncated_or_widened(tmp_path):
    """Its content is nothing and its mode is readable to the operator only
    writable by the owner, so a stray write there cannot become a channel."""
    path = str(tmp_path / "probe.lock")
    with open(path, "w") as f:
        f.write("left by hand")
    with probelock.ProbeLock(path):
        pass
    with open(path) as f:
        assert f.read() == "left by hand"
    fresh = str(tmp_path / "fresh.lock")
    with probelock.ProbeLock(fresh):
        pass
    assert oct(os.stat(fresh).st_mode & 0o777) == oct(0o644 & ~_umask())


def _umask():
    current = os.umask(0)
    os.umask(current)
    return current


def test_a_release_without_an_acquire_is_harmless(tmp_path):
    lock = probelock.ProbeLock(str(tmp_path / "probe.lock"))
    lock.release()
    lock.release()


def test_nonsense_waits_are_refused_at_the_door(tmp_path):
    with pytest.raises(ValueError):
        probelock.ProbeLock(str(tmp_path / "x"), wait_seconds=-1)
    with pytest.raises(ValueError):
        probelock.ProbeLock(str(tmp_path / "x"), poll_seconds=0)


def test_the_exit_code_is_its_own_and_the_units_can_grep_for_it():
    assert probelock.EXIT_HELD not in (0, 1, 2)
