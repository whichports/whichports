"""The finer probe locks, phase 1 of docs/SPEC-probe-locks.md (app/probelock.py).

One lock per prober, keyed on the vantage's row in the registry, and 4096
striped locks for the addresses. Each batch takes its prober's lock and the
stripes of its addresses together, or none of them, and its snapshot is read
only once they are held. What these hold:

  - two batches on two probers run at once, two on one prober never do
  - a batch that cannot take every lock holds none
  - the snapshot is read after the locks are held, so a revoke that lands
    while a batch waits holds for that batch
  - a prober that stays busy is skipped for the rest of the pass, a busy
    address costs that host only
  - no lock file names an address
  - an ssh that exited 255 is never tried again

The far end is the real runner in process against a fake socket, as in
tests/test_probe_lock.py. Threads stand in for processes, which is faithful:
flock(2) treats two descriptors of one file as two locks, even in one process.
"""
import fcntl
import json
import os
import stat
import threading
import time
from datetime import datetime, timezone

import pytest

from app import (authz, db, dispatch, probelock, probe_runner, prober, prober_cli,
                 store, vantages)

V4 = "185.199.108.153"
OTHER_V4 = "185.199.108.154"
V6 = "2606:50c0:8000::153"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"
PORTS = (22, 80)


# ------------------------------------------------------------------ a fleet


def make_fleet(path: str) -> None:
    """A control plane on disk with two servers, `one` on V4 and `two` on
    OTHER_V4, each proved by its agent, and two vantages."""
    con = db.connect(path)
    try:
        for module in (db, authz, prober, vantages):
            module.init(con)
        for name, address in (("one", V4), ("two", OTHER_V4)):
            host_id, _ = store.add_host(con, name)
            document = json.dumps({
                "sockets": {"listening": [
                    {"protocol": "tcp", "port": port, "bind_address": "0.0.0.0",
                     "family": "v4"} for port in PORTS]},
                "interface_addresses": {"addresses": [
                    {"interface": "eth0", "family": "v4", "address": address,
                     "global": True}]}})
            store.insert_report(con, host_id, 1, 1, document)
            proof = authz.record_agent_proof(con, host_id, address, document,
                                             now=datetime.now(timezone.utc))
            assert proof.recorded, proof.reason
        vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
        vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
        con.commit()
    finally:
        con.close()


@pytest.fixture(autouse=True)
def no_real_ssh(monkeypatch):
    """Nothing here may reach a real server. A transport built with the
    system's own ssh fails the test before it starts one."""
    real = dispatch.SshTransport.__call__

    def guarded(self, payload):
        assert self.ssh != "ssh", f"a test reached for real ssh to {self.destination}"
        return real(self, payload)

    monkeypatch.setattr(dispatch.SshTransport, "__call__", guarded)


@pytest.fixture()
def fleet(tmp_path):
    path = str(tmp_path / "cp.db")
    make_fleet(path)
    return path


def plan_of(con, name):
    host = next(h for h in store.list_hosts(con) if h["name"] == name)
    return prober_cli.plan_for(con, host)


def vantage(con, name):
    return vantages.by_name(con, name)


def locks_for(con, prober=None, wait_seconds=10.0):
    locks = probelock.BatchLocks.for_connection(con, wait_seconds=wait_seconds,
                                                poll_seconds=0.02)
    return locks if prober is None else locks.on_prober(prober.id)


def is_free(path: str) -> bool:
    """Whether nobody holds this lock file at all, asked the way another
    process would: its own descriptor, exclusive, without waiting."""
    if not os.path.exists(path):
        return True
    fd = os.open(path, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        return False
    finally:
        os.close(fd)
    return True


class Far:
    """One vantage host: the real runner in process. `during` runs inside
    each batch, while the runner holds the batch, so a test can look at the
    world from in there."""

    def __init__(self, during=None):
        self.batches = []
        self.connects = []
        self.during = during

    def __call__(self, payload):
        batch = json.loads(payload)
        self.batches.append(batch)
        if self.during is not None:
            self.during(batch)
        parsed = probe_runner.parse_batch(batch)

        async def connect(target, family, port):
            self.connects.append((target, port))
            return 0.002

        return json.dumps(probe_runner.measure_batch(parsed, connect=connect))


class InFlight:
    """How many batches were in flight at once, per key, at worst."""

    def __init__(self):
        self._lock = threading.Lock()
        self.now = {}
        self.worst = {}

    def started(self, key):
        with self._lock:
            self.now[key] = self.now.get(key, 0) + 1
            self.worst[key] = max(self.worst.get(key, 0), self.now[key])

    def ended(self, key):
        with self._lock:
            self.now[key] -= 1


def in_thread(fn, *args):
    """Run `fn` in a thread of its own and keep what it returned or raised."""
    kept = {}

    def body():
        try:
            kept["value"] = fn(*args)
        except BaseException as exc:  # handed back to the test, never lost
            kept["error"] = exc

    thread = threading.Thread(target=body)
    thread.start()
    return thread, kept


def one_host(path, host, vantage_name, far, wait_seconds=10.0):
    """One host from one vantage through `dispatch.run_host`, the way a pass
    of ours sends it, on a connection of its own."""
    con = db.connect(path)
    try:
        plan = plan_of(con, host)
        row = vantage(con, vantage_name)
        return dispatch.run_host(con, plan, far, row.name,
                                 locks=locks_for(con, row, wait_seconds))
    finally:
        con.close()


# ================================================ what may run at once


def test_two_batches_on_two_probers_run_at_once(fleet):
    """probe1 and probe2 each run a batch of their own, for two servers, in
    the same moment. Each batch waits inside the runner for the other to
    arrive, so they pass only when both are in flight together."""
    both = threading.Barrier(2, timeout=5)
    one = Far(during=lambda batch: both.wait())
    two = Far(during=lambda batch: both.wait())
    first, kept_first = in_thread(one_host, fleet, "one", "probe1", one)
    second, kept_second = in_thread(one_host, fleet, "two", "probe2", two)
    first.join()
    second.join()
    assert "error" not in kept_first, kept_first
    assert "error" not in kept_second, kept_second
    assert one.connects and two.connects


def test_never_two_batches_on_one_prober(fleet):
    """Two servers, two passes, the same prober. Each batch is slow enough
    that two would overlap if nothing kept them apart."""
    meter = InFlight()

    def slow(batch):
        meter.started(batch["vantage"])
        time.sleep(0.3)
        meter.ended(batch["vantage"])

    threads = [in_thread(one_host, fleet, host, "probe1", Far(during=slow))
               for host in ("one", "two")]
    for thread, _kept in threads:
        thread.join()
    for _thread, kept in threads:
        assert "error" not in kept, kept
    assert meter.worst == {"probe1": 1}


def test_without_the_locks_the_harness_sees_two_on_one_prober(fleet):
    """The test above is worth something only if the same harness sees the
    overlap when nothing keeps the batches apart."""
    meter = InFlight()

    def slow(batch):
        meter.started(batch["vantage"])
        time.sleep(0.3)
        meter.ended(batch["vantage"])

    def unlocked(host):
        con = db.connect(fleet)
        try:
            return dispatch.run_host(con, plan_of(con, host), Far(during=slow),
                                     "probe1", locks=None)
        finally:
            con.close()

    threads = [in_thread(unlocked, host) for host in ("one", "two")]
    for thread, _kept in threads:
        thread.join()
    assert meter.worst == {"probe1": 2}


def test_two_batches_on_one_address_never_overlap_from_two_probers(fleet):
    """Server one from probe1 and from probe2 at once: its address is one
    stripe, so the second batch waits for the first."""
    meter = InFlight()

    def slow(batch):
        for address in batch["addresses"]:
            meter.started(address)
        time.sleep(0.3)
        for address in batch["addresses"]:
            meter.ended(address)

    threads = [in_thread(one_host, fleet, "one", name, Far(during=slow))
               for name in ("probe1", "probe2")]
    for thread, _kept in threads:
        thread.join()
    for _thread, kept in threads:
        assert "error" not in kept, kept
    assert meter.worst == {V4: 1}


# ======================================================= all or none


def test_a_batch_that_cannot_take_every_lock_holds_none(tmp_path):
    directory = str(tmp_path)
    assert probelock.stripe_of(V4) != probelock.stripe_of(OTHER_V4)
    mine = [probelock.lock_path_in(directory),
            probelock.prober_path(directory, 1),
            probelock.stripe_path(directory, probelock.stripe_of(V4))]

    # Another batch holds OTHER_V4's stripe.
    other = probelock.Locks(directory, addresses=[OTHER_V4], pass_lock=False)
    assert other.try_acquire() is None
    batch = probelock.Locks(directory, prober=1, addresses=[V4, OTHER_V4])
    assert batch.try_acquire() == probelock.BUSY_ADDRESS
    assert all(is_free(path) for path in mine)
    other.release()

    # Another batch holds the prober.
    other = probelock.Locks(directory, prober=1, pass_lock=False)
    assert other.try_acquire() is None
    assert batch.try_acquire() == probelock.BUSY_PROBER
    assert all(is_free(path) for path in mine[:1] + mine[2:])
    other.release()

    # And with nothing in the way it takes every one of them.
    assert batch.try_acquire() is None
    assert not any(is_free(path) for path in mine[1:])
    batch.release()
    assert all(is_free(path) for path in mine)


def test_two_addresses_on_one_stripe_are_one_lock(tmp_path):
    """Two descriptors of one file exclude each other even in one process
    (flock(2)), so a batch whose two addresses share a stripe must take it
    once, or it would wait for itself."""
    spellings = ["2606:50c0:8000::153", "2606:50C0:8000:0::153"]
    assert probelock.stripe_of(spellings[0]) == probelock.stripe_of(spellings[1])
    batch = probelock.Locks(str(tmp_path), addresses=spellings)
    assert batch.try_acquire() is None
    batch.release()


def test_a_whole_pass_holder_and_a_batch_keep_each_other_out(tmp_path):
    """`probe.lock` held whole is how a self-hosted instance runs its passes,
    and how the code before these locks ran every pass. Every lock set of
    ours takes it shared, so the two never run at once, while two batches of
    ours share it."""
    directory = str(tmp_path)
    whole = probelock.ProbeLock(probelock.lock_path_in(directory), wait_seconds=0)
    whole.acquire()
    try:
        assert probelock.Locks(directory, prober=1, addresses=[V4]).try_acquire() \
            == probelock.BUSY_PASS
    finally:
        whole.release()
    first = probelock.Locks(directory, prober=1, addresses=[V4])
    second = probelock.Locks(directory, prober=2, addresses=[OTHER_V4])
    assert first.try_acquire() is None
    assert second.try_acquire() is None
    with pytest.raises(probelock.ProbeLockHeld):
        probelock.ProbeLock(probelock.lock_path_in(directory), wait_seconds=0).acquire()
    first.release()
    second.release()


def test_a_wait_that_runs_out_says_which_lock_and_holds_nothing(tmp_path):
    directory = str(tmp_path)
    other = probelock.Locks(directory, prober=1, pass_lock=False)
    other.acquire()
    try:
        with pytest.raises(probelock.ProberBusy):
            probelock.Locks(directory, prober=1, addresses=[V4],
                            wait_seconds=0.1, poll_seconds=0.02).acquire()
    finally:
        other.release()
    other = probelock.Locks(directory, addresses=[V4], pass_lock=False)
    other.acquire()
    try:
        with pytest.raises(probelock.AddressBusy):
            probelock.Locks(directory, prober=2, addresses=[V4],
                            wait_seconds=0.1, poll_seconds=0.02).acquire()
        assert is_free(probelock.prober_path(directory, 2))
    finally:
        other.release()


@pytest.mark.parametrize("prober", ["probe1", True, 0, -1, 1.0])
def test_a_prober_lock_is_keyed_on_a_registry_row_and_nothing_else(tmp_path, prober):
    with pytest.raises(ValueError):
        probelock.Locks(str(tmp_path), prober=prober)


def test_what_is_not_an_address_takes_no_stripe(tmp_path):
    """The engine records such a target as not tested and connects to
    nothing, so there is nothing to keep apart."""
    assert probelock.stripe_of("not an address") is None
    batch = probelock.Locks(str(tmp_path), addresses=["not an address"],
                            pass_lock=False)
    assert batch.try_acquire() is None
    batch.release()
    assert not os.path.exists(tmp_path / probelock.STRIPES_DIRECTORY)


def test_every_stripe_is_one_of_4096():
    seen = {probelock.stripe_of(f"185.199.{a}.{b}") for a in range(100, 120)
            for b in range(1, 255)}
    assert seen <= set(range(probelock.STRIPES))
    # Spread, not bunched: about 5,000 addresses fill well over half.
    assert len(seen) > probelock.STRIPES // 2


def test_a_directory_of_none_guards_nothing_and_says_so():
    batch = probelock.Locks(None, prober=1, addresses=[V4])
    assert batch.guards_nothing
    assert batch.try_acquire() is None
    batch.release()


def test_no_lock_file_names_an_address(fleet, tmp_path):
    """A lock file's name is a number, the registry row's or the stripe's,
    so a listing of the directory gives away no address we probe."""
    con = db.connect(fleet)
    try:
        row = vantage(con, "probe1")
        dispatch.run_host(con, plan_of(con, "one"), Far(), row.name,
                          locks=locks_for(con, row))
    finally:
        con.close()
    batch = probelock.Locks(str(tmp_path), prober=1, addresses=[V4, V6, OTHER_V4])
    assert batch.try_acquire() is None
    batch.release()
    names = []
    for _where, directories, files in os.walk(tmp_path):
        names.extend(directories + files)
    assert names
    for name in names:
        for address in (V4, V6, OTHER_V4):
            assert address not in name
            assert address.replace(":", "") not in name
        assert "185" not in name and "2606" not in name
    stripes = os.listdir(tmp_path / probelock.STRIPES_DIRECTORY)
    assert stripes and all(len(n) == 4 and n.isdigit() for n in stripes)
    assert os.listdir(tmp_path / probelock.PROBERS_DIRECTORY) == ["1"]


# ======================================== the snapshot, after the locks


def test_the_snapshot_is_built_after_the_locks_are_held(fleet, monkeypatch):
    con = db.connect(fleet)
    try:
        row = vantage(con, "probe1")
        directory = os.path.dirname(fleet)
        theirs = [probelock.prober_path(directory, row.id),
                  probelock.stripe_path(directory, probelock.stripe_of(V4))]
        seen = []
        real = authz.build_snapshot

        def watched(*args, **kwargs):
            seen.append([is_free(path) for path in theirs])
            return real(*args, **kwargs)

        monkeypatch.setattr(authz, "build_snapshot", watched)
        dispatch.run_host(con, plan_of(con, "one"), Far(), row.name,
                          locks=locks_for(con, row))
    finally:
        con.close()
    assert seen == [[False, False]]
    assert all(is_free(path) for path in theirs)


def test_a_revoke_while_a_batch_waits_for_its_address_is_honoured(fleet):
    """Server one's address is held by another batch. Its proof is revoked
    while this batch waits. When the address comes free the snapshot is read
    then, says no, and nothing connects to it."""
    directory = os.path.dirname(fleet)
    other = probelock.Locks(directory, addresses=[V4], pass_lock=False)
    other.acquire()
    far = Far()
    try:
        thread, kept = in_thread(one_host, fleet, "one", "probe1", far)
        time.sleep(0.3)
        assert far.batches == [], "the batch was sent while its address was held"
        con = db.connect(fleet)
        try:
            assert authz.revoke(con, V4) == 1
        finally:
            con.close()
    finally:
        other.release()
    thread.join()
    assert "error" not in kept, kept
    assert len(far.batches) == 1
    assert far.connects == []
    assert {(r.state, r.reason) for r in kept["value"].results if r.target == V4} \
        == {(prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


# ============================================ a lock that stays busy


def a_pass(path, far_for, wait_seconds=0.3):
    con = db.connect(path)
    try:
        plans = [plan_of(con, "one"), plan_of(con, "two")]
        return dispatch.run_pass(
            con, plans, vantages.enabled(con),
            transport_factory=far_for,
            locks=probelock.BatchLocks.for_connection(
                con, wait_seconds=wait_seconds, poll_seconds=0.02))
    finally:
        con.close()


def test_a_prober_that_stays_busy_is_skipped_for_the_rest_of_the_pass(fleet):
    con = db.connect(fleet)
    probe1 = vantage(con, "probe1")
    con.close()
    other = probelock.Locks(os.path.dirname(fleet), prober=probe1.id,
                            pass_lock=False)
    other.acquire()
    fars = {}
    try:
        outcomes = a_pass(fleet, lambda d: fars.setdefault(d, Far()))
    finally:
        other.release()
    said = [(o.host_name, o.vantage, o.measured, o.skipped) for o in outcomes]
    assert said == [("one", "probe1", False, False), ("one", "probe2", True, False),
                    ("two", "probe1", False, True), ("two", "probe2", True, False)]
    assert fars["root@" + PROBE1_V4].batches == []
    assert "busy" in outcomes[0].failure


def test_a_busy_address_costs_that_host_only(fleet):
    other = probelock.Locks(os.path.dirname(fleet), addresses=[V4],
                            pass_lock=False)
    other.acquire()
    try:
        outcomes = a_pass(fleet, lambda d: Far())
    finally:
        other.release()
    said = [(o.host_name, o.vantage, o.measured, o.skipped) for o in outcomes]
    assert said == [("one", "probe1", False, False), ("one", "probe2", False, False),
                    ("two", "probe1", True, False), ("two", "probe2", True, False)]


def counting_ssh(tmp_path, exit_code):
    """An ssh that writes one line per start and exits as told."""
    counter = tmp_path / "started"
    script = tmp_path / f"ssh-{exit_code}"
    script.write_text(f"#!/bin/sh\necho started >> {counter}\nexit {exit_code}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script), counter


def test_an_exit_255_is_never_retried(fleet, tmp_path):
    """ssh gives 255 for a connection lost after the runner started as well
    as for one that never opened, so a second try could put a second runner
    on the target. One start, and the vantage is skipped for the pass."""
    ssh, counter = counting_ssh(tmp_path, dispatch.SSH_ERROR_EXIT)

    def factory(destination):
        if destination == "root@" + PROBE1_V4:
            return dispatch.SshTransport(destination, ssh=ssh)
        return Far()

    outcomes = a_pass(fleet, factory, wait_seconds=10.0)
    assert counter.read_text().splitlines() == ["started"]
    said = [(o.host_name, o.vantage, o.measured, o.skipped) for o in outcomes]
    assert said == [("one", "probe1", False, False), ("one", "probe2", True, False),
                    ("two", "probe1", False, True), ("two", "probe2", True, False)]


def test_a_lock_file_that_cannot_be_opened_leaves_none_held(tmp_path):
    """The code challenge, finding 2. A lock of the set that cannot be
    opened, a full disk or a file another user made, raises, and the locks
    taken before it are let go first. A path that is a directory cannot be
    opened for writing by anyone, root too, so it stands in for all of them."""
    directory = str(tmp_path)
    first, second = sorted([V4, OTHER_V4], key=probelock.stripe_of)
    os.makedirs(probelock.stripe_path(directory, probelock.stripe_of(second)))
    batch = probelock.Locks(directory, prober=1, addresses=[V4, OTHER_V4])
    with pytest.raises(OSError):
        batch.try_acquire()
    for path in (probelock.lock_path_in(directory),
                 probelock.prober_path(directory, 1),
                 probelock.stripe_path(directory, probelock.stripe_of(first))):
        assert is_free(path), path
