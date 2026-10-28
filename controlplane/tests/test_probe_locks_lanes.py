"""Our passes, Scan now and the page's mark on the finer locks, and a
self-hosted instance on the whole-pass lock it keeps (docs/SPEC-probe-locks.md,
points 6 and 7).

  - every path that sends hands its locks down to every batch
  - `--via` names a vantage of the registry, and its lock is that row's
  - the local mode takes the stripes of its addresses
  - the mark reads `probe.ours`, which every pass of ours holds shared for
    its whole length and nothing else takes
  - an instance runs one pass at a time, so it never has two batches at our
    API, which would refuse the second as `batch_in_flight`

The far end is the real runner in process, as in tests/test_probe_lock.py.
"""
import ast
import os
import pathlib
import threading
import time
from datetime import datetime, timezone

import pytest

from app import (authz, db, dispatch, instances, probelock, prober, prober_cli,
                 proberapi, proberapi_worker, scan, scan_cli, vantages)

from test_probe_lock import (PORTS, PROBE1_V4, PROBE2_V4, V4, FakeVantage,
                             RefusingConnect, Target, drain_args, make_box,
                             probe_args, request_scan, run_together)


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
def box(tmp_path):
    path = str(tmp_path / "cp.db")
    host_id = make_box(path)
    return path, host_id


def row_of(path, name):
    con = db.connect(path)
    try:
        return vantages.by_name(con, name)
    finally:
        con.close()


def hold(locks):
    assert locks.try_acquire() is None
    return locks


class Watching(FakeVantage):
    """A vantage that looks at the page's mark from inside each batch."""

    def __init__(self, target, path, seen):
        super().__init__(target)
        self.ours = os.path.join(os.path.dirname(path), probelock.OURS_FILENAME)
        self.seen = seen

    def __call__(self, payload):
        self.seen.append(probelock.is_held(self.ours))
        return super().__call__(payload)


# ===================================================== the page's mark


@pytest.mark.parametrize("lane", ["registry", "via", "scan"])
def test_the_mark_shows_while_our_pass_runs(box, lane):
    path, host_id = box
    target, seen, codes = Target(), [], []
    factory = lambda destination: Watching(target, path, seen)  # noqa: E731
    con = db.connect(path)
    try:
        if lane == "scan":
            request_scan(path, host_id)
            codes.append(scan_cli.run(con, drain_args(transport_factory=factory)))
        elif lane == "via":
            codes.append(prober_cli.run(
                con, probe_args(registry=False, vantage="probe1",
                                via="root@" + PROBE1_V4,
                                transport_factory=factory),
                connect=RefusingConnect()))
        else:
            codes.append(prober_cli.run(con, probe_args(transport_factory=factory),
                                        connect=RefusingConnect()))
    finally:
        con.close()
    assert codes == [0]
    assert seen and all(seen), seen
    assert not probelock.is_held(os.path.join(os.path.dirname(path),
                                              probelock.OURS_FILENAME))


def test_an_instance_batch_marks_no_server_of_ours(box):
    """The worker serves instances, whose servers are not on this page. It
    held `probe.lock` until phase 1, which the mark read, so while any
    instance was served every server of every workspace read as probed."""
    path, _host = box
    con = db.connect(path)
    try:
        for module in (instances, proberapi):
            module.init(con)
        one = instances.add(con, "one", origin=authz.ORIGIN_INVITED).instance
        result = authz.record_presence_claim(
            con, one.account, "185.199.108.154", ["185.199.108.154"],
            now=datetime.now(timezone.utc), origin=one.origin)
        assert result.recorded, result.reason
        snapshot = authz.snapshot_to_json(authz.build_snapshot(
            con, ["185.199.108.154"], account=one.account))
        parsed = proberapi.parse_batch(
            {"version": dispatch.BATCH_VERSION, "vantage": "probe1",
             "addresses": ["185.199.108.154"], "ports": [22], "tls_ports": [],
             "snapshot": snapshot},
            {"probe1", "probe2"}, vantages.all_addresses(con))
        proberapi.submit(con, one.id, parsed, datetime.now(timezone.utc))
        seen = []
        outcomes = proberapi_worker.run_round(
            con, transport_factory=lambda d: Watching(Target(), path, seen),
            lock_wait_seconds=5)
    finally:
        con.close()
    assert outcomes == ["done"]
    assert seen == [False]


# ============================================== every path hands them down


def test_every_path_that_sends_hands_its_locks_down():
    """`dispatch.run_host` and `run_pass` take no lock per batch when they
    are given none, which only a pass that holds `probe.lock` whole may
    want. So every call of them in the control plane names its locks, and a
    new caller that forgets is red here rather than quietly lock free."""
    app = pathlib.Path(__file__).resolve().parents[1] / "app"
    calls = []
    for source in sorted(app.glob("*.py")):
        tree = ast.parse(source.read_text(), filename=str(source))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", getattr(node.func, "id", None))
            if name in ("run_host", "run_pass"):
                calls.append((source.name, node.lineno,
                              {k.arg for k in node.keywords}))
    assert len(calls) >= 4, calls
    for source, line, keywords in calls:
        assert "locks" in keywords, f"{source}:{line} sends without naming its locks"


def test_a_via_pass_names_a_vantage_of_the_registry_or_is_refused(box, capsys):
    path, _host = box
    target = Target()

    def via(destination, vantage, wait=10.0):
        con = db.connect(path)
        try:
            return prober_cli.run(
                con, probe_args(registry=False, vantage=vantage, via=destination,
                                lock_wait_seconds=wait,
                                transport_factory=lambda d: FakeVantage(target)),
                connect=RefusingConnect())
        finally:
            con.close()

    # Not in the registry at all, and another vantage's destination.
    assert via("root@185.199.111.1", "probe1") == 2
    assert "registry" in capsys.readouterr().err
    assert via("root@" + PROBE1_V4, "probe2") == 2
    assert via("root@" + PROBE1_V4, "probe9") == 2
    assert target.stamps == []

    # The lock it takes is that row's: probe2's held changes nothing, and
    # probe1's held keeps it out.
    directory = os.path.dirname(path)
    other = hold(probelock.Locks(directory, prober=row_of(path, "probe2").id,
                                 pass_lock=False))
    try:
        assert via("root@" + PROBE1_V4, "probe1") == 0
    finally:
        other.release()
    assert len(target.stamps) == len(PORTS)
    other = hold(probelock.Locks(directory, prober=row_of(path, "probe1").id,
                                 pass_lock=False))
    try:
        assert via("root@" + PROBE1_V4, "probe1", wait=0.3) == 1
    finally:
        other.release()
    assert len(target.stamps) == len(PORTS)


def test_a_drain_via_names_a_vantage_of_the_registry_or_is_refused(box, capsys):
    path, host_id = box
    request_scan(path, host_id)
    target = Target()
    con = db.connect(path)
    try:
        refused = scan_cli.run(con, drain_args(
            registry=False, vantage="probe1", via="root@185.199.111.1",
            transport_factory=lambda d: FakeVantage(target)))
        assert refused == 2
        assert target.stamps == []
        assert scan.pending_requests(con) == [host_id]
        assert scan_cli.run(con, drain_args(
            registry=False, vantage="probe1", via="root@" + PROBE1_V4,
            transport_factory=lambda d: FakeVantage(target))) == 0
    finally:
        con.close()
    assert len(target.stamps) == len(PORTS)


class Connects:
    """The local mode's connect, recording each one."""

    def __init__(self):
        self.made = []

    async def __call__(self, address, family, port):
        self.made.append((address, port))
        return 0.002


def test_the_local_pass_takes_the_stripes(box, capsys):
    """The laptop's path probes from this machine, so it has no prober to
    lock, and its addresses are kept apart from every batch of ours all the
    same."""
    path, _host = box
    directory = os.path.dirname(path)
    other = hold(probelock.Locks(directory, addresses=[V4], pass_lock=False))
    try:
        con = db.connect(path)
        try:
            code = prober_cli.run(
                con, probe_args(registry=False, vantage="laptop",
                                lock_wait_seconds=0.3),
                connect=RefusingConnect())
        finally:
            con.close()
    finally:
        other.release()
    assert code == 1
    assert "not measured" in capsys.readouterr().err
    connects = Connects()
    con = db.connect(path)
    try:
        assert prober_cli.run(con, probe_args(registry=False, vantage="laptop"),
                              connect=connects) == 0
    finally:
        con.close()
    assert len(connects.made) == len(PORTS)


# ==================================== a self-hosted instance, one pass at a time


class FakeApi:
    """Our prober API as one instance meets it: one batch of the instance's
    in flight at a time, and a second refused `batch_in_flight`, which the
    instance reads as the vantage gone for the rest of its pass
    (`dispatch.API_UNREACHABLE_ERRORS`). Behind it, the real runner."""

    def __init__(self, target):
        self.target = target
        self._lock = threading.Lock()
        self.in_flight = 0
        self.order = []

    def factory(self, lane):
        def transport_for(destination):
            def send(payload):
                with self._lock:
                    if self.in_flight:
                        raise dispatch.VantageUnreachable(
                            "the prober API refused the batch: batch_in_flight")
                    self.in_flight += 1
                    self.order.append(lane)
                try:
                    time.sleep(0.2)
                    return FakeVantage(self.target)(payload)
                finally:
                    with self._lock:
                        self.in_flight -= 1
            return send
        return transport_for


def instance_lanes(path, monkeypatch):
    """Two lanes of a self-hosted instance landing together."""
    monkeypatch.setenv(dispatch.PROBER_API_ENV, "https://app.example.com")
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, "whpk_" + "0" * 64)
    api, codes = FakeApi(Target()), []

    def lane(name):
        con = db.connect(path)
        try:
            codes.append(prober_cli.run(
                con, probe_args(transport_factory=api.factory(name)),
                connect=RefusingConnect()))
        finally:
            con.close()

    run_together([(lane, ("fast",)), (lane, ("hourly",))])
    return api, codes


def test_an_instance_still_runs_one_pass_at_a_time(box, monkeypatch):
    path, _host = box
    api, _codes = instance_lanes(path, monkeypatch)
    # Two vantages a pass: one lane's two batches, then the other's.
    assert api.order in (["fast", "fast", "hourly", "hourly"],
                         ["hourly", "hourly", "fast", "fast"]), api.order


def test_an_instances_two_lanes_landing_together_both_measure_every_host(box, monkeypatch):
    path, _host = box
    api, codes = instance_lanes(path, monkeypatch)
    assert codes == [0, 0]
    assert len(api.target.stamps) == 2 * 2 * len(PORTS)
    con = db.connect(path)
    try:
        stored = con.execute("SELECT vantage FROM probe_runs").fetchall()
    finally:
        con.close()
    assert sorted(r["vantage"] for r in stored) == ["probe1", "probe1",
                                                    "probe2", "probe2"]


# ================================== the journal's line for a batch that gave up


def held_lines(err):
    return [line for line in err.splitlines()
            if line.startswith(probelock.HELD_LINE)]


def test_each_batch_that_gave_up_writes_one_typed_line(box, capsys):
    """The exit code no longer finds the overlaps on our box, since a pass
    that gave up on one batch still measured the rest and exits 1. So each
    batch that gave up writes one line a grep finds: its class, the vantage
    and the server's number, and no address."""
    path, host_id = box
    directory = os.path.dirname(path)
    other = hold(probelock.Locks(directory, addresses=[V4], pass_lock=False))
    try:
        con = db.connect(path)
        try:
            code = prober_cli.run(
                con, probe_args(lock_wait_seconds=0.1,
                                transport_factory=lambda d: FakeVantage(Target())),
                connect=RefusingConnect())
            local = prober_cli.run(
                con, probe_args(registry=False, vantage="laptop",
                                lock_wait_seconds=0.1),
                connect=RefusingConnect())
        finally:
            con.close()
    finally:
        other.release()
    assert (code, local) == (1, 1)
    lines = held_lines(capsys.readouterr().err)
    assert lines == [
        f"{probelock.HELD_LINE}: address_busy vantage=probe1 host_id={host_id}",
        f"{probelock.HELD_LINE}: address_busy vantage=probe2 host_id={host_id}",
        f"{probelock.HELD_LINE}: address_busy vantage=laptop host_id={host_id}"]
    assert not any(V4 in line for line in lines)


def test_a_prober_that_stayed_busy_writes_one_line_and_the_other_measures(box, capsys):
    path, host_id = box
    directory = os.path.dirname(path)
    other = hold(probelock.Locks(directory, prober=row_of(path, "probe1").id,
                                 pass_lock=False))
    target = Target()
    try:
        con = db.connect(path)
        try:
            code = prober_cli.run(
                con, probe_args(lock_wait_seconds=0.1,
                                transport_factory=lambda d: FakeVantage(target)),
                connect=RefusingConnect())
        finally:
            con.close()
    finally:
        other.release()
    assert code == 1
    assert held_lines(capsys.readouterr().err) == [
        f"{probelock.HELD_LINE}: prober_busy vantage=probe1 host_id={host_id}"]
    # probe2 measured the server all the same.
    assert len(target.stamps) == len(PORTS)
