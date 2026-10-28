"""The runner that runs on the vantage host.

These attack the batch rather than demonstrate it. The properties that matter:
nothing unreadable becomes an empty measurement, and nothing outside the
snapshot reaches the network.
"""
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, probe_runner, prober, store

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    yield connection
    connection.close()


def authorise(con, address, name="box"):
    host_id, _ = store.add_host(con, name)
    document = json.dumps({
        "sockets": {"listening": []},
        "interface_addresses": {"addresses": [
            {"interface": "eth0",
             "family": "v4" if ":" not in address else "v6",
             "address": address, "global": True}]}})
    result = authz.record_agent_proof(con, host_id, address, document,
                                      now=datetime.now(timezone.utc))
    assert result.recorded, result.reason


def batch(con, addresses, ports, *, vantage="probe1", tls_ports=(), now=None):
    """A batch as the control plane will build one.

    **The snapshot is built against the real clock by default**, because the
    gate is asked against the real clock and a fixture time three days in the
    past produces a snapshot that refuses everything. An earlier version of
    this file did exactly that, and its happy-path test passed while measuring
    nothing at all.
    """
    now = now or datetime.now(timezone.utc)
    snapshot = authz.build_snapshot(con, addresses, now=now)
    return {"version": probe_runner.BATCH_VERSION, "vantage": vantage,
            "addresses": list(addresses), "ports": list(ports),
            "tls_ports": list(tls_ports),
            "snapshot": authz.snapshot_to_json(snapshot)}


class FakeConnect:
    """Stands in for the connect primitive. Nothing in this file opens a real
    socket to a real stranger to prove a code path."""

    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port):
        self.calls.append((target, family, port))
        return 0.002


class RefusingConnect:
    """A primitive that must never be called."""

    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port):  # pragma: no cover
        self.calls.append((target, family, port))
        raise AssertionError(f"a packet was sent to {target}:{port}")


def measure(payload, connect=None):
    """Parse and measure with an injected primitive, the way the tests need,
    and assert the batch parsed rather than letting a refusal look like a
    measurement."""
    connect = connect or FakeConnect()
    parsed = probe_runner.parse_batch(payload)
    return prober.run_from_json(
        probe_runner.measure_batch(parsed, connect=connect)), connect


def drive(payload):
    """Exactly what a shell does: bytes in, bytes out, an exit code.

    **`main` never injects a fake primitive**, so anything driven through here
    holds the real one. Every call below therefore uses either an empty port
    list or a batch that is refused before measuring. Do not add a call with
    ports to probe: use `measure` instead, or this suite starts opening sockets
    to a stranger to prove a code path.
    """
    out, err = io.StringIO(), io.StringIO()
    code = probe_runner.main([], io.StringIO(json.dumps(payload)), out, err)
    return code, out.getvalue(), err.getvalue()


# ------------------------------------------------------------- the snapshot


def test_a_snapshot_survives_the_round_trip_unchanged(con):
    authorise(con, V4)
    original = authz.build_snapshot(con, [V4], now=datetime.now(timezone.utc))
    restored = authz.snapshot_from_json(authz.snapshot_to_json(original))
    assert restored.require(V4) == V4
    assert restored.expires_at == original.expires_at
    assert restored.targets == original.targets


def test_a_round_tripped_snapshot_still_expires(con):
    authorise(con, V4)
    built = datetime.now(timezone.utc)
    restored = authz.snapshot_from_json(
        authz.snapshot_to_json(authz.build_snapshot(con, [V4], now=built)))
    later = built + timedelta(seconds=authz.SNAPSHOT_TTL_SECONDS)
    with pytest.raises(authz.NotAuthorized):
        restored.require(V4, now=later)


def test_a_snapshot_target_goes_through_the_address_rules(con):
    """Text is text. A snapshot cannot smuggle a private address in by writing
    it down, because parsing puts every entry through the same door."""
    for bad in ("10.0.0.1", "127.0.0.1", "100.64.0.1", "not-an-address",
                "185.199.108.153%eth0"):
        payload = {"version": authz.SNAPSHOT_VERSION,
                   "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
                   "targets": {bad: (NOW + timedelta(days=1)).isoformat()}}
        with pytest.raises(authz.SnapshotUnreadable):
            authz.snapshot_from_json(payload)


def test_a_non_canonical_snapshot_target_is_stored_canonically():
    """Otherwise the lookup in require would miss an entry that is present."""
    expanded = "2606:50c0:8000:0000:0000:0000:0000:0153"
    snap = authz.snapshot_from_json({
        "version": authz.SNAPSHOT_VERSION,
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
        "targets": {expanded: (NOW + timedelta(days=1)).isoformat()}})
    assert snap.require(V6, now=NOW) == V6


@pytest.mark.parametrize("payload", [
    None, [], "snapshot", {},
    {"version": 999, "expires_at": "2026-08-15T12:00:00+00:00", "targets": {}},
    {"version": 1, "targets": {}},
    {"version": 1, "expires_at": "not a time", "targets": {}},
    {"version": 1, "expires_at": "2026-08-15T12:00:00+00:00"},
    {"version": 1, "expires_at": "2026-08-15T12:00:00+00:00", "targets": []},
    {"version": 1, "expires_at": "2026-08-15T12:00:00+00:00",
     "targets": {"185.199.108.153": "not a time"}},
])
def test_an_unreadable_snapshot_raises_rather_than_authorising_nothing(payload):
    """An empty snapshot sounds safe and is not. It would let a garbled batch
    look like a run that measured nothing."""
    with pytest.raises(authz.SnapshotUnreadable):
        authz.snapshot_from_json(payload)


# --------------------------------------------------------------- the runner


def test_a_batch_actually_probes_the_ports_it_was_given(con):
    """The happy path, and it asserts packets rather than rows.

    An earlier version of this test checked only that ports 80 and 443
    appeared in the output. They appeared as `not_tested`, because the fixture
    clock made the snapshot stale, so it passed while measuring nothing. What
    it has to check is that the primitive was called.
    """
    authorise(con, V4)
    measured, connect = measure(batch(con, [V4], [80, 443]))
    assert [(t, p) for t, _f, p in connect.calls] == [(V4, 80), (V4, 443)]
    assert measured.vantage == "probe1"
    assert measured.id is None
    probed = [r for r in measured.results if r.target == V4]
    assert {r.state for r in probed} == {prober.STATE_CONNECTED}


def test_a_batch_writes_a_readable_run_through_main(con):
    """The stream path, separately, so the wiring in main is covered without
    pretending it measured anything."""
    authorise(con, V4)
    code, out, err = drive(batch(con, [V4], []))
    assert code == probe_runner.EXIT_OK, err
    measured = prober.run_from_json(json.loads(out))
    assert measured.vantage == "probe1"
    assert measured.results == ()


def test_the_runner_refuses_an_address_outside_the_snapshot(con):
    """The batch says probe it and the snapshot does not, so it is not probed.
    The addresses list is a request, never a permission."""
    authorise(con, V4)
    payload = batch(con, [V4], [80])
    payload["addresses"] = [V4, V6]
    measured, connect = measure(payload)
    assert V6 not in [target for target, _f, _p in connect.calls]
    refused = [r for r in measured.results if r.target == V6]
    assert refused, "the v6 address has to appear, said no"
    assert all(r.state == prober.STATE_NOT_TESTED for r in refused)


def test_a_stale_snapshot_sends_no_packet(con):
    """The bound on the revocation window, asserted at the socket. The
    primitive raises if it is called at all."""
    authorise(con, V4)
    payload = batch(con, [V4], [80])
    payload["snapshot"]["expires_at"] = (
        datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    measured, connect = measure(payload, connect=RefusingConnect())
    assert connect.calls == []
    assert all(r.state == prober.STATE_NOT_TESTED for r in measured.results)


@pytest.mark.parametrize("payload", [
    {}, [], "batch", 3,
    {"version": 999},
    {"version": 1, "vantage": "", "addresses": ["185.199.108.153"], "ports": []},
    {"version": 1, "vantage": "probe1", "addresses": [], "ports": []},
    {"version": 1, "vantage": "probe1", "addresses": ["185.199.108.153"]},
    {"version": 1, "vantage": "probe1", "addresses": ["185.199.108.153"],
     "ports": [], "snapshot": {"version": 1}},
])
def test_an_unusable_batch_exits_non_zero_and_writes_no_stdout(payload):
    """A batch that cannot be read must not look like a completed run. This is
    RECORD 4.46's shape: silence that reads as a measurement."""
    code, out, err = drive(payload)
    assert code == probe_runner.EXIT_UNREADABLE
    assert out == ""
    assert err.strip()


def test_stdin_that_is_not_json_is_refused():
    out, err = io.StringIO(), io.StringIO()
    code = probe_runner.main([], io.StringIO("not json at all"), out, err)
    assert code == probe_runner.EXIT_UNREADABLE
    assert out.getvalue() == ""


def test_the_runner_takes_no_arguments(con):
    """Every input arrives in the batch. An argument naming a target would be a
    second way in that the snapshot never saw."""
    out, err = io.StringIO(), io.StringIO()
    code = probe_runner.main(["--host", V4], io.StringIO("{}"), out, err)
    assert code == probe_runner.EXIT_UNREADABLE
    assert out.getvalue() == ""
    assert "usage" in err.getvalue()


# ----------------------------------------------------------- the run on the wire


def test_a_run_survives_the_round_trip(con):
    authorise(con, V4)
    once = probe_runner.measure_batch(
        probe_runner.parse_batch(batch(con, [V4], [80, 443])),
        connect=FakeConnect())
    twice = prober.run_to_json(prober.run_from_json(once))
    assert once == twice


@pytest.mark.parametrize("mangle", [
    lambda d: d.update(version=999),
    lambda d: d.pop("vantage"),
    lambda d: d.pop("results"),
    lambda d: d.update(results="rows"),
    lambda d: d["results"][0].update(surprise=1),
    lambda d: d["results"][0].pop("state"),
])
def test_a_mangled_run_is_refused_rather_than_partly_stored(con, mangle):
    """The control plane parses whatever a prober sent. A row carrying fields
    this build does not know is a row from a different contract, and storing
    the half we recognise is how a mismatch becomes a stored fact."""
    authorise(con, V4)
    payload = probe_runner.measure_batch(
        probe_runner.parse_batch(batch(con, [V4], [80])),
        connect=FakeConnect())
    mangle(payload)
    with pytest.raises(prober.RunUnreadable):
        prober.run_from_json(payload)


# ------------------------------------------- a vantage may not measure itself
#
# `docs/RECORD.md` 4.62. This box probed its own address and reported
# connect_refused on ports an outside machine sees time out, because traffic to
# a machine's own address does not traverse its firewall the way traffic from
# the internet does. The run looked entirely healthy, which is why this is a
# refusal in code and not a line in a runbook.


def test_own_addresses_reads_what_the_machine_answers_on():
    assert probe_runner.own_addresses(lambda: ["192.0.2.5", "2001:db8::1"]) == {
        "192.0.2.5", "2001:db8::1"}


def test_own_addresses_canonicalises_and_drops_the_zone_index():
    """`fe80::1%eth0` and `fe80::1` have to compare equal, or a batch naming
    the plain form walks past a guard holding the scoped one."""
    found = probe_runner.own_addresses(lambda: ["fe80::1%eth0"])
    assert found == {"fe80::1"}


def test_own_addresses_ignores_anything_that_is_not_an_address():
    assert probe_runner.own_addresses(lambda: ["", "not-an-address", "1.2.3.4"]) == {
        "1.2.3.4"}


def test_a_batch_naming_this_hosts_own_address_is_refused(con, monkeypatch):
    authorise(con, V4)
    monkeypatch.setattr(probe_runner, "own_addresses", lambda: {V4})
    with pytest.raises(probe_runner.BatchUnreadable) as raised:
        probe_runner.parse_batch(batch(con, [V4], [80]))
    assert "cannot measure itself" in str(raised.value)


def test_the_refusal_happens_before_any_packet(con, monkeypatch):
    """Refused at parse, so nothing downstream gets the chance."""
    authorise(con, V4)
    monkeypatch.setattr(probe_runner, "own_addresses", lambda: {V4})
    code, out, err = drive(batch(con, [V4], [80]))
    assert code == probe_runner.EXIT_UNREADABLE
    assert out == ""
    assert "cannot measure itself" in err


def test_a_non_canonical_spelling_of_our_own_address_is_still_refused(
        con, monkeypatch):
    """Otherwise the guard is bypassed by writing the address differently."""
    authorise(con, V6)
    monkeypatch.setattr(probe_runner, "own_addresses", lambda: {V6})
    payload = batch(con, [V6], [80])
    payload["addresses"] = ["2606:50c0:8000:0000:0000:0000:0000:0153"]
    with pytest.raises(probe_runner.BatchUnreadable):
        probe_runner.parse_batch(payload)


def test_a_batch_for_somebody_elses_address_is_untouched(con, monkeypatch):
    """The guard must not refuse the ordinary case."""
    authorise(con, V4)
    monkeypatch.setattr(probe_runner, "own_addresses", lambda: {"192.0.2.99"})
    measured, connect = measure(batch(con, [V4], [80]))
    assert [(t, p) for t, _f, p in connect.calls] == [(V4, 80)]


# ------------------------------------------------------ the caller hangs up
#
# The runner is started over ssh, and its answer goes back on its stdout.
# When the process on our box that started the ssh dies, its lock on our box
# is let go at once, and sshd on the prober goes with the connection. Until
# 2026-10-28 the runner did not notice: measured on a stand-in prober, it
# was still measuring 56 s after its ssh was killed, so the next batch
# could put a second runner on the same target, up to 80 connects a second
# where `docs/PRODUCT.md` 5d promises 40.
#
# These start the real `main` in a child process with pipes, as sshd does.
# Only the connect and the certificate read are replaced, by a script that
# notes each call in a file, so nothing here reaches the network.

CONTROLPLANE = pathlib.Path(__file__).resolve().parents[1]

# How long the runner may take to stop once nobody can read its answer.
# On the stand-in prober the hangup reached the runner the moment its ssh was
# killed, so this is margin for a busy machine. It is below the 5 s a connect
# waits for an answer on purpose: a runner that only stopped starting connects
# and waited out the ones in flight would need up to 5 s, and fail here.
STOP_SECONDS = 3.0
assert STOP_SECONDS < prober.CONNECT_TIMEOUT_SECONDS

# A connect that starts this long after the hangup means the runner carried
# on. The watch wakes in milliseconds, so this too is margin.
LAST_CONNECT_SECONDS = 1.0

RATE = prober.CONNECTS_PER_SECOND_PER_TARGET

DRIVER = """
import asyncio
import functools
import sys
import time

from app import probe_runner

mode, log_path = sys.argv[1], sys.argv[2]


def note(word):
    with open(log_path, "a") as log:
        log.write(f"{word} {time.monotonic()}\\n")


async def connect(target, family, port):
    note("connect")
    if mode == "silent":
        # A target that never answers. The runner's own timeout ends it.
        await asyncio.sleep(3600)
    return 0.001


async def tls_read(target, family, port, timeout):
    note("tls")
    # In a worker thread, as the real read is, where nothing can cancel it.
    await asyncio.to_thread(time.sleep, 3600)
    return b""


injected = {"connect": connect, "tls_read": tls_read}
if mode == "writing":
    # Only so the answer is ready in a moment. The pace is not tested here.
    injected["rate_per_second"] = 100000.0
probe_runner.measure_batch = functools.partial(probe_runner.measure_batch,
                                               **injected)
sys.exit(probe_runner.main([]))
"""


def start_runner(tmp_path, payload, mode, *, stdin=subprocess.PIPE,
                 stdout=subprocess.PIPE):
    """The real `main` in a child process, as sshd starts it. Returns the
    child and the file it notes every connect and certificate read in."""
    driver = tmp_path / "driver.py"
    driver.write_text(DRIVER)
    log = tmp_path / "calls.log"
    log.write_text("")
    env = dict(os.environ, PYTHONPATH=str(CONTROLPLANE))
    child = subprocess.Popen([sys.executable, str(driver), mode, str(log)],
                             stdin=stdin, stdout=stdout,
                             stderr=subprocess.PIPE, cwd=CONTROLPLANE, env=env)
    if stdin == subprocess.PIPE:
        child.stdin.write(json.dumps(payload).encode())
        # The batch is sent, so stdin ends here, as it does over ssh. A pipe
        # reports that end as a hangup on stdin, which must not count.
        child.stdin.close()
    return child, log


def noted(log, word):
    """The monotonic times of every call of one kind, in order."""
    times = []
    for line in log.read_text().splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == word:
            times.append(float(parts[1]))
    return times


def wait_until_noted(log, word, count, limit=30.0):
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if len(noted(log, word)) >= count:
            return
        time.sleep(0.02)
    raise AssertionError(f"the runner never reached {count} {word} calls")


def wait_for_exit(child, hung_up):
    """The exit code, or a failure naming how long it ran on."""
    try:
        return child.wait(timeout=STOP_SECONDS)
    except subprocess.TimeoutExpired:
        pytest.fail(f"the runner was still running {STOP_SECONDS} s after"
                    " nobody could read its answer any more")


def worst_second(times):
    """The most calls inside any one second, the window starting at a call."""
    return max(sum(1 for t in times if start <= t < start + 1.0)
               for start in times)


@pytest.mark.parametrize("mode, word, count, ports, tls", [
    # Connecting at the pace, which is what holds a batch of open ports.
    ("connecting", "connect", 10, 4000, False),
    # Every slot waiting on a target that never answers, held by the timeout.
    ("silent", "connect", prober.MAX_CONCURRENT_CONNECTS, 4000, False),
    # A certificate read, in a worker thread that nothing can interrupt.
    ("certificate", "tls", 1, 3, True),
])
def test_a_runner_whose_ssh_died_stops_connecting(con, tmp_path, mode, word,
                                                  count, ports, tls):
    authorise(con, V4)
    numbers = list(range(1, ports + 1))
    payload = batch(con, [V4], numbers, tls_ports=numbers if tls else ())
    child, log = start_runner(tmp_path, payload, mode)
    try:
        wait_until_noted(log, word, count)
        # What the runner sees when the ssh that started it dies: nobody
        # reads its stdout any more.
        hung_up = time.monotonic()
        child.stdout.close()
        code = wait_for_exit(child, hung_up)
        assert child.stderr.read() == b"", "it wrote after its caller went"
        assert code == probe_runner.EXIT_CALLER_GONE
        late = [t for t in noted(log, "connect") + noted(log, "tls")
                if t > hung_up + LAST_CONNECT_SECONDS]
        assert late == [], f"{len(late)} calls began after the hangup"
    finally:
        child.kill()
        child.wait()


def test_a_runner_whose_caller_goes_while_it_writes_stops_without_a_word(
        con, tmp_path):
    """The answer of 2000 ports is far larger than a pipe holds, so the
    runner blocks writing it until its caller reads or goes."""
    authorise(con, V4)
    ports = list(range(1, 2001))
    child, log = start_runner(tmp_path, batch(con, [V4], ports), "writing")
    try:
        wait_until_noted(log, "connect", len(ports))
        time.sleep(0.5)  # the answer is built and fills the pipe
        hung_up = time.monotonic()
        child.stdout.close()
        code = wait_for_exit(child, hung_up)
        assert child.stderr.read() == b"", "it wrote after its caller went"
        assert code == probe_runner.EXIT_CALLER_GONE
    finally:
        child.kill()
        child.wait()


def test_a_runner_on_a_socket_stops_when_its_caller_closes_it(con, tmp_path):
    """Some builds of sshd hand the program one socket for stdin and stdout
    instead of two pipes. Its caller closing it is the same hangup.

    On Linux, where the probers run, the watch sees it and the runner stops
    at once. On macOS a socket is not watched (`hangup_is_visible` says why),
    so there the runner measures its whole batch and stops, in silence, at
    the write nobody can read. Each platform is held to what it does, so
    neither one skips."""
    authorise(con, V4)
    ports = list(range(1, 121))
    ours, theirs = socket.socketpair()
    payload = batch(con, [V4], ports)
    child, log = start_runner(tmp_path, payload, "connecting",
                              stdin=theirs.fileno(), stdout=theirs.fileno())
    theirs.close()
    try:
        ours.sendall(json.dumps(payload).encode())
        ours.shutdown(socket.SHUT_WR)
        wait_until_noted(log, "connect", 10)
        hung_up = time.monotonic()
        ours.close()
        if sys.platform.startswith("linux"):
            code = wait_for_exit(child, hung_up)
            assert len(noted(log, "connect")) < len(ports)
        else:
            code = child.wait(timeout=60)
            assert len(noted(log, "connect")) == len(ports)
        assert child.stderr.read() == b"", "it wrote after its caller went"
        assert code == probe_runner.EXIT_CALLER_GONE
    finally:
        child.kill()
        child.wait()


@pytest.mark.parametrize("stdio", ["pipe", "socket"])
def test_a_healthy_batch_is_untouched_by_the_watch(con, tmp_path, stdio):
    """The whole answer, one line, exit 0, at the pace.

    Its stdin is done the moment the batch is sent, and over a socket the
    caller says so by closing its sending half while it still reads. Neither
    is a hangup. The pace is the one in `test_every_connect_takes_a_token_from_the_pace`,
    read here on the real clock with the watch running beside it."""
    authorise(con, V4)
    ports = list(range(1, 81))
    payload = batch(con, [V4], ports)
    if stdio == "pipe":
        child, log = start_runner(tmp_path, payload, "connecting")
        out, err = child.stdout.read(), child.stderr.read()
        child.wait(timeout=60)
    else:
        ours, theirs = socket.socketpair()
        child, log = start_runner(tmp_path, payload, "connecting",
                                  stdin=theirs.fileno(),
                                  stdout=theirs.fileno())
        theirs.close()
        ours.sendall(json.dumps(payload).encode())
        ours.shutdown(socket.SHUT_WR)
        chunks = []
        while chunk := ours.recv(65536):
            chunks.append(chunk)
        ours.close()
        out, err = b"".join(chunks), child.stderr.read()
        child.wait(timeout=60)
    assert child.returncode == probe_runner.EXIT_OK, err
    assert err == b""
    assert out.endswith(b"\n") and out.count(b"\n") == 1
    measured = prober.run_from_json(json.loads(out))
    probed = [r for r in measured.results if r.target == V4]
    assert [r.port for r in probed] == ports
    assert {r.state for r in probed} == {prober.STATE_CONNECTED}
    connects = noted(log, "connect")
    assert len(connects) == len(ports)
    assert connects[-1] - connects[0] >= (len(ports) - 1) / RATE - 0.01
    assert worst_second(connects) <= RATE + 1


def test_only_a_pipe_or_a_linux_socket_is_watched(tmp_path):
    """A file or /dev/null has no reader to lose, and macOS answers poll on
    /dev/null with POLLNVAL, which is not a hangup either."""
    reader, writer = os.pipe()
    ours, theirs = socket.socketpair()
    with open(tmp_path / "answer.json", "w") as file, \
            open(os.devnull, "w") as null:
        try:
            assert probe_runner.hangup_is_visible(writer)
            assert probe_runner.hangup_is_visible(theirs.fileno()) == \
                sys.platform.startswith("linux")
            assert not probe_runner.hangup_is_visible(file.fileno())
            assert not probe_runner.hangup_is_visible(null.fileno())
        finally:
            os.close(reader)
            os.close(writer)
            ours.close()
            theirs.close()


def test_a_stream_with_no_descriptor_is_not_watched():
    """The in-memory streams the tests above hand `main`. A process sshd
    starts always has a real stdout."""
    assert probe_runner.watch_for_hangup(io.StringIO()) is False
