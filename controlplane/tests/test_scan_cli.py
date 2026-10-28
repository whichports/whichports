"""The scan responder: `scan_cli drain` probes every host that asked, from the
vantage host, and clears the requests it handled.

Nothing here runs ssh or opens a socket. The transport is swapped for a fake far
end that runs the real runner in-process, the same shape test_dispatch.py uses,
so the batch really is parsed and the snapshot really is enforced.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import (authz, db, dispatch, probe_runner, prober, scan, scan_cli,
                 store, vantages)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    scan.init(connection)
    # A drain --via names a vantage of the registry and its destination
    # (prober_cli.registry_row_for_via), which is the one every drain here
    # names.
    vantages.init(connection)
    vantages.add(connection, "probe1", "root@198.51.100.7", ["78.141.210.130"])
    yield connection
    connection.close()


def authorise(con, address, name="box"):
    """A host that reported one listening socket on `address` and authorised it,
    so a drain has a target and a port to probe."""
    host_id, _ = store.add_host(con, name)
    document = json.dumps({
        "sockets": {"listening": [
            {"protocol": "tcp", "port": 80, "bind_address": address}]},
        "interface_addresses": {"addresses": [
            {"interface": "eth0",
             "family": "v6" if ":" in address else "v4",
             "address": address, "global": True}]}})
    store.insert_report(con, host_id, 1, 1, document)
    result = authz.record_agent_proof(con, host_id, address, document,
                                      now=datetime.now(timezone.utc))
    assert result.recorded, result.reason
    return host_id


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


def drain_args():
    return scan_cli.parse_args(["drain", "--vantage", "probe1",
                                "--via", "root@198.51.100.7"])


def use_transport(monkeypatch, transport_factory):
    """Swap the ssh transport the drain builds for a fake. Both scan_cli and
    dispatch reference the same module object, so patching it here reaches the
    drain."""
    monkeypatch.setattr(dispatch, "SshTransport", transport_factory)


# --------------------------------------------------------------- a clean drain

def test_a_pending_host_is_probed_and_its_request_cleared(con, monkeypatch):
    host_id = authorise(con, V4)
    scan.request_scan(con, host_id, datetime.now(timezone.utc))
    far = FakeProber()
    use_transport(monkeypatch, lambda via: far)

    code = scan_cli._drain(con, drain_args())
    assert code == 0
    assert far.connects == [(V4, 80)]
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 1
    assert scan.pending_requests(con) == [], "a measured host's request is cleared"


def test_the_measurement_is_stored_through_run_host(con, monkeypatch):
    host_id = authorise(con, V4)
    scan.request_scan(con, host_id, datetime.now(timezone.utc))
    use_transport(monkeypatch, lambda via: FakeProber())

    scan_cli._drain(con, drain_args())
    run = prober.latest_run(con, host_id)
    assert run is not None
    ports = {row["port"] for row in prober.run_results(con, run["id"])}
    assert 80 in ports


def test_a_burst_for_one_host_is_probed_once_and_all_cleared(con, monkeypatch):
    host_id = authorise(con, V4)
    now = datetime.now(timezone.utc)
    scan.request_scan(con, host_id, now)
    scan.request_scan(con, host_id,
                      now + timedelta(seconds=scan.SCAN_MIN_INTERVAL_SECONDS))
    assert len(scan.pending_ids_for_host(con, host_id)) == 2
    use_transport(monkeypatch, lambda via: FakeProber())

    scan_cli._drain(con, drain_args())
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 1
    assert scan.pending_requests(con) == []


# ----------------------------------------------------- hosts that are skipped

def test_a_revoked_host_is_skipped_and_its_request_cleared(con, monkeypatch, capsys):
    host_id = authorise(con, V4)
    scan.request_scan(con, host_id, datetime.now(timezone.utc))
    store.revoke_host(con, "box")
    far = FakeProber()
    use_transport(monkeypatch, lambda via: far)

    code = scan_cli._drain(con, drain_args())
    assert code == 0
    assert far.connects == [], "a revoked host is never probed"
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 0
    assert scan.pending_requests(con) == [], "cleared so it does not loop forever"
    assert "revoked" in capsys.readouterr().out


def test_a_host_that_never_reported_is_skipped_and_cleared(con, monkeypatch):
    """Nothing derived from any document means no target to probe. The request
    is cleared rather than retried forever, and a fresh scan after the host
    reports records a new one."""
    host_id, _ = store.add_host(con, "silent")
    scan.request_scan(con, host_id, datetime.now(timezone.utc))
    far = FakeProber()
    use_transport(monkeypatch, lambda via: far)

    code = scan_cli._drain(con, drain_args())
    assert code == 0
    assert far.connects == []
    assert scan.pending_requests(con) == []


# -------------------------------------------- one failure does not sink the rest

def test_one_host_failing_does_not_stop_the_others_and_stays_pending(con, monkeypatch):
    """The retry choice, as behaviour. A DispatchFailed means the pass did not
    happen, so that host's request is left pending and the next drain retries
    it, while the other host is still measured and cleared. Clearing a pass that
    did not happen would read afterwards like a pass that found nothing."""
    first = authorise(con, V4, name="box-one")
    second = authorise(con, V6, name="box-two")
    now = datetime.now(timezone.utc)
    scan.request_scan(con, first, now)
    scan.request_scan(con, second, now)
    far = FakeProber()
    calls = {"n": 0}

    def maybe_fail(via):
        def transport(payload):
            calls["n"] += 1
            if calls["n"] == 1:
                raise dispatch.DispatchFailed("the vantage host was unreachable")
            return far(payload)
        return transport

    use_transport(monkeypatch, maybe_fail)
    code = scan_cli._drain(con, drain_args())
    assert code == 1, "a pass that did not happen is not a clean drain"
    # One host measured and cleared, the failed one left pending to retry.
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 1
    assert scan.pending_requests(con) == [first], \
        "the failed host's request is retried, not swallowed"


def test_a_retried_failure_measures_on_the_next_drain(con, monkeypatch):
    """The other half of the retry choice: the request that stayed pending is
    probed the next time the drain runs."""
    host_id = authorise(con, V4)
    scan.request_scan(con, host_id, datetime.now(timezone.utc))

    def failing(via):
        def transport(payload):
            raise dispatch.DispatchFailed("the vantage host was unreachable")
        return transport

    use_transport(monkeypatch, failing)
    assert scan_cli._drain(con, drain_args()) == 1
    assert scan.pending_requests(con) == [host_id]

    far = FakeProber()
    use_transport(monkeypatch, lambda via: far)
    assert scan_cli._drain(con, drain_args()) == 0
    assert far.connects == [(V4, 80)]
    assert scan.pending_requests(con) == []


# ------------------------------------------------------------ the command shape

def test_no_pending_requests_is_a_clean_exit(con, monkeypatch, capsys):
    use_transport(monkeypatch, lambda via: FakeProber())
    code = scan_cli._drain(con, drain_args())
    assert code == 0
    assert "no scan requests are waiting" in capsys.readouterr().out


def test_a_drain_without_a_vantage_refuses(con):
    parsed = scan_cli.parse_args(["drain", "--via", "root@198.51.100.7"])
    assert scan_cli._drain(con, parsed) == 2


def test_a_drain_without_a_via_refuses(con, capsys):
    parsed = scan_cli.parse_args(["drain", "--vantage", "probe1"])
    assert scan_cli._drain(con, parsed) == 2
    assert "--via" in capsys.readouterr().err


def test_the_placeholder_vantage_is_refused(con):
    """chosen_vantage refuses the 'unnamed' placeholder, and the drain reuses
    it, so a result that could not say where it was taken from is never stored."""
    parsed = scan_cli.parse_args(
        ["drain", "--vantage", prober.UNNAMED_VANTAGE, "--via", "root@x"])
    assert scan_cli._drain(con, parsed) == 2


def test_the_drain_command_is_reachable_from_the_command_line():
    parsed = scan_cli.parse_args(["drain", "--vantage", "probe1",
                                  "--via", "root@198.51.100.7"])
    assert parsed.command == "drain"
    assert parsed.vantage == "probe1"
    assert parsed.via == "root@198.51.100.7"
