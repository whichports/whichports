"""`scan_cli drain --registry`: the responder driving every vantage.

The far end is the real runner in process, as in tests/test_scan_cli.py.
"""
import argparse
import json
from datetime import datetime, timezone

import pytest

from app import (authz, db, dispatch, probe_runner, prober, scan, scan_cli,
                 store, vantages)

V4 = "185.199.108.153"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    scan.init(connection)
    vantages.init(connection)
    yield connection
    connection.close()


def enrol(con, address, name="box"):
    host_id, _ = store.add_host(con, name)
    document = json.dumps({
        "sockets": {"listening": [
            {"protocol": "tcp", "port": 80, "bind_address": address,
             "family": "v4"}]},
        "interface_addresses": {"addresses": [
            {"interface": "eth0", "family": "v4", "address": address,
             "global": True}]}})
    store.insert_report(con, host_id, 1, 1, document)
    result = authz.record_agent_proof(con, host_id, address, document,
                                      now=datetime.now(timezone.utc))
    assert result.recorded, result.reason
    return host_id


class FakeProber:
    def __init__(self, name):
        self.name = name
        self.connects = []

    def __call__(self, payload):
        parsed = probe_runner.parse_batch(json.loads(payload))
        outer = self

        async def connect(target, family, port):
            outer.connects.append((target, port))
            return 0.002

        return json.dumps(probe_runner.measure_batch(parsed, connect=connect))


def drain(con, factory, **overrides):
    base = dict(command="drain", vantage=None, via=None, registry=True,
                transport_factory=factory)
    base.update(overrides)
    return scan_cli.run(con, argparse.Namespace(**base))


def request(con, host_id):
    now = datetime.now(timezone.utc)
    result = scan.request_scan(con, host_id, now)
    assert result.accepted, result.sentence


def test_the_flag_exists():
    assert scan_cli.parse_args(["drain", "--registry"]).registry is True
    assert scan_cli.parse_args(["drain", "--vantage", "p", "--via", "x"]).registry is False


def test_an_empty_registry_drains_nothing_and_keeps_the_request(con, capsys):
    host_id = enrol(con, V4)
    request(con, host_id)
    fars = {}
    assert drain(con, lambda d: fars.setdefault(d, FakeProber(d))) == 2
    assert fars == {}
    assert scan.pending_requests(con) == [host_id]
    assert "no enabled vantage" in capsys.readouterr().err


def test_a_request_is_probed_from_every_vantage_and_cleared(con, capsys):
    host_id = enrol(con, V4)
    request(con, host_id)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    fars = {}
    assert drain(con, lambda d: fars.setdefault(d, FakeProber(d))) == 0
    assert set(fars) == {"root@" + PROBE1_V4, "root@" + PROBE2_V4}
    stored = con.execute("SELECT vantage FROM probe_runs ORDER BY id").fetchall()
    assert [r["vantage"] for r in stored] == ["probe1", "probe2"]
    assert scan.pending_requests(con) == []
    assert "1 of 1 requested hosts measured from probe1, probe2" in capsys.readouterr().out


def test_one_vantage_measuring_clears_the_request_and_the_other_is_reported(con, capsys):
    host_id = enrol(con, V4)
    request(con, host_id)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])

    def factory(destination):
        if destination == "root@" + PROBE2_V4:
            def dead(payload):
                raise dispatch.VantageUnreachable("down")
            return dead
        return FakeProber(destination)

    assert drain(con, factory) == 1
    assert scan.pending_requests(con) == []
    captured = capsys.readouterr()
    assert "box from probe2" in captured.out
    assert "not measured" in captured.err


def test_no_vantage_measuring_keeps_the_request(con):
    host_id = enrol(con, V4)
    request(con, host_id)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])

    def factory(destination):
        def dead(payload):
            raise dispatch.VantageUnreachable("down")
        return dead

    assert drain(con, factory) == 1
    assert scan.pending_requests(con) == [host_id]


def test_the_hand_named_path_still_works_and_excludes_our_address(con):
    host_id = enrol(con, V4)
    request(con, host_id)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    # Named by hand, and still a vantage of the registry, as every pass
    # --via is since the finer locks (prober_cli.registry_row_for_via).
    vantages.add(con, "byhand", "root@elsewhere", ["185.199.110.7"])
    fars = {}
    code = drain(con, lambda d: fars.setdefault(d, FakeProber(d)),
                 registry=False, vantage="byhand", via="root@elsewhere")
    assert code == 0
    assert set(fars) == {"root@elsewhere"}
    assert scan.pending_requests(con) == []
    stored = con.execute("SELECT vantage FROM probe_runs").fetchall()
    assert [r["vantage"] for r in stored] == ["byhand"]


def test_a_drain_with_tls_known_reads_the_certificate_on_a_known_port(con):
    from test_prober_tls import certificate as a_certificate
    host_id, _ = store.add_host(con, "tlsbox")
    document = json.dumps({
        "sockets": {"listening": [
            {"protocol": "tcp", "port": 443, "bind_address": V4, "family": "v4"}]},
        "interface_addresses": {"addresses": [
            {"interface": "eth0", "family": "v4", "address": V4, "global": True}]}})
    store.insert_report(con, host_id, 1, 1, document)
    assert authz.record_agent_proof(con, host_id, V4, document,
                                    now=datetime.now(timezone.utc)).recorded
    request(con, host_id)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    reads = []

    def factory(destination):
        def transport(payload):
            parsed = probe_runner.parse_batch(json.loads(payload))

            async def connect(target, family, port):
                return 0.002

            async def tls_read(target, family, port, timeout):
                reads.append((target, port))
                return a_certificate()
            return json.dumps(probe_runner.measure_batch(parsed, connect=connect,
                                                         tls_read=tls_read))
        return transport

    assert drain(con, factory, tls_known=True) == 0
    assert reads == [(V4, 443)]
    assert con.execute("SELECT COUNT(*) c FROM probe_tls WHERE state = ?",
                       (prober.TLS_STATE_READ,)).fetchone()["c"] == 1
    assert scan_cli.parse_args(["drain", "--registry", "--tls-known"]).tls_known is True
