"""`probe --registry`: the command driving every vantage in the registry.

Nothing here opens a socket. The far end is the real runner in process
against a fake socket, handed in through the namespace the way the tests
for `--via` hand a transport in.
"""
import argparse
import json
from datetime import datetime, timezone

import pytest

from app import (authz, db, dispatch, probe_runner, prober, prober_cli, store,
                 vantages)

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    vantages.init(connection)
    yield connection
    connection.close()


def enrol(con, addresses, name="box", ports=(80,)):
    host_id, _ = store.add_host(con, name)
    document = {
        "sockets": {"listening": [
            {"protocol": "tcp", "port": port, "bind_address": "0.0.0.0",
             "family": "v4"} for port in ports]},
        "interface_addresses": {"addresses": [
            {"interface": "eth0", "family": "v6" if ":" in a else "v4",
             "address": a, "global": True} for a in addresses]}}
    store.insert_report(con, host_id, 1, 1, json.dumps(document))
    for address in addresses:
        result = authz.record_agent_proof(con, host_id, address, json.dumps(document),
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


class RefusingConnect:
    async def __call__(self, target, family, port):
        raise AssertionError("the registry path must not connect locally")


def args(**overrides):
    base = dict(command="probe", host=None, dry_run=False, tls_ports=None,
                vantage=None, registry=True, via=None, joined=False,
                changed=False)
    base.update(overrides)
    return argparse.Namespace(**base)


def run(con, fars, **overrides):
    def factory(destination):
        fars[destination] = FakeProber(destination)
        return fars[destination]
    return prober_cli.run(con, args(transport_factory=factory, **overrides),
                          connect=RefusingConnect())


def test_the_flag_exists_and_is_off_by_default():
    assert prober_cli.parse_args(["probe", "--registry"]).registry is True
    assert prober_cli.parse_args(["probe"]).registry is False


def test_an_empty_registry_probes_nothing_and_says_so(con, capsys):
    enrol(con, [V4])
    fars = {}
    assert run(con, fars) == 2
    assert fars == {}
    assert "no enabled vantage" in capsys.readouterr().err
    assert con.execute("SELECT COUNT(*) c FROM probe_runs").fetchone()["c"] == 0


def test_every_enabled_vantage_is_driven_and_each_run_is_named(con, capsys):
    host_id = enrol(con, [V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    fars = {}
    assert run(con, fars) == 0
    assert set(fars) == {"root@" + PROBE1_V4, "root@" + PROBE2_V4}
    for far in fars.values():
        assert far.connects == [(V4, 80)]
    stored = con.execute("SELECT host_id, vantage FROM probe_runs ORDER BY id").fetchall()
    assert [(r["host_id"], r["vantage"]) for r in stored] == [
        (host_id, "probe1"), (host_id, "probe2")]
    out = capsys.readouterr().out
    assert "box from probe1" in out and "box from probe2" in out
    assert "2 of 2 host passes measured" in out


def test_a_disabled_vantage_is_not_driven(con):
    enrol(con, [V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    vantages.set_enabled(con, "probe2", False)
    fars = {}
    assert run(con, fars) == 0
    assert set(fars) == {"root@" + PROBE1_V4}


def test_vantage_narrows_the_registry_to_one(con):
    enrol(con, [V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    fars = {}
    assert run(con, fars, vantage="probe2") == 0
    assert set(fars) == {"root@" + PROBE2_V4}
    stored = con.execute("SELECT vantage FROM probe_runs").fetchall()
    assert [r["vantage"] for r in stored] == ["probe2"]


def test_naming_a_vantage_not_in_the_registry_is_refused(con, capsys):
    enrol(con, [V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    fars = {}
    assert run(con, fars, vantage="probe9") == 2
    assert fars == {}
    assert "probe9" in capsys.readouterr().err


def test_registry_and_via_together_are_refused(con, capsys):
    enrol(con, [V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    fars = {}
    assert run(con, fars, vantage="probe1", via="root@somewhere") == 2
    assert fars == {}


def test_a_dead_vantage_is_reported_and_the_pass_still_stores_the_other(con, capsys):
    enrol(con, [V4], "one")
    enrol(con, [V6], "two")
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])

    def factory(destination):
        if destination == "root@" + PROBE2_V4:
            def dead(payload):
                raise dispatch.VantageUnreachable("ssh could not reach it")
            return dead
        return FakeProber(destination)

    code = prober_cli.run(con, args(transport_factory=factory),
                          connect=RefusingConnect())
    assert code == 1, "a pass that did not happen from one vantage is said"
    stored = con.execute("SELECT vantage FROM probe_runs").fetchall()
    assert [r["vantage"] for r in stored] == ["probe1", "probe1"]
    captured = capsys.readouterr()
    assert "2 of 4 host passes measured" in captured.out
    assert "not measured" in captured.err and "not tried" in captured.err


def test_our_own_addresses_are_not_probed_from_any_vantage(con):
    enrol(con, [V4, PROBE1_V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    fars = {}
    assert run(con, fars) == 0
    for far in fars.values():
        assert far.connects == [(V4, 80)]
    rows = con.execute("SELECT DISTINCT target, reason FROM probe_results"
                       " WHERE target = ?", (PROBE1_V4,)).fetchall()
    assert [(r["target"], r["reason"]) for r in rows] == [
        (PROBE1_V4, prober.REASON_VANTAGE_ADDRESS)]


def test_the_dry_run_names_our_own_address_and_sends_nothing(con, capsys):
    enrol(con, [V4, PROBE1_V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    fars = {}
    assert run(con, fars, dry_run=True) == 0
    assert fars == {}
    out = capsys.readouterr().out
    assert f"{PROBE1_V4} is one of our own vantage addresses" in out
    assert f"v4 {V4}  yes" in out
    assert f"v4 {PROBE1_V4}  yes" not in out


def test_the_local_path_drops_our_own_address_too(con, capsys):
    """The laptop's mode. No typed row, because the engine stores its own
    rows and this path does not go through dispatch, but no packet either."""
    enrol(con, [V4, PROBE1_V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    calls = []

    async def connect(target, family, port):
        calls.append((target, port))
        return 0.001

    code = prober_cli.run(con, args(registry=False, vantage="laptop"), connect=connect)
    assert code == 0
    assert calls == [(V4, 80)]
    assert PROBE1_V4 in capsys.readouterr().err


def test_the_via_path_writes_the_typed_row_for_our_own_address(con):
    enrol(con, [V4, PROBE1_V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    far = FakeProber("far")
    code = prober_cli._probe_via(con, [prober_cli.plan_for(
        con, store.list_hosts(con)[0])], "root@x", vantage="probe1",
        transport=far, exclude=vantages.all_addresses(con))
    assert code == 0
    assert far.connects == [(V4, 80)]
    rows = con.execute("SELECT reason FROM probe_results WHERE target = ?",
                       (PROBE1_V4,)).fetchall()
    assert {r["reason"] for r in rows} == {prober.REASON_VANTAGE_ADDRESS}


def test_a_database_from_before_the_registry_still_runs(tmp_path):
    """`run` on a connection that never ran vantages.init: no table, no
    exclusion, no crash. That is every test written before today."""
    con = db.connect(str(tmp_path / "old.db"))
    db.init(con)
    authz.init(con)
    prober.init(con)
    enrol(con, [V4])
    calls = []

    async def connect(target, family, port):
        calls.append((target, port))
        return 0.001

    assert prober_cli.run(con, args(registry=False, vantage="laptop"),
                          connect=connect) == 0
    assert calls == [(V4, 80)]
    con.close()


def test_changed_applies_to_the_registry_path_as_well(con, capsys):
    enrol(con, [V4])
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    fars = {}
    assert run(con, fars, changed=True) == 0
    assert len(fars) == 1
    fars = {}
    assert run(con, fars, changed=True) == 0
    assert fars == {}
    assert "nothing has moved" in capsys.readouterr().out


# ================================================ the deployment is part of this


@pytest.mark.parametrize("unit", ["whichports-probe.service",
                                  "whichports-probe-fast.service",
                                  "whichports-scan.service"])
def test_the_probe_units_drive_the_registry_and_read_no_environment_file(unit):
    """The three units that probe pass --registry and nothing that names a
    vantage or a destination. A unit that still read prober.env would keep
    driving one box by hand while the registry said two, which is the kind of
    thing a rewrite drops, so it is pinned here."""
    import pathlib
    path = pathlib.Path(__file__).resolve().parents[1] / "ops" / unit
    text = path.read_text()
    exec_start = [line for line in text.splitlines() if line.startswith("ExecStart=")]
    assert len(exec_start) == 1, exec_start
    assert "--registry" in exec_start[0]
    assert "--via" not in exec_start[0] and "--vantage" not in exec_start[0]
    assert not any(line.startswith("EnvironmentFile=") for line in text.splitlines())


# ================================ certificates on the known ports, 2026-09-10
#
# No unit ever passed --tls-port, so no certificate was ever read in production
# (docs/RECORD.md 4.158). The owner decided the list on 2026-09-10 and the timers
# pass --tls-known.

from test_prober_tls import certificate as a_certificate  # noqa: E402


class ReadingProber(FakeProber):
    """The far end with a TLS primitive that presents one certificate."""

    def __init__(self, name):
        super().__init__(name)
        self.reads = []

    def __call__(self, payload):
        parsed = probe_runner.parse_batch(json.loads(payload))
        outer = self

        async def connect(target, family, port):
            outer.connects.append((target, port))
            return 0.002

        async def tls_read(target, family, port, timeout):
            outer.reads.append((target, port))
            return a_certificate()

        return json.dumps(probe_runner.measure_batch(parsed, connect=connect,
                                                     tls_read=tls_read))


def test_the_known_list_is_what_the_owner_decided():
    assert prober_cli.KNOWN_TLS_PORTS == (443, 465, 636, 853, 993, 995, 8443)


def test_tls_known_reads_the_known_ports_the_plan_carries_and_no_other(con):
    enrol(con, [V4], ports=(22, 80, 443, 8443))
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    fars = {}

    def factory(destination):
        fars[destination] = ReadingProber(destination)
        return fars[destination]

    code = prober_cli.run(con, args(transport_factory=factory, tls_known=True),
                          connect=RefusingConnect())
    assert code == 0
    far = fars["root@" + PROBE1_V4]
    assert sorted(far.reads) == [(V4, 443), (V4, 8443)]
    # One row per named port per family. The host has no v6 address, so the
    # v6 rows say the connect never happened, which is the honest half.
    rows = con.execute("SELECT family, port, state FROM probe_tls"
                       " ORDER BY family, port").fetchall()
    assert [(r["family"], r["port"], r["state"]) for r in rows] == [
        ("v4", 443, prober.TLS_STATE_READ), ("v4", 8443, prober.TLS_STATE_READ),
        ("v6", 443, prober.TLS_STATE_NOT_READ), ("v6", 8443, prober.TLS_STATE_NOT_READ)]
    assert con.execute("SELECT subject FROM probe_tls WHERE port = 443"
                       " AND family = 'v4'").fetchone()[0] == "CN=subject.test"


def test_a_host_with_no_known_port_reads_nothing_and_stores_no_tls_row(con):
    enrol(con, [V4], ports=(22, 80))
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    far = {}
    code = prober_cli.run(con, args(transport_factory=lambda d: far.setdefault(d, ReadingProber(d)),
                                    tls_known=True), connect=RefusingConnect())
    assert code == 0
    assert far["root@" + PROBE1_V4].reads == []
    assert con.execute("SELECT COUNT(*) c FROM probe_tls").fetchone()["c"] == 0


def test_without_the_flag_nothing_is_read_as_before(con):
    enrol(con, [V4], ports=(443,))
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    far = {}
    prober_cli.run(con, args(transport_factory=lambda d: far.setdefault(d, ReadingProber(d))),
                   connect=RefusingConnect())
    assert far["root@" + PROBE1_V4].reads == []


def test_a_port_named_by_hand_joins_the_known_list(con):
    enrol(con, [V4], ports=(443, 9443))
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    far = {}
    prober_cli.run(con, args(transport_factory=lambda d: far.setdefault(d, ReadingProber(d)),
                             tls_known=True, tls_ports=[9443]), connect=RefusingConnect())
    assert sorted(far["root@" + PROBE1_V4].reads) == [(V4, 443), (V4, 9443)]


def test_a_read_is_a_second_connection_from_the_same_vantage_and_every_vantage_reads(con):
    enrol(con, [V4], ports=(443,))
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    fars = {}
    prober_cli.run(con, args(transport_factory=lambda d: fars.setdefault(d, ReadingProber(d)),
                             tls_known=True), connect=RefusingConnect())
    for far in fars.values():
        assert far.reads == [(V4, 443)]
    rows = con.execute("SELECT runs.vantage FROM probe_tls t JOIN probe_runs runs"
                       " ON t.run_id = runs.id WHERE t.state = ?"
                       " ORDER BY runs.vantage", (prober.TLS_STATE_READ,)).fetchall()
    assert [r["vantage"] for r in rows] == ["probe1", "probe2"]


def test_the_dry_run_names_the_reads_and_does_not_complain_about_known_ports_the_host_lacks(con, capsys):
    enrol(con, [V4], ports=(22, 443))
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    assert prober_cli.run(con, args(dry_run=True, tls_known=True),
                          connect=RefusingConnect()) == 0
    out = capsys.readouterr().out
    assert "a certificate would be read from 443" in out
    assert "was named for a certificate read and the document does not report it" not in out
    assert "1 handshakes" in out


def test_the_flag_parses_and_the_units_pass_it():
    assert prober_cli.parse_args(["probe", "--tls-known"]).tls_known is True
    assert prober_cli.parse_args(["probe"]).tls_known is False
    import pathlib
    for unit in ("whichports-probe.service", "whichports-probe-fast.service",
                 "whichports-scan.service"):
        path = pathlib.Path(__file__).resolve().parents[1] / "ops" / unit
        exec_start = [l for l in path.read_text().splitlines() if l.startswith("ExecStart=")][0]
        assert "--tls-known" in exec_start, unit
