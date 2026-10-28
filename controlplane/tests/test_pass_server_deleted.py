"""A server deleted while a probe pass runs is left out, and the pass goes on.

    python -m pytest tests/test_pass_server_deleted.py

Found on the box on 2026-10-03 (docs/RECORD.md 4.312): the hourly pass started
at 15:26:15 UTC, a server was deleted in the dashboard at 15:26:32, and at
15:27:03 the pass ended with `sqlite3.IntegrityError: FOREIGN KEY constraint
failed` on the insert into `probe_runs`. A pass takes its list of servers
before it measures the first one, so a server deleted after that had its run
stored against a host that no longer existed, and every server after it in
the list, in every workspace, went unmeasured in that pass. The same error
stood in the probe units' journal three times in three days.

A server that is gone when its run is stored is not an error. The pass leaves
it out, says so as a typed line, and goes on. Any other failure to store a
run is still an error and still ends the pass.
"""
import pathlib
import sqlite3

import pytest

from app import dispatch, prober, prober_cli, store, vantages
from test_dispatch_vantages import (OTHER_V4, PROBE1_V4, PROBE1_V6, PROBE2_V4,  # noqa: F401
                                    V4, FakeProber, authorise, con, plan,
                                    two_vantages)

THIRD_V4 = "185.199.109.153"


def delete_server(con, name):
    """Remove, then Delete, the two acts the dashboard takes."""
    assert store.revoke_host(con, name)
    assert store.delete_host(con, name)


def three_servers(con):
    """Three servers, each with one proved address, and their plans, made
    before anything is measured, as a pass makes them."""
    plans = []
    for name, address in (("first", V4), ("middle", OTHER_V4), ("last", THIRD_V4)):
        host_id = authorise(con, [address], name=name)
        plans.append(plan(con, host_id, name, [address], [80, 443]))
    return plans


class DeletesWhileMeasuring(FakeProber):
    """A vantage that measures as the real one does, during whose measurement
    of one address somebody deletes that server in the dashboard."""

    def __init__(self, con, name, address, deletes):
        super().__init__(name)
        self.con, self.address, self.deletes, self.done = con, address, deletes, False

    def __call__(self, payload):
        answer = super().__call__(payload)
        if not self.done and self.address in payload:
            self.done = True
            delete_server(self.con, self.deletes)
        return answer


def factory_for(fakes):
    by_destination = {"root@" + PROBE1_V4: fakes[0], "root@" + PROBE2_V4: fakes[1]}
    return lambda destination: by_destination[destination]


def measured_names(con):
    return sorted(row["name"] for row in con.execute(
        "SELECT DISTINCT h.name FROM probe_runs r JOIN hosts h ON h.id = r.host_id"
        " WHERE r.finished_at IS NOT NULL"))


# ------------------------------------------------------------- the pass itself

def test_a_server_deleted_during_its_measurement_does_not_end_the_pass(con):
    plans = three_servers(con)
    chosen = two_vantages(con)
    fakes = [DeletesWhileMeasuring(con, "probe1", OTHER_V4, "middle"), FakeProber("probe2")]

    outcomes = dispatch.run_pass(con, plans, chosen, transport_factory=factory_for(fakes))

    by_host = {}
    for outcome in outcomes:
        by_host.setdefault(outcome.host_name, []).append(outcome)
    # the servers before it and after it are measured from both vantages
    assert [o.measured for o in by_host["first"]] == [True, True]
    assert [o.measured for o in by_host["last"]] == [True, True]
    assert measured_names(con) == ["first", "last"]
    # the deleted one is one typed outcome, and the second vantage is not sent
    # to a server that is gone
    assert len(by_host["middle"]) == 1
    gone = by_host["middle"][0]
    assert gone.gone and not gone.measured and not gone.skipped
    assert gone.failure == dispatch.SERVER_DELETED
    assert all(OTHER_V4 not in batch["addresses"] for batch in fakes[1].batches)


def test_a_server_deleted_before_its_turn_is_left_out_the_same_way(con):
    """The list was made, then the server went, then its turn came."""
    plans = three_servers(con)
    chosen = two_vantages(con)
    delete_server(con, "middle")
    fakes = [FakeProber("probe1"), FakeProber("probe2")]

    outcomes = dispatch.run_pass(con, plans, chosen, transport_factory=factory_for(fakes))

    assert [(o.host_name, o.gone) for o in outcomes if o.gone] == [("middle", True)]
    assert measured_names(con) == ["first", "last"]
    assert sum(1 for o in outcomes if o.measured) == 4


def test_the_last_server_of_the_list_deleted_leaves_the_others_stored(con):
    plans = three_servers(con)
    chosen = two_vantages(con)
    fakes = [DeletesWhileMeasuring(con, "probe1", THIRD_V4, "last"), FakeProber("probe2")]
    outcomes = dispatch.run_pass(con, plans, chosen, transport_factory=factory_for(fakes))
    assert measured_names(con) == ["first", "middle"]
    assert [o.host_name for o in outcomes if o.gone] == ["last"]


def test_a_removed_server_is_still_a_row_and_is_no_error_either(con):
    """Remove keeps the row, so its run is stored like any other. What may be
    probed is the gate's business, batch by batch, and not this test's."""
    plans = three_servers(con)
    chosen = two_vantages(con)
    assert store.revoke_host(con, "middle")
    fakes = [FakeProber("probe1"), FakeProber("probe2")]
    outcomes = dispatch.run_pass(con, plans, chosen, transport_factory=factory_for(fakes))
    assert not any(o.gone for o in outcomes)
    assert len(outcomes) == 6


def test_any_other_failure_to_store_a_run_still_ends_the_pass(con, monkeypatch):
    """Only a server that is gone is left out. A run that cannot be stored for
    a server that is still there is an error nobody has explained, and it is
    not turned into a line."""
    plans = three_servers(con)
    chosen = two_vantages(con)

    def broken(*args, **kwargs):
        raise sqlite3.IntegrityError("NOT NULL constraint failed: probe_results.state")

    monkeypatch.setattr(prober, "_finish_run", broken)
    fakes = [FakeProber("probe1"), FakeProber("probe2")]
    with pytest.raises(sqlite3.IntegrityError):
        dispatch.run_pass(con, plans, chosen, transport_factory=factory_for(fakes))


def test_storing_a_run_for_a_deleted_server_says_which_error_it_is(con):
    """The one place a run is stored names the case, so every caller can tell
    it from any other failure."""
    host_id = authorise(con, [V4], name="box")
    far = FakeProber()
    run = dispatch.run_host(con, plan(con, host_id, "box", [V4], [80]), far, "probe1")
    measured = prober.Run(id=None, vantage="probe1", started_at=run.started_at,
                          finished_at=run.finished_at, results=run.results,
                          certificates=())
    delete_server(con, "box")
    with pytest.raises(prober.HostGone):
        prober.store_measurement(con, host_id, measured)
    # and nothing is left behind for it
    assert con.execute("SELECT COUNT(*) FROM probe_runs").fetchone()[0] == 0


# ------------------------------------------------- what the timers' command says

def test_the_command_says_so_as_a_typed_line_and_is_not_a_failure(con, capsys, monkeypatch):
    plans = three_servers(con)
    two_vantages(con)
    fakes = [DeletesWhileMeasuring(con, "probe1", OTHER_V4, "middle"), FakeProber("probe2")]
    code = prober_cli._probe_registry(con, plans, transport_factory=factory_for(fakes))
    said = capsys.readouterr()
    assert code == 0, said.err
    assert "middle from probe1" in said.out
    assert "  not measured: " + dispatch.SERVER_DELETED in said.out
    # The summary's own lines agree: three servers were on the list, one was
    # deleted, so two were there to measure, from two vantages each. On the
    # box on 2026-10-03 this line counted the deleted server among its hosts
    # and named it as left out two lines on (docs/RECORD.md 4.328).
    assert "4 of 4 host passes measured, 2 hosts from probe1, probe2" in said.out
    assert "1 server deleted during the pass: middle" in said.out
    assert "not measured: middle" not in said.out      # it is not among the failures


def test_a_pass_with_a_real_failure_beside_it_still_fails(con, capsys):
    """The deleted server is left out of the count of failures, and a vantage
    that could not be reached is still one."""
    plans = three_servers(con)
    two_vantages(con)

    def unreachable(payload):
        raise dispatch.VantageUnreachable("ssh could not be reached")

    fakes = [DeletesWhileMeasuring(con, "probe1", OTHER_V4, "middle"), unreachable]
    code = prober_cli._probe_registry(con, plans, transport_factory=factory_for(fakes))
    assert code == 1
    assert "1 server deleted during the pass: middle" in capsys.readouterr().out


def test_both_lanes_run_the_command_this_file_tests():
    """The hourly lane and the ten-minute lane are two units with one command
    line, so one path is tested and both are covered. If either stops passing
    --registry, this says so."""
    units = pathlib.Path(__file__).resolve().parents[1] / "ops"
    for unit in ("whichports-probe.service", "whichports-probe-fast.service"):
        line = [l for l in (units / unit).read_text().splitlines() if l.startswith("ExecStart=")]
        assert len(line) == 1 and "app.prober_cli probe" in line[0] and "--registry" in line[0], unit


# ------------------------------------- the same thing by the other ways to probe

def test_one_vantage_named_by_hand_leaves_it_out_too(con, capsys):
    """`probe --via`, which stores through the same function."""
    plans = three_servers(con)
    far = DeletesWhileMeasuring(con, "probe1", OTHER_V4, "middle")
    code = prober_cli._probe_via(con, plans, "root@" + PROBE1_V4, vantage="probe1",
                                 transport=far)
    said = capsys.readouterr()
    assert code == 0, said.err
    assert "  not measured: " + dispatch.SERVER_DELETED in said.out
    assert "2 of 2 hosts measured" in said.out
    assert "1 server deleted during the pass: middle" in said.out
    assert measured_names(con) == ["first", "last"]


def test_a_probe_from_this_machine_leaves_it_out_too(con, capsys):
    """The path with no vantage, which opens the run's row before the first
    connect. The server goes while it is being measured."""
    plans = three_servers(con)
    state = {"done": False}

    async def connect(target, family, port):
        if target == OTHER_V4 and not state["done"]:
            state["done"] = True
            delete_server(con, "middle")
        return 0.002

    code = prober_cli._probe(con, plans, connect)
    said = capsys.readouterr()
    assert code == 0, said.err
    assert "middle: not measured: " + dispatch.SERVER_DELETED in said.out
    assert "2 hosts probed" in said.out
    assert measured_names(con) == ["first", "last"]


def test_a_scan_somebody_asked_for_is_cleared_when_its_server_goes(tmp_path, capsys):
    """Scan now, and the server is deleted while it is measured. The request
    went with the server, the drain says so and ends well."""
    import argparse
    from datetime import datetime, timezone
    from app import authz, db, scan, scan_cli
    from test_scan_cli_registry import enrol

    connection = db.connect(str(tmp_path / "cp.db"))
    for module in (db, authz, prober, scan, vantages):
        module.init(connection)
    try:
        host_id = enrol(connection, V4, name="box")
        vantages.add(connection, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
        assert scan.request_scan(connection, host_id, datetime.now(timezone.utc)).accepted
        far = DeletesWhileMeasuring(connection, "probe1", V4, "box")
        code = scan_cli.run(connection, argparse.Namespace(
            command="drain", vantage=None, via=None, registry=True,
            transport_factory=lambda destination: far))
        said = capsys.readouterr()
        assert code == 0, said.err
        assert "  not measured: " + dispatch.SERVER_DELETED in said.out
        assert "1 server deleted during the pass: box" in said.out
        assert scan.pending_requests(connection) == []
    finally:
        connection.close()
