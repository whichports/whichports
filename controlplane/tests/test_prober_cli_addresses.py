"""An address host is probed on what its operator proved and declared, never
on a document, because it has none (RECORD 4.104, part 2). The review of the
plan such a host gets, and of the two ways it honestly gets none."""
import argparse
import json

import pytest

from app import authz, db, dispatch, intent, prober, prober_cli, store

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    intent.init(connection)
    yield connection
    connection.close()


class FakeConnect:
    def __init__(self, answers=None, default=0.002):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    async def __call__(self, target, family, port):
        self.calls.append((target, family, port))
        answer = self.answers.get(port, self.default)
        if isinstance(answer, BaseException):
            raise answer
        return answer


class RefusingConnect:
    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port):
        raise AssertionError(f"a packet was sent to {target} port {port} and must not be")


class RefusingTlsRead:
    async def __call__(self, target, family, port, timeout):
        raise AssertionError("a handshake was made and must not be")


def probe_args(host=None, dry_run=False, joined=True, changed=False):
    return argparse.Namespace(command="probe", host=host, dry_run=dry_run,
                              tls_ports=None, vantage="test-vantage",
                              joined=joined, changed=changed)


def run_cli(con, args, connect=None):
    return prober_cli.run(con, args, connect=connect or RefusingConnect(),
                          tls_read=RefusingTlsRead())


def prove(con, host_id, address, now=None):
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN,
                                  host_id=host_id, now=now)
    result = authz.verify_proof(con, challenge.id, now=now,
                                fetcher=lambda url, timeout=0: challenge.token)
    assert result.recorded, result.reason


def host_row(con, name):
    return store.active_host_by_name(con, name)


# ------------------------------------------------------------------ the plan

def test_an_address_host_with_no_proof_carries_a_note_and_sends_nothing(con, capsys):
    store.add_address_host(con, "outside-only")
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert not plan.derived and plan.note == prober_cli.NOTE_NO_PROVED_ADDRESS
    assert plan.agentless
    assert run_cli(con, probe_args()) == 0
    assert "no address proved" in capsys.readouterr().out
    assert con.execute("SELECT COUNT(*) FROM probe_runs").fetchone()[0] == 0


def test_a_proved_address_with_no_port_carries_the_other_note(con, capsys):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert not plan.derived and plan.note == prober_cli.NOTE_NO_PORT_DECLARED
    assert plan.targets == (V4,)
    assert run_cli(con, probe_args()) == 0
    assert "no port declared" in capsys.readouterr().out


def test_the_plan_is_the_proved_addresses_and_the_declared_ports(con):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    prove(con, host_id, V6)
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(con, "outside-only", "tcp", 22, "v4", intent.INTENT_CLOSED)
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert plan.derived and plan.agentless and plan.joined
    assert set(plan.targets) == {V4, V6}
    assert plan.ports == (22, 443)
    assert plan.not_targets == ()
    # already the joined set, so widening it again changes nothing
    assert prober_cli._with_joined_ports(con, plan) == plan


def test_an_expired_or_revoked_proof_leaves_the_plan_without_that_address(con):
    host_id = store.add_address_host(con, "outside-only")
    now = authz._now()
    prove(con, host_id, V4, now=now)
    prove(con, host_id, V6, now=now)
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    authz.revoke(con, V6)
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert plan.targets == (V4,)


def test_a_previously_measured_port_stays_in_the_plan_after_its_declaration_goes(con):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    intent.declare(con, "outside-only", "tcp", 8080, "v4", intent.INTENT_OPEN)
    assert run_cli(con, probe_args(), connect=FakeConnect()) == 0
    intent.clear(con, "outside-only", "tcp", 8080, "v4")
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert plan.ports == (8080,), "the measured port is a port somebody cares about"


def test_the_plan_carries_the_hosts_workspace_account(con):
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'two', 't')")
    con.commit()
    host_id = store.add_address_host(con, "theirs", workspace_id=2)
    prove(con, host_id, V4, now=None)
    plan = prober_cli.plan_for(con, host_row(con, "theirs"))
    assert plan.account == authz.account_for_workspace(2)


# --------------------------------------------------------------- a real pass

def test_a_real_pass_probes_the_declared_ports_on_the_proved_addresses(con):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(con, "outside-only", "tcp", 22, "v6", intent.INTENT_CLOSED)
    connect = FakeConnect()
    assert run_cli(con, probe_args(), connect=connect) == 0
    assert sorted(connect.calls) == [(V4, "v4", 22), (V4, "v4", 443)]
    rows = con.execute("SELECT family, port, state, reason FROM probe_results"
                       " ORDER BY family, port").fetchall()
    states = {(r["family"], r["port"]): (r["state"], r["reason"]) for r in rows}
    assert states[("v4", 22)][0] == prober.STATE_CONNECTED
    assert states[("v4", 443)][0] == prober.STATE_CONNECTED
    # no v6 address was proved, so the v6 half says not tested rather than guessing
    assert states[("v6", 22)] == (prober.STATE_NOT_TESTED, prober.REASON_NO_ADDRESS_IN_FAMILY)
    assert states[("v6", 443)] == (prober.STATE_NOT_TESTED, prober.REASON_NO_ADDRESS_IN_FAMILY)


def test_the_gate_still_refuses_an_address_whose_proof_lapsed_mid_way(con):
    """The plan was built while the proof was live; the gate is asked again
    before every connect, and this is the second question saying no."""
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert plan.derived
    authz.revoke(con, V4)
    connect = FakeConnect()
    assert prober_cli._probe(con, [plan], connect, None, (), "test-vantage") == 0
    assert connect.calls == []
    row = con.execute("SELECT state, reason FROM probe_results WHERE port = 443"
                      " AND family = 'v4'").fetchone()
    assert (row["state"], row["reason"]) == (prober.STATE_NOT_TESTED,
                                              prober.REASON_NO_AUTHORIZATION)


def test_the_changed_lane_reprobes_when_a_proof_or_declaration_moves(con):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    assert run_cli(con, probe_args(), connect=FakeConnect()) == 0
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert not dispatch.needs_reprobe(con, plan, set(plan.ports))
    intent.declare(con, "outside-only", "tcp", 8443, "v4", intent.INTENT_OPEN)
    plan = prober_cli.plan_for(con, host_row(con, "outside-only"))
    assert dispatch.needs_reprobe(con, plan, set(plan.ports))


def test_the_dry_run_says_proved_rather_than_in_the_document(con, capsys):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, V4)
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    assert run_cli(con, probe_args(dry_run=True)) == 0
    out = capsys.readouterr().out
    assert f"v4 {V4}  yes" in out
    assert "v6 no address proved" in out
    assert "in the document" not in out


def test_an_agent_host_is_planned_exactly_as_before(con):
    host_id, _ = store.add_host(con, "box")
    doc = {"schema_version": 1, "hostname": "box", "collected_at_unix": 0,
           "sockets": {"status": "collected", "listening": [
               {"protocol": "tcp", "family": "v4", "bind_address": V4, "port": 22}]}}
    store.insert_report(con, host_id, 0, 1, json.dumps(doc))
    plan = prober_cli.plan_for(con, host_row(con, "box"))
    assert plan.derived and not plan.agentless and not plan.joined
    assert plan.targets == (V4,) and plan.ports == (22,)
