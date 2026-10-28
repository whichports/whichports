"""The command that drives the connect engine.

    python -m pytest tests/test_prober_cli.py

The engine's own suite is `tests/test_prober.py` and it owns the packet. This
file owns the two questions the command adds:

  - **what would be probed**, derived from the host documents already stored,
    and nothing else. A document that cannot be read yields nothing rather
    than a guess, and a host that never reported is named rather than skipped
  - **that the command adds no second path to a packet.** It asks the gate
    through `authz.may_probe` and it sends through `app.prober` and there is
    no third way. The dry run sends nothing at all, and a test proves it by
    handing the command a primitive that fails if it is called

No test here connects to anything. Every run below is given an injected
connect primitive, so nothing in this file puts a packet on any network.
"""

import argparse
import ast
import asyncio
import json
import pathlib
import re
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, prober, prober_cli, store

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


# ------------------------------------------------------------- fake primitives

class FakeConnect:
    """Stands in for the connect primitive and records every call. The same
    shape `tests/test_prober.py` uses, kept here rather than imported so this
    file can be read on its own."""

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

    @property
    def ports(self):
        return [port for _target, _family, port in self.calls]


class RefusingConnect:
    """A primitive that must never be called, for every test whose point is
    that no packet leaves."""

    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port):
        self.calls.append((target, family, port))
        raise AssertionError(
            f"a packet was sent to {target} port {port} ({family}) and this"
            " test exists because it must not be")


# ------------------------------------------------------------------- documents

def socket_entry(bind, port, protocol="tcp", family=None):
    return {"protocol": protocol,
            "family": family if family is not None else ("v6" if ":" in bind else "v4"),
            "bind_address": bind, "port": port}


def document(sockets=(), containers=None, status="collected", **extra):
    doc = {"schema_version": 1, "hostname": "box", "collected_at_unix": 0,
           "sockets": {"status": status, "listening": list(sockets)}}
    if containers is not None:
        doc["containers"] = containers
    doc.update(extra)
    return json.dumps(doc)


def published(host_port, protocol="tcp", host_ip="0.0.0.0"):
    return {"protocol": protocol, "host_port": host_port, "host_ip": host_ip}


def add_host(con, name, document_text=None):
    """A host, with its latest document if it has one."""
    host_id, _ = store.add_host(con, name)
    if document_text is not None:
        store.insert_report(con, host_id, 0, 1, document_text)
    return host_id


def authorise(con, host_id, address, document_text, at=None):
    """Authorise an address the way a reporting agent does, which is the only
    proof that needs no network."""
    result = authz.record_agent_proof(con, host_id, address, document_text, now=at)
    assert result.recorded, result.reason


# ----------------------------------------------------------------- the command

class RefusingTlsRead:
    """A handshake that must never happen, for every test whose point is that
    no certificate is read."""

    def __init__(self):
        self.calls = []

    async def __call__(self, target, family, port, timeout):
        self.calls.append((target, family, port))
        raise AssertionError(
            f"a handshake was made with {target} port {port} ({family}) and"
            " this test exists because it must not be")


class FakeTlsRead:
    """Stands in for the handshake and hands back one certificate. The DER is
    the leaf `tests/test_prober_tls.py` made with openssl, imported rather than
    pasted a second time."""

    def __init__(self, answers=None):
        from tests.test_prober_tls import LEAF_SIGNED
        self.answers = answers or {}
        self.default = LEAF_SIGNED
        self.calls = []

    async def __call__(self, target, family, port, timeout):
        self.calls.append((target, family, port))
        answer = self.answers.get(port, self.default)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def probe_args(host=None, dry_run=False, tls_ports=None, vantage="test-vantage"):
    """A real run must name where it was taken from, so the shared helper
    names one. The tests that are about the vantage itself override it, and
    `_vantage_args` below builds the no-vantage case on purpose."""
    return argparse.Namespace(command="probe", host=host, dry_run=dry_run,
                              tls_ports=tls_ports, vantage=vantage)


def run_cli(con, args, connect=None, tls_read=None):
    return prober_cli.run(con, args, connect=connect or RefusingConnect(),
                          tls_read=tls_read or RefusingTlsRead())


def stored_runs(con):
    return con.execute("SELECT * FROM probe_runs ORDER BY id").fetchall()


def stored_results(con):
    return con.execute("SELECT * FROM probe_results ORDER BY id").fetchall()


def rows_by_port(con):
    return {(row["family"], row["port"]): row for row in stored_results(con)}


# ======================================================== deriving what to probe

def test_ports_come_from_the_tcp_sockets_the_document_reports():
    doc = json.loads(document([socket_entry("0.0.0.0", 22),
                               socket_entry("::", 443),
                               socket_entry("127.0.0.1", 8410)]))
    assert prober_cli.candidate_ports(doc) == [22, 443, 8410]


def test_a_container_publication_is_a_port_worth_probing():
    """A published container port is reachable from outside even when no host
    process binds it, which is the whole Docker finding this product leads
    with."""
    doc = json.loads(document(
        [socket_entry("0.0.0.0", 22)],
        containers={"status": "collected",
                    "podman": [{"name": "jellyfin", "ports": [published(8096)]}],
                    "docker": [{"name": "web", "ports": [published(8080)]}]}))
    assert prober_cli.candidate_ports(doc) == [22, 8080, 8096]


def test_udp_is_never_probed():
    """SI-7 and the engine both: this is a TCP connect prober. A UDP port in
    the document is not a TCP port and answering about it would be inventing a
    measurement."""
    doc = json.loads(document([socket_entry("0.0.0.0", 53, protocol="udp"),
                               socket_entry("0.0.0.0", 22)],
                              containers={"docker": [{"ports": [published(514, "udp")]}]}))
    assert prober_cli.candidate_ports(doc) == [22]


def test_a_port_bound_to_loopback_is_still_probed():
    """The bind address does not decide reachability, which is the sentence
    this product is sold on. A port bound to 127.0.0.1 that answers from
    outside is exactly the finding worth having, so the measurement decides
    rather than the document."""
    doc = json.loads(document([socket_entry("127.0.0.1", 8410)]))
    assert prober_cli.candidate_ports(doc) == [8410]


def test_a_port_that_is_not_an_integer_reaches_the_engine_rather_than_vanishing():
    """The engine has a typed reason for this exact case, so the port is
    passed through and recorded not tested rather than dropped between the
    document and the answer."""
    doc = json.loads(document([socket_entry("0.0.0.0", "22"),
                               socket_entry("0.0.0.0", None),
                               socket_entry("0.0.0.0", 70000),
                               socket_entry("0.0.0.0", 443)]))
    ports = prober_cli.candidate_ports(doc)
    assert ports[0] == 443
    assert "22" in ports and 70000 in ports


def test_true_is_not_port_one():
    """bool is an int in Python, and `True == 1`, so a document carrying both
    would lose one of them in the deduplication and nobody would see it go.

    Written this way because the one-value version of this test passed with
    the guard removed: `sorted({True})` is `[True]` either way, and the engine
    refuses a bool on its own account. The collision is where the guard earns
    its place, so the collision is what the test does.
    """
    doc = json.loads(document([socket_entry("0.0.0.0", 1),
                               socket_entry("0.0.0.0", True)]))
    ports = prober_cli.candidate_ports(doc)
    assert len(ports) == 2, ports
    assert ports[0] == 1 and ports[0] is not True
    assert ports[1] is True


def test_the_same_port_twice_is_one_port():
    doc = json.loads(document([socket_entry("0.0.0.0", 443),
                               socket_entry("::", 443)],
                              containers={"docker": [{"ports": [published(443)]}]}))
    assert prober_cli.candidate_ports(doc) == [443]


def test_a_document_with_no_sockets_yields_no_ports_and_no_targets():
    for doc in ({}, {"sockets": None}, {"sockets": {}},
                {"sockets": {"status": "denied", "listening": None}},
                {"sockets": {"listening": []}},
                {"sockets": {"listening": ["not a socket", 7]}}):
        assert prober_cli.candidate_ports(doc) == []
        assert prober_cli.candidate_targets(doc)[0] == []


def test_a_document_that_is_not_a_dict_yields_nothing():
    for doc in (None, [], "text", 7):
        assert prober_cli.candidate_ports(doc) == []
        assert prober_cli.candidate_targets(doc)[0] == []


# ------------------------------------------------------------------ addresses

def test_targets_are_the_globally_routable_addresses_the_document_reports():
    doc = json.loads(document([socket_entry(V4, 22), socket_entry(V6, 22)]))
    targets, refused = prober_cli.candidate_targets(doc)
    assert targets == [V4, V6]
    assert refused == []


def test_an_address_that_cannot_be_a_target_is_named_and_never_probed():
    """Private, loopback, wildcard, link-local and carrier-NAT. The last one
    matters most: 100.64.0.0/10 is shared between a carrier's customers, so
    probing it would probe a stranger."""
    not_targets = ["0.0.0.0", "::", "127.0.0.1", "::1", "10.0.0.5",
                   "192.168.1.10", "169.254.1.1", "100.64.3.4", "fe80::1"]
    doc = json.loads(document([socket_entry(a, 22) for a in not_targets]
                              + [socket_entry(V4, 22)]))
    targets, refused = prober_cli.candidate_targets(doc)
    assert targets == [V4]
    assert [text for text, _reason in refused] == not_targets


def test_an_address_the_gate_would_spell_differently_is_canonicalised():
    """The command probes the spelling the gate holds, never the spelling the
    document happens to use, because two spellings of one address is how a
    revocation misses."""
    doc = json.loads(document([socket_entry("2606:50c0:8000:0000::0153", 22,
                                            family="v6")]))
    targets, _refused = prober_cli.candidate_targets(doc)
    assert targets == [V6]


def test_the_family_comes_from_the_address_and_never_from_the_field_beside_it(
        con, capsys):
    """A document writes its own `family` field, and a v6 answer filed under
    v4 is the failure `docs/PRODUCT.md` 4b is a retraction of. The address
    decides, through the same function the gate uses."""
    add_host(con, "box", document([socket_entry(V6, 22, family="v4")]))
    run_cli(con, probe_args(dry_run=True))
    out = capsys.readouterr().out
    assert f"v6 {V6}" in out
    assert f"v4 {V6}" not in out


def test_one_address_reported_twice_is_one_target():
    doc = json.loads(document([socket_entry(V4, 22), socket_entry(V4, 443)]))
    assert prober_cli.candidate_targets(doc)[0] == [V4]


def test_a_bind_address_that_is_not_text_is_refused_rather_than_raising():
    doc = json.loads(document([{"protocol": "tcp", "family": "v4",
                                "bind_address": None, "port": 22},
                               {"protocol": "tcp", "family": "v4", "port": 22}]))
    targets, refused = prober_cli.candidate_targets(doc)
    assert targets == []
    assert len(refused) <= 1


# ==================================================================== planning

def test_a_host_that_never_reported_is_named_and_probes_nothing(con, capsys):
    add_host(con, "silent")
    assert run_cli(con, probe_args()) == 0
    out = capsys.readouterr().out
    assert "silent" in out and "never reported" in out
    assert stored_runs(con) == []


def test_a_document_that_is_not_json_probes_nothing_and_does_not_crash(con, capsys):
    add_host(con, "corrupt", "{not json at all")
    assert run_cli(con, probe_args()) == 0
    out = capsys.readouterr().out
    assert "corrupt" in out and "cannot be read" in out
    assert stored_runs(con) == []


def test_a_document_that_is_json_but_not_an_object_probes_nothing(con, capsys):
    add_host(con, "odd", json.dumps(["sockets"]))
    assert run_cli(con, probe_args()) == 0
    assert "cannot be read" in capsys.readouterr().out
    assert stored_runs(con) == []


def test_a_revoked_host_is_not_probed(con, capsys):
    host_id = add_host(con, "gone", document([socket_entry(V4, 22)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 22)]))
    store.revoke_host(con, "gone")
    assert run_cli(con, probe_args()) == 0
    assert "revoked" in capsys.readouterr().out
    assert stored_runs(con) == []


def test_the_latest_document_is_the_one_that_decides(con):
    """Documents are stored verbatim and never edited, so the newest one is
    the only one that says what the host is listening on now."""
    host_id = add_host(con, "box", document([socket_entry(V4, 22)]))
    store.insert_report(con, host_id, 1, 1,
                        document([socket_entry(V4, 443), socket_entry(V4, 8443)]))
    plan = prober_cli.plan_for(con, store.list_hosts(con)[0])
    assert plan.ports == (443, 8443)


# ================================================================== the dry run

def test_the_dry_run_sends_nothing_even_when_the_gate_says_yes(con, capsys):
    doc = document([socket_entry(V4, 22), socket_entry(V4, 443)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    refusing = RefusingConnect()
    assert prober_cli.run(con, probe_args(dry_run=True), connect=refusing) == 0
    assert refusing.calls == []


def test_the_dry_run_stores_no_run(con, capsys):
    doc = document([socket_entry(V4, 22)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    run_cli(con, probe_args(dry_run=True))
    assert stored_runs(con) == []
    assert stored_results(con) == []


def test_the_dry_run_prints_the_targets_the_ports_and_the_gate_answer(con, capsys):
    doc = document([socket_entry(V4, 22), socket_entry(V4, 443)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    run_cli(con, probe_args(dry_run=True))
    out = capsys.readouterr().out
    assert V4 in out
    assert "22" in out and "443" in out
    assert "yes" in out


def test_the_dry_run_says_no_for_an_address_nobody_proved(con, capsys):
    add_host(con, "box", document([socket_entry(V4, 22)]))
    run_cli(con, probe_args(dry_run=True))
    out = capsys.readouterr().out
    assert authz.NO_PROOF in out
    # The word itself, because "no" on its own appears in half these lines.
    assert "yes" not in out


def test_the_dry_run_answers_for_both_families(con, capsys):
    """A host with no v6 address gets told so, rather than the family simply
    not appearing."""
    add_host(con, "box", document([socket_entry(V4, 22)]))
    run_cli(con, probe_args(dry_run=True))
    out = capsys.readouterr().out
    assert "v4" in out and "v6" in out
    assert prober.REASON_NO_ADDRESS_IN_FAMILY in out


# ================================================================== the real run

def test_an_authorised_target_is_probed_and_the_run_is_stored(con, capsys):
    doc = document([socket_entry(V4, 22), socket_entry(V4, 443)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    connect = FakeConnect()
    assert prober_cli.run(con, probe_args(), connect=connect) == 0
    assert sorted(connect.ports) == [22, 443]

    runs = stored_runs(con)
    assert len(runs) == 1
    assert runs[0]["host_id"] == host_id
    assert runs[0]["finished_at"]
    assert runs[0]["vantage"]

    rows = rows_by_port(con)
    assert rows[("v4", 22)]["state"] == prober.STATE_CONNECTED
    assert rows[("v4", 443)]["state"] == prober.STATE_CONNECTED


def test_an_unauthorised_target_is_recorded_not_tested_and_never_skipped(con, capsys):
    """The refusal has to leave a record. A target that quietly disappears
    from the output is a target nobody can see was not measured."""
    add_host(con, "box", document([socket_entry(V4, 22), socket_entry(V4, 443)]))
    assert run_cli(con, probe_args()) == 0
    rows = rows_by_port(con)
    for port in (22, 443):
        assert rows[("v4", port)]["state"] == prober.STATE_NOT_TESTED
        assert rows[("v4", port)]["reason"] == prober.REASON_NO_AUTHORIZATION


def test_a_refused_target_never_carries_a_measured_state(con):
    """The accuracy rule at the level this command works at. Nothing it stores
    may read as a finding about a host we did not touch."""
    add_host(con, "box", document([socket_entry(V4, 22), socket_entry(V6, 22)]))
    run_cli(con, probe_args())
    for row in stored_results(con):
        assert row["state"] == prober.STATE_NOT_TESTED
        assert row["reason"] in prober.UNMEASURED_REASONS


def test_a_family_with_no_address_is_recorded_not_tested_for_every_port(con):
    doc = document([socket_entry(V4, 22), socket_entry(V4, 443)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    prober_cli.run(con, probe_args(), connect=FakeConnect())
    rows = rows_by_port(con)
    for port in (22, 443):
        assert rows[("v6", port)]["state"] == prober.STATE_NOT_TESTED
        assert rows[("v6", port)]["reason"] == prober.REASON_NO_ADDRESS_IN_FAMILY
        assert rows[("v6", port)]["target"] is None


def test_a_host_with_no_globally_routable_address_still_leaves_a_record(con, capsys):
    """almabox in the real database looks exactly like this: every socket is
    on a wildcard or a private address, so there is no target. The honest
    output is a stored run saying every port is not tested, never silence."""
    add_host(con, "home", document([socket_entry("0.0.0.0", 22),
                                    socket_entry("192.168.1.10", 445)]))
    assert run_cli(con, probe_args()) == 0
    rows = stored_results(con)
    assert len(rows) == 4  # two families, two ports
    assert {row["reason"] for row in rows} == {prober.REASON_NO_ADDRESS_IN_FAMILY}


def test_a_port_that_is_not_a_port_is_stored_with_its_own_reason(con):
    doc = document([socket_entry(V4, 22), socket_entry(V4, "22")])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    connect = FakeConnect()
    prober_cli.run(con, probe_args(), connect=connect)
    reasons = {row["reason"] for row in stored_results(con)}
    assert prober.REASON_PORT_NOT_AN_INTEGER in reasons
    assert connect.ports == [22]


def test_an_authorisation_revoked_mid_run_stops_the_packets(con):
    """The gate is asked again before every connect, and this proves the
    command did not cache the answer it got at the start."""
    ports = [22, 80, 443, 8080, 9090]
    doc = document([socket_entry(V4, port) for port in ports])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)

    class RevokingConnect(FakeConnect):
        async def __call__(self, target, family, port):
            authz.revoke(con, target)
            return await super().__call__(target, family, port)

    connect = RevokingConnect()
    assert prober_cli.run(con, probe_args(), connect=connect) == 0
    assert 0 < len(connect.calls) < len(ports)

    touched = set(connect.ports)
    for row in stored_results(con):
        if row["family"] == "v4" and row["port"] not in touched:
            assert row["state"] == prober.STATE_NOT_TESTED
            assert row["reason"] == prober.REASON_NO_AUTHORIZATION


def test_an_expired_authorisation_probes_nothing(con):
    doc = document([socket_entry(V4, 22)])
    host_id = add_host(con, "box", doc)
    long_ago = datetime.now(timezone.utc) - timedelta(seconds=authz.AGENT_TTL_SECONDS + 60)
    authorise(con, host_id, V4, doc, at=long_ago)
    assert run_cli(con, probe_args()) == 0
    rows = rows_by_port(con)
    assert rows[("v4", 22)]["state"] == prober.STATE_NOT_TESTED
    assert rows[("v4", 22)]["reason"] == prober.REASON_NO_AUTHORIZATION


def test_every_host_in_the_fleet_gets_its_own_run(con):
    for name in ("one", "two"):
        doc = document([socket_entry(V4, 22)])
        add_host(con, name, doc)
    assert run_cli(con, probe_args()) == 0
    runs = stored_runs(con)
    assert len(runs) == 2
    assert len({row["host_id"] for row in runs}) == 2


def test_one_host_can_be_named_and_the_others_are_left_alone(con):
    add_host(con, "one", document([socket_entry(V4, 22)]))
    two = add_host(con, "two", document([socket_entry(V4, 22)]))
    assert run_cli(con, probe_args(host="two")) == 0
    runs = stored_runs(con)
    assert len(runs) == 1 and runs[0]["host_id"] == two


def test_a_named_host_is_matched_whole_and_not_by_prefix(con):
    """Probing a host nobody asked for is sending packets nobody asked for."""
    box = add_host(con, "box", document([socket_entry(V4, 22)]))
    add_host(con, "box2", document([socket_entry(V4, 22)]))
    assert run_cli(con, probe_args(host="box")) == 0
    runs = stored_runs(con)
    assert len(runs) == 1 and runs[0]["host_id"] == box


# ==================================================================== exit codes

def test_a_closed_port_is_not_a_failure(con):
    """sweep_cli's reasoning: a unit that goes red because a server is down
    teaches everyone to ignore it. A refused connect is the prober working."""
    import errno as errno_module
    doc = document([socket_entry(V4, 22)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    connect = FakeConnect({22: OSError(errno_module.ECONNREFUSED, "refused")})
    assert prober_cli.run(con, probe_args(), connect=connect) == 0
    assert stored_results(con)[0]["state"] in (prober.STATE_REFUSED,
                                               prober.STATE_NO_RESPONSE)


def test_a_target_nobody_authorised_is_not_a_failure(con):
    add_host(con, "box", document([socket_entry(V4, 22)]))
    assert run_cli(con, probe_args()) == 0


def test_an_empty_fleet_says_so_and_succeeds(con, capsys):
    assert run_cli(con, probe_args()) == 0
    assert "no hosts" in capsys.readouterr().out


def test_a_host_name_nobody_enrolled_is_a_failure(con, capsys):
    add_host(con, "box", document([socket_entry(V4, 22)]))
    assert run_cli(con, probe_args(host="ghost")) == 1
    assert "ghost" in capsys.readouterr().err
    assert stored_runs(con) == []


def test_naming_a_revoked_host_is_a_failure(con, capsys):
    add_host(con, "gone", document([socket_entry(V4, 22)]))
    store.revoke_host(con, "gone")
    assert run_cli(con, probe_args(host="gone")) == 1
    assert stored_runs(con) == []


# =============================================== the last run, read back plainly

def test_the_last_run_can_be_read_back(con, capsys):
    doc = document([socket_entry(V4, 22)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    prober_cli.run(con, probe_args(), connect=FakeConnect())
    capsys.readouterr()
    assert prober_cli.run(con, argparse.Namespace(command="last", host=None)) == 0
    out = capsys.readouterr().out
    assert "box" in out and V4 in out and prober.STATE_CONNECTED in out


def test_a_host_with_no_run_says_so(con, capsys):
    add_host(con, "box", document([socket_entry(V4, 22)]))
    assert prober_cli.run(con, argparse.Namespace(command="last", host=None)) == 0
    assert "no run" in capsys.readouterr().out


# ============================================ the command adds no second path

SOURCE = pathlib.Path(prober_cli.__file__).read_text(encoding="utf-8")

SQL = re.compile(r"\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|CREATE TABLE)\b")


def test_the_scan_below_actually_reads_the_command():
    """A scan that reads nothing passes forever, which is `docs/RECORD.md`
    4.46. This is the canary for the two scans under it."""
    assert len(SOURCE) > 1000
    assert "def run(" in SOURCE
    assert SQL.search("con.execute('SELECT 1')")


def test_the_command_writes_no_sql_of_its_own():
    """Storage goes through the engine, which is the only thing that may write
    a run. A query here would be a second way for a row to exist, and the two
    would drift."""
    assert SQL.search(SOURCE) is None
    assert "probe_runs" not in SOURCE
    assert "probe_results" not in SOURCE


def _authz_uses():
    """Every name this command reaches for on the authorisation module, read
    from the syntax rather than from the text, so a mention in a comment is
    not the same as a call."""
    return {node.attr for node in ast.walk(ast.parse(SOURCE))
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "authz"}


def test_the_command_asks_the_gate_only_through_may_probe():
    """SI-6. `may_probe` is the only door, and this is the list of everything
    the command is allowed to reach for beside it. Adding to that list is a
    decision somebody has to take deliberately, which is the point.

      - `may_probe`         the gate, asked once per target for the dry run
      - `normalise_target`  the spelling and the family of an address, which
                            authorises nothing and is what the engine uses too
      - `TargetError`       what that raises for an address that can never be
                            a target
      - `init`              creating the tables if they are missing, the same
                            as every other command here
      - `account_for_host`  which workspace's account a host's targets are
                            asked about. It reads a column off a host row and
                            authorises nothing: what it can do is make the gate
                            answer about a narrower set of rows, never a wider
                            one, because an account with no proof for an
                            address is refused exactly like no proof at all
      - `DEFAULT_ACCOUNT`   the account a plan carries when nothing said
                            otherwise, which is workspace 1's
      - `live_addresses_for_host`
                            which addresses an address host already holds a
                            live proof for, read the way the gate reads them
                            (added 2026-08-26, RECORD 4.104). It is the source
                            of an agentless plan's targets the way a document
                            is an agent host's, and it authorises nothing: a
                            target it yields is still asked at `may_probe`
                            before every connect, and
                            test_prober_cli_addresses proves a proof revoked
                            after the plan was built is refused there

    The workspace names and the address reader were added deliberately, and
    this docstring is where those decisions are recorded. None of them can
    turn a no into a yes: they only decide which rows `may_probe` is asked
    about, and `may_probe` is still the only thing that answers.
    """
    assert _authz_uses() == {"may_probe", "normalise_target", "TargetError",
                             "init", "account_for_host", "DEFAULT_ACCOUNT",
                             "live_addresses_for_host"}


def test_the_command_opens_no_socket_of_its_own():
    """SI-7 and the engine's boundary: the only thing that may connect is
    `app.prober`."""
    for forbidden in ("import socket", "socket.socket", "ssl", "recv", "send("):
        assert forbidden not in SOURCE


def test_the_command_claims_nothing_about_anybody(con):
    """The writing rules. Not a word of this vocabulary belongs anywhere in
    the command, source or output."""
    for word in ("secure", "protected", "compliant", "guaranteed", "certified",
                 "vulnerable", "score", "grade"):
        assert not re.search(rf"\b{word}\b", SOURCE, re.IGNORECASE), word


def test_the_output_uses_the_engine_vocabulary_and_no_conclusions(con, capsys):
    """The four state names are the whole vocabulary and every one of them
    says what was observed. `open`, `closed` and `filtered` are judgements
    about a path this saw one end of."""
    doc = document([socket_entry(V4, 22), socket_entry(V4, 443)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    prober_cli.run(con, probe_args(dry_run=True), connect=RefusingConnect())
    prober_cli.run(con, probe_args(), connect=FakeConnect())
    out = capsys.readouterr().out
    for word in ("open", "closed", "filtered", "reachable", "secure", "safe"):
        assert not re.search(rf"\b{word}\b", out, re.IGNORECASE), word
    assert prober.STATE_CONNECTED in out


def test_the_output_carries_no_dashes_or_semicolons_in_its_prose(con, capsys):
    """The writing rules, checked on what a person actually sees rather than
    on the source."""
    doc = document([socket_entry(V4, 22)])
    host_id = add_host(con, "box", doc)
    authorise(con, host_id, V4, doc)
    prober_cli.run(con, probe_args(dry_run=True), connect=RefusingConnect())
    prober_cli.run(con, probe_args(), connect=FakeConnect())
    prober_cli.run(con, argparse.Namespace(command="last", host=None))
    out = capsys.readouterr().out
    assert "—" not in out and "–" not in out
    assert ";" not in out


# ==================================================================== the parser

def test_the_parser_offers_a_dry_run_and_a_named_host():
    parsed = prober_cli.parse_args(["probe", "--dry-run", "--host", "box"])
    assert parsed.command == "probe" and parsed.dry_run and parsed.host == "box"


def test_probing_the_whole_fleet_needs_no_flag():
    parsed = prober_cli.parse_args(["probe"])
    assert parsed.command == "probe" and parsed.host is None and not parsed.dry_run


def test_a_command_is_required():
    with pytest.raises(SystemExit):
        prober_cli.parse_args([])


def test_the_module_runs_end_to_end_against_a_real_file(tmp_path, monkeypatch,
                                                        capsys):
    """`main` opens its own connection and initialises what it uses, the same
    as every other CLI here. This is the only test that exercises that path."""
    path = tmp_path / "cp.db"
    monkeypatch.setenv(db.DB_ENV, str(path))
    setup = db.connect(str(path))
    db.init(setup)
    doc = document([socket_entry(V4, 22)])
    host_id, _ = store.add_host(setup, "box")
    store.insert_report(setup, host_id, 0, 1, doc)
    setup.close()

    assert prober_cli.main(["probe", "--dry-run"]) == 0
    assert "box" in capsys.readouterr().out


# ================================================= reading a certificate

def test_no_certificate_is_read_unless_a_port_was_named(con):
    """The default. A certificate read is a second connection, so it happens
    where it was asked for and nowhere else."""
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    tls_read = RefusingTlsRead()
    assert run_cli(con, probe_args(), connect=FakeConnect(),
                   tls_read=tls_read) == 0
    assert tls_read.calls == []
    assert con.execute("SELECT COUNT(*) c FROM probe_tls").fetchone()["c"] == 0


def test_a_named_port_is_read_and_the_certificate_is_printed(con, capsys):
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    tls_read = FakeTlsRead()
    assert run_cli(con, probe_args(tls_ports=[443]), connect=FakeConnect(),
                   tls_read=tls_read) == 0
    assert tls_read.calls == [(V4, "v4", 443)]
    out = capsys.readouterr().out
    assert "certificate_read" in out
    assert "CN=example.test" in out
    assert "1 certificates read" in out


def test_the_printed_certificate_never_calls_itself_valid(con, capsys):
    """The writing rules, at the one place a person actually reads."""
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    run_cli(con, probe_args(tls_ports=[443]), connect=FakeConnect(),
            tls_read=FakeTlsRead())
    out = capsys.readouterr().out.lower()
    for word in ("valid", "trusted", "secure", "safe", "expired", "compliant"):
        assert word not in out, f"the output says {word} about a certificate"


def test_the_dry_run_reads_no_certificate_even_with_a_port_named(con, capsys):
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    tls_read = RefusingTlsRead()
    assert run_cli(con, probe_args(dry_run=True, tls_ports=[443]),
                   tls_read=tls_read) == 0
    assert tls_read.calls == []
    out = capsys.readouterr().out
    assert "a certificate would be read from 443" in out
    assert "1 connects plus 1 handshakes" in out


def test_the_dry_run_says_when_a_named_port_is_not_in_the_document(con, capsys):
    """Rather than quietly doing nothing, which is a port nobody can see was
    not measured."""
    host_id = add_host(con, "box", document([socket_entry(V4, 22)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 22)]))
    run_cli(con, probe_args(dry_run=True, tls_ports=[443]))
    out = capsys.readouterr().out
    assert "port 443 was named for a certificate read" in out
    assert "nothing is read there" in out


def test_a_named_port_the_document_never_reported_reads_nothing(con):
    host_id = add_host(con, "box", document([socket_entry(V4, 22)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 22)]))
    tls_read = RefusingTlsRead()
    assert run_cli(con, probe_args(tls_ports=[443]), connect=FakeConnect(),
                   tls_read=tls_read) == 0
    assert tls_read.calls == []


def test_a_revoked_host_is_never_handshaked(con):
    """The same narrowing the connect half has. We withdrew the evidence, so we
    do not act on the document it came with."""
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    store.revoke_host(con, "box")
    tls_read = RefusingTlsRead()
    assert run_cli(con, probe_args(tls_ports=[443]), connect=FakeConnect(),
                   tls_read=tls_read) == 0
    assert tls_read.calls == []


def test_the_last_command_prints_the_certificate_that_was_stored(con, capsys):
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    run_cli(con, probe_args(tls_ports=[443]), connect=FakeConnect(),
            tls_read=FakeTlsRead())
    capsys.readouterr()
    assert prober_cli.run(con, argparse.Namespace(command="last", host=None)) == 0
    out = capsys.readouterr().out
    assert "CN=example.test" in out
    assert "certificate_read" in out


def test_a_certificate_that_could_not_be_read_still_prints_its_reason(con, capsys):
    import ssl
    host_id = add_host(con, "box", document([socket_entry(V4, 443)]))
    authorise(con, host_id, V4, document([socket_entry(V4, 443)]))
    failing = FakeTlsRead({443: ssl.SSLError(1, "[SSL: NO] the peer said no")})
    assert run_cli(con, probe_args(tls_ports=[443]), connect=FakeConnect(),
                   tls_read=failing) == 0
    out = capsys.readouterr().out
    assert prober.REASON_TLS_HANDSHAKE_FAILED in out
    assert "SSL:" not in out, "the far side's own words reached the terminal"


def test_the_parser_takes_a_repeatable_tls_port():
    parsed = prober_cli.parse_args(["probe", "--tls-port", "443",
                                    "--tls-port", "8443"])
    assert parsed.tls_ports == [443, 8443]


def test_the_parser_defaults_to_reading_no_certificate():
    assert prober_cli.parse_args(["probe"]).tls_ports is None


def test_the_parser_refuses_a_tls_port_that_is_not_a_number():
    with pytest.raises(SystemExit):
        prober_cli.parse_args(["probe", "--tls-port", "https"])


# ------------------------------------ a run has to say where it was taken from

def _one_authorised_host(con):
    doc = document([socket_entry(V4, 22)])
    host_id = add_host(con, "box1", doc)
    authorise(con, host_id, V4, doc)
    return host_id


def _vantage_args(vantage=None, dry_run=False):
    return probe_args(dry_run=dry_run, vantage=vantage)


def test_a_real_run_refuses_without_a_named_vantage(con, monkeypatch):
    """Measured on 2026-08-16: the first real probe run this project ever took
    stored `vantage = "unnamed"`, because `default_vantage` falls back to that
    string when the environment says nothing.

    docs/RECORD.md 4.53 states the rule this breaks, in the entry recording that
    very run: a reachability finding without a vantage point is not a finding.
    Where a connect was attempted from decides what its result means. The same
    port answers from one network and not another, which is the whole reason
    section 5c prices a second vantage point at all.

    So a run that would be stored refuses rather than inventing a name.
    """
    monkeypatch.delenv(prober.VANTAGE_ENV, raising=False)
    _one_authorised_host(con)
    code = prober_cli.run(con, _vantage_args(), connect=RefusingConnect())
    assert code != 0, "a run with no vantage was allowed to store results"
    assert stored_runs(con) == []


def test_the_dry_run_needs_no_vantage_because_it_stores_nothing(con, monkeypatch, capsys):
    """The refusal is about a stored measurement, not about looking. Somebody
    checking what would happen must not have to name a vantage first."""
    monkeypatch.delenv(prober.VANTAGE_ENV, raising=False)
    _one_authorised_host(con)
    assert prober_cli.run(con, _vantage_args(dry_run=True),
                          connect=RefusingConnect()) == 0
    assert "nothing is sent" in capsys.readouterr().out


def test_the_flag_names_the_vantage_and_it_is_what_gets_stored(con, monkeypatch):
    monkeypatch.delenv(prober.VANTAGE_ENV, raising=False)
    _one_authorised_host(con)
    prober_cli.run(con, _vantage_args("brussels-laptop"), connect=FakeConnect())
    assert {row["vantage"] for row in stored_runs(con)} == {"brussels-laptop"}


def test_the_environment_names_it_too_and_the_flag_wins(con, monkeypatch):
    """The env var is for a unit file, the flag is for a person at a terminal,
    and when both speak the person in front of it wins."""
    monkeypatch.setenv(prober.VANTAGE_ENV, "from-the-unit")
    _one_authorised_host(con)
    prober_cli.run(con, _vantage_args(), connect=FakeConnect())
    assert {row["vantage"] for row in stored_runs(con)} == {"from-the-unit"}
    prober_cli.run(con, _vantage_args("the-person"), connect=FakeConnect())
    assert "the-person" in {row["vantage"] for row in stored_runs(con)}


@pytest.mark.parametrize("bad", ["", "   ", "unnamed", "a" * 65, "has space",
                                 'quote"inside', "new\nline"])
def test_a_vantage_name_that_is_not_usable_is_refused_at_the_door(bad, con, monkeypatch):
    """The name is stored, printed, and will end up on the published list of
    addresses we probe from. It is restricted here rather than escaped in three
    places later, the posture store.NAME_RE takes for a host name. "unnamed" is
    refused by name, because it is the placeholder this change exists to stop.
    """
    monkeypatch.delenv(prober.VANTAGE_ENV, raising=False)
    _one_authorised_host(con)
    assert prober_cli.run(con, _vantage_args(bad), connect=RefusingConnect()) != 0
    assert stored_runs(con) == []


# ============================================================== the joined set
#
# The owner's decision, 2026-08-21, recorded in docs/RECORD.md 4.78. The port set
# is owned by `app/dispatch.py` and its own suite covers what goes in it. What
# is proved here is that the flag reaches it, that the plain form is unchanged,
# and that the dry run prints the set a real run would send.


def joined_args(**kwargs):
    args = probe_args(**kwargs)
    args.joined = True
    return args


def test_the_plain_form_still_offers_only_the_documents_ports(con):
    """The widening is opt in. A person asking what the document alone says
    still gets that answer."""
    from app import intent
    intent.init(con)
    doc = document([socket_entry(V4, 80)])
    host_id = add_host(con, "box", doc)
    intent.declare(con, "box", "tcp", 8443, "v4", intent.INTENT_OPEN)
    authorise(con, host_id, V4, doc)

    connect = FakeConnect()
    assert run_cli(con, probe_args(), connect=connect) == 0
    assert sorted(set(connect.ports)) == [80]


def test_the_joined_flag_widens_what_is_probed(con):
    from app import intent
    intent.init(con)
    doc = document([socket_entry(V4, 80)])
    host_id = add_host(con, "box", doc)
    intent.declare(con, "box", "tcp", 8443, "v4", intent.INTENT_OPEN)
    authorise(con, host_id, V4, doc)

    connect = FakeConnect()
    assert run_cli(con, joined_args(), connect=connect) == 0
    assert sorted(set(connect.ports)) == [80, 8443]


def test_the_joined_dry_run_prints_the_wider_set_and_sends_nothing(con, capsys):
    """The dry run is the mode a person runs first, so it has to show the set
    the real run would send rather than a narrower one."""
    from app import intent
    intent.init(con)
    doc = document([socket_entry(V4, 80)])
    host_id = add_host(con, "box", doc)
    intent.declare(con, "box", "tcp", 8443, "v4", intent.INTENT_OPEN)
    authorise(con, host_id, V4, doc)

    refusing = RefusingConnect()
    assert run_cli(con, joined_args(dry_run=True), connect=refusing) == 0
    assert refusing.calls == []
    out = capsys.readouterr().out
    assert "8443" in out
    assert "tcp ports (2)" in out


def test_a_host_that_derived_nothing_is_named_not_widened(con, capsys):
    """A host we know nothing about earns no invented port set."""
    from app import intent
    intent.init(con)
    add_host(con, "quiet")
    assert run_cli(con, joined_args(), connect=RefusingConnect()) == 0
    assert "has never reported" in capsys.readouterr().out


def test_the_cap_is_reported_on_stderr(con, capsys):
    """A pass that covered less than it was asked to says so where the output
    is read, rather than returning a shorter list quietly."""
    from app import dispatch, intent
    intent.init(con)
    many = [socket_entry(V4, port)
            for port in range(1, dispatch.MAX_JOINED_PORTS + 6)]
    doc = document(many)
    host_id = add_host(con, "many", doc)
    authorise(con, host_id, V4, doc)

    assert run_cli(con, joined_args(dry_run=True), connect=RefusingConnect()) == 0
    assert "capped at" in capsys.readouterr().err


def test_the_flag_parses_and_defaults_to_off(con):
    assert prober_cli.parse_args(["probe", "--joined"]).joined is True
    assert prober_cli.parse_args(["probe"]).joined is False


# ------------------------------------------------------------- workspaces
#
# The plan carries the gate's account for its host's workspace, because the
# plan is the only thing that reaches both the dry run and the dispatch. These
# say the account gets there and that it narrows the gate rather than widening
# it.


def test_a_plan_carries_its_hosts_workspace_account(con):
    second = db.create_workspace(con, "second")
    store.add_host(con, "mine", workspace_id=db.DEFAULT_WORKSPACE_ID)
    store.add_host(con, "theirs", workspace_id=second)
    plans = {host["name"]: prober_cli.plan_for(con, host)
             for host in store.list_hosts(con)}
    assert plans["mine"].account == authz.DEFAULT_ACCOUNT
    assert plans["theirs"].account == authz.account_for_workspace(second)


def test_a_plan_with_nothing_derived_still_carries_the_account(con):
    """A host that never reported produces a plan carrying a note. It still has
    to carry the right account, or a later run over the same row would ask the
    gate the wrong question."""
    second = db.create_workspace(con, "second")
    store.add_host(con, "quiet", workspace_id=second)
    plan = prober_cli.plan_for(con, store.list_hosts(con)[0])
    assert plan.derived is False
    assert plan.account == authz.account_for_workspace(second)


def test_the_dry_run_asks_the_gate_about_the_plans_own_workspace(con, capsys):
    """Workspace 2's host proved its address. The dry run for that host must be
    told yes, and a dry run over the same address in workspace 1 must be told
    no, which is what proves the account travelled rather than being ignored."""
    second = db.create_workspace(con, "second")
    host_id, _ = store.add_host(con, "theirs", workspace_id=second)
    # Bound to the address itself rather than the wildcard, because
    # `candidate_targets` derives what would be probed from bind addresses.
    document = json.dumps({
        "sockets": {"status": "ok", "listening": [
            {"protocol": "tcp", "family": "v4", "bind_address": V4,
             "port": 443}]},
        "interface_addresses": {"status": "collected", "addresses": [
            {"interface": "eth0", "family": "v4", "address": V4,
             "global": True}]}})
    store.insert_report(con, host_id, 0, 1, document)
    assert authz.record_agent_proof(con, host_id, V4, document).recorded is True

    theirs = prober_cli.plan_for(con, store.list_hosts(con)[0])
    prober_cli._dry_run(con, [theirs])
    assert " yes: " in capsys.readouterr().out

    from dataclasses import replace
    prober_cli._dry_run(con, [replace(theirs, account=authz.DEFAULT_ACCOUNT)])
    out = capsys.readouterr().out
    assert " no: " in out
    assert authz.NO_PROOF in out
