"""Findings for a host that has no agent (RECORD 4.104, part 2). The inside
view abstains, the outside view and the declaration decide, no layer is ever
named, and the two states that assert something about the inside of a host
can never arise."""
import pytest

from app import db, intent, join, prober, store

V4 = "185.199.108.153"


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "j.db"))
    db.init(c)
    prober.init(c)
    intent.init(c)
    yield c
    c.close()


def probe_run(con, host_id, results, started_at="2026-08-26T12:00:00+00:00"):
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, "test-vantage", started_at, started_at))
    for family, port, state, reason in results:
        con.execute(
            "INSERT INTO probe_results (run_id, target, family, port, state,"
            " reason, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (cur.lastrowid, V4, family, port, state, reason, started_at))
    con.commit()


def one(result, port, family="v4"):
    hits = [f for f in result.findings if (f.port, f.family) == (port, family)]
    assert len(hits) == 1, [(f.port, f.family) for f in result.findings]
    return hits[0]


def test_an_address_host_with_nothing_measured_has_no_findings_and_no_document(con):
    host_id = store.add_address_host(con, "outside-only")
    result = join.host_findings(con, host_id)
    assert result.kind == db.HOST_KIND_ADDRESS
    assert result.document_readable is True, "nothing failed to read, there was nothing to read"
    assert result.received_at is None and result.hostname is None
    assert result.findings == ()


def test_a_measured_port_gets_a_state_from_the_declaration_alone(con):
    host_id = store.add_address_host(con, "outside-only")
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(con, "outside-only", "tcp", 22, "v4", intent.INTENT_CLOSED)
    probe_run(con, host_id, [("v4", 443, prober.STATE_CONNECTED, None),
                             ("v4", 22, prober.STATE_CONNECTED, None),
                             ("v4", 8080, prober.STATE_CONNECTED, None)])
    result = join.host_findings(con, host_id)
    assert one(result, 443).state == join.STATE_INTENDED
    assert one(result, 22).state == join.STATE_CONFLICT
    assert one(result, 8080).state == join.STATE_UNREVIEWED


def test_a_measured_silence_earns_the_same_rules_inverted(con):
    """The declared pair inverts and the undeclared one has a word of its own.
    `not reachable` since 2026-08-28 (RECORD 4.112). An address host is held
    to exactly the rules an agent host is held to here, because the word is
    about what was measured and not about how much of the host could be read.

    Read against the test above it: the same three ports, the same two
    declarations, and only the measurement differs. Every state flips.
    """
    host_id = store.add_address_host(con, "outside-only")
    intent.declare(con, "outside-only", "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(con, "outside-only", "tcp", 22, "v4", intent.INTENT_CLOSED)
    silent = prober.STATE_NO_RESPONSE
    probe_run(con, host_id, [("v4", 443, silent, None), ("v4", 22, silent, None),
                             ("v4", 8080, silent, None)])
    result = join.host_findings(con, host_id)
    assert one(result, 443).state == join.STATE_CONFLICT
    assert one(result, 22).state == join.STATE_INTENDED
    assert one(result, 8080).state == join.STATE_NOT_REACHABLE


def test_no_layer_is_named_and_nothing_is_quoted(con):
    host_id = store.add_address_host(con, "outside-only")
    probe_run(con, host_id, [("v4", 8080, prober.STATE_CONNECTED, None)])
    finding = one(join.host_findings(con, host_id), 8080)
    assert finding.cause.layer == join.LAYER_NOT_DETERMINED
    assert finding.cause.quotes == ()
    assert finding.inside.absent is True
    assert finding.rate_limited is False


def test_the_two_inside_states_can_never_arise(con):
    """stale rule and unexplained both assert something about the inside of
    the host. With no agent there is no inside to assert about."""
    host_id = store.add_address_host(con, "outside-only")
    probe_run(con, host_id, [("v4", 8080, prober.STATE_CONNECTED, None),
                             ("v4", 9090, prober.STATE_NO_RESPONSE, None)])
    states = {f.state for f in join.host_findings(con, host_id).findings}
    assert join.STATE_STALE_RULE not in states
    assert join.STATE_UNEXPLAINED not in states


def test_the_notes_say_no_agent_and_never_that_a_read_failed(con):
    host_id = store.add_address_host(con, "outside-only")
    probe_run(con, host_id, [("v4", 8080, prober.STATE_CONNECTED, None)])
    notes = one(join.host_findings(con, host_id), 8080).cause.notes
    assert join.NOTE_NO_AGENT in notes
    for wrong in (join.NOTE_SOCKETS_NOT_READ, join.NOTE_HOST_FIREWALL_NOT_READ,
                  join.NOTE_OUTSIDE_AGE_UNREADABLE, join.NOTE_NOTHING_ON_THE_HOST_OWNS_IT):
        assert wrong not in notes


def test_a_port_nobody_probed_has_no_state_and_says_so(con):
    host_id = store.add_address_host(con, "outside-only")
    # a provider-named port with no measurement is a candidate without an answer
    probe_run(con, host_id, [("v4", 443, prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)])
    finding = one(join.host_findings(con, host_id), 443)
    assert finding.state is None
    assert join.NOTE_OUTSIDE_NOT_MEASURED in finding.cause.notes


def test_acknowledgements_and_names_read_as_on_any_host(con):
    host_id = store.add_address_host(con, "outside-only")
    probe_run(con, host_id, [("v4", 8080, prober.STATE_CONNECTED, None)])
    intent.declare_name(con, "outside-only", "tcp", 8080, "the shop")
    intent.acknowledge(con, "outside-only", "tcp", 8080, "v4", state=join.STATE_UNREVIEWED)
    finding = one(join.host_findings(con, host_id), 8080)
    assert finding.declared_name == "the shop"
    assert finding.acknowledged is not None


def test_the_fleet_walk_includes_address_hosts(con):
    a = store.add_address_host(con, "outside-only")
    store.add_host(con, "box")
    probe_run(con, a, [("v4", 8080, prober.STATE_CONNECTED, None)])
    names = {h.host_name: h.kind for h in join.fleet_findings(con)}
    assert names == {"outside-only": db.HOST_KIND_ADDRESS, "box": db.HOST_KIND_AGENT}
