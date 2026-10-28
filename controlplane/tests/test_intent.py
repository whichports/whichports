"""Tests for declared intent and acknowledgement.

    python -m pytest tests/test_intent.py

Written before `app/intent.py` and `app/intent_cli.py` existed and run red
first, which is the method `docs/RECORD.md` 4.46 and 4.52 argue for: a guard
nobody has tried to break is not evidence, and a green run is not evidence that
a test ran.

The mutations these are built to catch, in the order they matter:

  1. **Inventing a measurement.** A declaration is a thing a person typed and
     it is never evidence that anything reached anything. Every test that
     declares an intent on a port the outside view did not reach asserts the
     **state**, not the note and not the sentence, because `docs/RECORD.md`
     4.48 is the case where watching the reason and never the state let a real
     bug through, and this is the same seam.
  2. **Reading one address family's declaration as the other's.** A v4
     declaration says nothing about v6, at the store and again at the join.
  3. **Losing a declaration into the wrong host, protocol or port.** Every
     part of the key is tested by declaring one thing and asking for its
     neighbour.
  4. **Trusting what a person typed.** A host that does not exist, a port that
     is not a whole number, a family that is neither v4 nor v6 and a revoked
     host all have to be refused at the door rather than stored and puzzled
     over later.
  5. **Confusing intent with acknowledgement.** Acknowledging a finding may
     never change its state, and an acknowledgement stops applying the moment
     the state it was given for changes.
"""

import argparse
import json
import sqlite3

import pytest

from app import db, intent, intent_cli, join, prober, store

HOST = "almabox"
OTHER = "webbox"
TARGET = "203.0.113.5"


# --------------------------------------------------------------- the fixtures

@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    prober.init(connection)
    intent.init(connection)
    yield connection
    connection.close()


@pytest.fixture()
def bare(tmp_path):
    """A database the intent tables have never been created in.

    The join engine has to answer against this, because production held four
    tables the day the prober's two were added (`docs/RECORD.md` 4.52) and an
    engine that needs a migration before it can read is an engine that breaks
    on the box rather than in a test.
    """
    connection = db.connect(str(tmp_path / "bare.db"))
    db.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


def socket_row(port, family="v4", protocol="tcp", process="sshd",
               bind_address="0.0.0.0", pid=1):
    return {"protocol": protocol, "family": family, "bind_address": bind_address,
            "port": port, "process_name": process, "pid": pid}


def document(*, hostname=HOST, sockets=(), collected_at_unix=1_700_000_000):
    return {
        "schema_version": 1,
        "hostname": hostname,
        "collected_at_unix": collected_at_unix,
        "sockets": {"status": "collected", "listening": list(sockets)},
        "nftables": {"status": "collected", "tables": []},
    }


def add_host(con, name=HOST):
    host_id, _ = store.add_host(con, name)
    return host_id


def report(con, host_id, doc):
    store.insert_report(con, host_id, doc.get("collected_at_unix", 0),
                        doc.get("schema_version", 1), json.dumps(doc))


def probe_run(con, host_id, results, started_at="2026-08-16T12:00:00+00:00"):
    """One probe run, written the way `app/prober.py` writes one. Results are
    (family, port, state, reason, target) tuples."""
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, "test-vantage", started_at, started_at))
    run_id = cur.lastrowid
    for family, port, state, reason, target in results:
        con.execute(
            "INSERT INTO probe_results (run_id, target, family, port, state,"
            " reason, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, target, family, port, state, reason, started_at))
    con.commit()
    return run_id


def finding_for(result, protocol, port, family):
    for finding in result.findings:
        if (finding.protocol, finding.port, finding.family) == (protocol, port, family):
            return finding
    raise AssertionError(
        f"no finding for {protocol}/{port} {family} in "
        f"{[(f.protocol, f.port, f.family) for f in result.findings]}")


def reachable_host(con, port=22, family="v4"):
    """A host with one listening port that the outside view really reached.

    Every state above `_decide`'s line needs a completed connect, so this is
    the only shape in which `conflict` and `intended` can exist at all.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(port, family=family)]))
    probe_run(con, host_id,
              [(family, port, prober.STATE_CONNECTED, None, TARGET)])
    return host_id


# ================================================================== the storage

def test_init_is_idempotent(con):
    """Run twice on a database that already holds declarations, and both the
    tables and the rows survive. `db.init` and `authz.init` take the same
    additive shape."""
    add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.init(con)
    intent.init(con)
    assert len(intent.list_declarations(con)) == 1


def test_a_declaration_round_trips(con):
    add_host(con)
    result = intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    assert result.intent == intent.INTENT_OPEN
    assert result.host_name == HOST
    rows = intent.list_declarations(con)
    assert [(r["host_name"], r["protocol"], r["port"], r["family"], r["intent"])
            for r in rows] == [(HOST, "tcp", 443, "v4", intent.INTENT_OPEN)]


def test_a_declaration_for_a_host_that_does_not_exist_is_refused(con):
    """No host row, no declaration. Storing one against a name would leave a
    row nothing can ever join to a finding."""
    with pytest.raises(intent.IntentError):
        intent.declare(con, "nosuchbox", "tcp", 443, "v4", intent.INTENT_OPEN)
    assert intent.list_declarations(con) == []


def test_a_declaration_on_a_revoked_host_is_refused(con):
    """A revoked host's reports are refused by the ingest and its probe
    authorisations are refused by the gate, so nothing new will ever be
    measured for it. Declaring what you meant for it is a statement about a
    host that has stopped being watched."""
    add_host(con)
    store.revoke_host(con, HOST)
    with pytest.raises(intent.IntentError):
        intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    assert intent.list_declarations(con) == []


@pytest.mark.parametrize("port", ["443", 443.0, True, False, None, b"443"])
def test_a_port_that_is_not_a_whole_number_is_refused(con, port):
    """`True` is in this list on purpose. It is an `int` in Python, so an
    `isinstance(port, int)` check alone would store a declaration for port 1."""
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare(con, HOST, "tcp", port, "v4", intent.INTENT_OPEN)
    assert intent.list_declarations(con) == []


@pytest.mark.parametrize("port", [0, -1, 65536, 70000])
def test_a_port_outside_the_range_is_refused(con, port):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare(con, HOST, "tcp", port, "v4", intent.INTENT_OPEN)
    assert intent.list_declarations(con) == []


@pytest.mark.parametrize("port", [1, 65535])
def test_the_ends_of_the_port_range_are_accepted(con, port):
    add_host(con)
    intent.declare(con, HOST, "tcp", port, "v4", intent.INTENT_OPEN)
    assert len(intent.list_declarations(con)) == 1


@pytest.mark.parametrize("family", ["v5", "ipv4", "inet", "", None, 4])
def test_a_family_that_is_neither_v4_nor_v6_is_refused(con, family):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare(con, HOST, "tcp", 443, family, intent.INTENT_OPEN)
    assert intent.list_declarations(con) == []


@pytest.mark.parametrize("protocol", ["sctp", "icmp", "", None, 6])
def test_a_protocol_we_cannot_answer_for_is_refused(con, protocol):
    """The prober measures TCP and the document carries TCP and UDP. A
    declaration for anything else would sit beside a finding that can never
    exist."""
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare(con, HOST, protocol, 443, "v4", intent.INTENT_OPEN)
    assert intent.list_declarations(con) == []


@pytest.mark.parametrize("value", ["yes", "shut", "", None, True, "open closed"])
def test_a_value_that_is_not_one_of_the_two_words_is_refused(con, value):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare(con, HOST, "tcp", 443, "v4", value)
    assert intent.list_declarations(con) == []


def test_case_and_spacing_are_normalised_at_the_door(con):
    """`TCP` and `V4` are the same protocol and the same family as their lower
    case spellings, and storing both would make one port two rows."""
    host_id = add_host(con)
    intent.declare(con, f" {HOST} ", " TCP ", 443, " V4 ", " OPEN ")
    row = intent.list_declarations(con)[0]
    assert (row["protocol"], row["family"], row["intent"]) == ("tcp", "v4", "open")
    assert intent.intents_for_host(con, host_id) == {
        ("tcp", 443, "v4"): intent.INTENT_OPEN}


def test_declaring_twice_leaves_one_live_declaration(con):
    """The second word wins and the first is kept as history rather than
    overwritten, the same posture `hosts.revoked_at` takes."""
    add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)
    rows = intent.list_declarations(con)
    assert [r["intent"] for r in rows] == [intent.INTENT_CLOSED]
    total = con.execute("SELECT COUNT(*) FROM port_intents").fetchone()[0]
    assert total == 2


def test_two_live_declarations_for_one_port_cannot_be_written(con):
    """The unique index is the guard, not the code path above it. A second
    live row for the same key has to be impossible even for a caller writing
    SQL directly."""
    add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO port_intents (host_id, protocol, port, family, intent,"
            " account, declared_at) VALUES (1, 'tcp', 443, 'v4', 'closed',"
            " 'default', '2026-08-16T00:00:00+00:00')")


def test_a_v4_declaration_says_nothing_about_v6(con):
    host_id = add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)
    declared = intent.intents_for_host(con, host_id)
    assert declared[("tcp", 443, "v4")] == intent.INTENT_CLOSED
    assert ("tcp", 443, "v6") not in declared


def test_the_protocol_is_part_of_the_key(con):
    host_id = add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)
    declared = intent.intents_for_host(con, host_id)
    assert ("udp", 443, "v4") not in declared


def test_two_hosts_do_not_share_a_declaration(con):
    first = add_host(con, HOST)
    second = add_host(con, OTHER)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)
    assert intent.intents_for_host(con, first) == {("tcp", 443, "v4"): intent.INTENT_CLOSED}
    assert intent.intents_for_host(con, second) == {}


def test_clearing_removes_it_from_the_live_list_and_keeps_the_history(con):
    host_id = add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    assert intent.clear(con, HOST, "tcp", 443, "v4") is True
    assert intent.list_declarations(con) == []
    assert intent.intents_for_host(con, host_id) == {}
    total = con.execute("SELECT COUNT(*) FROM port_intents").fetchone()[0]
    assert total == 1


def test_clearing_one_that_was_never_set_reports_that_plainly(con):
    add_host(con)
    assert intent.clear(con, HOST, "tcp", 443, "v4") is False


def test_clearing_a_declaration_on_a_revoked_host_still_works(con):
    """Declaring on a revoked host is refused, so tidying one up afterwards
    must not be, or a declaration made before the revocation could never be
    withdrawn."""
    add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    store.revoke_host(con, HOST)
    assert intent.clear(con, HOST, "tcp", 443, "v4") is True


def test_clearing_validates_its_arguments_too(con):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.clear(con, HOST, "tcp", "443", "v4")
    with pytest.raises(intent.IntentError):
        intent.clear(con, HOST, "tcp", 443, "v5")


def test_listing_can_be_narrowed_to_one_host(con):
    add_host(con, HOST)
    add_host(con, OTHER)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.declare(con, OTHER, "tcp", 80, "v4", intent.INTENT_CLOSED)
    rows = intent.list_declarations(con, host_name=OTHER)
    assert [(r["host_name"], r["port"]) for r in rows] == [(OTHER, 80)]


def test_reads_against_a_database_without_the_tables_answer_empty(bare):
    """Not caught, asked. `join._table_exists` takes the same posture and for
    the same reason: an engine that needs a migration before it can read is an
    engine that breaks on the box."""
    assert intent.intents_for_host(bare, 1) == {}
    assert intent.acknowledgements_for_host(bare, 1) == {}
    assert intent.list_declarations(bare) == []


# ========================================================== the acknowledgement

def test_the_acknowledged_state_vocabulary_is_the_join_engines(con):
    """One vocabulary, two modules, pinned. `app/join.py` cannot import this
    module's caller and this module must not import the join engine, so the
    five words are written twice and this is what stops them drifting apart.
    `app/authz.py` pins its copy of `alerts._parse` the same way."""
    assert intent.STATES == join.STATES


def test_the_two_intent_words_are_the_join_engines(con):
    assert (intent.INTENT_OPEN, intent.INTENT_CLOSED) == (join.INTENT_OPEN,
                                                          join.INTENT_CLOSED)


def test_acknowledging_records_the_state_that_was_on_screen(con):
    host_id = add_host(con)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_UNREVIEWED)
    seen = intent.acknowledgements_for_host(con, host_id)
    assert seen[("tcp", 443, "v4")][0] == join.STATE_UNREVIEWED


@pytest.mark.parametrize("state", ["reviewed", "", None, "OK", "not tested"])
def test_acknowledging_a_state_that_is_not_one_of_the_five_is_refused(con, state):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.acknowledge(con, HOST, "tcp", 443, "v4", state)
    assert intent.list_acknowledgements(con) == []


def test_acknowledging_validates_the_port_and_the_family_too(con):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.acknowledge(con, HOST, "tcp", "443", "v4", join.STATE_UNREVIEWED)
    with pytest.raises(intent.IntentError):
        intent.acknowledge(con, HOST, "tcp", 443, "v5", join.STATE_UNREVIEWED)


def test_acknowledging_twice_leaves_one_live_row(con):
    add_host(con)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_UNREVIEWED)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_CONFLICT)
    rows = intent.list_acknowledgements(con)
    assert [r["state"] for r in rows] == [join.STATE_CONFLICT]
    total = con.execute("SELECT COUNT(*) FROM port_acknowledgements").fetchone()[0]
    assert total == 2


def test_two_live_acknowledgements_for_one_port_cannot_be_written(con):
    add_host(con)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_UNREVIEWED)
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO port_acknowledgements (host_id, protocol, port, family,"
            " state, account, acknowledged_at) VALUES (1, 'tcp', 443, 'v4',"
            " 'conflict', 'default', '2026-08-16T00:00:00+00:00')")


def test_clearing_an_acknowledgement_that_was_never_set_reports_that_plainly(con):
    add_host(con)
    assert intent.clear_acknowledgement(con, HOST, "tcp", 443, "v4") is False


def test_clearing_an_acknowledgement_keeps_the_history(con):
    host_id = add_host(con)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_UNREVIEWED)
    assert intent.clear_acknowledgement(con, HOST, "tcp", 443, "v4") is True
    assert intent.acknowledgements_for_host(con, host_id) == {}
    total = con.execute("SELECT COUNT(*) FROM port_acknowledgements").fetchone()[0]
    assert total == 1


def test_an_acknowledgement_and_a_declaration_are_independent(con):
    """Two tables, so clearing one cannot silently clear the other. That is the
    whole argument for keeping them apart."""
    host_id = add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_INTENDED)
    intent.clear(con, HOST, "tcp", 443, "v4")
    assert intent.intents_for_host(con, host_id) == {}
    assert ("tcp", 443, "v4") in intent.acknowledgements_for_host(con, host_id)


def test_an_acknowledgement_on_a_revoked_host_is_refused(con):
    add_host(con)
    store.revoke_host(con, HOST)
    with pytest.raises(intent.IntentError):
        intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_UNREVIEWED)


# ============================================================== the join wiring

def test_a_port_with_no_declaration_is_still_unreviewed(con):
    """The honest default, unchanged. A stored declaration nobody made must
    never become one."""
    host_id = reachable_host(con)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.intent is None
    assert join.NOTE_NO_INTENT_DECLARED in finding.cause.notes


def test_a_stored_closed_declaration_makes_a_reachable_port_a_conflict(con):
    """The point of the whole change: `conflict` is reachable from storage,
    with no caller passing an argument."""
    host_id = reachable_host(con)
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_CONFLICT
    assert finding.intent == intent.INTENT_CLOSED
    assert finding.outside.state == prober.STATE_CONNECTED
    assert join.NOTE_NO_INTENT_DECLARED not in finding.cause.notes


def test_a_stored_open_declaration_makes_a_reachable_port_intended(con):
    host_id = reachable_host(con)
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_OPEN)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_INTENDED
    assert finding.intent == intent.INTENT_OPEN
    assert finding.outside.state == prober.STATE_CONNECTED


def test_a_declaration_invents_no_state_where_nothing_was_measured(con):
    """The rule that outranks the rest of this file. A person declaring a port
    open is not a measurement, so a port the prober never touched keeps no
    state at all, and the outside view still says it was not tested."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_OPEN)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state is None
    assert finding.outside.state == prober.STATE_NOT_TESTED
    assert finding.intent == intent.INTENT_OPEN


def test_a_declaration_beside_a_measured_silence_makes_it_a_conflict(con):
    """The state this whole feature exists to produce.

    The port is listening, the operator says it should be open, and the outside
    view measured that nothing answers. That is reality and declared intent
    disagreeing, which is what `conflict` means.

    **This test replaces one that pinned the opposite**, written while the
    question was still open and carrying a docstring saying it would pass
    whichever way the card went. It would not have: the decision (RECORD 4.55)
    was precisely that a declaration changes this case. A test that claims to
    be decision-agnostic and is not is worse than one that picks a side, because
    nobody rereads it when the decision lands.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(2019)]))
    probe_run(con, host_id, [("v4", 2019, prober.STATE_NO_RESPONSE,
                              "timeout_expired", TARGET)])
    before = finding_for(join.host_findings(con, host_id), "tcp", 2019, "v4")
    assert before.state == join.STATE_NOT_REACHABLE, "nothing declared yet"

    intent.declare(con, HOST, "tcp", 2019, "v4", intent.INTENT_OPEN)
    after = finding_for(join.host_findings(con, host_id), "tcp", 2019, "v4")
    assert after.state == join.STATE_CONFLICT
    assert after.intent == intent.INTENT_OPEN
    assert after.outside.state == prober.STATE_NO_RESPONSE


def test_a_declaration_changes_nothing_where_nothing_was_measured(con):
    """The half that did not change, and the one that matters more. With no
    probe result the outside view is `not tested`, and no declaration may
    conjure a state out of it, because there is no reality to disagree with.
    """
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(2019)]))
    before = finding_for(join.host_findings(con, host_id), "tcp", 2019, "v4").state
    intent.declare(con, HOST, "tcp", 2019, "v4", intent.INTENT_OPEN)
    after = finding_for(join.host_findings(con, host_id), "tcp", 2019, "v4")
    assert before is None and after.state is None, (
        "a declaration produced a state with nothing measured to compare it to")
    assert after.intent == intent.INTENT_OPEN
    assert after.outside.state == prober.STATE_NOT_TESTED


def test_a_v4_declaration_does_not_reach_the_v6_finding(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, family="v4"),
                                           socket_row(443, family="v6",
                                                      bind_address="2001:db8::1")]))
    probe_run(con, host_id, [
        ("v4", 443, prober.STATE_CONNECTED, None, TARGET),
        ("v6", 443, prober.STATE_CONNECTED, None, "2001:db8::1")])
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)

    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 443, "v4").state == join.STATE_CONFLICT
    v6 = finding_for(result, "tcp", 443, "v6")
    assert v6.state == join.STATE_UNREVIEWED
    assert v6.intent is None


def test_one_hosts_declaration_does_not_reach_another_host(con):
    first = reachable_host(con)
    second = add_host(con, OTHER)
    report(con, second, document(hostname=OTHER, sockets=[socket_row(22)]))
    probe_run(con, second, [("v4", 22, prober.STATE_CONNECTED, None, TARGET)])
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)

    assert finding_for(join.host_findings(con, first), "tcp", 22, "v4").state \
        == join.STATE_CONFLICT
    assert finding_for(join.host_findings(con, second), "tcp", 22, "v4").state \
        == join.STATE_UNREVIEWED


def test_a_cleared_declaration_returns_the_port_to_unreviewed(con):
    host_id = reachable_host(con)
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    intent.clear(con, HOST, "tcp", 22, "v4")
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.intent is None


def test_an_explicit_intent_argument_still_wins(con):
    """The argument is how a caller asks a what-if question, and an empty
    mapping means no declarations rather than read them from the database.
    `tests/test_join.py` depends on this and so does anything that wants the
    engine to answer about data it was handed."""
    host_id = reachable_host(con)
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    empty = finding_for(join.host_findings(con, host_id, intent={}), "tcp", 22, "v4")
    assert empty.state == join.STATE_UNREVIEWED
    given = finding_for(
        join.host_findings(con, host_id,
                           intent={("tcp", 22, "v4"): join.INTENT_OPEN}),
        "tcp", 22, "v4")
    assert given.state == join.STATE_INTENDED


def test_fleet_findings_reads_each_hosts_own_declarations(con):
    first = reachable_host(con)
    second = add_host(con, OTHER)
    report(con, second, document(hostname=OTHER, sockets=[socket_row(22)]))
    probe_run(con, second, [("v4", 22, prober.STATE_CONNECTED, None, TARGET)])
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    intent.declare(con, OTHER, "tcp", 22, "v4", intent.INTENT_OPEN)

    states = {result.host_name: finding_for(result, "tcp", 22, "v4").state
              for result in join.fleet_findings(con)}
    assert states == {HOST: join.STATE_CONFLICT, OTHER: join.STATE_INTENDED}


def test_the_join_engine_answers_without_the_intent_tables(bare):
    """The engine is deployed before any migration runs, so it has to read a
    database that has never seen `intent.init`."""
    host_id = add_host(bare)
    report(bare, host_id, document(sockets=[socket_row(22)]))
    probe_run(bare, host_id, [("v4", 22, prober.STATE_CONNECTED, None, TARGET)])
    finding = finding_for(join.host_findings(bare, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_UNREVIEWED
    assert finding.acknowledged is None


def test_a_declared_port_is_on_the_screen_as_not_tested_until_measured(con):
    """A declaration used to raise no finding, on the reasoning that a candidate
    port comes from something a view observed. A port added under Probing on
    the server's settings is a declaration, and the owner, 2026-09-08, expected
    it on the overview and in the evidence (`docs/RECORD.md` 4.155). So it
    is a finding with no state, which every screen shows as not tested, until
    the prober, whose joined port set already takes declarations, measures it
    (record 4.155)."""
    host_id = reachable_host(con)
    intent.declare(con, HOST, "tcp", 9999, "v4", intent.INTENT_CLOSED)
    found = {(f.protocol, f.port, f.family): f
             for f in join.host_findings(con, host_id).findings}
    assert ("tcp", 9999, "v4") in found
    assert found[("tcp", 9999, "v4")].state is None
    assert found[("tcp", 9999, "v4")].intent == intent.INTENT_CLOSED


# --------------------------------------------- the acknowledgement at the join

def test_an_acknowledgement_shows_on_the_finding_and_leaves_the_state_alone(con):
    host_id = reachable_host(con)
    before = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    intent.acknowledge(con, HOST, "tcp", 22, "v4", join.STATE_UNREVIEWED)
    after = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert after.state == before.state == join.STATE_UNREVIEWED
    assert before.acknowledged is None
    assert after.acknowledged is not None


def test_an_acknowledgement_stops_applying_when_the_state_changes(con):
    """You acknowledged a finding, not a port. Declaring the port closed turns
    `unreviewed` into `conflict`, which is a different finding, and it goes
    back on the list."""
    host_id = reachable_host(con)
    intent.acknowledge(con, HOST, "tcp", 22, "v4", join.STATE_UNREVIEWED)
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state == join.STATE_CONFLICT
    assert finding.acknowledged is None


def test_an_acknowledgement_never_reaches_a_port_with_no_state(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    intent.acknowledge(con, HOST, "tcp", 22, "v4", join.STATE_UNREVIEWED)
    finding = finding_for(join.host_findings(con, host_id), "tcp", 22, "v4")
    assert finding.state is None
    assert finding.acknowledged is None


def test_an_acknowledgement_does_not_cross_the_address_family(con):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(443, family="v4"),
                                           socket_row(443, family="v6",
                                                      bind_address="2001:db8::1")]))
    probe_run(con, host_id, [
        ("v4", 443, prober.STATE_CONNECTED, None, TARGET),
        ("v6", 443, prober.STATE_CONNECTED, None, "2001:db8::1")])
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_UNREVIEWED)
    result = join.host_findings(con, host_id)
    assert finding_for(result, "tcp", 443, "v4").acknowledged is not None
    assert finding_for(result, "tcp", 443, "v6").acknowledged is None


def test_the_sentence_says_a_finding_was_acknowledged_without_a_banned_word(con):
    """The writing rules, the same list `tests/test_join.py` pins."""
    banned = ("secure", "protected", "safe", "compliant", "guaranteed",
              "certified", "vulnerable", "risk", "score", "grade")
    host_id = reachable_host(con)
    intent.acknowledge(con, HOST, "tcp", 22, "v4", join.STATE_UNREVIEWED)
    sentence = join.describe(
        finding_for(join.host_findings(con, host_id), "tcp", 22, "v4"))
    lowered = sentence.lower()
    for word in banned:
        assert word not in lowered, f"{word!r} in {sentence!r}"
    assert "—" not in sentence and "–" not in sentence and ";" not in sentence
    assert "not acting" in lowered


# ====================================================================== the CLI

def run(con, **fields):
    return intent_cli.run(con, argparse.Namespace(**fields))


def test_cli_declares_lists_and_clears(con, capsys):
    add_host(con)
    assert run(con, command="declare", host=HOST, protocol="tcp", port=443,
               family="v4", value="open") == 0
    assert run(con, command="list", host=None) == 0
    listed = capsys.readouterr().out
    assert HOST in listed and "443" in listed and "open" in listed

    assert run(con, command="clear", host=HOST, protocol="tcp", port=443,
               family="v4") == 0
    assert run(con, command="list", host=None) == 0
    assert "nothing" in capsys.readouterr().out.lower()


def test_cli_refuses_an_unknown_host_and_says_so(con, capsys):
    assert run(con, command="declare", host="nosuchbox", protocol="tcp",
               port=443, family="v4", value="open") == 1
    assert "nosuchbox" in capsys.readouterr().err


def test_cli_refuses_a_family_it_does_not_answer_for(con, capsys):
    add_host(con)
    assert run(con, command="declare", host=HOST, protocol="tcp", port=443,
               family="v5", value="open") == 1
    assert intent.list_declarations(con) == []


def test_cli_clearing_one_that_was_never_set_is_not_reported_as_done(con, capsys):
    add_host(con)
    assert run(con, command="clear", host=HOST, protocol="tcp", port=443,
               family="v4") == 1
    assert "nothing" in capsys.readouterr().err.lower()


def test_cli_acknowledge_takes_the_state_from_the_engine(con, capsys):
    host_id = reachable_host(con)
    assert run(con, command="acknowledge", host=HOST, protocol="tcp", port=22,
               family="v4") == 0
    seen = intent.acknowledgements_for_host(con, host_id)
    assert seen[("tcp", 22, "v4")][0] == join.STATE_UNREVIEWED
    assert join.STATE_UNREVIEWED in capsys.readouterr().out


def test_cli_acknowledge_refuses_a_port_with_no_state(con, capsys):
    """Nothing was concluded about this port, so there is no finding to
    acknowledge, and inventing one to store would be the exact failure this
    engine exists to prevent."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    assert run(con, command="acknowledge", host=HOST, protocol="tcp", port=22,
               family="v4") == 1
    assert intent.list_acknowledgements(con) == []
    assert "no state" in capsys.readouterr().err.lower()


def test_cli_acknowledge_refuses_a_port_that_has_no_finding_at_all(con, capsys):
    host_id = reachable_host(con)
    assert run(con, command="acknowledge", host=HOST, protocol="tcp", port=9999,
               family="v4") == 1
    assert intent.list_acknowledgements(con) == []


def test_cli_list_says_when_an_acknowledgement_has_lapsed(con, capsys):
    """The listing is the store's contents, and an acknowledgement in it may
    no longer apply. Printing only what was acknowledged would let a stale one
    read as live, which is the finding hiding itself."""
    reachable_host(con)
    run(con, command="acknowledge", host=HOST, protocol="tcp", port=22,
        family="v4")
    capsys.readouterr()
    run(con, command="list", host=None)
    assert "still applies" in capsys.readouterr().out

    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    run(con, command="list", host=None)
    listed = capsys.readouterr().out
    assert "lapsed" in listed and join.STATE_CONFLICT in listed


def test_cli_list_says_when_an_acknowledged_port_has_no_state_at_all(con, capsys):
    host_id = add_host(con)
    report(con, host_id, document(sockets=[socket_row(22)]))
    intent.acknowledge(con, HOST, "tcp", 22, "v4", join.STATE_UNREVIEWED)
    run(con, command="list", host=None)
    assert "no state now" in capsys.readouterr().out


def test_cli_unacknowledge_clears_it(con):
    host_id = reachable_host(con)
    run(con, command="acknowledge", host=HOST, protocol="tcp", port=22,
        family="v4")
    assert run(con, command="unacknowledge", host=HOST, protocol="tcp", port=22,
               family="v4") == 0
    assert intent.acknowledgements_for_host(con, host_id) == {}


def test_cli_parser_refuses_a_port_that_is_not_a_number():
    """argparse is the outer door and it closes first. `--` free text never
    reaches the store."""
    with pytest.raises(SystemExit):
        intent_cli.parse_args(["declare", HOST, "tcp", "http", "v4", "open"])


def test_cli_parser_refuses_a_value_that_is_not_one_of_the_two_words():
    with pytest.raises(SystemExit):
        intent_cli.parse_args(["declare", HOST, "tcp", "443", "v4", "maybe"])


def test_cli_parser_accepts_the_documented_shape():
    args = intent_cli.parse_args(["declare", HOST, "tcp", "443", "v4", "closed"])
    assert (args.command, args.host, args.protocol, args.port, args.family,
            args.value) == ("declare", HOST, "tcp", 443, "v4", "closed")


# ------------------- both families present at once, which is where v4/v6 bites
#
# The family tests above each declare ONE family and assert the other is
# absent. That cannot fail when the family filter is broken, because the key
# comes from the row's own family column and not from the WHERE clause. Every
# one of the five `AND family = ?` filters in app/intent.py was mutated to
# `AND (family = ? OR 1=1)` on 2026-08-16 and the whole suite stayed green.
#
# v4 and v6 conflation is this project's signature failure. docs/RECORD.md
# section 5 lists "cloud firewalls often cover IPv4 only" as the worst thing it
# ever published, and PRODUCT.md 4b rule 3 makes the two separate throughout.
# So these put both families in the table at the same time, with different
# values, which is the only arrangement in which a broken filter can be seen.

def _declare_both(con, port=443, v4=None, v6=None):
    if v4 is not None:
        intent.declare(con, HOST, "tcp", port, "v4", v4)
    if v6 is not None:
        intent.declare(con, HOST, "tcp", port, "v6", v6)


def test_two_families_on_one_port_keep_their_own_declarations(con):
    host_id = add_host(con)
    _declare_both(con, 443, v4=intent.INTENT_CLOSED, v6=intent.INTENT_OPEN)
    declared = intent.intents_for_host(con, host_id)
    assert declared[("tcp", 443, "v4")] == intent.INTENT_CLOSED
    assert declared[("tcp", 443, "v6")] == intent.INTENT_OPEN


def test_declaring_one_family_does_not_withdraw_the_other(con):
    """`declare` clears and inserts in one transaction. If its clear is not
    bound to the family, declaring v6 silently withdraws v4."""
    host_id = add_host(con)
    _declare_both(con, 443, v4=intent.INTENT_CLOSED)
    intent.declare(con, HOST, "tcp", 443, "v6", intent.INTENT_OPEN)
    declared = intent.intents_for_host(con, host_id)
    assert declared.get(("tcp", 443, "v4")) == intent.INTENT_CLOSED, (
        "declaring v6 withdrew the v4 declaration")
    assert declared.get(("tcp", 443, "v6")) == intent.INTENT_OPEN


def test_redeclaring_one_family_leaves_the_other_alone(con):
    host_id = add_host(con)
    _declare_both(con, 443, v4=intent.INTENT_CLOSED, v6=intent.INTENT_OPEN)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_OPEN)
    declared = intent.intents_for_host(con, host_id)
    assert declared[("tcp", 443, "v4")] == intent.INTENT_OPEN
    assert declared[("tcp", 443, "v6")] == intent.INTENT_OPEN, (
        "redeclaring v4 changed v6")


def test_clearing_one_family_leaves_the_other_declared(con):
    host_id = add_host(con)
    _declare_both(con, 443, v4=intent.INTENT_CLOSED, v6=intent.INTENT_OPEN)
    assert intent.clear(con, HOST, "tcp", 443, "v4") is True
    declared = intent.intents_for_host(con, host_id)
    assert ("tcp", 443, "v4") not in declared
    assert declared[("tcp", 443, "v6")] == intent.INTENT_OPEN, (
        "clearing v4 also cleared v6")


def test_acknowledging_one_family_leaves_the_other_unacknowledged(con):
    host_id = add_host(con)
    _declare_both(con, 443, v4=intent.INTENT_CLOSED, v6=intent.INTENT_CLOSED)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_CONFLICT)
    acked = intent.acknowledgements_for_host(con, host_id)
    assert ("tcp", 443, "v4") in acked
    assert ("tcp", 443, "v6") not in acked, (
        "acknowledging v4 acknowledged v6 as well")


def test_clearing_one_familys_acknowledgement_leaves_the_other(con):
    host_id = add_host(con)
    _declare_both(con, 443, v4=intent.INTENT_CLOSED, v6=intent.INTENT_CLOSED)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_CONFLICT)
    intent.acknowledge(con, HOST, "tcp", 443, "v6", join.STATE_CONFLICT)
    assert intent.clear_acknowledgement(con, HOST, "tcp", 443, "v4") is True
    acked = intent.acknowledgements_for_host(con, host_id)
    assert ("tcp", 443, "v4") not in acked
    assert ("tcp", 443, "v6") in acked, "clearing v4's acknowledgement cleared v6's"


def test_the_previous_value_reported_is_this_familys_and_not_the_other_ones(con):
    """`previous` is what the operator is told they are changing, and the CLI
    prints it. With both families declared and the family filter broken, a
    first-ever v6 declaration reports the v4 value as its previous, so the
    operator is told they overwrote something they never set.

    This is the only one of the five family filters that no other test here
    reaches, because the stored rows come out right either way. What is wrong
    is only the sentence said about them, which is still a wrong sentence.
    """
    add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)
    first_v6 = intent.declare(con, HOST, "tcp", 443, "v6", intent.INTENT_OPEN)
    assert first_v6.previous is None, (
        f"a first v6 declaration reported {first_v6.previous!r} as its previous"
        " value, which is the v4 declaration")


def test_the_previous_acknowledgement_reported_is_this_familys(con):
    """The same seam on the acknowledgement table."""
    add_host(con)
    intent.declare(con, HOST, "tcp", 443, "v4", intent.INTENT_CLOSED)
    intent.declare(con, HOST, "tcp", 443, "v6", intent.INTENT_CLOSED)
    intent.acknowledge(con, HOST, "tcp", 443, "v4", join.STATE_CONFLICT)
    first_v6 = intent.acknowledge(con, HOST, "tcp", 443, "v6", join.STATE_CONFLICT)
    assert first_v6.previous is None, (
        "a first v6 acknowledgement reported the v4 one as its previous")


# ============================================================== declared names
#
# What the operator calls the service on a port (docs/RECORD.md 4.64, the owner's
# own suggestion). The mutations these exist to catch: a name changing a state,
# a name being lowercased or edited on the way in, a name for one port or one
# host leaking onto another, and a database from before the table refusing to
# answer.

def test_a_name_round_trips(con):
    host_id = add_host(con)
    result = intent.declare_name(con, HOST, "tcp", 22, "ssh")
    assert result.name == "ssh" and result.previous is None
    assert intent.names_for_host(con, host_id) == {("tcp", 22): "ssh"}


def test_a_name_keeps_its_case_and_loses_its_surrounding_spaces(con):
    """A name is the operator's own words. `_word` lowercases and a name must
    not go through it, or `Caddy` comes back as somebody else's spelling."""
    host_id = add_host(con)
    intent.declare_name(con, HOST, "tcp", 443, "  Caddy for the app  ")
    assert intent.names_for_host(con, host_id) == {
        ("tcp", 443): "Caddy for the app"}


def test_naming_twice_leaves_one_live_name_and_reports_the_previous(con):
    host_id = add_host(con)
    intent.declare_name(con, HOST, "tcp", 22, "ssh")
    second = intent.declare_name(con, HOST, "tcp", 22, "openssh")
    assert second.previous == "ssh"
    assert intent.names_for_host(con, host_id) == {("tcp", 22): "openssh"}
    assert len(intent.list_names(con)) == 1


def test_two_live_names_for_one_port_cannot_be_written(con):
    """The partial unique index holds against SQL written by hand, the same
    guarantee the intent table gives."""
    host_id = add_host(con)
    intent.declare_name(con, HOST, "tcp", 22, "ssh")
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO port_names (host_id, protocol, port, name, account,"
            " declared_at) VALUES (?, 'tcp', 22, 'other', 'default', 'now')",
            (host_id,))


def test_clearing_a_name_removes_it_from_the_live_list_and_keeps_history(con):
    host_id = add_host(con)
    intent.declare_name(con, HOST, "tcp", 22, "ssh")
    assert intent.clear_name(con, HOST, "tcp", 22) is True
    assert intent.names_for_host(con, host_id) == {}
    assert intent.list_names(con) == []
    kept = con.execute("SELECT name, cleared_at FROM port_names").fetchall()
    assert len(kept) == 1 and kept[0]["cleared_at"] is not None


def test_clearing_a_name_that_was_never_set_reports_that_plainly(con):
    add_host(con)
    assert intent.clear_name(con, HOST, "tcp", 22) is False


def test_a_name_on_a_port_with_no_listener_is_stored_and_raises_no_finding(con):
    """Naming needs no listener: the name is for the next document as much as
    for this one. And a name is a thing a person typed, so it puts no port on
    the screen, the same rule a declaration follows."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[]))
    intent.declare_name(con, HOST, "tcp", 8080, "the staging app")
    assert intent.names_for_host(con, host_id) == {("tcp", 8080): "the staging app"}
    result = join.host_findings(con, host_id)
    assert result.findings == (), "a name alone put a port on the screen"


def test_a_name_with_a_control_character_is_refused(con):
    add_host(con)
    for bad in ("ssh\nd", "ssh\td", "ssh\x00", "ssh\x1b[31m", "\x7f"):
        with pytest.raises(intent.IntentError):
            intent.declare_name(con, HOST, "tcp", 22, bad)
    assert intent.list_names(con) == []


def test_a_name_at_the_length_bound_is_kept_and_one_past_it_is_refused(con):
    host_id = add_host(con)
    longest = "n" * intent.MAX_NAME_LENGTH
    intent.declare_name(con, HOST, "tcp", 22, longest)
    assert intent.names_for_host(con, host_id) == {("tcp", 22): longest}
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, HOST, "tcp", 23, "n" * (intent.MAX_NAME_LENGTH + 1))


@pytest.mark.parametrize("value", ["", "   ", None, 7, True, ["ssh"]])
def test_a_name_that_is_not_plain_text_is_refused(con, value):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, HOST, "tcp", 22, value)


def test_naming_validates_the_protocol_and_the_port(con):
    add_host(con)
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, HOST, "icmp", 22, "ssh")
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, HOST, "tcp", 0, "ssh")
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, HOST, "tcp", True, "ssh")


def test_naming_a_host_that_does_not_exist_is_refused(con):
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, "nosuchbox", "tcp", 22, "ssh")


def test_naming_a_revoked_host_is_refused_and_clearing_still_works(con):
    add_host(con)
    intent.declare_name(con, HOST, "tcp", 22, "ssh")
    con.execute("UPDATE hosts SET revoked_at = ? WHERE name = ?",
                (store.now_utc(), HOST))
    con.commit()
    with pytest.raises(intent.IntentError):
        intent.declare_name(con, HOST, "tcp", 22, "ssh again")
    assert intent.clear_name(con, HOST, "tcp", 22) is True


def test_the_protocol_is_part_of_a_names_key(con):
    host_id = add_host(con)
    intent.declare_name(con, HOST, "tcp", 53, "dns over tcp")
    intent.declare_name(con, HOST, "udp", 53, "dns")
    named = intent.names_for_host(con, host_id)
    assert named[("tcp", 53)] == "dns over tcp"
    assert named[("udp", 53)] == "dns"


def test_two_hosts_do_not_share_a_name(con):
    host_id = add_host(con)
    other_id = add_host(con, OTHER)
    intent.declare_name(con, HOST, "tcp", 22, "ssh on almabox")
    assert intent.names_for_host(con, other_id) == {}
    assert intent.names_for_host(con, host_id) == {("tcp", 22): "ssh on almabox"}


def test_name_reads_against_a_database_without_the_table_answer_empty(bare):
    """Production ran before this table existed and must keep working without
    a migration step, the same rule the intent tables follow."""
    host_id, _ = store.add_host(bare, HOST)
    assert intent.names_for_host(bare, host_id) == {}
    assert intent.list_names(bare) == []


def test_the_join_engine_answers_without_the_names_table(bare):
    host_id, _ = store.add_host(bare, HOST)
    report(bare, host_id, document(sockets=[socket_row(22)]))
    result = join.host_findings(bare, host_id)
    assert finding_for(result, "tcp", 22, "v4").declared_name is None


def test_a_name_reaches_the_finding_on_both_families_and_changes_no_state(con):
    """One name serves v4 and v6, because it names the service and not an
    address. And a name is never evidence: the state with a name is the state
    without one, asserted on the state per this file's rule 1."""
    host_id = add_host(con)
    report(con, host_id, document(sockets=[
        socket_row(22, family="v4"),
        socket_row(22, family="v6", bind_address="::")]))
    probe_run(con, host_id, [("v4", 22, prober.STATE_CONNECTED, None, TARGET)])
    before = {(f.family): f.state for f in join.host_findings(con, host_id).findings}
    intent.declare_name(con, HOST, "tcp", 22, "ssh")
    result = join.host_findings(con, host_id)
    for family in ("v4", "v6"):
        finding = finding_for(result, "tcp", 22, family)
        assert finding.declared_name == "ssh"
        assert finding.state == before[family], "a name changed a state"


def test_the_sentence_says_the_name_was_yours_and_stays_clean(con):
    """`describe` may say the name only as something a person did. The same
    banned-word and punctuation pins as the acknowledgement sentence."""
    host_id = reachable_host(con)
    intent.declare_name(con, HOST, "tcp", 22, "ssh")
    sentence = join.describe(
        finding_for(join.host_findings(con, host_id), "tcp", 22, "v4"))
    assert "You named this port ssh." in sentence
    lowered = sentence.lower()
    for word in ("secure", "protected", "safe", "guaranteed", "certified"):
        assert word not in lowered, f"{word!r} in {sentence!r}"
    assert "—" not in sentence and "–" not in sentence and ";" not in sentence


def test_cli_names_lists_and_unnames(con, capsys):
    add_host(con)
    assert run(con, command="name", host=HOST, protocol="tcp", port=22,
               value="ssh") == 0
    assert run(con, command="list", host=None) == 0
    listed = capsys.readouterr().out
    assert "declared names:" in listed and "ssh" in listed

    assert run(con, command="unname", host=HOST, protocol="tcp", port=22) == 0
    assert run(con, command="list", host=None) == 0
    assert "declared names:" not in capsys.readouterr().out


def test_cli_naming_says_what_it_replaced(con, capsys):
    add_host(con)
    run(con, command="name", host=HOST, protocol="tcp", port=22, value="ssh")
    capsys.readouterr()
    assert run(con, command="name", host=HOST, protocol="tcp", port=22,
               value="openssh") == 0
    out = capsys.readouterr().out
    assert "named openssh" in out and "was named ssh before this" in out


def test_cli_unnaming_one_that_was_never_set_is_not_reported_as_done(con, capsys):
    add_host(con)
    assert run(con, command="unname", host=HOST, protocol="tcp", port=22) == 1
    assert "nothing" in capsys.readouterr().err.lower()


def test_cli_refuses_a_name_with_a_control_character_and_says_so(con, capsys):
    add_host(con)
    assert run(con, command="name", host=HOST, protocol="tcp", port=22,
               value="ssh\x1b[31m") == 1
    assert "cannot record that" in capsys.readouterr().err
    assert intent.list_names(con) == []


def test_cli_parser_accepts_the_documented_name_shape():
    args = intent_cli.parse_args(["name", HOST, "tcp", "22", "caddy for the app"])
    assert (args.command, args.host, args.protocol, args.port, args.value) == (
        "name", HOST, "tcp", 22, "caddy for the app")


def test_cli_parser_takes_no_family_for_a_name():
    """A name is keyed without a family, so a family in the argv is refused
    rather than silently read as the name."""
    with pytest.raises(SystemExit):
        intent_cli.parse_args(["unname", HOST, "tcp", "22", "v4"])
