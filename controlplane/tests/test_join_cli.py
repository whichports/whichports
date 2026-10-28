"""The command that shows the findings.

    python -m pytest tests/test_join_cli.py

The join engine produces the answer this product exists to give, and until
this command there was no way for a person to see it: not on a screen, because
the renderer does not read findings yet, and not on a terminal, because nothing
called `fleet_findings` outside the tests.

So the tests that matter here are about honesty rather than formatting. The
command must not invent a word for a state the engine declined to give, must
not say a port is reachable, and must say "not tested" where nothing was
measured.
"""

import argparse
import json
import sqlite3

import pytest

from app import authz, db, intent, join, join_cli, prober, store

V4 = "185.199.108.153"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    prober.init(connection)
    intent.init(connection)
    yield connection
    connection.close()


def document(port=443, bind=V4):
    return json.dumps({
        "schema_version": 1, "collected_at_unix": 1, "hostname": "box1",
        "sockets": {"status": "collected", "listening": [
            {"protocol": "tcp", "port": port, "family": "v4",
             "bind_address": bind, "process_name": "caddy"}]},
    })


def add_host(con, name="box1", doc=None):
    host_id, _ = store.add_host(con, name)
    store.insert_report(con, host_id, 0, 1, doc if doc is not None else document())
    return host_id


def store_probe(con, host_id, port, state, target=V4, family="v4"):
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, "test-vantage", "2026-08-16T12:00:00+00:00",
                                 "2026-08-16T12:00:01+00:00"))
    con.execute(
        "INSERT INTO probe_results (run_id, target, family, port, state, reason,"
        " measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cur.lastrowid, target, family, port, state, None, "2026-08-16T12:00:00+00:00"))
    con.commit()


def run(con, **kw):
    args = argparse.Namespace(command="findings", host=None, all=False)
    for k, v in kw.items():
        setattr(args, k, v)
    return join_cli.run(con, args)


def test_a_reachable_port_is_shown_with_the_state_the_engine_gave(con, capsys):
    host_id = add_host(con)
    store_probe(con, host_id, 443, prober.STATE_CONNECTED)
    assert run(con) == 0
    out = capsys.readouterr().out
    assert "tcp/443" in out
    assert join.STATE_UNREVIEWED in out


def test_nothing_is_ever_called_reachable_or_secure(con, capsys):
    """The writing rules. The engine's own `describe` is held to this by
    tests/test_join.py, and this command must not add a word of its own."""
    host_id = add_host(con)
    store_probe(con, host_id, 443, prober.STATE_CONNECTED)
    run(con, all=True)
    out = capsys.readouterr().out.lower()
    for word in ("reachable", "unreachable", "secure", "protected", "safe",
                 "compliant", "guaranteed", "certified", "exposed", "vulnerable"):
        assert word not in out, f"the command said {word}"


def test_a_port_never_probed_says_not_tested(con, capsys):
    add_host(con)
    run(con, all=True)
    out = capsys.readouterr().out
    assert "not tested" in out.lower()


def test_a_state_the_engine_declined_to_give_is_not_invented(con, capsys):
    """Wherever `_decide` declines to name a state, this command shows the
    views and leaves the column empty rather than filling it with a word of its
    own. Naming states is the engine's job, and a formatter that invented one
    would be making a product decision somewhere nobody would look for it.

    **Pointed at `not_tested` deliberately.** The first version of this test
    used a port measured as silent, which had no state when it was written and
    was given one hours later by RECORD 4.55. `not_tested` is the case that
    cannot be given a state without breaking the accuracy rule itself, so it is
    the stable place to pin this. If that ever changes, something much larger
    is wrong.
    """
    add_host(con)          # a document, and no probe result at all
    run(con, all=True)
    out = capsys.readouterr().out
    assert "not tested" in out.lower()
    for word in join.STATES:
        assert word not in out, (
            f"the command printed the state {word!r} for a port nobody probed")


def test_the_vantage_is_named_because_a_result_without_one_means_nothing(con, capsys):
    """RECORD 4.53 and PRODUCT 5e. Where a connect was attempted from decides
    what its result means, so a listing that shows results without naming the
    vantage is showing half a fact."""
    host_id = add_host(con)
    store_probe(con, host_id, 443, prober.STATE_CONNECTED)
    run(con)
    assert "test-vantage" in capsys.readouterr().out


def test_a_host_that_was_never_probed_says_so_rather_than_showing_nothing(con, capsys):
    add_host(con)
    run(con)
    out = capsys.readouterr().out.lower()
    assert "box1" in out
    assert "never" in out or "not tested" in out


def store_run(con, host_id, port, state, started_at, vantage, target=V4,
              family="v4"):
    """One probe run at a chosen time and vantage, so a two-lane header can be
    exercised. `store_probe` fixes both and cannot show which run the header
    reads."""
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, ?, ?, ?)", (host_id, vantage, started_at, started_at))
    con.execute(
        "INSERT INTO probe_results (run_id, target, family, port, state, reason,"
        " measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (cur.lastrowid, target, family, port, state, None, started_at))
    con.commit()


def test_the_header_names_the_most_recent_measurement_across_runs(con, capsys):
    """The header has no single run behind it any more, because two lanes can
    each measure some of a host's ports. It names the most recently measured
    port's time and vantage, so a stale broad-sweep run does not hide a fresh
    fast-lane one."""
    host_id = add_host(con)
    store_run(con, host_id, 9100, prober.STATE_CONNECTED,
              "2026-08-16T09:00:00+00:00", "sweep")
    store_run(con, host_id, 443, prober.STATE_CONNECTED,
              "2026-08-16T12:00:00+00:00", "fast")
    run(con, all=True)
    out = capsys.readouterr().out
    assert "fast" in out
    assert "2026-08-16T12:00:00+00:00" in out


def test_one_host_can_be_asked_for_by_name(con, capsys):
    add_host(con, "box1")
    add_host(con, "box2", document(port=22))
    run(con, host="box2", all=True)
    out = capsys.readouterr().out
    assert "box2" in out and "box1" not in out


def test_an_unknown_host_is_an_error_rather_than_an_empty_listing(con, capsys):
    add_host(con)
    assert run(con, host="nosuch") != 0


def test_a_revoked_host_is_not_listed(con, capsys):
    host_id = add_host(con)
    store.revoke_host(con, "box1")
    run(con, all=True)
    assert "box1" not in capsys.readouterr().out


def test_an_empty_fleet_says_so_and_exits_zero(con, capsys):
    assert run(con) == 0
    assert "no hosts" in capsys.readouterr().out.lower()


def test_a_declared_intent_is_shown_next_to_the_state(con, capsys):
    """`conflict` is the finding this product exists for, and it only exists
    once somebody has declared what they meant. The listing has to show both,
    or a reader cannot tell why the state is what it is."""
    host_id = add_host(con)
    store_probe(con, host_id, 443, prober.STATE_CONNECTED)
    intent.declare(con, "box1", "tcp", 443, "v4", intent.INTENT_CLOSED)
    run(con)
    out = capsys.readouterr().out
    assert join.STATE_CONFLICT in out
    assert intent.INTENT_CLOSED in out


def test_the_default_listing_leaves_out_what_needs_nobody(con, capsys):
    """A fleet listing that prints every port on every family in both
    directions is the wall of text the owner rejected in RECORD 4.49. The default
    shows what a person has to look at, and --all shows the rest."""
    host_id = add_host(con)
    store_probe(con, host_id, 443, prober.STATE_CONNECTED)
    intent.declare(con, "box1", "tcp", 443, "v4", intent.INTENT_OPEN)
    run(con)
    quiet = capsys.readouterr().out
    run(con, all=True)
    loud = capsys.readouterr().out
    assert len(loud) > len(quiet)
    assert join.STATE_INTENDED in loud
