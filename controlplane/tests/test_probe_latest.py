"""probe_latest: the newest result per port, address and vantage, kept by the
database itself, so a page load reads a few dozen rows and not every probe
result a server ever had.

Measured on production on 2026-09-20 (docs/RECORD.md 4.192): one page of
workspace 1 took 2.9 seconds, 85% of it in `join._probe_index` reading
476,000 rows to keep 100 of them, per load, growing with every pass. The same
query is the one that blinded the dashboard for seventeen days (4.183).

The table is kept by a trigger on `probe_results`, so every writer keeps it
right, the tests that write rows by hand included. What these hold is that it
can never give the engine a different answer than reading every row does.
"""

import random
import sqlite3

import pytest

from app import db, join, prober, store

FAMILIES = ("v4", "v6")
STATES = (prober.STATE_CONNECTED, "no_response", "refused")


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    prober.init(connection)
    yield connection
    connection.close()


def a_run(con, host_id, vantage, at):
    cur = con.execute("INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
                      " VALUES (?, ?, ?, ?)", (host_id, vantage, at, at))
    return cur.lastrowid


def a_result(con, run_id, family, port, target, state, measured_at):
    con.execute(
        "INSERT INTO probe_results (run_id, target, family, port, state, reason,"
        " connect_ms, os_errno, measured_at) VALUES (?, ?, ?, ?, ?, 'r', NULL, NULL, ?)",
        (run_id, target, family, port, state, measured_at))


def stamp(minute, micro=0):
    return f"2026-09-20T{10 + minute // 60:02d}:{minute % 60:02d}:00.{micro:06d}+00:00"


def both_ways(con, host_id):
    fast = join._probe_index(con, host_id)
    slow = join._probe_index(con, host_id, every_row=True)
    return fast, slow


def test_one_result_is_the_latest(con):
    host_id, _ = store.add_host(con, "box")
    run = a_run(con, host_id, "probe1", stamp(0))
    a_result(con, run, "v4", 22, "185.199.108.153", prober.STATE_CONNECTED, stamp(0))
    con.commit()
    rows = prober.host_latest_results(con, host_id)
    assert [(r["port"], r["state"], r["vantage"]) for r in rows] == [
        (22, prober.STATE_CONNECTED, "probe1")]


def test_a_later_measurement_replaces_an_earlier_one_whatever_order_they_are_stored_in(con):
    """Two lanes interleave: a pass measured earlier can be stored later. What
    counts is when it was measured, never the order of the rows."""
    host_id, _ = store.add_host(con, "box")
    late = a_run(con, host_id, "probe1", stamp(5))
    early = a_run(con, host_id, "probe1", stamp(1))
    a_result(con, late, "v4", 22, "185.199.108.153", "no_response", stamp(5))
    a_result(con, early, "v4", 22, "185.199.108.153", prober.STATE_CONNECTED, stamp(1))
    con.commit()
    (row,) = prober.host_latest_results(con, host_id)
    assert row["state"] == "no_response"


def test_each_vantage_address_and_family_keeps_its_own(con):
    host_id, _ = store.add_host(con, "box")
    for vantage in ("probe1", "probe2"):
        run = a_run(con, host_id, vantage, stamp(0))
        a_result(con, run, "v4", 22, "185.199.108.153", "no_response", stamp(0))
        a_result(con, run, "v4", 22, "185.199.108.154", "no_response", stamp(0))
        a_result(con, run, "v6", 22, "2001:20::1", "no_response", stamp(0))
    con.commit()
    assert len(prober.host_latest_results(con, host_id)) == 6


def test_a_result_with_no_address_shares_one_slot(con):
    host_id, _ = store.add_host(con, "box")
    run = a_run(con, host_id, "probe1", stamp(0))
    a_result(con, run, "v6", 22, None, "not_tested", stamp(0))
    a_result(con, run, "v6", 22, None, "not_tested", stamp(1))
    con.commit()
    (row,) = prober.host_latest_results(con, host_id)
    assert row["target"] is None and row["measured_at"] == stamp(1)


def test_another_hosts_results_are_never_this_hosts(con):
    one, _ = store.add_host(con, "one")
    two, _ = store.add_host(con, "two")
    a_result(con, a_run(con, one, "probe1", stamp(0)), "v4", 22, "185.199.108.153",
             prober.STATE_CONNECTED, stamp(0))
    con.commit()
    assert prober.host_latest_results(con, two) == []


@pytest.mark.parametrize("seed", range(40))
def test_the_engine_reads_the_same_index_either_way(con, seed):
    """The one that matters. Random runs, stored out of order, two vantages,
    two lanes over different port sets, equal timestamps included. Whatever
    the rows are, the small table and every row give the engine one index."""
    rng = random.Random(seed)
    host_id, _ = store.add_host(con, "box")
    addresses = {"v4": ["185.199.108.153", "185.199.108.154", None],
                 "v6": ["2001:20::1", None]}
    runs = []
    for _ in range(rng.randint(3, 14)):
        minute = rng.randint(0, 40)
        runs.append((a_run(con, host_id, rng.choice(("probe1", "probe2")), stamp(minute)),
                     minute))
    rng.shuffle(runs)
    for run_id, minute in runs:
        for port in rng.sample([22, 25, 80, 443, 8080], rng.randint(1, 5)):
            family = rng.choice(FAMILIES)
            a_result(con, run_id, family, port, rng.choice(addresses[family]),
                     rng.choice(STATES), stamp(minute, rng.choice((0, 0, 1, 500))))
    con.commit()
    fast, slow = both_ways(con, host_id)
    assert fast == slow
    assert fast, "a seed that stored nothing proves nothing"


def test_a_database_from_before_the_table_is_backfilled_once(tmp_path):
    """Production on the day this lands: results and no probe_latest. `init`
    fills it from what is there, and a second `init` adds nothing."""
    connection = db.connect(str(tmp_path / "old.db"))
    db.init(connection)
    connection.executescript(prober.SCHEMA_BEFORE_LATEST)
    host_id, _ = store.add_host(connection, "box")
    run = a_run(connection, host_id, "probe1", stamp(0))
    a_result(connection, run, "v4", 22, "185.199.108.153", "no_response", stamp(0))
    a_result(connection, run, "v4", 22, "185.199.108.153", prober.STATE_CONNECTED, stamp(3))
    connection.commit()
    prober.init(connection)
    (row,) = prober.host_latest_results(connection, host_id)
    assert row["state"] == prober.STATE_CONNECTED
    before = connection.execute("SELECT COUNT(*) FROM probe_latest").fetchone()[0]
    prober.init(connection)
    assert connection.execute("SELECT COUNT(*) FROM probe_latest").fetchone()[0] == before == 1
    fast, slow = both_ways(connection, host_id)
    assert fast == slow
    connection.close()


def test_without_the_table_the_engine_reads_every_row_as_before(tmp_path):
    """A database a tool opens that `prober.init` never ran against. The
    engine must still answer, the old way."""
    connection = db.connect(str(tmp_path / "bare.db"))
    db.init(connection)
    connection.executescript(prober.SCHEMA_BEFORE_LATEST)
    host_id, _ = store.add_host(connection, "box")
    a_result(connection, a_run(connection, host_id, "probe1", stamp(0)), "v4", 22,
             "185.199.108.153", prober.STATE_CONNECTED, stamp(0))
    connection.commit()
    index = join._probe_index(connection, host_id)
    assert index[("v4", 22)]["state"] == prober.STATE_CONNECTED
    connection.close()


def test_deleting_a_result_the_table_points_at_is_refused(con):
    """Retention is not built. When it is, it must spare these rows or move
    the pointer first, and the database says so rather than leaving a slot
    that silently vanished."""
    host_id, _ = store.add_host(con, "box")
    a_result(con, a_run(con, host_id, "probe1", stamp(0)), "v4", 22, "185.199.108.153",
             prober.STATE_CONNECTED, stamp(0))
    con.commit()
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("DELETE FROM probe_results")
        con.commit()
