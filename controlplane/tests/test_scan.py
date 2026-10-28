"""On-demand scan requests: the durable rate limit, the pending queue, and the
trigger file.

`app/scan.py` records a request, refuses one that came too soon, and hands the
responder (app/scan_cli.py) the hosts waiting. The rate limit is the part with
teeth: it is read from the table every time, so an ingest restart cannot forget
it. These tests move an injected clock rather than sleeping through it.
"""

import os
from datetime import datetime, timedelta, timezone

import pytest

from app import db, scan, store

T0 = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def con(tmp_path):
    # A file rather than :memory:, so a second connection sees the same rows and
    # the durability test below means something.
    connection = db.connect(str(tmp_path / "scan.db"))
    db.init(connection)
    scan.init(connection)
    yield connection
    connection.close()


def a_host(con, name="box"):
    host_id, _ = store.add_host(con, name)
    return host_id


# ------------------------------------------------------------- the rate limit

def test_a_fresh_host_is_accepted(con):
    host_id = a_host(con)
    result = scan.request_scan(con, host_id, T0)
    assert result.accepted is True
    assert result.retry_after == 0
    assert result.sentence
    assert scan.pending_requests(con) == [host_id]


def test_a_second_scan_too_soon_is_refused_with_a_wait(con):
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    result = scan.request_scan(con, host_id, T0 + timedelta(seconds=30))
    assert result.accepted is False
    # 120 - 30 = 90 seconds left.
    assert result.retry_after == 90
    assert "90 seconds" in result.sentence
    # And the refusal wrote no second row.
    assert len(scan.pending_ids_for_host(con, host_id)) == 1


def test_retry_after_rounds_up_so_it_never_undershoots(con):
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    result = scan.request_scan(con, host_id, T0 + timedelta(seconds=30.4))
    # 89.6 seconds left, and telling a person 89 would send them back a moment
    # before the limit has actually cleared.
    assert result.retry_after == 90


def test_one_second_before_the_interval_is_still_refused(con):
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    interval = scan.SCAN_MIN_INTERVAL_SECONDS
    result = scan.request_scan(con, host_id, T0 + timedelta(seconds=interval - 1))
    assert result.accepted is False
    assert result.retry_after == 1


def test_a_scan_exactly_at_the_interval_is_accepted_again(con):
    """elapsed < interval is the refusal, so elapsed == interval is not too
    soon."""
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    interval = scan.SCAN_MIN_INTERVAL_SECONDS
    result = scan.request_scan(con, host_id, T0 + timedelta(seconds=interval))
    assert result.accepted is True
    assert result.retry_after == 0


def test_two_hosts_do_not_share_a_limit(con):
    first = a_host(con, "one")
    second = a_host(con, "two")
    assert scan.request_scan(con, first, T0).accepted is True
    # The second host never scanned, so first's cooldown says nothing about it.
    assert scan.request_scan(con, second, T0).accepted is True
    # And first is still on cooldown.
    assert scan.request_scan(con, first, T0 + timedelta(seconds=1)).accepted is False


def test_the_limit_is_durable_across_a_fresh_connection(tmp_path):
    """The whole reason this is a table and not an in-memory bucket. A restart
    opens a new connection, and the cooldown has to survive it."""
    path = str(tmp_path / "durable.db")
    first = db.connect(path)
    db.init(first)
    scan.init(first)
    host_id, _ = store.add_host(first, "box")
    assert scan.request_scan(first, host_id, T0).accepted is True
    first.close()

    second = db.connect(path)
    result = scan.request_scan(second, host_id, T0 + timedelta(seconds=10))
    second.close()
    assert result.accepted is False, "a restart must not forget the cooldown"
    assert result.retry_after == 110


def test_a_custom_interval_is_honoured(con):
    """The owner can tune the interval, so the argument has to actually govern."""
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0, min_interval_seconds=10)
    too_soon = scan.request_scan(con, host_id, T0 + timedelta(seconds=5),
                                 min_interval_seconds=10)
    assert too_soon.accepted is False
    later = scan.request_scan(con, host_id, T0 + timedelta(seconds=10),
                              min_interval_seconds=10)
    assert later.accepted is True


# ---------------------------------------------------- unknown and odd clocks

def test_a_none_host_is_refused_and_writes_nothing(con):
    """The endpoint resolves the host and 404s an unknown one, so None is
    defence rather than a path a request takes. It must not become a row."""
    result = scan.request_scan(con, None, T0)
    assert result.accepted is False
    assert result.retry_after == 0
    assert scan.pending_requests(con) == []


def test_requested_at_is_stored_as_an_iso_utc_string(con):
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    stored = con.execute("SELECT requested_at FROM scan_requests").fetchone()[0]
    assert stored == T0.isoformat()
    assert datetime.fromisoformat(stored).tzinfo is not None


def test_a_naive_now_is_read_as_utc(con):
    host_id = a_host(con)
    naive = datetime(2026, 8, 22, 12, 0, 0)  # no tzinfo
    result = scan.request_scan(con, host_id, naive)
    assert result.accepted is True
    stored = con.execute("SELECT requested_at FROM scan_requests").fetchone()[0]
    assert datetime.fromisoformat(stored).tzinfo is not None


# ------------------------------------------------------------- the queue

def test_pending_and_mark_drained_round_trip(con):
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    ids = scan.pending_ids_for_host(con, host_id)
    assert ids
    assert scan.pending_requests(con) == [host_id]
    scan.mark_drained(con, ids, T0 + timedelta(seconds=1))
    assert scan.pending_requests(con) == []
    assert scan.pending_ids_for_host(con, host_id) == []


def test_a_burst_of_requests_is_one_pending_host(con):
    """Several scans in a burst appear once, so the drain probes the host once
    and clears all of them together."""
    host_id = a_host(con)
    interval = scan.SCAN_MIN_INTERVAL_SECONDS
    scan.request_scan(con, host_id, T0)
    scan.request_scan(con, host_id, T0 + timedelta(seconds=interval))
    scan.request_scan(con, host_id, T0 + timedelta(seconds=2 * interval))
    assert scan.pending_requests(con) == [host_id]
    assert len(scan.pending_ids_for_host(con, host_id)) == 3
    scan.mark_drained(con, scan.pending_ids_for_host(con, host_id), T0)
    assert scan.pending_requests(con) == []


def test_pending_hosts_come_oldest_first(con):
    later = a_host(con, "later")
    earlier = a_host(con, "earlier")
    scan.request_scan(con, earlier, T0)
    scan.request_scan(con, later, T0 + timedelta(seconds=5))
    assert scan.pending_requests(con) == [earlier, later]


def test_mark_drained_is_idempotent_and_empty_is_a_no_op(con):
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    ids = scan.pending_ids_for_host(con, host_id)
    scan.mark_drained(con, ids, T0 + timedelta(seconds=1))
    # A second drain of the same ids changes nothing and does not raise.
    scan.mark_drained(con, ids, T0 + timedelta(seconds=999))
    scan.mark_drained(con, [], T0)
    assert scan.pending_requests(con) == []


def test_a_drained_request_does_not_re_open_the_cooldown_gap(con):
    """Draining marks a request handled, it does not delete it, so the cooldown
    is still measured from the most recent requested_at."""
    host_id = a_host(con)
    scan.request_scan(con, host_id, T0)
    scan.mark_drained(con, scan.pending_ids_for_host(con, host_id), T0)
    result = scan.request_scan(con, host_id, T0 + timedelta(seconds=30))
    assert result.accepted is False


# ------------------------------------------------------------- the trigger

def test_init_is_idempotent(con):
    scan.init(con)
    scan.init(con)
    host_id = a_host(con)
    assert scan.request_scan(con, host_id, T0).accepted is True


def test_the_trigger_file_sits_beside_the_database(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "x.db"))
    path = scan.trigger_path()
    assert os.path.dirname(path) == str(tmp_path)
    assert os.path.basename(path) == scan.TRIGGER_FILENAME
    assert not os.path.exists(path)
    scan.touch_trigger(path)
    assert os.path.exists(path)


def test_touching_the_trigger_twice_rewrites_rather_than_appends(tmp_path):
    path = str(tmp_path / scan.TRIGGER_FILENAME)
    scan.touch_trigger(path)
    first = os.path.getsize(path)
    scan.touch_trigger(path)
    # It truncates and rewrites, so a second touch leaves one timestamp, never
    # two appended.
    assert os.path.getsize(path) == first
