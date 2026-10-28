"""What the last provider read did is recorded, so a token that stopped
working is a fact on a screen and not only a line in a journal."""
from datetime import datetime, timedelta, timezone

import pytest

from app import db, hetzner, sweep_cli


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    hetzner.init(connection)
    yield connection
    connection.close()


class FakeClient:
    def __init__(self, fail=None):
        self.fail = fail
        self.rate_limit = hetzner.RateLimit()

    def fetch_snapshot(self):
        if self.fail is not None:
            raise self.fail
        return hetzner.Snapshot(fetched_at=datetime.now(timezone.utc).isoformat())


def test_nothing_tried_is_none(con):
    assert hetzner.latest_fetch(con) is None


def test_a_database_without_the_table_answers_none(tmp_path):
    connection = db.connect(str(tmp_path / "old.db"))
    db.init(connection)
    assert hetzner.latest_fetch(connection) is None
    connection.close()


def test_a_success_is_recorded_without_an_error(con):
    now = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
    hetzner.record_fetch(con, now)
    assert hetzner.latest_fetch(con) == {
        "tried_at": now.isoformat(), "error_kind": None, "error_status": None}


def test_a_failure_records_the_kind_and_the_status_and_nothing_else(con):
    now = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
    hetzner.record_fetch(con, now, hetzner.ProviderError(hetzner.ERROR_UNAUTHORIZED, status=401))
    assert hetzner.latest_fetch(con) == {
        "tried_at": now.isoformat(), "error_kind": "unauthorized", "error_status": 401}


def test_one_row_per_provider_and_a_success_clears_the_failure(con):
    now = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)
    hetzner.record_fetch(con, now, hetzner.ProviderError(hetzner.ERROR_FORBIDDEN, status=403))
    hetzner.record_fetch(con, now + timedelta(hours=1))
    assert con.execute("SELECT COUNT(*) FROM provider_fetches").fetchone()[0] == 1
    got = hetzner.latest_fetch(con)
    assert got["error_kind"] is None and got["error_status"] is None
    assert got["tried_at"] == (now + timedelta(hours=1)).isoformat()


def test_the_sweep_records_a_refused_token_and_keeps_the_snapshot(con):
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    old = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    hetzner.store_snapshot(con, hetzner.Snapshot(fetched_at=old, servers=({"id": 1},)))
    now = datetime.now(timezone.utc)
    note = sweep_cli.refresh_provider(
        con, now, lambda token: FakeClient(fail=hetzner.ProviderError(hetzner.ERROR_UNAUTHORIZED, status=401)))
    assert "not refreshed" in note
    assert hetzner.latest_snapshot(con).fetched_at == old
    got = hetzner.latest_fetch(con)
    assert (got["error_kind"], got["error_status"]) == ("unauthorized", 401)
    assert got["tried_at"] == now.isoformat()


def test_the_sweep_records_a_good_read(con):
    hetzner.add_token(con, "tok-" + "x" * 20, 1)
    now = datetime.now(timezone.utc)
    assert "refreshed" in sweep_cli.refresh_provider(con, now, lambda token: FakeClient())
    got = hetzner.latest_fetch(con)
    assert got["error_kind"] is None and got["tried_at"] == now.isoformat()


def test_no_token_records_nothing(con):
    assert sweep_cli.refresh_provider(con, datetime.now(timezone.utc), lambda token: FakeClient()) == ""
    assert hetzner.latest_fetch(con) is None
