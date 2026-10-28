"""A server's first report asks for one scan, so its first measurement follows
in seconds (docs/screens/add-server/BRIEF-arrival.md, the owner's yes 2026-09-20).

Without it the first measurement waits for the ten minute lane. The request is
exactly what the Scan now button records (docs/PRODUCT.md 5f): a row in
scan_requests and a touched trigger file, nothing sent to the agent, so SI-1
and SI-2 stand. Measured on production on 2026-09-20: 13 seconds from such a
request to both vantages done.

It is a side effect kept off the report's path. Whatever goes wrong in it, the
report is stored and answered 204.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, scan, store
from operator_gate import gate


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def create(client, name):
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate()).json()["credential"]


def report(client, credential, hostname="box"):
    return client.post("/api/v1/reports",
                       content=json.dumps({"schema_version": 1,
                                           "collected_at_unix": 1,
                                           "hostname": hostname}),
                       headers={"Authorization": f"Bearer {credential}"})


def requests_for(name):
    con = db.connect()
    try:
        scan.init(con)
        return con.execute(
            "SELECT COUNT(*) FROM scan_requests r JOIN hosts h ON h.id = r.host_id"
            " WHERE h.name = ?", (name,)).fetchone()[0]
    finally:
        con.close()


def test_the_first_report_records_one_scan_request_and_touches_the_trigger(
        client, tmp_path):
    credential = create(client, "box")
    trigger = tmp_path / scan.TRIGGER_FILENAME
    assert requests_for("box") == 0 and not trigger.exists()
    assert report(client, credential).status_code == 204
    assert requests_for("box") == 1
    assert trigger.exists()


def test_a_second_report_asks_for_nothing(client, tmp_path):
    credential = create(client, "box")
    report(client, credential)
    (tmp_path / scan.TRIGGER_FILENAME).unlink()
    assert report(client, credential).status_code == 204
    assert requests_for("box") == 1
    assert not (tmp_path / scan.TRIGGER_FILENAME).exists()


def test_a_second_report_asks_for_nothing_even_after_the_limit_has_passed(client):
    """The two minute limit is not what holds the test above: a report hours
    later still asks for nothing, because it is not the first."""
    credential = create(client, "box")
    report(client, credential)
    con = db.connect()
    con.execute("UPDATE scan_requests SET requested_at = '2026-01-01T00:00:00+00:00'")
    con.commit()
    con.close()
    report(client, credential)
    assert requests_for("box") == 1


def test_another_servers_first_report_is_its_own(client):
    one, two = create(client, "one"), create(client, "two")
    report(client, one, "one")
    report(client, one, "one")
    report(client, two, "two")
    assert requests_for("one") == 1 and requests_for("two") == 1


def test_a_refused_report_asks_for_nothing(client, tmp_path):
    create(client, "box")
    assert report(client, "whp_" + "0" * 64).status_code == 401
    assert requests_for("box") == 0
    assert not (tmp_path / scan.TRIGGER_FILENAME).exists()


def test_a_revoked_servers_report_asks_for_nothing(client):
    credential = create(client, "box")
    client.post("/api/admin/hosts/box/revoke", headers=gate())
    assert report(client, credential).status_code == 401
    assert requests_for("box") == 0


def test_a_malformed_first_report_asks_for_nothing(client):
    """Nothing was stored, so it is not a first report, and the real one that
    follows still is."""
    credential = create(client, "box")
    bad = client.post("/api/v1/reports", content="not json",
                      headers={"Authorization": f"Bearer {credential}"})
    assert bad.status_code >= 400
    assert requests_for("box") == 0
    report(client, credential)
    assert requests_for("box") == 1


def test_a_trigger_that_cannot_be_written_never_fails_the_report(client, monkeypatch):
    credential = create(client, "box")

    def boom(_path):
        raise OSError("read-only file system")

    monkeypatch.setattr(scan, "touch_trigger", boom)
    assert report(client, credential).status_code == 204
    # The request is recorded, so the next pass of the lane still finds it.
    assert requests_for("box") == 1
    con = db.connect()
    stored = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    con.close()
    assert stored == 1


def test_a_scan_table_that_cannot_be_used_never_fails_the_report(client, monkeypatch):
    credential = create(client, "box")

    def boom(*_args, **_kwargs):
        raise RuntimeError("no such table")

    monkeypatch.setattr(scan, "request_scan", boom)
    assert report(client, credential).status_code == 204
    con = db.connect()
    stored = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    con.close()
    assert stored == 1
