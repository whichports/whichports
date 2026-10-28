"""The first-look window is seen once per account: the route that records
it, its gate, and the store behind it.

    python -m pytest tests/test_first_look_endpoint.py

The owner, 2026-09-06, on the window opening once per browser: it opens once per
account. The fixture and the gate pattern are test_admin.py's.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, intent, store
from operator_gate import gate



@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def seed(client, name="box"):
    client.post("/api/admin/hosts", content=json.dumps({"name": name}), headers=gate())
    con = db.connect()
    db.init(con)
    intent.init(con)
    host = store.active_host_by_name(con, name)
    con.close()
    return host["id"]


def seen():
    con = db.connect()
    intent.init(con)
    out = intent.first_looks_seen(con)
    con.close()
    return out


def test_the_first_look_is_recorded_once_and_stays(client):
    host_id = seed(client)
    assert seen() == set()
    assert client.post("/api/admin/hosts/box/first-look", headers=gate()).status_code == 204
    assert seen() == {host_id}
    # a second view changes nothing and is not an error
    assert client.post("/api/admin/hosts/box/first-look", headers=gate()).status_code == 204
    assert seen() == {host_id}


def test_the_route_is_gated_and_an_unknown_server_answers_not_found(client):
    seed(client)
    assert client.post("/api/admin/hosts/box/first-look").status_code in (401, 403)
    assert client.post("/api/admin/hosts/nope/first-look", headers=gate()).status_code == 404
    assert seen() == set()


def test_the_store_says_whether_it_was_the_first_time(client):
    seed(client)
    con = db.connect()
    intent.init(con)
    assert intent.mark_first_look(con, "box") is True
    assert intent.mark_first_look(con, "box") is False
    con.close()
