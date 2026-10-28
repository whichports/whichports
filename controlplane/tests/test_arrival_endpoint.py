"""GET /api/admin/hosts/arrival/<id>: has this new server reported, and has it
been measured. What the Add server window asks while it is open on the install
command (docs/screens/add-server/BRIEF-arrival.md, record 4.187).

By id and not by name, because a server made by the Agent card is called
new-xxxxxx until its first report renames it to its own hostname, so the name
the window was given stops existing at exactly the moment it is waiting for.

A read. It answers three facts and a name, all of them already on the
dashboard of the same workspace, and nothing about another workspace's server.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, prober
from operator_gate import gate


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def create(client, payload=None):
    return client.post("/api/admin/hosts", content=json.dumps(payload or {}),
                       headers=gate()).json()


def report(client, credential, hostname="Web-01"):
    return client.post("/api/v1/reports",
                       content=json.dumps({"schema_version": 1,
                                           "collected_at_unix": 1,
                                           "hostname": hostname}),
                       headers={"Authorization": f"Bearer {credential}"})


def arrival(client, host_id, headers=None):
    return client.get(f"/api/admin/hosts/arrival/{host_id}",
                      headers=gate() if headers is None else headers)


def a_run(host_id, finished=True):
    con = db.connect()
    prober.init(con)
    con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
        " VALUES (?, 'probe1', '2026-09-20T10:00:00+00:00', ?)",
        (host_id, "2026-09-20T10:00:05+00:00" if finished else None))
    con.commit()
    con.close()


def test_creating_a_server_answers_the_id_the_window_asks_with(client):
    body = create(client)
    assert isinstance(body["id"], int)
    con = db.connect()
    row = con.execute("SELECT name FROM hosts WHERE id = ?", (body["id"],)).fetchone()
    con.close()
    assert row["name"] == body["name"]


def test_a_server_nobody_installed_yet_has_neither(client):
    body = create(client)
    got = arrival(client, body["id"])
    assert got.status_code == 200
    assert got.json() == {"name": body["name"], "reported_at": None,
                          "probed_at": None}


def test_the_first_report_is_answered_with_the_servers_own_name(client):
    body = create(client)
    report(client, body["credential"], "Web-01")
    got = arrival(client, body["id"]).json()
    # The placeholder is gone and the name is the one the first report gave
    # it, which is why the window cannot ask by the name it was handed.
    assert got["name"] == "web-01" and got["name"] != body["name"]
    assert got["reported_at"] is not None
    assert got["probed_at"] is None


def test_a_pass_still_running_is_not_a_measurement(client):
    body = create(client)
    report(client, body["credential"])
    a_run(body["id"], finished=False)
    assert arrival(client, body["id"]).json()["probed_at"] is None


def test_a_finished_pass_is_the_first_measurement(client):
    body = create(client)
    report(client, body["credential"])
    a_run(body["id"])
    assert arrival(client, body["id"]).json()["probed_at"] == "2026-09-20T10:00:05+00:00"


def test_the_answer_has_exactly_three_keys_and_never_the_credential(client):
    body = create(client)
    report(client, body["credential"])
    got = arrival(client, body["id"])
    assert set(got.json()) == {"name", "reported_at", "probed_at"}
    assert body["credential"] not in got.text


def test_without_a_session_it_is_403(client):
    body = create(client)
    assert arrival(client, body["id"], headers={}).status_code == 403


def test_an_unknown_id_is_404(client):
    create(client)
    assert arrival(client, 99999).status_code == 404


def test_an_id_that_is_not_a_number_matches_no_server(client):
    assert client.get("/api/admin/hosts/arrival/box",
                      headers=gate()).status_code in (404, 422)


def test_another_workspaces_server_is_404_exactly_like_an_unknown_one(client):
    """The gate's operator is in workspace 1. A server in workspace 2 must
    answer what an id that does not exist answers, or the route is a way to
    ask which ids exist elsewhere."""
    body = create(client)
    con = db.connect()
    con.execute("INSERT OR IGNORE INTO workspaces (id, name, created_at)"
                " VALUES (2, 'other', '2026-09-20T00:00:00+00:00')")
    con.execute("UPDATE hosts SET workspace_id = 2 WHERE id = ?", (body["id"],))
    con.commit()
    con.close()
    theirs, unknown = arrival(client, body["id"]), arrival(client, 99999)
    assert theirs.status_code == unknown.status_code == 404
    assert theirs.text == unknown.text


def test_a_revoked_server_is_404(client):
    body = create(client)
    client.post(f"/api/admin/hosts/{body['name']}/revoke", headers=gate())
    assert arrival(client, body["id"]).status_code == 404
