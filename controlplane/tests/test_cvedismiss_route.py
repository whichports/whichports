"""The route a page calls to dismiss the CVE check's mark on one port, or to
bring it back.

    python -m pytest tests/test_cvedismiss_route.py

The rule and the store have their own file, test_cvedismiss.py. The fixtures
and the gate are test_rarelydismiss.py's, whose route this one stands
beside.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import cvedismiss, cveextract, cvestore, db, ingest, store
from operator_gate import gate
from test_admin import in_workspace
from test_cvetell import FIRST, report


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.delenv(cvestore.DIR_ENV, raising=False)
    modified = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cvestore.install(cveextract.dump(FIRST, "debian", "12", source_modified=modified),
                     cvestore.directory({db.DB_ENV: str(tmp_path / "test.db")}))
    return TestClient(ingest.app)


def post(client, name, protocol, port, dismissed, headers=None):
    return client.post(f"/api/admin/hosts/{name}/cve-mark/{protocol}/{port}",
                       content=json.dumps({"dismissed": dismissed}),
                       headers=gate() if headers is None else headers)


def add(client, name="box", through=None):
    """A server with a report in which OpenSSH on 22 and nginx on 80 each
    carry the mark."""
    made = (through or client).post("/api/admin/hosts", content=json.dumps({"name": name}),
                                    **({} if through else {"headers": gate()}))
    assert made.status_code == 201
    con = db.connect()
    try:
        host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
        doc = report()
        store.insert_report(con, host_id, doc["collected_at_unix"], doc["schema_version"], json.dumps(doc))
        con.commit()
    finally:
        con.close()


def stored(workspace_id=None):
    con = db.connect()
    try:
        return cvedismiss.dismissed_by_host(con, workspace_id=workspace_id)
    finally:
        con.close()


def test_dismiss_answers_what_is_stored_and_restore_takes_it_back(client):
    add(client)
    answer = post(client, "box", "tcp", 22, True)
    assert answer.status_code == 200 and answer.json() == {"dismissed": True}
    assert stored() == {"box": {("tcp", 22): frozenset({"CVE-2026-00001"})}}
    answer = post(client, "box", "tcp", 22, False)
    assert answer.status_code == 200 and answer.json() == {"dismissed": False}
    assert stored() == {}


def test_the_request_names_a_port_and_the_server_works_out_the_cves(client):
    """A body that names CVEs of its own changes nothing: what the mark
    stands for is the server's to say."""
    add(client)
    answer = client.post("/api/admin/hosts/box/cve-mark/tcp/22", headers=gate(),
                         content=json.dumps({"dismissed": True, "cves": ["CVE-1999-0001"]}))
    assert answer.status_code == 200
    assert stored() == {"box": {("tcp", 22): frozenset({"CVE-2026-00001"})}}


@pytest.mark.parametrize("port", [9999, 5432])
def test_a_port_that_carries_no_mark_is_a_400_in_words(client, port):
    add(client)
    answer = post(client, "box", "tcp", port, True)
    assert answer.status_code == 400
    assert answer.json() == {"detail": "this port carries no mark to dismiss"}
    assert stored() == {}


def test_a_port_that_is_not_a_number_is_refused(client):
    add(client)
    assert post(client, "box", "tcp", "ssh", True).status_code in (400, 422)
    assert stored() == {}


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b"{}", b'{"dismissed": "yes"}',
                                  b'{"dismiss": true}'])
def test_a_body_that_is_not_the_expected_object_is_a_400(client, body):
    add(client)
    answer = client.post("/api/admin/hosts/box/cve-mark/tcp/22", content=body, headers=gate())
    assert answer.status_code == 400
    assert stored() == {}


def test_an_unknown_server_answers_not_found(client):
    add(client)
    assert post(client, "nope", "tcp", 22, True).status_code == 404
    assert stored() == {}


def test_another_workspaces_server_answers_not_found_and_is_untouched(client):
    add(client, "mine")
    other = in_workspace("two@example.com", 2)
    add(client, "theirs", through=other)
    assert other.post("/api/admin/hosts/theirs/cve-mark/tcp/22",
                      content=json.dumps({"dismissed": True})).status_code == 200
    assert post(client, "theirs", "tcp", 22, False).status_code == 404
    assert list(stored()) == ["theirs"]
    assert other.post("/api/admin/hosts/mine/cve-mark/tcp/22",
                      content=json.dumps({"dismissed": True})).status_code == 404


def test_nobody_who_is_not_signed_in_dismisses_anything(client):
    add(client)
    answer = post(client, "box", "tcp", 22, True, headers={})
    assert answer.status_code in (401, 403)
    assert stored() == {}
