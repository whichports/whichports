"""The ingest contract, tested from the outside.

These tests speak to the app exactly as an agent would: HTTP requests with a
bearer credential and a JSON body. The database is a temp file per test, so
the suite touches nothing real and runs in any order.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, store


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


@pytest.fixture()
def enrolled(tmp_path, monkeypatch):
    """A host called box1, returning (client, credential)."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    _, credential = store.add_host(con, "box1")
    con.close()
    return TestClient(ingest.app), credential


def document(hostname="box1", **extra):
    doc = {"schema_version": 1, "collected_at_unix": 1755000000, "hostname": hostname}
    doc.update(extra)
    return doc


def post(client, credential, body, content_type="application/json"):
    headers = {"Content-Type": content_type}
    if credential is not None:
        headers["Authorization"] = f"Bearer {credential}"
    if isinstance(body, (dict, list)):
        body = json.dumps(body)
    return client.post("/api/v1/reports", content=body, headers=headers)


# --- the happy path ---

def test_valid_report_is_stored_verbatim(enrolled):
    client, credential = enrolled
    body = json.dumps(document(sockets={"status": "collected", "listeners": []}))
    resp = post(client, credential, body)
    assert resp.status_code == 204
    assert resp.content == b""  # the ack carries nothing an agent could act on

    con = db.connect()
    host = con.execute("SELECT * FROM hosts WHERE name='box1'").fetchone()
    report = store.latest_report(con, host["id"])
    con.close()
    assert report["document"] == body  # byte-identical, evidence not reshaped
    assert report["schema_version"] == 1
    assert report["collected_at_unix"] == 1755000000
    assert host["last_report_at"] == report["received_at"]


def test_socket_owner_fields_are_accepted_and_stored_verbatim(enrolled):
    """The 2026-08-19 schema addition: each listening socket may carry the
    owning uid and the name the host's passwd file gives it. The ingest checks
    only the envelope, so the new fields must pass through byte-identical,
    uid 0 included, because root is the most common owner on a server."""
    client, credential = enrolled
    body = json.dumps(document(sockets={"status": "collected", "listening": [
        {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
         "port": 22, "owner_uid": 0, "owner_name": "root"},
        {"protocol": "tcp", "family": "v6", "bind_address": "::",
         "port": 18080, "owner_uid": 1003},
    ]}))
    resp = post(client, credential, body)
    assert resp.status_code == 204

    con = db.connect()
    host = con.execute("SELECT * FROM hosts WHERE name='box1'").fetchone()
    report = store.latest_report(con, host["id"])
    con.close()
    assert report["document"] == body  # byte-identical, evidence not reshaped
    stored = json.loads(report["document"])["sockets"]["listening"]
    assert stored[0]["owner_uid"] == 0 and stored[0]["owner_name"] == "root"
    assert stored[1]["owner_uid"] == 1003 and "owner_name" not in stored[1]


def test_documents_with_and_without_owner_fields_live_side_by_side(enrolled):
    """The fleet runs 0.1.5, whose sockets carry no owner fields, while newer
    agents send them. Both shapes must be accepted and both stored, because an
    upgrade must never invalidate the documents that came before it."""
    client, credential = enrolled
    old_shape = document(collected_at_unix=100, sockets={
        "status": "collected", "listening": [
            {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
             "port": 22, "process_name": "sshd", "pid": 900}]})
    new_shape = document(collected_at_unix=200, sockets={
        "status": "collected", "listening": [
            {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
             "port": 22, "owner_uid": 0, "owner_name": "root"}]})
    assert post(client, credential, old_shape).status_code == 204
    assert post(client, credential, new_shape).status_code == 204

    con = db.connect()
    host = con.execute("SELECT * FROM hosts WHERE name='box1'").fetchone()
    count = con.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"]
    latest = store.latest_report(con, host["id"])
    con.close()
    assert count == 2  # both shapes stored, neither rejected nor rewritten
    sock = json.loads(latest["document"])["sockets"]["listening"][0]
    assert sock["owner_uid"] == 0
    old_sock = old_shape["sockets"]["listening"][0]
    assert "owner_uid" not in old_sock  # the old shape stays the old shape


def test_two_hosts_reports_are_attributed_correctly(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    id_a, cred_a = store.add_host(con, "alpha")
    id_b, cred_b = store.add_host(con, "beta")
    con.close()
    client = TestClient(ingest.app)

    assert post(client, cred_a, document(hostname="alpha")).status_code == 204
    assert post(client, cred_b, document(hostname="beta")).status_code == 204

    con = db.connect()
    latest_a = store.latest_report(con, id_a)
    latest_b = store.latest_report(con, id_b)
    con.close()
    assert json.loads(latest_a["document"])["hostname"] == "alpha"
    assert json.loads(latest_b["document"])["hostname"] == "beta"


def test_latest_report_is_the_newest(enrolled):
    client, credential = enrolled
    post(client, credential, document(collected_at_unix=100))
    post(client, credential, document(collected_at_unix=200))
    con = db.connect()
    host = con.execute("SELECT * FROM hosts WHERE name='box1'").fetchone()
    latest = store.latest_report(con, host["id"])
    count = con.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"]
    con.close()
    assert latest["collected_at_unix"] == 200
    assert count == 2  # history is kept, not overwritten


# --- authentication ---

def test_missing_credential_is_401(enrolled):
    client, _ = enrolled
    assert post(client, None, document()).status_code == 401


def test_wrong_credential_is_401_and_stores_nothing(enrolled):
    client, _ = enrolled
    wrong = store.new_credential()  # valid shape, not enrolled
    assert post(client, wrong, document()).status_code == 401
    con = db.connect()
    count = con.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"]
    con.close()
    assert count == 0


def test_revoked_credential_is_401(enrolled):
    client, credential = enrolled
    assert post(client, credential, document()).status_code == 204
    con = db.connect()
    assert store.revoke_host(con, "box1")
    con.close()
    assert post(client, credential, document()).status_code == 401


def test_unknown_and_revoked_are_indistinguishable(enrolled):
    """A 401 must not confirm whether a credential ever existed."""
    client, credential = enrolled
    con = db.connect()
    store.revoke_host(con, "box1")
    con.close()
    revoked = post(client, credential, document())
    unknown = post(client, store.new_credential(), document())
    assert revoked.status_code == unknown.status_code == 401
    assert revoked.content == unknown.content


# --- the envelope ---

@pytest.mark.parametrize(
    "body",
    [
        "not json at all",
        "[1,2,3]",                                       # JSON but not an object
        '"a string"',
        json.dumps({"collected_at_unix": 1, "hostname": "x"}),        # missing version
        json.dumps({"schema_version": 1, "hostname": "x"}),           # missing timestamp
        json.dumps({"schema_version": 1, "collected_at_unix": 1}),    # missing hostname
        json.dumps(document(schema_version="1")),        # wrong type
        json.dumps(document(schema_version=True)),       # bool is not a version
        json.dumps(document(collected_at_unix="soon")),
        json.dumps(document(hostname=7)),
        b"\xff\xfe invalid utf-8",
    ],
)
def test_bad_envelope_is_400_and_stores_nothing(enrolled, body):
    client, credential = enrolled
    assert post(client, credential, body).status_code == 400
    con = db.connect()
    count = con.execute("SELECT COUNT(*) c FROM reports").fetchone()["c"]
    con.close()
    assert count == 0


def test_oversized_document_is_413(enrolled):
    client, credential = enrolled
    big = json.dumps(document(padding="x" * (ingest.MAX_DOCUMENT_BYTES + 1)))
    assert post(client, credential, big).status_code == 413


# --- credentials at rest ---

def test_database_never_contains_the_credential(enrolled):
    _, credential = enrolled
    con = db.connect()
    row = con.execute("SELECT token_hash FROM hosts WHERE name='box1'").fetchone()
    con.close()
    assert row["token_hash"] != credential
    assert credential not in row["token_hash"]
    assert row["token_hash"] == store.credential_hash(credential)


def test_credential_shape():
    credential = store.new_credential()
    assert credential.startswith(store.CREDENTIAL_PREFIX)
    body = credential.removeprefix(store.CREDENTIAL_PREFIX)
    assert len(body) == 64
    assert all(c in "0123456789abcdef" for c in body)


# --- odds and ends ---

def test_healthz(client):
    assert client.get("/healthz").status_code == 200


def test_add_host_refuses_duplicate_names(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    store.add_host(con, "twin")
    with pytest.raises(Exception):
        store.add_host(con, "twin")
    con.close()


def test_add_host_refuses_empty_name(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    with pytest.raises(ValueError):
        store.add_host(con, "   ")
    con.close()
