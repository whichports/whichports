"""The account Settings screen's three writes and the facts whoami carries
for it (docs/screens/account-settings): the name on the account, the
password with the current one checked first, and the workspace's name. All
three need a signed-in account, and a forged gate header is refused."""
import json

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, ingest, web_auth
from operator_gate import gate

EMAIL = "operator@example.com"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def signed_in():
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if accounts.get_user_by_email(con, EMAIL) is None:
        accounts.create_user(con, EMAIL, PASSWORD)
    user = accounts.get_user_by_email(con, EMAIL)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def user_row():
    con = db.connect()
    row = accounts.get_user_by_email(con, EMAIL)
    con.close()
    return row


def post(c, path, body):
    return c.post(path, content=json.dumps(body), headers={"Content-Type": "application/json"})


# --------------------------------------------------------------- whoami

def test_whoami_carries_the_settings_facts_for_a_session(client):
    op = signed_in()
    got = op.get("/api/admin/whoami").json()
    assert got["user"] == EMAIL
    assert got["totp"] is False
    assert got["password_changed_at"] == ""
    assert got["workspace"]
    assert set(got) == {"user", "name", "totp", "password_changed_at", "workspace"}


def test_whoami_without_a_session_carries_nothing_at_all(client):
    """Until 2026-09-12 the headers Caddy once stamped under basic auth got
    an answer here with no session behind it. Now they get a refusal, so no
    fact about any account leaves on a forged header."""
    answer = client.get("/api/admin/whoami",
                        headers={"X-Admin-Gate": "caddy", "x-auth-user": "robin"})
    assert answer.status_code == 403
    assert "robin" not in answer.text


def test_whoami_never_carries_a_secret_or_a_hash(client):
    op = signed_in()
    text = op.get("/api/admin/whoami").text
    for word in ("hash", "secret", "totp_secret", "password_hash"):
        assert word not in text


# ----------------------------------------------------------------- name

def test_the_name_is_stored_and_read_back(client):
    op = signed_in()
    assert post(op, "/api/admin/account/name", {"name": "  Robin Sample "}).status_code == 204
    assert accounts.display_name_of(user_row()) == "Robin Sample"
    assert op.get("/api/admin/whoami").json()["name"] == "Robin Sample"


def test_an_empty_name_clears_it(client):
    op = signed_in()
    post(op, "/api/admin/account/name", {"name": "Robin"})
    assert post(op, "/api/admin/account/name", {"name": ""}).status_code == 204
    assert user_row()["display_name"] is None


def test_a_name_past_the_bound_is_refused_with_the_reason(client):
    op = signed_in()
    resp = post(op, "/api/admin/account/name", {"name": "x" * 81})
    assert resp.status_code == 400
    assert "80" in resp.json()["detail"]


def test_a_name_that_is_not_text_is_refused(client):
    op = signed_in()
    assert post(op, "/api/admin/account/name", {"name": 7}).status_code == 400
    assert post(op, "/api/admin/account/name", {}).status_code == 400


def test_a_forged_gate_header_cannot_change_a_name(client):
    resp = client.post("/api/admin/account/name", content=json.dumps({"name": "x"}),
                       headers={"X-Admin-Gate": "caddy", "Content-Type": "application/json"})
    assert resp.status_code == 403


def test_nobody_at_all_cannot_change_a_name(client):
    assert post(client, "/api/admin/account/name", {"name": "x"}).status_code == 403


# ------------------------------------------------------------- password

def test_the_password_changes_when_the_current_one_is_right(client):
    op = signed_in()
    resp = post(op, "/api/admin/account/password",
                {"current": PASSWORD, "new": "a-brand-new-passphrase-9"})
    assert resp.status_code == 204
    con = db.connect()
    assert accounts.authenticate(con, EMAIL, "a-brand-new-passphrase-9") is not None
    assert accounts.authenticate(con, EMAIL, PASSWORD) is None
    con.close()
    # and the date is stamped, and whoami says so
    assert user_row()["password_changed_at"]
    assert op.get("/api/admin/whoami").json()["password_changed_at"] == user_row()["password_changed_at"]


def test_a_wrong_current_password_changes_nothing(client):
    op = signed_in()
    resp = post(op, "/api/admin/account/password",
                {"current": "not-it-at-all", "new": "a-brand-new-passphrase-9"})
    assert resp.status_code == 400
    assert "current password" in resp.json()["detail"]
    con = db.connect()
    assert accounts.authenticate(con, EMAIL, PASSWORD) is not None
    con.close()


def test_a_new_password_outside_the_bounds_is_refused_with_the_reason(client):
    op = signed_in()
    resp = post(op, "/api/admin/account/password", {"current": PASSWORD, "new": "short"})
    assert resp.status_code == 400
    assert str(accounts.PASSWORD_MIN_CHARS) in resp.json()["detail"]


def test_a_password_change_keeps_this_session(client):
    op = signed_in()
    post(op, "/api/admin/account/password", {"current": PASSWORD, "new": "a-brand-new-passphrase-9"})
    assert op.get("/api/admin/whoami").json()["user"] == EMAIL


def test_a_forged_gate_header_cannot_change_a_password(client):
    resp = client.post("/api/admin/account/password",
                       content=json.dumps({"current": PASSWORD, "new": "a-brand-new-passphrase-9"}),
                       headers={"X-Admin-Gate": "caddy", "Content-Type": "application/json"})
    assert resp.status_code == 403


# ------------------------------------------------------------- workspace

def test_the_workspace_name_is_stored_and_read_back(client):
    op = signed_in()
    assert post(op, "/api/admin/workspace/name", {"name": " ops fleet "}).status_code == 204
    con = db.connect()
    row = db.workspace_by_id(con, accounts.workspace_of(user_row()))
    con.close()
    assert row["name"] == "ops fleet"
    assert op.get("/api/admin/whoami").json()["workspace"] == "ops fleet"


def test_an_empty_workspace_name_is_refused(client):
    op = signed_in()
    resp = post(op, "/api/admin/workspace/name", {"name": "   "})
    assert resp.status_code == 400
    assert "name" in resp.json()["detail"]


def test_a_workspace_name_past_the_bound_is_refused(client):
    op = signed_in()
    assert post(op, "/api/admin/workspace/name", {"name": "x" * 81}).status_code == 400


def test_a_forged_gate_header_cannot_rename_a_workspace(client):
    resp = client.post("/api/admin/workspace/name", content=json.dumps({"name": "x"}),
                       headers={"X-Admin-Gate": "caddy", "Content-Type": "application/json"})
    assert resp.status_code == 403


def test_the_rename_touches_only_the_sessions_workspace(client):
    con = db.connect()
    db.init(con)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'theirs', '2026-01-01')")
    con.commit()
    con.close()
    op = signed_in()
    post(op, "/api/admin/workspace/name", {"name": "mine"})
    con = db.connect()
    names = {r["id"]: r["name"] for r in db.list_workspaces(con)}
    con.close()
    assert names[2] == "theirs"
    assert names[accounts.workspace_of(user_row())] == "mine"


# ------------------------------------------------------------- the stamp

def test_set_password_stamps_when_and_an_old_row_reads_as_empty(tmp_path):
    con = db.connect(str(tmp_path / "x.db"))
    db.init(con)
    accounts.init(con)
    accounts.create_user(con, EMAIL, PASSWORD)
    user = accounts.get_user_by_email(con, EMAIL)
    assert accounts.password_changed_at(user) == ""
    accounts.set_password(con, user["id"], "a-brand-new-passphrase-9")
    user = accounts.get_user_by_email(con, EMAIL)
    assert accounts.password_changed_at(user).startswith("20")
    con.close()
