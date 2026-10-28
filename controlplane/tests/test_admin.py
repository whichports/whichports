"""The admin surface: create, revoke, pause, and its gate.

The gate accepts one proof that the caller is an operator: a live session
this application issued. Until 2026-09-12 it also took the header Caddy once
stamped under basic auth, and by then Caddy had stopped stamping it and a
browser could type it (docs/RECORD.md 4.171). Every request here that acts
as the operator carries a session, through `gate()` from operator_gate.py or
a signed-in client of its own, and the forged headers are the refused cases.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, ingest, store, web_auth
from operator_gate import gate



def who(answer):
    """The two fields these tests are about. whoami carries the account
    Settings screen's facts beside them since 2026-09-07, covered in
    test_account_settings_routes.py."""
    return {k: answer[k] for k in ("user", "name")}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def create(client, name, headers=None):
    if headers is None:
        headers = gate()
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=headers)


OPERATOR = "operator@example.com"


def signed_in_operator():
    """A browser signed in as a real operator, carrying only its session
    cookie. The proof is the cookie and a real session row backs it, so the
    tests exercise the same resolve_session the live gate does.

    It uses the database the `client` fixture pointed the process at, so call
    it from a test that takes `client`.
    """
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if accounts.get_user_by_email(con, OPERATOR) is None:
        accounts.create_user(con, OPERATOR, "correct-horse-battery-9")
    user = accounts.get_user_by_email(con, OPERATOR)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


# --- the gate ---

@pytest.mark.parametrize("method,path", [
    ("POST", "/api/admin/hosts"),
    ("POST", "/api/admin/hosts/x/revoke"),
    ("POST", "/api/admin/hosts/x/pause"),
    ("GET", "/api/admin/whoami"),
])
@pytest.mark.parametrize("headers", [
    {},
    {"X-Admin-Gate": "caddy"},
    {"X-Admin-Gate": "1", "X-Auth-User": "robin"},
], ids=["nothing", "forged gate header", "forged gate and user headers"])
def test_admin_without_a_session_is_403(client, method, path, headers):
    """The session is the only proof. Until 2026-09-12 the gate header Caddy
    once stamped under basic auth opened every route here on its own, and
    Caddy had stopped stamping it without anything stripping it, so a browser
    could type it. Measured from outside that day: a forged header answered
    200 on whoami (docs/RECORD.md 4.171). These are the requests that did
    that, and every one of them is refused now."""
    resp = client.request(method, path, content="{}", headers=headers)
    assert resp.status_code == 403


# --- create ---

def test_create_returns_credential_once_and_stores_only_the_hash(client):
    resp = create(client, "newbox")
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "newbox"
    assert body["credential"].startswith(store.CREDENTIAL_PREFIX)
    assert body["credential"] in body["install_command"]
    assert "--server=https://app.whichports.com" in body["install_command"]
    assert "\n" not in body["install_command"]  # one line, one paste
    con = db.connect()
    row = con.execute("SELECT token_hash FROM hosts WHERE name='newbox'").fetchone()
    con.close()
    assert row["token_hash"] == store.credential_hash(body["credential"])
    assert body["credential"] not in row["token_hash"]


def test_create_returns_one_install_command_and_no_second_one(client):
    """One command since 2026-09-12. The second one carried the installer's
    retired --full-visibility flag, and a screen that still drew it would
    hand out a command the installer now refuses."""
    body = create(client, "onebox").json()
    assert "install_command_full_visibility" not in body
    assert "--full-visibility" not in body["install_command"]
    assert body["install_command"].startswith(
        "curl -fsSL https://get.whichports.com/install.sh | sudo sh -s -- enroll ")


def test_the_install_command_is_one_pipe_with_nothing_after_it(client):
    """Until agent 0.1.12 the line chained the enrolment, the timer and one
    collection after the pipe with `&&`. A pipe's exit status is its last
    command's, and a shell given nothing exits 0, so a failed download
    carried on to "sudo: whichports-agent: command not found"
    (docs/RECORD.md 4.228). The installer takes the enrolment as its
    arguments now and does those three things itself, in that order
    (4.243), so the one collection that makes a working install report in
    seconds (4.184, 4.187) is its last step and no longer this line's.

    What this holds is that nothing follows the pipe: no `&&`, no `;`, no
    `||`, and exactly one `|`. The reissue route hands out the same line
    (`_install_commands` is shared)."""
    body = create(client, "nowbox").json()
    command = body["install_command"]
    assert command == (
        "curl -fsSL https://get.whichports.com/install.sh | sudo sh -s -- enroll"
        f" --server=https://app.whichports.com --credential={body['credential']}")
    assert command.count("|") == 1
    for joiner in ("&&", ";", "||", "$(", "`", ">"):
        assert joiner not in command, joiner
    # The three steps are the installer's now, and the window names none.
    assert "systemctl" not in command
    assert "sudo whichports-agent" not in command


def test_created_host_can_post_reports(client):
    credential = create(client, "newbox").json()["credential"]
    resp = client.post("/api/v1/reports",
                       content=json.dumps({"schema_version": 1,
                                           "collected_at_unix": 1, "hostname": "x"}),
                       headers={"Authorization": f"Bearer {credential}"})
    assert resp.status_code == 204


def test_duplicate_name_is_409(client):
    assert create(client, "twin").status_code == 201
    assert create(client, "twin").status_code == 409


@pytest.mark.parametrize("bad", ["", "UPPER", "has space", "-leading", "a" * 33,
                                 "semi;colon", "sla/sh", "dot.dot"])
def test_invalid_names_are_400(client, bad):
    assert create(client, bad).status_code == 400


def test_create_with_garbage_body_is_400(client):
    resp = client.post("/api/admin/hosts", content="not json", headers=gate())
    assert resp.status_code == 400


# --- revoke ---

def test_revoke_stops_reports(client):
    credential = create(client, "box").json()["credential"]
    assert client.post("/api/admin/hosts/box/revoke", headers=gate()).status_code == 204
    resp = client.post("/api/v1/reports",
                       content=json.dumps({"schema_version": 1,
                                           "collected_at_unix": 1, "hostname": "x"}),
                       headers={"Authorization": f"Bearer {credential}"})
    assert resp.status_code == 401


def test_revoke_unknown_host_is_404(client):
    assert client.post("/api/admin/hosts/ghost/revoke", headers=gate()).status_code == 404


def test_revoke_twice_is_404(client):
    create(client, "box")
    assert client.post("/api/admin/hosts/box/revoke", headers=gate()).status_code == 204
    assert client.post("/api/admin/hosts/box/revoke", headers=gate()).status_code == 404


# --- pause ---

def test_pause_and_resume(client):
    create(client, "box")
    resp = client.post("/api/admin/hosts/box/pause",
                       content=json.dumps({"paused": True}), headers=gate())
    assert resp.status_code == 204
    con = db.connect()
    assert con.execute("SELECT paused FROM hosts WHERE name='box'").fetchone()[0] == 1
    con.close()
    client.post("/api/admin/hosts/box/pause",
                content=json.dumps({"paused": False}), headers=gate())
    con = db.connect()
    assert con.execute("SELECT paused FROM hosts WHERE name='box'").fetchone()[0] == 0
    con.close()


def test_pause_wants_a_boolean(client):
    create(client, "box")
    resp = client.post("/api/admin/hosts/box/pause",
                       content=json.dumps({"paused": "yes"}), headers=gate())
    assert resp.status_code == 400


def test_pause_of_revoked_host_is_404(client):
    create(client, "box")
    client.post("/api/admin/hosts/box/revoke", headers=gate())
    resp = client.post("/api/admin/hosts/box/pause",
                       content=json.dumps({"paused": True}), headers=gate())
    assert resp.status_code == 404


def test_existing_database_gains_the_paused_column(tmp_path, monkeypatch):
    """A database created before the paused column existed migrates in
    place: init ALTERs it in and a second init is a no-op."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "old.db"))
    con = db.connect()
    con.execute("CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,"
                " token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,"
                " revoked_at TEXT, last_report_at TEXT)")
    con.execute("CREATE TABLE reports (id INTEGER PRIMARY KEY, host_id INTEGER,"
                " received_at TEXT, collected_at_unix INTEGER, schema_version INTEGER,"
                " document TEXT)")
    con.commit()
    db.init(con)
    db.init(con)  # idempotent
    cols = [r[1] for r in con.execute("PRAGMA table_info(hosts)")]
    con.close()
    assert "paused" in cols


# --- auto naming ---

def report(client, credential, hostname):
    return client.post("/api/v1/reports",
                       content=json.dumps({"schema_version": 1,
                                           "collected_at_unix": 1,
                                           "hostname": hostname}),
                       headers={"Authorization": f"Bearer {credential}"})


def test_create_without_name_gets_placeholder_then_its_own_hostname(client):
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    assert body["name"].startswith("new-")
    assert report(client, body["credential"], "Web-01.local").status_code == 204
    con = db.connect()
    names = [r["name"] for r in con.execute("SELECT name FROM hosts")]
    con.close()
    # lowered, dot replaced, fleet-safe
    assert "web-01-local" in names


def test_the_first_report_that_names_a_server_pins_its_id(client):
    """Decided 2026-10-03 (docs/RECORD.md 4.298): the ID is what the agent
    first says, and a constant. A later report with another hostname does not
    rename the server."""
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    report(client, body["credential"], "web-01")
    assert report(client, body["credential"], "web-01-renamed-on-the-box").status_code == 204
    con = db.connect()
    rows = [(r["name"], r["auto_named"]) for r in con.execute("SELECT name, auto_named FROM hosts")]
    con.close()
    assert rows == [("web-01", 0)]


def test_a_server_named_before_naming_pinned_keeps_the_name_it_carries(client):
    """A server on a box from before 2026-10-03 was named by a report and
    still has the flag. Its next report pins it under the name it has, and
    the hostname in that report does not rename it, even when it changed."""
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    con = db.connect()
    con.execute("UPDATE hosts SET name = 'old-name', auto_named = 1 WHERE name = ?", (body["name"],))
    con.commit()
    con.close()
    report(client, body["credential"], "new-hostname")
    report(client, body["credential"], "another-hostname")
    con = db.connect()
    rows = [(r["name"], r["auto_named"]) for r in con.execute("SELECT name, auto_named FROM hosts")]
    con.close()
    assert rows == [("old-name", 0)]


def test_a_placeholder_is_what_add_host_makes_and_nothing_else():
    """The one test that holds `is_placeholder` to the name `add_host` gives
    a server nobody named."""
    con = db.connect()
    db.init(con)
    host_id, _credential = store.add_host(con)
    made = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()["name"]
    con.close()
    assert store.is_placeholder(made)
    for name in ("new-", "new-12345", "new-1234567", "new-ABCDEF", "new-zzzzzz", "web-01", "renew-abc123"):
        assert not store.is_placeholder(name), name


def test_auto_name_deduplicates_with_a_suffix(client):
    create(client, "samehost")
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    report(client, body["credential"], "samehost")
    con = db.connect()
    names = {r["name"] for r in con.execute("SELECT name FROM hosts")}
    con.close()
    assert "samehost-2" in names


def test_a_deduplicated_name_is_pinned_too(client):
    """Two servers with one hostname: the second keeps its -2 for good, also
    after the first is gone and the plain name is free again."""
    create(client, "samehost")
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    report(client, body["credential"], "samehost")
    assert client.post("/api/admin/hosts/samehost/revoke", headers=gate()).status_code == 204
    report(client, body["credential"], "samehost")
    con = db.connect()
    rows = {(r["name"], r["auto_named"]) for r in con.execute(
        "SELECT name, auto_named FROM hosts WHERE revoked_at IS NULL")}
    con.close()
    assert rows == {("samehost-2", 0)}


def test_hostile_hostname_keeps_the_placeholder(client):
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    report(client, body["credential"], "!!!///")
    con = db.connect()
    names = {r["name"] for r in con.execute("SELECT name FROM hosts")}
    con.close()
    assert body["name"] in names  # nothing usable in the hostname, placeholder stays


def test_a_placeholder_left_by_an_unusable_hostname_is_named_later_once(client):
    """Nothing usable leaves the placeholder unpinned, so the first report
    that does carry a usable hostname names the server, and the one after it
    does not rename it."""
    body = client.post("/api/admin/hosts", content="{}", headers=gate()).json()
    report(client, body["credential"], "!!!///")
    con = db.connect()
    assert con.execute("SELECT auto_named FROM hosts").fetchone()["auto_named"] == 1
    con.close()
    report(client, body["credential"], "db-01")
    report(client, body["credential"], "db-02")
    con = db.connect()
    rows = [(r["name"], r["auto_named"]) for r in con.execute("SELECT name, auto_named FROM hosts")]
    con.close()
    assert rows == [("db-01", 0)]


# --- no rename ---

def test_there_is_no_route_that_renames_a_server(client):
    """The ID does not change (docs/RECORD.md 4.298). The route the Settings
    tab posted to until 2026-10-03 is gone, and a server keeps its name
    whatever is posted there."""
    create(client, "one")
    answer = client.post("/api/admin/hosts/one/rename",
                         content=json.dumps({"name": "two"}), headers=gate())
    assert answer.status_code in (404, 405)
    con = db.connect()
    names = [r["name"] for r in con.execute("SELECT name FROM hosts")]
    con.close()
    assert names == ["one"]
    assert not hasattr(store, "rename_host")


# --- the session path: an operator's cookie ---
#
# Caddy proxies /api/admin/* to the app with nothing in front since
# 2026-09-03, so these requests carry a real session cookie and nothing else.
# The gate has to let them through, and it has to fail closed on a session
# that is not live.

def test_admin_create_accepts_a_session_with_no_gate_header(client):
    """201, on the cookie alone. This is the property that lets the Caddy
    change land after this one instead of in the same instant."""
    op = signed_in_operator()
    resp = op.post("/api/admin/hosts", content=json.dumps({"name": "sessionbox"}))
    assert resp.status_code == 201
    assert resp.json()["name"] == "sessionbox"


def test_admin_revoke_and_pause_accept_a_session_with_no_gate_header(client):
    """The 204 routes take the session too, so the whole admin surface works
    under forward_auth and not just the create."""
    op = signed_in_operator()
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "sbox"})).status_code == 201
    assert op.post("/api/admin/hosts/sbox/pause",
                   content=json.dumps({"paused": True})).status_code == 204
    assert op.post("/api/admin/hosts/sbox/revoke").status_code == 204


def test_admin_whoami_accepts_a_session_with_no_gate_header(client):
    """The read routes move to the session too, or they would 403 under a
    deploy that proxies /api/admin/* without basic_auth."""
    op = signed_in_operator()
    assert op.get("/api/admin/whoami").status_code == 200


def test_admin_refuses_a_revoked_session_with_no_gate_header(client):
    """Fail closed. A session signed out from the CLI is no longer a proof, and
    with no gate header either the action is 403. This also confirms the tests
    above pass because the session is live, not because the gate is open: the
    same cookie that worked a moment ago is refused once its row is revoked."""
    op = signed_in_operator()
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "sbox"})).status_code == 201
    con = db.connect()
    user = accounts.get_user_by_email(con, OPERATOR)
    accounts.revoke_all_sessions(con, user["id"])
    con.close()
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "sbox2"})).status_code == 403


def test_admin_refuses_a_made_up_session_cookie(client):
    """A random cookie value is not a session, so with no gate header it is
    403. resolve_session returns None for it and the gate does not open."""
    bogus = TestClient(
        ingest.app,
        cookies={web_auth.SESSION_COOKIE: accounts.SESSION_PREFIX + "not-real"})
    assert bogus.post("/api/admin/hosts", content="{}").status_code == 403


# --- the workspace an admin action works in ---
#
# The session decides, and nothing about the request does. These are the tests
# that say a signed-in operator cannot touch another workspace's server through
# any of these routes, and that basic auth keeps working exactly as it does on
# the box today.


def in_workspace(email, workspace_id):
    """A browser signed in as an account in one workspace. Uses the database
    the `client` fixture pointed the process at."""
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if db.workspace_by_id(con, workspace_id) is None:
        con.execute("INSERT INTO workspaces (id, name, created_at)"
                    " VALUES (?, ?, ?)",
                    (workspace_id, f"w{workspace_id}", db.now_utc()))
        con.commit()
    user_id = accounts.create_user(con, email, "correct-horse-battery-9",
                                   workspace_id=workspace_id)
    token, _ = accounts.issue_session(con, user_id)
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def test_a_host_created_by_a_session_lands_in_that_sessions_workspace(client):
    op = in_workspace("two@example.com", 2)
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "theirs"})).status_code == 201
    con = db.connect()
    row = con.execute("SELECT workspace_id FROM hosts WHERE name='theirs'").fetchone()
    con.close()
    assert row["workspace_id"] == 2


def test_the_gate_header_alone_still_works_in_workspace_one(client):
    """Basic auth is the way in on the box today and has no session to read.
    Workspace 1 is where the owner's hosts were backfilled, so this is the answer
    that changes nothing for him."""
    assert create(client, "mine").status_code == 201
    con = db.connect()
    row = con.execute("SELECT workspace_id FROM hosts WHERE name='mine'").fetchone()
    con.close()
    assert row["workspace_id"] == db.DEFAULT_WORKSPACE_ID


@pytest.mark.parametrize("path,body", [
    ("/api/admin/hosts/mine/revoke", "{}"),
    ("/api/admin/hosts/mine/pause", json.dumps({"paused": True})),
    ("/api/admin/hosts/mine/scan", "{}"),
])
def test_a_session_cannot_touch_another_workspaces_host(client, path, body):
    """404, the same answer a name nobody enrolled gets. Anything else would be
    a way to ask which names exist in other workspaces."""
    assert create(client, "mine").status_code == 201
    op = in_workspace("two@example.com", 2)
    assert op.post(path, content=body).status_code == 404
    con = db.connect()
    row = con.execute("SELECT * FROM hosts WHERE name='mine'").fetchone()
    con.close()
    assert row is not None
    assert row["revoked_at"] is None
    assert row["paused"] == 0


def test_a_session_can_still_touch_its_own_workspaces_host(client):
    """The other half: scoping refuses the neighbour and changes nothing about
    your own."""
    op = in_workspace("two@example.com", 2)
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "theirs"})).status_code == 201
    assert op.post("/api/admin/hosts/theirs/pause",
                   content=json.dumps({"paused": True})).status_code == 204
    assert op.post("/api/admin/hosts/theirs/revoke").status_code == 204


def test_a_forged_gate_header_does_not_move_a_session_to_workspace_one(client):
    """The header used to mean workspace 1. A signed-in person who sends it
    anyway, or has it added by something in between, stays in their own
    workspace, because the session is the only thing read."""
    op = in_workspace("two@example.com", 2)
    assert op.post("/api/admin/hosts", headers={"X-Admin-Gate": "caddy"},
                   content=json.dumps({"name": "theirs"})).status_code == 201
    con = db.connect()
    row = con.execute("SELECT workspace_id FROM hosts WHERE name='theirs'").fetchone()
    con.close()
    assert row["workspace_id"] == 2


# --- whoami: what the account menu shows ---
#
# On 2026-08-23 the owner's menu read "Signed in as {http.auth.user.id}": the
# route echoed the x-auth-user header verbatim and what arrived was the
# literal placeholder text, rendered to him as a name. The session is the
# identity this application holds, so it answers first, and a header only
# stands in when it looks like a name.


def test_whoami_answers_the_session_email(client):
    op = signed_in_operator()
    resp = op.get("/api/admin/whoami")
    assert resp.status_code == 200
    assert who(resp.json()) == {"user": OPERATOR, "name": ""}


def test_whoami_is_never_cached(client):
    """Who is signed in changes at sign-out, so a cached answer is a wrong
    answer. Same rule as web_auth's own whoami."""
    op = signed_in_operator()
    assert op.get("/api/admin/whoami").headers["cache-control"] == "no-store"


@pytest.mark.parametrize("edge", ["somebody-else", "{http.auth.user.id}", "{",
                                  "}", "a{b}c", "", "   "])
def test_whoami_answers_from_the_session_whatever_the_edge_header_says(client, edge):
    """The x-auth-user header Caddy once stamped under basic auth names nobody
    now. A signed-in person who carries one, sane or a template, is still
    named by their session, and the exact string the owner once saw rendered
    (docs/RECORD.md 4.100) never reaches a screen through it."""
    op = signed_in_operator()
    resp = op.get("/api/admin/whoami", headers={"x-auth-user": edge})
    assert who(resp.json()) == {"user": OPERATOR, "name": ""}


@pytest.mark.parametrize("headers", [
    {"x-auth-user": "robin"},
    {"X-Admin-Gate": "caddy", "x-auth-user": "robin"},
    {"X-Admin-Gate": "caddy"},
])
def test_whoami_without_a_session_is_403_whatever_the_headers_say(client, headers):
    """Until 2026-09-12 the middle case answered 200 with "robin" in it, on
    no credential at all. Nothing here is a proof and nothing here is a name."""
    resp = client.get("/api/admin/whoami", headers=headers)
    assert resp.status_code == 403


def test_whoami_with_no_proof_at_all_is_403(client):
    """Fail closed, like every other admin route. Who is signed in is not an
    anonymous caller's question to ask."""
    assert client.get("/api/admin/whoami").status_code == 403


def test_whoami_answers_the_stored_display_name(client):
    """The avatar chip derives its letters from the name when one is stored.
    The route only reports what the account holds and derives nothing."""
    op = signed_in_operator()
    con = db.connect()
    user = accounts.get_user_by_email(con, OPERATOR)
    accounts.set_display_name(con, user["id"], "Robin Sample")
    con.close()
    assert who(op.get("/api/admin/whoami").json()) == \
        {"user": OPERATOR, "name": "Robin Sample"}


def test_whoami_forgets_a_cleared_display_name(client):
    op = signed_in_operator()
    con = db.connect()
    user = accounts.get_user_by_email(con, OPERATOR)
    accounts.set_display_name(con, user["id"], "Robin Sample")
    accounts.set_display_name(con, user["id"], "")
    con.close()
    assert who(op.get("/api/admin/whoami").json()) == {"user": OPERATOR, "name": ""}


def test_whoami_refuses_a_pending_two_factor_session(client):
    """A session that still owes a code is signed in nowhere else in the app,
    so the menu must not name its owner either."""
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if accounts.get_user_by_email(con, OPERATOR) is None:
        accounts.create_user(con, OPERATOR, "correct-horse-battery-9")
    user = accounts.get_user_by_email(con, OPERATOR)
    token, _ = accounts.issue_session(con, user["id"], totp_pending=True)
    con.close()
    pending = TestClient(ingest.app,
                         cookies={web_auth.SESSION_COOKIE: token})
    assert pending.get("/api/admin/whoami").status_code == 403


# --- sign out: destroys the session, never pops the browser dialog ---
#
# The old route answered 401 with a different Basic realm, a leftover from the
# basic-auth-only era, and that 401 is what made the browser pop its own
# password dialog on every click (the owner, 2026-08-23). It never touched the
# app session. Now the route defers to web_auth.logout, the one owner of what
# signing out means.


def test_signout_revokes_the_session_and_clears_the_cookie(client):
    op = signed_in_operator()
    assert who(op.get("/api/admin/whoami").json()) == {"user": OPERATOR, "name": ""}
    resp = op.post("/api/admin/signout", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?msg=signed-out"
    assert [line for line in resp.headers.get_list("set-cookie")
            if line.startswith(web_auth.SESSION_COOKIE + "=")]
    # The server-side row is gone, so the old cookie proves nothing anywhere:
    # the next admin action is refused even if a copy of it survived.
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "after"})).status_code == 403


def test_signout_never_answers_401_or_names_a_realm(client):
    """Signed in, a forged gate header, or nothing at all: no answer here may
    be the 401 that pops the browser's own dialog."""
    signed = signed_in_operator()
    for caller, headers in ((signed, {}), (client, {"X-Admin-Gate": "caddy"}),
                            (client, {})):
        resp = caller.post("/api/admin/signout", headers=headers,
                           follow_redirects=False)
        assert resp.status_code == 303
        assert "www-authenticate" not in resp.headers


def test_signout_with_no_session_still_succeeds(client):
    """A browser whose session already lapsed has nothing to destroy. Nothing
    to revoke is not an error, and the login page is still where it lands."""
    resp = client.post("/api/admin/signout", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?msg=signed-out"


def test_signout_is_not_reachable_by_a_get(client):
    """web_auth's own rule for /logout, kept at this path too: a GET would let
    a link or an image tag sign somebody out."""
    op = signed_in_operator()
    assert op.get("/api/admin/signout", follow_redirects=False).status_code == 405
    # and the session survived the refused GET
    assert who(op.get("/api/admin/whoami").json()) == {"user": OPERATOR, "name": ""}


# --- a never-reported server hands out its command again ---

def reissue(client, name, headers=None):
    if headers is None:
        headers = gate()
    return client.post(f"/api/admin/hosts/{name}/credential", headers=headers)


def test_reissue_replaces_the_credential_of_a_never_reported_host(client):
    """The add-server window shows the command once, so a window closed too
    early left a row whose command was gone for good (the 2026-08-23 audit,
    control 3). No agent has ever held this credential, so replacing it
    breaks nothing."""
    first = create(client, "newbox").json()
    resp = reissue(client, "newbox")
    assert resp.status_code == 200
    body = resp.json()
    assert body["credential"].startswith(store.CREDENTIAL_PREFIX)
    assert body["credential"] != first["credential"]
    assert body["credential"] in body["install_command"]
    assert "\n" not in body["install_command"]
    con = db.connect()
    row = con.execute("SELECT token_hash FROM hosts WHERE name='newbox'").fetchone()
    con.close()
    # the new hash is stored, so the abandoned command is dead and the new
    # one is the way in
    assert row["token_hash"] == store.credential_hash(body["credential"])
    assert row["token_hash"] != store.credential_hash(first["credential"])


def test_reissue_refuses_a_host_that_has_reported(client):
    """Its agent holds the working credential. Replacing that from a screen
    would silently cut a healthy server off at its next report."""
    create(client, "talking")
    con = db.connect()
    con.execute("UPDATE hosts SET last_report_at = '2026-08-29T12:00:00+00:00'"
                " WHERE name = 'talking'")
    before = con.execute("SELECT token_hash FROM hosts WHERE name='talking'").fetchone()
    con.commit()
    resp = reissue(client, "talking")
    assert resp.status_code == 409
    assert "has reported" in resp.json()["detail"]
    after = con.execute("SELECT token_hash FROM hosts WHERE name='talking'").fetchone()
    con.close()
    assert after["token_hash"] == before["token_hash"]


def test_reissue_refuses_a_revoked_host(client):
    create(client, "gone")
    con = db.connect()
    con.execute("UPDATE hosts SET revoked_at = '2026-08-29T12:00:00+00:00'"
                " WHERE name = 'gone'")
    con.commit()
    con.close()
    resp = reissue(client, "gone")
    assert resp.status_code == 409
    assert "revoked" in resp.json()["detail"]


def test_reissue_answers_not_found_for_the_rest(client):
    """An unknown name, an address host and another workspace's host all get
    the same 404 every host route gives, so the route says nothing about
    what exists where."""
    assert reissue(client, "nobody").status_code == 404
    client.post("/api/admin/hosts",
                content=json.dumps({"name": "justaddr", "kind": "address"}),
                headers=gate())
    assert reissue(client, "justaddr").status_code == 404
    con = db.connect()
    db.init(con)
    con.execute("INSERT INTO workspaces (id, name, created_at)"
                " VALUES (2, 'second', '2026-08-29T12:00:00+00:00')")
    con.commit()
    host_id, _ = store.add_host(con, "elsewhere", workspace_id=2)
    con.close()
    # the gate path acts in workspace 1, and workspace 2's host is not there
    assert reissue(client, "elsewhere").status_code == 404
