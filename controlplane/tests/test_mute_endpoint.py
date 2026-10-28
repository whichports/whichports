"""Mute and unmute from the dashboard: the two routes behind the button.

    python -m pytest tests/test_mute_endpoint.py

The store and every rule about what a mute means are `app/finding_alerts.py`'s
and `tests/test_finding_alerts.py` is where they are checked. This is the door
in front of them: who may open it, what a body may say, and which server the
answer is about.

The mutations these are built to catch:

  1. **A mute nobody asked for, or one nobody can lift.** A body that lost its
     number must not read as a length, and a mute with no expiry must be
     liftable by the route the screen posts to.
  2. **A mute that does not survive the process.** The button paints itself
     immediately, so if the row is not really there the screen is the only
     place the mute ever existed. Every duration is read back on a second
     connection.
  3. **Reaching somebody else's server.** The same 404 the other admin routes
     give, for unknown, revoked and another workspace's alike.
  4. **A number that takes the process down.** An expiry is a date, and date
     arithmetic overflows, so a request may not name a length that cannot be
     turned into one.
"""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, finding_alerts, ingest, web_auth
from operator_gate import gate


HOUR = 3600
NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def create(client, name):
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate())


def mute(client, name="box", headers=None, **body):
    if headers is None:
        headers = gate()
    return client.post(f"/api/admin/hosts/{name}/mute",
                       content=json.dumps(body), headers=headers)


def unmute(client, name="box", headers=None):
    if headers is None:
        headers = gate()
    return client.post(f"/api/admin/hosts/{name}/unmute", headers=headers)


def muted_at(name, when):
    """Whether a live mute covers this server at `when`, read on a connection
    of its own. A fresh connection is the point: it is the same read the sweep
    and the renderer do in their own processes, so a row that only exists in
    the request's transaction fails here."""
    con = db.connect()
    try:
        row = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()
        assert row is not None, f"no host named {name!r}"
        return finding_alerts.silenced(con, row["id"], "tcp", 443, "v4",
                                       now=when) == finding_alerts.SILENCE_MUTE
    finally:
        con.close()


def live_rows(name):
    """Every silence still standing against this server.

    A database with no `alert_silences` table has none, which is the state a
    refused request leaves behind: the body is checked before anything is
    created, so nothing was ever muted here.
    """
    con = db.connect()
    try:
        if con.execute("SELECT name FROM sqlite_master WHERE type='table'"
                       " AND name='alert_silences'").fetchone() is None:
            return []
        return con.execute(
            "SELECT s.* FROM alert_silences s JOIN hosts h ON h.id = s.host_id"
            " WHERE h.name = ? AND s.cleared_at IS NULL ORDER BY s.id",
            (name,)).fetchall()
    finally:
        con.close()


# --- the gate ---

@pytest.mark.parametrize("path", ["/api/admin/hosts/box/mute",
                                  "/api/admin/hosts/box/unmute"])
def test_muting_without_any_proof_is_403(client, path):
    """Fail closed, like every other admin route. Neither the Caddy gate header
    nor a session, so no."""
    assert client.post(path, content=json.dumps({"seconds": HOUR})
                       ).status_code == 403


@pytest.mark.parametrize("path", ["/api/admin/hosts/box/mute",
                                  "/api/admin/hosts/box/unmute"])
def test_a_refused_call_mutes_nothing(client, path):
    create(client, "box")
    assert client.post(path, content=json.dumps({"seconds": HOUR})
                       ).status_code == 403
    assert live_rows("box") == []


def signed_in_operator():
    """A browser signed in as a real operator, carrying only its session
    cookie. The forward_auth path, the same fixture tests/test_admin.py uses."""
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if accounts.get_user_by_email(con, "operator@example.com") is None:
        accounts.create_user(con, "operator@example.com", "correct-horse-battery-9")
    user = accounts.get_user_by_email(con, "operator@example.com")
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def test_mute_and_unmute_accept_a_session_with_no_gate_header(client):
    """The whole admin surface has to work under a deploy that proxies
    /api/admin/* without basic auth, and these two are part of it."""
    op = signed_in_operator()
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "sbox"})).status_code == 201
    assert op.post("/api/admin/hosts/sbox/mute",
                   content=json.dumps({"seconds": HOUR})).status_code == 204
    assert op.post("/api/admin/hosts/sbox/unmute").status_code == 204


# --- which server ---

def test_muting_an_unknown_host_is_404(client):
    assert mute(client, "ghost", seconds=HOUR).status_code == 404
    assert unmute(client, "ghost").status_code == 404


def test_muting_a_revoked_host_is_404(client):
    """Nothing new is measured for it, so there is nothing to keep quiet. The
    same answer an unknown name gets, so this route cannot be used to ask
    which names were revoked."""
    create(client, "box")
    assert client.post("/api/admin/hosts/box/revoke",
                       headers=gate()).status_code == 204
    assert mute(client, "box", seconds=HOUR).status_code == 404
    assert unmute(client, "box").status_code == 404
    assert live_rows("box") == []


def in_workspace(email, workspace_id):
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


@pytest.mark.parametrize("path,body", [
    ("/api/admin/hosts/mine/mute", json.dumps({"seconds": HOUR})),
    ("/api/admin/hosts/mine/mute", json.dumps({"indefinite": True})),
    ("/api/admin/hosts/mine/unmute", "{}"),
])
def test_a_session_cannot_mute_another_workspaces_host(client, path, body):
    """404, the same answer a name nobody enrolled gets, and the neighbour's
    server is not touched on the way past."""
    assert create(client, "mine").status_code == 201
    op = in_workspace("two@example.com", 2)
    assert op.post(path, content=body).status_code == 404
    assert live_rows("mine") == []


def test_a_session_can_mute_its_own_workspaces_host(client):
    """The other half: scoping refuses the neighbour and changes nothing about
    your own."""
    op = in_workspace("two@example.com", 2)
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "theirs"})).status_code == 201
    assert op.post("/api/admin/hosts/theirs/mute",
                   content=json.dumps({"seconds": HOUR})).status_code == 204
    assert muted_at("theirs", datetime.now(timezone.utc) + timedelta(minutes=30))


def test_muting_one_server_leaves_its_neighbour_mailing(client):
    create(client, "box")
    create(client, "other")
    assert mute(client, "box", seconds=HOUR).status_code == 204
    soon = datetime.now(timezone.utc) + timedelta(minutes=1)
    assert muted_at("box", soon)
    assert not muted_at("other", soon)


# --- the body ---

@pytest.mark.parametrize("body", ["not json", "", "[1, 2]", '"a string"', "7"])
def test_a_body_that_is_not_an_object_is_400(client, body):
    create(client, "box")
    resp = client.post("/api/admin/hosts/box/mute", content=body, headers=gate())
    assert resp.status_code == 400
    assert live_rows("box") == []


def test_a_body_that_is_not_utf8_is_400(client):
    """Bytes that never reach the JSON parser. The older host routes answer 500
    to these, which is named in app/ingest.py as its own fix, and a route added
    after that note must not repeat it."""
    create(client, "box")
    resp = client.post("/api/admin/hosts/box/mute", content=b"\xff\xfe",
                       headers=gate())
    assert resp.status_code == 400


@pytest.mark.parametrize("body", [
    {},                                  # no length at all
    {"seconds": None},
    {"seconds": "3600"},                 # text that looks like a number
    {"seconds": 3600.5},                 # not a whole number of them
    {"seconds": True},                   # a bool is an int in Python, not here
    {"seconds": 0},
    {"seconds": -1},
    {"seconds": -HOUR},
    {"indefinite": "yes"},
    {"indefinite": 1},
    {"seconds": HOUR, "indefinite": True},   # two answers, so no answer
    {"seconds": 0, "indefinite": True},
])
def test_a_length_that_is_not_a_length_is_400(client, body):
    create(client, "box")
    assert mute(client, "box", **body).status_code == 400
    assert live_rows("box") == []


def test_a_mute_longer_than_a_year_is_refused(client):
    """An expiry is a date and date arithmetic overflows, so an unbounded
    number would be a 500 anybody could ask for. Past a year the honest control
    is the one that carries no expiry."""
    create(client, "box")
    assert mute(client, "box",
                seconds=ingest.MAX_MUTE_SECONDS + 1).status_code == 400
    assert mute(client, "box", seconds=10 ** 20).status_code == 400
    assert live_rows("box") == []
    # and the boundary itself is allowed
    assert mute(client, "box", seconds=ingest.MAX_MUTE_SECONDS).status_code == 204


def test_indefinite_false_still_needs_a_number(client):
    """Saying it is not indefinite says nothing about how long it is."""
    create(client, "box")
    assert mute(client, "box", indefinite=False).status_code == 400
    assert mute(client, "box", indefinite=False,
                seconds=HOUR).status_code == 204


def test_an_unknown_field_is_ignored(client):
    """Only the two fields are read. Anything else beside them is not a reason
    to refuse a request that already said how long."""
    create(client, "box")
    assert mute(client, "box", seconds=HOUR, colour="blue").status_code == 204


# --- what the menu offers ---

@pytest.mark.parametrize("seconds", [HOUR, 8 * HOUR, 24 * HOUR])
def test_each_length_the_menu_offers_is_stored_and_expires(client, seconds):
    """The three timed choices on the button. Each one is live inside its own
    window and gone after it, read back on a connection of its own."""
    create(client, "box")
    assert mute(client, "box", seconds=seconds).status_code == 204
    start = datetime.now(timezone.utc)
    assert muted_at("box", start + timedelta(seconds=seconds - 60))
    assert not muted_at("box", start + timedelta(seconds=seconds + 60))


def test_a_stored_mute_carries_the_expiry_it_was_asked_for(client):
    create(client, "box")
    assert mute(client, "box", seconds=8 * HOUR).status_code == 204
    rows = live_rows("box")
    assert len(rows) == 1
    until = datetime.fromisoformat(rows[0]["until"])
    wanted = datetime.now(timezone.utc) + timedelta(hours=8)
    assert abs((until - wanted).total_seconds()) < 60


def test_an_indefinite_mute_stores_no_expiry_and_never_lapses(client):
    """"Until I turn it back on" is a row with no `until`, which is what a NULL
    there already means to the reader in app/finding_alerts.py, and the same
    thing a permanent per-port silence has always written."""
    create(client, "box")
    assert mute(client, "box", indefinite=True).status_code == 204
    rows = live_rows("box")
    assert len(rows) == 1
    assert rows[0]["until"] is None
    assert muted_at("box", datetime.now(timezone.utc) + timedelta(days=4000))


def test_muting_twice_leaves_one_live_mute(client):
    """A second choice from the menu replaces the first rather than stacking a
    row behind it, or one unmute would lift half a mute."""
    create(client, "box")
    assert mute(client, "box", seconds=HOUR).status_code == 204
    assert mute(client, "box", seconds=24 * HOUR).status_code == 204
    assert len(live_rows("box")) == 1
    assert muted_at("box", datetime.now(timezone.utc) + timedelta(hours=12))


def test_a_timed_mute_can_be_replaced_by_an_indefinite_one(client):
    create(client, "box")
    assert mute(client, "box", seconds=HOUR).status_code == 204
    assert mute(client, "box", indefinite=True).status_code == 204
    rows = live_rows("box")
    assert len(rows) == 1 and rows[0]["until"] is None


# --- unmute ---

def test_unmute_lifts_a_timed_mute(client):
    create(client, "box")
    assert mute(client, "box", seconds=24 * HOUR).status_code == 204
    assert unmute(client, "box").status_code == 204
    assert not muted_at("box", datetime.now(timezone.utc) + timedelta(minutes=1))
    assert live_rows("box") == []


def test_unmute_lifts_an_indefinite_mute(client):
    """The half that matters: a mute with no expiry has no other way to end."""
    create(client, "box")
    assert mute(client, "box", indefinite=True).status_code == 204
    assert unmute(client, "box").status_code == 204
    assert not muted_at("box", datetime.now(timezone.utc) + timedelta(days=4000))


def test_unmuting_something_that_was_not_muted_is_still_204(client):
    """The state the caller asked for is the state that holds, and a mute that
    expired a minute before the click is not an error to show anybody."""
    create(client, "box")
    assert unmute(client, "box").status_code == 204
    assert unmute(client, "box").status_code == 204


def test_unmute_ignores_whatever_body_it_is_given(client):
    """It takes no arguments, so nothing in a body can change what it does and
    a broken one cannot stop it. The way back must be the reliable half."""
    create(client, "box")
    assert mute(client, "box", indefinite=True).status_code == 204
    resp = client.post("/api/admin/hosts/box/unmute", content="not json",
                       headers=gate())
    assert resp.status_code == 204
    assert not muted_at("box", datetime.now(timezone.utc))


def test_a_mute_and_an_unmute_leave_the_history_readable(client):
    """Withdrawn rather than deleted, the rule app/finding_alerts.py applies to
    every silence, so what was muted and when stays readable."""
    create(client, "box")
    mute(client, "box", seconds=HOUR)
    unmute(client, "box")
    con = db.connect()
    rows = con.execute("SELECT * FROM alert_silences ORDER BY id").fetchall()
    con.close()
    assert len(rows) == 1
    assert rows[0]["cleared_at"] is not None


# --- muting is not pausing ---

def test_muting_does_not_pause_the_host(client):
    """Two controls over two different things. Pausing suppresses the alert
    about a silent agent, muting suppresses the letter about a finding, and
    neither may quietly do the other's job."""
    create(client, "box")
    assert mute(client, "box", indefinite=True).status_code == 204
    con = db.connect()
    row = con.execute("SELECT paused FROM hosts WHERE name='box'").fetchone()
    con.close()
    assert row["paused"] == 0


def test_pausing_does_not_mute_the_host(client):
    create(client, "box")
    assert client.post("/api/admin/hosts/box/pause",
                       content=json.dumps({"paused": True}),
                       headers=gate()).status_code == 204
    assert live_rows("box") == []


# --- the tables these routes need ---

def test_muting_works_on_a_database_the_sweep_has_never_run_against(client):
    """The silences table is not created by db.init, and the ingest process may
    well be the first thing on a fresh box to want it. A 500 here would mean
    the button works only after some other command has been run."""
    create(client, "box")
    con = db.connect()
    existing = con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
        " AND name='alert_silences'").fetchone()
    con.close()
    assert existing is None, "something else already made the table"
    assert mute(client, "box", seconds=HOUR).status_code == 204
