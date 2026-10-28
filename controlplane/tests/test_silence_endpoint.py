"""Silence and unsilence one port, the two routes behind the alert row's menu.

    python -m pytest tests/test_silence_endpoint.py

The store and every rule about what a silence means are `app/finding_alerts.py`'s
and `tests/test_finding_alerts.py` is where they are checked. This is the door in
front of them, and it is the same door `tests/test_mute_endpoint.py` describes for
the pair beside it: who may open it, what a path may say, and which server the
answer is about.

The mutations these are built to catch:

  1. **A silence that does not survive the process.** The menu item paints
     itself immediately, so if the row is not really there the screen is the
     only place the silence ever existed. Every one is read back on a second
     connection.
  2. **A silence wider than the port it was asked for.** It is keyed per
     protocol, per port and per address family, and silencing tcp/443 on v6
     must leave tcp/443 on v4 and tcp/80 on v6 alerting. A silence that
     quietly covered a whole server is the failure that loses an alert
     nobody knows they stopped getting.
  3. **A silence that closes the alert.** It stops the mail and nothing else.
     An open alert stays open, because a route that resolved it would be this
     product hiding a live finding on a click.
  4. **Reaching somebody else's server.** The same 404 the other admin routes
     give, for unknown, revoked and another workspace's alike.
  5. **A port that cannot be one.** The path carries three fields the store
     normalises, and a refusal must be the store's own sentence rather than a
     500 from inside it.
"""

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import accounts, alerts, db, finding_alerts, ingest, web_auth
from operator_gate import gate


NOW = datetime(2026, 8, 29, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def create(client, name):
    return client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate())


def path_for(name, protocol, port, family, action):
    return f"/api/admin/hosts/{name}/ports/{protocol}/{port}/{family}/{action}"


def silence(client, name="box", protocol="tcp", port=443, family="v6",
            headers=None):
    if headers is None:
        headers = gate()
    return client.post(path_for(name, protocol, port, family, "silence"),
                       headers=headers)


def unsilence(client, name="box", protocol="tcp", port=443, family="v6",
              headers=None):
    if headers is None:
        headers = gate()
    return client.post(path_for(name, protocol, port, family, "unsilence"),
                       headers=headers)


def silenced_at(name, protocol="tcp", port=443, family="v6", when=NOW):
    """The kind of silence covering this port at `when`, read on a connection
    of its own.

    A fresh connection is the point, the same reason `test_mute_endpoint.py`
    opens one: it is the read the sweep does in its own process, so a row that
    only existed inside the request's transaction fails here.
    """
    con = db.connect()
    try:
        row = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()
        assert row is not None, f"no host named {name!r}"
        return finding_alerts.silenced(con, row["id"], protocol, port, family,
                                       now=when)
    finally:
        con.close()


def live_rows(name):
    """Every silence still standing against this server.

    A database with no `alert_silences` table has none, which is the state a
    refused request leaves behind: the gate is checked before anything is
    created, so nothing was ever silenced here.
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

@pytest.mark.parametrize("action", ["silence", "unsilence"])
def test_silencing_without_any_proof_is_403(client, action):
    """Fail closed, like every other admin route. Neither the Caddy gate
    header nor a session, so no."""
    assert client.post(path_for("box", "tcp", 443, "v6", action)
                       ).status_code == 403


@pytest.mark.parametrize("action", ["silence", "unsilence"])
def test_a_refused_call_silences_nothing(client, action):
    create(client, "box")
    assert client.post(path_for("box", "tcp", 443, "v6", action)
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


def test_both_routes_accept_a_session_with_no_gate_header(client):
    """The whole admin surface has to work under a deploy that proxies
    /api/admin/* without basic auth, and these two are part of it."""
    op = signed_in_operator()
    assert op.post("/api/admin/hosts",
                   content=json.dumps({"name": "sbox"})).status_code == 201
    assert op.post(path_for("sbox", "tcp", 443, "v6", "silence")
                   ).status_code == 204
    assert op.post(path_for("sbox", "tcp", 443, "v6", "unsilence")
                   ).status_code == 204


# --- it reaches the store, and it survives the process ---

def test_a_silenced_port_is_quiet_on_a_second_connection(client):
    create(client, "box")
    assert silence(client).status_code == 204
    assert silenced_at("box") == finding_alerts.SILENCE_PORT


def test_unsilencing_lets_the_port_alert_again(client):
    create(client, "box")
    assert silence(client).status_code == 204
    assert unsilence(client).status_code == 204
    assert silenced_at("box") is None


def test_a_silence_never_expires(client):
    """Permanent is what the word means (`docs/PRODUCT.md` 4c), so the row
    carries no expiry at all rather than a far-future one."""
    create(client, "box")
    assert silence(client).status_code == 204
    rows = live_rows("box")
    assert len(rows) == 1
    assert rows[0]["until"] is None
    assert rows[0]["kind"] == finding_alerts.SILENCE_PORT


def test_silencing_twice_leaves_one_live_row(client):
    """The store withdraws any live silence before writing its own, so a
    double click cannot leave two rows that both have to be lifted."""
    create(client, "box")
    assert silence(client).status_code == 204
    assert silence(client).status_code == 204
    assert len(live_rows("box")) == 1


def test_unsilencing_a_port_that_was_never_silenced_is_204(client):
    """The answer is about the state the caller asked for, and that state
    holds either way. The same answer `admin_unmute_host` gives."""
    create(client, "box")
    assert unsilence(client).status_code == 204
    assert silenced_at("box") is None


# --- it covers the port it was asked for, and nothing beside it ---

@pytest.mark.parametrize("protocol,port,family", [
    ("tcp", 443, "v4"),
    ("tcp", 80, "v6"),
    ("udp", 443, "v6"),
])
def test_silencing_one_port_leaves_its_neighbours_alerting(client, protocol,
                                                           port, family):
    """v4 and v6 are separate silences and so are tcp and udp on the same
    number, for the same reason they are separate declarations
    (`docs/PRODUCT.md` 4b)."""
    create(client, "box")
    assert silence(client, protocol="tcp", port=443, family="v6").status_code == 204
    assert silenced_at("box", protocol, port, family) is None


def test_a_silence_is_not_a_mute(client):
    """`silenced` answers with the kind, and the two words mean different
    things on a screen: a mute is the whole server for a couple of hours, a
    silence is one port until somebody takes it back."""
    create(client, "box")
    assert silence(client).status_code == 204
    assert silenced_at("box") != finding_alerts.SILENCE_MUTE


# --- it does not close anything ---

def test_silencing_leaves_an_open_alert_open(client):
    """A silence stops the mail and nothing else. Closing the alert here
    would be this product hiding a live finding on a click, and the port's own
    row would then disagree with the alerts screen."""
    create(client, "box")
    con = db.connect()
    db.init(con)
    alerts.init(con)
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'box'"
                          ).fetchone()["id"]
    alerts.raise_alert(con, host_id, finding_alerts.KIND_FINDING,
                       "tcp/443 on v6 had no state, now unreviewed", NOW,
                       subject=finding_alerts.subject_for("tcp", 443, "v6"))
    con.commit()
    con.close()

    assert silence(client).status_code == 204

    con = db.connect()
    try:
        still_open = con.execute(
            "SELECT resolved_at, suppressed_at FROM alerts WHERE host_id = ?",
            (host_id,)).fetchone()
    finally:
        con.close()
    assert still_open["resolved_at"] is None
    assert still_open["suppressed_at"] is None


# --- which server ---

@pytest.mark.parametrize("action", ["silence", "unsilence"])
def test_an_unknown_host_is_404(client, action):
    assert client.post(path_for("ghost", "tcp", 443, "v6", action),
                       headers=gate()).status_code == 404


@pytest.mark.parametrize("action", ["silence", "unsilence"])
def test_a_revoked_host_is_404(client, action):
    """Nothing new is measured for it, so there is nothing to keep quiet. The
    same answer an unknown name gets, so this route cannot be used to ask
    which names were revoked."""
    create(client, "box")
    assert client.post("/api/admin/hosts/box/revoke",
                       headers=gate()).status_code == 204
    assert client.post(path_for("box", "tcp", 443, "v6", action),
                       headers=gate()).status_code == 404
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


@pytest.mark.parametrize("action", ["silence", "unsilence"])
def test_another_workspaces_server_is_404(client, action):
    """The host lookup is the whole of the scoping on these two routes, the
    same as the acknowledge and declare routes they sit beside."""
    mine = in_workspace("mine@example.com", 1)
    theirs = in_workspace("theirs@example.com", 2)
    assert mine.post("/api/admin/hosts",
                     content=json.dumps({"name": "mybox"})).status_code == 201
    assert theirs.post(path_for("mybox", "tcp", 443, "v6", action)
                       ).status_code == 404
    assert live_rows("mybox") == []


# --- a port that cannot be one ---

@pytest.mark.parametrize("action", ["silence", "unsilence"])
@pytest.mark.parametrize("protocol,port,family", [
    ("sctp", 443, "v6"),
    ("tcp", 0, "v6"),
    ("tcp", 70000, "v6"),
    ("tcp", "https", "v6"),
    ("tcp", 443, "v9"),
])
def test_a_port_that_cannot_be_one_is_400(client, action, protocol, port,
                                          family):
    """The path goes through `intent.normalise`, the same door the acknowledge
    and declare routes use, and its refusal carries that module's own sentence
    rather than becoming a 500 from inside the store."""
    create(client, "box")
    response = client.post(path_for("box", protocol, port, family, action),
                           headers=gate())
    assert response.status_code == 400
    assert response.json()["detail"]
    assert live_rows("box") == []
