"""The provider token per workspace, through the four admin routes.

Connect, Replace token, Read now and Disconnect, each scoped to the session's
workspace like every write, none of them ever returning the token, and a
fake provider standing in for Hetzner so nothing here touches the network.
"""
import json

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, hetzner, ingest, web_auth
from operator_gate import gate

TOKEN = "hzread" + "k" * 58  # the shape of a real one, 64 characters


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


class FakeProvider:
    """One provider, answering with a fixed inventory or a typed refusal, and
    remembering which token it was built with."""

    def __init__(self, fail=None, servers=2, firewalls=1):
        self.fail, self.servers, self.firewalls = fail, servers, firewalls
        self.tokens = []
        self.rate_limit = type("R", (), {"remaining": 3000})()

    def factory(self, token, opener=None):
        self.tokens.append(token)
        return self

    def fetch_snapshot(self):
        if self.fail:
            raise self.fail
        from datetime import datetime, timezone
        return hetzner.Snapshot(fetched_at=datetime.now(timezone.utc).isoformat(),
                                servers=tuple({"id": i, "name": f"s{i}", "public_net": {}}
                                              for i in range(self.servers)),
                                firewalls=tuple({"id": i, "name": f"fw{i}"}
                                                for i in range(self.firewalls)))


def in_workspace(email, workspace_id):
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if db.workspace_by_id(con, workspace_id) is None:
        con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)",
                    (workspace_id, f"ws{workspace_id}", "2026-09-14T00:00:00+00:00"))
        con.commit()
    if accounts.get_user_by_email(con, email) is None:
        accounts.create_user(con, email, "correct-horse-battery-9", workspace_id=workspace_id)
    user = accounts.get_user_by_email(con, email)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def connect(c, token=TOKEN, path="/api/admin/integrations/hetzner"):
    return c.post(path, content=json.dumps({"token": token}),
                  headers={"Content-Type": "application/json"})


def stored(workspace_id):
    con = db.connect()
    try:
        hetzner.init(con)
        return (hetzner.token_for(con, workspace_id),
                hetzner.latest_snapshot(con, workspace_id=workspace_id),
                hetzner.latest_fetch(con, workspace_id=workspace_id))
    finally:
        con.close()


# ------------------------------------------------------------------ connect


def test_connect_stores_the_token_reads_at_once_and_answers_without_the_token(client, monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    answer = client.post(
        "/api/admin/integrations/hetzner", content=json.dumps({"token": TOKEN}),
        headers=gate(**{"Content-Type": "application/json"}))
    assert answer.status_code == 201, answer.text
    body = answer.json()
    assert body["status"] == "connected"
    assert body["token_hint"] == "…" + TOKEN[-4:]
    assert body["servers"] == 2 and body["firewalls"] == 1
    assert TOKEN not in answer.text
    assert fake.tokens == [TOKEN], "the provider was read with the token just stored"
    token, snapshot, fetch = stored(1)
    assert token == TOKEN and snapshot is not None and fetch["error_kind"] is None


def test_a_refused_token_is_stored_and_the_refusal_is_answered_with_its_status(client, monkeypatch):
    fake = FakeProvider(fail=hetzner.ProviderError(hetzner.ERROR_UNAUTHORIZED, status=401))
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    answer = client.post("/api/admin/integrations/hetzner", content=json.dumps({"token": TOKEN}),
                         headers=gate(**{"Content-Type": "application/json"}))
    assert answer.status_code == 201
    body = answer.json()
    assert body["status"] == "refused" and body["http_status"] == 401 and body["kind"] == "unauthorized"
    assert TOKEN not in answer.text
    token, snapshot, fetch = stored(1)
    assert token == TOKEN and snapshot is None
    assert (fetch["error_kind"], fetch["error_status"]) == ("unauthorized", 401)


def test_a_network_failure_is_failed_not_refused(client, monkeypatch):
    fake = FakeProvider(fail=hetzner.ProviderError(hetzner.ERROR_NETWORK))
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    body = client.post("/api/admin/integrations/hetzner", content=json.dumps({"token": TOKEN}),
                       headers=gate(**{"Content-Type": "application/json"})).json()
    assert body["status"] == "failed" and body["kind"] == "network"


@pytest.mark.parametrize("bad", [{"token": ""}, {"token": "   "}, {"token": 5}, {},
                                 {"token": "with space"}, {"token": "a" * 257}, "not json"])
def test_a_token_that_cannot_be_stored_is_400_and_nothing_is_stored_or_read(client, monkeypatch, bad):
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    answer = client.post("/api/admin/integrations/hetzner",
                         content=json.dumps(bad) if not isinstance(bad, str) else bad,
                         headers=gate(**{"Content-Type": "application/json"}))
    assert answer.status_code == 400
    assert fake.tokens == []
    assert stored(1)[0] == ""


def test_the_refusal_never_echoes_the_token(client, monkeypatch):
    monkeypatch.setattr(ingest, "hetzner_client", FakeProvider().factory)
    answer = client.post("/api/admin/integrations/hetzner", content=json.dumps({"token": "sp ace"}),
                         headers=gate(**{"Content-Type": "application/json"}))
    assert answer.status_code == 400 and "sp ace" not in answer.text


# ---------------------------------------------------------- the other acts


def test_replace_token_stores_the_new_one_and_reads_with_it(client, monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    client.post("/api/admin/integrations/hetzner", content=json.dumps({"token": TOKEN}),
                headers=gate(**{"Content-Type": "application/json"}))
    new = TOKEN[::-1]
    answer = client.post("/api/admin/integrations/hetzner/token", content=json.dumps({"token": new}),
                         headers=gate(**{"Content-Type": "application/json"}))
    assert answer.status_code == 200 and answer.json()["token_hint"] == "…" + new[-4:]
    assert fake.tokens == [TOKEN, new]
    assert stored(1)[0] == new


def test_read_now_reads_with_the_stored_token(client, monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    client.post("/api/admin/integrations/hetzner", content=json.dumps({"token": TOKEN}),
                headers=gate(**{"Content-Type": "application/json"}))
    fake.servers = 5
    answer = client.post("/api/admin/integrations/hetzner/read", headers=gate())
    assert answer.status_code == 200 and answer.json()["servers"] == 5
    assert fake.tokens == [TOKEN, TOKEN]
    assert TOKEN not in answer.text


def test_read_now_with_nothing_connected_is_404(client, monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    assert client.post("/api/admin/integrations/hetzner/read", headers=gate()).status_code == 404
    assert fake.tokens == []


def test_disconnect_takes_everything_of_this_workspace_and_is_204(client, monkeypatch):
    monkeypatch.setattr(ingest, "hetzner_client", FakeProvider().factory)
    client.post("/api/admin/integrations/hetzner", content=json.dumps({"token": TOKEN}),
                headers=gate(**{"Content-Type": "application/json"}))
    assert client.post("/api/admin/integrations/hetzner/disconnect", headers=gate()).status_code == 204
    assert stored(1) == ("", None, None)
    assert client.post("/api/admin/integrations/hetzner/disconnect", headers=gate()).status_code == 404


# --------------------------------------------------- one workspace, one token


def test_no_workspace_sees_or_touches_another_workspaces_provider(client, monkeypatch):
    """The property the whole change exists for. Workspace 1 connects; a
    session in workspace 2 has no provider, reads nothing, cannot read with
    workspace 1's token, and its disconnect drops nothing of workspace 1's."""
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    one = in_workspace("one@example.com", 1)
    two = in_workspace("two@example.com", 2)
    assert connect(one).status_code == 201
    assert two.post("/api/admin/integrations/hetzner/read").status_code == 404
    assert two.post("/api/admin/integrations/hetzner/disconnect").status_code == 404
    assert stored(1)[0] == TOKEN and stored(2)[0] == ""
    # and workspace 2 connecting its own token never touches workspace 1's
    other = "other-" + "z" * 58
    assert connect(two, other).status_code == 201
    assert stored(1)[0] == TOKEN and stored(2)[0] == other
    assert fake.tokens == [TOKEN, other]
    assert stored(1)[1] is not None and stored(2)[1] is not None
    assert two.post("/api/admin/integrations/hetzner/disconnect").status_code == 204
    assert stored(1) != ("", None, None) and stored(2) == ("", None, None)


@pytest.mark.parametrize("path", ["/api/admin/integrations/hetzner",
                                  "/api/admin/integrations/hetzner/token",
                                  "/api/admin/integrations/hetzner/read",
                                  "/api/admin/integrations/hetzner/disconnect"])
def test_every_act_needs_a_session(client, monkeypatch, path):
    fake = FakeProvider()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    answer = client.post(path, content=json.dumps({"token": TOKEN}),
                         headers={"Content-Type": "application/json", "X-Admin-Gate": "x"})
    assert answer.status_code == 403
    assert fake.tokens == [] and stored(1)[0] == ""


def test_the_client_the_routes_build_can_only_get():
    """The routes read through app/hetzner.py's client and nothing else, so
    SI-3 holds here the way tests/test_hetzner.py proves it there."""
    assert ingest.hetzner_client is hetzner.client_for


# ------------------------------------------------- several tokens, one each
#
# Since 2026-09-27 a workspace holds one token per project (docs/RECORD.md
# 4.206). Connect adds, and the other three acts name a token by its id, or
# act on the workspace's only one.

SECOND = "second" + "p" * 58
THIRD = "third" + "r" * 59


def post(c, path, body=None):
    return c.post(path, content=json.dumps(body) if body is not None else b"",
                  headers=gate(**{"Content-Type": "application/json"}))


def held(workspace_id=1):
    con = db.connect()
    try:
        hetzner.init(con)
        return [(t["id"], hetzner.token_for(con, workspace_id, t["id"]))
                for t in hetzner.tokens(con, workspace_id)]
    finally:
        con.close()


def snapshot_names(workspace_id, token_id):
    con = db.connect()
    try:
        hetzner.init(con)
        snap = hetzner.latest_snapshot(con, workspace_id=workspace_id, token_id=token_id)
        return None if snap is None else [s["name"] for s in snap.servers]
    finally:
        con.close()


class TwoProjects(FakeProvider):
    """Each token reads its own project, so a test can tell whose read landed
    where."""

    def factory(self, token, opener=None):
        self.tokens.append(token)
        self.current = token
        return self

    def fetch_snapshot(self):
        from datetime import datetime, timezone
        return hetzner.Snapshot(fetched_at=datetime.now(timezone.utc).isoformat(),
                                servers=({"id": len(self.current), "name": self.current[:6],
                                          "public_net": {}},),
                                firewalls=())


def test_a_second_connect_adds_a_token_beside_the_first(client, monkeypatch):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    first = post(client, "/api/admin/integrations/hetzner", {"token": TOKEN})
    second = post(client, "/api/admin/integrations/hetzner", {"token": SECOND})
    assert first.status_code == 201 and second.status_code == 201
    one, two = first.json()["token_id"], second.json()["token_id"]
    assert one != two
    assert second.json()["token_hint"] == "…" + SECOND[-4:]
    assert held() == [(one, TOKEN), (two, SECOND)], "the first token is still held"
    assert snapshot_names(1, one) == [TOKEN[:6]] and snapshot_names(1, two) == [SECOND[:6]]
    assert TOKEN not in second.text and SECOND not in second.text


def test_connecting_a_token_already_held_reads_with_it_and_adds_nothing(client, monkeypatch):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    first = post(client, "/api/admin/integrations/hetzner", {"token": TOKEN}).json()
    again = post(client, "/api/admin/integrations/hetzner", {"token": TOKEN})
    assert again.status_code == 201 and again.json()["token_id"] == first["token_id"]
    assert len(held()) == 1 and fake.tokens == [TOKEN, TOKEN]


def test_replace_read_and_disconnect_act_on_the_token_they_name(client, monkeypatch):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    one = post(client, "/api/admin/integrations/hetzner", {"token": TOKEN}).json()["token_id"]
    two = post(client, "/api/admin/integrations/hetzner", {"token": SECOND}).json()["token_id"]

    replaced = post(client, "/api/admin/integrations/hetzner/token",
                    {"token": THIRD, "token_id": two})
    assert replaced.status_code == 200 and replaced.json()["token_id"] == two
    assert held() == [(one, TOKEN), (two, THIRD)]
    assert snapshot_names(1, two) == [THIRD[:6]], "read at once with the new value"
    assert snapshot_names(1, one) == [TOKEN[:6]], "the other token's read is untouched"

    fake.tokens.clear()
    read = post(client, "/api/admin/integrations/hetzner/read", {"token_id": one})
    assert read.status_code == 200 and read.json()["token_id"] == one
    assert fake.tokens == [TOKEN]

    gone = post(client, "/api/admin/integrations/hetzner/disconnect", {"token_id": one})
    assert gone.status_code == 204
    assert held() == [(two, THIRD)]
    assert snapshot_names(1, one) is None and snapshot_names(1, two) == [THIRD[:6]]


@pytest.mark.parametrize("path, body", [
    ("/api/admin/integrations/hetzner/token", {"token": THIRD}),
    ("/api/admin/integrations/hetzner/read", None),
    ("/api/admin/integrations/hetzner/read", {}),
    ("/api/admin/integrations/hetzner/disconnect", None),
])
def test_with_several_tokens_an_act_that_names_none_is_asked_which(client, monkeypatch, path, body):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    post(client, "/api/admin/integrations/hetzner", {"token": TOKEN})
    post(client, "/api/admin/integrations/hetzner", {"token": SECOND})
    before = held()
    fake.tokens.clear()
    answer = post(client, path, body)
    assert answer.status_code == 400
    assert held() == before and fake.tokens == [], "nothing replaced, read or dropped"


@pytest.mark.parametrize("named", [999, "1", True, 1.0, None])
def test_a_token_this_workspace_does_not_hold_is_404(client, monkeypatch, named):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    post(client, "/api/admin/integrations/hetzner", {"token": TOKEN})
    post(client, "/api/admin/integrations/hetzner", {"token": SECOND})
    before = held()
    fake.tokens.clear()
    body = {"token_id": named}
    if named is None:
        # null is "named none", which with two tokens is the question above
        assert post(client, "/api/admin/integrations/hetzner/read", body).status_code == 400
        return
    for path in ("/api/admin/integrations/hetzner/read",
                 "/api/admin/integrations/hetzner/disconnect"):
        assert post(client, path, body).status_code == 404, path
    assert post(client, "/api/admin/integrations/hetzner/token",
                {**body, "token": THIRD}).status_code == 404
    assert held() == before and fake.tokens == []


def test_another_workspaces_token_id_is_the_same_404_as_none(client, monkeypatch):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    one = in_workspace("one@example.com", 1)
    two = in_workspace("two@example.com", 2)
    theirs = connect(one).json()["token_id"]
    connect(two, SECOND)
    fake.tokens.clear()
    for path in ("/api/admin/integrations/hetzner/read",
                 "/api/admin/integrations/hetzner/disconnect"):
        answer = two.post(path, content=json.dumps({"token_id": theirs}),
                          headers={"Content-Type": "application/json"})
        assert answer.status_code == 404, path
    answer = two.post("/api/admin/integrations/hetzner/token",
                      content=json.dumps({"token_id": theirs, "token": THIRD}),
                      headers={"Content-Type": "application/json"})
    assert answer.status_code == 404
    assert fake.tokens == [] and held(1) == [(theirs, TOKEN)]


def test_replacing_with_a_value_another_token_holds_is_400_and_changes_nothing(client, monkeypatch):
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    one = post(client, "/api/admin/integrations/hetzner", {"token": TOKEN}).json()["token_id"]
    post(client, "/api/admin/integrations/hetzner", {"token": SECOND})
    before = held()
    answer = post(client, "/api/admin/integrations/hetzner/token",
                  {"token": SECOND, "token_id": one})
    assert answer.status_code == 400 and SECOND not in answer.text
    assert held() == before


def test_read_and_disconnect_with_no_body_act_on_the_only_token(client, monkeypatch):
    """How the screen sent them while a workspace could hold one token."""
    fake = TwoProjects()
    monkeypatch.setattr(ingest, "hetzner_client", fake.factory)
    only = post(client, "/api/admin/integrations/hetzner", {"token": TOKEN}).json()["token_id"]
    answer = client.post("/api/admin/integrations/hetzner/read", headers=gate())
    assert answer.status_code == 200 and answer.json()["token_id"] == only
    assert client.post("/api/admin/integrations/hetzner/disconnect",
                       headers=gate()).status_code == 204
    assert held() == []
