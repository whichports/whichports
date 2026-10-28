"""The address routes: adding a server without an agent, and proving the
addresses it may be probed on, through the dashboard's admin surface. The
proof logic itself is app/authz.py's and is reviewed in test_authz.py; what
is reviewed here is that the routes add the operator gate and the workspace
fence and nothing else."""
import json

import pytest
from fastapi.testclient import TestClient

from app import accounts, authz, db, ingest, store
from operator_gate import gate

ADDRESS = "185.199.108.153"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def post(client, path, body=None, headers=None):
    if headers is None:
        headers = gate()
    return client.post(path, content=json.dumps(body if body is not None else {}),
                       headers=headers)


def add_address_host(client, name="outside-only"):
    return post(client, "/api/admin/hosts", {"name": name, "kind": "address"})


def start(client, name="outside-only", address=ADDRESS, method="http-token"):
    return post(client, f"/api/admin/hosts/{name}/addresses",
                {"address": address, "method": method})


# --- adding the host ---

def test_an_address_host_is_created_without_a_credential_or_a_command(client):
    r = add_address_host(client)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body == {"name": "outside-only", "kind": "address"}
    con = db.connect()
    row = con.execute("SELECT kind, token_hash FROM hosts WHERE name = 'outside-only'").fetchone()
    con.close()
    assert row["kind"] == "address" and row["token_hash"] is None


def test_an_agent_host_says_so_and_keeps_its_commands(client):
    r = post(client, "/api/admin/hosts", {"name": "box"})
    assert r.status_code == 201
    body = r.json()
    assert body["kind"] == "agent"
    assert body["credential"].startswith(store.CREDENTIAL_PREFIX)
    assert "install_command" in body and "install_command_full_visibility" not in body


def test_an_unknown_kind_is_refused(client):
    r = post(client, "/api/admin/hosts", {"name": "box", "kind": "magic"})
    assert r.status_code == 400
    assert "kind must be one of" in r.json()["detail"]


def test_an_address_host_needs_a_name(client):
    r = post(client, "/api/admin/hosts", {"kind": "address"})
    assert r.status_code == 400


def test_an_address_host_name_must_be_free(client):
    assert add_address_host(client, "taken").status_code == 201
    assert add_address_host(client, "taken").status_code == 409


# --- the gate ---

@pytest.mark.parametrize("method,path", [
    ("GET", "/api/admin/hosts/x/addresses"),
    ("POST", "/api/admin/hosts/x/addresses"),
    ("POST", "/api/admin/hosts/x/addresses/1/verify"),
    ("POST", "/api/admin/hosts/x/addresses/revoke"),
])
def test_every_address_route_is_behind_the_operator_gate(client, method, path):
    r = client.request(method, path, content="{}")
    assert r.status_code in (401, 403), r.status_code


# --- starting a proof ---

def test_start_returns_the_token_once_and_where_to_publish_it(client):
    add_address_host(client)
    r = start(client)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["address"] == ADDRESS and body["family"] == "v4"
    assert body["method"] == "http-token"
    assert body["publish_at"] == f"http://{ADDRESS}:80{authz.HTTP_WELL_KNOWN_PATH}"
    assert body["token"] and body["expires_at"]
    # only the hash is stored
    con = db.connect()
    stored = con.execute("SELECT token_hash, host_id FROM authz_challenges").fetchone()
    con.close()
    assert stored["token_hash"] != body["token"]
    assert stored["host_id"] is not None


def test_start_with_dns_names_the_reverse_pointer(client):
    add_address_host(client)
    body = start(client, method="dns-txt").json()
    assert body["publish_at"].endswith(".in-addr.arpa")


@pytest.mark.parametrize("body,fragment", [
    ({"address": ADDRESS}, "method must be one of"),
    ({"address": ADDRESS, "method": "carrier-pigeon"}, "method must be one of"),
    ({"method": "http-token"}, "address is required"),
    ({"address": "   ", "method": "http-token"}, "address is required"),
])
def test_start_refuses_a_bad_request_plainly(client, body, fragment):
    add_address_host(client)
    r = post(client, "/api/admin/hosts/outside-only/addresses", body)
    assert r.status_code == 400
    assert fragment in r.json()["detail"]


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "100.64.1.1", "not-an-ip", "::1"])
def test_start_refuses_an_address_that_can_never_be_a_target(client, address):
    """The registry's own refusal, surfaced as a 400 with its reason."""
    add_address_host(client)
    r = start(client, address=address)
    assert r.status_code == 400, r.text


def test_start_for_an_unknown_or_revoked_host_is_404(client):
    assert start(client, name="nobody").status_code == 404
    add_address_host(client, "gone")
    post(client, "/api/admin/hosts/gone/revoke")
    assert start(client, name="gone").status_code == 404


def test_an_agent_host_may_prove_an_address_too(client):
    """Tier 2 contains tier 1: an agent host may also be probed on an address
    its operator proves, not only on what its documents claim."""
    post(client, "/api/admin/hosts", {"name": "box"})
    assert start(client, name="box").status_code == 201


# --- verifying ---

def test_verify_records_the_authorisation_for_this_host(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: challenge["token"])
    r = post(client, f"/api/admin/hosts/outside-only/addresses/{challenge['id']}/verify")
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True
    con = db.connect()
    host = store.active_host_by_name(con, "outside-only")
    live = authz.live_addresses_for_host(con, host["id"])
    assert [row["target"] for row in live] == [ADDRESS]
    assert authz.may_probe(con, ADDRESS).allowed
    con.close()


def test_verify_with_the_wrong_token_is_an_answer_not_an_error(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: "something else")
    r = post(client, f"/api/admin/hosts/outside-only/addresses/{challenge['id']}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and "not found" in body["detail"]
    con = db.connect()
    assert not authz.may_probe(con, ADDRESS).allowed
    con.close()


def test_verify_when_the_evidence_cannot_be_read_says_so(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    def boom(url, timeout=0):
        raise authz.ProofError("could not read http://x: connection refused")
    monkeypatch.setattr(authz, "fetch_token_file", boom)
    r = post(client, f"/api/admin/hosts/outside-only/addresses/{challenge['id']}/verify")
    assert r.status_code == 200
    assert r.json()["ok"] is False and "could not read" in r.json()["detail"]


def test_verify_of_another_hosts_challenge_is_404(client):
    add_address_host(client, "mine")
    add_address_host(client, "theirs")
    challenge = start(client, name="mine").json()
    r = post(client, f"/api/admin/hosts/theirs/addresses/{challenge['id']}/verify")
    assert r.status_code == 404


def test_verify_of_a_missing_challenge_is_404(client):
    add_address_host(client)
    assert post(client, "/api/admin/hosts/outside-only/addresses/999/verify").status_code == 404


# --- listing ---

def test_the_listing_shows_live_proofs_and_open_challenges(client, monkeypatch):
    add_address_host(client)
    proved = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: proved["token"])
    post(client, f"/api/admin/hosts/outside-only/addresses/{proved['id']}/verify")
    pending = start(client, address="185.199.109.153", method="dns-txt").json()
    r = client.get("/api/admin/hosts/outside-only/addresses", headers=gate())
    assert r.status_code == 200
    body = r.json()
    assert [a["address"] for a in body["authorizations"]] == [ADDRESS]
    assert body["authorizations"][0]["live"] is True
    # the secret itself never comes back, only its consequences
    assert proved["token"] not in json.dumps(body)
    assert pending["token"] not in json.dumps(body)
    assert [c["id"] for c in body["open_challenges"]] == [pending["id"]]


def test_the_listing_is_empty_for_a_fresh_host_and_404_for_a_stranger(client):
    add_address_host(client)
    r = client.get("/api/admin/hosts/outside-only/addresses", headers=gate())
    assert r.json() == {"authorizations": [], "open_challenges": []}
    assert client.get("/api/admin/hosts/nobody/addresses", headers=gate()).status_code == 404


# --- revoking ---

def test_revoke_stops_probing_at_once_and_shows_in_the_listing(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: challenge["token"])
    post(client, f"/api/admin/hosts/outside-only/addresses/{challenge['id']}/verify")
    r = post(client, "/api/admin/hosts/outside-only/addresses/revoke", {"address": ADDRESS})
    assert r.status_code == 204
    con = db.connect()
    assert not authz.may_probe(con, ADDRESS).allowed
    con.close()
    listing = client.get("/api/admin/hosts/outside-only/addresses", headers=gate()).json()
    assert listing["authorizations"][0]["live"] is False
    assert listing["authorizations"][0]["revoked_at"] is not None


def test_revoke_wants_an_address(client):
    add_address_host(client)
    assert post(client, "/api/admin/hosts/outside-only/addresses/revoke", {}).status_code == 400
    assert post(client, "/api/admin/hosts/outside-only/addresses/revoke",
                {"address": "nonsense"}).status_code == 400


# --- the workspace fence ---

def signed_in(client, email, workspace_id):
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if accounts.get_user_by_email(con, email) is None:
        accounts.create_user(con, email, "correct-horse-battery-9",
                             workspace_id=workspace_id)
    user = accounts.get_user_by_email(con, email)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    from app import web_auth
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def test_another_workspace_cannot_see_start_verify_or_revoke_my_addresses(client, monkeypatch):
    add_address_host(client)  # workspace 1, via the gate header
    challenge = start(client).json()
    con = db.connect(); db.init(con)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', 't')")
    con.commit(); con.close()
    other = signed_in(client, "other@example.com", 2)
    assert other.get("/api/admin/hosts/outside-only/addresses").status_code == 404
    assert other.post("/api/admin/hosts/outside-only/addresses",
                      content=json.dumps({"address": ADDRESS, "method": "http-token"})).status_code == 404
    assert other.post(f"/api/admin/hosts/outside-only/addresses/{challenge['id']}/verify").status_code == 404
    assert other.post("/api/admin/hosts/outside-only/addresses/revoke",
                      content=json.dumps({"address": ADDRESS})).status_code == 404


# --- one token for a server (docs/RECORD.md 4.329) ---
#
# The rule itself is app/authz.py's and is reviewed in test_authz_one_token.py.
# What is reviewed here is that the route hands the registry the server and
# its own workspace's account, so the token it answers is that server's and
# nobody else's.

SECOND_ADDRESS = "2606:50c0:8000::153"


def proved(client, monkeypatch, name="outside-only", address=ADDRESS):
    challenge = start(client, name=name, address=address).json()
    monkeypatch.setattr(authz, "fetch_token_file",
                        lambda url, timeout=0: challenge["token"])
    r = post(client, f"/api/admin/hosts/{name}/addresses/{challenge['id']}/verify")
    assert r.json()["ok"] is True, r.text
    return challenge


def test_a_second_address_of_a_server_is_answered_with_the_same_token(client, monkeypatch):
    add_address_host(client)
    first = proved(client, monkeypatch)

    r = start(client, address=SECOND_ADDRESS)

    assert r.status_code == 201, r.text
    second = r.json()
    assert second["token"] == first["token"]
    assert second["id"] != first["id"]
    assert second["family"] == "v6"
    assert second["publish_at"] == \
        f"http://[{SECOND_ADDRESS}]:80{authz.HTTP_WELL_KNOWN_PATH}"
    # Asked for by DNS, the same address gets a token of its own.
    by_dns = start(client, address=SECOND_ADDRESS, method="dns-txt").json()
    assert by_dns["token"] != first["token"]


def test_a_servers_token_is_never_answered_for_another_server(client, monkeypatch):
    add_address_host(client)
    first = proved(client, monkeypatch)

    # Another server in the same workspace.
    add_address_host(client, name="neighbour")
    neighbour = start(client, name="neighbour", address=SECOND_ADDRESS).json()
    assert neighbour["token"] != first["token"]

    # A server in another workspace, asked for by that workspace's own user.
    con = db.connect(); db.init(con)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', 't')")
    con.commit()
    store.add_address_host(con, "theirs", workspace_id=2)
    con.close()
    other = signed_in(client, "other@example.com", 2)
    r = other.post("/api/admin/hosts/theirs/addresses",
                   content=json.dumps({"address": SECOND_ADDRESS, "method": "http-token"}))
    assert r.status_code == 201, r.text
    assert r.json()["token"] not in (first["token"], neighbour["token"])
