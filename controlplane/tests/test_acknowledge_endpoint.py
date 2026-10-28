"""Reviewing one port: the acknowledge endpoint, its gate, and its refusals.

    python -m pytest tests/test_acknowledge_endpoint.py

The route exists because the owner read the host page on 2026-08-24 and said the
header button was in the wrong place. What gets reviewed is a line of a
firewall rule and not a whole server (docs/RECORD.md 4.101). The store already
agreed with him, so this is the store's own key made reachable from a browser
and nothing wider.

The mutations these are built to catch, in the order they matter:

  1. **Acknowledging a finding nobody produced.** The state is read from the
     join engine, never taken from the request, so a port with no finding and a
     port with no state are both refused and neither is stored.
  2. **Widening the key.** A call names one protocol, one port and one address
     family, and acknowledging one family must leave the other on the list.
  3. **Reaching somebody else's server.** The route is scoped to the operator's
     own workspace, and a host outside it answers exactly what an unknown name
     answers.
  4. **Pretending a review is permanent.** The state changes, the
     acknowledgement lapses, and the finding comes back.

The fixture and the gate pattern are test_admin.py's, read there first.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import (accounts, db, ingest, intent, join, prober, store,
                 web_auth)
from operator_gate import gate


HOST = "box"
TARGET = "203.0.113.5"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def path(host=HOST, protocol="tcp", port=22, family="v4"):
    return f"/api/admin/hosts/{host}/ports/{protocol}/{port}/{family}/acknowledge"


def socket_row(port, family="v4", protocol="tcp"):
    return {"protocol": protocol, "family": family,
            "bind_address": "0.0.0.0" if family == "v4" else "::",
            "port": port, "process_name": "sshd", "pid": 1}


def document(sockets=()):
    """A host document with the two sections the join engine needs to reach a
    state at all: what is listening, and the host firewall."""
    return {
        "schema_version": 1,
        "hostname": HOST,
        "collected_at_unix": 1_700_000_000,
        "sockets": {"status": "collected", "listening": list(sockets)},
        "nftables": {"status": "collected", "tables": []},
    }


def seed(client, sockets=(), probed=(), name=HOST):
    """One host with one document, and whatever the outside view measured.

    `probed` is (family, port, prober state) and an empty one means the prober
    has never run, which is the everyday shape on a fresh box.
    """
    client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                headers=gate())
    con = db.connect()
    db.init(con)
    prober.init(con)
    intent.init(con)
    host = store.active_host_by_name(con, name)
    doc = document(sockets)
    store.insert_report(con, host["id"], doc["collected_at_unix"], 1,
                        json.dumps(doc))
    if probed:
        cur = con.execute(
            "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
            " VALUES (?, ?, ?, ?)",
            (host["id"], "test-vantage", "2026-08-24T12:00:00+00:00",
             "2026-08-24T12:00:00+00:00"))
        for family, port, state in probed:
            con.execute(
                "INSERT INTO probe_results (run_id, target, family, port, state,"
                " reason, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (cur.lastrowid, TARGET, family, port, state, None,
                 "2026-08-24T12:00:00+00:00"))
    con.commit()
    con.close()
    return host["id"]


def reachable(client, port=22, family="v4", name=HOST):
    """A host with one listening port the outside view really reached, which is
    the only shape in which a state above `_decide`'s line exists."""
    return seed(client, sockets=[socket_row(port, family=family)],
                probed=[(family, port, prober.STATE_CONNECTED)], name=name)


def finding(host_id, protocol="tcp", port=22, family="v4"):
    """One finding straight from the join engine, so a test asserts on the
    state the screen would show rather than on the row this route wrote."""
    con = db.connect()
    result = join.host_findings(con, host_id)
    con.close()
    for one in result.findings:
        if (one.protocol, one.port, one.family) == (protocol, port, family):
            return one
    raise AssertionError(
        f"no finding for {protocol}/{port} on {family} in "
        f"{[(f.protocol, f.port, f.family) for f in result.findings]}")


# ----------------------------------------------------------------- the gate

def test_acknowledge_without_the_gate_header_is_403(client):
    assert client.post(path()).status_code == 403


def test_the_gate_is_checked_before_the_arguments(client):
    """A caller who has proved nothing learns nothing, not even that the port
    was unreadable."""
    assert client.post(path(port="http")).status_code == 403


# --------------------------------------------------------- what is refused

def test_acknowledge_of_an_unknown_host_is_404(client):
    assert client.post(path(host="ghost"), headers=gate()).status_code == 404


def test_acknowledge_of_a_revoked_host_is_404(client):
    """Revoked and unknown 404 identically, the same as the other admin
    routes."""
    reachable(client)
    client.post(f"/api/admin/hosts/{HOST}/revoke", headers=gate())
    assert client.post(path(), headers=gate()).status_code == 404


def test_a_host_in_another_workspace_is_404(client):
    """The session decides the workspace and the request never does. An
    operator signed in to their own workspace cannot review a port on a server
    that is not theirs, and the answer is the one an unknown name gets."""
    reachable(client)  # workspace 1, the basic-auth path
    con = db.connect()
    db.init(con)
    accounts.init(con)
    other = db.create_workspace(con, "second")
    accounts.create_user(con, "somebody@example.com", "correct-horse-battery-9",
                         workspace_id=other)
    user = accounts.get_user_by_email(con, "somebody@example.com")
    assert accounts.workspace_of(user) == other
    token, _ = accounts.issue_session(con, user["id"])
    con.commit()
    con.close()
    stranger = TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})
    assert stranger.post(path()).status_code == 404


@pytest.mark.parametrize("port", ["http", "", "0", "70000", "22.0", "-1",
                                  "٤٤٣", " 22"])
def test_a_port_that_is_not_a_port_is_400(client, port):
    """Every one of these has reached a store as a port at some point in some
    product. "٤٤٣" is here because `str.isdigit` is true for it and `int`
    accepts it, so a URL nobody typed would otherwise act on 443."""
    reachable(client)
    resp = client.post(path(port=port), headers=gate())
    # An empty segment does not match the route at all, which is also a refusal
    # and is the one answer of the set that is not 400.
    assert resp.status_code in (400, 404)
    if resp.status_code == 400:
        assert resp.json()["detail"]


@pytest.mark.parametrize("protocol", ["icmp", "TCP-ish", "sctp"])
def test_a_protocol_the_store_does_not_hold_is_400(client, protocol):
    reachable(client)
    resp = client.post(path(protocol=protocol), headers=gate())
    assert resp.status_code == 400
    assert "protocol" in resp.json()["detail"]


@pytest.mark.parametrize("family", ["v5", "ipv4", "inet"])
def test_an_address_family_the_store_does_not_hold_is_400(client, family):
    reachable(client)
    resp = client.post(path(family=family), headers=gate())
    assert resp.status_code == 400
    assert "family" in resp.json()["detail"]


def test_a_port_nothing_has_raised_is_a_refusal_and_not_a_500(client):
    """Nothing listens on 9999, nothing published it and nothing probed it, so
    there is no finding to file against and the answer says so."""
    reachable(client)
    resp = client.post(path(port=9999), headers=gate())
    assert resp.status_code == 409
    assert resp.json()["detail"] == "nothing has raised tcp/9999 on v4"


def test_a_port_with_no_state_is_a_refusal_and_not_a_silent_success(client):
    """docs/PRODUCT.md 8a: a port whose evidence supports none of the five
    states has no state at all. The prober never ran here, so tcp/22 is on the
    page with an empty State cell, and there is nothing to acknowledge."""
    host_id = seed(client, sockets=[socket_row(22)])
    assert finding(host_id).state is None

    resp = client.post(path(), headers=gate())
    assert resp.status_code == 409
    assert resp.json()["detail"] == "tcp/22 on v4 has no state"

    con = db.connect()
    stored = intent.list_acknowledgements(con)
    con.close()
    assert stored == []


def test_a_refused_acknowledge_stores_nothing_on_the_other_family_either(client):
    """A refusal is a refusal for the whole call. Nothing part-succeeds."""
    seed(client, sockets=[socket_row(22)])
    client.post(path(family="v6"), headers=gate())
    con = db.connect()
    stored = intent.list_acknowledgements(con)
    con.close()
    assert stored == []


# ------------------------------------------------------ what is recorded

def test_a_successful_acknowledge_is_204_with_an_empty_body(client):
    reachable(client)
    resp = client.post(path(), headers=gate())
    assert resp.status_code == 204
    assert resp.content == b""


def test_it_records_the_state_that_was_really_there(client):
    """The state is read from the join engine, never taken from the caller, so
    what is stored is the finding that existed at the moment of the click."""
    host_id = reachable(client)
    assert finding(host_id).state == join.STATE_UNREVIEWED

    client.post(path(), headers=gate())

    con = db.connect()
    rows = intent.list_acknowledgements(con)
    con.close()
    assert [(r["host_name"], r["protocol"], r["port"], r["family"], r["state"])
            for r in rows] == [(HOST, "tcp", 22, "v4", join.STATE_UNREVIEWED)]


def test_the_finding_carries_the_acknowledgement_after_the_call(client):
    """What the screen reads. `acknowledged` is set and the state is untouched,
    because an acknowledgement is not an intent and decides nothing."""
    host_id = reachable(client)
    client.post(path(), headers=gate())
    after = finding(host_id)
    assert after.acknowledged
    assert after.state == join.STATE_UNREVIEWED


def test_acknowledging_one_family_leaves_the_other_on_the_list(client):
    """The key includes the address family. Reviewing v4 says nothing about
    v6, at the store and again at the join."""
    host_id = seed(
        client,
        sockets=[socket_row(22, family="v4"), socket_row(22, family="v6")],
        probed=[("v4", 22, prober.STATE_CONNECTED),
                ("v6", 22, prober.STATE_CONNECTED)])
    client.post(path(family="v4"), headers=gate())
    assert finding(host_id, family="v4").acknowledged
    assert finding(host_id, family="v6").acknowledged is None


def test_acknowledging_one_port_leaves_its_neighbour_on_the_list(client):
    host_id = seed(client,
                   sockets=[socket_row(22), socket_row(443)],
                   probed=[("v4", 22, prober.STATE_CONNECTED),
                           ("v4", 443, prober.STATE_CONNECTED)])
    client.post(path(port=22), headers=gate())
    assert finding(host_id, port=22).acknowledged
    assert finding(host_id, port=443).acknowledged is None


def test_a_second_acknowledge_replaces_the_first_and_leaves_one_live_row(client):
    """The store keeps one live acknowledgement per port per family. Clicking
    twice must not leave two."""
    reachable(client)
    assert client.post(path(), headers=gate()).status_code == 204
    assert client.post(path(), headers=gate()).status_code == 204
    con = db.connect()
    rows = intent.list_acknowledgements(con)
    con.close()
    assert len(rows) == 1


# ------------------------------------------------------------ and it lapses

def test_a_state_change_lapses_the_acknowledgement(client):
    """An acknowledgement is about a finding, not about a port. Declaring the
    port closed turns `unreviewed` into `conflict`, which is a different
    finding, so the review stops applying and the port is back on the list.

    This is the property the screen must not contradict: nothing there may
    imply a review is permanent.
    """
    host_id = reachable(client)
    client.post(path(), headers=gate())
    assert finding(host_id).acknowledged

    con = db.connect()
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    con.close()

    after = finding(host_id)
    assert after.state == join.STATE_CONFLICT
    assert after.acknowledged is None
    # The row is still in the table, holding the state it was filed against.
    # Lapsed is not deleted, and going back to `unreviewed` brings it back.
    con = db.connect()
    rows = intent.list_acknowledgements(con)
    intent.clear(con, HOST, "tcp", 22, "v4")
    con.close()
    assert [r["state"] for r in rows] == [join.STATE_UNREVIEWED]
    assert finding(host_id).acknowledged


def test_reviewing_the_new_state_puts_the_finding_back_under_review(client):
    """After a lapse the same control files against the state that is there
    now, which is the whole reason the route reads the state rather than
    taking one."""
    host_id = reachable(client)
    client.post(path(), headers=gate())
    con = db.connect()
    intent.declare(con, HOST, "tcp", 22, "v4", intent.INTENT_CLOSED)
    con.close()

    assert client.post(path(), headers=gate()).status_code == 204
    after = finding(host_id)
    assert after.state == join.STATE_CONFLICT
    assert after.acknowledged


# --------------------------------------------------------- the other proof

def test_a_signed_in_operator_can_review_their_own_port(client):
    """The forward_auth path: no gate header, a real session cookie, and the
    workspace comes from the session. The same proof every other admin route
    takes."""
    con = db.connect()
    db.init(con)
    accounts.init(con)
    accounts.create_user(con, "operator@example.com", "correct-horse-battery-9")
    user = accounts.get_user_by_email(con, "operator@example.com")
    token, _ = accounts.issue_session(con, user["id"])
    con.commit()
    con.close()
    signed_in = TestClient(ingest.app,
                           cookies={web_auth.SESSION_COOKIE: token})
    host_id = reachable(client)

    assert signed_in.post(path()).status_code == 204
    assert finding(host_id).acknowledged
