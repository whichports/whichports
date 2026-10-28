"""Telling a host which ports to watch, over HTTP.

    python -m pytest tests/test_ports_endpoint.py

**The tier this unblocks.** A host with no agent sends no document, so the
ports its probe plan covers come from the joined set alone (`app/dispatch.py`):
what the operator declared, plus what a previous pass measured. A host that has
neither has an empty set, `app/prober_cli.py` refuses to hand an empty plan to
the engine, and the host sits on "not probed yet" for ever. Until these routes
there was no way to give it the first half, so the agentless tier shipped and
could not be exercised. The last test in this file walks the whole chain and is
the one that proves it works.

The mutations these are built to catch, in the order they matter:

  1. **Reaching somebody else's server.** The routes are scoped to the
     operator's own workspace, and a host outside it answers exactly what an
     unknown name answers.
  2. **Storing something the vocabulary does not hold.** The port, the
     protocol, the address family and the intent word all go through
     `app/intent.py`'s own doors and a refusal carries that module's sentence.
  3. **Widening the key.** One call names one protocol, one port and one
     address family, and declaring one family leaves the other alone.
  4. **Losing a declaration on the way.** Declaring twice replaces rather than
     duplicates, and clearing what was never declared is not an error.

The fixture and the gate pattern are test_admin.py's, read there first.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app import (accounts, authz, db, dispatch, ingest, intent, prober,
                 prober_cli, store, web_auth)
from operator_gate import gate


HOST = "outside-only"
V4 = "185.199.108.153"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def declare_path(host=HOST, protocol="tcp", port=443, family="v4"):
    return f"/api/admin/hosts/{host}/ports/{protocol}/{port}/{family}/declare"


def clear_path(host=HOST, protocol="tcp", port=443, family="v4"):
    return f"/api/admin/hosts/{host}/ports/{protocol}/{port}/{family}/clear"


def list_path(host=HOST):
    return f"/api/admin/hosts/{host}/ports"


def address_host(client, name=HOST):
    """One host with no agent, made the way the add-server window makes it."""
    resp = client.post("/api/admin/hosts",
                       content=json.dumps({"name": name, "kind": "address"}),
                       headers=gate())
    assert resp.status_code == 201, resp.text
    return resp.json()


def agent_host(client, name="box"):
    resp = client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate())
    assert resp.status_code == 201, resp.text
    return resp.json()


def declare(client, value="open", **kwargs):
    return client.post(declare_path(**kwargs),
                       content=json.dumps({"intent": value}), headers=gate())


def live(name=HOST):
    """The live declarations for one host, straight out of the store, so a
    test asserts on what was written rather than on what a route said."""
    con = db.connect()
    intent.init(con)
    rows = intent.list_declarations(con, name)
    out = {(row["protocol"], row["port"], row["family"]): row["intent"]
           for row in rows}
    con.close()
    return out


# ----------------------------------------------------------------- the gate

def test_declare_without_the_gate_header_is_403(client):
    assert client.post(declare_path()).status_code == 403


def test_clear_without_the_gate_header_is_403(client):
    assert client.post(clear_path()).status_code == 403


def test_listing_without_the_gate_header_is_403(client):
    assert client.get(list_path()).status_code == 403


def test_the_gate_is_checked_before_the_arguments(client):
    """A caller who has proved nothing learns nothing, not even that the port
    was unreadable."""
    assert client.post(declare_path(port="http")).status_code == 403


def test_a_session_is_proof_enough_without_the_header(client):
    """The forward_auth path. The same proof every other admin route takes."""
    address_host(client)
    con = db.connect()
    db.init(con)
    accounts.init(con)
    accounts.create_user(con, "sysadmin@example.com", "correct-horse-battery-9")
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    token, _ = accounts.issue_session(con, user["id"])
    con.commit()
    con.close()
    signed_in = TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})
    assert signed_in.post(declare_path(),
                          content=json.dumps({"intent": "open"})).status_code == 204


# --------------------------------------------------------- what is refused

def test_declaring_on_an_unknown_host_is_404(client):
    assert declare(client, host="ghost").status_code == 404


def test_clearing_on_an_unknown_host_is_404(client):
    assert client.post(clear_path(host="ghost"), headers=gate()).status_code == 404


def test_listing_an_unknown_host_is_404(client):
    assert client.get(list_path("ghost"), headers=gate()).status_code == 404


def test_a_revoked_host_is_404_on_all_three(client):
    """Revoked and unknown 404 identically, the same as the other admin
    routes."""
    address_host(client)
    assert client.post(f"/api/admin/hosts/{HOST}/revoke",
                       headers=gate()).status_code == 204
    assert declare(client).status_code == 404
    assert client.post(clear_path(), headers=gate()).status_code == 404
    assert client.get(list_path(), headers=gate()).status_code == 404


def test_a_host_in_another_workspace_is_404(client):
    """The session decides the workspace and the request never does. An
    operator signed in to their own workspace cannot declare a port on a
    server that is not theirs, and the answer is the one an unknown name
    gets."""
    address_host(client)  # workspace 1, the basic-auth path
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
    assert stranger.post(declare_path(),
                         content=json.dumps({"intent": "open"})).status_code == 404
    assert stranger.post(clear_path()).status_code == 404
    assert stranger.get(list_path()).status_code == 404
    # and nothing was written on the way past
    assert live() == {}


@pytest.mark.parametrize("port", ["http", "", "0", "70000", "443.0", "-1",
                                  "٤٤٣", " 443", "+443", "0x1bb"])
def test_a_port_that_is_not_a_port_is_refused(client, port):
    """Every one of these has reached a store as a port at some point in some
    product. "٤٤٣" is here because `str.isdigit` is true for it and `int`
    accepts it, so a URL nobody typed would otherwise act on 443."""
    address_host(client)
    resp = declare(client, port=port)
    # An empty segment does not match the route at all, which is also a
    # refusal and is the one answer of the set that is not 400.
    assert resp.status_code in (400, 404)
    if resp.status_code == 400:
        assert resp.json()["detail"]
    assert live() == {}


@pytest.mark.parametrize("protocol", ["icmp", "TCP-ish", "sctp", "%20"])
def test_a_protocol_the_store_does_not_hold_is_400(client, protocol):
    address_host(client)
    resp = declare(client, protocol=protocol)
    assert resp.status_code == 400
    assert "protocol" in resp.json()["detail"]


@pytest.mark.parametrize("family", ["v5", "ipv4", "inet"])
def test_an_address_family_the_store_does_not_hold_is_400(client, family):
    address_host(client)
    resp = declare(client, family=family)
    assert resp.status_code == 400
    assert "family" in resp.json()["detail"]


@pytest.mark.parametrize("value", [None, "", "OPEN-ish", "yes", "reachable",
                                   "intended", 1, True, ["open"], {"a": 1}])
def test_an_intent_the_store_does_not_hold_is_400(client, value):
    """`open` and `closed` are the whole vocabulary. `intended` is in the list
    because it is one of the join engine's five state words, and a caller who
    confuses the two must be refused rather than have one silently read as the
    other."""
    address_host(client)
    resp = client.post(declare_path(), content=json.dumps({"intent": value}),
                       headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"]
    assert live() == {}


def test_a_body_that_is_not_json_is_400(client):
    address_host(client)
    resp = client.post(declare_path(), content=b"{not json", headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not JSON"


def test_a_body_that_is_not_utf8_is_400_rather_than_a_500(client):
    address_host(client)
    resp = client.post(declare_path(), content=b"\xff\xfe", headers=gate())
    assert resp.status_code == 400


def test_a_body_that_is_not_an_object_is_400(client):
    address_host(client)
    for body in ("[]", '"open"', "null", "3"):
        resp = client.post(declare_path(), content=body, headers=gate())
        assert resp.status_code == 400, body


def test_an_empty_body_is_400_and_not_a_500(client):
    address_host(client)
    assert client.post(declare_path(), headers=gate()).status_code == 400


def test_the_arguments_are_checked_before_the_host_is_looked_up(client):
    """A caller who is an operator of some workspace may learn that "http" is
    not a port, whatever host name they aimed it at. That is a fact about
    their own request and never about which names exist."""
    assert declare(client, host="ghost", port="http").status_code == 400


# ------------------------------------------------------------ what is stored

def test_a_declaration_is_stored_under_the_key_the_path_names(client):
    address_host(client)
    assert declare(client, port=443, family="v4", value="open").status_code == 204
    assert live() == {("tcp", 443, "v4"): "open"}


def test_closed_is_stored_as_itself(client):
    """Both words count. A port declared closed is a person saying it should
    not answer, which is the half where a conflict comes from."""
    address_host(client)
    assert declare(client, value="closed").status_code == 204
    assert live() == {("tcp", 443, "v4"): "closed"}


def test_udp_is_stored_because_the_store_holds_it(client):
    address_host(client)
    assert declare(client, protocol="udp", port=1194).status_code == 204
    assert live() == {("udp", 1194, "v4"): "open"}


@pytest.mark.parametrize("port", [1, 65535])
def test_the_ends_of_the_port_range_are_accepted(client, port):
    address_host(client)
    assert declare(client, port=port).status_code == 204
    assert live() == {("tcp", port, "v4"): "open"}


def test_declaring_one_family_leaves_the_other_undeclared(client):
    """The key is per family, so v6 is not decided by a v4 call."""
    address_host(client)
    declare(client, family="v4")
    assert live() == {("tcp", 443, "v4"): "open"}


def test_the_two_families_are_two_declarations(client):
    address_host(client)
    declare(client, family="v4", value="open")
    declare(client, family="v6", value="closed")
    assert live() == {("tcp", 443, "v4"): "open",
                      ("tcp", 443, "v6"): "closed"}


def test_declaring_twice_replaces_rather_than_duplicates(client):
    address_host(client)
    declare(client, value="open")
    declare(client, value="closed")
    assert live() == {("tcp", 443, "v4"): "closed"}


def test_the_protocol_and_family_are_normalised_the_way_the_store_does(client):
    """`TCP` and `tcp` cannot become two rows for one port."""
    address_host(client)
    assert declare(client, protocol="TCP", family="V4").status_code == 204
    assert declare(client, protocol="tcp", family="v4",
                   value="closed").status_code == 204
    assert live() == {("tcp", 443, "v4"): "closed"}


def test_the_intent_word_is_normalised_the_way_the_store_does(client):
    address_host(client)
    assert client.post(declare_path(), content=json.dumps({"intent": " OPEN "}),
                       headers=gate()).status_code == 204
    assert live() == {("tcp", 443, "v4"): "open"}


def test_an_agent_host_can_be_declared_against_too(client):
    """The route is about a port, not about a tier. Declaring on a host that
    does send a document is what `python -m app.intent_cli` has always
    allowed, and nothing here narrows it."""
    agent_host(client, "box")
    assert declare(client, host="box", port=22).status_code == 204
    assert live("box") == {("tcp", 22, "v4"): "open"}


def test_the_declaration_is_recorded_against_the_workspace(client):
    """The account column is the workspace, the same rule
    `authz.account_for_workspace` sets, so a declaration cannot be filed under
    somebody else's account."""
    address_host(client)
    declare(client)
    con = db.connect()
    row = con.execute("SELECT account FROM port_intents"
                      " WHERE cleared_at IS NULL").fetchone()
    con.close()
    assert row["account"] == authz.account_for_workspace(db.DEFAULT_WORKSPACE_ID)


# ----------------------------------------------------------------- clearing

def test_clearing_withdraws_the_declaration(client):
    address_host(client)
    declare(client)
    assert client.post(clear_path(), headers=gate()).status_code == 204
    assert live() == {}


def test_clearing_what_was_never_declared_is_204(client):
    """The caller asked for this port to carry no declaration and it carries
    none either way, the answer unmute gives and for the same reason."""
    address_host(client)
    assert client.post(clear_path(), headers=gate()).status_code == 204
    assert live() == {}


def test_clearing_twice_is_204_both_times(client):
    address_host(client)
    declare(client)
    assert client.post(clear_path(), headers=gate()).status_code == 204
    assert client.post(clear_path(), headers=gate()).status_code == 204
    assert live() == {}


def test_clearing_one_family_leaves_the_other_declared(client):
    address_host(client)
    declare(client, family="v4")
    declare(client, family="v6")
    client.post(clear_path(family="v4"), headers=gate())
    assert live() == {("tcp", 443, "v6"): "open"}


def test_clearing_one_port_leaves_the_others_declared(client):
    address_host(client)
    declare(client, port=443)
    declare(client, port=22)
    client.post(clear_path(port=443), headers=gate())
    assert live() == {("tcp", 22, "v4"): "open"}


def test_a_cleared_declaration_stays_in_the_table_as_history(client):
    """History rather than deletion, the posture `app/intent.py` takes."""
    address_host(client)
    declare(client)
    client.post(clear_path(), headers=gate())
    con = db.connect()
    rows = con.execute("SELECT cleared_at FROM port_intents").fetchall()
    con.close()
    assert len(rows) == 1 and rows[0]["cleared_at"]


def test_declaring_after_clearing_starts_a_second_live_row(client):
    address_host(client)
    declare(client)
    client.post(clear_path(), headers=gate())
    declare(client, value="closed")
    assert live() == {("tcp", 443, "v4"): "closed"}
    con = db.connect()
    count = con.execute("SELECT COUNT(*) AS n FROM port_intents").fetchone()["n"]
    con.close()
    assert count == 2


@pytest.mark.parametrize("port", ["http", "70000"])
def test_clearing_a_port_that_is_not_a_port_is_400(client, port):
    address_host(client)
    assert client.post(clear_path(port=port), headers=gate()).status_code == 400


# ----------------------------------------------------------------- listing

def test_a_host_with_no_declarations_lists_none(client):
    address_host(client)
    resp = client.get(list_path(), headers=gate())
    assert resp.status_code == 200
    assert resp.json() == {"declarations": []}


def test_the_listing_carries_every_part_of_the_key(client):
    address_host(client)
    declare(client, port=443, family="v4", value="open")
    rows = client.get(list_path(), headers=gate()).json()["declarations"]
    assert len(rows) == 1
    row = rows[0]
    assert row["protocol"] == "tcp" and row["port"] == 443
    assert row["family"] == "v4" and row["intent"] == "open"
    assert row["declared_at"]


def test_the_listing_holds_only_this_host(client):
    address_host(client, HOST)
    address_host(client, "other")
    declare(client, host=HOST, port=443)
    declare(client, host="other", port=22)
    ports = [row["port"]
             for row in client.get(list_path(), headers=gate()).json()["declarations"]]
    assert ports == [443]


def test_a_cleared_declaration_is_not_listed(client):
    address_host(client)
    declare(client)
    client.post(clear_path(), headers=gate())
    assert client.get(list_path(), headers=gate()).json()["declarations"] == []


def test_the_listing_is_ordered_by_port(client):
    address_host(client)
    for port in (8443, 22, 443):
        declare(client, port=port)
    ports = [row["port"]
             for row in client.get(list_path(), headers=gate()).json()["declarations"]]
    assert ports == [22, 443, 8443]


def test_the_listing_answers_on_a_database_the_store_never_ran_against(client):
    """`port_intents` arrives after the four tables production already had, so
    a box where only the ingest has ever run has no such table and the listing
    must still answer."""
    address_host(client)
    con = db.connect()
    con.execute("DROP TABLE IF EXISTS port_intents")
    con.commit()
    con.close()
    assert client.get(list_path(), headers=gate()).json() == {"declarations": []}


# ------------------------------------------------ the chain this unblocks
#
# The point of the whole change, walked end to end: a host with no agent, an
# address its operator proved control of, one declared port, and a plan the
# engine would really be handed.

def prove_an_address(name=HOST, address=V4):
    con = db.connect()
    db.init(con)
    authz.init(con)
    host = store.active_host_by_name(con, name)
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN,
                                  account=authz.account_for_host(host),
                                  host_id=host["id"])
    result = authz.verify_proof(con, challenge.id,
                                fetcher=lambda url, timeout=0: challenge.token)
    assert result.recorded, result.reason
    con.close()
    return host["id"]


def plan_for(name=HOST):
    """The plan `app/prober_cli.py` would build for this host right now, which
    is the thing the dispatch hands to the engine."""
    con = db.connect()
    # The tables the run itself creates, the same additive init
    # `python -m app.prober_cli` does before it plans anything.
    prober.init(con)
    intent.init(con)
    host = store.active_host_by_name(con, name)
    plan = prober_cli.plan_for(con, host)
    con.close()
    return plan


def test_a_proved_address_host_with_no_declared_port_has_nothing_to_probe(client):
    """The deadlock this change exists to break, pinned so a later change
    cannot quietly reintroduce it while the fix stays in the tree."""
    address_host(client)
    prove_an_address()
    plan = plan_for()
    assert plan.targets == (V4,)
    assert plan.ports == ()
    assert plan.note
    assert plan.derived is False


def test_declaring_a_port_gives_the_prober_a_plan_it_can_run(client):
    """**The test this whole change is for.** Create an address host, prove an
    address, declare a port over HTTP, and the plan the engine is handed
    carries that port with no note against it."""
    address_host(client)
    prove_an_address()
    assert declare(client, port=443, family="v4", value="open").status_code == 204
    plan = plan_for()
    assert plan.targets == (V4,)
    assert plan.ports == (443,)
    assert plan.note == ""
    assert plan.derived is True
    assert plan.agentless is True


def test_the_declared_port_reaches_the_joined_set_by_the_store_and_not_by_luck(client):
    """The route wrote a row `app/dispatch.py` reads, which is the join this
    tier has and the agent tier gets from its document."""
    address_host(client)
    prove_an_address()
    declare(client, port=443)
    con = db.connect()
    prober.init(con)
    host = store.active_host_by_name(con, HOST)
    ports, note = dispatch.joined_ports(
        con, prober_cli.Plan(host["id"], HOST, (V4,), ()))
    con.close()
    assert ports == (443,) and note == ""


def test_two_declared_ports_are_both_in_the_plan(client):
    address_host(client)
    prove_an_address()
    declare(client, port=443)
    declare(client, port=22)
    assert plan_for().ports == (22, 443)


def test_a_udp_declaration_does_not_widen_the_plan(client):
    """The engine connects over TCP, so the joined set is TCP ports. A UDP
    declaration is stored and is not something to probe, and a host with only
    one still has nothing to probe."""
    address_host(client)
    prove_an_address()
    declare(client, protocol="udp", port=1194)
    plan = plan_for()
    assert plan.ports == ()
    assert plan.note


def test_clearing_the_only_declaration_empties_the_plan_again(client):
    address_host(client)
    prove_an_address()
    declare(client, port=443)
    assert plan_for().ports == (443,)
    client.post(clear_path(port=443), headers=gate())
    plan = plan_for()
    assert plan.ports == () and plan.note


def test_a_declared_port_without_a_proved_address_is_still_not_probed(client):
    """SI-6 is untouched by any of this. A declaration says which ports to
    watch and never which addresses may be reached, so a host with no proof
    has no plan whatever it declared."""
    address_host(client)
    con = db.connect()
    authz.init(con)
    con.close()
    declare(client, port=443)
    plan = plan_for()
    assert plan.targets == ()
    assert plan.ports == ()
    assert plan.note
