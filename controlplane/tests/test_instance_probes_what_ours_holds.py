"""What an instance's batch lets through to our probers
(docs/PRODUCT.md 5g, the paragraph of 2026-10-24 on the snapshot).

The fault this holds shut was found by the second big test (finding D1). An
agent sends its presence to its instance and to our API over each address
family apart. An instance whose own name has no AAAA record never receives
the IPv6 one, so its own registry held the IPv4 proof alone, while our side
proved both families by the same agent's presence. The instance's batch
carried its own registry's snapshot, and our side reads that snapshot to
narrow its own, so every IPv6 port of every server read `not tested` with
`no_authorization`.

Since then, for a batch to our API, our registry decides alone which of the
batch's addresses the prober touches, and the instance's snapshot narrows
only by what it refuses outright: an address that can never be a target, and
one on its own exclusion list. For anything without our probers its own
registry stays the gate. A revoke on the instance's dashboard revokes on our
API first, so it still stops the probe at once.

The pass runs from the instance's own database through the real routes of
our ingest and our real worker, to the real runner in process.
"""
import json
import threading
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import (authz, db, dispatch, ingest, instances, prober, proberapi,
                 proberproofs, store, vantages, vantages_cli)

from test_api_transport import (BASE, Far, Scripted, ThroughTheIngest, a_pass,
                                rows, serve_the_queue, through_the_api)
from tests.test_admin_addresses import ADDRESS, add_address_host, client, post  # noqa: F401

__all__ = ["client"]

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
P = proberapi.PATH_PREFIX
NOW = datetime.now(timezone.utc)


def document(*addresses):
    return json.dumps({
        "sockets": {"listening": [
            {"protocol": "tcp", "port": 22, "bind_address": "0.0.0.0", "family": "v4"},
            {"protocol": "tcp", "port": 22, "bind_address": "::", "family": "v6"}]},
        "interface_addresses": {"addresses": [
            {"interface": "eth0", "family": authz.normalise_target(a)[1],
             "address": a, "global": True} for a in addresses]}})


@pytest.fixture()
def sides(tmp_path, monkeypatch):
    """Our control plane, two vantages and one instance, and the instance's
    own control plane with one dual-stack server whose agent reported. On
    our side its presence arrived over both families. On the instance only
    the IPv4 one did, as under a name with an A record alone. Returns (ours,
    theirs, issued, client)."""
    ours = str(tmp_path / "ours.db")
    monkeypatch.setenv(db.DB_ENV, ours)
    con = db.connect(ours)
    for module in (db, authz, prober, vantages, instances, proberapi):
        module.init(con)
    vantages.add(con, "probe1", "root@78.141.210.130", ["78.141.210.130"])
    vantages.add(con, "probe2", "root@185.199.110.7", ["185.199.110.7"])
    issued = instances.add(con, "freedom", origin=authz.ORIGIN_INVITED)
    con.close()
    client = TestClient(ingest.app, client=("127.0.0.1", 40000))
    for family_address in (V4, V6):
        sent = client.post(f"{P}/presence", headers={
            "Authorization": f"Bearer {issued.proof_key}",
            "X-Forwarded-For": family_address},
            content=json.dumps({"interface_addresses": [V4, V6]}))
        assert sent.status_code == 204

    theirs = db.connect(str(tmp_path / "theirs.db"))
    for module in (db, authz, prober, vantages, proberproofs):
        module.init(theirs)
    host_id, _ = store.add_host(theirs, "web1")
    held = document(V4, V6)
    store.insert_report(theirs, host_id, 1, 1, held)
    assert authz.record_agent_proof(theirs, host_id, V4, held, now=NOW).recorded
    vantages_cli._sync_api(theirs, environ={
        dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_API_KEY_ENV: issued.api_key},
        opener=ThroughTheIngest(client))
    yield ours, theirs, issued, client
    theirs.close()


def through_our_api(ours, theirs, issued, client):
    stop = threading.Event()
    worker = threading.Thread(target=serve_the_queue, args=(ours, stop))
    worker.start()
    try:
        return a_pass(theirs, through_the_api(client, issued))
    finally:
        stop.set()
        worker.join()


def states(con, outcome, address):
    return {(state, reason) for family, target, port, state, reason in rows(con, outcome.run)
            if target == address}


def ours_allows(ours, issued, address):
    con = db.connect(ours)
    try:
        return authz.may_probe(con, address, account=issued.instance.account).allowed
    finally:
        con.close()


# ======================================================== the edge cases

def test_an_address_our_side_does_not_hold_stays_not_tested(sides):
    ours, theirs, issued, client = sides
    con = db.connect(ours)
    authz.revoke(con, V6, account=issued.instance.account)
    con.close()
    # The instance holding a proof of its own changes nothing on our side.
    assert authz.record_agent_proof(theirs, store.list_hosts(theirs)[0]["id"], V6,
                                    document(V4, V6), now=NOW).recorded

    outcomes = through_our_api(ours, theirs, issued, client)

    assert [o.measured for o in outcomes] == [True, True]
    for outcome in outcomes:
        assert states(theirs, outcome, V6) == {
            (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}
        assert {s for s, _r in states(theirs, outcome, V4)} == {prober.STATE_CONNECTED}


def test_an_address_on_the_instances_own_exclusion_list_is_not_let_through(sides):
    ours, theirs, issued, client = sides
    authz.exclude(theirs, V6)

    outcomes = through_our_api(ours, theirs, issued, client)

    assert ours_allows(ours, issued, V6)
    for outcome in outcomes:
        assert states(theirs, outcome, V6) == {
            (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


def test_a_snapshot_for_our_api_takes_ours_only_where_this_registry_allows_it():
    """Each rule of `authz.snapshot_for_prober_api`, on one registry, with
    our listing handed in. The pass tests above and test_b6_challenge.py
    hold the same rules end to end."""
    con = db.connect(":memory:")
    for module in (db, authz):
        module.init(con)
    hour = timedelta(hours=1)
    mine, _ = store.add_host(con, "web1")
    other_workspace = db.create_workspace(con, "second@example.com")
    theirs, _ = store.add_host(con, "web2", workspace_id=other_workspace)
    held_here, excluded, theirs_too, closed, lapsed, unreadable = (
        "185.199.108.150", "185.199.108.151", "185.199.108.152",
        "185.199.108.154", "185.199.108.155", "185.199.108.156")
    assert authz.record_agent_proof(con, mine, held_here, document(held_here),
                                    now=NOW).recorded
    assert authz.record_agent_proof(con, theirs, theirs_too, document(theirs_too),
                                    now=NOW).recorded
    authz.exclude(con, excluded, now=NOW - hour)
    assert authz.record_agent_proof(con, mine, closed, document(closed),
                                    now=NOW - 3 * hour).recorded
    authz.revoke(con, closed, now=NOW - hour, account=authz.DEFAULT_ACCOUNT)
    ours = {V4: (NOW - hour, NOW + hour), V6: (NOW, NOW + hour),
            excluded: (NOW, NOW + hour), theirs_too: (NOW, NOW + hour),
            closed: (NOW - 2 * hour, NOW + hour), lapsed: (NOW - 2 * hour, NOW - hour),
            unreadable: ("yesterday", NOW + hour)}
    addresses = [held_here, V4, "2606:50C0:8000:0::153", excluded, theirs_too,
                 closed, lapsed, unreadable, "10.0.0.1"]

    snapshot = authz.snapshot_for_prober_api(con, addresses, ours, now=NOW)

    assert sorted(snapshot.targets) == sorted([held_here, V4, V6])
    assert snapshot.targets[V4] == NOW + hour
    assert snapshot.expires_at == NOW + timedelta(seconds=authz.SNAPSHOT_TTL_SECONDS)
    # The same listing, read for the other workspace: its own proof, and
    # nothing another workspace holds.
    for_them = authz.snapshot_for_prober_api(
        con, addresses, ours, now=NOW, account=authz.account_for_workspace(other_workspace))
    assert sorted(for_them.targets) == sorted([theirs_too, V4, V6, closed])


def test_a_pass_over_ssh_still_asks_this_registry_alone(sides):
    """Without our probers the instance's own registry is the gate."""
    _ours, theirs, _issued, _client = sides
    far = Far()

    outcomes = a_pass(theirs, far.factory)

    assert [o.measured for o in outcomes] == [True, True]
    for outcome in outcomes:
        assert states(theirs, outcome, V6) == {
            (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}
    for batch in far.batches:
        assert sorted(batch["snapshot"]["targets"]) == [V4]


def test_our_worker_still_builds_the_probers_snapshot_from_ours(sides):
    """Our side never takes the instance's snapshot as permission: an address
    the instance lets through and ours does not hold is not in what the
    runner carries."""
    ours, theirs, issued, client = sides
    con = db.connect(ours)
    authz.revoke(con, V6, account=issued.instance.account)
    con.close()
    far = Far()
    stop = threading.Event()

    def serve():
        con = db.connect(ours)
        try:
            from app import proberapi_worker
            while not stop.is_set():
                proberapi_worker.run_round(con, transport_factory=far.factory,
                                           lock_wait_seconds=5)
        finally:
            con.close()

    worker = threading.Thread(target=serve)
    worker.start()
    try:
        a_pass(theirs, through_the_api(client, issued))
    finally:
        stop.set()
        worker.join()
    assert far.batches
    for batch in far.batches:
        assert sorted(batch["snapshot"]["targets"]) == [V4]
        assert set(batch["addresses"]) == {V4, V6}


# --------------------------------------------------- a revoke on the instance

def with_prober_lines(monkeypatch, opener):
    monkeypatch.setenv(dispatch.PROBER_API_ENV, BASE)
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, "whpi_" + "c" * 64)
    monkeypatch.setattr(proberproofs, "opener", lambda: opener)


def proved_here():
    con = db.connect()
    try:
        host = store.active_host_by_name(con, "outside-only")
        return [row["target"] for row in authz.live_addresses_for_host(con, host["id"])]
    finally:
        con.close()


def an_address_proved_here(client, monkeypatch):
    """An address host with ADDRESS proved in this registry, by hand."""
    add_address_host(client)
    con = db.connect()
    authz.init(con)
    host = store.active_host_by_name(con, "outside-only")
    challenge = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN,
                                  host_id=host["id"])
    assert authz.verify_proof(con, challenge.id,
                              fetcher=lambda url: challenge.token).recorded
    con.close()


def revoke(client):
    return post(client, "/api/admin/hosts/outside-only/addresses/revoke",
                {"address": ADDRESS})


@pytest.mark.parametrize("answer, status, code", [
    ((400, {"error": "target_refused"}), 400, "target_refused"),
    ((401, {"error": "unknown_key"}), 502, "unknown_key"),
    ((0, OSError("no route")), 502, dispatch.NO_ANSWER),
    ((502, b"<html>bad gateway</html>"), 502, dispatch.NO_ANSWER),
    ((200, {"revoked": "all"}), 502, dispatch.NO_ANSWER),
])
def test_a_revoke_our_api_did_not_take_changes_nothing_here(client, monkeypatch,
                                                            answer, status, code):
    an_address_proved_here(client, monkeypatch)
    with_prober_lines(monkeypatch, Scripted(answer))

    r = revoke(client)

    assert r.status_code == status
    assert r.json() == {"detail": f"{ADDRESS} not revoked with the probers:"
                                  f" {proberproofs.CODE_WORDS[code]}",
                        "code": code, "refused_by": "prober_api"}
    assert proved_here() == [ADDRESS]


def test_a_revoke_goes_to_our_api_first_and_then_here(client, monkeypatch):
    an_address_proved_here(client, monkeypatch)
    opener = Scripted((200, {"revoked": 1}))
    with_prober_lines(monkeypatch, opener)

    r = revoke(client)

    assert r.status_code == 204
    (asked,) = opener.asked
    assert (asked.get_method(), asked.full_url) == (
        "DELETE", f"{BASE}/api/v1/prober/proofs/{ADDRESS}")
    assert asked.get_header("Authorization") == "Bearer whpi_" + "c" * 64
    assert not asked.data
    assert proved_here() == []


def test_a_revoke_of_an_address_this_workspace_does_not_hold_alone_sends_nothing(
        client, monkeypatch):
    """Our side has one account for the whole instance, so a DELETE ends the
    proof for every workspace of it. It goes only for an address this
    workspace holds and no other workspace holds (the challenge of
    2026-10-24, test_b6_challenge.py holds the same through our real API)."""
    an_address_proved_here(client, monkeypatch)
    con = db.connect()
    other = db.create_workspace(con, "second@example.com")
    host_id = store.add_address_host(con, "neighbour", workspace_id=other)
    challenge = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN, host_id=host_id,
                                  account=authz.account_for_workspace(other))
    assert authz.verify_proof(con, challenge.id,
                              fetcher=lambda url: challenge.token).recorded
    con.close()
    opener = Scripted()
    with_prober_lines(monkeypatch, opener)

    held_by_two = revoke(client)
    never_held = post(client, "/api/admin/hosts/outside-only/addresses/revoke",
                      {"address": "185.199.108.154"})

    assert (held_by_two.status_code, never_held.status_code) == (204, 204)
    assert opener.asked == []
    assert proved_here() == []
    con = db.connect()
    assert authz.may_probe(con, ADDRESS, account=authz.account_for_workspace(other)).allowed
    con.close()


def test_with_no_prober_lines_a_revoke_sends_nothing(client, monkeypatch):
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)

    def refuse():
        raise AssertionError("an instance with no prober lines sent a request")

    monkeypatch.setattr(proberproofs, "opener", refuse)
    monkeypatch.setattr(dispatch, "revoke_api_proof", lambda *a, **k: refuse())
    an_address_proved_here(client, monkeypatch)

    assert revoke(client).status_code == 204
    assert proved_here() == []


def test_a_revoke_on_the_instance_ends_the_proof_on_our_side(sides):
    ours, theirs, issued, client = sides
    api = proberproofs.ProberApi(BASE, issued.api_key)
    authz.record_agent_proof(theirs, store.list_hosts(theirs)[0]["id"], V6,
                             document(V4, V6), now=NOW)

    closed = proberproofs.revoke(theirs, api, V6, opener=ThroughTheIngest(client))

    assert closed == 1

    assert not ours_allows(ours, issued, V6)
    assert ours_allows(ours, issued, V4)


# ========================================================= the happy path

def test_a_dual_stack_server_under_an_instance_with_no_aaaa_is_probed_on_both(sides):
    ours, theirs, issued, client = sides
    host_id = store.list_hosts(theirs)[0]["id"]
    assert [row["target"] for row in authz.live_addresses_for_host(theirs, host_id)] == [V4]
    assert ours_allows(ours, issued, V4) and ours_allows(ours, issued, V6)

    outcomes = through_our_api(ours, theirs, issued, client)

    assert [o.measured for o in outcomes] == [True, True]
    # Our listing, as every batch read it, kept for the address rows.
    assert dispatch.api_proofs_held(theirs) == {V4, V6}
    for outcome in outcomes:
        for address in (V4, V6):
            assert {s for s, _r in states(theirs, outcome, address)} == {
                prober.STATE_CONNECTED}, (outcome.vantage, address)


# ------------------------------------------------------- the command line

@pytest.fixture()
def instance_cli(tmp_path, monkeypatch):
    """`python -m app.authz_cli` on an instance: its own database with V4
    proved, and no environment file read from the machine running the
    tests. Returns (run, con)."""
    from app import authz_cli, envfile
    path = str(tmp_path / "theirs.db")
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    con = db.connect(path)
    for module in (db, authz):
        module.init(con)
    host_id, _ = store.add_host(con, "web1")
    assert authz.record_agent_proof(con, host_id, V4, document(V4), now=NOW).recorded
    yield (lambda *argv: authz_cli.main(list(argv))), con
    con.close()


def test_the_command_line_revokes_with_our_api_first(instance_cli, monkeypatch, capsys):
    run, con = instance_cli
    opener = Scripted((200, {"revoked": 1}))
    with_prober_lines(monkeypatch, opener)

    assert run("revoke", V4) == 0

    (asked,) = opener.asked
    assert (asked.get_method(), asked.full_url) == (
        "DELETE", f"{BASE}/api/v1/prober/proofs/{V4}")
    assert not authz.may_probe(con, V4).allowed
    assert "revoked with the probers first" in capsys.readouterr().out


@pytest.mark.parametrize("answer, code", [
    ((401, {"error": "unknown_key"}), "unknown_key"),
    ((0, OSError("no route")), dispatch.NO_ANSWER),
])
def test_the_command_line_changes_nothing_when_our_api_did_not_take_it(
        instance_cli, monkeypatch, capsys, answer, code):
    run, con = instance_cli
    with_prober_lines(monkeypatch, Scripted(answer))

    assert run("revoke", V4) == 1

    assert authz.may_probe(con, V4).allowed
    assert (f"{V4} not revoked with the probers: {proberproofs.CODE_WORDS[code]}"
            in capsys.readouterr().err)


def test_the_command_line_with_no_prober_lines_sends_nothing(instance_cli, monkeypatch):
    run, con = instance_cli
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(dispatch, "revoke_api_proof",
                        lambda *a, **k: pytest.fail("a request was sent"))

    assert run("revoke", V4) == 0
    assert not authz.may_probe(con, V4).allowed


# ------------------------------- an exclusion, a Remove and a Delete reach ours
#
# The challenge of 2026-10-24, its third point: an exclusion on the instance
# never reached our API, so our live proof brought the probes back the moment
# it was lifted. Decided: exclude goes to our API first, as revoke does, and
# so do Remove server and Delete, each for an address no other server holds.

def test_the_command_line_excludes_with_our_api_first(instance_cli, monkeypatch, capsys):
    run, con = instance_cli
    opener = Scripted((200, {"revoked": 1}))
    with_prober_lines(monkeypatch, opener)

    assert run("exclude", V4) == 0

    (asked,) = opener.asked
    assert (asked.get_method(), asked.full_url) == (
        "DELETE", f"{BASE}/api/v1/prober/proofs/{V4}")
    assert authz.active_exclusion(con, V4) is not None


def test_an_exclusion_our_api_did_not_take_changes_nothing(instance_cli, monkeypatch, capsys):
    run, con = instance_cli
    with_prober_lines(monkeypatch, Scripted((0, OSError("no route"))))

    assert run("exclude", V4) == 1

    assert authz.active_exclusion(con, V4) is None
    assert authz.may_probe(con, V4).allowed
    assert f"{V4} not revoked with the probers: no answer" in capsys.readouterr().err


def test_an_exclusion_on_the_instance_ends_the_proof_on_our_side(sides):
    ours, theirs, issued, client = sides
    api = proberproofs.ProberApi(BASE, issued.api_key)

    proberproofs.exclude(theirs, api, V6, opener=ThroughTheIngest(client))

    assert not ours_allows(ours, issued, V6)
    assert ours_allows(ours, issued, V4)
    assert authz.active_exclusion(theirs, V6) is not None


def remove(client, name="outside-only"):
    return post(client, f"/api/admin/hosts/{name}/revoke")


def delete(client, name="outside-only"):
    return post(client, f"/api/admin/hosts/{name}/delete")


def test_remove_ends_the_servers_addresses_on_our_api_first(client, monkeypatch):
    an_address_proved_here(client, monkeypatch)
    opener = Scripted((200, {"revoked": 1}))
    with_prober_lines(monkeypatch, opener)

    assert remove(client).status_code == 204

    (asked,) = opener.asked
    assert (asked.get_method(), asked.full_url) == (
        "DELETE", f"{BASE}/api/v1/prober/proofs/{ADDRESS}")


@pytest.mark.parametrize("answer, code", [
    ((401, {"error": "unknown_key"}), "unknown_key"),
    ((0, OSError("no route")), dispatch.NO_ANSWER),
])
def test_a_remove_or_delete_our_api_did_not_take_changes_nothing(client, monkeypatch,
                                                                 answer, code):
    an_address_proved_here(client, monkeypatch)
    with_prober_lines(monkeypatch, Scripted(answer))

    r = remove(client)

    assert r.status_code == 502
    assert r.json() == {"detail": f"outside-only not removed with the probers: {code}",
                        "code": code, "refused_by": "prober_api"}
    assert proved_here() == [ADDRESS]

    # Removed before the prober lines were set, so nothing went then: Delete
    # asks our API, and changes nothing when it does not take it.
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name)
    assert remove(client).status_code == 204
    with_prober_lines(monkeypatch, Scripted(answer))
    r = delete(client)
    assert r.status_code == 502
    assert r.json()["detail"] == f"outside-only not deleted with the probers: {code}"
    con = db.connect()
    assert [h["name"] for h in store.list_hosts(con)] == ["outside-only"]
    con.close()

    opener = Scripted((200, {"revoked": 1}))
    with_prober_lines(monkeypatch, opener)
    assert delete(client).status_code == 204
    assert [r.full_url for r in opener.asked] == [f"{BASE}/api/v1/prober/proofs/{ADDRESS}"]


def test_remove_sends_nothing_for_an_address_another_server_holds(client, monkeypatch):
    an_address_proved_here(client, monkeypatch)
    add_address_host(client, "neighbour")
    con = db.connect()
    host = store.active_host_by_name(con, "neighbour")
    challenge = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN, host_id=host["id"])
    assert authz.verify_proof(con, challenge.id, fetcher=lambda url: challenge.token).recorded
    con.close()
    opener = Scripted()
    with_prober_lines(monkeypatch, opener)

    assert remove(client).status_code == 204
    assert opener.asked == []


def test_with_no_prober_lines_remove_and_delete_send_nothing(client, monkeypatch):
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(dispatch, "revoke_api_proof",
                        lambda *a, **k: pytest.fail("a request was sent"))
    an_address_proved_here(client, monkeypatch)

    assert remove(client).status_code == 204
    assert delete(client).status_code == 204
