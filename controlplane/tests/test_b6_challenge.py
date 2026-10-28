"""Challenge of branch b6-instance-address-proof (eeb94ab5), docs/PRODUCT.md 5g.

Each test states the behaviour main had and the branch should keep. All
three fail on the branch. The first and third pass on main, and the second
needs the branch's own module.

1. A second workspace of one instance has its batch to our probers let
   through for an address only another workspace of that instance proved.
2. A revoke from a second workspace of the instance ends, on our side, the
   proof another workspace of that instance holds.
3. An exclusion on the instance (`authz_cli exclude`) does not reach our
   registry, so once it is lifted our probers measure the address again with
   no new proof on the instance ("unexclude restores nothing").
"""
import json
import threading
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import (authz, db, dispatch, ingest, instances, prober, proberapi,
                 prober_cli, store, vantages, vantages_cli)

from test_api_transport import (BASE, ThroughTheIngest, rows, serve_the_queue,
                                through_the_api)

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
    """Our side holds V4 and V6 for the instance by its agent's presence.
    The instance: workspace 1 has web1, which reported both and holds V4.
    Workspace 2 (a signup on the instance) has `intruder`, whose report
    names V4 and nothing of its own, and which proved nothing."""
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
    for module in (db, authz, prober, vantages):
        module.init(theirs)
    web1, _ = store.add_host(theirs, "web1")
    store.insert_report(theirs, web1, 1, 1, document(V4, V6))
    assert authz.record_agent_proof(theirs, web1, V4, document(V4, V6), now=NOW).recorded

    second = db.create_workspace(theirs, "second@example.com")
    intruder, _ = store.add_host(theirs, "intruder", workspace_id=second)
    store.insert_report(theirs, intruder, 1, 1, document(V4))

    vantages_cli._sync_api(theirs, environ={
        dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_API_KEY_ENV: issued.api_key},
        opener=ThroughTheIngest(client))
    yield ours, theirs, issued, client
    theirs.close()


def host(con, name):
    return next(h for h in store.list_hosts(con) if h["name"] == name)


def pass_for(ours, theirs, issued, client, name):
    """One pass for one host of the instance, through our real API and worker."""
    plan = prober_cli._with_joined_ports(theirs, prober_cli.plan_for(theirs, host(theirs, name)))
    stop = threading.Event()
    worker = threading.Thread(target=serve_the_queue, args=(ours, stop))
    worker.start()
    try:
        return dispatch.run_pass(theirs, [plan], vantages.enabled(theirs),
                                 transport_factory=through_the_api(client, issued),
                                 exclude=vantages.all_addresses(theirs))
    finally:
        stop.set()
        worker.join()


def states(con, outcome, address):
    return {(state, reason) for _f, target, _p, state, reason in rows(con, outcome.run)
            if target == address}


def ours_allows(ours, issued, address):
    con = db.connect(ours)
    try:
        return authz.may_probe(con, address, account=issued.instance.account).allowed
    finally:
        con.close()


REFUSED = {(prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


def test_a_second_workspace_is_not_probed_on_another_workspaces_proof(sides):
    ours, theirs, issued, client = sides
    outcomes = pass_for(ours, theirs, issued, client, "intruder")
    assert outcomes and all(o.measured for o in outcomes)
    for outcome in outcomes:
        assert states(theirs, outcome, V4) == REFUSED


def test_a_revoke_from_a_second_workspace_leaves_the_other_workspaces_proof_on_ours(sides):
    from app import proberproofs  # the branch only
    ours, theirs, issued, client = sides
    intruder = host(theirs, "intruder")
    # Exactly what ingest._revoke_address runs for a revoke on intruder's window.
    proberproofs.revoke(theirs, proberproofs.ProberApi(BASE, issued.api_key), V4,
                        account=authz.account_for_host(intruder),
                        opener=ThroughTheIngest(client))
    assert authz.may_probe(theirs, V4, account=authz.DEFAULT_ACCOUNT).allowed
    assert ours_allows(ours, issued, V4)


def test_unexclude_on_the_instance_restores_nothing_for_our_probers(sides):
    ours, theirs, issued, client = sides
    authz.exclude(theirs, V4)
    authz.unexclude(theirs, V4)
    outcomes = pass_for(ours, theirs, issued, client, "web1")
    assert outcomes and all(o.measured for o in outcomes)
    for outcome in outcomes:
        assert states(theirs, outcome, V4) == REFUSED
