"""One token for one server's token file, when an instance proves on our
prober API too (docs/PRODUCT.md 5, the clause of 2026-10-03, and 5g, the
paragraph of 2026-10-24).

A machine serves one file at the well-known path and the file holds one
token (docs/record 4.329). Since an instance starts its token file proofs on
our API and takes the token our API made (`app/proberproofs.py`), a second
address of the same server would be given a new token by our API, the file
would have to hold the new one, and the first address would fail its next
reading on both sides, which is 4.297 again.

So an instance starting a token file proof for a server whose file already
holds a token names that token, and our API gives it again when, and only
when, it is the token of one of that instance's own live token file proofs.
Anything else gets a new token. The token stays ours to make: an instance
can only ask again for one we made for it, which its file already serves.

Edge cases first, the happy path last.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, proberapi, proberproofs, store

from test_api_transport import BASE, Scripted
from test_instance_address_proof import DNS, HTTP, SERVER, publish, sides  # noqa: F401
from test_proberapi_routes import P, V4, V6, assert_refused, key

__all__ = ["sides"]

OTHER_V4 = "185.199.108.154"


def our_start(client, issued, address, method="http-token", **more):
    return client.post(f"{P}/proofs/challenges", headers=key(issued),
                       content=json.dumps({"address": address, "method": method, **more}))


def our_proof(client, ours, issued, address, method="http-token", **more):
    """A proof made on our API directly, its evidence served."""
    started = our_start(client, issued, address, method, **more).json()
    if method == "dns-txt":
        ours.records[address] = [started["token"]]
    else:
        ours.served[address] = started["token"]
    proved = client.post(f"{P}/proofs/challenges/{started['id']}/verify",
                         headers=key(issued)).json()
    assert proved["proved"] is True, proved
    return started


# ====================================================== our API, the edges

@pytest.mark.parametrize("more, method", [
    ({"token": "whpa_" + "a" * 64}, "dns-txt"),
    ({"token": 7}, "http-token"),
    ({"token": ""}, "http-token"),
    ({"token": "whpa_short"}, "http-token"),
    ({"token": "whp_" + "a" * 64}, "http-token"),
    ({"token": ["whpa_" + "a" * 64]}, "http-token"),
])
def test_a_named_token_of_the_wrong_shape_or_for_dns_is_refused(sides, more, method):
    _instance, _ours, client, issued, _path = sides
    assert_refused(our_start(client, issued["one"], V4, method, **more),
                   "malformed_request")


def test_another_instances_token_is_never_given(sides):
    _instance, ours, client, issued, _path = sides
    theirs = our_proof(client, ours, issued["two"], OTHER_V4)

    mine = our_start(client, issued["one"], V4, token=theirs["token"]).json()

    assert mine["token"] != theirs["token"]


def test_a_token_whose_proof_was_revoked_or_lapsed_is_never_given(sides):
    _instance, ours, client, issued, path = sides
    revoked = our_proof(client, ours, issued["one"], OTHER_V4)
    con = db.connect(path)
    authz.revoke(con, OTHER_V4, account=issued["one"].instance.account)
    con.close()
    assert our_start(client, issued["one"], V4,
                     token=revoked["token"]).json()["token"] != revoked["token"]

    lapsed = our_proof(client, ours, issued["one"], V6)
    con = db.connect(path)
    later = datetime.now(timezone.utc) + timedelta(seconds=authz.PUBLISHED_TTL_SECONDS + 60)
    authz.sweep(con, now=later)
    con.close()
    # Swept as lapsed, so it lends nothing even though the clock here is today.
    assert our_start(client, issued["one"], V4,
                     token=lapsed["token"]).json()["token"] != lapsed["token"]


def test_a_dns_proofs_token_is_never_given_for_a_token_file(sides):
    _instance, ours, client, issued, _path = sides
    by_dns = our_proof(client, ours, issued["one"], OTHER_V4, method="dns-txt")

    started = our_start(client, issued["one"], V4, token=by_dns["token"]).json()

    assert started["token"] != by_dns["token"]


def test_a_token_nobody_made_is_never_given(sides):
    _instance, _ours, client, issued, _path = sides
    made_up = "whpa_" + "e" * 64

    assert our_start(client, issued["one"], V4, token=made_up).json()["token"] != made_up


def test_a_given_token_still_proves_nothing_until_it_is_read_at_the_address(sides):
    _instance, ours, client, issued, path = sides
    first = our_proof(client, ours, issued["one"], OTHER_V4)
    second = our_start(client, issued["one"], V4, token=first["token"]).json()
    assert second["token"] == first["token"]

    answer = client.post(f"{P}/proofs/challenges/{second['id']}/verify",
                         headers=key(issued["one"])).json()

    assert answer == {"proved": False, "result": "token_not_found"}


# ================================================= the registry, the edges

def registry():
    con = db.connect(":memory:")
    for module in (db, authz):
        module.init(con)
    return con


@pytest.mark.parametrize("method, host", [(authz.METHOD_DNS_TXT, False),
                                          (authz.METHOD_HTTP_TOKEN, True)])
def test_the_registry_takes_a_named_token_only_for_a_token_file_with_no_server(method, host):
    con = registry()
    host_id = store.add_address_host(con, SERVER) if host else None
    with pytest.raises(ValueError):
        authz.start_proof(con, V4, method, account=authz.account_for_instance(1),
                          host_id=host_id, same_token_as="whpa_" + "a" * 64)
    assert authz.list_challenges(con) == []


def test_the_registry_never_takes_both_kinds_of_token_at_once():
    con = registry()
    with pytest.raises(ValueError):
        authz.start_proof(con, V4, HTTP, same_token_as="whpa_" + "a" * 64,
                          adopt_token="whpa_" + "b" * 64)


# ===================================================== the instance's side

def test_a_first_address_and_a_dns_proof_name_no_token(sides):
    instance, _ours, _client, _issued, _path = sides
    instance.opener = Scripted(
        (201, {"id": 7, "address": V4, "method": "http-token", "token": "whpa_" + "b" * 64}),
        (201, {"id": 8, "address": V6, "method": "dns-txt", "token": "whpa_" + "c" * 64}))

    instance.start(V4)
    instance.start(V6, method=DNS)

    for asked in instance.opener.asked:
        assert "token" not in json.loads(asked.data)


def test_a_second_address_names_the_token_its_file_holds(sides):
    instance, ours, _client, _issued, _path = sides
    first = instance.start(V4)
    publish(instance, ours, first)
    assert instance.verify(first).result.recorded
    instance.opener = Scripted(
        (201, {"id": 9, "address": V6, "method": "http-token", "token": first.token}))

    instance.start(V6)

    (asked,) = instance.opener.asked
    assert json.loads(asked.data) == {"address": V6, "method": "http-token",
                                      "token": first.token}


def test_when_our_api_gives_a_new_token_the_instance_takes_it(sides):
    """Our side no longer holds the first proof, so it lends nothing, and one
    token is still what both registries read."""
    instance, ours, _client, _issued, path = sides
    first = instance.start(V4)
    publish(instance, ours, first)
    assert instance.verify(first).result.recorded
    con = db.connect(path)
    authz.revoke(con, V4)
    con.close()

    second = instance.start(V6)

    assert second.token != first.token
    (row,) = [r for r in authz.list_challenges(instance.con) if r["id"] == second.id]
    assert row["token_hash"] == authz.token_hash(second.token)


# ======================================================= the happy path

def test_two_addresses_of_one_server_are_proved_on_both_sides_by_one_file(sides):
    instance, ours, _client, issued, path = sides
    first = instance.start(V4)
    publish(instance, ours, first)
    assert instance.verify(first).result.recorded

    second = instance.start(V6)
    assert second.token == first.token
    publish(instance, ours, second, V6)
    assert instance.verify(second).result.recorded

    # A day on, both readings on our side find the one token in both places.
    tomorrow = datetime.now(timezone.utc) + timedelta(hours=25)
    con = db.connect(path)
    renewal = authz.renew_published(con, now=tomorrow)
    con.close()
    assert sorted(renewal["renewed"]) == sorted([V4, V6])
    assert sorted(instance.live()) == sorted([V4, V6])
    con = db.connect(path)
    assert {row["target"] for row in authz.live_for_account(
        con, issued["one"].instance.account, tomorrow)} == {V4, V6}
    con.close()


def test_a_first_address_started_again_takes_the_new_token(sides):
    """What PRODUCT 5g says for the case our side lends nothing: the second
    address gets a new token, and starting the first again gives it that
    one, so the file holds one token again."""
    instance, ours, _client, _issued, path = sides
    first = instance.start(V4)
    publish(instance, ours, first)
    assert instance.verify(first).result.recorded
    con = db.connect(path)
    authz.revoke(con, V4)
    con.close()
    second = instance.start(V6)
    publish(instance, ours, second, V6)
    assert instance.verify(second).result.recorded

    again = instance.start(V4)

    assert again.token == second.token != first.token
