"""An instance's DNS TXT and token file proofs, made on our prober API too
(`app/proberproofs.py`, docs/PRODUCT.md 5g, the paragraph of 2026-10-24).

The fault this holds shut was found by the second big test (finding B6): an
instance proved an address of a server with no agent by token file, its window
said proved, and our probers answered `not tested` with `no_authorization`,
because nothing on the instance's side ever called our proof routes.

Two halves.

**Through our real routes.** The instance's registry is a database of its own,
and its client reaches our ingest in process (`ThroughTheIngest`), so our side
is the real API with the real registry. Our side reads the evidence with its
own reader, which these tests stand in for at `authz.fetch_token_file` and
`dnstxt.query_txt`. The instance's side reads with the reader handed to it.
So the two can be made to disagree, and each test says what each one saw.

**Through the instance's own admin routes**, with our API scripted, for what
the window is answered and for what is sent.

Edge cases first, the happy path last.
"""
import ipaddress
import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import (authz, db, dispatch, dnstxt, ingest, instances, prober,
                 proberapi, proberapi_routes, proberproofs, renderbridge, store,
                 vantages)

from test_api_transport import BASE, Scripted, ThroughTheIngest
from test_proberapi_routes import P, V4, V6, key, post_batch, work
from tests.test_admin_addresses import (ADDRESS, add_address_host, client,  # noqa: F401
                                        post, start)

__all__ = ["client"]

SERVER = "wptest-addr"
HTTP = authz.METHOD_HTTP_TOKEN
DNS = authz.METHOD_DNS_TXT


# ================================================================ two sides

class Side:
    """What one side's readers find, and how often they looked: `served` is
    the token file each address serves, `records` the TXT strings at each
    address's reverse name."""

    def __init__(self):
        self.served = {}
        self.records = {}
        self.reads = 0
        self.unreadable = False

    def fetch(self, url, timeout=0):
        self.reads += 1
        if self.unreadable:
            raise authz.ProofError("could not read the token file: TimeoutError")
        for address, body in self.served.items():
            if f"//{address}:" in url or f"//[{address}]:" in url:
                return body
        raise authz.ProofError("the address answered 404", answered=True)

    def txt(self, name):
        self.reads += 1
        return [text for address, strings in self.records.items()
                if ipaddress.ip_address(address).reverse_pointer == name
                for text in strings]


class Instance:
    """The instance: its own database, one server with no agent, and the
    client that reaches our API with its key."""

    def __init__(self, con, issued, opener):
        self.con = con
        self.issued = issued
        self.opener = opener
        self.api = proberproofs.ProberApi(BASE, issued.api_key)
        self.reader = Side()

    @property
    def host(self):
        return store.active_host_by_name(self.con, SERVER)

    def start(self, address=V4, method=HTTP):
        return proberproofs.start(self.con, self.api, self.host, address, method,
                                  opener=self.opener)

    def verify(self, challenge, now=None):
        row = authz.challenge_for_host(self.con, challenge.id, self.host["id"],
                                       authz.account_for_host(self.host))
        return proberproofs.verify(self.con, self.api, row, opener=self.opener,
                                   now=now, fetcher=self.reader.fetch,
                                   resolver=self.reader.txt)

    def live(self):
        return [row["target"] for row in
                authz.live_addresses_for_host(self.con, self.host["id"])]


@pytest.fixture()
def sides(tmp_path, monkeypatch):
    """Our control plane (the ingest's database, two vantages, instances one
    and two) and instance one's own control plane, with a server that has
    no agent. Returns (instance, ours, client, issued, path)."""
    path = str(tmp_path / "ours.db")
    monkeypatch.setenv(db.DB_ENV, path)
    con = db.connect(path)
    for module in (db, authz, prober, vantages, instances, proberapi):
        module.init(con)
    vantages.add(con, "probe1", "root@78.141.210.130", ["78.141.210.130"])
    vantages.add(con, "probe2", "root@185.199.110.7", ["185.199.110.7"])
    issued = {name: instances.add(con, name, origin=authz.ORIGIN_INVITED)
              for name in ("one", "two")}
    con.close()

    ours = Side()
    monkeypatch.setattr(authz, "fetch_token_file", ours.fetch)
    monkeypatch.setattr(dnstxt, "query_txt", ours.txt)
    # Our API reads one challenge at most once every few seconds
    # (`proberapi.PROOF_VERIFY_SPACING_SECONDS`). A person clicking Verify
    # twice is that far apart, so each request here is too.
    moved = [0]

    def later():
        moved[0] += proberapi.PROOF_VERIFY_SPACING_SECONDS
        return datetime.now(timezone.utc) + timedelta(seconds=moved[0])

    monkeypatch.setattr(proberapi_routes, "_now", later)

    theirs = db.connect(str(tmp_path / "theirs.db"))
    for module in (db, authz, proberproofs):
        module.init(theirs)
    store.add_address_host(theirs, SERVER)
    client = TestClient(ingest.app, client=("127.0.0.1", 40000))
    instance = Instance(theirs, issued["one"], ThroughTheIngest(client))
    yield instance, ours, client, issued, path
    theirs.close()


def ours_allows(path, issued, address=V4, now=None):
    con = db.connect(path)
    try:
        return authz.may_probe(con, address, now=now,
                               account=issued.instance.account).allowed
    finally:
        con.close()


def ours_proofs(path, issued):
    con = db.connect(path)
    try:
        return [(row["target"], row["method"]) for row in
                authz.live_for_account(con, issued.instance.account)]
    finally:
        con.close()


def publish(instance, ours, challenge, address=V4):
    """The operator publishes the token once, where its way says, and both
    sides read it."""
    for side in (instance.reader, ours):
        if challenge.method == DNS:
            side.records[address] = [challenge.token]
        else:
            side.served[address] = challenge.token


def probed_states(client, issued, path):
    """A batch from the instance for V4, its own registry allowing it, run by
    our worker. What came back for V4."""
    batch_id = post_batch(client, issued).json()["id"]
    work(path)
    answer = client.get(f"{P}/batches/{batch_id}", headers=key(issued)).json()
    measured = prober.run_from_json(answer["answer"])
    return {(r.state, r.reason) for r in measured.results if r.target == V4}


# ======================================================= our API refusing

def test_an_address_another_instance_holds_is_refused_and_not_proved_here(sides):
    instance, ours, client, issued, path = sides
    held = client.post(f"{P}/proofs/challenges", headers=key(issued["two"]),
                       content=json.dumps({"address": V4, "method": "dns-txt"})).json()
    ours.records[V4] = [held["token"]]
    assert client.post(f"{P}/proofs/challenges/{held['id']}/verify",
                       headers=key(issued["two"])).json()["proved"] is True

    # Instance one's token file is served too. Instance two's record is still
    # there when our side reads it again, so two keeps the address.
    challenge = instance.start()
    publish(instance, ours, challenge)
    outcome = instance.verify(challenge)

    assert outcome.result.recorded is False
    assert outcome.result.code == "address_held"
    assert outcome.refused_by == proberproofs.PROBER_API
    assert instance.live() == []
    assert instance.reader.reads == 0
    assert not ours_allows(path, issued["one"])


def test_an_excluded_address_is_refused_at_start_and_nothing_is_made_here(sides):
    instance, _ours, _client, issued, path = sides
    con = db.connect(path)
    authz.exclude(con, V4)
    con.close()

    with pytest.raises(proberproofs.NotStarted) as refused:
        instance.start()

    assert refused.value.code == "target_refused"
    assert authz.list_challenges(instance.con) == []


def test_an_address_excluded_after_its_start_is_refused_at_verify(sides):
    instance, ours, _client, issued, path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    con = db.connect(path)
    authz.exclude(con, V4)
    con.close()

    outcome = instance.verify(challenge)

    assert (outcome.result.recorded, outcome.result.code, outcome.refused_by) == (
        False, "challenge_cancelled", proberproofs.PROBER_API)
    assert instance.live() == []
    assert not ours_allows(path, issued["one"])


def test_an_address_on_the_instances_own_list_is_refused_before_anything_is_sent(sides):
    instance, _ours, _client, _issued, _path = sides
    authz.exclude(instance.con, V4)
    instance.opener = Scripted()

    with pytest.raises(authz.TargetError):
        instance.start()
    assert instance.opener.asked == []


@pytest.mark.parametrize("address", ["10.0.0.1", "127.0.0.1", "100.64.1.1", "::1",
                                     "not-an-ip"])
def test_an_address_that_can_never_be_a_target_is_never_sent(sides, address):
    instance, _ours, _client, _issued, _path = sides
    instance.opener = Scripted()
    with pytest.raises(authz.TargetError):
        instance.start(address)
    assert instance.opener.asked == []


def test_a_token_file_our_api_cannot_read_is_refused_and_not_read_here(sides):
    """Our API reads first. When it cannot, the instance reads nothing and
    records nothing, whatever it would have found."""
    instance, ours, _client, issued, path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    ours.unreadable = True

    outcome = instance.verify(challenge)

    assert (outcome.result.recorded, outcome.result.code, outcome.refused_by) == (
        False, "evidence_unreadable", proberproofs.PROBER_API)
    assert instance.reader.reads == 0
    assert instance.live() == []
    assert not ours_allows(path, issued["one"])


def test_our_api_reads_the_token_itself_and_never_takes_the_instances_word(sides):
    """The instance's reader finds the token. Ours does not, so it is not
    proved on either side."""
    instance, ours, _client, issued, path = sides
    challenge = instance.start()
    instance.reader.served[V4] = challenge.token
    ours.served[V4] = "something else"

    outcome = instance.verify(challenge)

    assert (outcome.result.code, outcome.refused_by) == (
        "token_not_found", proberproofs.PROBER_API)
    assert ours.reads == 1
    assert instance.live() == []
    assert not ours_allows(path, issued["one"])


def test_a_revoked_instance_is_refused_at_start_and_at_verify(sides):
    instance, ours, _client, issued, path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    con = db.connect(path)
    instances.revoke(con, "one")
    con.close()

    with pytest.raises(proberproofs.NotStarted) as refused:
        instance.start(V6)
    outcome = instance.verify(challenge)

    assert refused.value.code == "unknown_key"
    assert (outcome.result.code, outcome.refused_by) == (
        "unknown_key", proberproofs.PROBER_API)
    assert instance.live() == []


def test_a_challenge_our_api_does_not_know_is_started_again(sides):
    """Our API answers unknown_challenge for a challenge that is not this
    instance's, which is the case after a new invitation. The window's word
    for it is the registry's, and it starts again."""
    instance, ours, _client, issued, path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    instance.api = proberproofs.ProberApi(BASE, issued["two"].api_key)

    outcome = instance.verify(challenge)

    assert (outcome.result.code, outcome.refused_by) == (
        "no_such_challenge", proberproofs.PROBER_API)
    assert instance.live() == []


def test_a_challenge_our_api_never_saw_is_started_again_and_nothing_is_sent(sides):
    """A challenge started on the instance before this, in its registry only."""
    instance, ours, _client, _issued, _path = sides
    challenge = authz.start_proof(instance.con, V4, HTTP,
                                  account=authz.account_for_host(instance.host),
                                  host_id=instance.host["id"])
    publish(instance, ours, challenge)
    instance.opener = Scripted()

    outcome = instance.verify(challenge)

    assert (outcome.result.code, outcome.refused_by) == (
        "no_such_challenge", proberproofs.PROBER_API)
    assert instance.opener.asked == []
    assert instance.reader.reads == 0
    assert instance.live() == []


def test_a_challenge_the_instance_cancelled_is_answered_here_and_nothing_is_sent(sides):
    instance, ours, _client, _issued, _path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    authz.revoke(instance.con, V4, account=authz.account_for_host(instance.host))
    instance.opener = Scripted()

    outcome = instance.verify(challenge)

    assert (outcome.result.code, outcome.refused_by) == (
        "challenge_cancelled", proberproofs.INSTANCE)
    assert instance.opener.asked == []
    assert ours.reads == 0


def test_a_challenge_past_its_day_is_answered_here_and_nothing_is_sent(sides):
    instance, ours, _client, _issued, _path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    instance.opener = Scripted()
    later = datetime.now(timezone.utc) + timedelta(seconds=authz.CHALLENGE_TTL_SECONDS + 60)

    outcome = instance.verify(challenge, now=later)

    assert (outcome.result.code, outcome.refused_by) == (
        "challenge_expired", proberproofs.INSTANCE)
    assert instance.opener.asked == []


# ====================================================== our API not answering

@pytest.mark.parametrize("answer", [
    (0, OSError("connection refused")),
    (0, TimeoutError()),
    (502, b"<html>bad gateway</html>"),
    (200, {"id": 7}),
    (201, []),
    (201, {"id": True, "address": V4, "method": "http-token",
           "token": "whpa_" + "a" * 64}),
    (201, {"id": 7, "address": "185.199.108.154", "method": "http-token",
           "token": "whpa_" + "a" * 64}),
    (201, {"id": 7, "address": V4, "method": "dns-txt",
           "token": "whpa_" + "a" * 64}),
    (201, {"id": 7, "address": V4, "method": "http-token", "token": "short"}),
    (418, {"error": "a_class_we_never_sent"}),
])
def test_a_start_with_no_answer_of_ours_makes_nothing_here(sides, answer):
    instance, _ours, _client, _issued, _path = sides
    instance.opener = Scripted(answer)

    with pytest.raises(proberproofs.NotStarted) as refused:
        instance.start()

    assert refused.value.code == dispatch.NO_ANSWER
    assert authz.list_challenges(instance.con) == []


@pytest.mark.parametrize("answer", [
    (0, OSError("connection refused")),
    (0, TimeoutError()),
    (502, b"<html>bad gateway</html>"),
    (200, {"proved": True}),
    (200, {"proved": True, "result": "token_not_found"}),
    (200, {"proved": False, "result": "proved"}),
    (200, {"proved": "yes", "result": "proved"}),
    (200, {"proved": False, "result": "a_code_we_never_had"}),
    (202, {"proved": True, "result": "proved"}),
    (400, {"error": "too_large"}),
])
def test_a_verify_with_no_answer_of_ours_records_nothing_here(sides, answer):
    instance, ours, _client, _issued, _path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    instance.opener = Scripted(answer)

    outcome = instance.verify(challenge)

    assert (outcome.result.recorded, outcome.result.code, outcome.refused_by) == (
        False, dispatch.NO_ANSWER, proberproofs.PROBER_API)
    assert instance.reader.reads == 0
    assert instance.live() == []


def test_what_is_sent_is_the_address_and_the_way_with_the_key_in_the_header(sides):
    instance, _ours, _client, issued, _path = sides
    instance.opener = Scripted(
        (201, {"id": 7, "address": V4, "method": "http-token",
               "token": "whpa_" + "b" * 64}),
        (200, {"proved": False, "result": "token_not_found"}))
    challenge = instance.start()
    instance.verify(challenge)

    started, verified = instance.opener.asked
    assert (started.get_method(), started.full_url) == (
        "POST", f"{BASE}/api/v1/prober/proofs/challenges")
    assert json.loads(started.data) == {"address": V4, "method": "http-token"}
    assert (verified.get_method(), verified.full_url) == (
        "POST", f"{BASE}/api/v1/prober/proofs/challenges/7/verify")
    assert not verified.data
    for request in (started, verified):
        assert request.get_header("Authorization") == f"Bearer {issued['one'].api_key}"
    assert challenge.token == "whpa_" + "b" * 64


# ================================================ the two registries disagree

def test_proved_on_ours_and_not_here_is_not_proved_here_and_says_so(sides):
    instance, ours, client, issued, path = sides
    challenge = instance.start()
    ours.served[V4] = challenge.token
    instance.reader.served[V4] = "the page a firewall in between serves"

    outcome = instance.verify(challenge)

    assert (outcome.result.recorded, outcome.result.code, outcome.refused_by) == (
        False, "token_not_found", proberproofs.INSTANCE)
    assert instance.live() == []
    # Ours holds it for this instance, and the batch the instance sends
    # carries only what its own registry allows, which is not this address.
    assert ours_allows(path, issued["one"])


def test_a_proof_here_alone_is_never_probed(sides):
    """The fault as the test found it: proved on the instance only."""
    instance, _ours, client, issued, path = sides
    challenge = authz.start_proof(instance.con, V4, HTTP,
                                  account=authz.account_for_host(instance.host),
                                  host_id=instance.host["id"])
    assert authz.verify_proof(instance.con, challenge.id,
                              fetcher=lambda url: challenge.token).recorded

    assert instance.live() == [V4]
    assert probed_states(client, issued["one"], path) == {
        (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


# ============================================================ a second verify

def test_a_second_verify_reads_again_on_both_sides(sides):
    instance, ours, _client, issued, path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    assert instance.verify(challenge).result.recorded

    again = instance.verify(challenge)

    assert again.result.recorded and again.refused_by is None
    assert (ours.reads, instance.reader.reads) == (2, 2)
    assert instance.live() == [V4]
    assert ours_proofs(path, issued["one"]) == [(V4, HTTP)]


def test_a_verify_refused_before_the_token_was_up_proves_once_it_is(sides):
    instance, ours, _client, issued, path = sides
    challenge = instance.start()

    first = instance.verify(challenge)
    publish(instance, ours, challenge)
    second = instance.verify(challenge)

    assert (first.result.code, first.refused_by) == ("token_not_found",
                                                     proberproofs.PROBER_API)
    assert second.result.recorded and second.result.code == "proved"
    assert instance.live() == [V4]
    assert ours_allows(path, issued["one"])


# ===================================================== the daily read on ours

def test_our_daily_read_ends_it_on_ours_and_verify_proves_it_again(sides):
    instance, ours, client, issued, path = sides
    challenge = instance.start()
    publish(instance, ours, challenge)
    assert instance.verify(challenge).result.recorded

    # A day later the file holds something else when our side reads it.
    ours.served[V4] = "another owner's page"
    tomorrow = datetime.now(timezone.utc) + timedelta(hours=25)
    con = db.connect(path)
    renewal = authz.renew_published(con, now=tomorrow)
    con.close()

    assert renewal["ended"] == [V4]
    assert not ours_allows(path, issued["one"], now=tomorrow)
    assert not ours_allows(path, issued["one"])
    assert probed_states(client, issued["one"], path) == {
        (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}
    # The instance's own row does not learn of it (docs/PRODUCT.md 5g).
    assert instance.live() == [V4]

    # The token is back, and verifying again proves it on both sides.
    ours.served[V4] = challenge.token
    again = instance.verify(challenge)
    assert again.result.recorded
    assert ours_allows(path, issued["one"])
    assert {state for state, _reason in probed_states(client, issued["one"], path)} == {
        prober.STATE_CONNECTED}


# ====================================================== the happy path, last

def test_a_token_file_proof_is_made_on_both_sides_with_one_token(sides):
    instance, ours, client, issued, path = sides
    challenge = instance.start()

    assert challenge.publish_at == f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}"
    # One token: our challenge and the instance's hold the hash of the one
    # string the operator publishes, and ours is instance one's alone.
    con = db.connect(path)
    (twin,) = authz.list_challenges(con)
    con.close()
    assert twin["id"] == proberproofs.twin_of(instance.con, challenge.id)
    assert twin["account"] == issued["one"].instance.account
    assert twin["host_id"] is None
    (mine,) = authz.list_challenges(instance.con)
    assert twin["token_hash"] == mine["token_hash"] == authz.token_hash(challenge.token)

    publish(instance, ours, challenge)
    outcome = instance.verify(challenge)

    assert outcome.result.recorded and outcome.result.code == "proved"
    assert outcome.refused_by is None
    assert instance.live() == [V4]
    assert ours_proofs(path, issued["one"]) == [(V4, HTTP)]
    assert ours_proofs(path, issued["two"]) == []
    # Our listing, read after both proved, for the address row.
    assert dispatch.api_proofs_held(instance.con) == {V4}
    assert {state for state, _reason in probed_states(client, issued["one"], path)} == {
        prober.STATE_CONNECTED}


def test_a_dns_txt_proof_is_made_on_both_sides_with_one_token(sides):
    instance, ours, _client, issued, path = sides
    challenge = instance.start(method=DNS)

    assert challenge.publish_at == "153.108.199.185.in-addr.arpa"
    publish(instance, ours, challenge)
    outcome = instance.verify(challenge)

    assert outcome.result.recorded and outcome.refused_by is None
    assert instance.live() == [V4]
    assert ours_proofs(path, issued["one"]) == [(V4, DNS)]


# ================================================== the instance's own routes

def with_prober_lines(monkeypatch, opener):
    monkeypatch.setenv(dispatch.PROBER_API_ENV, BASE)
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, "whpi_" + "c" * 64)
    monkeypatch.setattr(proberproofs, "opener", lambda: opener)


def nothing_may_be_sent(monkeypatch):
    def refuse():
        raise AssertionError("an instance with no prober lines sent a request")
    monkeypatch.setattr(proberproofs, "opener", refuse)
    monkeypatch.setattr(dispatch, "start_api_proof", lambda *a, **k: refuse())
    monkeypatch.setattr(dispatch, "verify_api_proof", lambda *a, **k: refuse())


def verify_route(client, challenge_id, name="outside-only"):
    return post(client, f"/api/admin/hosts/{name}/addresses/{challenge_id}/verify")


def test_with_no_prober_lines_nothing_is_sent_and_the_answer_is_todays(client, monkeypatch):
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    nothing_may_be_sent(monkeypatch)
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: challenge["token"])

    body = verify_route(client, challenge["id"]).json()

    assert set(body) == {"ok", "code", "detail"}
    assert body["ok"] is True and body["code"] == "proved"


@pytest.mark.parametrize("environ", [
    {dispatch.PROBER_API_ENV: BASE},
    {dispatch.PROBER_API_KEY_ENV: "whpi_" + "c" * 64},
    {dispatch.PROBER_API_ENV: "http://app.whichports.test",
     dispatch.PROBER_API_KEY_ENV: "whpi_" + "c" * 64},
])
def test_half_a_setting_starts_nothing_and_sends_nothing(client, monkeypatch, environ):
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    nothing_may_be_sent(monkeypatch)
    add_address_host(client)

    r = start(client)

    assert r.status_code == 502
    assert r.json() == {"detail": f"{ADDRESS} not started with the probers: no answer",
                        "code": "no_answer", "refused_by": "prober_api"}
    con = db.connect()
    assert authz.list_challenges(con) == []
    con.close()


def test_start_with_prober_lines_reaches_our_api_through_the_clients_own_opener(
        client, monkeypatch):
    """The finding itself: on the code before 2026-10-24 nothing was asked.
    No opener is stood in here, so this is the one a running instance uses."""
    monkeypatch.setenv(dispatch.PROBER_API_ENV, BASE)
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, "whpi_" + "c" * 64)
    asked = []

    def record(self, request, data=None, timeout=None):
        asked.append(request.full_url)
        raise urllib.error.URLError("no network in this test")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", record)
    add_address_host(client)

    r = start(client)

    assert asked == [f"{BASE}/api/v1/prober/proofs/challenges"]
    assert r.status_code == 502 and r.json()["code"] == dispatch.NO_ANSWER


def test_the_route_answers_the_token_our_api_made(client, monkeypatch):
    opener = Scripted((201, {"id": 41, "address": ADDRESS, "method": "http-token",
                             "token": "whpa_" + "d" * 64}))
    with_prober_lines(monkeypatch, opener)
    add_address_host(client)

    r = start(client)

    assert r.status_code == 201, r.text
    assert r.json()["token"] == "whpa_" + "d" * 64
    con = db.connect()
    (row,) = authz.list_challenges(con)
    assert row["token_hash"] == authz.token_hash("whpa_" + "d" * 64)
    assert proberproofs.twin_of(con, row["id"]) == 41
    con.close()


@pytest.mark.parametrize("answer, status, code", [
    ((400, {"error": "target_refused"}), 400, "target_refused"),
    ((401, {"error": "unknown_key"}), 502, "unknown_key"),
    ((400, {"error": "malformed_request"}), 502, "malformed_request"),
    ((0, OSError("no route")), 502, "no_answer"),
    ((429, {"error": "over_instance_pace"}), 502, "over_instance_pace"),
])
def test_a_start_our_api_refused_says_which_side_and_its_class(client, monkeypatch,
                                                               answer, status, code):
    with_prober_lines(monkeypatch, Scripted(answer))
    add_address_host(client)

    r = start(client)

    assert r.status_code == status
    assert r.json() == {"detail": f"{ADDRESS} not started with the probers:"
                                  f" {proberproofs.CODE_WORDS[code]}",
                        "code": code, "refused_by": "prober_api"}
    con = db.connect()
    assert authz.list_challenges(con) == []
    con.close()


def test_a_verify_our_api_refused_says_which_side_and_its_class(client, monkeypatch):
    opener = Scripted((201, {"id": 41, "address": ADDRESS, "method": "http-token",
                             "token": "whpa_" + "d" * 64}),
                      (200, {"proved": False, "result": "address_held"}))
    with_prober_lines(monkeypatch, opener)
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: challenge["token"])

    body = verify_route(client, challenge["id"]).json()

    assert body == {"ok": False, "code": "address_held", "refused_by": "prober_api",
                    "detail": f"{ADDRESS} not proved with the probers: another account"
                              " holds a live proof of this address"}



def test_a_verify_our_api_paced_is_said_in_words(client, monkeypatch):
    """Our API reads one challenge at most once every few seconds and caps
    an instance's proofs by the hour. The window says so in words."""
    opener = Scripted((201, {"id": 41, "address": ADDRESS, "method": "http-token",
                             "token": "whpa_" + "d" * 64}),
                      (429, {"error": "over_instance_pace"}))
    with_prober_lines(monkeypatch, opener)
    add_address_host(client)
    challenge = start(client).json()

    body = verify_route(client, challenge["id"]).json()

    assert body == {"ok": False, "code": "over_instance_pace", "refused_by": "prober_api",
                    "detail": f"{ADDRESS} not proved with the probers:"
                              f" {proberproofs.CODE_WORDS['over_instance_pace']}"}
    assert "_" not in proberproofs.CODE_WORDS["over_instance_pace"]


LISTED = {"proofs": [{"address": ADDRESS, "family": "v4", "method": "http_token",
                      "verified_at": "2026-10-24T12:00:00+00:00",
                      "expires_at": "2099-01-01T00:00:00+00:00"}]}


@pytest.mark.parametrize("listing, held", [((200, LISTED), {ADDRESS}),
                                           ((0, OSError("no route")), set())])
def test_a_verify_both_proved_reads_our_listing_for_the_row(client, monkeypatch,
                                                            listing, held):
    """So the row reads proved at once (docs/PRODUCT.md 5g, the challenge of
    2026-10-24). A listing that does not come changes nothing kept, and the
    answer is the answer all the same."""
    opener = Scripted((201, {"id": 41, "address": ADDRESS, "method": "http-token",
                             "token": "whpa_" + "d" * 64}),
                      (200, {"proved": True, "result": "proved"}), listing)
    with_prober_lines(monkeypatch, opener)
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: challenge["token"])

    body = verify_route(client, challenge["id"]).json()

    assert body["ok"] is True and body["code"] == "proved"
    assert (opener.asked[-1].get_method(), opener.asked[-1].full_url) == (
        "GET", f"{BASE}/api/v1/prober/proofs")
    con = db.connect()
    assert dispatch.api_proofs_held(con) == held
    con.close()


def test_a_verify_both_proved_answers_the_rows_words(client, monkeypatch):
    opener = Scripted((201, {"id": 41, "address": ADDRESS, "method": "http-token",
                             "token": "whpa_" + "d" * 64}),
                      (200, {"proved": True, "result": "proved"}), (200, LISTED))
    with_prober_lines(monkeypatch, opener)
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: challenge["token"])

    body = verify_route(client, challenge["id"]).json()

    con = db.connect()
    host = store.active_host_by_name(con, "outside-only")
    (row,) = authz.live_addresses_for_host(con, host["id"])
    con.close()
    assert body == {"ok": True, "code": "proved", "refused_by": None,
                    "detail": renderbridge.load().proof_yes_words(row)}


def test_a_verify_refused_here_after_ours_proved_says_so(client, monkeypatch):
    opener = Scripted((201, {"id": 41, "address": ADDRESS, "method": "http-token",
                             "token": "whpa_" + "d" * 64}),
                      (200, {"proved": True, "result": "proved"}))
    with_prober_lines(monkeypatch, opener)
    add_address_host(client)
    challenge = start(client).json()
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: "something else")

    body = verify_route(client, challenge["id"]).json()

    assert (body["ok"], body["code"], body["refused_by"]) == (
        False, "token_not_found", "instance")


# ============================================================ the closed sets

def test_every_class_a_verify_can_end_on_is_the_registrys_or_one_of_four():
    assert proberproofs.CODES == authz.PROOF_CODES | {
        dispatch.NO_ANSWER, "unknown_key", "malformed_request", "over_instance_pace"}
    assert proberproofs.REFUSERS == (proberproofs.PROBER_API, proberproofs.INSTANCE)


def test_the_method_words_and_the_token_shape_are_our_apis():
    from app import proberapi_routes
    assert set(dispatch.PROOF_METHOD_WORDS.values()) == set(proberapi_routes.PROOF_METHODS)
    for method, word in dispatch.PROOF_METHOD_WORDS.items():
        assert proberapi_routes.PROOF_METHODS[word] == method
    assert dispatch.PROOF_TOKEN_RE.fullmatch(authz.new_token())
    assert not dispatch.PROOF_TOKEN_RE.fullmatch(authz.new_token() + "0")


# ================================================== the registry takes a token

def test_a_token_our_api_made_is_taken_as_it_is():
    con = db.connect(":memory:")
    for module in (db, authz):
        module.init(con)
    host_id = store.add_address_host(con, SERVER)
    token = authz.new_token()
    challenge = authz.start_proof(con, V4, HTTP, host_id=host_id, adopt_token=token)
    assert challenge.token == token
    (row,) = authz.list_challenges(con)
    assert row["token_hash"] == authz.token_hash(token)


@pytest.mark.parametrize("token", ["", "whpa_short", "whp_" + "a" * 64, 7,
                                   "whpa_" + "A" * 64, " whpa_" + "a" * 64])
def test_a_token_of_any_other_shape_is_refused(token):
    con = db.connect(":memory:")
    for module in (db, authz):
        module.init(con)
    host_id = store.add_address_host(con, SERVER)
    with pytest.raises(ValueError):
        authz.start_proof(con, V4, HTTP, host_id=host_id, adopt_token=token)
    assert authz.list_challenges(con) == []


def test_our_api_never_takes_a_token_for_an_instance():
    """SI-6: on our side the token is always ours to make. An instance that
    could name it could name the token another instance's file serves."""
    con = db.connect(":memory:")
    for module in (db, authz):
        module.init(con)
    with pytest.raises(ValueError):
        authz.start_proof(con, V4, HTTP, account=authz.account_for_instance(1),
                          adopt_token=authz.new_token())
    assert authz.list_challenges(con) == []


def test_our_routes_never_hand_the_registry_a_token():
    from pathlib import Path
    source = (Path(__file__).resolve().parent.parent / "app" /
              "proberapi_routes.py").read_text(encoding="utf-8")
    assert "adopt_token" not in source


# ======================================================== SI-8, our journal

def test_a_verify_our_api_did_not_prove_writes_its_class_and_no_address(sides, caplog):
    """Every verify of an instance now passes our route, so the line it
    writes when it did not prove is the class alone, the rule presence
    follows (SI-8, the challenge of 2026-10-24)."""
    instance, ours, _client, _issued, _path = sides
    challenge = instance.start()
    ours.served[V4] = "something else"
    caplog.set_level("INFO")

    assert instance.verify(challenge).result.code == "token_not_found"

    said = " ".join(record.getMessage() for record in caplog.records
                    if record.name == "app.proberapi_routes")
    assert "token_not_found" in said
    assert V4 not in said and "well-known" not in said


# ------------------------------ our side's refusal in the window's own words
#
# The second big test, 25 October 2026: on an instance, a token file our side
# could not read read "not proved with the probers: evidence_unreadable" in
# the address window, a code word on a screen. The class still crosses from
# our side and nothing more (SI-8), and the instance says it in words.

def test_every_class_our_side_can_answer_is_said_in_words():
    assert set(proberproofs.CODE_WORDS) == proberproofs.CODES
    for code in proberproofs.CODES:
        for said in (proberproofs.verify_words(ADDRESS, code),
                     proberproofs.start_words(ADDRESS, code),
                     proberproofs.revoke_words(ADDRESS, code)):
            assert "_" not in said, said
            assert code not in said or "_" not in code, said


def test_a_token_our_side_could_not_read_is_said_in_words():
    assert proberproofs.verify_words(ADDRESS, "evidence_unreadable") == (
        f"{ADDRESS} not proved with the probers: the token could not be read"
        " where it was published")


def test_a_class_nobody_knows_is_said_as_not_proved_and_no_more():
    assert proberproofs.verify_words(ADDRESS, "something_new") == (
        f"{ADDRESS} not proved with the probers")
