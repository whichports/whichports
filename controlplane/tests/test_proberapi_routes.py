"""The prober API over HTTP, through the real ingest app
(`app/proberapi_routes.py`).

Written from two attackers. One holds no key, or a revoked one, and wants to
learn anything at all. The other is a real instance that wants to see or use
what another instance has: its batches, its answers, its proofs. Both get the
same answers as for something that does not exist. And every refusal is one
word from the closed set, never a sentence (SI-8).
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import (authz, db, dispatch, dnstxt, ingest, instances, prober,
                 proberapi, proberapi_routes, proberapi_worker, vantages)

from test_proberapi_worker import Far, their_snapshot

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"
P = proberapi.PATH_PREFIX


@pytest.fixture()
def box(tmp_path, monkeypatch):
    """The ingest behind Caddy on loopback, with two vantages and two
    instances. Returns (client, {name: Issued}, path)."""
    path = str(tmp_path / "cp.db")
    monkeypatch.setenv(db.DB_ENV, path)
    con = db.connect()
    for module in (db, authz, prober, vantages, instances, proberapi):
        module.init(con)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    issued = {name: instances.add(con, name, origin=authz.ORIGIN_INVITED)
              for name in ("one", "two")}
    con.close()
    client = TestClient(ingest.app, client=("127.0.0.1", 40000))
    return client, issued, path


def key(issued, kind="api"):
    return {"Authorization": "Bearer " + (issued.api_key if kind == "api"
                                          else issued.proof_key)}


def batch(**overrides):
    base = {"version": dispatch.BATCH_VERSION, "vantage": "probe1",
            "addresses": [V4], "ports": [22, 80], "tls_ports": [],
            "snapshot": their_snapshot([V4])}
    base.update(overrides)
    return base


def post_batch(client, issued, body=None, **overrides):
    return client.post(f"{P}/batches", headers=key(issued),
                       content=json.dumps(body if body is not None else batch(**overrides)))


def presence(client, issued, claimed, forwarded=V4, headers=None):
    sent = dict(key(issued, "proof"))
    if forwarded is not None:
        sent["X-Forwarded-For"] = forwarded
    sent.update(headers or {})
    return client.post(f"{P}/presence", headers=sent,
                       content=json.dumps({"interface_addresses": claimed}))


def proofs_of(path, issued):
    con = db.connect(path)
    try:
        return [row["target"] for row in
                authz.live_for_account(con, issued.instance.account)]
    finally:
        con.close()


def work(path):
    con = db.connect(path)
    try:
        return proberapi_worker.run_round(con, transport_factory=Far().factory,
                                          lock_wait_seconds=5)
    finally:
        con.close()


def assert_refused(response, error):
    """One class, its status, and nothing else in the body."""
    assert response.status_code == proberapi.ERRORS[error], response.text
    assert response.json() == {"error": error}
    assert response.headers["cache-control"] == "no-store"


# ================================================================= the keys

ROUTES = [
    ("post", f"{P}/batches"), ("get", f"{P}/batches/abc"),
    ("get", f"{P}/vantages"), ("get", f"{P}/proofs"),
    ("post", f"{P}/proofs/challenges"), ("post", f"{P}/proofs/challenges/1/verify"),
    ("delete", f"{P}/proofs/{V4}"),
]


@pytest.mark.parametrize("method, route", ROUTES + [("post", f"{P}/presence")])
@pytest.mark.parametrize("header", [
    None, "Bearer ", "Bearer whpi_" + "0" * 64, "Basic abc", "whpi_x",
])
def test_no_key_is_the_same_401_everywhere(box, method, route, header):
    client, _issued, _path = box
    headers = {} if header is None else {"Authorization": header}
    kwargs = {"content": b"{}"} if method == "post" else {}
    assert_refused(getattr(client, method)(route, headers=headers, **kwargs),
                   "unknown_key")


@pytest.mark.parametrize("method, route", ROUTES)
def test_a_revoked_key_reads_exactly_like_one_never_issued(box, method, route):
    client, issued, path = box
    con = db.connect(path)
    instances.revoke(con, "one")
    con.close()
    kwargs = {"content": b"{}"} if method == "post" else {}
    revoked = getattr(client, method)(route, headers=key(issued["one"]), **kwargs)
    never = getattr(client, method)(route, headers={
        "Authorization": "Bearer whpi_" + "f" * 64}, **kwargs)
    assert_refused(revoked, "unknown_key")
    assert revoked.content == never.content


def test_a_proof_key_cannot_send_a_batch_and_an_api_key_cannot_prove(box):
    client, issued, path = box
    response = client.post(f"{P}/batches", headers=key(issued["one"], "proof"),
                           content=json.dumps(batch()))
    assert_refused(response, "unknown_key")
    response = client.post(f"{P}/presence", headers={
        **key(issued["one"]), "X-Forwarded-For": V4},
        content=json.dumps({"interface_addresses": [V4]}))
    assert_refused(response, "unknown_key")
    assert proofs_of(path, issued["one"]) == []


# ============================================================ a batch, whole

def test_a_batch_is_queued_measured_and_handed_back_once(box):
    client, issued, path = box
    presence(client, issued["one"], [V4])
    queued = post_batch(client, issued["one"])
    assert queued.status_code == 202
    batch_id = queued.json()["id"]
    assert queued.json()["state"] == "queued"

    waiting = client.get(f"{P}/batches/{batch_id}", headers=key(issued["one"]))
    assert waiting.status_code == 202
    assert waiting.json() == {"state": "queued"}

    assert work(path) == ["done"]
    done = client.get(f"{P}/batches/{batch_id}", headers=key(issued["one"]))
    assert done.status_code == 200
    assert done.json()["state"] == "done"
    measured = prober.run_from_json(done.json()["answer"])
    assert {r.state for r in measured.results if r.target == V4} == {
        prober.STATE_CONNECTED}

    assert_refused(client.get(f"{P}/batches/{batch_id}", headers=key(issued["one"])),
                   "unknown_batch")


def test_another_instances_batch_is_a_batch_that_does_not_exist(box):
    client, issued, _path = box
    batch_id = post_batch(client, issued["one"]).json()["id"]
    theirs = client.get(f"{P}/batches/{batch_id}", headers=key(issued["two"]))
    nothing = client.get(f"{P}/batches/nothing", headers=key(issued["two"]))
    assert_refused(theirs, "unknown_batch")
    assert theirs.content == nothing.content
    # Still there for its owner.
    assert client.get(f"{P}/batches/{batch_id}",
                      headers=key(issued["one"])).status_code == 202


def test_an_address_another_instance_proved_is_not_probed_for_this_one(box):
    client, issued, path = box
    presence(client, issued["one"], [V4])
    batch_id = post_batch(client, issued["two"]).json()["id"]
    work(path)
    answer = client.get(f"{P}/batches/{batch_id}", headers=key(issued["two"])).json()
    measured = prober.run_from_json(answer["answer"])
    assert {r.reason for r in measured.results if r.target == V4} == {
        prober.REASON_NO_AUTHORIZATION}


# ============================================================ each refusal

@pytest.mark.parametrize("body, error", [
    (b"not json", "malformed_request"),
    (b"\xff\xfe", "malformed_request"),
    (b"[]", "malformed_request"),
    (json.dumps(batch(version=9)).encode(), "unsupported_version"),
    (json.dumps(batch(vantage="probe9")).encode(), "unknown_vantage"),
    (json.dumps(batch(addresses=[PROBE2_V4])).encode(), "names_a_vantage_address"),
    (json.dumps(batch(ports=list(range(1, 300)))).encode(), "malformed_request"),
    (json.dumps(batch(snapshot=None)).encode(), "malformed_request"),
])
def test_a_bad_batch_is_refused_with_its_class(box, body, error):
    client, issued, _path = box
    response = client.post(f"{P}/batches", headers=key(issued["one"]), content=body)
    assert_refused(response, error)


def test_a_body_that_is_too_large_is_refused_before_it_is_read(box):
    client, issued, _path = box
    response = client.post(f"{P}/batches", headers={
        **key(issued["one"]), "Content-Length": str(proberapi.MAX_BODY_BYTES + 1)},
        content=b"x" * (proberapi.MAX_BODY_BYTES + 1))
    assert_refused(response, "too_large")


def test_a_second_batch_while_one_is_in_flight_is_refused(box):
    client, issued, _path = box
    assert post_batch(client, issued["one"]).status_code == 202
    assert_refused(post_batch(client, issued["one"]), "batch_in_flight")
    assert post_batch(client, issued["two"]).status_code == 202


def test_over_the_hour_says_when_to_come_back(box, monkeypatch):
    client, issued, _path = box
    monkeypatch.setattr(proberapi, "CONNECTS_PER_HOUR", 1)
    response = post_batch(client, issued["one"])
    assert_refused(response, "over_instance_pace")
    assert int(response.headers["retry-after"]) >= 1


def test_every_refusal_is_a_word_from_the_closed_set(box):
    """Whatever goes wrong, the body is one class and nothing a person wrote."""
    client, issued, _path = box
    responses = [
        client.post(f"{P}/batches", content=b"{}"),
        client.post(f"{P}/batches", headers=key(issued["one"]), content=b"{"),
        client.get(f"{P}/batches/zzz", headers=key(issued["one"])),
        client.post(f"{P}/proofs/challenges", headers=key(issued["one"]),
                    content=json.dumps({"address": "10.0.0.1", "method": "dns-txt"})),
        client.post(f"{P}/proofs/challenges/abc/verify", headers=key(issued["one"])),
        client.delete(f"{P}/proofs/localhost", headers=key(issued["one"])),
    ]
    for response in responses:
        body = response.json()
        assert set(body) == {"error"}
        assert body["error"] in proberapi.ERRORS


# ================================================================= vantages

def test_vantages_are_names_and_addresses_and_never_the_ssh_destination(box):
    client, issued, path = box
    con = db.connect(path)
    vantages.set_enabled(con, "probe2", False)
    con.close()
    response = client.get(f"{P}/vantages", headers=key(issued["one"]))
    assert response.status_code == 200
    assert response.json() == {"vantages": [
        {"name": "probe1", "enabled": True, "addresses": [PROBE1_V4]},
        {"name": "probe2", "enabled": False, "addresses": [PROBE2_V4]}]}
    assert "root@" not in response.text


# ================================================================= presence

def test_presence_proves_the_address_it_arrived_from_when_it_is_claimed(box):
    client, issued, path = box
    response = presence(client, issued["one"], [V4, V6])
    assert response.status_code == 204
    assert response.content == b""
    # V6 was claimed but the request did not arrive from it.
    assert proofs_of(path, issued["one"]) == [V4]
    assert proofs_of(path, issued["two"]) == []


def test_presence_from_an_address_the_host_does_not_claim_proves_nothing(box):
    """A host behind NAT: the request arrives from a gateway it does not hold."""
    client, issued, path = box
    assert presence(client, issued["one"], [V6], forwarded=V4).status_code == 204
    assert proofs_of(path, issued["one"]) == []


def test_a_claimed_address_the_request_did_not_come_from_proves_nothing(box):
    client, issued, path = box
    assert presence(client, issued["one"], [OTHER_V4], forwarded=V4).status_code == 204
    assert proofs_of(path, issued["one"]) == []


@pytest.mark.parametrize("forwarded, headers", [
    (None, None),
    (f"{OTHER_V4}, {V4}", None),
    ("10.0.0.5", None),
    (V4 + ":443", None),
])
def test_presence_trusts_the_forwarded_address_only_as_the_ingest_does(
        box, forwarded, headers):
    client, issued, path = box
    claimed = [V4, OTHER_V4, "10.0.0.5"]
    assert presence(client, issued["one"], claimed, forwarded=forwarded,
                    headers=headers).status_code == 204
    assert proofs_of(path, issued["one"]) == []


def test_presence_on_a_connection_that_did_not_come_from_loopback_proves_nothing(box):
    _client, issued, path = box
    outside = TestClient(ingest.app, client=(OTHER_V4, 40000))
    assert presence(outside, issued["one"], [V4]).status_code == 204
    assert proofs_of(path, issued["one"]) == []


@pytest.mark.parametrize("claimed", [None, V4, {"a": V4}, [["x"]], [4],
                                     [V4] * 65, [V4 + "%eth0"]])
def test_a_claim_of_the_wrong_shape_proves_nothing(box, claimed):
    client, issued, path = box
    assert presence(client, issued["one"], claimed).status_code == 204
    assert proofs_of(path, issued["one"]) == []


def test_a_presence_body_that_is_not_json_is_refused(box):
    client, issued, _path = box
    response = client.post(f"{P}/presence", headers={
        **key(issued["one"], "proof"), "X-Forwarded-For": V4}, content=b"nope")
    assert_refused(response, "malformed_request")


def test_the_answer_to_presence_says_nothing_about_the_outcome(box):
    """The agent reads nothing (SI-2), and a proof key may not ask whether an
    address was proved. Proved and not proved are the same empty 204."""
    client, issued, _path = box
    proved = presence(client, issued["one"], [V4])
    refused = presence(client, issued["one"], [OTHER_V4])
    assert proved.status_code == refused.status_code == 204
    assert proved.content == refused.content == b""


# =================================================================== proofs

def test_proofs_lists_this_instances_own_and_no_one_elses(box):
    client, issued, _path = box
    presence(client, issued["one"], [V4])
    mine = client.get(f"{P}/proofs", headers=key(issued["one"])).json()
    theirs = client.get(f"{P}/proofs", headers=key(issued["two"])).json()
    assert [p["address"] for p in mine["proofs"]] == [V4]
    assert mine["proofs"][0]["method"] == authz.METHOD_AGENT
    assert theirs == {"proofs": []}


def test_a_dns_proof_is_started_and_verified_for_this_instance_only(box, clock, monkeypatch):
    client, issued, path = box
    started = client.post(f"{P}/proofs/challenges", headers=key(issued["one"]),
                          content=json.dumps({"address": V4, "method": "dns-txt"}))
    assert started.status_code == 201
    challenge = started.json()
    assert challenge["publish_at"] == "153.108.199.185.in-addr.arpa"
    assert challenge["token"].startswith(authz.TOKEN_PREFIX)

    # The other instance cannot verify it, and cannot tell it exists.
    assert_refused(client.post(f"{P}/proofs/challenges/{challenge['id']}/verify",
                               headers=key(issued["two"])), "unknown_challenge")

    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [])
    missing = client.post(f"{P}/proofs/challenges/{challenge['id']}/verify",
                          headers=key(issued["one"]))
    assert missing.json() == {"proved": False, "result": "token_not_found"}

    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [challenge["token"]])
    clock[0] += timedelta(seconds=proberapi.PROOF_VERIFY_SPACING_SECONDS)
    proved = client.post(f"{P}/proofs/challenges/{challenge['id']}/verify",
                         headers=key(issued["one"]))
    assert proved.json() == {"proved": True, "result": "proved"}
    assert proofs_of(path, issued["one"]) == [V4]
    assert proofs_of(path, issued["two"]) == []


@pytest.mark.parametrize("body, error", [
    ({"address": "10.0.0.1", "method": "dns-txt"}, "target_refused"),
    ({"address": V4, "method": "agent"}, "malformed_request"),
    ({"address": V4}, "malformed_request"),
    ({"method": "http-token"}, "malformed_request"),
    ([V4], "malformed_request"),
])
def test_a_bad_challenge_is_refused(box, body, error):
    client, issued, _path = box
    assert_refused(client.post(f"{P}/proofs/challenges", headers=key(issued["one"]),
                               content=json.dumps(body)), error)


@pytest.mark.parametrize("challenge_id", ["abc", "-1", "1.0", "9" * 19, "999"])
def test_a_challenge_that_is_not_ones_own_is_unknown(box, challenge_id):
    client, issued, _path = box
    assert_refused(client.post(f"{P}/proofs/challenges/{challenge_id}/verify",
                               headers=key(issued["one"])), "unknown_challenge")


def test_every_verify_result_is_a_known_code():
    assert "proved" in authz.PROOF_CODES
    assert "token_not_found" in authz.PROOF_CODES


def test_revoking_an_address_ends_this_instances_proof_only(box):
    """Since 2026-10-20 one address belongs to one instance, so the other
    instance holds an address of its own here, and one instance's revoke of
    it reaches nothing."""
    client, issued, path = box
    presence(client, issued["one"], [V4])
    presence(client, issued["two"], [OTHER_V4], forwarded=OTHER_V4)
    response = client.delete(f"{P}/proofs/{V4}", headers=key(issued["one"]))
    assert response.json() == {"revoked": 1}
    other = client.delete(f"{P}/proofs/{OTHER_V4}", headers=key(issued["one"]))
    assert other.json() == {"revoked": 0}
    assert proofs_of(path, issued["one"]) == []
    assert proofs_of(path, issued["two"]) == [OTHER_V4]
    assert_refused(client.delete(f"{P}/proofs/10.0.0.1", headers=key(issued["one"])),
                   "target_refused")


# ===================================================== proofs are paced
#
# Since the open signup a stranger can hold an API key, and every start and
# every verify of a proof makes our side do something: a row, or a read of a
# DNS record or of a file at an address the instance names. So both are
# counted per instance and per hour, like the connects, and one challenge is
# read at most once every few seconds. Every instance is held to the same
# numbers, invited or signed up.

def addresses(count, third=0):
    return [f"185.199.{third + n // 200}.{n % 200 + 1}" for n in range(count)]


@pytest.fixture()
def clock(monkeypatch):
    """The routes' clock, moved by hand."""
    now = [datetime(2026, 11, 2, 9, 0, tzinfo=timezone.utc)]
    monkeypatch.setattr(proberapi_routes, "_now", lambda: now[0])
    return now


def start_proof(client, issued, address, method="dns-txt"):
    return client.post(f"{P}/proofs/challenges", headers=key(issued),
                       content=json.dumps({"address": address, "method": method}))


def verify_proof(client, issued, challenge_id):
    return client.post(f"{P}/proofs/challenges/{challenge_id}/verify",
                       headers=key(issued))


def assert_paced(response):
    assert_refused(response, "over_instance_pace")
    assert int(response.headers["retry-after"]) >= 1


def instance_of(path, name, origin):
    con = db.connect(path)
    try:
        return instances.add(con, name, origin=origin)
    finally:
        con.close()


@pytest.mark.parametrize("origin", [authz.ORIGIN_INVITED, authz.ORIGIN_SIGNUP])
def test_proof_starts_are_capped_per_instance_per_hour(box, clock, origin):
    client, issued, path = box
    mine = instance_of(path, "paced", origin)
    for address in addresses(proberapi.PROOF_STARTS_PER_HOUR):
        assert start_proof(client, mine, address).status_code == 201
    assert_paced(start_proof(client, mine, addresses(1, third=50)[0]))
    # Another instance is not held by this one's count.
    assert start_proof(client, issued["two"], addresses(1, third=51)[0]).status_code == 201
    clock[0] += timedelta(hours=1, seconds=1)
    assert start_proof(client, mine, addresses(1, third=52)[0]).status_code == 201


def test_an_honest_instance_proves_a_few_dozen_addresses_in_an_hour():
    """The numbers leave room for an instance proving forty addresses, each
    started once and verified a few times."""
    assert proberapi.PROOF_STARTS_PER_HOUR >= 40
    assert proberapi.PROOF_VERIFIES_PER_HOUR >= 40 * 4
    assert 1 <= proberapi.PROOF_VERIFY_SPACING_SECONDS <= 10


@pytest.mark.parametrize("origin", [authz.ORIGIN_INVITED, authz.ORIGIN_SIGNUP])
def test_proof_reads_are_capped_per_instance_per_hour(box, clock, monkeypatch, origin):
    client, _issued, path = box
    mine = instance_of(path, "paced", origin)
    reads = []
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: reads.append(name) or [])
    challenge = start_proof(client, mine, V4).json()
    for _ in range(proberapi.PROOF_VERIFIES_PER_HOUR):
        clock[0] += timedelta(seconds=proberapi.PROOF_VERIFY_SPACING_SECONDS)
        assert verify_proof(client, mine, challenge["id"]).json() == {
            "proved": False, "result": "token_not_found"}
    clock[0] += timedelta(seconds=proberapi.PROOF_VERIFY_SPACING_SECONDS)
    assert_paced(verify_proof(client, mine, challenge["id"]))
    assert len(reads) == proberapi.PROOF_VERIFIES_PER_HOUR


def test_one_challenge_is_read_at_most_once_every_few_seconds(box, clock, monkeypatch):
    client, issued, _path = box
    reads = []
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: reads.append(name) or [])
    first = start_proof(client, issued["one"], V4).json()
    second = start_proof(client, issued["one"], OTHER_V4).json()
    assert verify_proof(client, issued["one"], first["id"]).json()["result"] == "token_not_found"
    clock[0] += timedelta(seconds=1)
    assert_paced(verify_proof(client, issued["one"], first["id"]))
    # Another challenge of the same instance is read at once.
    assert verify_proof(client, issued["one"], second["id"]).json()["result"] == "token_not_found"
    assert len(reads) == 2
    clock[0] += timedelta(seconds=proberapi.PROOF_VERIFY_SPACING_SECONDS)
    assert verify_proof(client, issued["one"], first["id"]).json()["result"] == "token_not_found"
    assert len(reads) == 3


def test_a_verify_of_a_challenge_that_is_not_ones_own_spends_nothing(box, clock):
    client, issued, path = box
    for _ in range(proberapi.PROOF_VERIFIES_PER_HOUR + 1):
        assert_refused(verify_proof(client, issued["one"], 999), "unknown_challenge")
    con = db.connect(path)
    try:
        assert con.execute("SELECT COUNT(*) FROM prober_api_proof_uses").fetchone()[0] == 0
    finally:
        con.close()


def test_the_hours_proof_counts_go_with_the_hour(box, clock, monkeypatch):
    client, issued, path = box
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [])
    challenge = start_proof(client, issued["one"], V4).json()
    verify_proof(client, issued["one"], challenge["id"])
    con = db.connect(path)
    try:
        assert con.execute("SELECT COUNT(*) FROM prober_api_proof_uses").fetchone()[0] == 2
        proberapi.sweep(con, clock[0] + timedelta(hours=1, seconds=1))
        assert con.execute("SELECT COUNT(*) FROM prober_api_proof_uses").fetchone()[0] == 0
    finally:
        con.close()


# ======================================= a challenge that proved nothing
#
# A start keeps the address the instance named. One that never proved it is
# kept for its day and no longer: the sweep deletes it once its day is over,
# for every instance. A proved one stays, as the record of the proof.

def test_an_instances_expired_challenge_that_proved_nothing_is_deleted(box, clock, monkeypatch):
    client, issued, path = box
    unproved = start_proof(client, issued["one"], V4).json()
    proved = start_proof(client, issued["two"], OTHER_V4).json()
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [proved["token"]])
    assert verify_proof(client, issued["two"], proved["id"]).json()["proved"] is True
    con = db.connect(path)
    try:
        # Our own control plane's challenge is not an instance's: it stays.
        ours = authz.start_proof(con, "185.199.111.1", authz.METHOD_DNS_TXT, now=clock[0])
        assert authz.forget_unproved_challenges(con, clock[0] + timedelta(hours=23)) == 0
        assert authz.forget_unproved_challenges(
            con, clock[0] + timedelta(seconds=authz.CHALLENGE_TTL_SECONDS + 1)) == 1
        left = {row["id"] for row in authz.list_challenges(con)}
    finally:
        con.close()
    assert unproved["id"] not in left
    assert {proved["id"], ours.id} <= left


def test_the_sweep_deletes_an_instances_challenge_that_proved_nothing(box, capsys):
    _client, issued, path = box
    long_ago = datetime.now(timezone.utc) - timedelta(days=2)
    con = db.connect(path)
    try:
        challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT,
                                      account=issued["one"].instance.account, now=long_ago)
    finally:
        con.close()
    from app import sweep_cli
    assert sweep_cli.main([]) == 0
    con = db.connect(path)
    try:
        assert challenge.id not in {row["id"] for row in authz.list_challenges(con)}
    finally:
        con.close()
    assert "1 challenges that proved nothing deleted" in capsys.readouterr().out


# ======================= what stops our probers on an instance's address
#
# ops/RUNBOOK.md, "Answering an abuse report", names what stops them: the
# exclusion list for the address, and revoking the instance for the rest of
# what it proved. These hold that section to the code.

def test_an_address_revoked_on_our_side_is_proved_again_by_the_next_presence(box):
    """`authz_cli revoke` closes the proof, and the instance's agent proves
    the address again with its next presence, a new row after the revoked one
    (`authz._record`). So an address revoke alone does not stop the probing."""
    client, issued, path = box
    presence(client, issued["one"], [V4])
    con = db.connect(path)
    try:
        assert authz.revoke(con, V4) == 1
    finally:
        con.close()
    assert proofs_of(path, issued["one"]) == []
    assert presence(client, issued["one"], [V4]).status_code == 204
    assert proofs_of(path, issued["one"]) == [V4]


def test_revoking_the_instance_stops_every_address_it_proved(box):
    """`instances_cli revoke` is the stop, and it is the whole instance:
    every address it proved, its keys, and no presence proves one again. The
    other instance's own address is untouched, and the address the revoked
    one held is free for another instance from then on."""
    client, issued, path = box
    presence(client, issued["one"], [V4])
    presence(client, issued["two"], [OTHER_V4], forwarded=OTHER_V4)
    con = db.connect(path)
    try:
        instances.revoke(con, "one")
    finally:
        con.close()
    assert proofs_of(path, issued["one"]) == []
    assert_refused(presence(client, issued["one"], [V4]), "unknown_key")
    assert proofs_of(path, issued["one"]) == []
    assert proofs_of(path, issued["two"]) == [OTHER_V4]
    presence(client, issued["two"], [V4])
    assert sorted(proofs_of(path, issued["two"])) == sorted([V4, OTHER_V4])


def test_an_excluded_address_is_not_proved_again_by_the_next_presence(box):
    """`authz_cli exclude` is the stop for one address: it closes the proof,
    and neither this instance's next presence nor another's proves it again
    (docs/PRODUCT.md 5, the exclusion list)."""
    client, issued, path = box
    presence(client, issued["one"], [V4])
    con = db.connect(path)
    try:
        assert authz.exclude(con, V4) == (True, 1)
    finally:
        con.close()
    for name in ("one", "two"):
        assert presence(client, issued[name], [V4]).status_code == 204
        assert proofs_of(path, issued[name]) == []


# ============= a shared address, the clauses of 2026-10-20 (docs/PRODUCT.md 5)

def add_instance(path, name, origin):
    con = db.connect(path)
    try:
        return instances.add(con, name, origin=origin)
    finally:
        con.close()


def test_presence_of_a_signup_instance_proves_nothing_and_answers_the_same(box, caplog):
    client, issued, path = box
    stranger = add_instance(path, "stranger", authz.ORIGIN_SIGNUP)
    caplog.set_level("INFO")
    answered = presence(client, stranger, [V4])
    proved = presence(client, issued["one"], [OTHER_V4], forwarded=OTHER_V4)
    assert answered.status_code == proved.status_code == 204
    assert answered.content == proved.content == b""
    assert proofs_of(path, stranger) == []
    assert "presence proved nothing: not_invited" in caplog.text


def test_a_signup_instance_proves_by_dns_txt(box, monkeypatch):
    client, _issued, path = box
    stranger = add_instance(path, "stranger", authz.ORIGIN_SIGNUP)
    started = client.post(f"{P}/proofs/challenges", headers=key(stranger),
                          content=json.dumps({"address": V4, "method": "dns-txt"})).json()
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [started["token"]])
    proved = client.post(f"{P}/proofs/challenges/{started['id']}/verify",
                         headers=key(stranger))
    assert proved.json() == {"proved": True, "result": "proved"}
    assert proofs_of(path, stranger) == [V4]


def test_a_second_instances_presence_for_a_held_address_proves_nothing(box, caplog):
    client, issued, path = box
    presence(client, issued["one"], [V4])
    before = client.get(f"{P}/proofs", headers=key(issued["one"])).json()
    caplog.set_level("INFO")
    assert presence(client, issued["two"], [V4]).status_code == 204
    assert proofs_of(path, issued["two"]) == []
    assert "presence proved nothing: address_held" in caplog.text
    # What the first instance sees has not changed.
    assert client.get(f"{P}/proofs", headers=key(issued["one"])).json() == before


def test_a_second_instance_verifying_a_held_address_is_told_address_held(box, monkeypatch):
    """Held by a published proof. A presence it would close instead."""
    client, issued, path = box
    first = client.post(f"{P}/proofs/challenges", headers=key(issued["one"]),
                        content=json.dumps({"address": V4, "method": "dns-txt"})).json()
    started = client.post(f"{P}/proofs/challenges", headers=key(issued["two"]),
                          content=json.dumps({"address": V4, "method": "dns-txt"}))
    assert started.status_code == 201
    challenge = started.json()
    # The reverse zone holds both tokens, so the first proof still stands.
    monkeypatch.setattr(dnstxt, "query_txt",
                        lambda name: [first["token"], challenge["token"]])
    held = client.post(f"{P}/proofs/challenges/{first['id']}/verify",
                       headers=key(issued["one"]))
    assert held.json() == {"proved": True, "result": "proved"}
    answer = client.post(f"{P}/proofs/challenges/{challenge['id']}/verify",
                         headers=key(issued["two"]))
    assert answer.json() == {"proved": False, "result": "address_held"}
    assert proofs_of(path, issued["two"]) == []
    assert proofs_of(path, issued["one"]) == [V4]


def test_an_excluded_address_is_refused_by_every_route(box, monkeypatch):
    """Presence, start and verify, for an instance that held it, one that
    did not, and one made after the exclusion. A refusal is the class an
    address that can never be a target gets."""
    client, issued, path = box
    presence(client, issued["one"], [V4])
    started = client.post(f"{P}/proofs/challenges", headers=key(issued["two"]),
                          content=json.dumps({"address": V4, "method": "dns-txt"})).json()
    con = db.connect(path)
    try:
        authz.exclude(con, V4)
        # A challenge left open beside the exclusion, which `exclude` never
        # leaves, so that verify's own refusal is what is read below.
        con.execute("UPDATE authz_challenges SET cancelled_at = NULL")
        con.commit()
    finally:
        con.close()
    later = add_instance(path, "later", authz.ORIGIN_INVITED)
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [started["token"]])

    for holder in (issued["one"], issued["two"], later):
        assert presence(client, holder, [V4]).status_code == 204
        assert_refused(client.post(f"{P}/proofs/challenges", headers=key(holder),
                                   content=json.dumps({"address": V4,
                                                       "method": "http-token"})),
                       "target_refused")
        assert proofs_of(path, holder) == []
    verified = client.post(f"{P}/proofs/challenges/{started['id']}/verify",
                           headers=key(issued["two"]))
    assert verified.json() == {"proved": False, "result": "target_refused"}
    assert proofs_of(path, issued["two"]) == []


def test_what_an_instance_sees_when_its_address_is_excluded(box, monkeypatch):
    """What docs/PRODUCT.md 5 and the runbook say an instance sees, read
    from the routes: its proof gone from the listing, a proof in progress
    answering challenge_cancelled, and a new start target_refused."""
    client, issued, path = box
    presence(client, issued["one"], [V4])
    started = client.post(f"{P}/proofs/challenges", headers=key(issued["one"]),
                          content=json.dumps({"address": V4, "method": "dns-txt"})).json()
    con = db.connect(path)
    try:
        authz.exclude(con, V4)
    finally:
        con.close()
    assert client.get(f"{P}/proofs", headers=key(issued["one"])).json() == {"proofs": []}
    monkeypatch.setattr(dnstxt, "query_txt", lambda name: [started["token"]])
    verified = client.post(f"{P}/proofs/challenges/{started['id']}/verify",
                           headers=key(issued["one"]))
    assert verified.json() == {"proved": False, "result": "challenge_cancelled"}
    assert_refused(client.post(f"{P}/proofs/challenges", headers=key(issued["one"]),
                               content=json.dumps({"address": V4, "method": "dns-txt"})),
                   "target_refused")


def test_a_presence_writes_no_address_to_the_journal(box, caplog):
    """SI-8: a server's address every quarter hour is not a journal line.
    A presence that proves writes none at all, and one that proves nothing
    writes its class and nothing else (decided 2026-10-20)."""
    client, issued, path = box
    stranger = add_instance(path, "stranger", authz.ORIGIN_SIGNUP)
    caplog.set_level("DEBUG", logger="app")
    presence(client, issued["one"], [V4])
    assert caplog.records == []
    presence(client, issued["two"], [V4])                       # held
    presence(client, issued["two"], [V6], forwarded=OTHER_V4)   # not claimed
    presence(client, stranger, [OTHER_V4], forwarded=OTHER_V4)  # not invited
    lines = [record.getMessage() for record in caplog.records]
    assert lines == ["presence proved nothing: address_held",
                     "presence proved nothing: not_held",
                     "presence proved nothing: not_invited"]
    for address in (V4, V6, OTHER_V4):
        assert address not in caplog.text
    assert "stranger" not in caplog.text and "two" not in caplog.text


def test_nothing_a_presence_request_carries_reaches_the_journal(box, caplog):
    client, issued, path = box
    stranger = add_instance(path, "stranger", authz.ORIGIN_SIGNUP)
    caplog.set_level("DEBUG", logger="app")
    marker = "typed-by-the-sender"
    for sender in (issued["one"], issued["two"], stranger):
        presence(client, sender, [V4, marker],
                 headers={"User-Agent": marker})
    assert marker not in caplog.text


# =============================== the stamp of a key's use, 2026-10-06 (4.425)
#
# His level 2 for the admin console (docs/screens/admin/SPEC.md): an instance's
# heartbeat on our box is its API key's last use, written when a key passes
# the check every route makes. A timestamp on the key's own row and nothing
# else, API key only, never on a refusal.

def key_rows(path, issued):
    con = db.connect(path)
    rows = con.execute("SELECT kind, last_used_at FROM probe_instance_keys"
                       " WHERE instance_id = ? ORDER BY kind", (issued.instance.id,)).fetchall()
    con.close()
    return {r["kind"]: r["last_used_at"] for r in rows}


def table_counts(path):
    con = db.connect(path)
    names = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
    counts = {n: con.execute(f"SELECT COUNT(*) FROM {n}").fetchone()[0] for n in names}
    con.close()
    return counts


def test_a_used_api_key_is_stamped_once_per_request_and_a_proof_key_never(box):
    client, issued, path = box
    assert key_rows(path, issued["one"]) == {"api": None, "proof": None}
    first = client.get(f"{P}/vantages", headers=key(issued["one"]))
    assert first.status_code == 200
    after_one = key_rows(path, issued["one"])
    assert after_one["api"] and after_one["proof"] is None
    second = client.get(f"{P}/vantages", headers=key(issued["one"]))
    assert second.status_code == 200
    after_two = key_rows(path, issued["one"])
    assert after_two["api"] >= after_one["api"]
    # a proof key's request stamps nothing, on either row
    presence(client, issued["one"], V4)
    assert key_rows(path, issued["one"])["proof"] is None
    assert key_rows(path, issued["one"])["api"] == after_two["api"]
    # the other instance's key is untouched
    assert key_rows(path, issued["two"]) == {"api": None, "proof": None}


def test_a_refused_key_stamps_nothing(box):
    client, issued, path = box
    before = table_counts(path)
    response = client.get(f"{P}/vantages", headers={"Authorization": "Bearer whpi_" + "0" * 64})
    assert response.status_code == 401
    assert key_rows(path, issued["one"]) == {"api": None, "proof": None}
    assert table_counts(path) == before


def test_the_stamp_is_a_timestamp_and_nothing_else_is_written_on_the_path(box):
    client, issued, path = box
    before = table_counts(path)
    client.get(f"{P}/vantages", headers=key(issued["one"]))
    assert table_counts(path) == before, "no row was added or removed anywhere"
    stamped = key_rows(path, issued["one"])["api"]
    from datetime import datetime
    datetime.fromisoformat(stamped)
    con = db.connect(path)
    row = con.execute("SELECT * FROM probe_instance_keys WHERE instance_id = ? AND kind = 'api'",
                      (issued["one"].instance.id,)).fetchone()
    con.close()
    assert row["revoked_at"] is None and row["key_hash"]


# Four more, asked for in review on 2026-10-06, by what they show.

def set_stamp(path, issued, when):
    con = db.connect(path)
    con.execute("UPDATE probe_instance_keys SET last_used_at = ? WHERE instance_id = ?"
                " AND kind = 'api'", (when, issued.instance.id))
    con.commit()
    con.close()


def test_a_burst_inside_a_minute_writes_the_column_once(box):
    client, issued, path = box
    for _ in range(20):
        assert client.get(f"{P}/vantages", headers=key(issued["one"])).status_code == 200
    first = key_rows(path, issued["one"])["api"]
    assert first
    for _ in range(20):
        client.get(f"{P}/vantages", headers=key(issued["one"]))
    assert key_rows(path, issued["one"])["api"] == first, "the same stamp, written once"


def test_the_stamp_against_a_held_lock_is_dropped_at_once(box):
    """A busy database costs the stamp, never the answer and never a wait.

    Measured at the stamp itself, because the routes' own `_open` runs
    `db.init` on every request, whose INSERT OR IGNORE on workspaces takes the
    write lock before any route code runs: a lock held across a whole request
    already breaks every route today, with or without the stamp. What the
    stamp controls is its own wait and its own failure, and both are small.
    """
    import time
    client, issued, path = box
    stale = "2026-09-30T12:00:00+00:00"
    set_stamp(path, issued["one"], stale)
    holder = db.connect(path)
    holder.execute("BEGIN IMMEDIATE")
    try:
        started = time.perf_counter()
        written = instances.stamp_api_key_use(path, issued["one"].api_key)
        took = time.perf_counter() - started
    finally:
        holder.rollback()
        holder.close()
    assert written is False
    assert took < 0.5, f"the stamp waited {took:.2f}s on a held lock"
    assert key_rows(path, issued["one"])["api"] == stale


def test_a_read_route_with_a_fresh_stamp_does_not_reach_for_the_write(box, monkeypatch):
    """With a fresh stamp the route decides from the row it already read and
    never calls the stamp, so it takes no write lock of its own; with a stale
    one it calls it once."""
    from datetime import datetime, timezone
    from app import proberapi_routes
    client, issued, path = box
    calls = []
    real = instances.stamp_api_key_use
    monkeypatch.setattr(instances, "stamp_api_key_use",
                        lambda *a, **k: calls.append(a) or real(*a, **k))
    set_stamp(path, issued["one"], datetime.now(timezone.utc).isoformat())
    assert client.get(f"{P}/vantages", headers=key(issued["one"])).status_code == 200
    assert calls == []
    set_stamp(path, issued["one"], "2026-09-30T12:00:00+00:00")
    assert client.get(f"{P}/vantages", headers=key(issued["one"])).status_code == 200
    assert len(calls) == 1


def test_the_stamp_survives_the_routes_own_rollback(box):
    """The stamp is written on a connection of its own and committed there,
    so a route's rollback on its own connection cannot take it back."""
    client, issued, path = box
    con = db.connect(path)
    found, used = instances.instance_and_key_use(con, issued["one"].api_key, "api")
    assert found is not None and used is None
    assert instances.stamp_api_key_use(path, issued["one"].api_key)
    con.rollback()
    con.close()
    assert key_rows(path, issued["one"])["api"]
