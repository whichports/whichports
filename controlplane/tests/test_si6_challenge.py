"""The challenge of the SI-6 fix of 2026-10-20, as tests.

Each test asserts what the promise in docs/PRODUCT.md 5 (the clauses of
2026-10-20) or SI-6 itself needs, and each one fails on the branch it
challenges. The facts each failure rests on are asserted first, so a
failure names the step that broke.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, instances, store

NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)

# A VPN exit, a carrier NAT's public side or an office NAT: one address that
# many people send from. Documentation-free but globally routable.
SHARED = "185.199.108.153"

M = authz.account_for_instance(1)  # the instance that sends from the shared address
L = authz.account_for_instance(2)  # the one that really controls it

DNS = authz.METHOD_DNS_TXT
HTTP = authz.METHOD_HTTP_TOKEN


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    authz.init(connection)
    instances.init(connection)
    yield connection
    connection.close()


def document_claiming(address):
    """A host document written by hand: it names the address on an
    interface, which is all the host side of an agent proof asks for."""
    return json.dumps({
        "schema_version": 1, "hostname": "box", "collected_at_unix": 0,
        "sockets": {"status": "ok", "listening": []},
        "interface_addresses": {"status": "collected", "addresses": [
            {"address": address, "family": "v4", "interface": "eth0"}]},
    })


def published(con, account, method, address=SHARED, moment=NOW, body=None):
    challenge = authz.start_proof(con, address, method, account=account, now=moment)
    token = challenge.token if body is None else body
    return challenge, authz.verify_proof(
        con, challenge.id, now=moment,
        resolver=lambda name: [token], fetcher=lambda url: token)


def allowed(con, account, moment, address=SHARED):
    return authz.may_probe(con, address, now=moment, account=account).allowed


# 1. Our own control plane's report path keeps the week with the same two
#    halves presence has: an address we saw and a list the host wrote.

def test_challenge_a_hand_made_report_from_a_shared_address_is_not_probed_for_a_week(con):
    """Anyone with a host credential of a workspace (today: whoever
    WHICHPORTS_SIGNUP or its allow list lets make an account) can send a
    report by hand from a shared address with a document naming that
    address. It is proved for a week, a second workspace proves it too, and
    a revoke is undone by the next report. PRODUCT 5 says the week is kept
    because the address 'comes with an authenticated report and the host
    document, never as a bare claim', but the document is the same bare
    claim the presence body is (authz.py's own docstring, 'asserted by the
    host')."""
    second = db.create_workspace(con, "second")
    third = db.create_workspace(con, "third")
    one, _ = store.add_host(con, "one", workspace_id=second)
    two, _ = store.add_host(con, "two", workspace_id=third)
    assert authz.record_agent_proof(con, one, SHARED, document_claiming(SHARED),
                                    now=NOW).recorded
    # These lines asserted the hole as it was found, a second workspace
    # proving the address and both probed for six days. They assert it
    # closed since the decision: one holder, and an hour.
    second_holder = authz.record_agent_proof(con, two, SHARED,
                                             document_claiming(SHARED), now=NOW)
    assert not second_holder.recorded and second_holder.code == "address_held"
    w2, w3 = authz.account_for_workspace(second), authz.account_for_workspace(third)
    assert allowed(con, w2, NOW + HOUR - timedelta(seconds=1))
    assert not allowed(con, w2, NOW + 6 * DAY) and not allowed(con, w3, NOW)
    authz.revoke(con, SHARED, now=NOW + DAY)
    assert authz.record_agent_proof(con, one, SHARED, document_claiming(SHARED),
                                    now=NOW + DAY).recorded
    # What the hour gives an instance's presence, asked of this path.
    assert not allowed(con, w2, NOW + DAY + 2 * HOUR)


# 2. The weaker proof holds the address against the stronger one.

def test_challenge_a_published_proof_wins_over_another_instances_presence(con):
    """M's agent sends presence from a shared address and claims it, which
    the decision still allows an invited instance. L, which publishes a DNS
    TXT record in the address's own reverse zone, is refused `address_held`
    for as long as M keeps sending, and M stays probed."""
    assert authz.record_presence_claim(con, M, SHARED, [SHARED], now=NOW,
                                       origin=authz.ORIGIN_INVITED).recorded
    _challenge, result = published(con, L, DNS, moment=NOW + timedelta(minutes=10))
    assert result.recorded, result.code


# 3. A token file proof outlives the server that served it by up to 30 days.

def test_challenge_a_token_proof_whose_file_is_gone_stops_being_probed(con):
    """A proves a cloud address by its token file, then releases it. The
    file is gone the next day: a re-read finds other content. The re-read
    the sweep does only starts seven days before the end, and a failed one
    changes nothing, so A's instance keeps our probers on the new owner's
    server until day 30."""
    _challenge, first = published(con, M, HTTP)
    assert first.recorded
    report = authz.renew_published(con, now=NOW + DAY,
                                   fetcher=lambda url: "somebody else's page")
    # This line asserted the hole as it was found, the proof not even read
    # a day after. Since the decision it is read daily, and this read ends it.
    assert report["renewed"] == [] and report["ended"] == [SHARED]
    again = authz.verify_proof(con, _challenge.id, now=NOW + DAY,
                               fetcher=lambda url: "somebody else's page")
    assert again.code == "token_not_found"
    assert not allowed(con, M, NOW + 2 * DAY)


def test_challenge_the_new_owner_of_a_released_address_is_not_held_out(con):
    """The same release, seen from L, the new owner, who serves its own
    token file on the address: refused `address_held` for up to 30 days."""
    published(con, M, HTTP)
    _challenge, result = published(con, L, HTTP, moment=NOW + DAY)
    assert result.recorded, result.code


# 4. Presence rests on `invited`, and `invited` is the default.

def test_challenge_instances_add_names_how_the_instance_was_made(con):
    """`record_presence_claim` takes `origin` with no default 'so no caller
    can leave it out'. `instances.add` defaults it to `invited`, so the
    first web route that calls it without thinking (the spec's fast invites
    run `instances.add` from a keys page POST) makes a stranger's instance
    prove by presence."""
    with pytest.raises(TypeError):
        instances.add(con, "from-a-web-route", now=NOW)
