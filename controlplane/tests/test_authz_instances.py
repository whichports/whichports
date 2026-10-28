"""The registry's half of the prober API (`app/authz.py`, since 2026-09-30).

A self-hosted instance proves addresses into an account of its own. What
these hold, at the registry rather than through HTTP:

  - a presence claim proves an address only when the request arrived from it
    **and** claims it, the two halves of `docs/RECORD.md` 4.185
  - a claim can never land in a workspace's account
  - one instance's proof is not another's, and not a workspace's
  - every verify outcome carries a code from the closed set, because the API
    sends the code and never the sentence
"""
from datetime import datetime, timedelta, timezone

import pytest

from app import authz, db, dnstxt

NOW = datetime(2026, 9, 30, 12, 0, tzinfo=timezone.utc)
V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
ONE = authz.account_for_instance(1)
TWO = authz.account_for_instance(2)
# Every claim here is an invited instance's. The other way an instance is
# made is held in tests/test_authz_shared_address.py.
INVITED = authz.ORIGIN_INVITED


@pytest.fixture()
def con():
    connection = db.connect(":memory:")
    db.init(connection)
    authz.init(connection)
    yield connection
    connection.close()


# ======================================================= the presence claim

def test_the_address_it_arrived_from_and_claims_is_proved(con):
    result = authz.record_presence_claim(con, ONE, V4, [V6, V4], now=NOW, origin=INVITED)
    assert result.recorded and result.code == "proved"
    assert authz.may_probe(con, V4, now=NOW, account=ONE).allowed
    # Claimed, but the request did not arrive from it.
    assert not authz.may_probe(con, V6, now=NOW, account=ONE).allowed


def test_an_address_it_did_not_arrive_from_proves_nothing(con):
    result = authz.record_presence_claim(con, ONE, V4, [OTHER_V4], now=NOW, origin=INVITED)
    assert not result.recorded and result.code == "not_held"
    assert not authz.may_probe(con, OTHER_V4, now=NOW, account=ONE).allowed
    assert not authz.may_probe(con, V4, now=NOW, account=ONE).allowed


def test_a_host_behind_nat_proves_nothing(con):
    """The request arrives from the gateway, which the host does not hold."""
    result = authz.record_presence_claim(con, ONE, V4, ["10.0.0.5"], now=NOW, origin=INVITED)
    assert result.code == "not_held"
    assert authz.live_for_account(con, ONE, now=NOW) == []


@pytest.mark.parametrize("claimed", [
    None, V4, {V4: True}, [None], [4], [b"185.199.108.153"], ["V4"],
    [V4 + "%eth0"], ["::ffff:" + V4], [V4] * (authz.MAX_CLAIMED_ADDRESSES + 1),
])
def test_a_claim_of_any_other_shape_proves_nothing(con, claimed):
    assert not authz.record_presence_claim(con, ONE, V4, claimed, now=NOW, origin=INVITED).recorded
    assert authz.live_for_account(con, ONE, now=NOW) == []


def test_the_claim_is_compared_as_an_address_not_as_text(con):
    spelled = "2606:50C0:8000:0000:0000:0000:0000:0153"
    assert authz.record_presence_claim(con, ONE, V6, [spelled], now=NOW, origin=INVITED).recorded


@pytest.mark.parametrize("observed", ["10.0.0.5", "127.0.0.1", "100.64.0.1",
                                      "fe80::1", "not an address", ""])
def test_an_observed_address_that_can_never_be_a_target_proves_nothing(con, observed):
    result = authz.record_presence_claim(con, ONE, observed, [observed], now=NOW, origin=INVITED)
    assert not result.recorded and result.code == "target_refused"


@pytest.mark.parametrize("account", [authz.DEFAULT_ACCOUNT,
                                     authz.account_for_workspace(2), "", None, "i0"])
def test_a_claim_never_lands_in_a_workspace(con, account):
    """A hosted workspace proves from the documents its agents send. A bare
    claim is not a way into one."""
    with pytest.raises(ValueError):
        authz.record_presence_claim(con, account, V4, [V4], now=NOW, origin=INVITED)
    assert not authz.may_probe(con, V4, now=NOW).allowed


def test_a_claim_is_an_agent_proof_and_lapses_in_an_hour(con):
    """An hour since 2026-10-20, where an agent reporting to our own control
    plane keeps its week (docs/PRODUCT.md 5)."""
    authz.record_presence_claim(con, ONE, V4, [V4], now=NOW, origin=INVITED)
    row = authz.live_for_account(con, ONE, now=NOW)[0]
    assert row["method"] == authz.METHOD_AGENT
    assert row["host_id"] is None
    lapse = NOW + timedelta(seconds=authz.HOUR_TTL_SECONDS)
    assert authz.may_probe(con, V4, now=lapse - timedelta(seconds=1), account=ONE).allowed
    assert not authz.may_probe(con, V4, now=lapse, account=ONE).allowed


def test_a_claim_every_quarter_hour_refreshes_one_row(con):
    """An agent re-proves every report. A row per report would bury the
    history rather than be it, the reason `_record` gives."""
    for minutes in range(0, 60, 15):
        authz.record_presence_claim(con, ONE, V4, [V4],
                                    now=NOW + timedelta(minutes=minutes), origin=INVITED)
    assert len(authz.live_for_account(con, ONE, now=NOW + timedelta(hours=1))) == 1
    assert len([r for r in authz.list_authorizations(con) if r["account"] == ONE]) == 1


def test_the_evidence_holds_the_one_address_and_nothing_else(con):
    authz.record_presence_claim(con, ONE, V4, [V4, V6, OTHER_V4], now=NOW, origin=INVITED)
    evidence = authz.list_authorizations(con)[0]["evidence"]
    assert V6 not in evidence and OTHER_V4 not in evidence


# ================================================= accounts stay apart

def test_one_instances_proof_is_not_anothers_nor_a_workspaces(con):
    authz.record_presence_claim(con, ONE, V4, [V4], now=NOW, origin=INVITED)
    assert authz.may_probe(con, V4, now=NOW, account=ONE).allowed
    assert not authz.may_probe(con, V4, now=NOW, account=TWO).allowed
    assert not authz.may_probe(con, V4, now=NOW).allowed
    assert authz.live_for_account(con, TWO, now=NOW) == []
    # And the refusal is word for word the refusal for nobody.
    other = authz.may_probe(con, V4, now=NOW, account=TWO).reason
    nobody = authz.may_probe(con, OTHER_V4, now=NOW, account=TWO).reason
    assert other.replace(V4, "X") == nobody.replace(OTHER_V4, "X")


def test_a_snapshot_for_an_instance_carries_only_its_own_proofs(con):
    authz.record_presence_claim(con, ONE, V4, [V4], now=NOW, origin=INVITED)
    authz.record_presence_claim(con, TWO, OTHER_V4, [OTHER_V4], now=NOW, origin=INVITED)
    snapshot = authz.build_snapshot(con, [V4, OTHER_V4], now=NOW, account=ONE)
    assert set(snapshot.targets) == {V4}


def test_live_for_account_leaves_out_the_revoked_and_the_lapsed(con):
    authz.record_presence_claim(con, ONE, V4, [V4], now=NOW, origin=INVITED)
    authz.record_presence_claim(con, ONE, V6, [V6],
                                now=NOW - timedelta(seconds=authz.HOUR_TTL_SECONDS),
                                origin=INVITED)
    authz.record_presence_claim(con, ONE, OTHER_V4, [OTHER_V4], now=NOW, origin=INVITED)
    authz.revoke(con, OTHER_V4, now=NOW, account=ONE)
    assert [r["target"] for r in authz.live_for_account(con, ONE, now=NOW)] == [V4]


def test_a_challenge_is_found_only_by_the_account_that_started_it(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, account=ONE, now=NOW)
    assert authz.challenge_for_account(con, challenge.id, ONE)["target"] == V4
    assert authz.challenge_for_account(con, challenge.id, TWO) is None
    assert authz.challenge_for_account(con, challenge.id, authz.DEFAULT_ACCOUNT) is None
    for asked in ("1", None, True, 1.0):
        assert authz.challenge_for_account(con, asked, ONE) is None


# ==================================================== verify gives a code

def started(con, method=authz.METHOD_DNS_TXT, address=V4):
    return authz.start_proof(con, address, method, account=ONE, now=NOW)


def test_every_verify_outcome_has_a_code_from_the_set(con):
    outcomes = {}

    outcomes["no_such_challenge"] = authz.verify_proof(con, 999, now=NOW)

    challenge = started(con)
    outcomes["token_not_found"] = authz.verify_proof(
        con, challenge.id, now=NOW, resolver=lambda name: ["something else"])

    def unreadable(name):
        raise dnstxt.DnsError("the resolver timed out")

    outcomes["evidence_unreadable"] = authz.verify_proof(
        con, challenge.id, now=NOW, resolver=unreadable)
    outcomes["proved"] = authz.verify_proof(
        con, challenge.id, now=NOW, resolver=lambda name: [challenge.token])

    stale = started(con, address=OTHER_V4)
    outcomes["challenge_expired"] = authz.verify_proof(
        con, stale.id, now=NOW + timedelta(seconds=authz.CHALLENGE_TTL_SECONDS),
        resolver=lambda name: [stale.token])

    cancelled = started(con, address=V6)
    authz.revoke(con, V6, now=NOW, account=ONE)
    outcomes["challenge_cancelled"] = authz.verify_proof(
        con, cancelled.id, now=NOW, resolver=lambda name: [cancelled.token])

    for code, result in outcomes.items():
        assert result.code == code, (code, result)
        assert result.code in authz.PROOF_CODES
        assert result.recorded is (code == "proved")


def test_the_codes_carry_no_address(con):
    """The sentence names the address and where it was read from. The code is
    what crosses the wire, so it must not."""
    for code in authz.PROOF_CODES:
        assert "." not in code and ":" not in code and " " not in code
