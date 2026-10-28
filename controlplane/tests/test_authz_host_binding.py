"""A published proof can belong to a host since 2026-08-26 (RECORD 4.104),
which is what lets an address host be probed on the addresses its operator
proved. This is the review of that binding: the challenge carries the host,
the authorisation it earns carries the host, the per-host readers answer
only for that host, and a workspace-scoped revoke reaches nobody else."""
from datetime import timedelta

import pytest

from app import authz, db, store

ADDRESS = "185.199.108.153"
OTHER = "185.199.109.153"


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "a.db"))
    db.init(c)
    authz.init(c)
    yield c
    c.close()


def fetcher_returning(token):
    def fetch(url):
        return token + "\n"
    return fetch


def prove(con, host_id, address=ADDRESS, account=authz.DEFAULT_ACCOUNT, now=None):
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN,
                                  account=account, now=now, host_id=host_id)
    result = authz.verify_proof(con, challenge.id, now=now,
                                fetcher=fetcher_returning(challenge.token))
    assert result.recorded, result.detail
    return challenge, result


def test_init_adds_the_host_column_once(con):
    cols = [r[1] for r in con.execute("PRAGMA table_info(authz_challenges)")]
    assert "host_id" in cols
    authz.init(con)  # a second init must not raise on the duplicate column
    assert [r[1] for r in con.execute("PRAGMA table_info(authz_challenges)")] == cols


def test_a_challenge_started_for_a_host_earns_an_authorisation_for_that_host(con):
    host_id = store.add_address_host(con, "outside-only")
    challenge, result = prove(con, host_id)
    row = con.execute("SELECT host_id FROM authz_challenges WHERE id = ?",
                      (challenge.id,)).fetchone()
    assert row["host_id"] == host_id
    auth = con.execute("SELECT host_id, target FROM authorizations WHERE id = ?",
                       (result.authorization_id,)).fetchone()
    assert auth["host_id"] == host_id and auth["target"] == ADDRESS
    # and the gate says yes, exactly as before
    assert authz.may_probe(con, ADDRESS).allowed


def test_a_challenge_without_a_host_still_earns_an_account_only_authorisation(con):
    """The CLI path from before, unchanged: no host named, none recorded."""
    challenge = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN)
    result = authz.verify_proof(con, challenge.id,
                                fetcher=fetcher_returning(challenge.token))
    assert result.recorded
    auth = con.execute("SELECT host_id FROM authorizations WHERE id = ?",
                       (result.authorization_id,)).fetchone()
    assert auth["host_id"] is None


def test_challenge_for_host_answers_only_for_its_own_host_and_account(con):
    mine = store.add_address_host(con, "mine")
    theirs = store.add_address_host(con, "theirs")
    challenge = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN,
                                  host_id=mine)
    assert authz.challenge_for_host(con, challenge.id, mine, authz.DEFAULT_ACCOUNT) is not None
    assert authz.challenge_for_host(con, challenge.id, theirs, authz.DEFAULT_ACCOUNT) is None
    assert authz.challenge_for_host(con, challenge.id, mine, "w2") is None
    assert authz.challenge_for_host(con, 9999, mine, authz.DEFAULT_ACCOUNT) is None


def test_live_addresses_are_the_ones_the_gate_would_allow(con):
    host_id = store.add_address_host(con, "outside-only")
    now = authz._now()
    prove(con, host_id, ADDRESS, now=now)
    prove(con, host_id, OTHER, now=now)
    live = authz.live_addresses_for_host(con, host_id, now=now)
    assert sorted(r["target"] for r in live) == sorted([ADDRESS, OTHER])
    # one lapses by the clock alone, with no sweep having run
    later = now + timedelta(seconds=authz.PUBLISHED_TTL_SECONDS + 1)
    assert authz.live_addresses_for_host(con, host_id, now=later) == []
    assert not authz.may_probe(con, ADDRESS, now=later).allowed


def test_live_addresses_exclude_a_revoked_one_and_another_hosts(con):
    a = store.add_address_host(con, "a")
    b = store.add_address_host(con, "b")
    prove(con, a, ADDRESS)
    prove(con, b, OTHER)
    authz.revoke(con, ADDRESS)
    assert authz.live_addresses_for_host(con, a) == []
    assert [r["target"] for r in authz.live_addresses_for_host(con, b)] == [OTHER]


def test_a_scoped_revoke_reaches_only_its_own_account(con):
    """Two workspaces, one address each proved under their own account. A
    revoke scoped to one account leaves the other's proof standing, and the
    unscoped CLI revoke closes both, which is what it always did."""
    host_id = store.add_address_host(con, "outside-only")
    now = authz._now()
    prove(con, host_id, ADDRESS, account="w2", now=now)
    prove(con, None, ADDRESS, account=authz.DEFAULT_ACCOUNT, now=now)
    closed = authz.revoke(con, ADDRESS, now=now, account="w2")
    assert closed == 1
    assert authz.may_probe(con, ADDRESS, account=authz.DEFAULT_ACCOUNT, now=now).allowed
    assert not authz.may_probe(con, ADDRESS, account="w2", now=now).allowed
    assert authz.revoke(con, ADDRESS, now=now) == 1
    assert not authz.may_probe(con, ADDRESS, account=authz.DEFAULT_ACCOUNT, now=now).allowed


def test_a_scoped_revoke_cancels_only_that_accounts_open_challenges(con):
    host_id = store.add_address_host(con, "outside-only")
    mine = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN,
                             account="w2", host_id=host_id)
    other = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN)
    authz.revoke(con, ADDRESS, account="w2")
    rows = {r["id"]: r["cancelled_at"] for r in authz.list_challenges(con)}
    assert rows[mine.id] is not None
    assert rows[other.id] is None


def test_addresses_for_host_lists_proofs_and_open_challenges(con):
    host_id = store.add_address_host(con, "outside-only")
    prove(con, host_id, ADDRESS)
    pending = authz.start_proof(con, OTHER, authz.METHOD_DNS_TXT, host_id=host_id)
    listing = authz.addresses_for_host(con, host_id)
    assert [r["target"] for r in listing["authorizations"]] == [ADDRESS]
    assert [r["id"] for r in listing["open_challenges"]] == [pending.id]
    # verified challenges are not "open", and another host's are not listed
    other = store.add_address_host(con, "other")
    authz.start_proof(con, OTHER, authz.METHOD_DNS_TXT, host_id=other)
    assert [r["id"] for r in authz.addresses_for_host(con, host_id)["open_challenges"]] == [pending.id]
