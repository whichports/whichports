"""A published proof left in place renews itself; one whose evidence went
away ends and says so (RECORD 4.104, part 3). SI-6's expiring clause, made
true in both directions. Since 2026-10-20 every published proof is read
again daily, and a read that finds other content or no file ends it
(docs/PRODUCT.md 5)."""
from datetime import timedelta

import pytest

from app import authz, db, store

ADDRESS = "185.199.108.153"
OTHER = "185.199.109.153"
DAY = timedelta(days=1)


@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "r.db"))
    db.init(c)
    authz.init(c)
    yield c
    c.close()


def prove_http(con, address, now, host_id=None, account=authz.DEFAULT_ACCOUNT):
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN,
                                  account=account, now=now, host_id=host_id)
    result = authz.verify_proof(con, challenge.id, now=now,
                                fetcher=lambda url, timeout=0: challenge.token)
    assert result.recorded, result.reason
    return challenge


def prove_dns(con, address, now):
    challenge = authz.start_proof(con, address, authz.METHOD_DNS_TXT, now=now)
    result = authz.verify_proof(con, challenge.id, now=now,
                               resolver=lambda name: [challenge.token])
    assert result.recorded, result.reason
    return challenge


def expiry_of(con, address):
    row = con.execute("SELECT expires_at, renewal_attempted_at, renewal_failure"
                      " FROM authorizations WHERE target = ? AND revoked_at IS NULL"
                      " AND expired_at IS NULL", (address,)).fetchone()
    return row


def still_good(fetcher_token):
    return lambda url, timeout=0: fetcher_token


def gone(url, timeout=0):
    """No answer at all, which is tried again rather than ending the proof."""
    raise authz.ProofError(f"could not read {url}: HTTP 404")


def no_file(url, timeout=0):
    """The address answered, and not with the file."""
    raise authz.ProofError("the address answered 404", answered=True)


def test_init_adds_the_renewal_columns_once(con):
    cols = [r[1] for r in con.execute("PRAGMA table_info(authorizations)")]
    assert "renewal_attempted_at" in cols and "renewal_failure" in cols
    authz.init(con)
    assert [r[1] for r in con.execute("PRAGMA table_info(authorizations)")] == cols


def test_a_proof_read_within_the_day_is_left_alone(con):
    t0 = authz._now()
    challenge = prove_http(con, ADDRESS, t0)
    calls = []
    def fetch(url, timeout=0):
        calls.append(url); return challenge.token
    out = authz.renew_published(con, now=t0 + DAY - timedelta(minutes=1), fetcher=fetch)
    assert out["renewed"] == [] and out["failed"] == [] and calls == []
    assert expiry_of(con, ADDRESS)["renewal_attempted_at"] is None


def test_a_proof_read_a_day_ago_is_read_again_and_extended(con):
    t0 = authz._now()
    challenge = prove_http(con, ADDRESS, t0)
    before = expiry_of(con, ADDRESS)["expires_at"]
    later = t0 + DAY
    out = authz.renew_published(con, now=later, fetcher=still_good(challenge.token))
    assert out["renewed"] == [ADDRESS] and out["failed"] == []
    row = expiry_of(con, ADDRESS)
    assert row["expires_at"] > before
    assert authz._parse(row["expires_at"]) == later + timedelta(
        seconds=authz.PUBLISHED_TTL_SECONDS)
    assert row["renewal_failure"] is None
    # one row, refreshed, not a second one beside it
    assert con.execute("SELECT COUNT(*) FROM authorizations").fetchone()[0] == 1
    # and the gate keeps saying yes past the old expiry
    assert authz.may_probe(con, ADDRESS, now=t0 + 30 * DAY + timedelta(hours=1)).allowed


def test_a_dns_proof_renews_through_the_resolver(con):
    t0 = authz._now()
    challenge = prove_dns(con, ADDRESS, t0)
    out = authz.renew_published(con, now=t0 + DAY,
                                resolver=lambda name: ["other", challenge.token])
    assert out["renewed"] == [ADDRESS]


def test_a_read_with_no_answer_is_written_down_and_nothing_is_extended(con):
    t0 = authz._now()
    prove_http(con, ADDRESS, t0)
    before = expiry_of(con, ADDRESS)["expires_at"]
    later = t0 + DAY
    out = authz.renew_published(con, now=later, fetcher=gone)
    assert out["renewed"] == [] and out["ended"] == []
    assert len(out["failed"]) == 1 and out["failed"][0][0] == ADDRESS
    assert "could not read" in out["failed"][0][1]
    row = expiry_of(con, ADDRESS)
    assert row["expires_at"] == before
    assert "could not read" in row["renewal_failure"]
    assert authz._parse(row["renewal_attempted_at"]) == later
    # still live, and read again in an hour
    assert authz.may_probe(con, ADDRESS, now=later).allowed


def test_two_days_with_no_good_read_end_the_proof(con):
    """A released address that answers nothing is not probed for thirty days."""
    t0 = authz._now()
    prove_http(con, ADDRESS, t0)
    authz.renew_published(con, now=t0 + DAY, fetcher=gone)
    out = authz.renew_published(con, now=t0 + 2 * DAY, fetcher=gone)
    assert out["ended"] == [ADDRESS]
    assert expiry_of(con, ADDRESS) is None
    assert not authz.may_probe(con, ADDRESS, now=t0 + 2 * DAY).allowed


@pytest.mark.parametrize("fetcher", [no_file, still_good("somebody else's page")])
def test_other_content_or_no_file_ends_the_proof_at_once(con, fetcher):
    t0 = authz._now()
    prove_http(con, ADDRESS, t0)
    out = authz.renew_published(con, now=t0 + DAY, fetcher=fetcher)
    assert out["ended"] == [ADDRESS]
    assert not authz.may_probe(con, ADDRESS, now=t0 + DAY).allowed
    ended = con.execute("SELECT expired_at, renewal_failure FROM authorizations").fetchone()
    assert authz._parse(ended["expired_at"]) == t0 + DAY and ended["renewal_failure"]


def test_a_dns_name_that_no_longer_holds_the_token_ends_the_proof(con):
    t0 = authz._now()
    prove_dns(con, ADDRESS, t0)
    out = authz.renew_published(con, now=t0 + DAY, resolver=lambda name: [])
    assert out["ended"] == [ADDRESS]


def test_an_ended_proof_is_proved_again_by_verifying_its_challenge(con):
    """The standing challenge stays, so the token published again is enough."""
    t0 = authz._now()
    challenge = prove_http(con, ADDRESS, t0)
    authz.renew_published(con, now=t0 + DAY, fetcher=no_file)
    again = authz.verify_proof(con, challenge.id, now=t0 + DAY + timedelta(hours=2),
                               fetcher=still_good(challenge.token))
    assert again.recorded


def test_the_wrong_token_is_a_failure_too(con):
    t0 = authz._now()
    prove_http(con, ADDRESS, t0)
    out = authz.renew_published(con, now=t0 + DAY,
                                fetcher=still_good("somebody else's token"))
    assert out["renewed"] == [] and "not found" in out["failed"][0][1]


def test_a_failed_row_is_not_tried_again_inside_the_hour(con):
    t0 = authz._now()
    challenge = prove_http(con, ADDRESS, t0)
    later = t0 + DAY
    authz.renew_published(con, now=later, fetcher=gone)
    calls = []
    def counting(url, timeout=0):
        calls.append(url); return challenge.token
    out = authz.renew_published(con, now=later + timedelta(minutes=5), fetcher=counting)
    assert calls == [] and out["skipped"] == [ADDRESS]
    out = authz.renew_published(con, now=later + timedelta(hours=1, minutes=1),
                                fetcher=counting)
    assert calls and out["renewed"] == [ADDRESS]
    assert expiry_of(con, ADDRESS)["renewal_failure"] is None


def test_an_agent_proof_is_never_touched(con):
    """An agent proof renews itself with every report, and one whose agent
    stopped must lapse on its own."""
    host_id, _ = store.add_host(con, "box")
    con.execute(
        "INSERT INTO authorizations (target, family, method, evidence, account,"
        " host_id, verified_at, expires_at) VALUES (?, 'v4', ?, '{}', ?, ?, ?, ?)",
        (ADDRESS, authz.METHOD_AGENT, authz.DEFAULT_ACCOUNT, host_id,
         authz._now().isoformat(), (authz._now() + DAY).isoformat()))
    con.commit()
    calls = []
    out = authz.renew_published(con, fetcher=lambda url, timeout=0: calls.append(url) or "x")
    assert out["checked"] == 0 and calls == []


def test_revoked_and_lapsed_rows_are_not_renewed(con):
    t0 = authz._now()
    challenge = prove_http(con, ADDRESS, t0)
    prove_http(con, OTHER, t0)
    authz.revoke(con, OTHER)
    out = authz.renew_published(con, now=t0 + 31 * DAY, fetcher=still_good(challenge.token))
    assert out["renewed"] == [] and out["failed"] == []
    # and the bookkeeping sweep now writes the lapse down
    assert authz.sweep(con, now=t0 + 31 * DAY)["expired"] == [ADDRESS]


def test_a_proof_whose_challenge_was_cancelled_asks_for_a_new_one(con):
    t0 = authz._now()
    prove_http(con, ADDRESS, t0)
    con.execute("UPDATE authz_challenges SET cancelled_at = ?", (t0.isoformat(),))
    con.commit()
    out = authz.renew_published(con, now=t0 + DAY, fetcher=gone)
    assert out["failed"] == [(ADDRESS, "no verified challenge to read again, start a new proof")]
    assert out["ended"] == [ADDRESS]


def test_renewal_keeps_the_hosts_binding(con):
    host_id = store.add_address_host(con, "outside-only")
    t0 = authz._now()
    challenge = prove_http(con, ADDRESS, t0, host_id=host_id)
    authz.renew_published(con, now=t0 + 25 * DAY, fetcher=still_good(challenge.token))
    rows = con.execute("SELECT host_id FROM authorizations").fetchall()
    assert [r["host_id"] for r in rows] == [host_id]
    assert [r["target"] for r in authz.live_addresses_for_host(con, host_id, now=t0 + 28 * DAY)] == [ADDRESS]


def test_two_hosts_proving_one_address_renew_independently(con):
    """Two host rows in one workspace may both prove the same address. Before
    the host clause on `_standing_challenge`, the newest challenge answered for
    both authorisations, so the older host's row was read against a token that
    was not its own. `_record` refused to move the live row between hosts, so
    the data stayed right, and the caller still counted it as renewed. The row
    was never extended and lapsed a week later with no failure recorded.

    Only host b's token is published here, which is the real situation: one
    machine, one file, one token in it.
    """
    a = store.add_address_host(con, "box-a")
    b = store.add_address_host(con, "box-b")
    t0 = authz._now()
    authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN, host_id=a, now=t0)
    prove_http(con, ADDRESS, t0, host_id=a)
    challenge_b = prove_http(con, ADDRESS, t0, host_id=b)

    before = {r["host_id"]: r["expires_at"] for r in
              con.execute("SELECT host_id, expires_at FROM authorizations")}
    out = authz.renew_published(con, now=t0 + 25 * DAY,
                                fetcher=still_good(challenge_b.token))
    after = {r["host_id"]: r["expires_at"] for r in
             con.execute("SELECT host_id, expires_at FROM authorizations")}

    # b's file is up, so b renews and a does not.
    assert after[b] != before[b], "the host whose token is published renews"
    assert after[a] == before[a], "the other host's row is not extended"
    # And the count says so, rather than claiming two.
    assert out["renewed"] == [ADDRESS]
    assert [target for target, _reason in out["failed"]] == [ADDRESS]


def test_a_host_whose_token_is_gone_records_why(con):
    """The other half of the same case: the row that did not renew has to
    carry its reason, or nothing anywhere says it is about to lapse."""
    a = store.add_address_host(con, "box-a")
    b = store.add_address_host(con, "box-b")
    t0 = authz._now()
    prove_http(con, ADDRESS, t0, host_id=a)
    challenge_b = prove_http(con, ADDRESS, t0, host_id=b)
    authz.renew_published(con, now=t0 + 25 * DAY,
                          fetcher=still_good(challenge_b.token))
    failures = {r["host_id"]: r["renewal_failure"] for r in
                con.execute("SELECT host_id, renewal_failure FROM authorizations")}
    assert failures[b] is None
    assert failures[a], "the row that did not renew says why"
