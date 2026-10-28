"""Links that work once and expire.

    python -m pytest tests/test_onetime.py

The mutations these are built to catch, in the order they matter:

  1. **A link that works twice.** Two requests racing on one token must not
     both succeed, so the spend is asserted against a second call and against
     a second connection.
  2. **A link that outlives its mail.** Every TTL is compared against the words
     `app/notify.py` puts in the mail that carries it, because a mail promising
     30 minutes over a link that lasts a day is a lie with a lock on it.
  3. **A token doing the wrong job.** A reset token handed to the confirm
     route must be nothing at all.
  4. **A database copy being a set of working links.** The raw token is never
     in the table.
  5. **The page above this one answering questions.** Expired, spent, unknown
     and wrong-purpose are one answer, None, not four.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import accounts, db, notify, onetime

NOW = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
EMAIL = "sysadmin@example.net"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    # accounts first: a link row references an account, so the table it points
    # at has to exist, which is the order `web_auth._connect` opens in too.
    accounts.init(connection)
    onetime.init(connection)
    yield connection
    connection.close()


def test_init_is_idempotent_and_keeps_the_rows(con):
    onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    onetime.init(con)
    onetime.init(con)
    assert con.execute("SELECT COUNT(*) AS n FROM one_time_links").fetchone()["n"] == 1


def test_a_link_round_trips_and_carries_what_it_was_given(con):
    token, expires_at = onetime.issue(
        con, onetime.INVITE, EMAIL, workspace_id=2, role="Admin",
        invited_by="boss@example.net", now=NOW)
    row = onetime.look_up(con, onetime.INVITE, token, now=NOW)
    assert row is not None
    assert row["email"] == EMAIL
    assert (row["workspace_id"], row["role"], row["invited_by"]) == (2, "Admin", "boss@example.net")
    assert expires_at == NOW + onetime.TTL[onetime.INVITE]


def test_the_address_is_stored_folded(con):
    """One address, one spelling, so a second issue really replaces the first."""
    token, _ = onetime.issue(con, onetime.RESET, "  Sysadmin@Example.NET ", now=NOW)
    assert onetime.look_up(con, onetime.RESET, token, now=NOW)["email"] == EMAIL


def test_a_link_with_no_address_is_refused(con):
    with pytest.raises(ValueError):
        onetime.issue(con, onetime.RESET, "  ", now=NOW)


def test_a_purpose_nobody_has_heard_of_is_refused(con):
    with pytest.raises(ValueError):
        onetime.issue(con, "become_admin", EMAIL, now=NOW)


# ------------------------------------------------------------- once, and once

def test_spending_a_link_works_exactly_once(con):
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    row = onetime.look_up(con, onetime.RESET, token, now=NOW)
    assert onetime.spend(con, row["id"], now=NOW) is True
    assert onetime.spend(con, row["id"], now=NOW) is False
    assert onetime.look_up(con, onetime.RESET, token, now=NOW) is None


def test_two_connections_racing_on_one_link_produce_one_winner(con, tmp_path):
    """The `used_at IS NULL` in the UPDATE is the whole guarantee, so it is
    tested through two connections rather than two calls on one."""
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    row_id = onetime.look_up(con, onetime.RESET, token, now=NOW)["id"]
    other = db.connect(str(tmp_path / "cp.db"))
    try:
        results = [onetime.spend(con, row_id, now=NOW),
                   onetime.spend(other, row_id, now=NOW)]
    finally:
        other.close()
    assert results.count(True) == 1


def test_looking_up_does_not_spend(con):
    """A mail client that fetches the link to preview it must not burn it."""
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    for _ in range(3):
        assert onetime.look_up(con, onetime.RESET, token, now=NOW) is not None


def test_issuing_again_kills_the_earlier_link(con):
    first, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    second, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    assert onetime.look_up(con, onetime.RESET, first, now=NOW) is None
    assert onetime.look_up(con, onetime.RESET, second, now=NOW) is not None


def test_issuing_one_purpose_leaves_another_alone(con):
    reset, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    onetime.issue(con, onetime.CONFIRM, EMAIL, now=NOW)
    assert onetime.look_up(con, onetime.RESET, reset, now=NOW) is not None


def test_issuing_for_one_address_leaves_another_alone(con):
    mine, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    onetime.issue(con, onetime.RESET, "someone@example.net", now=NOW)
    assert onetime.look_up(con, onetime.RESET, mine, now=NOW) is not None


# ------------------------------------------------------------------ expiry

@pytest.mark.parametrize("purpose", onetime.PURPOSES)
def test_a_link_dies_on_its_own_schedule(con, purpose):
    token, _ = onetime.issue(con, purpose, EMAIL, now=NOW)
    just_inside = NOW + onetime.TTL[purpose] - timedelta(seconds=1)
    just_outside = NOW + onetime.TTL[purpose] + timedelta(seconds=1)
    assert onetime.look_up(con, purpose, token, now=just_inside) is not None
    assert onetime.look_up(con, purpose, token, now=just_outside) is None


def test_every_ttl_is_what_its_mail_says_out_loud():
    """A mail promising 30 minutes over a link that lasts a day is a lie with
    a lock on it, so the two are compared rather than kept in step by hand."""
    said = {
        onetime.SET_PASSWORD: notify.ACCOUNT_LINK_LASTS,
        onetime.RESET: notify.RESET_LINK_LASTS,
        onetime.CONFIRM: notify.CONFIRM_LINK_LASTS,
        onetime.INVITE: notify.INVITE_LINK_LASTS,
    }
    hours = {"24 hours": timedelta(hours=24), "30 minutes": timedelta(minutes=30),
             "7 days": timedelta(days=7)}
    for purpose, words in said.items():
        assert onetime.TTL[purpose] == hours[words], purpose


def test_an_expiry_stamp_nobody_can_read_is_refused(con):
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    con.execute("UPDATE one_time_links SET expires_at = 'whenever'")
    con.commit()
    assert onetime.look_up(con, onetime.RESET, token, now=NOW) is None


def test_a_naive_expiry_stamp_is_refused(con):
    """Every stamp this module writes carries an offset. One without is not a
    stamp this module wrote, so it is not a link anybody may use."""
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    con.execute("UPDATE one_time_links SET expires_at = '2099-01-01T00:00:00'")
    con.commit()
    assert onetime.look_up(con, onetime.RESET, token, now=NOW) is None


# --------------------------------------------------- what a lookup will not do

def test_a_token_for_one_purpose_is_nothing_at_another(con):
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    assert onetime.look_up(con, onetime.CONFIRM, token, now=NOW) is None
    assert onetime.look_up(con, onetime.INVITE, token, now=NOW) is None


@pytest.mark.parametrize("token", ["", "   ", "not-a-token", "0" * 64])
def test_a_token_nobody_issued_is_nothing(con, token):
    onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    assert onetime.look_up(con, onetime.RESET, token, now=NOW) is None


def test_a_purpose_nobody_has_heard_of_looks_nothing_up(con):
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    assert onetime.look_up(con, "become_admin", token, now=NOW) is None


# ------------------------------------------------------------- the token itself

def test_the_raw_token_is_never_in_the_table(con):
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    dump = "\n".join(line for line in con.iterdump())
    assert token not in dump
    assert onetime._hash(token) in dump


def test_two_links_never_share_a_token(con):
    tokens = {onetime.issue(con, onetime.RESET, f"a{i}@example.net", now=NOW)[0]
              for i in range(25)}
    assert len(tokens) == 25


# ---------------------------------------------------------------- housekeeping

def test_purging_leaves_a_recently_expired_link_findable(con):
    """"That link has expired" is worth saying for as long as somebody might
    click an old mail, so a purge does not take yesterday's rows."""
    token, _ = onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    assert onetime.purge_expired(con, now=NOW + timedelta(days=1)) == 0
    assert con.execute("SELECT COUNT(*) AS n FROM one_time_links").fetchone()["n"] == 1
    assert onetime.purge_expired(con, now=NOW + timedelta(days=30)) == 1
    assert onetime.look_up(con, onetime.RESET, token, now=NOW) is None


def _count(con):
    return con.execute("SELECT COUNT(*) FROM one_time_links").fetchone()[0]


def test_issuing_a_link_keeps_one_that_expired_less_than_a_week_ago(con):
    """The week of grace survives the purge that issuing now runs."""
    onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    onetime.issue(con, onetime.RESET, "other@example.net", now=NOW + timedelta(days=6))
    assert _count(con) == 2


def test_issuing_a_link_deletes_links_expired_more_than_a_week_ago(con):
    """A link row holds a mail address, so it must not stay for ever.

    Nothing else calls `purge_expired`, so issuing is where it runs, the way
    `accounts.issue_session` and `identities.start_flow` purge their own
    tables. Spent and unspent rows both go once their expiry is a week old.
    """
    onetime.issue(con, onetime.RESET, EMAIL, now=NOW)
    spent, _ = onetime.issue(con, onetime.CONFIRM, EMAIL, now=NOW)
    onetime.spend(con, onetime.look_up(con, onetime.CONFIRM, spent, now=NOW)["id"], now=NOW)
    onetime.issue(con, onetime.INVITE, "new@example.net", now=NOW + timedelta(days=30))
    left = con.execute("SELECT email FROM one_time_links").fetchall()
    assert [row[0] for row in left] == ["new@example.net"]


def test_issuing_purges_on_a_bare_connection(tmp_path):
    """Site tests open plain sqlite3 connections, which hand back tuples."""
    bare = sqlite3.connect(str(tmp_path / "bare.db"))
    accounts.init(bare)
    onetime.init(bare)
    onetime.issue(bare, onetime.RESET, EMAIL, now=NOW)
    onetime.issue(bare, onetime.RESET, "other@example.net", now=NOW + timedelta(days=30))
    assert _count(bare) == 1
    bare.close()
