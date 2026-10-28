"""Accounts, password hashing and server-side sessions.

    python -m pytest tests/test_accounts.py

The two properties worth reading first, because they are the ones a reviewer
cannot check by eye: an unknown address costs the same hashing work as a known
one, so response timing does not enumerate accounts, and a session lives in the
database, so signing out kills a cookie somebody else already copied.
"""

import sqlite3
import time
from datetime import timedelta

import pytest

from app import accounts, db

PASSWORD = "correct-horse-battery-9"
OTHER = "a-different-long-password-9"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    accounts.init(connection)
    yield connection
    connection.close()


def make_user(con, email="sysadmin@example.com", password=PASSWORD):
    return accounts.create_user(con, email, password)


# ------------------------------------------------------------------- schema

def test_init_is_idempotent(con):
    accounts.init(con)
    accounts.init(con)
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"users", "sessions"} <= tables


def test_an_existing_database_gains_the_tables(tmp_path):
    """A database made before this module existed picks the tables up on the
    next init, the additive rule db.py and alerts.py both follow."""
    path = str(tmp_path / "old.db")
    first = db.connect(path)
    db.init(first)
    first.close()
    second = db.connect(path)
    accounts.init(second)
    tables = {r[0] for r in second.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}
    second.close()
    assert {"hosts", "reports", "users", "sessions"} <= tables


# ---------------------------------------------------------------- passwords

def test_a_password_round_trips():
    stored = accounts.hash_password(PASSWORD)
    assert accounts.verify_password(PASSWORD, stored)
    assert not accounts.verify_password(OTHER, stored)


def test_the_stored_hash_never_contains_the_password():
    stored = accounts.hash_password(PASSWORD)
    assert PASSWORD not in stored
    assert stored.startswith("scrypt$")


def test_the_same_password_hashes_differently_every_time():
    """Salted, so two accounts with the same password do not look alike in a
    stolen database."""
    assert accounts.hash_password(PASSWORD) != accounts.hash_password(PASSWORD)


def test_the_parameters_travel_with_the_hash():
    """Raising the cost later must not invalidate passwords already set, so a
    hash made with smaller numbers still verifies against its own."""
    salt_hash = accounts.hash_password(PASSWORD)
    n, r, p = salt_hash.split("$")[1:4]
    assert (int(n), int(r), int(p)) == (accounts.SCRYPT_N, accounts.SCRYPT_R,
                                        accounts.SCRYPT_P)
    weaker = salt_hash.replace(f"scrypt${n}$", "scrypt$1024$", 1)
    # A hash claiming parameters it was not made with simply does not verify.
    assert not accounts.verify_password(PASSWORD, weaker)


@pytest.mark.parametrize("stored", [
    "", "not-a-hash", "scrypt$", "scrypt$a$b$c$d$e", "bcrypt$1$1$1$AAAA$AAAA",
    "scrypt$16384$8$1$!!!!$AAAA", "scrypt$16384$8$1$$", "scrypt$16384$8$1$AAAA",
])
def test_a_malformed_hash_is_false_and_never_an_exception(stored):
    """A row edited by hand, or written by another product, must read as a
    wrong password rather than take the login route down with a 500."""
    assert accounts.verify_password(PASSWORD, stored) is False


@pytest.mark.parametrize("password,ok", [
    ("a1!" + "a" * 8, False), ("a1!" + "a" * 9, True),
    ("a1!" + "a" * 125, True), ("a1!" + "a" * 126, False),
])
def test_password_length_bounds(password, ok):
    if ok:
        accounts.check_password_shape(password)
    else:
        with pytest.raises(accounts.AccountError):
            accounts.check_password_shape(password)


# The two rules that joined the length one on 2026-09-10, at the owner's word
# (`docs/RECORD.md` 4.163). The screens draw the same three from
# `PASSWORD_RULES`, so a form and the server ask the same three questions.

@pytest.mark.parametrize("password,missing", [
    ("abcdefghijkl!", "a number"),
    ("abcdefghijkl9", "a special character"),
    ("abcdefghijkl", "a number, a special character"),
    ("ab9!", "at least 12 characters"),
])
def test_a_password_that_misses_a_rule_says_which(password, missing):
    with pytest.raises(accounts.AccountError) as raised:
        accounts.check_password_shape(password)
    assert str(raised.value) == f"Needs {missing}."


@pytest.mark.parametrize("password", [
    "abcdefghijk9!", "abcdefghijk 9", "abcdefghijk9\u00e9!", "123456789012!",
    "aaaaaaaaaaaa1_",
])
def test_a_password_that_meets_every_rule_is_accepted(password):
    accounts.check_password_shape(password)


def test_a_space_counts_as_a_special_character():
    """Anything that is not a letter or a digit counts. Naming a short list of
    punctuation would refuse characters people really use, with no way to
    explain why."""
    assert accounts.password_rules_met("abcdefghijk 9")["special"] is True


def test_the_rules_the_screens_draw_are_the_rules_the_server_checks():
    """One list. A page listing three rules while the server checks two is how
    a form comes back refused for a reason nobody was shown."""
    keys = [key for key, _words, _test in accounts.PASSWORD_RULES]
    assert keys == ["length", "digit", "special"]
    assert set(accounts.password_rules_met("x")) == set(keys)
    assert str(accounts.PASSWORD_MIN_CHARS) in accounts.PASSWORD_RULES[0][1]


def test_too_long_is_answered_as_too_long_and_not_as_a_missing_digit():
    """A paste of a whole document is not somebody who forgot a digit."""
    with pytest.raises(accounts.AccountError) as raised:
        accounts.check_password_shape("a" * (accounts.PASSWORD_MAX_CHARS + 1))
    assert "at most" in str(raised.value)


# -------------------------------------------------------------------- users

def test_create_and_find(con):
    make_user(con)
    user = accounts.get_user_by_email(con, "SYSADMIN@Example.COM  ")
    assert user is not None and user["email"] == "sysadmin@example.com"


@pytest.mark.parametrize("email", ["", "nope", "no@domain", "a b@c.d", "@c.d",
                                   "a@" + "b" * 300 + ".com"])
def test_a_malformed_address_is_refused(con, email):
    with pytest.raises(accounts.AccountError):
        accounts.create_user(con, email, PASSWORD)


def test_a_short_password_is_refused(con):
    with pytest.raises(accounts.AccountError):
        accounts.create_user(con, "a@example.com", "short")
    assert accounts.get_user_by_email(con, "a@example.com") is None


def test_the_same_address_twice_is_refused(con):
    make_user(con)
    with pytest.raises(accounts.AccountError):
        make_user(con)
    with pytest.raises(accounts.AccountError):
        accounts.create_user(con, "SYSADMIN@EXAMPLE.COM", OTHER)


def test_authenticate(con):
    make_user(con)
    assert accounts.authenticate(con, "sysadmin@example.com", PASSWORD) is not None
    assert accounts.authenticate(con, "sysadmin@example.com", OTHER) is None
    assert accounts.authenticate(con, "nobody@example.com", PASSWORD) is None


def test_a_disabled_account_cannot_authenticate(con):
    make_user(con)
    assert accounts.set_disabled(con, "sysadmin@example.com", True)
    assert accounts.authenticate(con, "sysadmin@example.com", PASSWORD) is None
    assert accounts.set_disabled(con, "sysadmin@example.com", False)
    assert accounts.authenticate(con, "sysadmin@example.com", PASSWORD) is not None


def test_an_unknown_address_costs_the_same_hashing_work_as_a_known_one(con):
    """The account-enumeration test. An early return on an unknown address
    answers in about a millisecond while a real one pays for a scrypt hash, and
    that difference is a working oracle whatever the page says.

    The bound is loose on purpose: this asserts that the work happened, not how
    long a particular machine takes to do it.
    """
    make_user(con)

    def measure(email, password):
        best = None
        for _ in range(3):
            start = time.perf_counter()
            accounts.authenticate(con, email, password)
            elapsed = time.perf_counter() - start
            best = elapsed if best is None else min(best, elapsed)
        return best

    wrong_password = measure("sysadmin@example.com", OTHER)
    unknown_address = measure("nobody@example.com", OTHER)
    disabled_account = None
    accounts.create_user(con, "off@example.com", PASSWORD)
    accounts.set_disabled(con, "off@example.com", True)
    disabled_account = measure("off@example.com", OTHER)

    assert unknown_address >= 0.5 * wrong_password
    assert disabled_account >= 0.5 * wrong_password


def test_setting_a_password_replaces_the_hash(con):
    user_id = make_user(con)
    before = accounts.get_user_by_email(con, "sysadmin@example.com")["password_hash"]
    accounts.set_password(con, user_id, OTHER)
    after = accounts.get_user_by_email(con, "sysadmin@example.com")["password_hash"]
    assert before != after
    assert accounts.authenticate(con, "sysadmin@example.com", OTHER) is not None
    assert accounts.authenticate(con, "sysadmin@example.com", PASSWORD) is None


def test_setting_a_short_password_changes_nothing(con):
    user_id = make_user(con)
    with pytest.raises(accounts.AccountError):
        accounts.set_password(con, user_id, "short")
    assert accounts.authenticate(con, "sysadmin@example.com", PASSWORD) is not None


# ------------------------------------------------------------- display name
#
# The name the account menu and the avatar chip show. The property that
# matters: nothing here invents one. An account without a stored name answers
# empty, and every reader falls back to the email on its own.

def test_a_display_name_round_trips(con):
    user_id = make_user(con)
    accounts.set_display_name(con, user_id, "Robin Sample")
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    assert accounts.display_name_of(user) == "Robin Sample"


def test_a_new_account_has_no_display_name(con):
    make_user(con)
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    assert user["display_name"] is None
    assert accounts.display_name_of(user) == ""


def test_empty_text_clears_a_display_name(con):
    user_id = make_user(con)
    accounts.set_display_name(con, user_id, "Robin Sample")
    accounts.set_display_name(con, user_id, "")
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    # NULL rather than empty text, so "no name" has exactly one stored shape.
    assert user["display_name"] is None
    assert accounts.display_name_of(user) == ""


@pytest.mark.parametrize("given", ["   ", "\t", None])
def test_whitespace_or_nothing_stores_no_name(con, given):
    user_id = make_user(con)
    accounts.set_display_name(con, user_id, given)
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    assert user["display_name"] is None


def test_a_display_name_is_stored_trimmed(con):
    user_id = make_user(con)
    accounts.set_display_name(con, user_id, "  Robin Sample  ")
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    assert user["display_name"] == "Robin Sample"


def test_a_display_name_at_the_bound_is_kept_and_past_it_is_refused(con):
    user_id = make_user(con)
    longest = "a" * accounts.DISPLAY_NAME_MAX_CHARS
    accounts.set_display_name(con, user_id, longest)
    with pytest.raises(accounts.AccountError):
        accounts.set_display_name(con, user_id, "a" * (accounts.DISPLAY_NAME_MAX_CHARS + 1))
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    assert user["display_name"] == longest


def test_display_name_of_nobody_is_empty():
    assert accounts.display_name_of(None) == ""


def test_display_name_of_a_row_without_the_column_is_empty(con):
    """A Row selected before init added the column, the same defensive read
    workspace_of does."""
    make_user(con)
    row = con.execute("SELECT id, email FROM users").fetchone()
    assert accounts.display_name_of(row) == ""


def test_display_name_of_a_hand_edited_row_that_is_not_text_is_empty(con):
    """A blob, because that is the one value SQLite's TEXT affinity stores
    without converting to text. A number written by hand arrives as its text
    and is shown, which is fine, but bytes must never reach a template."""
    make_user(con)
    con.execute("UPDATE users SET display_name = ?", (b"\x00\xff",))
    con.commit()
    user = accounts.get_user_by_email(con, "sysadmin@example.com")
    assert accounts.display_name_of(user) == ""


def test_an_existing_database_gains_the_display_name_column(tmp_path):
    """A database from before the column existed picks it up on the next init,
    with nothing stored for the accounts already there."""
    path = str(tmp_path / "old.db")
    first = db.connect(path)
    db.init(first)
    # The users table as it was first shipped, without the added columns, so
    # this init really is the upgrade path and not a fresh CREATE.
    first.execute("CREATE TABLE users (id INTEGER PRIMARY KEY,"
                  " email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,"
                  " created_at TEXT NOT NULL, disabled_at TEXT,"
                  " last_login_at TEXT)")
    first.execute("INSERT INTO users (email, password_hash, created_at)"
                  " VALUES ('old@example.com', 'x', 'y')")
    first.commit()
    first.close()
    second = db.connect(path)
    accounts.init(second)
    user = accounts.get_user_by_email(second, "old@example.com")
    assert user["display_name"] is None
    assert accounts.display_name_of(user) == ""
    second.close()


# ----------------------------------------------------------------- sessions

def test_a_session_resolves_to_its_user(con):
    user_id = make_user(con)
    token, expires = accounts.issue_session(con, user_id)
    assert token.startswith(accounts.SESSION_PREFIX)
    user = accounts.resolve_session(con, token)
    assert user is not None and user["id"] == user_id
    assert expires > accounts.now_utc()


def test_the_database_never_holds_the_token(con):
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    stored = con.execute("SELECT token_hash FROM sessions").fetchone()["token_hash"]
    assert stored != token
    assert token not in stored
    # A database copy hands over the inventory, never a usable cookie.
    dump = "\n".join(line for line in con.iterdump())
    assert token not in dump


@pytest.mark.parametrize("token", ["", "nonsense", "whp_sess_", "whp_sess_wrong",
                                   "Bearer whp_sess_x"])
def test_a_token_that_was_never_issued_resolves_to_nobody(con, token):
    make_user(con)
    assert accounts.resolve_session(con, token) is None


def test_revoking_a_session_stops_it_at_once(con):
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    assert accounts.revoke_session(con, token) is True
    assert accounts.resolve_session(con, token) is None
    # Idempotent: revoking again is not an error and not a second revocation.
    assert accounts.revoke_session(con, token) is False


def test_revoking_one_session_leaves_the_others(con):
    user_id = make_user(con)
    first, _ = accounts.issue_session(con, user_id)
    second, _ = accounts.issue_session(con, user_id)
    accounts.revoke_session(con, first)
    assert accounts.resolve_session(con, first) is None
    assert accounts.resolve_session(con, second) is not None


def test_revoking_every_session(con):
    user_id = make_user(con)
    tokens = [accounts.issue_session(con, user_id)[0] for _ in range(3)]
    assert accounts.revoke_all_sessions(con, user_id) == 3
    assert all(accounts.resolve_session(con, t) is None for t in tokens)
    assert accounts.revoke_all_sessions(con, user_id) == 0


def test_a_session_expires_on_its_own_clock(con):
    """Absolute, not sliding: a stolen cookie dies on schedule however busy the
    thief keeps it."""
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    later = accounts.now_utc() + accounts.SESSION_TTL - timedelta(minutes=1)
    assert accounts.resolve_session(con, token, now=later) is not None
    past = accounts.now_utc() + accounts.SESSION_TTL + timedelta(seconds=1)
    assert accounts.resolve_session(con, token, now=past) is None


def test_using_a_session_does_not_extend_it(con):
    user_id = make_user(con)
    token, expires = accounts.issue_session(con, user_id)
    accounts.resolve_session(con, token,
                             now=accounts.now_utc() + timedelta(hours=6))
    row = con.execute("SELECT expires_at FROM sessions").fetchone()
    assert row["expires_at"] == expires.isoformat()


def test_last_used_is_written_at_most_every_few_minutes(con):
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    first = con.execute("SELECT last_used_at FROM sessions").fetchone()[0]
    accounts.resolve_session(con, token,
                             now=accounts.now_utc() + timedelta(seconds=30))
    assert con.execute("SELECT last_used_at FROM sessions").fetchone()[0] == first
    accounts.resolve_session(con, token,
                             now=accounts.now_utc() + timedelta(minutes=30))
    assert con.execute("SELECT last_used_at FROM sessions").fetchone()[0] != first


def test_disabling_an_account_kills_its_live_sessions(con):
    """The row is not revoked, but nothing resolves through a disabled account,
    so a session cannot outlive the decision to shut the account off."""
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    accounts.set_disabled(con, "sysadmin@example.com", True)
    assert accounts.resolve_session(con, token) is None


def test_a_session_whose_user_is_gone_resolves_to_nobody(con):
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    con.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    con.execute("DELETE FROM users WHERE id = ?", (user_id,))
    con.commit()
    assert accounts.resolve_session(con, token) is None


def test_live_sessions_lists_only_the_ones_that_resolve(con):
    user_id = make_user(con)
    live, _ = accounts.issue_session(con, user_id)
    dead, _ = accounts.issue_session(con, user_id)
    accounts.revoke_session(con, dead)
    rows = accounts.live_sessions(con, user_id)
    assert len(rows) == 1


def test_purge_removes_only_what_can_never_resolve_again(con):
    user_id = make_user(con)
    accounts.issue_session(con, user_id)
    assert accounts.purge_expired_sessions(con) == 0
    con.commit()
    assert con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    far_future = accounts.now_utc() + timedelta(days=365)
    assert accounts.purge_expired_sessions(con, now=far_future) == 1
    con.commit()
    assert con.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0


def test_a_bad_timestamp_in_a_row_does_not_take_the_request_down(con):
    """Boundary: a row written by hand with an unparseable expiry reads as
    dead rather than raising in the middle of a request."""
    user_id = make_user(con)
    token, _ = accounts.issue_session(con, user_id)
    con.execute("UPDATE sessions SET expires_at = 'whenever'")
    con.commit()
    assert accounts.resolve_session(con, token) is None


def test_the_foreign_key_to_users_holds(con):
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)"
            " VALUES ('x', 999, 'now', 'later')")
