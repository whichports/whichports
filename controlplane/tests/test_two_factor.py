"""The login's second step, which is the gate rather than the arithmetic.

    python -m pytest tests/test_two_factor.py

app/totp.py is pinned to the RFC vectors in tests/test_totp.py. This file is
about what the application does with them, and because the owner reads every diff
but has said he cannot be relied on to catch a subtle security bug in review, these tests are the review.

The ones that matter most, in the order a reviewer should read them:

  - a session that owes a code is refused by every gate in the application,
  - the code page tells an anonymous visitor nothing about any account,
  - a code cannot be used twice, even inside the window that still accepts it,
  - the cookie is replaced when the code lands,
  - the rate limit is keyed on the account, so minting fresh sessions does not
    buy fresh attempts,
  - a wrong code, an expired pending session and a cross-site post are all
    refused, and none of them signs anybody in.
"""

import re
import time

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, ingest, ratelimit, totp, web_auth

EMAIL = "sysadmin@example.com"
PASSWORD = "correct-horse-battery-9"

# Far from a step boundary, so a test never straddles one.
NOW = 1_700_000_015.0


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """An account with two-factor on, and a client. Returns the secret and the
    recovery codes, because both are only readable at enrolment."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    user_id = accounts.create_user(con, EMAIL, PASSWORD)
    secret = accounts.begin_totp_enrollment(con, user_id)
    codes = accounts.confirm_totp_enrollment(
        con, user_id, totp.code_at_time(secret, NOW), at_time=NOW)
    con.close()
    return {"client": TestClient(ingest.app), "secret": secret,
            "codes": codes, "user_id": user_id}


def csrf_of(page_html):
    match = re.search(r'name="csrf" value="([^"]+)"', page_html)
    assert match, "the form did not carry a CSRF token"
    return match.group(1)


def password_step(client, next_field="/"):
    """The first half of the login: fetch the form and post the password."""
    page = client.get("/login", follow_redirects=False)
    assert page.status_code == 200, "already signed in, use a fresh client"
    return client.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": next_field,
        "csrf": csrf_of(page.text)})


def code_step(client, code, next_field="/"):
    page = client.get("/login/2fa", follow_redirects=False)
    assert page.status_code == 200, "there is no pending session to answer"
    return client.post("/login/2fa", follow_redirects=False, data={
        "code": code, "next": next_field, "csrf": csrf_of(page.text)})


def a_live_code(secret, at_time=None):
    """A code the replay guard has not already seen. Enrolment burned the code
    for the step it confirmed on, so the next step's code is the first usable
    one, and it is inside the verify window."""
    return totp.code_at_time(secret, (at_time or time.time()) + totp.STEP_SECONDS)


def sign_in_fully(env, next_field="/"):
    client = env["client"]
    password_step(client, next_field)
    return code_step(client, a_live_code(env["secret"]), next_field)


# ------------------------------------- the password alone is not a login

def test_the_password_alone_redirects_to_the_code_page(env):
    response = password_step(env["client"])
    assert response.status_code == 303
    assert response.headers["location"] == "/login/2fa?next=%2F"


def test_a_pending_session_is_refused_by_the_gate_caddy_asks(env):
    """This is the load-bearing one. `/api/auth/check` is what stands in front
    of the whole dashboard (ops/RUNBOOK.md), and a half-finished login has to
    read as signed out there or the second factor is decoration."""
    client = env["client"]
    password_step(client)
    assert client.cookies.get(web_auth.SESSION_COOKIE), "no cookie was set at all"
    assert client.get("/api/auth/check").status_code == 401


def test_a_pending_session_is_refused_by_whoami(env):
    client = env["client"]
    password_step(client)
    assert client.get("/api/auth/whoami").status_code == 401


def test_a_pending_session_is_refused_by_the_admin_routes(env):
    """require_operator accepts a session or the Caddy gate header. A pending
    session is not a session, so the write actions stay shut."""
    client = env["client"]
    password_step(client)
    response = client.post("/api/admin/hosts", json={"name": "x"})
    # ingest.require_operator refuses with 403, not the 401 the browser-facing
    # pages use. Either way nothing was let through, which is the property.
    assert response.status_code == 403


def test_the_account_module_refuses_a_pending_token_directly(env):
    """Belt and braces, one layer below the routes: whatever a future caller
    does, resolve_session is the one function every gate asks."""
    client = env["client"]
    password_step(client)
    token = client.cookies.get(web_auth.SESSION_COOKIE)
    con = db.connect()
    try:
        assert accounts.resolve_session(con, token) is None
        assert accounts.resolve_pending_session(con, token) is not None
    finally:
        con.close()


def test_a_pending_session_is_not_counted_as_signed_in_on_the_box(env):
    """`users_cli list` prints live sessions. A half-login must not read there
    as somebody being signed in."""
    client = env["client"]
    password_step(client)
    con = db.connect()
    try:
        assert accounts.live_sessions(con, env["user_id"]) == []
    finally:
        con.close()


def test_the_login_page_sends_a_pending_browser_back_to_the_code_page(env):
    """Not to a second password form, which would ask somebody to type their
    password twice for no reason."""
    client = env["client"]
    password_step(client)
    response = client.get("/login?next=/hosts", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login/2fa?next=%2Fhosts"


def test_a_wrong_password_never_reaches_the_code_page(env):
    client = env["client"]
    page = client.get("/login")
    response = client.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": "not-the-password", "next": "/",
        "csrf": csrf_of(page.text)})
    assert response.status_code == 401
    assert not client.cookies.get(web_auth.SESSION_COOKIE)


# --------------------------------------------- the code page says nothing

def test_the_code_page_is_unreachable_without_a_pending_session(env):
    """It must never become a way to ask whether an address has an account, or
    whether an account has two-factor on. Getting here costs a password."""
    response = env["client"].get("/login/2fa", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_posting_a_code_without_a_pending_session_signs_nobody_in(env):
    client = env["client"]
    response = client.post("/login/2fa", follow_redirects=False, data={
        "code": "000000", "next": "/", "csrf": "x" * 40})
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/api/auth/check").status_code == 401


def test_the_code_page_carries_no_email_and_no_account_detail(env):
    client = env["client"]
    password_step(client)
    page = client.get("/login/2fa")
    assert page.status_code == 200
    assert EMAIL not in page.text
    # No email field either, so nothing on the page names or asks for an
    # account. (A broader search for the local part would hit theme.py, which
    # quotes the owner in a CSS comment.)
    assert 'name="email"' not in page.text
    assert "@" not in re.sub(r"<style>.*?</style>", "", page.text, flags=re.S)


def test_the_code_page_is_not_cached_and_not_indexed(env):
    client = env["client"]
    password_step(client)
    page = client.get("/login/2fa")
    assert page.headers["cache-control"] == "no-store"
    assert 'name="robots" content="noindex,nofollow"' in page.text


def test_the_code_page_takes_its_look_from_the_design_system(env):
    """The palette is not restated in the control plane, the same rule the
    login page is held to."""
    from app import web_pages
    client = env["client"]
    password_step(client)
    page = client.get("/login/2fa")
    assert web_pages.theme().TOKENS.strip() in page.text


def test_an_already_signed_in_browser_is_sent_on_rather_than_asked_again(env):
    sign_in_fully(env)
    response = env["client"].get("/login/2fa?next=/hosts", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/hosts"


# ------------------------------------------------------- the code itself

def test_the_right_code_signs_in(env):
    response = sign_in_fully(env)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert env["client"].get("/api/auth/check").status_code == 204
    assert env["client"].get("/api/auth/whoami").json() == {"email": EMAIL}


def test_the_cookie_is_replaced_when_the_code_lands(env):
    """Session fixation: the value the browser carried through the challenge is
    not the value it leaves with."""
    client = env["client"]
    password_step(client)
    pending = client.cookies.get(web_auth.SESSION_COOKIE)
    code_step(client, a_live_code(env["secret"]))
    assert client.cookies.get(web_auth.SESSION_COOKIE) != pending
    con = db.connect()
    try:
        assert accounts.resolve_session(con, pending) is None
        assert accounts.resolve_pending_session(con, pending) is None
    finally:
        con.close()


def test_the_new_cookie_is_httponly_and_samesite_lax(env):
    client = env["client"]
    password_step(client)
    response = code_step(client, a_live_code(env["secret"]))
    lines = [line for line in response.headers.get_list("set-cookie")
             if line.startswith(web_auth.SESSION_COOKIE + "=")]
    assert len(lines) == 1
    assert "HttpOnly" in lines[0]
    assert "SameSite=lax" in lines[0].replace("SameSite=Lax", "SameSite=lax")


def test_a_code_cannot_be_used_twice(env):
    """The window accepts a step either side of now, so a code stays valid for
    a minute and a half. Somebody reading it over a shoulder must not be able
    to spend it again in their own browser."""
    client = env["client"]
    password_step(client)
    code = a_live_code(env["secret"])
    assert code_step(client, code).status_code == 303

    second = TestClient(ingest.app)
    password_step(second)
    response = code_step(second, code)
    assert response.status_code == 401
    assert second.get("/api/auth/check").status_code == 401


def test_the_code_that_confirmed_the_enrolment_is_already_spent(env):
    """Enrolment accepts a code and raises the replay floor with it, so it can
    never be replayed at the login page a few seconds later."""
    client = env["client"]
    password_step(client)
    response = code_step(client, totp.code_at_time(env["secret"], NOW))
    assert response.status_code == 401


@pytest.mark.parametrize("code", ["", "000000", "12345", "abcdef", "١٢٣٤٥٦",
                                  "not-a-code", "aaaa-bbbb", " "])
def test_a_wrong_or_malformed_code_is_refused_and_signs_nobody_in(env, code):
    client = env["client"]
    password_step(client)
    response = code_step(client, code)
    assert response.status_code == 401
    assert client.get("/api/auth/check").status_code == 401


def test_a_code_from_another_secret_is_refused(env):
    client = env["client"]
    password_step(client)
    response = code_step(client, a_live_code(totp.generate_secret()))
    assert response.status_code == 401


def test_a_refused_code_leaves_the_pending_session_usable(env):
    """A mistyped code must not cost the operator their password as well."""
    client = env["client"]
    password_step(client)
    assert code_step(client, "000000").status_code == 401
    assert code_step(client, a_live_code(env["secret"])).status_code == 303


def test_an_expired_pending_session_cannot_be_answered(env, monkeypatch):
    client = env["client"]
    password_step(client)
    later = accounts.now_utc() + accounts.PENDING_SESSION_TTL + accounts.timedelta(seconds=1)
    monkeypatch.setattr(accounts, "now_utc", lambda: later)
    response = client.post("/login/2fa", follow_redirects=False, data={
        "code": a_live_code(env["secret"]), "next": "/", "csrf": "x" * 40})
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_the_pending_session_expires_far_sooner_than_a_real_one(env):
    """A step in a login is not a login, and does not get a login's lifetime."""
    assert accounts.PENDING_SESSION_TTL < accounts.SESSION_TTL
    client = env["client"]
    password_step(client)
    token = client.cookies.get(web_auth.SESSION_COOKIE)
    con = db.connect()
    try:
        row = con.execute("SELECT * FROM sessions WHERE token_hash = ?",
                          (accounts._hash_token(token),)).fetchone()
        created = accounts._parse(row["created_at"])
        expires = accounts._parse(row["expires_at"])
        assert expires - created == accounts.PENDING_SESSION_TTL
    finally:
        con.close()


def test_signing_out_mid_login_revokes_the_pending_session(env):
    client = env["client"]
    password_step(client)
    token = client.cookies.get(web_auth.SESSION_COOKIE)
    assert client.post("/logout", follow_redirects=False).status_code == 303
    con = db.connect()
    try:
        assert accounts.resolve_pending_session(con, token) is None
    finally:
        con.close()


def test_a_password_change_kills_a_pending_session_too(env):
    """revoke_all_sessions is what a password change and a disable both use, so
    it has to reach the rows live_sessions hides."""
    client = env["client"]
    password_step(client)
    token = client.cookies.get(web_auth.SESSION_COOKIE)
    con = db.connect()
    try:
        assert accounts.revoke_all_sessions(con, env["user_id"]) == 1
        assert accounts.resolve_pending_session(con, token) is None
    finally:
        con.close()


def test_a_disabled_account_cannot_finish_a_login_it_started(env):
    client = env["client"]
    password_step(client)
    con = db.connect()
    try:
        accounts.set_disabled(con, EMAIL, True)
    finally:
        con.close()
    response = client.post("/login/2fa", follow_redirects=False, data={
        "code": a_live_code(env["secret"]), "next": "/", "csrf": "x" * 40})
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# ---------------------------------------------------------------- CSRF

def test_a_post_with_no_csrf_token_is_refused(env):
    client = env["client"]
    password_step(client)
    response = client.post("/login/2fa", follow_redirects=False, data={
        "code": a_live_code(env["secret"]), "next": "/", "csrf": ""})
    assert response.status_code == 400
    assert client.get("/api/auth/check").status_code == 401


def test_a_post_with_somebody_elses_csrf_token_is_refused(env):
    client = env["client"]
    password_step(client)
    client.get("/login/2fa")
    response = client.post("/login/2fa", follow_redirects=False, data={
        "code": a_live_code(env["secret"]), "next": "/", "csrf": "y" * 44})
    assert response.status_code == 400


def test_a_non_ascii_csrf_token_is_refused_rather_than_raising(env):
    """compare_digest raises TypeError above U+007F, and a 500 on this endpoint
    would be a refusal turning into a crash."""
    client = env["client"]
    password_step(client)
    response = client.post("/login/2fa", follow_redirects=False, data={
        "code": a_live_code(env["secret"]), "next": "/", "csrf": "é" * 44})
    assert response.status_code == 400


# ------------------------------------------------------------ rate limit

def test_the_rate_limit_bites_after_a_burst_of_wrong_codes(env):
    client = env["client"]
    password_step(client)
    for _ in range(int(ratelimit.TOTP_USER_CAPACITY)):
        assert code_step(client, "000000").status_code == 401
    assert code_step(client, "000000").status_code == 429


def test_the_rate_limit_is_keyed_on_the_account_not_the_session(env):
    """Somebody at this page knows the password, so they can mint pending
    sessions at will. A per-session bucket would give each a full allowance and
    bound nothing."""
    client = env["client"]
    password_step(client)
    for _ in range(int(ratelimit.TOTP_USER_CAPACITY)):
        code_step(client, "000000")

    fresh = TestClient(ingest.app)
    password_step(fresh)
    assert code_step(fresh, "000000").status_code == 429


def test_the_rate_limit_refuses_even_a_right_code(env):
    """Fail closed. A limiter that let the correct answer through would be a
    limiter an attacker simply outlasts."""
    client = env["client"]
    password_step(client)
    for _ in range(int(ratelimit.TOTP_USER_CAPACITY)):
        code_step(client, "000000")
    assert code_step(client, a_live_code(env["secret"])).status_code == 429


def test_the_rate_limit_recovers(env):
    client = env["client"]
    password_step(client)
    for _ in range(int(ratelimit.TOTP_USER_CAPACITY)):
        code_step(client, "000000")
    assert code_step(client, "000000").status_code == 429

    moved = [time.monotonic() + 3600]
    ingest.app.state.limiters.totp_user._clock = lambda: moved[0]
    ingest.app.state.limiters.totp_global._clock = lambda: moved[0]
    assert code_step(client, a_live_code(env["secret"])).status_code == 303


# ------------------------------------------------------- recovery codes

def test_a_recovery_code_signs_in_and_says_how_many_are_left(env):
    client = env["client"]
    password_step(client)
    response = code_step(client, env["codes"][0])
    assert response.status_code == 200
    assert "9 recovery codes remaining" in response.text
    assert client.get("/api/auth/check").status_code == 204


def test_a_recovery_code_works_once(env):
    client = env["client"]
    password_step(client)
    code_step(client, env["codes"][0])

    second = TestClient(ingest.app)
    password_step(second)
    assert code_step(second, env["codes"][0]).status_code == 401


def test_the_last_recovery_code_says_so_in_the_singular(env):
    con = db.connect()
    try:
        # Keep the two oldest, which are codes[0] and codes[1], so spending
        # codes[0] below leaves exactly one. Ordered explicitly rather than
        # relying on what an unordered LIMIT happens to return.
        con.execute("DELETE FROM totp_recovery_codes WHERE user_id = ? AND id NOT IN"
                    " (SELECT id FROM totp_recovery_codes WHERE user_id = ?"
                    "  ORDER BY id LIMIT 2)",
                    (env["user_id"], env["user_id"]))
        con.commit()
    finally:
        con.close()
    client = env["client"]
    password_step(client)
    response = code_step(client, env["codes"][0])
    assert "1 recovery code remaining" in response.text


def test_recovery_codes_are_not_stored_in_readable_form(env):
    """A copy of the database is the inventory, not a way in."""
    con = db.connect()
    try:
        rows = con.execute("SELECT code_hash FROM totp_recovery_codes").fetchall()
    finally:
        con.close()
    assert len(rows) == accounts.RECOVERY_CODE_COUNT
    stored = {row["code_hash"] for row in rows}
    for code in env["codes"]:
        assert code not in stored
    assert all(row["code_hash"].startswith("scrypt$") for row in rows)


def test_recovery_codes_avoid_the_lookalike_characters(env):
    """They are read off a printout and typed by somebody who has just lost
    their phone, so no 0 against o and no 1 against l against i."""
    for code in env["codes"]:
        assert re.fullmatch(r"[a-z2-9]{4}-[a-z2-9]{4}", code), code
        assert not set(code) & set("01loi")


def test_a_recovery_code_of_the_wrong_shape_is_refused(env):
    client = env["client"]
    password_step(client)
    assert code_step(client, "aaaa-bbbb").status_code == 401


def test_resetting_the_codes_invalidates_the_old_ones(env):
    con = db.connect()
    try:
        fresh = accounts.reset_recovery_codes(con, env["user_id"])
    finally:
        con.close()
    assert set(fresh) & set(env["codes"]) == set()
    client = env["client"]
    password_step(client)
    assert code_step(client, env["codes"][0]).status_code == 401
    second = TestClient(ingest.app)
    password_step(second)
    assert code_step(second, fresh[0]).status_code == 200


# --------------------------------------------------------------- enrolment

def test_an_unconfirmed_enrolment_leaves_two_factor_off(tmp_path, monkeypatch):
    """The whole point of confirming with a code: a secret nobody typed in
    correctly must not lock the operator out of their own control plane."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "t.db"))
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    user_id = accounts.create_user(con, EMAIL, PASSWORD)
    accounts.begin_totp_enrollment(con, user_id)
    user = accounts.get_user_by_email(con, EMAIL)
    assert user["totp_secret"]
    assert not accounts.totp_enabled(user)
    con.close()

    client = TestClient(ingest.app)
    response = password_step(client)
    assert response.headers["location"] == "/"
    assert client.get("/api/auth/check").status_code == 204


def test_starting_again_replaces_an_unconfirmed_secret(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "t.db"))
    con = db.connect()
    db.init(con)
    accounts.init(con)
    user_id = accounts.create_user(con, EMAIL, PASSWORD)
    first = accounts.begin_totp_enrollment(con, user_id)
    second = accounts.begin_totp_enrollment(con, user_id)
    assert first != second
    con.close()


def test_enrolment_refuses_to_replace_a_confirmed_secret(env):
    """That would silently break the app the operator is already using."""
    con = db.connect()
    try:
        with pytest.raises(accounts.AccountError):
            accounts.begin_totp_enrollment(con, env["user_id"])
    finally:
        con.close()


def test_a_wrong_confirmation_code_leaves_two_factor_off(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "t.db"))
    con = db.connect()
    db.init(con)
    accounts.init(con)
    user_id = accounts.create_user(con, EMAIL, PASSWORD)
    accounts.begin_totp_enrollment(con, user_id)
    with pytest.raises(accounts.AccountError):
        accounts.confirm_totp_enrollment(con, user_id, "000000", at_time=NOW)
    assert not accounts.totp_enabled(accounts.get_user_by_email(con, EMAIL))
    assert accounts.recovery_codes_remaining(con, user_id) == 0
    con.close()


def test_turning_two_factor_off_removes_the_secret_and_the_codes(env):
    con = db.connect()
    try:
        accounts.disable_totp(con, env["user_id"])
        user = accounts.get_user_by_email(con, EMAIL)
        assert not accounts.totp_enabled(user)
        assert user["totp_secret"] is None
        assert user["totp_last_step"] is None
        assert accounts.recovery_codes_remaining(con, env["user_id"]) == 0
    finally:
        con.close()
    client = env["client"]
    assert password_step(client).headers["location"] == "/"
    assert client.get("/api/auth/check").status_code == 204


# ------------------------------------------------------------------ schema

def test_init_is_idempotent_over_the_added_columns(tmp_path, monkeypatch):
    """The columns are ALTERed in, and SQLite has no ADD COLUMN IF NOT EXISTS.
    Running init twice on a live database must not raise."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "t.db"))
    con = db.connect()
    db.init(con)
    accounts.init(con)
    accounts.init(con)
    accounts.init(con)
    columns = {row["name"] for row in con.execute("PRAGMA table_info(users)")}
    assert {"totp_secret", "totp_enabled_at", "totp_last_step"} <= columns
    sessions = {row["name"] for row in con.execute("PRAGMA table_info(sessions)")}
    assert "totp_pending" in sessions
    con.close()


def test_a_session_row_written_before_this_change_still_resolves(tmp_path, monkeypatch):
    """The upgrade a real box actually walks: rows exist, then the column is
    added under them. ALTER TABLE fills it with the default, so an operator who
    was signed in across the deploy is not signed out by it.

    The pre-change schema is written out here rather than taken from SCHEMA,
    because the point is what was on disk before this change and that is a
    fixed historical fact, not something that should follow the file.
    """
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "t.db"))
    con = db.connect()
    db.init(con)
    con.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
            disabled_at TEXT, last_login_at TEXT);
        CREATE TABLE sessions (
            id INTEGER PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id),
            created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            last_used_at TEXT, revoked_at TEXT, user_agent TEXT);
    """)
    con.commit()
    # Written with raw SQL rather than accounts.create_user, for the reason the
    # docstring gives about the schema: this row is meant to be one that existed
    # before the upgrade, and today's create_user writes today's columns.
    cur = con.execute(
        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
        (EMAIL, accounts.hash_password(PASSWORD),
         accounts._iso(accounts.now_utc())))
    user_id = cur.lastrowid
    now = accounts.now_utc()
    token = accounts.SESSION_PREFIX + "a-token-from-before-the-upgrade"
    con.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (accounts._hash_token(token), user_id, accounts._iso(now),
                 accounts._iso(now + accounts.SESSION_TTL)))
    con.commit()

    accounts.init(con)

    assert accounts.resolve_session(con, token) is not None
    assert accounts.resolve_pending_session(con, token) is None
    con.close()
