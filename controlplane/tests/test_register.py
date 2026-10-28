"""Signing up, which is the one place an account comes from the internet.

    python -m pytest tests/test_register.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle security bug in review, these tests are the review.
The ones that matter most, in the order a reviewer should read them:

  - a new account lands in a workspace of its own and never in workspace 1,
    which is where the existing fleet lives,
  - it cannot see anything that was there before it,
  - a cross-site post creates nothing,
  - the rate limit bites and refuses even a valid signup,
  - a refused signup leaves no workspace behind.
"""

import re

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, ingest, ratelimit, store, web_auth

EMAIL = "new@example.com"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "open")
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    con.close()
    return TestClient(ingest.app)


def connect():
    con = db.connect()
    db.init(con)
    accounts.init(con)
    return con


def csrf_of(page_html):
    match = re.search(r'name="csrf" value="([^"]+)"', page_html)
    assert match, "the form did not carry a CSRF token"
    return match.group(1)


def sign_up(client, email=EMAIL, password=PASSWORD, confirm=None):
    page = client.get("/register", follow_redirects=False)
    assert page.status_code == 200, "already signed in, use a fresh client"
    return client.post("/register", follow_redirects=False, data={
        "email": email, "password": password,
        "confirm": password if confirm is None else confirm,
        "csrf": csrf_of(page.text)})


def workspace_count(con):
    return con.execute("SELECT COUNT(*) AS n FROM workspaces").fetchone()["n"]


# ------------------------------------------------------------- the form

def test_the_page_renders_and_sets_a_csrf_cookie(client):
    page = client.get("/register")
    assert page.status_code == 200
    assert csrf_of(page.text) == client.cookies["whichports_csrf"]
    assert page.headers["cache-control"] == "no-store"


def test_the_page_is_not_indexed(client):
    assert 'name="robots" content="noindex,nofollow"' in client.get("/register").text


def test_the_page_takes_its_look_from_the_design_system(client):
    from app import web_pages
    assert web_pages.theme().TOKENS.strip() in client.get("/register").text


def test_it_offers_the_way_to_the_login_page(client):
    assert 'href="/login"' in client.get("/register").text


def test_a_signed_in_browser_is_sent_on_rather_than_offered_a_second_account(client):
    sign_up(client)
    response = client.get("/register", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


# ------------------------------------------------------- the workspace

def test_a_new_account_gets_a_workspace_of_its_own(client):
    """The load-bearing one. Workspace 1 is where the existing fleet lives, and
    a new arrival landing there would see somebody else's servers."""
    con = connect()
    try:
        before = workspace_count(con)
    finally:
        con.close()

    assert sign_up(client).status_code == 303

    con = connect()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
        assert user["workspace_id"] != db.DEFAULT_WORKSPACE_ID
        assert workspace_count(con) == before + 1
    finally:
        con.close()


def test_two_signups_get_two_workspaces(client):
    sign_up(client)
    sign_up(TestClient(ingest.app), email="other@example.com")
    con = connect()
    try:
        first = accounts.get_user_by_email(con, EMAIL)["workspace_id"]
        second = accounts.get_user_by_email(con, "other@example.com")["workspace_id"]
        assert first != second
    finally:
        con.close()


def test_a_new_account_cannot_see_what_was_already_there(client):
    """A host in workspace 1, and somebody who signs up afterwards. The scoping
    is tested at length in tests/test_workspaces.py; this asserts that signing
    up actually lands on the safe side of it."""
    con = connect()
    try:
        store.add_host(con, "robins-box")
    finally:
        con.close()

    sign_up(client)
    con = connect()
    try:
        workspace = accounts.get_user_by_email(con, EMAIL)["workspace_id"]
        mine = store.list_hosts(con, workspace_id=workspace)
        theirs = store.list_hosts(con, workspace_id=db.DEFAULT_WORKSPACE_ID)
    finally:
        con.close()
    assert mine == []
    assert len(theirs) == 1


def test_signing_up_signs_you_in(client):
    sign_up(client)
    assert client.get("/api/auth/check").status_code == 204
    assert client.get("/api/auth/whoami").json() == {"email": EMAIL}


def test_the_new_session_cookie_is_httponly_and_samesite_lax(client):
    response = sign_up(client)
    lines = [line for line in response.headers.get_list("set-cookie")
             if line.startswith(web_auth.SESSION_COOKIE + "=")]
    assert len(lines) == 1
    assert "HttpOnly" in lines[0]
    assert "samesite=lax" in lines[0].lower()


def test_the_password_can_sign_in_again_afterwards(client):
    sign_up(client)
    con = connect()
    try:
        assert accounts.authenticate(con, EMAIL, PASSWORD) is not None
    finally:
        con.close()


# ------------------------------------------------------- what is refused

@pytest.mark.parametrize("email", [
    "", "not-an-address", "@example.com", "a@b", "a b@example.com",
    "a@@example.com", "a" * 250 + "@example.com",
])
def test_a_malformed_address_creates_nothing(client, email):
    response = sign_up(client, email=email)
    assert response.status_code == 400
    con = connect()
    try:
        assert workspace_count(con) == 1
        assert accounts.list_users(con) == []
    finally:
        con.close()


@pytest.mark.parametrize("password", ["", "short", "a" * 11])
def test_a_password_under_the_minimum_creates_nothing(client, password):
    response = sign_up(client, password=password)
    assert response.status_code == 400
    assert "at least" in response.text
    con = connect()
    try:
        assert workspace_count(con) == 1
    finally:
        con.close()


def test_a_password_over_the_maximum_creates_nothing(client):
    response = sign_up(client, password="a" * (accounts.PASSWORD_MAX_CHARS + 1))
    assert response.status_code == 400
    con = connect()
    try:
        assert workspace_count(con) == 1
    finally:
        con.close()


def test_two_passwords_that_do_not_match_create_nothing(client):
    response = sign_up(client, confirm="something-else-entirely")
    assert response.status_code == 400
    assert "do not match" in response.text
    con = connect()
    try:
        assert workspace_count(con) == 1
    finally:
        con.close()


def test_a_mismatch_is_reported_before_the_length_rule(client):
    """Both are wrong. "They do not match" is the more useful thing to hear."""
    response = sign_up(client, password="short", confirm="also-short")
    assert "do not match" in response.text


def test_an_address_that_already_exists_is_refused_and_makes_no_workspace(client):
    sign_up(client)
    con = connect()
    try:
        after_first = workspace_count(con)
    finally:
        con.close()

    response = sign_up(TestClient(ingest.app))
    assert response.status_code == 400
    assert "already exists" in response.text
    con = connect()
    try:
        assert workspace_count(con) == after_first, "a refused signup left a workspace"
    finally:
        con.close()


def test_the_address_is_matched_however_it_is_cased(client):
    sign_up(client)
    response = sign_up(TestClient(ingest.app), email=EMAIL.upper())
    assert response.status_code == 400
    assert "already exists" in response.text


def test_an_account_made_on_the_box_still_blocks_the_same_address(client):
    """`users_cli add` and this form write to the same table, so the two ways in
    must agree about what is taken."""
    con = connect()
    try:
        accounts.create_user(con, EMAIL, PASSWORD)
    finally:
        con.close()
    assert sign_up(TestClient(ingest.app)).status_code == 400


# ---------------------------------------------------------------- CSRF

def test_a_post_with_no_csrf_token_creates_nothing(client):
    client.get("/register")
    response = client.post("/register", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "confirm": PASSWORD, "csrf": ""})
    assert response.status_code == 400
    con = connect()
    try:
        assert accounts.list_users(con) == []
        assert workspace_count(con) == 1
    finally:
        con.close()


def test_a_post_with_somebody_elses_csrf_token_creates_nothing(client):
    client.get("/register")
    response = client.post("/register", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "confirm": PASSWORD,
        "csrf": "y" * 44})
    assert response.status_code == 400
    con = connect()
    try:
        assert accounts.list_users(con) == []
    finally:
        con.close()


def test_a_non_ascii_csrf_token_is_refused_rather_than_raising(client):
    """compare_digest raises TypeError above U+007F, and a 500 on an
    unauthenticated endpoint would be a refusal turning into a crash."""
    client.get("/register")
    response = client.post("/register", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "confirm": PASSWORD,
        "csrf": "é" * 44})
    assert response.status_code == 400


# ------------------------------------------------------------ rate limit

def test_the_rate_limit_bites_and_refuses_even_a_valid_signup(client):
    """Fail closed. A limiter that let the good request through is a limiter an
    attacker outlasts, and here the thing being bounded is workspace creation."""
    # The same address every time, because the tight bucket is keyed on it.
    for _ in range(int(ratelimit.LOGIN_EMAIL_CAPACITY)):
        sign_up(TestClient(ingest.app), password="short")
    response = sign_up(TestClient(ingest.app))
    assert response.status_code == 429
    con = connect()
    try:
        assert accounts.get_user_by_email(con, EMAIL) is None
    finally:
        con.close()


def test_the_global_bucket_bounds_a_spray_across_addresses(client):
    """A per-email bucket alone is walked past by using a new address each
    time, which is exactly what creating workspaces in a loop looks like. So
    the global bucket has to be consulted too, and this proves the endpoint
    asks it.

    **The bucket is drained directly rather than by a hundred real signups**,
    and that is not just for speed. The global bucket refills once a second, so
    a loop of real signups is a race between how fast it drains and how long a
    hundred scrypt hashes take on this particular machine. Written that way it
    passed here and failed in CI, which is a test that measures the machine
    rather than the code. Draining takes microseconds, so no meaningful refill
    happens while it runs.
    """
    limiters = ingest.app.state.limiters
    drained = 0
    while limiters.login_global.allow(ratelimit.GLOBAL_KEY):
        drained += 1
    assert drained >= int(ratelimit.LOGIN_GLOBAL_CAPACITY) - 1

    # A brand new address, so its own bucket is untouched and full. It is the
    # global one that has to refuse this.
    response = sign_up(TestClient(ingest.app), email="untouched@example.com")
    assert response.status_code == 429
    con = connect()
    try:
        assert accounts.get_user_by_email(con, "untouched@example.com") is None
        assert workspace_count(con) == 1
    finally:
        con.close()


# ---------------------------------------------------- the password itself

def test_the_password_is_not_written_anywhere_readable(client):
    sign_up(client)
    con = connect()
    try:
        user = accounts.get_user_by_email(con, EMAIL)
    finally:
        con.close()
    assert PASSWORD not in user["password_hash"]
    assert user["password_hash"].startswith("scrypt$")


def test_the_password_never_reaches_a_log_line(client, caplog):
    import logging
    with caplog.at_level(logging.DEBUG):
        sign_up(client)
    assert PASSWORD not in caplog.text


def test_the_password_is_not_echoed_back_on_a_refusal(client):
    """The form redraws with the address filled in and the password blank, so a
    refused signup does not put it in the HTML."""
    response = sign_up(client, confirm="mismatch")
    assert PASSWORD not in response.text
    assert EMAIL in response.text
