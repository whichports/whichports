"""Whether anybody may create an account, and who.

    python -m pytest tests/test_signup.py

The owner, 2026-08-23: the login page says that no new account can be made, none
is accepted, and he names the addresses that may register while he tests.

So the banner is the smallest part of this and the tests are weighted the other
way. **A notice that only says no is a lie the moment somebody posts the form
anyway**, and there are two ways an account comes into being here, not one. The
register form is the obvious one. A provider sign-in from an identity nobody has
seen is the one a banner would have walked straight past.

Read first: `test_a_provider_sign_in_cannot_walk_past_the_gate`.
"""

import re

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, identities, ingest, ratelimit, signup

EMAIL = "stranger@example.com"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Deliberately does NOT open signups: closed is the default and this file
    is about the default."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.delenv(signup.MODE_ENV, raising=False)
    monkeypatch.delenv(signup.ALLOW_ENV, raising=False)
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    identities.init(con)
    con.close()
    return TestClient(ingest.app)


def connect():
    con = db.connect()
    db.init(con)
    accounts.init(con)
    identities.init(con)
    return con


def csrf_of(html):
    match = re.search(r'name="csrf" value="([^"]+)"', html)
    assert match, "no CSRF token on the page"
    return match.group(1)


def try_register(client, email=EMAIL):
    page = client.get("/register")
    return client.post("/register", follow_redirects=False, data={
        "email": email, "password": PASSWORD, "confirm": PASSWORD,
        "csrf": csrf_of(page.text)})


# ------------------------------------------------------------- the decision

def test_closed_is_the_default(monkeypatch):
    """A configuration mistake leaves this shut rather than open, which is the
    safe way round for a gate whose whole job is to be shut."""
    monkeypatch.delenv(signup.MODE_ENV, raising=False)
    assert signup.mode() == signup.CLOSED
    assert not signup.is_open()


@pytest.mark.parametrize("value", ["", "  ", "yes", "true", "1", "OPEN ", "opened",
                                   "closed", "nonsense"])
def test_only_the_exact_word_opens_it(monkeypatch, value):
    """A typo reads as closed. Anything else and a slip in an env file is an
    open signup form on the internet."""
    monkeypatch.setenv(signup.MODE_ENV, value)
    assert signup.is_open() is (value.strip().lower() == "open")


@pytest.mark.parametrize("raw,expected", [
    ("a@example.com", {"a@example.com"}),
    ("a@example.com,b@example.org", {"a@example.com", "b@example.org"}),
    ("a@example.com b@example.org", {"a@example.com", "b@example.org"}),
    ("a@example.com, b@example.org,  c@example.net ", {"a@example.com", "b@example.org", "c@example.net"}),
    ("A@EXAMPLE.COM", {"a@example.com"}),
    ("", set()),
    ("   ", set()),
])
def test_the_allow_list_is_read_forgivingly(monkeypatch, raw, expected):
    """It is typed into a file by hand, so commas, spaces and capitals all have
    to work or the answer is a silent refusal nobody can explain."""
    monkeypatch.setenv(signup.ALLOW_ENV, raw)
    assert signup.allow_list() == expected


def test_an_allowed_address_may_sign_up_while_closed(monkeypatch):
    monkeypatch.setenv(signup.ALLOW_ENV, "invited@example.com")
    assert signup.may_sign_up("invited@example.com")
    assert signup.may_sign_up("INVITED@example.com"), "matched case insensitively"
    assert not signup.may_sign_up("someone@example.com")


def test_an_empty_address_is_never_allowed(monkeypatch):
    """Refused rather than treated as a wildcard, which is the safe way round
    and matches identities.provision refusing to name an account after
    nothing. Whitespace counts as empty: before this was pinned, a
    blank-but-not-empty address passed the emptiness check and the open mode
    answered yes to it."""
    monkeypatch.setenv(signup.MODE_ENV, "open")
    assert not signup.may_sign_up("")
    assert not signup.may_sign_up(None)
    assert not signup.may_sign_up("   ")
    assert not signup.may_sign_up("\t\n")


def test_open_lets_anybody_through(monkeypatch):
    monkeypatch.setenv(signup.MODE_ENV, "open")
    assert signup.may_sign_up("anybody@example.com")


# ------------------------------------------------------------- the form

def test_the_register_form_refuses_while_closed(client):
    response = try_register(client)
    assert response.status_code == 400
    assert signup.CLOSED_NOTICE in response.text
    con = connect()
    try:
        assert accounts.list_users(con) == []
        assert con.execute("SELECT COUNT(*) c FROM workspaces").fetchone()["c"] == 1
    finally:
        con.close()


def test_an_allowed_address_can_still_register(client, monkeypatch):
    """The "tell me the emails I want to add" half. One line in a file, no
    deploy."""
    monkeypatch.setenv(signup.ALLOW_ENV, EMAIL)
    assert try_register(client).status_code == 303
    con = connect()
    try:
        assert accounts.get_user_by_email(con, EMAIL) is not None
    finally:
        con.close()


def test_somebody_not_on_the_list_is_still_refused(client, monkeypatch):
    monkeypatch.setenv(signup.ALLOW_ENV, "invited@example.com")
    assert try_register(client, email="gatecrasher@example.com").status_code == 400


def test_the_refusal_does_not_say_whether_the_address_is_taken(client, monkeypatch):
    """Checked before the address lookup, so a closed server is not an
    enumeration oracle for the accounts it already has."""
    con = connect()
    try:
        accounts.create_user(con, "taken@example.com", PASSWORD)
    finally:
        con.close()
    taken = try_register(client, email="taken@example.com")
    fresh = try_register(client, email="nobody@example.com")
    assert taken.status_code == fresh.status_code == 400
    assert "already exists" not in taken.text


def test_the_gate_is_checked_before_any_hashing(client, monkeypatch):
    """A closed server should not be a way to spend its CPU."""
    calls = []
    monkeypatch.setattr(accounts, "hash_password",
                        lambda p: calls.append(p) or "scrypt$never")
    try_register(client)
    assert calls == []


# --------------------------------------------------------- the provider path

def test_a_provider_sign_in_cannot_walk_past_the_gate(client):
    """**The one that matters.** A banner on the register page covers the form
    and nothing else, and a provider sign-in is the other way an account comes
    into being. `identities.provision` is where both meet."""
    con = connect()
    try:
        with pytest.raises(identities.LinkError) as raised:
            identities.provision(con, "google", "sub-123", "stranger@example.com")
        assert signup.CLOSED_NOTICE in str(raised.value)
        assert accounts.list_users(con) == []
    finally:
        con.close()


def test_an_allowed_address_may_arrive_by_provider(client, monkeypatch):
    monkeypatch.setenv(signup.ALLOW_ENV, "invited@example.com")
    con = connect()
    try:
        user_id = identities.provision(con, "google", "sub-123", "invited@example.com")
        assert identities.find_user_id(con, "google", "sub-123") == user_id
    finally:
        con.close()


def test_a_provider_identity_that_already_signed_up_still_signs_in(client, monkeypatch):
    """Closing signups must not lock out the accounts that already exist. The
    gate is on creating an account, never on using one."""
    monkeypatch.setenv(signup.ALLOW_ENV, "invited@example.com")
    con = connect()
    try:
        user_id = identities.provision(con, "google", "sub-123", "invited@example.com")
    finally:
        con.close()
    monkeypatch.delenv(signup.ALLOW_ENV)
    con = connect()
    try:
        # The lookup that a returning sign-in uses does not consult the gate.
        assert identities.find_user_id(con, "google", "sub-123") == user_id
    finally:
        con.close()


def test_a_password_account_still_signs_in_while_closed(client, monkeypatch):
    con = connect()
    try:
        accounts.create_user(con, "operator@example.com", PASSWORD)
    finally:
        con.close()
    page = client.get("/login")
    response = client.post("/login", follow_redirects=False, data={
        "email": "operator@example.com", "password": PASSWORD, "next": "/",
        "csrf": csrf_of(page.text)})
    assert response.status_code == 303
    assert client.get("/api/auth/check").status_code == 204


# ------------------------------------------------------------- what is shown

def test_the_login_page_says_accounts_are_closed_and_offers_no_way_to_register(client):
    """Offering a button that leads to a refusal is the dead end this page
    already had once, in a different shape."""
    page = client.get("/login")
    assert signup.CLOSED_NOTICE in page.text
    assert 'href="/register"' not in page.text


def test_the_register_page_says_so_too(client):
    """It stays reachable, because somebody on the allow list has to use it."""
    page = client.get("/register")
    assert page.status_code == 200
    assert signup.CLOSED_NOTICE in page.text


def test_the_login_page_offers_registration_again_when_it_is_open(client, monkeypatch):
    monkeypatch.setenv(signup.MODE_ENV, "open")
    page = client.get("/login")
    assert signup.CLOSED_NOTICE not in page.text
    assert 'href="/register"' in page.text


def test_the_notice_and_the_refusal_are_the_same_words(client):
    """One string, so the promise on the page and the refusal behind it cannot
    drift apart."""
    page = client.get("/login")
    refusal = try_register(client)
    assert signup.CLOSED_NOTICE in page.text
    assert signup.CLOSED_NOTICE in refusal.text


# ------------------------------------------- the page shows a shut door
#
# The owner suggested a register button that cannot be clicked for now. A button
# that cannot be pressed rather than no button at all, which is the better
# answer as well as the asked-for one: an absent button says the product has no
# signup, a dead one says it has a signup and it is shut.


def body_of(markup):
    """The markup after the stylesheet. `theme.BASE` contains a `:disabled`
    rule, so searching the whole document for the word finds the CSS and
    reports the opposite of the truth."""
    return markup.split("</style>")[-1]


def test_the_login_page_says_so_in_a_banner_and_offers_nothing(client):
    """The dead button was a step on the way and did not survive contact.
    The owner had asked for a permanent banner on the login page saying that
    registration is closed, not for an error after signing in with a
    provider. So the notice is at the top, before the form, where somebody reads it
    before spending a consent screen finding out.

    Nothing is offered at all now, dead or alive: a button that cannot be
    pressed is still a button asking to be pressed.
    """
    page = body_of(client.get("/login").text)
    assert signup.CLOSED_NOTICE in page
    assert page.index(signup.CLOSED_NOTICE) < page.index('name="email"')
    assert 'href="/register"' not in page
    assert "Create an account" not in page


def test_the_register_page_says_so_before_its_form(client):
    page = body_of(client.get("/register").text)
    assert signup.CLOSED_NOTICE in page
    assert page.index(signup.CLOSED_NOTICE) < page.index('name="email"')


def test_the_disabled_attribute_is_not_the_check(client):
    """The page telling the truth is not the gate. A caller that ignores the
    attribute entirely, which is anything that is not a browser, still gets
    refused by the server."""
    response = try_register(client)
    assert response.status_code == 400
    con = connect()
    try:
        assert accounts.list_users(con) == []
    finally:
        con.close()


def test_the_way_to_register_comes_back_when_signups_are_open(client, monkeypatch):
    monkeypatch.setenv(signup.MODE_ENV, "open")
    login = body_of(client.get("/login").text)
    register = body_of(client.get("/register").text)
    assert 'href="/register"' in login
    assert signup.CLOSED_NOTICE not in login
    assert signup.CLOSED_NOTICE not in register


def test_no_field_carries_the_browsers_own_validation(client):
    """The browser's "Please fill in this field" bubble cannot be styled and
    matches nothing else on the page. The server validates every field anyway
    and answers in the same treatment as every other refusal."""
    for path in ("/login", "/register"):
        assert "required" not in body_of(client.get(path).text), path


# ----------------------------------------- one quiet banner, no tag chips
#
# The owner, 2026-08-23, seeing the login page say it twice, a banner with a SHUT
# chip plus a NO error after a refused Google sign-in. He asked for one plain
# yellow banner that says registration is not open for now (docs/RECORD.md
# 4.100). So the banner is one warn-toned sentence with nothing beside it, and a
# refusal that would repeat the banner's own words draws no second message.
# The provider half of that lives with the callback machinery in
# test_oidc_google.py.


def closed_banner_of(markup):
    """The closed banner and only the closed banner, markup included."""
    match = re.search(r'<div class="msg closed">.*?</div>', markup)
    assert match, "no closed banner on the page"
    return match.group(0)


def test_the_closed_banner_is_the_warn_tone_and_carries_no_chip(client):
    for path in ("/login", "/register"):
        banner = closed_banner_of(body_of(client.get(path).text))
        assert signup.CLOSED_NOTICE in banner, path
        assert "<em>" not in banner, path


def test_a_fresh_login_page_carries_no_tag_chip_at_all(client):
    """The banner is the only message on the page as it first loads, so any
    chip anywhere is one too many."""
    assert "<em>" not in body_of(client.get("/login").text)


def test_a_refused_register_says_the_line_once_with_no_error_on_top(client):
    """The refusal is signup.CLOSED_NOTICE, the banner's own words, one string
    on purpose. Stacking it as a second message said one fact twice."""
    response = try_register(client)
    assert response.status_code == 400
    body = body_of(response.text)
    assert body.count(signup.CLOSED_NOTICE) == 1
    assert 'class="msg fail"' not in body


def test_a_refusal_that_is_not_the_banner_keeps_the_error_treatment(client, monkeypatch):
    """Only the repeated line collapses into the banner. Any other refusal is
    still an error and still reads as one."""
    monkeypatch.setenv(signup.ALLOW_ENV, EMAIL)
    page = client.get("/register")
    response = client.post("/register", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "confirm": "different",
        "csrf": csrf_of(page.text)})
    assert response.status_code == 400
    body = body_of(response.text)
    assert 'class="msg fail"' in body
    assert "Those two do not match." in body
