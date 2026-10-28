"""The login surface: the form, the cookie, CSRF, the rate limit, and logout.

    python -m pytest tests/test_login.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle security bug in review, these tests are the review.
The ones that matter most, in the order a reviewer should read them: a stolen
cookie stops working the moment its owner signs out, a cross-site post is
refused, the rate limit bites and then recovers, `?next=` cannot leave this
site, and the password reaches neither a log line nor a response.
"""

import logging
import re

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, ingest, ratelimit, web_auth

EMAIL = "sysadmin@example.com"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "open")
    # The app object is a module-level singleton, so its limiters carry across
    # tests unless each one starts with its own set.
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    accounts.create_user(con, EMAIL, PASSWORD)
    con.close()
    return TestClient(ingest.app)


def csrf_of(page_html):
    match = re.search(r'name="csrf" value="([^"]+)"', page_html)
    assert match, "the login form did not carry a CSRF token"
    return match.group(1)


def sign_in(client, email=EMAIL, password=PASSWORD, next_field="/"):
    """The whole flow a browser walks: fetch the form, post it back."""
    page = client.get("/login", follow_redirects=False)
    assert page.status_code == 200, "already signed in, use a fresh client"
    return client.post("/login", follow_redirects=False, data={
        "email": email, "password": password, "next": next_field,
        "csrf": csrf_of(page.text)})


def fresh_client():
    """A second browser, with no cookies of its own."""
    return TestClient(ingest.app)


def set_cookie_lines(response, name):
    return [line for line in response.headers.get_list("set-cookie")
            if line.startswith(name + "=")]


# ---------------------------------------------------------------- the form

def test_the_login_page_renders_and_sets_a_csrf_cookie(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert "Sign in" in page.text
    assert csrf_of(page.text) == client.cookies["whichports_csrf"]
    assert page.headers["cache-control"] == "no-store"


def test_the_login_page_is_not_cached_and_not_indexed(client):
    page = client.get("/login")
    assert page.headers["cache-control"] == "no-store"
    assert 'name="robots" content="noindex,nofollow"' in page.text


def test_the_page_takes_its_look_from_the_design_system(client):
    """The palette is not restated in the control plane. docs/DESIGN.md section
    1 owns the values and site/theme.py is where they become code, so the page
    has to be carrying that file's tokens rather than a copy of them."""
    from app import web_pages
    page = client.get("/login")
    assert web_pages.theme().TOKENS.strip() in page.text
    assert "Space Grotesk" in page.text


# -------------------------------------------------------------- signing in

def test_a_good_password_signs_in(client):
    resp = sign_in(client)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"
    assert client.get("/api/auth/whoami").json() == {"email": EMAIL}


def test_the_session_cookie_is_httponly_and_samesite(client):
    resp = sign_in(client)
    line = set_cookie_lines(resp, "whichports_session")[0].lower()
    assert "httponly" in line
    assert "samesite=lax" in line
    # Plain http in the test client, so Secure is correctly absent here.
    assert "secure" not in line


def test_the_session_cookie_is_secure_over_https(client):
    """A cookie set without Secure over a TLS connection is one a downgrade can
    read off the wire."""
    over_tls = TestClient(ingest.app, base_url="https://testserver")
    resp = sign_in(over_tls)
    line = set_cookie_lines(resp, "whichports_session")[0].lower()
    assert "secure" in line


@pytest.mark.parametrize("headers,scheme,expected", [
    ({"x-forwarded-proto": "https"}, "http", True),
    ({"x-forwarded-proto": "http"}, "http", False),
    ({}, "https", True),
    ({}, "http", False),
    # A proxy that forwards the browser's plain http must not have the flag
    # turned back on by the connection to the app being TLS.
    ({"x-forwarded-proto": "http"}, "https", False),
])
def test_the_forwarded_protocol_decides_the_secure_flag(headers, scheme, expected):
    """Behind Caddy this process sees plain http, so the forwarded protocol is
    what decides. Getting it wrong either drops the flag in production or sets a
    cookie a plain-http lab box never sends back."""
    from starlette.requests import Request
    scope = {"type": "http", "scheme": scheme, "path": "/login", "method": "GET",
             "headers": [(k.encode(), v.encode()) for k, v in headers.items()],
             "query_string": b"", "server": ("testserver", 80)}
    assert web_auth.cookie_secure(Request(scope)) is expected


def test_a_wrong_password_does_not_sign_in(client):
    resp = sign_in(client, password="the-wrong-one-entirely")
    assert resp.status_code == 401
    assert "whichports_session" not in client.cookies
    assert client.get("/api/auth/whoami").status_code == 401


def test_an_unknown_address_and_a_wrong_password_answer_identically(client):
    """No enumeration through the wording. The two pages have to be the same
    bytes once each one's own email is taken out of it."""
    page = client.get("/login")
    token = csrf_of(page.text)

    def attempt(email):
        return client.post("/login", follow_redirects=False, data={
            "email": email, "password": "the-wrong-one-entirely",
            "next": "/", "csrf": token})

    wrong = attempt(EMAIL)
    unknown = attempt("nobody@example.com")
    assert wrong.status_code == unknown.status_code == 401
    assert (wrong.text.replace(EMAIL, "X")
            == unknown.text.replace("nobody@example.com", "X"))


def test_a_disabled_account_gets_the_same_answer_as_a_wrong_password(client):
    con = db.connect()
    accounts.set_disabled(con, EMAIL, True)
    con.close()
    resp = sign_in(client)
    assert resp.status_code == 401
    assert "That email and password do not match." in resp.text


def test_the_form_keeps_the_email_and_never_the_password(client):
    resp = sign_in(client, password="the-wrong-one-entirely")
    assert f'value="{EMAIL}"' in resp.text
    assert "the-wrong-one-entirely" not in resp.text


def test_two_browsers_get_two_sessions_and_neither_ends_the_other(client):
    """Signing in on the laptop must not sign the phone out. Two rows, two
    tokens, and revoking one leaves the other alone."""
    first = sign_in(client).cookies["whichports_session"]
    second = sign_in(fresh_client()).cookies["whichports_session"]
    assert first != second
    for token in (first, second):
        other = TestClient(ingest.app, cookies={"whichports_session": token})
        assert other.get("/api/auth/whoami").status_code == 200


def test_the_login_page_redirects_someone_already_signed_in(client):
    sign_in(client)
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


# --------------------------------------------------------------------- CSRF

def test_a_post_with_no_csrf_field_is_refused(client):
    client.get("/login")
    resp = client.post("/login", follow_redirects=False,
                       data={"email": EMAIL, "password": PASSWORD})
    assert resp.status_code == 400
    assert "whichports_session" not in client.cookies


def test_a_cross_site_post_is_refused(client):
    """The double-submit check. A cross-site page can guess the field name but
    cannot read the cookie, so the token it sends will not match."""
    client.get("/login")
    resp = client.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/",
        "csrf": "b" * 64})
    assert resp.status_code == 400
    assert "whichports_session" not in client.cookies


def test_a_post_with_no_csrf_cookie_at_all_is_refused(client):
    """SameSite=Lax already stops the cookie arriving cross-site, so this is
    what a real cross-site post looks like from the server's side."""
    page = client.get("/login")
    token = csrf_of(page.text)
    bare = TestClient(ingest.app)
    resp = bare.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/", "csrf": token})
    assert resp.status_code == 400


def test_a_short_csrf_token_is_refused_even_if_it_matches(client):
    """An empty cookie and an empty field match each other, and must not pass."""
    bare = TestClient(ingest.app, cookies={"whichports_csrf": "short"})
    resp = bare.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/", "csrf": "short"})
    assert resp.status_code == 400


def test_a_non_ascii_csrf_token_is_refused_rather_than_crashing(client):
    """hmac.compare_digest raises TypeError on two str values the moment
    either holds a codepoint above U+007F, and both of these come from the
    request. Unhandled that is a 500 on an unauthenticated endpoint instead
    of a refusal. The token this code issues is url-safe base64, so anything
    outside ASCII is not our token."""
    bare = TestClient(ingest.app, cookies={"whichports_csrf": "e" * 40})
    resp = bare.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/", "csrf": "\u00e9" * 40})
    assert resp.status_code == 400


def test_a_non_ascii_csrf_cookie_is_refused_rather_than_crashing():
    """The same crash is reachable from the cookie side, because Starlette
    decodes header bytes as latin-1, so bytes 0x80 to 0xFF arrive as
    non-ASCII text.

    This one goes at the function rather than through the client, because
    httpx refuses to encode a non-ASCII cookie and the request never leaves.
    A real browser is under no such obligation, so the path is reachable in
    production even though this client cannot reach it.
    """
    class _Req:
        cookies = {web_auth.CSRF_COOKIE: "\u00e9" * 40}

    assert web_auth._csrf_ok(_Req(), "e" * 40) is False
    assert web_auth._csrf_ok(_Req(), "\u00e9" * 40) is False


def test_an_oversized_body_is_refused_before_it_is_parsed(client):
    client.get("/login")
    resp = client.post("/login", follow_redirects=False,
                       content=b"csrf=" + b"a" * (web_auth.FORM_BODY_MAX_BYTES + 1),
                       headers={"content-type": "application/x-www-form-urlencoded"})
    # Every field comes back empty, so the CSRF check refuses it.
    assert resp.status_code == 400


def test_an_undecodable_body_is_refused(client):
    client.get("/login")
    resp = client.post("/login", follow_redirects=False, content=b"\xff\xfe\xfd",
                       headers={"content-type": "application/x-www-form-urlencoded"})
    assert resp.status_code == 400


# ------------------------------------------------------------------- logout

def test_logout_revokes_the_session_on_the_server(client):
    """A cookie somebody else copied stops working, which is the whole reason
    sessions live in the database instead of being signed and self-contained."""
    token = sign_in(client).cookies["whichports_session"]
    stolen = TestClient(ingest.app, cookies={"whichports_session": token})
    assert stolen.get("/api/auth/whoami").status_code == 200

    resp = client.post("/logout", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?msg=signed-out"

    assert stolen.get("/api/auth/whoami").status_code == 401
    assert client.get("/api/auth/whoami").status_code == 401


def test_logout_clears_the_cookie_in_the_browser_too(client):
    sign_in(client)
    resp = client.post("/logout", follow_redirects=False)
    assert set_cookie_lines(resp, "whichports_session")


def test_logout_without_a_session_is_not_an_error(client):
    resp = client.post("/logout", follow_redirects=False)
    assert resp.status_code == 303


def test_logout_is_not_reachable_by_a_get(client):
    """A GET would let an image tag or a link sign somebody out."""
    sign_in(client)
    assert client.get("/logout", follow_redirects=False).status_code == 405
    assert client.get("/api/auth/whoami").status_code == 200


def test_the_signed_out_notice_shows_once_on_the_login_page(client):
    page = client.get("/login?msg=signed-out")
    assert "You are signed out." in page.text
    assert "You are signed out." not in client.get("/login").text


def test_an_unknown_notice_key_renders_nothing(client):
    page = client.get("/login?msg=<script>alert(1)</script>")
    assert page.status_code == 200
    assert "<script>alert(1)" not in page.text


# --------------------------------------------------------------- rate limit

def test_the_rate_limit_bites(client):
    """Per email. Ten in a burst, then refused, so the form is not an
    unlimited guessing machine."""
    page = client.get("/login")
    token = csrf_of(page.text)

    def attempt():
        return client.post("/login", follow_redirects=False, data={
            "email": EMAIL, "password": "the-wrong-one-entirely",
            "next": "/", "csrf": token})

    codes = [attempt().status_code for _ in range(
        int(ratelimit.LOGIN_EMAIL_CAPACITY) + 2)]
    assert codes[0] == 401
    assert codes[-1] == 429


def test_the_rate_limit_recovers(client):
    """It has to let a real person back in, or a griefer locks an operator out
    of their own fleet permanently. Time is injected so the test never sleeps."""
    clock = [1000.0]
    ingest.app.state.limiters.login_email = ratelimit.TokenBucket(
        ratelimit.LOGIN_EMAIL_CAPACITY, ratelimit.LOGIN_EMAIL_REFILL_PER_SECOND,
        clock=lambda: clock[0])
    page = client.get("/login")
    token = csrf_of(page.text)

    def attempt(password):
        return client.post("/login", follow_redirects=False, data={
            "email": EMAIL, "password": password, "next": "/", "csrf": token})

    for _ in range(int(ratelimit.LOGIN_EMAIL_CAPACITY)):
        attempt("the-wrong-one-entirely")
    assert attempt("the-wrong-one-entirely").status_code == 429
    # One token refills every thirty seconds.
    clock[0] += 31.0
    assert attempt(PASSWORD).status_code == 303


def test_the_rate_limit_is_per_email_not_across_the_fleet(client):
    """One address being hammered must not lock everybody else out. That is
    what the global bucket is for, and it is set far above real traffic."""
    page = client.get("/login")
    token = csrf_of(page.text)
    for _ in range(int(ratelimit.LOGIN_EMAIL_CAPACITY) + 1):
        client.post("/login", follow_redirects=False, data={
            "email": "someone-else@example.com", "password": "wrong-wrong-wrong",
            "next": "/", "csrf": token})
    resp = client.post("/login", follow_redirects=False, data={
        "email": EMAIL, "password": PASSWORD, "next": "/", "csrf": token})
    assert resp.status_code == 303


def test_the_global_backstop_bounds_a_spray_across_many_addresses(client):
    """A per-email bucket alone is walked straight past by one attempt each at
    a thousand different addresses.

    The clock is frozen, or the bucket refills during the run: a hundred real
    scrypt hashes take long enough to hand back the very tokens being counted.
    """
    ingest.app.state.limiters.login_global = ratelimit.TokenBucket(
        ratelimit.LOGIN_GLOBAL_CAPACITY, ratelimit.LOGIN_GLOBAL_REFILL_PER_SECOND,
        clock=lambda: 1000.0)
    page = client.get("/login")
    token = csrf_of(page.text)
    codes = []
    for i in range(int(ratelimit.LOGIN_GLOBAL_CAPACITY) + 2):
        codes.append(client.post("/login", follow_redirects=False, data={
            "email": f"spray-{i}@example.com", "password": "wrong-wrong-wrong",
            "next": "/", "csrf": token}).status_code)
    assert codes[0] == 401
    assert codes[-1] == 429


# ------------------------------------------------------------------- ?next=

@pytest.mark.parametrize("hostile", [
    "https://evil.example/", "http://evil.example/", "//evil.example/",
    "\\\\evil.example\\", "/\\evil.example", "javascript:alert(1)",
    "evil.example", "/ok\nLocation: https://evil.example/",
])
def test_next_refuses_anything_that_leaves_this_site(hostile):
    assert web_auth.safe_next(hostile) == "/"


@pytest.mark.parametrize("fine", ["/", "/host/almabox", "/?tab=rules",
                                  "/host/almabox#packet-path"])
def test_next_keeps_a_relative_path(fine):
    assert web_auth.safe_next(fine) == fine


def test_a_hostile_next_on_the_form_does_not_redirect_off_site(client):
    resp = sign_in(client, next_field="https://evil.example/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_a_scheme_relative_next_on_the_form_does_not_redirect_off_site(client):
    resp = sign_in(client, next_field="//evil.example/")
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_a_relative_next_survives_the_login(client):
    resp = sign_in(client, next_field="/host/almabox")
    assert resp.headers["location"] == "/host/almabox"


def test_a_hostile_next_in_the_query_never_reaches_the_form(client):
    page = client.get("/login?next=https://evil.example/")
    assert 'name="next" value="/"' in page.text
    assert "evil.example" not in page.text


# ---------------------------------------------------- the password itself

def test_the_password_reaches_no_log_line_and_no_response(client, caplog):
    """SI-8's spirit applied to this side of the box: nothing that could carry
    a secret leaves the process. A password in a journal is a password in every
    backup of that journal."""
    caplog.set_level(logging.DEBUG)
    bad = sign_in(client, password="another-wrong-password")
    good = sign_in(fresh_client())
    client.get("/api/auth/whoami")

    for response in (good, bad):
        assert PASSWORD not in response.text
        assert "another-wrong-password" not in response.text
        assert PASSWORD not in str(response.headers)
    for record in caplog.records:
        assert PASSWORD not in record.getMessage()
        assert "another-wrong-password" not in record.getMessage()


def test_the_password_is_never_written_to_the_database(client):
    sign_in(client)
    con = db.connect()
    dump = "\n".join(line for line in con.iterdump())
    con.close()
    assert PASSWORD not in dump


# -------------------------------------------------------------- the gate

def test_whoami_needs_a_session(client):
    assert client.get("/api/auth/whoami").status_code == 401


def test_whoami_refuses_a_session_that_was_revoked_out_of_band(client):
    """The CLI's sign-out, seen from the browser's side."""
    sign_in(client)
    con = db.connect()
    user = accounts.get_user_by_email(con, EMAIL)
    accounts.revoke_all_sessions(con, user["id"])
    con.close()
    assert client.get("/api/auth/whoami").status_code == 401


def test_the_existing_ingest_and_admin_surface_is_unchanged(client):
    """This pull request gates nothing that already existed. The agents' path
    and the admin gate answer exactly as they did before."""
    assert client.get("/healthz").json() == {"status": "up"}
    assert client.post("/api/v1/reports").status_code == 401
    assert client.post("/api/admin/hosts", content="{}").status_code == 403


# --------------------------------------------------- the forward-auth check
#
# GET /api/auth/check is what a future Caddy forward_auth asks before serving
# the static dashboard. It answers only 204 or 401, so Caddy can gate a set of
# static files on "is this browser signed in" without the app rendering them.

def test_auth_check_is_204_with_a_session(client):
    """A signed-in browser gets a 204, an empty body, and no-store."""
    sign_in(client)
    resp = client.get("/api/auth/check")
    assert resp.status_code == 204
    assert resp.content == b""
    assert resp.headers["cache-control"] == "no-store"


def test_auth_check_is_401_without_a_session(client):
    """A browser with no session cookie is refused, and that answer is not
    cached either."""
    resp = fresh_client().get("/api/auth/check")
    assert resp.status_code == 401
    assert resp.content == b""
    assert resp.headers["cache-control"] == "no-store"


def test_auth_check_refuses_a_session_revoked_out_of_band(client):
    """The CLI's sign-out closes the dashboard on the session's next request,
    the same revocation whoami already honours. If this did not hold, a copied
    cookie would keep opening the dashboard after its owner signed out."""
    sign_in(client)
    con = db.connect()
    user = accounts.get_user_by_email(con, EMAIL)
    accounts.revoke_all_sessions(con, user["id"])
    con.close()
    assert client.get("/api/auth/check").status_code == 401


def test_auth_check_does_not_enumerate_accounts(client):
    """The check reads only this request's own session cookie and never an
    email, so a caller with no cookie and one waving a made-up token get the
    byte-identical empty 401. Neither learns whether any address has an
    account."""
    no_cookie = fresh_client().get("/api/auth/check")
    made_up = TestClient(
        ingest.app,
        cookies={web_auth.SESSION_COOKIE: accounts.SESSION_PREFIX + "not-real"}
    ).get("/api/auth/check")
    assert no_cookie.status_code == made_up.status_code == 401
    assert no_cookie.content == made_up.content == b""


# ------------------------------------------------ the page reads as a product
#
# The owner, 2026-08-23, on the page as it stood: registering works the way it
# does on any other website, and the line "Accounts are created from the
# server." goes. These pin what changed, so a later edit does not quietly put
# it back.

def test_the_login_page_offers_the_way_to_register(client):
    """It used to say "Accounts are created from the server", which was true
    when the only way in was a shell and is a dead end now that anybody can
    sign up."""
    page = client.get("/login")
    assert "Accounts are created from the server" not in page.text
    assert 'href="/register"' in page.text


def test_the_register_page_offers_the_way_back_to_signing_in(client):
    page = client.get("/register")
    assert 'href="/login"' in page.text


def test_the_provider_marks_are_drawn_rather_than_fetched(client, monkeypatch):
    """docs/DESIGN.md section 4: no third-party request from a page we serve.
    A logo loaded from Google would tell them who is looking at this page
    before anybody has chosen to sign in with them."""
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_ID", "id")
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_SECRET", "secret")
    monkeypatch.setenv("WHICHPORTS_BASE_URL", "https://app.example")
    page = client.get("/login")
    assert "<svg" in page.text
    for host in ("google.com", "gstatic.com", "microsoft.com", "//"):
        assert f"src=\"{host}" not in page.text
    # No external stylesheet or script either, which is the same rule.
    assert "<script src=" not in page.text


def test_every_page_here_carries_no_external_reference(client):
    """The whole surface, not only the login page."""
    from app import web_pages
    pages = [web_pages.login_page(csrf="x" * 40, next_path="/"),
             web_pages.register_page(csrf="x" * 40),
             web_pages.two_factor_page(csrf="x" * 40, next_path="/")]
    for markup in pages:
        assert "http://" not in markup
        assert "https://" not in markup


def test_every_served_page_fixes_its_relative_references(client):
    """`theme.fonts()` and `theme.ICON_LINKS` use relative paths, which is right
    for the public site where each directory ships its own copy. The control
    plane serves pages at several depths from one place, so on `/login/2fa` a
    relative `fonts/X.woff2` asks for `/login/fonts/X.woff2` and nothing serves
    that. The page does not fail, it silently falls back to a system font, which
    is exactly the kind of break nobody files a bug about.

    The owner noticed the fonts also did not load anymore on the site.
    """
    from app import web_pages
    pages = {
        "login": web_pages.login_page(csrf="x" * 40, next_path="/"),
        "two factor": web_pages.two_factor_page(csrf="x" * 40, next_path="/"),
        "register": web_pages.register_page(csrf="x" * 40),
    }
    for name, markup in pages.items():
        assert '<base href="/">' in markup, f"{name} would look for its files sideways"
        # The base only helps if the references really are relative, so this
        # fails loudly if theme.py ever starts emitting absolute URLs and the
        # base element becomes dead weight nobody removed.
        assert "url(fonts/" in markup, name


def test_the_pages_served_from_a_nested_path_are_the_ones_that_needed_it(client):
    """The two-factor page lives at /login/2fa, one level down, which is where
    the relative path actually bit."""
    from app import web_auth
    assert web_auth.TWO_FACTOR_PATH.count("/") == 2
