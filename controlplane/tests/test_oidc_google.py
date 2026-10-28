"""Sign in with Google, and what a provider token is allowed to mean.

    python -m pytest tests/test_oidc_google.py

No network. A fake opener answers the discovery and token endpoints, so every
one of these runs the real `app/oidc.py` code path and only the socket is
replaced.

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle security bug in review, these tests are the review.
The ones that matter most, in the order a reviewer should read them:

  - an identity nobody linked signs nobody in, even when its email exactly
    matches an existing account,
  - a callback in the wrong browser is refused, which is login CSRF,
  - a state cannot be used twice,
  - a token for another audience, another issuer, another attempt's nonce, or
    an expired one, is refused,
  - a provider sign-in does not skip the second factor,
  - the token exchange cannot be sent through a proxy.
"""

import base64
import json
import re
import time
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from app import (accounts, db, identities, ingest, oidc, oidc_google,
                 ratelimit, signup, store, totp, web_auth)

EMAIL = "sysadmin@example.com"
PASSWORD = "correct-horse-battery-9"
CLIENT_ID = "1234.apps.googleusercontent.com"
SUBJECT = "108054000000000000000"
BASE = "https://app.whichports.example"

DISCOVERY = {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
    "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
}


class _Body:
    def __init__(self, payload):
        self._raw = json.dumps(payload).encode("utf-8")

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Answers the two Google endpoints and refuses anything else.

    `token_payload` is a callable so a test can see the body that was posted,
    which is how the PKCE verifier and the client secret are asserted on.
    """

    def __init__(self, token_payload=None, discovery=None):
        self.token_payload = token_payload
        self.discovery = discovery if discovery is not None else DISCOVERY
        self.posts = []
        self.gets = []

    def open(self, request, timeout=None):
        url = request.full_url
        if request.get_method() == "GET":
            self.gets.append(url)
            if url == oidc_google.DISCOVERY_URL:
                return _Body(self.discovery)
            raise AssertionError(f"unexpected GET {url}")
        body = dict(urllib.parse.parse_qsl(request.data.decode("utf-8")))
        self.posts.append((url, body))
        payload = self.token_payload(body) if callable(self.token_payload) \
            else self.token_payload
        return _Body(payload)


def id_token(claims):
    """A JWT with a real header and payload and a signature that is nonsense.

    The nonsense is the point of one test below: this build does not verify the
    signature, under the carve-out documented on `oidc.claims_from_id_token`,
    and a test that used a valid signature would not show that.
    """
    def seg(obj):
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{seg({'alg': 'RS256', 'kid': 'x'})}.{seg(claims)}.bm90LWEtc2lnbmF0dXJl"


def claims(bound_nonce, **overrides):
    base = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "exp": time.time() + 300,
        "iat": time.time(),
        "nonce": bound_nonce,
        "email": EMAIL,
        "email_verified": True,
    }
    base.update(overrides)
    return base


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "open")
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_SECRET", "a-secret")
    monkeypatch.setenv(oidc.BASE_URL_ENV, BASE)
    oidc.forget_discovery()
    ingest.app.state.limiters = ratelimit.Limiters()
    con = db.connect()
    db.init(con)
    accounts.init(con)
    identities.init(con)
    user_id = accounts.create_user(con, EMAIL, PASSWORD)
    con.close()

    opener = FakeOpener()
    monkeypatch.setattr(oidc, "build_opener", lambda context=None: opener)
    return {"client": TestClient(ingest.app), "user_id": user_id,
            "opener": opener, "tmp": tmp_path}


def connect():
    con = db.connect()
    db.init(con)
    accounts.init(con)
    identities.init(con)
    return con


def start(client, path="/login/google?next=/"):
    """Begin a sign-in and pull the state and nonce back out of the redirect."""
    response = client.get(path, follow_redirects=False)
    assert response.status_code == 303, response.text
    query = urllib.parse.parse_qs(urllib.parse.urlparse(
        response.headers["location"]).query)
    return {"state": query["state"][0], "nonce": query["nonce"][0],
            "query": query, "response": response}


def callback(client, env, attempt, token_claims=None, code="the-code"):
    payload = token_claims if token_claims is not None else claims(attempt["nonce"])
    env["opener"].token_payload = {"id_token": id_token(payload)}
    return client.get(f"/login/google/callback?code={code}&state={attempt['state']}",
                      follow_redirects=False)


def link_identity(env, subject=SUBJECT, user_id=None):
    con = connect()
    try:
        identities.link(con, "google", subject, user_id or env["user_id"])
    finally:
        con.close()


# ------------------------------------------------------ starting the flow

def test_the_login_page_offers_google_when_it_is_configured(env):
    """Asserted on the link rather than on the words beside it. The label is
    presentation and has already changed once, where the href is the
    behaviour and changing it would break the sign-in."""
    page = env["client"].get("/login")
    assert 'href="/login/google?next=%2F"' in page.text
    assert "Google" in page.text


def test_the_login_page_offers_nothing_when_it_is_not_configured(env, monkeypatch):
    monkeypatch.delenv("WHICHPORTS_GOOGLE_CLIENT_SECRET")
    page = env["client"].get("/login")
    assert "/login/google" not in page.text
    assert env["client"].get("/login/google", follow_redirects=False).status_code == 404


def test_a_client_id_without_a_secret_is_not_configured(env, monkeypatch):
    """Both halves or nothing. An id with no secret cannot finish the exchange,
    so a button for it would only ever lead to an error."""
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_SECRET", "   ")
    assert not oidc.is_ready(oidc_google.PROVIDER)


def test_without_a_base_url_there_is_no_provider_sign_in(env, monkeypatch):
    """The redirect URI has to byte-match what is registered, so it is
    configuration. Deriving it from the Host header would let whoever controls
    that header choose where the code is delivered."""
    monkeypatch.delenv(oidc.BASE_URL_ENV)
    assert not oidc.is_ready(oidc_google.PROVIDER)
    assert env["client"].get("/login/google", follow_redirects=False).status_code == 404


def test_an_unknown_provider_is_a_404_rather_than_an_explanation(env):
    assert env["client"].get("/login/facebook", follow_redirects=False).status_code == 404


def test_the_two_factor_page_is_not_swallowed_by_the_provider_route(env):
    """`/login/{provider_name}` matches the literal `/login/2fa` perfectly well,
    so registration order is load bearing. Registered the wrong way round, a
    two-factor login could never be completed."""
    paths = [r.path for r in web_auth.router.routes
             if getattr(r, "path", "").startswith("/login")]
    assert paths.index("/login/2fa") < paths.index("/login/{provider_name}")
    # And the behaviour, not only the order.
    assert env["client"].get("/login/2fa", follow_redirects=False).status_code == 303


def test_the_authorization_request_carries_what_the_spec_needs(env):
    query = start(env["client"])["query"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid email profile"]
    assert query["redirect_uri"] == [f"{BASE}/login/google/callback"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["state"][0]) >= 32
    assert len(query["nonce"][0]) >= 32
    assert len(query["code_challenge"][0]) == 43


def test_the_endpoints_come_from_discovery_and_not_from_this_codebase(env):
    """Only the discovery URI is written down, which is what Google asks for."""
    attempt = start(env["client"])
    assert attempt["response"].headers["location"].startswith(
        DISCOVERY["authorization_endpoint"] + "?")
    assert env["opener"].gets == [oidc_google.DISCOVERY_URL]


def test_the_discovery_document_is_cached_across_sign_ins(env):
    start(env["client"])
    start(TestClient(ingest.app))
    assert env["opener"].gets.count(oidc_google.DISCOVERY_URL) == 1


@pytest.mark.parametrize("document", [
    {},
    {"authorization_endpoint": "https://a", "token_endpoint": "https://b"},
    {"issuer": "x", "authorization_endpoint": "https://a", "token_endpoint": ""},
    {"issuer": "x", "authorization_endpoint": "http://a", "token_endpoint": "https://b"},
    {"issuer": "x", "authorization_endpoint": "https://a", "token_endpoint": "http://b"},
])
def test_a_discovery_document_that_is_not_usable_is_refused(env, document):
    """Including a plain http endpoint, because the whole argument for not
    checking the token signature is that the channel was TLS."""
    oidc.forget_discovery()
    env["opener"].discovery = document
    with pytest.raises(oidc.OIDCError):
        oidc.discovery(oidc_google.PROVIDER, opener=env["opener"])


def test_the_flow_is_remembered_server_side_and_the_browser_gets_only_a_binding(env):
    attempt = start(env["client"])
    cookie = env["client"].cookies.get(web_auth.FLOW_COOKIE)
    assert cookie and len(cookie) >= 32
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_flows").fetchone()
    finally:
        con.close()
    # The state and the binding are stored as hashes, never in the clear.
    assert row["state_hash"] != attempt["state"]
    assert row["binding_hash"] != cookie
    assert row["nonce"] == attempt["nonce"]


# ------------------------------------------------------------ PKCE

def test_the_verifier_is_within_the_rfc_bounds_and_from_its_alphabet():
    verifier = oidc.new_verifier()
    assert 43 <= len(verifier) <= 128
    assert re.fullmatch(r"[A-Za-z0-9\-._~]+", verifier)


def test_the_challenge_is_the_base64url_sha256_of_the_verifier():
    # SHA-256 of "abc" is a published value, so this pins the transform rather
    # than checking it against itself.
    assert oidc.challenge_of("abc") == "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    assert "=" not in oidc.challenge_of(oidc.new_verifier())


def test_the_verifier_is_sent_at_the_exchange_and_matches_the_challenge(env):
    link_identity(env)
    attempt = start(env["client"])
    challenge = attempt["query"]["code_challenge"][0]
    callback(env["client"], env, attempt)
    _, body = env["opener"].posts[0]
    assert oidc.challenge_of(body["code_verifier"]) == challenge


def test_the_exchange_posts_the_secret_to_the_discovered_token_endpoint(env):
    link_identity(env)
    attempt = start(env["client"])
    callback(env["client"], env, attempt)
    url, body = env["opener"].posts[0]
    assert url == DISCOVERY["token_endpoint"]
    assert body["client_secret"] == "a-secret"
    assert body["grant_type"] == "authorization_code"
    assert body["redirect_uri"] == f"{BASE}/login/google/callback"


# These two take no `env`, deliberately: that fixture replaces `build_opener`,
# and these are about what the real one is made of.

def test_the_exchange_cannot_be_sent_through_a_proxy(monkeypatch):
    """`build_opener` installs a bare ProxyHandler unless it is handed one, and
    a bare one reads `https_proxy` from the environment. The body of that POST
    carries the client secret, so the hole would open with nobody touching this
    code. `docs/RECORD.md` 4.86 is the entry about that gap being found in one
    outbound call and not another.

    **Asserted with `https_proxy` actually set, and against the unguarded
    default alongside it**, because the obvious structural test is silently
    vacuous. `OpenerDirector.add_handler` drops a handler that registers no
    methods, and a `ProxyHandler({})` registers none, so it never appears in
    `.handlers` at all. Looking for it there passes for the wrong reason
    whether the guard is present or absent. What is visible is the effect: with
    a proxy in the environment the default opener grows a ProxyHandler carrying
    it, and this one does not.
    """
    import urllib.request
    monkeypatch.setenv("https_proxy", "http://198.51.100.9:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://198.51.100.9:3128")

    unguarded = [h for h in urllib.request.build_opener().handlers
                 if isinstance(h, urllib.request.ProxyHandler)]
    assert unguarded and unguarded[0].proxies, (
        "the default opener stopped reading the environment, so this test no"
        " longer proves anything and needs rewriting")

    guarded = [h for h in oidc.build_opener().handlers
               if isinstance(h, urllib.request.ProxyHandler)]
    assert guarded == [], "the token exchange can be rerouted through a proxy"


def test_a_redirect_on_the_exchange_is_refused():
    """Following one would send a POST carrying the client secret somewhere
    nobody chose."""
    import urllib.request
    handlers = oidc.build_opener().handlers
    assert any(isinstance(h, oidc._NoRedirect) for h in handlers)
    assert not any(type(h) is urllib.request.HTTPRedirectHandler for h in handlers)


def test_certificate_verification_is_on():
    """It is the entire reason the token signature is not checked."""
    import ssl
    import urllib.request
    https = [h for h in oidc.build_opener().handlers
             if isinstance(h, urllib.request.HTTPSHandler)]
    assert https
    context = https[0]._context
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True


# ---------------------------------------------------------- the callback

def test_a_linked_identity_signs_in(env):
    link_identity(env)
    attempt = start(env["client"])
    response = callback(env["client"], env, attempt)
    assert response.status_code == 303
    assert response.headers["location"] == "/"
    assert env["client"].get("/api/auth/check").status_code == 204
    assert env["client"].get("/api/auth/whoami").json() == {"email": EMAIL}


def test_the_signature_is_not_verified_and_that_is_the_documented_carve_out(env):
    """Every token in this file carries a nonsense signature. This asserts that
    on purpose, so the day somebody moves the token onto a browser-delivered
    path, the reasoning on `oidc.claims_from_id_token` is not quietly wrong.

    OIDC Core 3.1.3.7 item 6 allows it only because the token came straight from
    the token endpoint over TLS we verified.
    """
    link_identity(env)
    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 303


def test_an_unlinked_identity_signs_nobody_in(env):
    """The token is valid and its address already belongs to an account
    here, so it is refused. An address never merges two accounts."""
    attempt = start(env["client"])
    response = callback(env["client"], env, attempt)
    assert response.status_code == 403
    assert "did not work" in response.text or "already exists" in response.text
    assert env["client"].get("/api/auth/check").status_code == 401


def test_a_matching_email_address_is_not_a_link(env):
    """The single most important test in this file.

    The token's email is exactly the address of an existing, enabled account,
    and it still signs nobody in. Matching an incoming token to a local account
    by email is the account-takeover pattern Microsoft published an advisory
    about in June 2023, and this asserts that the shortcut does not exist here.
    """
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], email=EMAIL, email_verified=True)
    response = callback(env["client"], env, attempt, token_claims=payload)
    assert response.status_code == 403
    assert env["client"].get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert identities.find_user_id(con, "google", SUBJECT) is None
    finally:
        con.close()


def test_a_different_subject_on_the_same_address_is_refused(env):
    """A linked account, and a token for a different Google user that happens to
    carry the same address. The subject is the key, so this is not that user."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], sub="999-somebody-else")
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 403


def test_a_disabled_account_is_refused_in_the_same_words_as_an_unlinked_one(env):
    link_identity(env)
    con = connect()
    try:
        accounts.set_disabled(con, EMAIL, True)
    finally:
        con.close()
    attempt = start(env["client"])
    response = callback(env["client"], env, attempt)
    assert response.status_code == 403
    assert "did not work" in response.text or "already exists" in response.text


# ------------------------------------------------- state, replay and CSRF

def test_a_callback_in_another_browser_is_refused(env):
    """Login CSRF. An attacker starts a flow, gets a callback URL carrying their
    own code and state, and tricks the victim into visiting it. Without the
    binding cookie the victim ends up signed in as the attacker."""
    attacker = env["client"]
    link_identity(env)
    attempt = start(attacker)
    victim = TestClient(ingest.app)
    env["opener"].token_payload = {"id_token": id_token(claims(attempt["nonce"]))}
    response = victim.get(
        f"/login/google/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert response.status_code == 400
    assert victim.get("/api/auth/check").status_code == 401


def test_a_state_cannot_be_used_twice(env):
    link_identity(env)
    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 303
    second = TestClient(ingest.app)
    assert callback(second, env, attempt).status_code == 400


def test_a_failed_callback_still_spends_the_state(env):
    """A wrong browser burns the attempt rather than getting another go."""
    link_identity(env)
    attempt = start(env["client"])
    TestClient(ingest.app).get(
        f"/login/google/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert callback(env["client"], env, attempt).status_code == 400


def test_an_unknown_state_is_refused(env):
    env["client"].get("/login/google", follow_redirects=False)
    response = env["client"].get("/login/google/callback?code=c&state=made-up",
                                 follow_redirects=False)
    assert response.status_code == 400


@pytest.mark.parametrize("query", [
    "?code=c", "?state=s", "", "?error=access_denied&state=s",
    "?code=&state=", "?error=access_denied",
])
def test_a_callback_that_is_not_an_answer_is_refused(env, query):
    response = env["client"].get(f"/login/google/callback{query}",
                                 follow_redirects=False)
    assert response.status_code == 400
    assert env["opener"].posts == [], "nothing should have been exchanged"


def test_an_expired_flow_is_refused(env, monkeypatch):
    link_identity(env)
    attempt = start(env["client"])
    later = identities.now_utc() + identities.FLOW_TTL + identities.timedelta(seconds=1)
    monkeypatch.setattr(identities, "now_utc", lambda: later)
    assert callback(env["client"], env, attempt).status_code == 400


# ------------------------------------------------------ the token claims

@pytest.mark.parametrize("issuer", ["https://accounts.google.com", "accounts.google.com"])
def test_both_issuer_strings_google_documents_are_accepted(env, issuer):
    """Google publishes two. A check against only the https form is a bug that
    bites the day the other one arrives."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], iss=issuer)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 303


@pytest.mark.parametrize("issuer", [
    "https://accounts.google.com.evil.example", "https://evil.example",
    "accounts.google.com.evil.example", "", None, 42,
    "https://accounts.google.com/", " https://accounts.google.com",
])
def test_any_other_issuer_is_refused(env, issuer):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], iss=issuer)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


def test_a_token_for_another_audience_is_refused(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], aud="somebody-elses-client-id")
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


def test_a_token_with_our_audience_and_another_alongside_it_is_refused(env):
    """A second audience means the token is also somebody else's."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], aud=[CLIENT_ID, "another-client"])
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


def test_an_audience_list_holding_only_us_is_accepted(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], aud=[CLIENT_ID])
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 303


def test_an_expired_token_is_refused(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], exp=time.time() - 3600)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


@pytest.mark.parametrize("exp", [None, "soon", [], {}])
def test_a_token_with_no_usable_expiry_is_refused(env, exp):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], exp=exp)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


def test_a_token_answering_another_attempt_is_refused(env):
    """The nonce check. Without it a token captured from one sign-in could be
    replayed into another attempt."""
    link_identity(env)
    first = start(env["client"])
    second = start(TestClient(ingest.app))
    payload = claims(second["nonce"])
    assert callback(env["client"], env, first, token_claims=payload).status_code == 400


@pytest.mark.parametrize("nonce", [None, "", 42, []])
def test_a_token_with_no_usable_nonce_is_refused(env, nonce):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], nonce=nonce)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


def test_a_token_with_no_subject_is_refused(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], sub=None)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 400


@pytest.mark.parametrize("token", [
    "", "not-a-jwt", "a.b", "a.b.c.d", "a.!!!.c",
    "a." + base64.urlsafe_b64encode(b"[1,2]").decode().rstrip("=") + ".c",
    "a." + base64.urlsafe_b64encode(b"not json").decode().rstrip("=") + ".c",
])
def test_a_malformed_id_token_is_refused_rather_than_raising(env, token):
    link_identity(env)
    attempt = start(env["client"])
    env["opener"].token_payload = {"id_token": token}
    response = env["client"].get(
        f"/login/google/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert response.status_code == 400


@pytest.mark.parametrize("payload", [
    {"error": "invalid_grant"}, {}, {"id_token": ""}, {"id_token": 42},
    {"access_token": "x"},
])
def test_an_exchange_that_yields_no_token_is_refused(env, payload):
    link_identity(env)
    attempt = start(env["client"])
    env["opener"].token_payload = payload
    response = env["client"].get(
        f"/login/google/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert response.status_code == 400
    assert env["client"].get("/api/auth/check").status_code == 401


def test_an_unverified_email_is_not_shown_as_the_address(env):
    """It is a label either way, never a key, but an unverified address is not
    worth displaying as fact."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], email_verified=False)
    assert callback(env["client"], env, attempt, token_claims=payload).status_code == 303
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_identities").fetchone()
    finally:
        con.close()
    assert row["email_shown"] is None


# ------------------------------------------------ the second factor holds

def test_a_provider_sign_in_does_not_skip_the_second_factor(env):
    """Google proving who somebody is does not prove they hold the operator's
    authenticator. The provider path lands where the password path lands."""
    con = connect()
    try:
        secret = accounts.begin_totp_enrollment(con, env["user_id"])
        accounts.confirm_totp_enrollment(
            con, env["user_id"], totp.code_at_time(secret, time.time()),
            at_time=time.time())
    finally:
        con.close()
    link_identity(env)
    attempt = start(env["client"])
    response = callback(env["client"], env, attempt)
    assert response.status_code == 303
    assert response.headers["location"].startswith("/login/2fa")
    assert env["client"].get("/api/auth/check").status_code == 401
    assert env["client"].get("/api/auth/whoami").status_code == 401


# ----------------------------------------------------------- linking

def test_a_ticket_links_the_identity_and_does_not_sign_anybody_in(env):
    con = connect()
    try:
        ticket = identities.issue_ticket(con, env["user_id"], "google")
    finally:
        con.close()
    client = env["client"]
    attempt_response = client.get(f"/login/link/{ticket}", follow_redirects=False)
    assert attempt_response.status_code == 303
    query = urllib.parse.parse_qs(
        urllib.parse.urlparse(attempt_response.headers["location"]).query)
    attempt = {"state": query["state"][0], "nonce": query["nonce"][0]}
    response = callback(client, env, attempt)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?msg=linked"
    # Linking proves a provider identity, not the operator account.
    assert client.get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert identities.find_user_id(con, "google", SUBJECT) == env["user_id"]
    finally:
        con.close()


def test_a_ticket_works_once(env):
    con = connect()
    try:
        ticket = identities.issue_ticket(con, env["user_id"], "google")
    finally:
        con.close()
    assert env["client"].get(f"/login/link/{ticket}",
                             follow_redirects=False).status_code == 303
    second = env["client"].get(f"/login/link/{ticket}", follow_redirects=False)
    assert second.status_code == 400
    assert "used already" in second.text


@pytest.mark.parametrize("ticket", ["made-up", "whp_link_nope", "whp_link_", ""])
def test_an_unknown_ticket_is_refused(env, ticket):
    """An empty one answers 307 to the collection path rather than 400, which is
    Starlette's redirect_slashes and is still no way in. What matters is that
    nothing is linked and nobody is signed in."""
    response = env["client"].get(f"/login/link/{ticket}", follow_redirects=False)
    assert response.status_code in (307, 400, 404)
    assert env["client"].get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert con.execute("SELECT COUNT(*) c FROM oidc_identities").fetchone()["c"] == 0
    finally:
        con.close()


def test_an_expired_ticket_is_refused(env, monkeypatch):
    con = connect()
    try:
        ticket = identities.issue_ticket(con, env["user_id"], "google")
    finally:
        con.close()
    later = identities.now_utc() + identities.TICKET_TTL + identities.timedelta(seconds=1)
    monkeypatch.setattr(identities, "now_utc", lambda: later)
    assert env["client"].get(f"/login/link/{ticket}",
                             follow_redirects=False).status_code == 400


def test_linking_refuses_to_take_an_identity_from_another_account(env):
    con = connect()
    try:
        other = accounts.create_user(con, "someone@example.com", PASSWORD)
        identities.link(con, "google", SUBJECT, other)
        with pytest.raises(identities.LinkError):
            identities.link(con, "google", SUBJECT, env["user_id"])
        assert identities.find_user_id(con, "google", SUBJECT) == other
    finally:
        con.close()


def test_an_account_holds_one_identity_per_provider(env):
    con = connect()
    try:
        identities.link(con, "google", SUBJECT, env["user_id"])
        with pytest.raises(identities.LinkError):
            identities.link(con, "google", "a-second-google-account", env["user_id"])
    finally:
        con.close()


def test_linking_the_same_identity_again_is_not_an_error(env):
    con = connect()
    try:
        identities.link(con, "google", SUBJECT, env["user_id"])
        identities.link(con, "google", SUBJECT, env["user_id"])
        assert len(identities.for_user(con, env["user_id"])) == 1
    finally:
        con.close()


def test_unlinking_stops_the_sign_in(env):
    link_identity(env)
    con = connect()
    try:
        assert identities.unlink(con, "google", env["user_id"]) is True
        assert identities.unlink(con, "google", env["user_id"]) is False
    finally:
        con.close()
    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 403


def test_tickets_and_flows_are_stored_as_hashes(env):
    con = connect()
    try:
        ticket = identities.issue_ticket(con, env["user_id"], "google")
        row = con.execute("SELECT * FROM oidc_link_tickets").fetchone()
    finally:
        con.close()
    assert row["token_hash"] != ticket
    assert ticket not in json.dumps(dict(row))


def test_expired_flows_and_tickets_are_swept(env, monkeypatch):
    con = connect()
    try:
        identities.issue_ticket(con, env["user_id"], "google")
        identities.start_flow(con, "google", "s", "n", "v", "b", "/")
        later = identities.now_utc() + identities.TICKET_TTL + identities.timedelta(days=1)
        identities.purge_expired(con, now=later)
        assert con.execute("SELECT COUNT(*) c FROM oidc_flows").fetchone()["c"] == 0
        assert con.execute("SELECT COUNT(*) c FROM oidc_link_tickets").fetchone()["c"] == 0
    finally:
        con.close()


def test_init_is_idempotent(env):
    con = connect()
    try:
        identities.init(con)
        identities.init(con)
    finally:
        con.close()


# ------------------------------------------------- signing up with a provider
#
# The owner, 2026-08-23, asked for a normal register and login page. An
# identity nobody has seen used to be
# refused until a single-use URL minted on the box connected it. Now it signs
# up, which is what every other site does.
#
# The rule that did NOT move is the one above: an email address never merges two
# accounts. `test_a_matching_email_address_is_not_a_link` is the test for that
# and it passed unchanged across this behaviour change, which is the point.

NEW_SUBJECT = "999-somebody-new"
NEW_EMAIL = "stranger@example.com"


def new_person_claims(nonce):
    return claims(nonce, sub=NEW_SUBJECT, email=NEW_EMAIL, email_verified=True)


def test_an_unknown_identity_signs_up_and_gets_its_own_workspace(env):
    """The whole point of the change. No ticket, no CLI, no operator."""
    client = env["client"]
    attempt = start(client)
    response = callback(client, env, attempt,
                        token_claims=new_person_claims(attempt["nonce"]))
    assert response.status_code == 303
    assert client.get("/api/auth/check").status_code == 204
    assert client.get("/api/auth/whoami").json() == {"email": NEW_EMAIL}

    con = connect()
    try:
        newcomer = accounts.get_user_by_email(con, NEW_EMAIL)
        existing = accounts.get_user_by_email(con, EMAIL)
        assert newcomer is not None
        # Their own workspace, and emphatically not the one the fleet is in.
        assert newcomer["workspace_id"] != db.DEFAULT_WORKSPACE_ID
        assert newcomer["workspace_id"] != existing["workspace_id"]
        assert identities.find_user_id(con, "google", NEW_SUBJECT) == newcomer["id"]
    finally:
        con.close()


def test_signing_up_twice_with_the_same_identity_is_one_account(env):
    """The second visit is a sign-in, not a second signup."""
    first = env["client"]
    attempt = start(first)
    callback(first, env, attempt, token_claims=new_person_claims(attempt["nonce"]))

    second = TestClient(ingest.app)
    attempt2 = start(second)
    assert callback(second, env, attempt2,
                    token_claims=new_person_claims(attempt2["nonce"])).status_code == 303
    con = connect()
    try:
        assert len(accounts.list_users(con)) == 2, "the fixture user, plus one"
        rows = con.execute("SELECT COUNT(*) AS n FROM workspaces").fetchone()
        assert rows["n"] == 2, "one workspace for the fleet, one for the newcomer"
    finally:
        con.close()


def test_a_new_account_from_a_provider_sees_nothing_of_the_existing_fleet(env):
    con = connect()
    try:
        store.add_host(con, "robins-box")
    finally:
        con.close()
    client = env["client"]
    attempt = start(client)
    callback(client, env, attempt, token_claims=new_person_claims(attempt["nonce"]))
    con = connect()
    try:
        newcomer = accounts.get_user_by_email(con, NEW_EMAIL)
        assert store.list_hosts(con, workspace_id=newcomer["workspace_id"]) == []
        assert len(store.list_hosts(con, workspace_id=db.DEFAULT_WORKSPACE_ID)) == 1
    finally:
        con.close()


def test_an_address_that_already_has_an_account_is_refused_rather_than_merged(env):
    """**The security property, and it is the one that must never regress.**
    Attaching by address is the account-takeover pattern Microsoft published an
    advisory about, and here it would hand over a whole workspace rather than an
    empty one. The person is told to sign in with their password instead."""
    client = env["client"]
    attempt = start(client)
    payload = claims(attempt["nonce"], sub="a-different-google-user", email=EMAIL,
                     email_verified=True)
    response = callback(client, env, attempt, token_claims=payload)
    assert response.status_code == 403
    assert "already exists" in response.text
    assert client.get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert identities.find_user_id(con, "google", "a-different-google-user") is None
        assert len(accounts.list_users(con)) == 1
    finally:
        con.close()


def test_a_callback_refused_while_closed_says_it_once_in_the_banner(env, monkeypatch):
    """What the owner hit on 2026-08-23, arriving back from Google with signups
    closed: the page said accounts were closed twice, once as the permanent
    banner and once as an error with a fail chip. The words are
    signup.CLOSED_NOTICE both times, one string on purpose, so the page now
    collapses the repeat and the banner says it once. Nothing is created."""
    monkeypatch.setenv(signup.MODE_ENV, "closed")
    client = env["client"]
    attempt = start(client)
    response = callback(client, env, attempt,
                        token_claims=new_person_claims(attempt["nonce"]))
    assert response.status_code == 403
    body = response.text.split("</style>")[-1]
    assert body.count(signup.CLOSED_NOTICE) == 1
    assert 'class="msg closed"' in body
    assert 'class="msg fail"' not in body
    assert client.get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert accounts.get_user_by_email(con, NEW_EMAIL) is None
        assert identities.find_user_id(con, "google", NEW_SUBJECT) is None
    finally:
        con.close()


def test_a_callback_refusal_that_is_not_the_banner_keeps_the_error_treatment(env, monkeypatch):
    """Forgery, a provider failure and every other refusal still read as
    errors. Only the line that repeats the banner collapses into it. This one
    arrives while closed with an address that already has an account, which is
    refused in different words, so the fail treatment stays."""
    monkeypatch.setenv(signup.MODE_ENV, "closed")
    monkeypatch.setenv(signup.ALLOW_ENV, EMAIL)
    client = env["client"]
    attempt = start(client)
    payload = claims(attempt["nonce"], sub="a-different-google-user", email=EMAIL,
                     email_verified=True)
    response = callback(client, env, attempt, token_claims=payload)
    assert response.status_code == 403
    body = response.text.split("</style>")[-1]
    assert 'class="msg fail"' in body
    assert "already exists" in body
    assert 'class="msg closed"' in body, "the banner stays up beside the error"


def test_a_provider_that_shares_no_address_creates_nothing(env):
    """There would be nothing to name the account with, and a made-up
    placeholder is a login nobody could ever sign into again."""
    client = env["client"]
    attempt = start(client)
    payload = claims(attempt["nonce"], sub=NEW_SUBJECT, email=None,
                     email_verified=False)
    response = callback(client, env, attempt, token_claims=payload)
    assert response.status_code == 403
    con = connect()
    try:
        assert len(accounts.list_users(con)) == 1
        assert con.execute("SELECT COUNT(*) AS n FROM workspaces").fetchone()["n"] == 1
    finally:
        con.close()


def test_the_account_a_provider_creates_has_no_guessable_password(env):
    """It is created with a random one nobody is ever shown. The way in is the
    provider, and `users_cli passwd` is how it gains a password if wanted."""
    client = env["client"]
    attempt = start(client)
    callback(client, env, attempt, token_claims=new_person_claims(attempt["nonce"]))
    con = connect()
    try:
        for guess in ("", NEW_EMAIL, "password", "correct-horse-battery-9"):
            assert accounts.authenticate(con, NEW_EMAIL, guess) is None
    finally:
        con.close()
