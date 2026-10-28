"""Sign in with Microsoft, and what a Microsoft token is allowed to mean.

    python -m pytest tests/test_oidc_microsoft.py

No network. A fake opener answers the metadata and token endpoints, so every one
of these runs the real `app/oidc.py` path and only the socket is replaced.

These are the review, for the reason `tests/test_oidc_google.py` gives. The
Microsoft-specific ones, in the order a reviewer should read them:

  - an identity nobody linked signs nobody in, including when the address in the
    token is exactly an existing account's,
  - the key is the pair `(tid, oid)`, so the same object id in another tenant is
    another person and signs nobody in,
  - `sub` is not the key here, so a token whose `sub` matches an identity signs
    nobody in,
  - the issuer check substitutes the token's own tenant into the template the
    metadata carries, so the raw template is refused, an issuer naming a tenant
    that is not the token's is refused, and
    `login.microsoftonline.com.evil.example` is refused,
  - a tenant that is not a GUID is refused before it can become half of a key,
  - with a tenant GUID as the authority, a token from any other tenant is
    refused,
  - with no authority configured there is no button and no route,
  - and a Microsoft sign-in lands where a password lands, in front of the
    second factor.
"""

import base64
import json
import time
import urllib.parse

import pytest
from fastapi.testclient import TestClient

from app import (accounts, db, identities, ingest, oidc, oidc_google,
                 oidc_microsoft, ratelimit, totp, web_auth)

EMAIL = "sysadmin@example.com"
PASSWORD = "correct-horse-battery-9"

# An Entra application id is a GUID. The one in the token's `aud`.
CLIENT_ID = "11112222-3333-4444-5555-666677778888"

TENANT = "aaaabbbb-0000-cccc-1111-dddd2222eeee"
OTHER_TENANT = "bbbbcccc-1111-dddd-2222-eeee3333ffff"
OID = "00aa00aa-bb11-cc22-dd33-44ee44ee44ee"

# Microsoft's `sub` is pairwise, scoped to one application id. It is in every
# token here and it is never the key, which several tests below are about.
PAIRWISE_SUB = "kaXqBQR2vaMjJDlLZRHRlPFCLCwT9-bLTvBbHVFvOKM"

# What `subject_of` builds out of the pair, which is what `identities` stores.
SUBJECT = f"{TENANT}:{OID}"

BASE = "https://app.whichports.example"

GOOGLE_CLIENT_ID = "1234.apps.googleusercontent.com"
GOOGLE_SUBJECT = "108054000000000000000"

# **The issuer a multi-tenant metadata document carries, verbatim.** Braces
# included, because it is a template and not a URL. Read from
# `https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration`
# and from the `organizations` document on 2026-08-22.
TEMPLATE_ISSUER = "https://login.microsoftonline.com/{tenantid}/v2.0"


def issuer_for(tenant):
    """The issuer a v2.0 token from this tenant carries."""
    return f"https://login.microsoftonline.com/{tenant}/v2.0"


def discovery_document(authority="organizations", issuer=TEMPLATE_ISSUER):
    root = f"https://login.microsoftonline.com/{authority}"
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{root}/oauth2/v2.0/authorize",
        "token_endpoint": f"{root}/oauth2/v2.0/token",
        "jwks_uri": f"{root}/discovery/v2.0/keys",
    }


DISCOVERY = discovery_document()

GOOGLE_DISCOVERY = {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
    "token_endpoint": "https://oauth2.googleapis.com/token",
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
    """Answers the metadata and token endpoints and refuses anything else.

    The Microsoft metadata address is asked for at the time of the call rather
    than remembered, because the authority is in it and a test may change the
    authority. Google's is answered too, so the one test that starts a Google
    flow beside a Microsoft one needs no second opener.
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
            if url == oidc_microsoft.discovery_url():
                return _Body(self.discovery)
            if url == oidc_google.DISCOVERY_URL:
                return _Body(GOOGLE_DISCOVERY)
            raise AssertionError(f"unexpected GET {url}")
        body = dict(urllib.parse.parse_qsl(request.data.decode("utf-8")))
        self.posts.append((url, body))
        payload = self.token_payload(body) if callable(self.token_payload) \
            else self.token_payload
        return _Body(payload)


def id_token(claim_set):
    """A JWT with a real header and payload and a signature that is nonsense.

    Deliberate, and asserted on below: this build does not verify the signature,
    under the carve-out documented on `oidc.claims_from_id_token`.
    """
    def seg(obj):
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{seg({'alg': 'RS256', 'kid': 'x'})}.{seg(claim_set)}.bm90LWEtc2ln"


def claims(bound_nonce, **overrides):
    """A v2.0 ID token's claims.

    `iss` follows `tid` unless a test names it, because in a real token the two
    agree and the interesting cases are the ones where they do not.
    """
    base = {
        "aud": CLIENT_ID,
        "sub": PAIRWISE_SUB,
        "oid": OID,
        "tid": TENANT,
        "exp": time.time() + 300,
        "iat": time.time(),
        "nonce": bound_nonce,
        "email": EMAIL,
        "preferred_username": EMAIL,
        "name": "Robin Sample",
        "ver": "2.0",
    }
    base.update(overrides)
    if "iss" not in overrides:
        tenant = base.get("tid")
        base["iss"] = issuer_for(tenant) if isinstance(tenant, str) else None
    return base


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """A configured Microsoft, and a configured Google beside it, because two
    providers on one server is the state this branch creates."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    monkeypatch.setenv("WHICHPORTS_SIGNUP", "open")
    monkeypatch.setenv("WHICHPORTS_MICROSOFT_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("WHICHPORTS_MICROSOFT_CLIENT_SECRET", "a-secret")
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, "organizations")
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID)
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_SECRET", "a-google-secret")
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


def start(client, path="/login/microsoft?next=/"):
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
    return client.get(
        f"/login/microsoft/callback?code={code}&state={attempt['state']}",
        follow_redirects=False)


def link_identity(env, subject=SUBJECT, user_id=None, provider="microsoft"):
    con = connect()
    try:
        identities.link(con, provider, subject, user_id or env["user_id"])
    finally:
        con.close()


# ------------------------------------------------------ the authority

def test_the_login_page_offers_microsoft_when_it_is_configured(env):
    page = env["client"].get("/login")
    assert 'href="/login/microsoft?next=%2F"' in page.text
    assert "Microsoft" in page.text


def test_no_authority_means_no_button_and_no_route(env, monkeypatch):
    """**The authority is a decision nobody has taken yet**, and this file must
    not take it by defaulting to one. Unset, the provider is not ready, so the
    login page shows no Microsoft button and the route answers 404 rather than
    an explanation."""
    monkeypatch.delenv(oidc_microsoft.AUTHORITY_ENV)
    assert oidc_microsoft.authority() is None
    assert oidc_microsoft.discovery_url() is None
    assert not oidc.is_ready(oidc_microsoft.PROVIDER)
    page = env["client"].get("/login")
    assert "/login/microsoft" not in page.text
    assert env["client"].get("/login/microsoft",
                             follow_redirects=False).status_code == 404
    assert env["client"].get("/login/microsoft/callback?code=c&state=s",
                             follow_redirects=False).status_code == 404


@pytest.mark.parametrize("value", [
    "", "   ", "consumers", "Common", "common/../consumers", "contoso.com",
    "https://login.microsoftonline.com/common", "aaaabbbb", "*",
    "aaaabbbb-0000-cccc-1111-dddd2222eeee/../common",
    "aaaabbbb-0000-cccc-1111-dddd2222eeee organizations",
])
def test_an_authority_this_build_does_not_know_is_the_same_as_none(env, monkeypatch,
                                                                  value):
    """A typo must not build a URL nobody chose, so anything that is not one of
    the three accepted values reads as unset. `consumers` is a real Microsoft
    authority and is deliberately not one of them."""
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, value)
    assert oidc_microsoft.authority() is None
    assert not oidc.is_ready(oidc_microsoft.PROVIDER)
    assert env["client"].get("/login/microsoft",
                             follow_redirects=False).status_code == 404


def test_whitespace_around_the_authority_is_stripped(env, monkeypatch):
    """A value pasted into a unit file arrives with a stray space sooner or
    later, and that is a different thing from a value nobody recognises."""
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, f"  {TENANT} ")
    assert oidc_microsoft.authority() == TENANT
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, " organizations\n")
    assert oidc_microsoft.authority() == "organizations"


@pytest.mark.parametrize("value", ["common", "organizations", TENANT])
def test_the_metadata_address_carries_the_configured_authority(env, monkeypatch,
                                                               value):
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, value)
    assert oidc_microsoft.discovery_url() == (
        f"https://login.microsoftonline.com/{value}"
        f"/v2.0/.well-known/openid-configuration")
    assert oidc.is_ready(oidc_microsoft.PROVIDER)


def test_the_authority_is_read_when_it_is_used_and_not_at_import(env, monkeypatch):
    """Otherwise the unit file's environment at import time would decide, and a
    test could not change it either."""
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, "common")
    assert "common" in oidc_microsoft.PROVIDER.metadata_url()
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, "organizations")
    assert "organizations" in oidc_microsoft.PROVIDER.metadata_url()


def test_a_client_id_without_a_secret_is_not_configured(env, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_MICROSOFT_CLIENT_SECRET", "   ")
    assert not oidc.is_ready(oidc_microsoft.PROVIDER)


def test_without_a_base_url_there_is_no_provider_sign_in(env, monkeypatch):
    monkeypatch.delenv(oidc.BASE_URL_ENV)
    assert not oidc.is_ready(oidc_microsoft.PROVIDER)
    assert env["client"].get("/login/microsoft",
                             follow_redirects=False).status_code == 404


def test_discovery_refuses_when_there_is_no_authority(env, monkeypatch):
    monkeypatch.delenv(oidc_microsoft.AUTHORITY_ENV)
    with pytest.raises(oidc.OIDCError):
        oidc.discovery(oidc_microsoft.PROVIDER, opener=env["opener"])
    assert env["opener"].gets == []


# ------------------------------------------------------ starting the flow

def test_the_authorization_request_carries_what_the_spec_needs(env):
    query = start(env["client"])["query"]
    assert query["client_id"] == [CLIENT_ID]
    assert query["response_type"] == ["code"]
    # `profile` is not optional here: Microsoft says `oid` and
    # `preferred_username` need it, and `oid` is half the account key.
    assert query["scope"] == ["openid profile email"]
    assert query["redirect_uri"] == [f"{BASE}/login/microsoft/callback"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["state"][0]) >= 32
    assert len(query["nonce"][0]) >= 32
    assert len(query["code_challenge"][0]) == 43


def test_a_nonce_is_sent_even_though_the_code_flow_table_does_not_list_one(env):
    """Microsoft does not mark `nonce` required for the plain code flow, and it
    documents that the claim echoes the request and that a mismatch means
    reject. So it is sent on every request and checked on every token."""
    assert "nonce" in start(env["client"])["query"]


def test_the_endpoints_come_from_discovery_and_not_from_this_codebase(env):
    attempt = start(env["client"])
    assert attempt["response"].headers["location"].startswith(
        DISCOVERY["authorization_endpoint"] + "?")
    assert env["opener"].gets == [oidc_microsoft.discovery_url()]


def test_the_discovery_document_is_cached_across_sign_ins(env):
    start(env["client"])
    start(TestClient(ingest.app))
    assert env["opener"].gets.count(oidc_microsoft.discovery_url()) == 1


def test_changing_the_authority_reads_the_other_document(env, monkeypatch):
    """The cache is keyed on the address rather than on the provider name. Keyed
    on the name, a server moved from one authority to another would go on being
    answered from the document it read for the old one."""
    start(env["client"])
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, "common")
    env["opener"].discovery = discovery_document(authority="common")
    start(TestClient(ingest.app))
    assert len(env["opener"].gets) == 2
    assert env["opener"].gets[0] != env["opener"].gets[1]


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
        oidc.discovery(oidc_microsoft.PROVIDER, opener=env["opener"])


def test_the_flow_is_remembered_server_side_and_the_browser_gets_only_a_binding(env):
    attempt = start(env["client"])
    cookie = env["client"].cookies.get(web_auth.FLOW_COOKIE)
    assert cookie and len(cookie) >= 32
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_flows").fetchone()
    finally:
        con.close()
    assert row["provider"] == "microsoft"
    assert row["state_hash"] != attempt["state"]
    assert row["binding_hash"] != cookie
    assert row["nonce"] == attempt["nonce"]


def test_the_verifier_is_sent_at_the_exchange_and_matches_the_challenge(env):
    link_identity(env)
    attempt = start(env["client"])
    challenge = attempt["query"]["code_challenge"][0]
    callback(env["client"], env, attempt)
    _, body = env["opener"].posts[0]
    assert oidc.challenge_of(body["code_verifier"]) == challenge


def test_the_exchange_posts_the_secret_to_the_discovered_token_endpoint(env):
    """Form encoded, which is what Microsoft asks for by name because an Entra
    secret contains punctuation that has to be percent encoded."""
    link_identity(env)
    attempt = start(env["client"])
    callback(env["client"], env, attempt)
    url, body = env["opener"].posts[0]
    assert url == DISCOVERY["token_endpoint"]
    assert body["client_secret"] == "a-secret"
    assert body["grant_type"] == "authorization_code"
    assert body["redirect_uri"] == f"{BASE}/login/microsoft/callback"


# ------------------------------------------------- the key is (tid, oid)

def test_the_subject_is_the_tenant_and_the_object_id_joined():
    """Microsoft: "use the immutable claim values tid and oid as a combined key
    for application data and determining whether a user should be granted
    access", and "the tid claim must be part of the key used to access the
    user's data"."""
    assert oidc_microsoft.subject_of(
        {"tid": TENANT, "oid": OID, "sub": PAIRWISE_SUB}) == f"{TENANT}:{OID}"


def test_the_subject_is_not_sub_and_not_an_address():
    key = oidc_microsoft.subject_of(
        {"tid": TENANT, "oid": OID, "sub": PAIRWISE_SUB, "email": EMAIL,
         "preferred_username": EMAIL})
    assert PAIRWISE_SUB not in key
    assert EMAIL not in key


def test_the_two_halves_of_the_key_cannot_be_read_two_ways():
    """A GUID is hexadecimal and hyphens, so neither half can hold the colon
    that joins them, so one string is one pair."""
    key = oidc_microsoft.subject_of({"tid": TENANT, "oid": OID})
    assert key.count(":") == 1
    assert key.split(":") == [TENANT, OID]


def test_the_key_is_lowercased_so_one_user_is_one_key():
    upper = oidc_microsoft.subject_of({"tid": TENANT.upper(), "oid": OID.upper()})
    assert upper == oidc_microsoft.subject_of({"tid": TENANT, "oid": OID})


@pytest.mark.parametrize("claim_set", [
    {"oid": OID},
    {"tid": TENANT},
    {},
    {"tid": TENANT, "oid": ""},
    {"tid": "", "oid": OID},
    {"tid": TENANT, "oid": "not-a-guid"},
    {"tid": "not-a-guid", "oid": OID},
    {"tid": TENANT, "oid": None},
    {"tid": None, "oid": OID},
    {"tid": TENANT, "oid": 42},
    {"tid": [TENANT], "oid": OID},
    {"tid": TENANT, "oid": OID + "-extra"},
    {"tid": TENANT, "oid": f"prefix{OID}"},
    {"sub": PAIRWISE_SUB, "email": EMAIL},
])
def test_a_pair_that_is_not_two_guids_is_refused(claim_set):
    """Refused rather than made into a key out of whatever arrived. `sub` and an
    address are in the last case on purpose: neither one stands in."""
    with pytest.raises(oidc.OIDCError):
        oidc_microsoft.subject_of(claim_set)


@pytest.mark.parametrize("value, ok", [
    (TENANT, True),
    (TENANT.upper(), True),
    ("9188040d-6c67-4c5b-b112-36a304b66dad", True),
    ("aaaabbbb-0000-cccc-1111-dddd2222eee", False),
    ("aaaabbbb-0000-cccc-1111-dddd2222eeeee", False),
    ("aaaabbbb00000cccc1111dddd2222eeee", False),
    ("gggghhhh-0000-cccc-1111-dddd2222eeee", False),
    (f" {TENANT}", False),
    (f"{TENANT} ", False),
    (f"{TENANT}\n", False),
    ("", False),
    (None, False),
    (42, False),
])
def test_what_counts_as_a_guid(value, ok):
    assert oidc_microsoft.is_guid(value) is ok


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
    """Every token in this file carries a nonsense signature, which is asserted
    on purpose. Microsoft says a web app has no need to validate a token it got
    from the token endpoint itself, and lists the hybrid flow, where the token
    arrives through the browser, as the case that must. This is not that flow,
    and the day it becomes that flow the reasoning on
    `oidc.claims_from_id_token` is wrong rather than quietly stale."""
    link_identity(env)
    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 303


def test_an_unlinked_identity_signs_nobody_in(env):
    attempt = start(env["client"])
    response = callback(env["client"], env, attempt)
    assert response.status_code == 403
    assert "did not work" in response.text or "already exists" in response.text
    assert env["client"].get("/api/auth/check").status_code == 401


def test_a_matching_email_address_is_not_a_link(env):
    """The single most important test in this file.

    The token's `email` and `preferred_username` are exactly the address of an
    existing, enabled account, and it still signs nobody in. Microsoft's own
    words on `email`: "This value isn't guaranteed to be correct and is mutable
    over time. Never use it for authorization or to save data for a user." The
    mechanism is in the warning beside it, that these claims "can be
    controllable by tenant administrators or sometimes users", and anybody can
    create a tenant.
    """
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], email=EMAIL, preferred_username=EMAIL)
    response = callback(env["client"], env, attempt, token_claims=payload)
    assert response.status_code == 403
    assert env["client"].get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert con.execute(
            "SELECT COUNT(*) c FROM oidc_identities").fetchone()["c"] == 0
    finally:
        con.close()


def test_the_same_object_id_in_another_tenant_is_another_person(env):
    """**The reason the tenant is half the key.** Microsoft: a user in two
    tenants "contains a different object ID in each tenant", and its example
    spells out that the same subject under two issuers describes two different
    users, "because claims like sub are interpreted within the context of the
    issuer/tenant". A guest, in Microsoft's words, should be treated "as if
    they're a brand new user to the service".

    This token is entirely valid. It is signed for the same person's object id,
    it passes every check, and it is not the linked account.
    """
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], tid=OTHER_TENANT)
    response = callback(env["client"], env, attempt, token_claims=payload)
    assert response.status_code == 403
    assert env["client"].get("/api/auth/check").status_code == 401


def test_the_same_tenant_with_another_object_id_is_another_person(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], oid="99999999-8888-7777-6666-555544443333")
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 403


def test_a_matching_sub_is_not_a_way_in(env):
    """`sub` is pairwise and is not the key here. An identity linked under the
    raw `sub` string is not what this token unlocks, whatever `sub` says."""
    link_identity(env, subject=PAIRWISE_SUB)
    attempt = start(env["client"])
    response = callback(env["client"], env, attempt)
    assert response.status_code == 403
    assert env["client"].get("/api/auth/check").status_code == 401


def test_a_token_whose_sub_matches_but_whose_pair_does_not_is_refused(env):
    """Both at once: the identity is linked under the pair, and the token
    carries the same `sub` with a different tenant and object id."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], tid=OTHER_TENANT,
                     oid="99999999-8888-7777-6666-555544443333",
                     sub=PAIRWISE_SUB)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 403


def test_another_sub_on_the_same_pair_still_signs_in(env):
    """The other half of the same point. `sub` decides nothing here, so a token
    whose `sub` changed is still the same account."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], sub="a-completely-different-subject")
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 303


def test_the_stored_subject_is_the_pair_and_not_anything_else(env):
    link_identity(env)
    attempt = start(env["client"])
    callback(env["client"], env, attempt)
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_identities").fetchone()
    finally:
        con.close()
    assert row["subject"] == SUBJECT
    assert row["provider"] == "microsoft"


def test_a_tenant_in_upper_case_is_the_same_account(env):
    """Microsoft's own published issuer comparison is case-invariant, so a case
    difference must not mint a second identity."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], tid=TENANT.upper(), oid=OID.upper(),
                     iss=issuer_for(TENANT.upper()))
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 303


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


# ------------------------------------------------------------ the issuer

def test_the_template_in_the_metadata_is_filled_in_with_the_tokens_tenant(env):
    """The metadata says `https://login.microsoftonline.com/{tenantid}/v2.0`,
    braces and all. Microsoft: "the application should replace the {tenantid}
    value in the issuer metadata with the tenant id that is the target of the
    current request, and then check the exact match"."""
    assert DISCOVERY["issuer"] == TEMPLATE_ISSUER
    assert oidc_microsoft.TENANT_PLACEHOLDER in DISCOVERY["issuer"]
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], iss=issuer_for(TENANT))
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 303


def test_the_raw_template_as_an_issuer_is_refused(env):
    """A naive equality check against the metadata would accept this and nothing
    else, which is the failure that never signs anybody in. This is the other
    direction: it must not be accepted either."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], iss=TEMPLATE_ISSUER)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


def test_an_issuer_naming_a_tenant_that_is_not_the_tokens_is_refused(env):
    """Microsoft: "Validate that the tid claim is a GUID and the iss claim is of
    the form https://login.microsoftonline.com/{tid}/v2.0 where {tid} is the
    exact tid claim. This validation ties the tenant back to the issuer"."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], iss=issuer_for(OTHER_TENANT))
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


@pytest.mark.parametrize("issuer", [
    f"https://login.microsoftonline.com.evil.example/{TENANT}/v2.0",
    f"https://login.microsoftonline.com.evil.example/{TENANT}/v2.0/",
    f"https://evil.example/login.microsoftonline.com/{TENANT}/v2.0",
    f"https://login.microsoftonline.com@evil.example/{TENANT}/v2.0",
    f"https://login.microsoftonline.com/{TENANT}/v2.0/../{OTHER_TENANT}/v2.0",
    f"http://login.microsoftonline.com/{TENANT}/v2.0",
    f"https://login.microsoftonline.com/{TENANT}/v2.0/",
    f"https://login.microsoftonline.com/{TENANT}",
    f"https://sts.windows.net/{TENANT}/",
    f"https://login.microsoftonline.com/common/v2.0",
    "https://login.microsoftonline.com//v2.0",
    "", None, 42, [],
])
def test_any_other_issuer_is_refused(env, issuer):
    """Every one of these passes a "does it mention login.microsoftonline.com"
    test, which is why that test is not the one being run. The comparison is
    exact, against the metadata with the token's own tenant substituted in.

    `https://sts.windows.net/{tid}/` is in the list because it is the v1.0 shape
    and this is a v2.0 integration.
    """
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], iss=issuer)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


@pytest.mark.parametrize("tenant", [
    "not-a-guid", "common", "organizations", "", None, 42,
    "aaaabbbb-0000-cccc-1111-dddd2222eee",
    f"{TENANT} ", f" {TENANT}",
])
def test_a_tenant_that_is_not_a_guid_is_refused(env, tenant):
    """Microsoft asks for the GUID check by name, and the reason is that the
    tenant becomes half of the key an account is found by. The issuer is built
    from the same value here, so this is the case where everything agrees and
    the tenant is still not a tenant."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], tid=tenant)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


def test_a_metadata_document_with_an_issuer_we_cannot_use_refuses_everything(env):
    """`oidc.discovery` refuses a document with no usable issuer before this can
    happen, and the hook says no on its own besides."""
    for document in ({}, {"issuer": ""}, {"issuer": 42}, {"issuer": None}):
        assert oidc_microsoft.issuer_ok(
            {"tid": TENANT, "iss": issuer_for(TENANT)}, document) is False


def test_the_issuer_hook_answers_yes_only_for_the_substituted_form(env):
    document = {"issuer": TEMPLATE_ISSUER}
    assert oidc_microsoft.issuer_ok(
        {"tid": TENANT, "iss": issuer_for(TENANT)}, document) is True
    assert oidc_microsoft.issuer_ok(
        {"tid": TENANT, "iss": TEMPLATE_ISSUER}, document) is False
    assert oidc_microsoft.issuer_ok(
        {"tid": TENANT, "iss": issuer_for(OTHER_TENANT)}, document) is False
    assert oidc_microsoft.issuer_ok({"tid": TENANT}, document) is False
    assert oidc_microsoft.issuer_ok({"iss": issuer_for(TENANT)}, document) is False


def test_google_keeps_its_fixed_allow_list(env):
    """The seam that let Microsoft answer for itself must not have changed what
    Google does. Google publishes two exact strings and accepts nothing else."""
    assert oidc_google.PROVIDER.issuer_ok is None
    assert oidc_google.PROVIDER.issuers == (
        "https://accounts.google.com", "accounts.google.com")
    for issuer in oidc_google.PROVIDER.issuers:
        oidc.check_issuer(oidc_google.PROVIDER, {"iss": issuer})
    for issuer in ("https://accounts.google.com.evil.example", "", None,
                   issuer_for(TENANT)):
        with pytest.raises(oidc.OIDCError):
            oidc.check_issuer(oidc_google.PROVIDER, {"iss": issuer})


# ------------------------------------------- a tenant GUID as the authority

@pytest.fixture()
def single_tenant(env, monkeypatch):
    """One organisation, which is the only authority that restricts anything at
    the provider. The metadata for one tenant is expected to name that tenant
    in its issuer rather than carry the template, which is what this document
    does."""
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, TENANT)
    env["opener"].discovery = discovery_document(
        authority=TENANT, issuer=issuer_for(TENANT))
    return env


def test_with_a_tenant_authority_that_tenant_signs_in(single_tenant):
    env = single_tenant
    link_identity(env)
    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 303


def test_with_a_tenant_authority_another_tenant_is_refused(single_tenant):
    env = single_tenant
    link_identity(env, subject=f"{OTHER_TENANT}:{OID}")
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], tid=OTHER_TENANT)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


def test_the_tenant_authority_is_checked_even_when_the_metadata_is_templated(env,
                                                                            monkeypatch):
    """**This is the check that does not rely on an assumption.** The single
    tenant metadata was never read against a real tenant, so it was never
    confirmed that it carries a concrete issuer rather than the template. If it
    turns out to carry the template, the substitution alone would accept a token
    from any tenant, and this is what stops that."""
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, TENANT)
    env["opener"].discovery = discovery_document(authority=TENANT)
    link_identity(env, subject=f"{OTHER_TENANT}:{OID}")
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], tid=OTHER_TENANT)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400
    assert oidc_microsoft.issuer_ok(
        {"tid": OTHER_TENANT, "iss": issuer_for(OTHER_TENANT)},
        {"issuer": TEMPLATE_ISSUER}) is False


def test_a_tenant_authority_in_the_other_case_still_matches(env, monkeypatch):
    monkeypatch.setenv(oidc_microsoft.AUTHORITY_ENV, TENANT.upper())
    assert oidc_microsoft.authority() == TENANT.upper()
    assert oidc_microsoft.issuer_ok(
        {"tid": TENANT, "iss": issuer_for(TENANT)},
        {"issuer": TEMPLATE_ISSUER}) is True


def test_a_word_authority_does_not_restrict_the_tenant(env):
    """`organizations` is any tenant, which is what Microsoft says it is. The
    tenant check is only for a GUID authority, and this says so rather than
    leaving it to be inferred from a passing sign-in."""
    assert oidc_microsoft.authority() == "organizations"
    assert oidc_microsoft.issuer_ok(
        {"tid": OTHER_TENANT, "iss": issuer_for(OTHER_TENANT)},
        {"issuer": TEMPLATE_ISSUER}) is True


# ------------------------------------------------- state, replay and CSRF

def test_a_callback_in_another_browser_is_refused(env):
    """Login CSRF. An attacker starts a flow, gets a callback URL carrying their
    own code and state, and tricks the victim into visiting it. Without the
    binding cookie the victim ends up signed in as the attacker."""
    link_identity(env)
    attempt = start(env["client"])
    victim = TestClient(ingest.app)
    env["opener"].token_payload = {"id_token": id_token(claims(attempt["nonce"]))}
    response = victim.get(
        f"/login/microsoft/callback?code=c&state={attempt['state']}",
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
    link_identity(env)
    attempt = start(env["client"])
    TestClient(ingest.app).get(
        f"/login/microsoft/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert callback(env["client"], env, attempt).status_code == 400


def test_an_unknown_state_is_refused(env):
    env["client"].get("/login/microsoft", follow_redirects=False)
    response = env["client"].get(
        "/login/microsoft/callback?code=c&state=made-up", follow_redirects=False)
    assert response.status_code == 400


def test_a_state_minted_for_google_is_not_an_answer_here(env):
    """The provider is part of the lookup, so an attempt started at one provider
    cannot be finished at another's callback."""
    link_identity(env)
    attempt = start(env["client"], path="/login/google?next=/")
    response = env["client"].get(
        f"/login/microsoft/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert response.status_code == 400
    assert env["client"].get("/api/auth/check").status_code == 401


@pytest.mark.parametrize("query", [
    "?code=c", "?state=s", "", "?error=access_denied&state=s",
    "?code=&state=", "?error=access_denied",
])
def test_a_callback_that_is_not_an_answer_is_refused(env, query):
    response = env["client"].get(f"/login/microsoft/callback{query}",
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

def test_a_token_for_another_audience_is_refused(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], aud="99999999-9999-9999-9999-999999999999")
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


def test_a_token_with_our_audience_and_another_alongside_it_is_refused(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], aud=[CLIENT_ID, "another-client"])
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


def test_an_audience_list_holding_only_us_is_accepted(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], aud=[CLIENT_ID])
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 303


def test_an_expired_token_is_refused(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], exp=time.time() - 3600)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


@pytest.mark.parametrize("exp", [None, "soon", [], {}])
def test_a_token_with_no_usable_expiry_is_refused(env, exp):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], exp=exp)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


def test_a_token_answering_another_attempt_is_refused(env):
    link_identity(env)
    first = start(env["client"])
    second = start(TestClient(ingest.app))
    payload = claims(second["nonce"])
    assert callback(env["client"], env, first,
                    token_claims=payload).status_code == 400


@pytest.mark.parametrize("nonce", [None, "", 42, []])
def test_a_token_with_no_usable_nonce_is_refused(env, nonce):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], nonce=nonce)
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 400


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
        f"/login/microsoft/callback?code=c&state={attempt['state']}",
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
        f"/login/microsoft/callback?code=c&state={attempt['state']}",
        follow_redirects=False)
    assert response.status_code == 400
    assert env["client"].get("/api/auth/check").status_code == 401


# ------------------------------------------------- the address, for showing

def test_the_address_is_stored_to_be_shown(env):
    link_identity(env)
    attempt = start(env["client"])
    callback(env["client"], env, attempt)
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_identities").fetchone()
    finally:
        con.close()
    assert row["email_shown"] == EMAIL


def test_the_username_stands_in_when_there_is_no_email_claim(env):
    """Microsoft sends `email` only in some configurations. Both claims are
    labels under the same rule, so either one may be displayed and neither one
    is ever read to decide anything."""
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"], preferred_username="robin@contoso.example")
    del payload["email"]
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 303
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_identities").fetchone()
    finally:
        con.close()
    assert row["email_shown"] == "robin@contoso.example"


def test_no_address_at_all_is_stored_as_nothing(env):
    link_identity(env)
    attempt = start(env["client"])
    payload = claims(attempt["nonce"])
    del payload["email"]
    del payload["preferred_username"]
    assert callback(env["client"], env, attempt,
                    token_claims=payload).status_code == 303
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_identities").fetchone()
    finally:
        con.close()
    assert row["email_shown"] is None


@pytest.mark.parametrize("claim_set, shown", [
    ({"email": "  SYSADMIN@Example.COM "}, EMAIL),
    ({"email": EMAIL, "preferred_username": "other@example.com"}, EMAIL),
    ({"preferred_username": "+3212345678"}, "+3212345678"),
    ({"email": "", "preferred_username": EMAIL}, EMAIL),
    ({"email": "   ", "preferred_username": EMAIL}, EMAIL),
    ({"email": 42, "preferred_username": EMAIL}, EMAIL),
    ({"email": None}, None),
    ({}, None),
    ({"name": "Robin Sample"}, None),
])
def test_which_claim_is_shown_as_the_address(claim_set, shown):
    assert oidc_microsoft.email_of(claim_set) == shown


# ------------------------------------------------ the second factor holds

def test_a_microsoft_sign_in_does_not_skip_the_second_factor(env):
    """Microsoft proving who somebody is does not prove they hold the operator's
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

def issue(env, provider="microsoft"):
    con = connect()
    try:
        return identities.issue_ticket(con, env["user_id"], provider)
    finally:
        con.close()


def follow_ticket(env, ticket):
    response = env["client"].get(f"/login/link/{ticket}", follow_redirects=False)
    assert response.status_code == 303, response.text
    query = urllib.parse.parse_qs(
        urllib.parse.urlparse(response.headers["location"]).query)
    return {"state": query["state"][0], "nonce": query["nonce"][0]}


def test_a_ticket_links_the_identity_and_does_not_sign_anybody_in(env):
    attempt = follow_ticket(env, issue(env))
    response = callback(env["client"], env, attempt)
    assert response.status_code == 303
    assert response.headers["location"] == "/login?msg=linked"
    assert env["client"].get("/api/auth/check").status_code == 401
    con = connect()
    try:
        assert identities.find_user_id(con, "microsoft", SUBJECT) == env["user_id"]
    finally:
        con.close()


def test_a_ticket_works_once(env):
    ticket = issue(env)
    assert env["client"].get(f"/login/link/{ticket}",
                             follow_redirects=False).status_code == 303
    second = env["client"].get(f"/login/link/{ticket}", follow_redirects=False)
    assert second.status_code == 400
    assert "used already" in second.text


def test_an_expired_ticket_is_refused(env, monkeypatch):
    ticket = issue(env)
    later = identities.now_utc() + identities.TICKET_TTL + identities.timedelta(seconds=1)
    monkeypatch.setattr(identities, "now_utc", lambda: later)
    assert env["client"].get(f"/login/link/{ticket}",
                             follow_redirects=False).status_code == 400


def test_a_microsoft_ticket_starts_a_microsoft_flow(env):
    """The ticket says which provider before a browser is involved, so a ticket
    minted for Microsoft cannot be spent on Google's consent screen."""
    follow_ticket(env, issue(env))
    con = connect()
    try:
        row = con.execute("SELECT * FROM oidc_flows").fetchone()
    finally:
        con.close()
    assert row["provider"] == "microsoft"
    assert env["opener"].gets == [oidc_microsoft.discovery_url()]


def test_a_ticket_for_a_provider_that_is_not_configured_is_refused(env, monkeypatch):
    ticket = issue(env)
    monkeypatch.delenv(oidc_microsoft.AUTHORITY_ENV)
    response = env["client"].get(f"/login/link/{ticket}", follow_redirects=False)
    assert response.status_code == 400
    assert "not configured" in response.text


def test_both_providers_can_be_linked_to_one_account_and_stay_separate(env):
    """One operator, two ways in, and neither row is the other. The rows are
    keyed per provider, so Google's subject and Microsoft's pair cannot collide,
    and unlinking one leaves the other alone."""
    link_identity(env, subject=GOOGLE_SUBJECT, provider="google")
    attempt = follow_ticket(env, issue(env))
    assert callback(env["client"], env, attempt).status_code == 303

    con = connect()
    try:
        rows = identities.for_user(con, env["user_id"])
        assert [row["provider"] for row in rows] == ["google", "microsoft"]
        assert identities.find_user_id(con, "google", GOOGLE_SUBJECT) == env["user_id"]
        assert identities.find_user_id(con, "microsoft", SUBJECT) == env["user_id"]
        # Neither key is a key for the other provider.
        assert identities.find_user_id(con, "microsoft", GOOGLE_SUBJECT) is None
        assert identities.find_user_id(con, "google", SUBJECT) is None
    finally:
        con.close()

    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 303
    assert env["client"].get("/api/auth/whoami").json() == {"email": EMAIL}

    con = connect()
    try:
        assert identities.unlink(con, "microsoft", env["user_id"]) is True
        assert identities.find_user_id(con, "google", GOOGLE_SUBJECT) == env["user_id"]
    finally:
        con.close()


def test_an_account_holds_one_microsoft_identity(env):
    con = connect()
    try:
        identities.link(con, "microsoft", SUBJECT, env["user_id"])
        with pytest.raises(identities.LinkError):
            identities.link(con, "microsoft", f"{OTHER_TENANT}:{OID}",
                            env["user_id"])
    finally:
        con.close()


def test_linking_refuses_to_take_an_identity_from_another_account(env):
    con = connect()
    try:
        other = accounts.create_user(con, "someone@example.com", PASSWORD)
        identities.link(con, "microsoft", SUBJECT, other)
        with pytest.raises(identities.LinkError):
            identities.link(con, "microsoft", SUBJECT, env["user_id"])
        assert identities.find_user_id(con, "microsoft", SUBJECT) == other
    finally:
        con.close()


def test_unlinking_stops_the_sign_in(env):
    link_identity(env)
    con = connect()
    try:
        assert identities.unlink(con, "microsoft", env["user_id"]) is True
        assert identities.unlink(con, "microsoft", env["user_id"]) is False
    finally:
        con.close()
    attempt = start(env["client"])
    assert callback(env["client"], env, attempt).status_code == 403
