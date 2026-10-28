"""OpenID Connect, the provider-agnostic half.

Reviewed from the OAuth flow of an earlier project of the author's.
What came across is the shape: mint a state, check it with
`hmac.compare_digest` on the way back, exchange the code server side, never let
a secret near the browser. The providers themselves are new, because that
project has neither.

**Every claim in this file was read from a primary source on 2026-08-22**, and
each one names the document it came from. The reason for that discipline is
the accuracy rule, and the reason it matters more here than usual is that a
guess about a token claim is not a wrong sentence on a page, it is a way in.

The shape, and why each piece is here:

  - **Discovery, not hardcoded endpoints.** Only the discovery URI is written
    down, and the authorization endpoint, token endpoint and issuer are read
    from the document. Google asks for exactly this.
  - **`response_type=code`, never `id_token`.** The whole basis for not
    verifying the token signature below is that the token reaches us only from
    the token endpoint, over TLS we verified. An implicit or hybrid response
    would break that and this module would have to grow a JWT verifier.
  - **`state`, `nonce` and a PKCE verifier, one set per attempt**, held server
    side and single use. `state` is the CSRF defence, `nonce` binds the token to
    this attempt, and PKCE binds the code to it.
  - **No JWT signature verification, deliberately, under a documented
    carve-out.** Read the long comment on `claims_from_id_token` before
    changing anything about how the token arrives.
  - **No new dependency.** urllib, hashlib, hmac, secrets, base64, json.

What is deliberately not here: refresh tokens, access tokens kept for anything,
userinfo calls, and any scope beyond identity. We want a stable identifier and
an address to show. We are not becoming a client of anybody's API.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

# Same posture as every other outbound call here, and for the same reason:
# `docs/RECORD.md` 4.86 is the entry about one call having the guard and
# another not having it.
REQUEST_TIMEOUT = 15

# A discovery document is re-read this often. Google asks callers to respect
# the document's cache headers; this is the simpler promise, which is that we
# do not fetch it on every sign-in and we do not cache it for a whole process
# lifetime either.
DISCOVERY_TTL_SECONDS = 3600

# RFC 7636 section 4.1 puts the verifier at 43 to 128 characters from the
# unreserved set. `token_urlsafe(64)` is 86 characters of that alphabet.
_VERIFIER_BYTES = 64


# The redirect URI has to byte-match what is registered with the provider, so
# it is configuration rather than something derived from the request. Deriving
# it from the Host header would mean whoever controls that header chooses where
# the code is delivered.
BASE_URL_ENV = "WHICHPORTS_BASE_URL"


def base_url() -> str | None:
    """Where this control plane answers, without a trailing slash. None when it
    is not set, which makes every provider not ready rather than guessing."""
    value = os.environ.get(BASE_URL_ENV, "").strip().rstrip("/")
    return value or None


def redirect_uri(provider) -> str:
    base = base_url()
    if not base:
        raise OIDCError(f"{BASE_URL_ENV} is not set, so there is nowhere to come back to")
    return f"{base}/login/{provider.name}/callback"


def is_ready(provider) -> bool:
    """Whether a button for this provider should exist at all: both halves of
    the client credential, and somewhere to come back to."""
    return provider.is_configured() and base_url() is not None


class OIDCError(Exception):
    """A sign-in that did not work. **The message is safe to show and safe to
    log**: it carries our own words and a provider's own fixed error code, never
    a token, never a code, never the client secret."""


@dataclass(frozen=True)
class Provider:
    """One identity provider, as configuration rather than as code.

    `subject_of` is the piece that is genuinely per provider: it turns a set of
    claims into the string this application keys an account on. It is a function
    and not a claim name because Microsoft's answer is two claims joined, and
    writing that as a special case somewhere else is how it would eventually be
    got wrong.

    `email_of` is the same idea for the address a screen shows. It is a label
    and never a key, which is `app/identities.py`'s subject and not repeated
    here.
    """

    name: str
    label: str
    discovery_url: str
    scope: str
    env_prefix: str
    subject_of: object
    email_of: object
    # Extra parameters on the authorization request, per provider.
    extra_auth_params: dict = field(default_factory=dict)
    # Exact strings the `iss` claim may equal. Google publishes two.
    issuers: tuple = ()
    # A provider whose `iss` is not one of a fixed set answers for itself,
    # given the token's claims and the metadata document. Microsoft's issuer
    # names the tenant the person signed in to, so it cannot be a constant.
    # None means the `issuers` tuple above is the whole answer, which is
    # Google.
    issuer_ok: object = None
    # A provider whose metadata address depends on configuration supplies a
    # function that returns it, or None when that configuration is missing.
    # Microsoft puts the authority in the path. None here means the fixed
    # `discovery_url` above is the whole answer, which is Google.
    discovery_url_of: object = None

    # Environment variables this provider needs beyond the client id and the
    # secret, named here so `users_cli providers` can report on them without
    # knowing anything about any particular provider. Microsoft's authority is
    # the only one today.
    #
    # **Nothing secret belongs in this tuple.** That command prints these values
    # in full, because they are configuration a person needs to read back. A
    # secret is reported as set or not set and is never shown.
    extra_env_vars: tuple = ()

    def extra_env(self) -> dict:
        """The extra variables and what they currently hold, for reporting."""
        return {name: os.environ.get(name, "").strip() for name in self.extra_env_vars}

    def client_id(self) -> str | None:
        return os.environ.get(f"{self.env_prefix}_CLIENT_ID", "").strip() or None

    def client_secret(self) -> str | None:
        return os.environ.get(f"{self.env_prefix}_CLIENT_SECRET", "").strip() or None

    def metadata_url(self) -> str | None:
        """Where this provider's discovery document lives, or None when the
        configuration it needs is missing.

        A fixed address for a provider that has one, which is Google. Microsoft
        carries the authority in the path, and the authority is configuration
        with no default, so its module answers None until it is set.
        """
        if self.discovery_url_of is None:
            return self.discovery_url
        return self.discovery_url_of()

    def is_configured(self) -> bool:
        """Whether this server can run the flow at all. **Both halves of the
        credential, and an address to read the metadata from**: a client id with
        no secret cannot complete the exchange, and a provider whose authority
        is unset has nowhere to send anybody, so either gap counts as not
        configured and the button does not appear."""
        return (self.client_id() is not None
                and self.client_secret() is not None
                and self.metadata_url() is not None)


# ------------------------------------------------------------- the transport

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects rather than follow them. A redirect on a token exchange
    is not something either provider documents, and following one would send a
    POST carrying the client secret somewhere nobody chose."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    """The one opener this module uses.

    **`ProxyHandler({})`, for the reason `app/hetzner.py` and `app/authz.py`
    already give.** `urllib.request.build_opener` installs a bare
    `ProxyHandler()` unless it is handed one, and a bare one reads `https_proxy`
    from the environment. The token exchange below carries the client secret in
    its body, so without this guard one variable in the unit's environment sends
    that secret to whoever answers there, with nobody touching this code.
    `docs/RECORD.md` 4.86 is the entry about that gap being found in one call
    and not another.

    **And certificate verification stays on**, which is not a default worth
    leaving implicit here: it is the entire reason `claims_from_id_token` is
    allowed not to check a signature.
    """
    https = urllib.request.HTTPSHandler(context=context or ssl.create_default_context())
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), https, _NoRedirect())


def _get_json(url: str, opener=None) -> dict:
    request = urllib.request.Request(url, method="GET",
                                     headers={"Accept": "application/json"})
    opener = opener or build_opener()
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise OIDCError(f"could not read {url}: {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise OIDCError(f"{url} did not answer with a JSON object")
    return payload


_discovery_cache: dict = {}


def discovery(provider: Provider, opener=None, now=None) -> dict:
    """The provider's discovery document, cached for DISCOVERY_TTL_SECONDS.

    Only the discovery URI is written down in this codebase. The endpoints come
    from here, which is what Google asks for in as many words: hardcode the
    discovery URI rather than the endpoints it contains.
    """
    now = now if now is not None else time.time()
    url = provider.metadata_url()
    if url is None:
        raise OIDCError(f"{provider.label} sign-in is not configured on this server")
    # Keyed on the address rather than on the provider name, because Microsoft's
    # address contains the authority. Keyed on the name, changing the authority
    # would go on being answered from a document read for the old one.
    cached = _discovery_cache.get(url)
    if cached and cached[0] > now:
        return cached[1]
    document = _get_json(url, opener=opener)
    for key in ("authorization_endpoint", "token_endpoint", "issuer"):
        if not isinstance(document.get(key), str) or not document[key]:
            raise OIDCError(f"{provider.label} discovery has no usable {key}")
    if not document["authorization_endpoint"].startswith("https://"):
        raise OIDCError(f"{provider.label} authorization endpoint is not https")
    if not document["token_endpoint"].startswith("https://"):
        raise OIDCError(f"{provider.label} token endpoint is not https")
    _discovery_cache[url] = (now + DISCOVERY_TTL_SECONDS, document)
    return document


def forget_discovery() -> None:
    """Drop the cache. For the tests, and for a process that wants to re-read."""
    _discovery_cache.clear()


# -------------------------------------------------------------------- PKCE

def new_verifier() -> str:
    """A PKCE code verifier: RFC 7636 section 4.1 wants 43 to 128 characters
    from the unreserved set, and `token_urlsafe` produces exactly that
    alphabet."""
    return secrets.token_urlsafe(_VERIFIER_BYTES)


def challenge_of(verifier: str) -> str:
    """The S256 challenge: base64url of the SHA-256 of the verifier, with the
    padding stripped, per RFC 7636 section 4.2."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def new_state() -> str:
    """An unguessable single-use value for one sign-in attempt."""
    return secrets.token_urlsafe(32)


def new_nonce() -> str:
    return secrets.token_urlsafe(32)


# ------------------------------------------------------------ the two legs

def authorize_url(provider: Provider, redirect_uri: str, state: str, nonce: str,
                  verifier: str, opener=None) -> str:
    """Where to send the operator's browser. The provider shows its own consent
    screen and comes back to `redirect_uri` with `?code=&state=`.

    PKCE is sent to both providers. Microsoft recommends it for confidential
    clients in as many words, RFC 9700 section 2.1.1 recommends it for
    confidential clients generally, and Google's own metadata lists S256 among
    the methods it accepts. **It is not relied on for CSRF**, because RFC 9700
    section 4.7.1 says a client must know the server supports PKCE before
    leaning on it that way, and Microsoft's metadata does not advertise it. That
    is `state`'s job, below, and it is always sent and always checked.
    """
    if not provider.is_configured():
        raise OIDCError(f"{provider.label} sign-in is not configured on this server")
    params = {
        "client_id": provider.client_id(),
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": provider.scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge_of(verifier),
        "code_challenge_method": "S256",
    }
    params.update(provider.extra_auth_params)
    endpoint = discovery(provider, opener=opener)["authorization_endpoint"]
    return f"{endpoint}?{urllib.parse.urlencode(params)}"


def exchange_code(provider: Provider, code: str, redirect_uri: str, verifier: str,
                  opener=None) -> dict:
    """Trade the one-time code for the token response, server side.

    The client secret goes in the body, form-urlencoded, which is what both
    providers document. `urlencode` percent-encodes it, which Microsoft asks for
    by name because its secrets contain punctuation.

    `redirect_uri` must byte-match the one sent to the authorization endpoint,
    or the provider refuses.
    """
    if not provider.is_configured():
        raise OIDCError(f"{provider.label} sign-in is not configured on this server")
    body = urllib.parse.urlencode({
        "client_id": provider.client_id(),
        "client_secret": provider.client_secret(),
        "code": code,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    }).encode("utf-8")
    endpoint = discovery(provider, opener=opener)["token_endpoint"]
    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    opener = opener or build_opener()
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        # Deliberately typed rather than free text. The exception could carry a
        # response body, and a response body on this endpoint can carry the code
        # we just sent.
        raise OIDCError(f"{provider.label} did not complete the exchange:"
                        f" {type(exc).__name__}") from exc
    if not isinstance(payload, dict):
        raise OIDCError(f"{provider.label} answered the exchange with no object")
    if payload.get("error"):
        # A provider error code is a fixed string of theirs, so it is safe to
        # surface. `error_description` is not, and is not read.
        raise OIDCError(f"{provider.label} refused the exchange:"
                        f" {str(payload['error'])[:64]}")
    if not isinstance(payload.get("id_token"), str) or not payload["id_token"]:
        raise OIDCError(f"{provider.label} returned no id token")
    return payload


# ---------------------------------------------------------------- the token

def claims_from_id_token(id_token: str) -> dict:
    """The claims out of an ID token, **without verifying its signature**.

    Read this before changing how the token gets here.

    OpenID Connect Core section 3.1.3.7 item 6 says, verbatim: "If the ID Token
    is received via direct communication between the Client and the Token
    Endpoint (which it is in this flow), the TLS server validation MAY be used
    to validate the issuer in place of checking the token signature." Both
    providers say the same for themselves. Google: "since you are communicating
    directly with Google over an intermediary-free HTTPS channel and using your
    client secret ... you can be confident that the token you receive really
    comes from Google and is valid." Microsoft says a web app doing the plain
    code flow has no need to validate the token itself.

    **Four conditions hold that up, and all four are this codebase's job:**

      1. the code is exchanged server side, by `exchange_code` above,
      2. certificate verification is on, which `build_opener` states explicitly,
      3. the token endpoint came from the discovery document rather than from
         anything in the request,
      4. the token is used here and dropped. It is never stored, never logged
         and never handed to another component. That is Google's stated
         condition, not a preference of ours.

    **If any of those stops being true, this function becomes wrong** and the
    module needs a real JWKS verifier. In particular, the moment a token arrives
    through the browser rather than from the token endpoint, the carve-out is
    gone.

    What this does not excuse is `validate_claims` below. The carve-out replaces
    the signature check and nothing else: issuer, audience, expiry and nonce are
    still checked, and they are items 2, 3, 9 and 11 of the same section.
    """
    parts = id_token.split(".")
    if len(parts) != 3:
        raise OIDCError("the id token is not a three part JWT")
    payload = parts[1]
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        claims = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise OIDCError("the id token payload could not be read") from exc
    if not isinstance(claims, dict):
        raise OIDCError("the id token payload is not an object")
    return claims


def check_issuer(provider: Provider, claims: dict, opener=None) -> None:
    """Where the token says it came from, refused unless it is a place this
    provider accepts.

    Two shapes, because the two providers are genuinely different.

    **A fixed allow list**, which is Google. `iss` is compared as an exact
    string against `provider.issuers`. Google publishes two accepted values,
    `https://accounts.google.com` and `accounts.google.com`, and a check against
    only the first is a bug that bites the day they send the other.

    **The provider answers for itself**, which is Microsoft. Its issuer names
    the tenant the person signed in to, so there is no fixed string to compare
    with, and the metadata document is handed over so the provider can do what
    Microsoft documents: substitute the token's own tenant into the issuer the
    metadata carries, then compare exactly. The document comes from the cache
    the exchange just filled, so this is not another network call.

    One refusal message for every way of failing, deliberately. Which check said
    no is not something a signed-out browser is owed.
    """
    issuer = claims.get("iss")
    if not isinstance(issuer, str) or not issuer:
        raise OIDCError("the id token came from an issuer we do not accept")
    if provider.issuer_ok is None:
        if issuer not in provider.issuers:
            raise OIDCError("the id token came from an issuer we do not accept")
        return
    if not provider.issuer_ok(claims, discovery(provider, opener=opener)):
        raise OIDCError("the id token came from an issuer we do not accept")


def validate_claims(provider: Provider, claims: dict, nonce: str,
                    now: float | None = None, leeway: int = 60,
                    opener=None) -> None:
    """The checks the carve-out above does not touch, and refusing rather than
    warning on every one of them.

    `iss`, `aud`, `exp` and `nonce`, for every provider. They are items 2, 3, 9
    and 11 of OIDC Core 3.1.3.7. `check_issuer` above is the only one of the
    four whose answer is per provider.
    """
    now = now if now is not None else time.time()

    check_issuer(provider, claims, opener=opener)

    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list) else [audience]
    if provider.client_id() not in audiences:
        raise OIDCError("the id token was not issued for this application")
    if len(audiences) > 1:
        # More than one audience means the token is also for somebody else, and
        # OIDC Core requires an azp when that happens. Refusing is the honest
        # answer for an application that has exactly one audience of its own.
        raise OIDCError("the id token carries an audience we did not expect")

    expires = claims.get("exp")
    if not isinstance(expires, (int, float)) or expires + leeway <= now:
        raise OIDCError("the id token has expired")

    # The spec makes this a MUST once a nonce was sent, and one is always sent.
    # compare_digest on the two values, and both are ours or the provider's
    # echo of ours, so an attacker replaying a token from another attempt fails
    # here rather than at the account lookup.
    supplied = claims.get("nonce")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, nonce):
        raise OIDCError("the id token does not answer this sign-in attempt")
