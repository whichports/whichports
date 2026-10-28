"""Sign in, sign out, and the dependency that says who is signed in.

Plain HTML forms and full page renders, so signing in needs no JavaScript. The
properties that make this safe, spelled out because they are the whole point of
the module and each one has a test:

  - **CSRF by double-submit cookie on the login form.** The GET sets a random
    token as a cookie and puts the same token in the form, the POST requires
    the two to match. A cross-site page cannot read the cookie to fill the
    field in, and SameSite=Lax means its POST does not even carry one.
  - **The session cookie is HttpOnly and SameSite=Lax**, and Secure whenever
    the browser-facing hop was HTTPS. Behind Caddy this process sees plain
    http, so `X-Forwarded-Proto` decides. On a plain-http lab box the flag
    stays off, or the cookie would be set and never sent back.
  - **Sessions are server side** (app/accounts.py), so signing out revokes the
    row and a copied cookie stops working on its next request.
  - **Login is rate limited per email and globally** (app/ratelimit.py), and an
    unknown address and a wrong password give the same words and cost the same
    hashing work, so neither the wording nor the timing enumerates accounts.
  - **`?next=` only ever goes to a relative path on this site.** No absolute
    URL, no scheme-relative `//host`, no backslash.

No dependency is added for form parsing. FastAPI's `Form()`, and since
Starlette 0.37 `request.form()` as well, need the `python-multipart` package.
These forms are ordinary urlencoded pairs, so the body is parsed with
`urllib.parse.parse_qsl` from the standard library. The work behind a login is
then run in the threadpool, which is where a scrypt hash belongs rather than on
the event loop.

  - **The second factor is a gate and not a suggestion.** A right password
    with two-factor on issues a *pending* session, which `accounts.resolve_session`
    refuses, so `/api/auth/check`, `require_operator` and everything else keep
    saying signed out until a code lands. The token is then replaced, so the
    cookie the browser carried through the challenge is not the one it leaves
    with.
  - **The code page tells an anonymous visitor nothing.** It is reachable only
    with a pending session, which costs a correct password, so it can never be
    used to ask whether an account exists or whether it has two-factor on.

What this module deliberately does not have: signup, password reset by email,
two-factor *enrolment*, invitations, organisations and roles. Accounts are
created by `app.users_cli` on the box, and two-factor is turned on there too,
so no account-creation surface exists on the internet before anyone decides one
should.

The dashboard is served from here too, at the foot of this file. It is here
rather than in a module of its own because it is a session-gated page and this
is the module that owns what a session is.
"""

import hmac
import secrets
import sqlite3
import sys
import time
from dataclasses import replace
from urllib.parse import parse_qsl, quote

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import (accounts, dashboard, db, identities, notify, oidc, onetime,
               publicurl, ratelimit, signup, totp, web_pages)
from .providers import PROVIDERS

router = APIRouter()

SESSION_COOKIE = "whichports_session"
CSRF_COOKIE = "whichports_csrf"

# These forms carry a few short fields. Anything larger is not a browser
# submitting ours, and refusing early keeps the parse away from memory games.
#
# It is also what bounds the password a login hashes. The length rule in
# accounts.check_password_shape only applies when a password is set, so without
# this cap a megabyte in the password field would be fed to scrypt on every
# attempt.
FORM_BODY_MAX_BYTES = 64 * 1024

# One answer for an unknown address, a wrong password and a disabled account.
# Three different words here would be an account-enumeration oracle that no
# amount of timing equalisation could fix.
_BAD_LOGIN = "That email and password do not match."

# One-shot lines a redirect can carry to the login page through ?msg=, as
# (tag, text). An unknown key renders nothing.
_NOTICES = {
    "signed-out": ("OUT", "You are signed out."),
    "linked": ("OK", "That sign-in is connected. You can use it from now on."),
}

# Where the second step lives. One constant, because three routes point at it.
TWO_FACTOR_PATH = "/login/2fa"

# The cookie that ties one sign-in attempt to one browser. Short lived, and read
# exactly once, at the callback. Its reason for existing is in the docstring of
# `identities.start_flow`, and the short version is that a `state` nobody bound
# to a browser does not stop login CSRF.
FLOW_COOKIE = "whichports_oidc"

# One answer for every way a provider sign-in can fail to find an account. It
# says nothing about whether the address has an account here, for the same
# reason `_BAD_LOGIN` says nothing: the login surface is not an enumeration
# oracle, and adding a second, chattier way in would undo that.
# What is left of the old refusal. A provider identity nobody has seen now
# creates an account rather than being turned away, so this is reached only when
# the account behind a known identity is disabled. It stays deliberately vague,
# because whether an address has an account here is not a signed-out visitor's
# to learn.
_NO_LINK = "That sign-in did not work. Try again, or use your password."


def _to_two_factor(next_path: str) -> RedirectResponse:
    """Send the browser to the code page, carrying where it was going."""
    return RedirectResponse(
        url=f"{TWO_FACTOR_PATH}?next={quote(next_path, safe='')}", status_code=303)


# ------------------------------------------------------------------ helpers

def cookie_secure(request: Request) -> bool:
    """Secure cookies whenever the browser-facing hop was HTTPS. Caddy tells us
    with X-Forwarded-Proto; without a proxy the request's own scheme answers."""
    return request.headers.get("x-forwarded-proto", request.url.scheme) == "https"


def safe_next(next_path: str | None) -> str:
    """Where a login may send the browser afterwards: a relative path on this
    site and nothing else.

    Rejected, each for its own reason: an absolute URL (https://evil/) sends
    the operator somewhere else entirely, a scheme-relative one (//evil/) does
    the same while looking like a path, a backslash is treated as a slash by
    some browsers, and a control character could split the Location header.
    """
    if not next_path:
        return "/"
    if not next_path.startswith("/") or next_path.startswith("//"):
        return "/"
    if "\\" in next_path:
        return "/"
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in next_path):
        return "/"
    return next_path


def _limiters(request: Request) -> ratelimit.Limiters:
    return request.app.state.limiters


def _connect() -> sqlite3.Connection:
    con = db.connect()
    db.init(con)
    accounts.init(con)
    identities.init(con)
    onetime.init(con)
    return con


def _ensure_csrf(request: Request, response: Response) -> str:
    """This request's CSRF token, minting the cookie when there is not one."""
    token = request.cookies.get(CSRF_COOKIE) or ""
    if len(token) < 32:
        token = secrets.token_urlsafe(32)
        response.set_cookie(CSRF_COOKIE, token, httponly=True, samesite="lax",
                            secure=cookie_secure(request))
    return token


def _csrf_ok(request: Request, form_token: str) -> bool:
    cookie = request.cookies.get(CSRF_COOKIE) or ""
    if len(form_token) < 32:
        return False
    # compare_digest on two str values raises TypeError the moment either
    # holds a codepoint above U+007F, and both of these come from the
    # request: the form field directly, and the cookie through Starlette,
    # which decodes header bytes as latin-1 so 0x80 to 0xFF arrive as
    # non-ASCII text. Unhandled, that turns a refusal into a 500 on an
    # unauthenticated endpoint. The token this code issues is url-safe
    # base64, so anything outside ASCII is not our token and the answer is
    # no, reached without comparing.
    try:
        cookie_bytes = cookie.encode("ascii")
        form_bytes = form_token.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(cookie_bytes, form_bytes)


def _no_store(response: Response) -> Response:
    """A page or an answer about who is signed in is never cached, by the
    browser or by anything between."""
    response.headers["Cache-Control"] = "no-store"
    return response


async def form_fields(request: Request, *names: str) -> dict[str, str]:
    """The named fields of an urlencoded body, parsed with the standard
    library. Missing fields come back empty, and an oversized or undecodable
    body yields every field empty, which the CSRF check then refuses.

    A body that says it is larger than the cap is not read at all, and one
    that says nothing is read only to the cap. These forms are on
    app.whichports.com, where strangers reach them, and reading the whole
    body first would let one make the ingest hold any size in memory only
    to refuse it (decided 27 October 2026)."""
    fields = dict.fromkeys(names, "")
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > FORM_BODY_MAX_BYTES:
        return fields
    received = bytearray()
    async for chunk in request.stream():
        received += chunk
        if len(received) > FORM_BODY_MAX_BYTES:
            return fields
    body = bytes(received)
    try:
        pairs = dict(parse_qsl(body.decode("utf-8"), keep_blank_values=True))
    except UnicodeDecodeError:
        return fields
    for name in names:
        fields[name] = pairs.get(name, "")
    return fields


def signed_in_user(request: Request) -> sqlite3.Row | None:
    """The account behind this request's session cookie, or None. Opens its own
    connection, the same short-lived pattern every other route here uses."""
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None
    con = _connect()
    try:
        return accounts.resolve_session(con, token)
    finally:
        con.close()


def pending_user(request: Request) -> sqlite3.Row | None:
    """The account behind a session that has passed the password and still owes
    a code, or None. Same short-lived connection pattern as everything here."""
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        return None
    con = _connect()
    try:
        return accounts.resolve_pending_session(con, token)
    finally:
        con.close()


def require_user(request: Request) -> sqlite3.Row:
    """FastAPI dependency: the signed-in account, or 401.

    Nothing in this pull request uses it as a gate except /api/auth/whoami. It
    is what the follow-up puts in front of the dashboard and the write actions,
    and it is here now so the session it depends on is already reviewed and
    tested when that lands.
    """
    user = signed_in_user(request)
    if user is None:
        raise HTTPException(status_code=401)
    return user


def _set_session_cookie(response: Response, request: Request, token: str) -> None:
    # No max-age, so this is a browser-session cookie: closing the browser ends
    # it. The server-side TTL in accounts.SESSION_TTL bounds it absolutely
    # either way, which is the half a thief cannot ignore.
    response.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="lax",
                        secure=cookie_secure(request))


# ------------------------------------------------------------------- log in

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", msg: str = "") -> Response:
    if signed_in_user(request) is not None:
        return _no_store(RedirectResponse(url=safe_next(next), status_code=303))
    if pending_user(request) is not None:
        # Password already proved, code still owed. Back to the challenge
        # rather than to a second password form.
        return _no_store(_to_two_factor(safe_next(next)))
    # The token is minted on a carrier response first, because the page body
    # has to contain the same token the cookie carries.
    carrier = Response()
    token = _ensure_csrf(request, carrier)
    response = HTMLResponse(web_pages.login_page(
        csrf=token, next_path=safe_next(next), notice=_NOTICES.get(msg),
        providers=_ready_providers(), closed=signup.notice()))
    for key, value in carrier.raw_headers:
        if key == b"set-cookie":
            response.raw_headers.append((key, value))
    return _no_store(response)


def _login_submit(request: Request, email: str, password: str,
                  next_field: str, csrf: str) -> Response:
    """The blocking half of a login, run in the threadpool by the route below.

    The password is a local here and reaches nothing else. It is never logged,
    never put in a response, and never written to the database in any form
    other than the scrypt hash it is checked against.
    """
    email = accounts.normalize_email(email)
    next_path = safe_next(next_field)

    def again(error: str, code: int) -> Response:
        carrier = Response()
        token = _ensure_csrf(request, carrier)
        response = HTMLResponse(
            web_pages.login_page(csrf=token, next_path=next_path, email=email,
                                 error=error, providers=_ready_providers(), closed=signup.notice()),
            status_code=code)
        for key, value in carrier.raw_headers:
            if key == b"set-cookie":
                response.raw_headers.append((key, value))
        return _no_store(response)

    if not _csrf_ok(request, csrf):
        return again("That took too long and the form expired. Try again.", 400)

    limiters = _limiters(request)
    # Both buckets are asked, and both are charged, so a spray across many
    # addresses still meets the global ceiling.
    global_ok = limiters.login_global.allow(ratelimit.GLOBAL_KEY)
    email_ok = limiters.login_email.allow(email)
    if not (global_ok and email_ok):
        return again("Too many attempts. Wait a minute, then try again.", 429)

    con = _connect()
    try:
        user = accounts.authenticate(con, email, password)
        if user is None:
            return again(_BAD_LOGIN, 401)
        owes_code = accounts.totp_enabled(user)
        token, _ = accounts.issue_session(
            con, user["id"], user_agent=request.headers.get("user-agent"),
            totp_pending=owes_code)
    finally:
        con.close()

    # A pending session is not a login. Nothing in the application accepts it,
    # so this redirect is the only thing it can be used for.
    response = _to_two_factor(next_path) if owes_code else RedirectResponse(
        url=next_path, status_code=303)
    _set_session_cookie(response, request, token)
    return _no_store(response)


@router.post("/login", response_class=HTMLResponse)
async def login_submit(request: Request) -> Response:
    fields = await form_fields(request, "email", "password", "next", "csrf")
    return await run_in_threadpool(
        _login_submit, request, fields["email"], fields["password"],
        fields["next"], fields["csrf"])


# ------------------------------------------------------- the second factor

# Reached only with a pending session, which costs a correct password. So this
# page cannot be used to ask whether an address has an account, or whether an
# account has two-factor on: an anonymous visitor is redirected away before
# anything renders, and gets exactly what a visitor to any signed-out page gets.


def _render_two_factor(request: Request, next_path: str, error: str | None = None,
                       status_code: int = 200,
                       recovery_left: int | None = None) -> Response:
    """The second factor, with a CSRF token minted on the way out, the same
    carrier trick the login page uses.

    **It is the sign-in card with the code field open in it** since 2026-09-09
    (docs/screens/sign-in/SPEC.md), rather than a page of its own. Nothing on
    it names an account, which is the older decision `tests/test_two_factor.py`
    holds and this change keeps.

    The one page that is still its own is the line after a recovery code was
    spent, which is not a form and says something no other page says.
    """
    carrier = Response()
    token = _ensure_csrf(request, carrier)
    if recovery_left is not None:
        body = web_pages.two_factor_page(csrf=token, next_path=next_path,
                                         recovery_left=recovery_left)
    else:
        body = web_pages.login_page(csrf=token, next_path=next_path,
                                    error=error, code=True)
    response = HTMLResponse(body, status_code=status_code)
    for key, value in carrier.raw_headers:
        if key == b"set-cookie":
            response.raw_headers.append((key, value))
    return _no_store(response)


@router.get(TWO_FACTOR_PATH, response_class=HTMLResponse)
def two_factor_page(request: Request, next: str = "/") -> Response:
    if signed_in_user(request) is not None:
        return _no_store(RedirectResponse(url=safe_next(next), status_code=303))
    if pending_user(request) is None:
        return _no_store(RedirectResponse(url="/login", status_code=303))
    return _render_two_factor(request, safe_next(next))


def _two_factor_submit(request: Request, code: str, next_field: str,
                       csrf: str) -> Response:
    """The blocking half of the second step, run in the threadpool by the route
    below. A recovery code costs one scrypt hash per unused code, which belongs
    nowhere near the event loop.

    The code is a local here and reaches nothing else. It is never logged and
    never put in a response.
    """
    next_path = safe_next(next_field)
    con = _connect()
    try:
        token = request.cookies.get(SESSION_COOKIE, "")
        user = accounts.resolve_pending_session(con, token) if token else None
        if user is None:
            # Expired, revoked, already finished, or never pending. The same
            # answer any signed-out visitor gets.
            return _no_store(RedirectResponse(url="/login", status_code=303))

        def again(error: str, status_code: int) -> Response:
            return _render_two_factor(request, next_path, error=error,
                                      status_code=status_code)

        if not _csrf_ok(request, csrf):
            return again("That took too long and the form expired. Try again.", 400)

        limiters = _limiters(request)
        # Both buckets are asked and both are charged, the same shape the login
        # uses. The per-account one is keyed on the account rather than on this
        # session, because somebody here can mint fresh sessions at will.
        global_ok = limiters.totp_global.allow(ratelimit.GLOBAL_KEY)
        user_ok = limiters.totp_user.allow(str(user["id"]))
        if not (global_ok and user_ok):
            return again("Too many attempts. Wait a minute, then try again.", 429)

        method = accounts.verify_second_factor(con, user, code, at_time=time.time())
        if method is None:
            return again("That code is not right. Try again, or use a recovery code.", 401)

        issued = accounts.complete_pending_session(
            con, token, user_agent=request.headers.get("user-agent"))
        if issued is None:
            # The session went away between the two reads above. Nothing is
            # wrong, and starting over is the honest answer.
            return _no_store(RedirectResponse(url="/login", status_code=303))
        new_token, _ = issued

        if method == "recovery":
            left = accounts.recovery_codes_remaining(con, user["id"])
            # No redirect on this path. A burned code is a fact the operator has
            # to see once, here, before the dashboard takes over.
            response = _render_two_factor(request, next_path, recovery_left=left)
        else:
            response = _no_store(RedirectResponse(url=next_path, status_code=303))
    finally:
        con.close()
    _set_session_cookie(response, request, new_token)
    return response


@router.post(TWO_FACTOR_PATH, response_class=HTMLResponse)
async def two_factor_submit(request: Request) -> Response:
    fields = await form_fields(request, "code", "next", "csrf")
    return await run_in_threadpool(
        _two_factor_submit, request, fields["code"], fields["next"], fields["csrf"])


# NOTE ON ORDER. These routes are registered AFTER `/login/2fa` on purpose.
# Starlette matches in registration order, and `/login/{provider_name}` matches
# the literal path `/login/2fa` perfectly well. Registered first, it would
# swallow the second factor page and turn it into a 404, which is a two-factor
# login that can never be completed. `tests/test_two_factor.py` is what would
# catch it, and `tests/test_oidc_google.py` asserts the order directly.
# ----------------------------------------------------- signing in with a provider

# Three routes, and the whole security argument sits in four places rather than
# in these handlers: `identities` decides what a token is allowed to mean,
# `oidc.validate_claims` decides whether the token is ours, `oidc.build_opener`
# keeps the exchange off any proxy, and `accounts` decides what a session is.
#
# **A provider sign-in is not a way past the second factor.** It lands in the
# same place a password does: `_finish_sign_in` below, which issues a pending
# session when the account has two-factor on. A provider proving who somebody
# is does not prove they hold the operator's authenticator.


def _flow_binding(request: Request, response: Response) -> str:
    """Mint the value that ties this attempt to this browser and set it as a
    cookie. SameSite=Lax is what the callback needs: it is a top-level
    navigation from the provider, so a Lax cookie is sent, while a cross-site
    POST would carry nothing."""
    binding = secrets.token_urlsafe(32)
    response.set_cookie(FLOW_COOKIE, binding, httponly=True, samesite="lax",
                        secure=cookie_secure(request), max_age=600)
    return binding


def _begin_flow(request: Request, provider, next_path: str,
                link_user_id: int | None = None) -> Response:
    """Mint an attempt, remember it, and send the browser to the provider."""
    state, nonce, verifier = oidc.new_state(), oidc.new_nonce(), oidc.new_verifier()
    try:
        url = oidc.authorize_url(provider, oidc.redirect_uri(provider), state,
                                 nonce, verifier)
    except oidc.OIDCError as exc:
        return _no_store(_render_login_error(request, str(exc)))
    response = RedirectResponse(url=url, status_code=303)
    binding = _flow_binding(request, response)
    con = _connect()
    try:
        identities.start_flow(con, provider.name, state, nonce, verifier,
                              binding, next_path, link_user_id=link_user_id)
    finally:
        con.close()
    return _no_store(response)


def _render_login_error(request: Request, message: str, status_code: int = 400) -> Response:
    """Back to the login page carrying one line. Provider failures land here
    rather than on a page of their own, so there is one place a signed-out
    person ever ends up."""
    carrier = Response()
    token = _ensure_csrf(request, carrier)
    response = HTMLResponse(
        web_pages.login_page(csrf=token, next_path="/", error=message,
                             providers=_ready_providers(), closed=signup.notice()),
        status_code=status_code)
    for key, value in carrier.raw_headers:
        if key == b"set-cookie":
            response.raw_headers.append((key, value))
    return response


def _ready_providers() -> list[tuple[str, str]]:
    """The (name, label) pairs the login page draws a button for."""
    return [(p.name, p.label) for p in PROVIDERS.values() if oidc.is_ready(p)]


@router.get("/login/{provider_name}")
def provider_start(request: Request, provider_name: str, next: str = "/") -> Response:
    provider = PROVIDERS.get(provider_name)
    if provider is None or not oidc.is_ready(provider):
        # An unknown or unconfigured provider is a 404 rather than an
        # explanation, because the set of providers a build has is not
        # information a signed-out visitor needs.
        raise HTTPException(status_code=404)
    if signed_in_user(request) is not None:
        return _no_store(RedirectResponse(url=safe_next(next), status_code=303))
    return _begin_flow(request, provider, safe_next(next))


@router.get("/login/link/{ticket}")
def link_start(request: Request, ticket: str) -> Response:
    """The gated first sign-in. `users_cli link` printed this URL, and spending
    the ticket is what says which local account the identity may bind to.

    The ticket is spent here, before the provider is involved at all, so a URL
    that leaked buys exactly one trip to a consent screen.
    """
    con = _connect()
    try:
        row = identities.take_ticket(con, ticket)
    finally:
        con.close()
    if row is None:
        return _no_store(_render_login_error(
            request, "That link has been used already, or it has expired.", 400))
    provider = PROVIDERS.get(row["provider"])
    if provider is None or not oidc.is_ready(provider):
        return _no_store(_render_login_error(
            request, f"{row['provider']} sign-in is not configured on this server.", 400))
    return _begin_flow(request, provider, "/", link_user_id=int(row["user_id"]))


def _callback(request: Request, provider, code: str, state: str) -> Response:
    """The blocking half of a callback: two network calls and a scrypt-free but
    still database-bound path, so it runs in the threadpool."""
    binding = request.cookies.get(FLOW_COOKIE, "")
    con = _connect()
    try:
        flow = identities.take_flow(con, provider.name, state, binding)
        if flow is None:
            # Wrong browser, replayed callback, unknown or expired state. One
            # answer for all of them, and the attempt is spent either way.
            return _no_store(_render_login_error(
                request, "That sign-in did not complete. Start again.", 400))
        try:
            tokens = oidc.exchange_code(provider, code, oidc.redirect_uri(provider),
                                        flow["verifier"])
            claims = oidc.claims_from_id_token(tokens["id_token"])
            oidc.validate_claims(provider, claims, flow["nonce"])
            subject = provider.subject_of(claims)
        except oidc.OIDCError as exc:
            return _no_store(_render_login_error(request, str(exc), 400))

        # The address is a label, and which claim carries it is the provider's
        # business rather than this handler's. `app/identities.py` owns what it
        # is allowed to mean, which is nothing.
        email_shown = provider.email_of(claims)

        if flow["link_user_id"] is not None:
            try:
                identities.link(con, provider.name, subject,
                                int(flow["link_user_id"]), email_shown=email_shown)
            except identities.LinkError as exc:
                return _no_store(_render_login_error(request, str(exc), 400))
            # Linking does not sign anybody in. The person at the browser has
            # proved a provider identity and nothing about the operator account,
            # so they go to the login page and use it.
            return _no_store(RedirectResponse(url="/login?msg=linked", status_code=303))

        user_id = identities.find_user_id(con, provider.name, subject)
        if user_id is None:
            # Nobody has signed in with this identity before, so this is a
            # signup and it behaves like one: a workspace of their own with
            # nothing in it. `identities.provision` carries the reasoning, and
            # the one rule that does not move is that an email address never
            # merges two accounts.
            try:
                user_id = identities.provision(
                    con, provider.name, subject, email_shown)
            except identities.LinkError as exc:
                return _no_store(_render_login_error(request, str(exc), 403))
        user = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user is None or user["disabled_at"]:
            # A disabled account says the same thing a refused signup says, so
            # the two are not distinguishable from outside.
            return _no_store(_render_login_error(request, _NO_LINK, 403))
        identities.mark_used(con, provider.name, subject, email_shown=email_shown)

        owes_code = accounts.totp_enabled(user)
        token, _ = accounts.issue_session(
            con, user["id"], user_agent=request.headers.get("user-agent"),
            totp_pending=owes_code)
    finally:
        con.close()

    next_path = safe_next(flow["next_path"])
    response = _to_two_factor(next_path) if owes_code else RedirectResponse(
        url=next_path, status_code=303)
    _set_session_cookie(response, request, token)
    response.delete_cookie(FLOW_COOKIE)
    return _no_store(response)


@router.get("/login/{provider_name}/callback")
async def provider_callback(request: Request, provider_name: str, code: str = "",
                            state: str = "", error: str = "") -> Response:
    provider = PROVIDERS.get(provider_name)
    if provider is None or not oidc.is_ready(provider):
        raise HTTPException(status_code=404)
    if error or not code or not state:
        # The provider says the person declined, or the query is not one of
        # ours. Either way there is nothing to exchange. The provider's own
        # error code is a fixed string of theirs, so a short slice of it is safe
        # to show, and nothing else from the query is echoed.
        return await run_in_threadpool(
            _render_login_error, request,
            "That sign-in did not complete. Start again.", 400)
    return await run_in_threadpool(_callback, request, provider, code, state)


# ------------------------------------------------------------- registering

# Self-serve. Somebody registers, a workspace is created, and the account that
# owns it is the first thing in it. `accounts.register` is where those two
# happen together, and the reason it is not `create_user` with an argument: a
# new arrival must never land in workspace 1, which is where the command line
# quite rightly puts everybody.
#
# The page below is the only one anybody can reach without already having
# something, so what it may say is worth stating. It does tell a visitor that an
# address is already taken, which the login page deliberately never does. That
# is not an inconsistency: a signup form that refused without saying why is
# unusable, and every real signup form on the internet answers this question.
# What it must not be is a *cheaper* oracle than signing up, so it sits behind
# the same two buckets the login uses and costs a full request either way.


def _render_register(request: Request, email: str = "", error: str | None = None,
                     status_code: int = 200) -> Response:
    carrier = Response()
    token = _ensure_csrf(request, carrier)
    response = HTMLResponse(
        web_pages.register_page(csrf=token, email=email, error=error,
                                closed=signup.notice(),
                                providers=_ready_providers()),
        status_code=status_code)
    for key, value in carrier.raw_headers:
        if key == b"set-cookie":
            response.raw_headers.append((key, value))
    return _no_store(response)


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request) -> Response:
    if signed_in_user(request) is not None:
        return _no_store(RedirectResponse(url="/", status_code=303))
    return _render_register(request)


def _register_submit(request: Request, email: str, password: str,
                     confirm: str, csrf: str) -> Response:
    """The blocking half, run in the threadpool by the route below, because
    creating an account is one scrypt hash and that does not belong on the
    event loop.

    The password is a local here and reaches nothing else. It is never logged,
    never put in a response, and never written anywhere but as its hash.
    """
    email = accounts.normalize_email(email)

    if not _csrf_ok(request, csrf):
        return _render_register(
            request, email, "That took too long and the form expired. Try again.", 400)

    limiters = _limiters(request)
    # Both buckets are asked and both are charged, the same shape the login
    # uses. The global one is what stops a script creating workspaces in a loop.
    global_ok = limiters.login_global.allow(ratelimit.GLOBAL_KEY)
    email_ok = limiters.login_email.allow(email)
    if not (global_ok and email_ok):
        return _render_register(
            request, email, "Too many attempts. Wait a minute, then try again.", 429)

    if password != confirm:
        # Before the length rule, because "they do not match" is the more
        # useful thing to hear when both are also too short.
        return _render_register(request, email, "Those two do not match.", 400)

    con = _connect()
    try:
        try:
            user_id = accounts.register(con, email, password)
        except accounts.AccountError as exc:
            return _render_register(request, email, str(exc), 400)
        token, _ = accounts.issue_session(
            con, user_id, user_agent=request.headers.get("user-agent"))
    finally:
        con.close()

    # A new account has no second factor yet, so this is a full session rather
    # than a pending one. Turning two-factor on is `users_cli 2fa enable`.
    response = RedirectResponse(url="/", status_code=303)
    _set_session_cookie(response, request, token)
    return _no_store(response)


@router.post("/register", response_class=HTMLResponse)
async def register_submit(request: Request) -> Response:
    fields = await form_fields(request, "email", "password", "confirm", "csrf")
    return await run_in_threadpool(
        _register_submit, request, fields["email"], fields["password"],
        fields["confirm"], fields["csrf"])


# ------------------------------------------ the screens around signing in
#
# docs/screens/sign-in/SPEC.md, the sketch the owner approved on 2026-09-09, and
# the four mails `app/notify.py` writes for them. Every one of these flows is
# the same three steps: ask, mail a link that works once and expires
# (`app/onetime.py`), land on a form the link decided the account for.
#
# **A link is not a session and never skips the second factor.** Every one of
# these ends by handing the caller to `_after_link`, which issues a pending
# session when the account has two-factor on, exactly as a password does.

# Where a link in a mail points is `publicurl.base()`, the host the mails
# already print, so the two cannot disagree about where the product lives.

# What every dead link says, whatever killed it. Expired, already used, never
# existed and wrong purpose are one sentence on purpose: telling them apart
# would answer questions about somebody else's account for anybody guessing.
_DEAD_LINK = "That link does not work any more. Ask for a new one."


def _link_url(purpose: str, token: str) -> str:
    """The address a mail puts behind its button."""
    return f"{publicurl.base()}{_LINK_PATHS[purpose]}/{token}"


_LINK_PATHS = {
    onetime.SET_PASSWORD: "/set-password",
    onetime.RESET: "/reset",
    onetime.CONFIRM: "/confirm",
    onetime.INVITE: "/join",
}


def _with_csrf(request: Request, render, status_code: int = 200) -> Response:
    """One page, with a CSRF token minted on the way out. `render` takes the
    token and returns the HTML. The carrier trick is the login page's, named
    once here rather than copied into seven more handlers."""
    carrier = Response()
    token = _ensure_csrf(request, carrier)
    response = HTMLResponse(render(token), status_code=status_code)
    for key, value in carrier.raw_headers:
        if key == b"set-cookie":
            response.raw_headers.append((key, value))
    return _no_store(response)


def _after_link(request: Request, con, user_id: int) -> Response:
    """Signed in, the moment a link has been redeemed.

    An account with two-factor on gets a pending session and the code field,
    not a way past it: a link proves somebody reads that mailbox, which is not
    the same as holding the operator's authenticator.
    """
    user = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    owes_code = user is not None and accounts.totp_enabled(user)
    token, _ = accounts.issue_session(
        con, user_id, user_agent=request.headers.get("user-agent"),
        totp_pending=owes_code)
    response = _to_two_factor("/") if owes_code else RedirectResponse(
        url="/", status_code=303)
    _set_session_cookie(response, request, token)
    return _no_store(response)


def _send(subject: str, body: str, html_body: str, to: str) -> None:
    """One mail, to one address, or a line in the journal.

    A relay that will not take it is ours to see and never something to hand
    back to the page: on the reset flow it would say whether that address has
    an account here, because nothing is sent when it does not.

    The line says what failed and never to whom. A mail address goes into no
    log of ours (app/journal.py, SI-8), and `reason` is the class of failure
    `notify.send` hands back, never the relay's own text.
    """
    config = notify.config_from_env()
    if not config.host:
        print("no relay configured, so a link mail was not sent", file=sys.stderr)
        return
    one = replace(config, to=to, sender=config.sender or to)
    sent, reason = notify.send(subject, body, one, html_body)
    if not sent:
        print(f"a link mail did not go out: {reason}", file=sys.stderr)


# ------------------------------------------------------- forgot your password

@router.get("/forgot", response_class=HTMLResponse)
def forgot_page(request: Request) -> Response:
    if signed_in_user(request) is not None:
        return _no_store(RedirectResponse(url="/", status_code=303))
    return _with_csrf(request, lambda token: web_pages.reset_ask_page(csrf=token))


def _forgot_submit(request: Request, email: str, csrf: str) -> Response:
    """Ask for a reset link.

    **The answer never depends on whether the address has an account.** Same
    page, same words, same status, whether a mail went out or nothing
    happened at all. That is the whole reason this page exists in the shape it
    does: a reset form is the easiest way to ask a product who its customers
    are, and this one does not answer.
    """
    email = accounts.normalize_email(email)

    def again(error: str, code: int) -> Response:
        return _with_csrf(
            request,
            lambda token: web_pages.reset_ask_page(csrf=token, email=email, error=error),
            status_code=code)

    if not _csrf_ok(request, csrf):
        return again("That took too long and the form expired. Try again.", 400)
    if not accounts.valid_email(email):
        return again("That does not look like an email address.", 400)

    limiters = _limiters(request)
    # Both buckets, the same shape the login uses. The global one is what stops
    # a script walking a list of addresses to see which ones get mail.
    global_ok = limiters.login_global.allow(ratelimit.GLOBAL_KEY)
    email_ok = limiters.login_email.allow(email)
    if not (global_ok and email_ok):
        return again("Too many attempts. Wait a minute, then try again.", 429)

    if not notify.config_from_env().host:
        # No relay, so no link could reach anybody. One page for every
        # address, so it says nothing about who has an account, and no link
        # is issued that nobody can receive.
        print("no relay configured, so a link mail was not sent", file=sys.stderr)
        return _with_csrf(request, lambda _t: web_pages.no_link_sent_page())

    con = _connect()
    try:
        user = accounts.get_user_by_email(con, email)
        if user is not None and not user["disabled_at"]:
            token, _ = onetime.issue(con, onetime.RESET, email, user_id=user["id"])
            subject, body, html_body = notify.format_reset(
                email, _link_url(onetime.RESET, token))
            _send(subject, body, html_body, email)
    finally:
        con.close()
    return _with_csrf(
        request, lambda _t: web_pages.link_sent_page("Check your mail", email))


@router.post("/forgot", response_class=HTMLResponse)
async def forgot_submit(request: Request) -> Response:
    fields = await form_fields(request, "email", "csrf")
    return await run_in_threadpool(
        _forgot_submit, request, fields["email"], fields["csrf"])


# ------------------------------------------------- choosing a password

def _choose_password(request: Request, purpose: str, token: str,
                     error: str | None = None, status_code: int = 200) -> Response:
    """The form a reset link and a new account's link both land on."""
    con = _connect()
    try:
        link = onetime.look_up(con, purpose, token)
    finally:
        con.close()
    if link is None:
        return _with_csrf(
            request,
            lambda _t: web_pages.link_expired_page(),
            status_code=410)
    return _with_csrf(
        request,
        lambda csrf: web_pages.choose_password_page(
            csrf=csrf, action=f"{_LINK_PATHS[purpose]}/{quote(token, safe='')}",
            email=link["email"], error=error),
        status_code=status_code)


def _choose_password_submit(request: Request, purpose: str, token: str,
                            password: str, confirm: str, csrf: str) -> Response:
    """Set the password the link decided the account for.

    The address is never read from the form. The link says whose account this
    is, and a posted address would be a second opinion about that.
    """
    if not _csrf_ok(request, csrf):
        return _choose_password(request, purpose, token,
                                "That took too long and the form expired. Try again.", 400)
    if password != confirm:
        # Before the length rule, because "they do not match" is the more
        # useful thing to hear when both are also too short.
        return _choose_password(request, purpose, token, "Those two do not match.", 400)

    con = _connect()
    try:
        link = onetime.look_up(con, purpose, token)
        if link is None:
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        user = accounts.get_user_by_email(con, link["email"])
        if user is None or user["disabled_at"]:
            # The account went away between the mail and the click. Nothing is
            # wrong with the link, and there is nothing to set a password on.
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        try:
            accounts.check_password_shape(password)
        except accounts.AccountError as exc:
            return _choose_password(request, purpose, token, str(exc), 400)
        # Spent first, and the password set only when this call is the one that
        # spent it. Two clicks racing cannot both set a password.
        if not onetime.spend(con, link["id"]):
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        accounts.set_password(con, user["id"], password)
        # Every other session goes. Somebody resetting a password is somebody
        # who may have lost the old one to another person.
        accounts.revoke_all_sessions(con, user["id"])
        return _after_link(request, con, user["id"])
    finally:
        con.close()


@router.get("/reset/{token}", response_class=HTMLResponse)
def reset_page(request: Request, token: str) -> Response:
    return _choose_password(request, onetime.RESET, token)


@router.post("/reset/{token}", response_class=HTMLResponse)
async def reset_submit(request: Request, token: str) -> Response:
    fields = await form_fields(request, "password", "confirm", "csrf")
    return await run_in_threadpool(
        _choose_password_submit, request, onetime.RESET, token,
        fields["password"], fields["confirm"], fields["csrf"])


@router.get("/set-password/{token}", response_class=HTMLResponse)
def set_password_page(request: Request, token: str) -> Response:
    return _choose_password(request, onetime.SET_PASSWORD, token)


@router.post("/set-password/{token}", response_class=HTMLResponse)
async def set_password_submit(request: Request, token: str) -> Response:
    fields = await form_fields(request, "password", "confirm", "csrf")
    return await run_in_threadpool(
        _choose_password_submit, request, onetime.SET_PASSWORD, token,
        fields["password"], fields["confirm"], fields["csrf"])


# ------------------------------------------------------- confirming an email

def _confirm(request: Request, token: str) -> Response:
    """The link from the confirm mail, redeemed.

    It stamps the address as confirmed and signs the person in. **Nothing
    refuses an unconfirmed account yet**, so this records a fact rather than
    opening a gate: sign-ups are closed, and the gate is the beta's to add
    with the flow that issues these links.
    """
    con = _connect()
    try:
        link = onetime.look_up(con, onetime.CONFIRM, token)
        if link is None:
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        user = accounts.get_user_by_email(con, link["email"])
        if user is None or not onetime.spend(con, link["id"]):
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        accounts.mark_email_confirmed(con, user["id"])
        return _after_link(request, con, user["id"])
    finally:
        con.close()


@router.get("/confirm/{token}", response_class=HTMLResponse)
async def confirm_page(request: Request, token: str) -> Response:
    return await run_in_threadpool(_confirm, request, token)


# ------------------------------------------------------- joining a workspace

def _join_form(request: Request, token: str, name: str = "",
               error: str | None = None, status_code: int = 200) -> Response:
    con = _connect()
    try:
        link = onetime.look_up(con, onetime.INVITE, token)
        workspace = None
        if link is not None:
            workspace = db.workspace_by_id(con, link["workspace_id"])
    finally:
        con.close()
    if link is None or workspace is None:
        return _with_csrf(
            request,
            lambda _t: web_pages.link_expired_page(),
            status_code=410)
    return _with_csrf(
        request,
        lambda csrf: web_pages.join_page(
            csrf=csrf, action=f"/join/{quote(token, safe='')}",
            workspace=workspace["name"], invited_by=link["invited_by"] or "",
            role=link["role"] or "", name=name, error=error),
        status_code=status_code)


def _join_submit(request: Request, token: str, name: str, password: str,
                 confirm: str, csrf: str) -> Response:
    """Redeem an invitation: an account in the workspace the link names.

    The workspace comes from the link and never from the form, the same rule
    the reset flow keeps about the address.
    """
    if not _csrf_ok(request, csrf):
        return _join_form(request, token, name,
                          "That took too long and the form expired. Try again.", 400)
    if password != confirm:
        return _join_form(request, token, name, "Those two do not match.", 400)

    con = _connect()
    try:
        link = onetime.look_up(con, onetime.INVITE, token)
        if link is None:
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        if accounts.get_user_by_email(con, link["email"]) is not None:
            return _join_form(request, token, name,
                              "That address already has an account. Sign in instead.", 400)
        try:
            accounts.check_password_shape(password)
        except accounts.AccountError as exc:
            return _join_form(request, token, name, str(exc), 400)
        if not onetime.spend(con, link["id"]):
            return _with_csrf(
                request,
                lambda _t: web_pages.link_expired_page(),
                status_code=410)
        try:
            user_id = accounts.create_user(con, link["email"], password,
                                           workspace_id=link["workspace_id"])
        except accounts.AccountError as exc:
            return _join_form(request, token, name, str(exc), 400)
        if name.strip():
            accounts.set_display_name(con, user_id, name)
        return _after_link(request, con, user_id)
    finally:
        con.close()


@router.get("/join/{token}", response_class=HTMLResponse)
async def join_page(request: Request, token: str) -> Response:
    return await run_in_threadpool(_join_form, request, token)


@router.post("/join/{token}", response_class=HTMLResponse)
async def join_submit(request: Request, token: str) -> Response:
    fields = await form_fields(request, "name", "password", "confirm", "csrf")
    return await run_in_threadpool(
        _join_submit, request, token, fields["name"], fields["password"],
        fields["confirm"], fields["csrf"])


# Turning two-factor on is a window on the account's Security settings since
# 2026-09-10 (docs/RECORD.md 4.163), so it is two API routes in
# `app/ingest.py` rather
# than a page here. Turning it off stays `users_cli 2fa disable` on the box.


# ------------------------------------------------------------------ log out

@router.post("/logout")
def logout(request: Request) -> Response:
    """POST only, so a link or an image tag cannot sign somebody out.

    No CSRF token is asked for, and that is not an omission. SameSite=Lax means
    a cross-site POST arrives with no session cookie at all, so there is
    nothing for it to revoke.
    """
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        con = _connect()
        try:
            accounts.revoke_session(con, token)
        finally:
            con.close()
    response = RedirectResponse(url="/login?msg=signed-out", status_code=303)
    response.delete_cookie(SESSION_COOKIE)
    return _no_store(response)


# ------------------------------------------------------------------ who am I

@router.get("/api/auth/whoami")
def whoami(request: Request) -> Response:
    """Who this session belongs to. The account menu reads it once the
    dashboard is behind the session; today it is what proves the gate works
    from end to end.

    It answers 401 rather than an empty user, so a caller cannot mistake
    signed-out for signed-in-as-nobody.
    """
    user = require_user(request)
    return _no_store(JSONResponse({"email": user["email"]}))


# --------------------------------------------------------------- the gate check

@router.get("/api/auth/check")
def auth_check(request: Request) -> Response:
    """The one question Caddy's forward_auth asks before it serves the static
    dashboard: is this browser signed in?

    204 with an empty body when a live session cookie is present, 401 with an
    empty body when it is not. Caddy reads only the status: a 2xx lets the
    request through to the file server, and the non-2xx is what its
    handle_response turns into a redirect to /login (ops/RUNBOOK.md).

    It reveals nothing about accounts. The only input it reads is this
    request's own session cookie, never an email, so the two answers differ
    only by whether that cookie resolves to a live session. A signed-out
    caller, and one waving a made-up cookie, get the identical empty 401 and
    neither can learn whether any address has an account. No-store on both, so
    a per-request answer is never cached by the browser or by anything between.
    """
    if signed_in_user(request) is None:
        return _no_store(Response(status_code=401))
    return _no_store(Response(status_code=204))


# ------------------------------------------------------------- the dashboard
#
# **This reverses `docs/RECORD.md` 4.34 decision 2**, which said the dashboard
# is a static file that Caddy serves. It has to be reversed: which page a
# browser may see comes from its session, Caddy holds no session, and one file
# rendered for the whole fleet cannot show two people different things. Since
# 2026-08-25 (`docs/RECORD.md` 4.102) there is no file at all: the page is
# rendered from the database when the browser asks, so a reload after an
# action shows the action. `app/dashboard.py` owns the render call, and
# `ops/RUNBOOK.md` says what this means for the box.
#
# **The workspace comes from the session and never from the request.** None of
# these routes takes a workspace parameter, and there is nothing in a path, a
# query string or a header that reaches `dashboard.page`. The only input is
# the account behind the cookie. That is why there is no traversal to defend
# against here: the guard in `app/dashboard.py` is a second answer to a
# question this route already answers by having no first.
#
# The paths are written out rather than caught with a catch-all. The dashboard
# routes client side and a refresh on one of its addresses has to answer with
# the same shell, but a catch-all would answer HTML to a mistyped `/api/v1/`
# path an agent sent, and it would shadow every route added after it.
#
# The nav entries come from `site/app/build.py` NAV, and `/host/<name>` and its
# optional tab come from `viewToPath` in the same file. A nav entry added there
# and not added here lands on the fleet view after a refresh, which is what an
# address nobody has a view for already does (`applyPath`), so the failure is
# untidy rather than broken.
# `/admin` is here for the same reason as the rest: a refresh on the address
# the page put in the bar has to answer with the shell. Whether that shell
# carries the screen is decided below, from the session, and an account
# without the flag gets a page with no Admin view in it, which the page
# script then treats as the stale bookmark it is and lands on the fleet.
DASHBOARD_PATHS = ("/", "/alerts", "/integrations", "/settings", "/auth",
                  "/admin")


def _dashboard(request: Request) -> Response:
    """This session's workspace dashboard, or the way to get a session.

    A browser that owes a second factor goes back to the code page rather than
    to the login form, the same as `login_page` does, because its password is
    already proved and asking for it again would be theatre.
    """
    where = safe_next(request.url.path)
    user = signed_in_user(request)
    if user is None:
        if pending_user(request) is not None:
            return _no_store(_to_two_factor(where))
        return _no_store(RedirectResponse(
            url=f"/login?next={quote(where, safe='')}", status_code=303))
    return _no_store(_admin_aware_page(request, user))


def _admin_aware_page(request: Request, user, lookup=None) -> HTMLResponse:
    """This user's dashboard, with the Admin screen and its form token when
    the account carries the flag. The token is the one the sign-in form
    uses, minted on the response that carries the page, so the lookup's form
    can post with it. An ordinary account's page carries no token and no
    form: there is nothing on it that posts."""
    admin = accounts.is_admin(user)
    # The page needs the token before it is rendered, and the cookie is set
    # on the response that carries it, so the response is made first and the
    # page put into it after.
    response = HTMLResponse("")
    token = _ensure_csrf(request, response) if admin else ""
    response.body = dashboard.page(accounts.workspace_of(user), admin=admin,
                                   lookup=lookup, csrf=token).encode("utf-8")
    response.headers["content-length"] = str(len(response.body))
    # no-store, the same as every other page here. A dashboard is one
    # workspace's servers and must never sit in a shared cache, and a browser
    # that kept it would show it again after a sign-out.
    return response


for _path in DASHBOARD_PATHS:
    router.get(_path, response_class=HTMLResponse)(_dashboard)


@router.post("/admin/lookup", response_class=HTMLResponse)
async def admin_lookup(request: Request) -> Response:
    """The admin console's address lookup (docs/screens/admin/SPEC.md).

    A form that posts, never a query string: the address is somebody's who
    complained and must not land in an access log, a history or a proxy. It
    is read from the body, handed to the page, and kept nowhere: not logged,
    not stored, not put in the address bar. 404 without the flag, the same
    answer `/admin/workspace/{id}` gives a signed-in stranger; 400 without the
    page's own token, as the sign-in form refuses.
    """
    user = signed_in_user(request)
    if user is None:
        if pending_user(request) is not None:
            return _no_store(_to_two_factor("/admin"))
        return _no_store(RedirectResponse(url="/login?next=%2Fadmin", status_code=303))
    if not accounts.is_admin(user):
        raise HTTPException(status_code=404)
    fields = await form_fields(request, "address", "csrf")
    if not _csrf_ok(request, fields["csrf"]):
        raise HTTPException(status_code=400)
    return _no_store(_admin_aware_page(request, user, lookup=fields["address"]))


# ------------------------------------- an admin looking into a workspace
#
# **This is the one place in the application where a page shows a workspace
# other than the session's**, and it is a read. The owner asked for it on
# 2026-08-28 so that what a new signup actually sees is answerable
# (`docs/RECORD.md` 4.108), and the reasoning for allowing it at all is there.
#
# Three properties, and they are the whole of the argument:
#
#   - **The flag decides, and nothing else does.** Not a header, not a query
#     string, not the Caddy gate header, which is enough to reach the write
#     routes and is not an account. An account without the flag gets 404 here,
#     the same answer a workspace that does not exist gets, so this route tells
#     an ordinary account nothing about how many workspaces there are.
#   - **No write moves.** Every `/api/admin/*` route still acts on
#     `operator_workspace(request)`, which reads the session and never a path.
#     Nothing about that changes here, so the read is the only thing widened.
#     The page turns its own controls off as well, which stops a mis-click
#     acting on a server of your own with the same name.
#   - **The Admin screen is not on this render.** It is the whole service's
#     numbers and it belongs on your own page, not layered over somebody
#     else's, so the nav here is the nav they have.


@router.get("/admin/workspace/{workspace_id}", response_class=HTMLResponse)
def dashboard_as_workspace(request: Request, workspace_id: str) -> Response:
    """One workspace's dashboard, for an admin, read only.

    404 rather than 403 for an account without the flag. A 403 would confirm
    the route exists and that some workspace does, which is not a signed-in
    stranger's to learn, and there is nothing here they could do with it.
    """
    user = signed_in_user(request)
    if user is None:
        if pending_user(request) is not None:
            return _no_store(_to_two_factor(safe_next(request.url.path)))
        return _no_store(RedirectResponse(
            url=f"/login?next={quote(safe_next(request.url.path), safe='')}",
            status_code=303))
    if not accounts.is_admin(user):
        raise HTTPException(status_code=404)
    # The path segment is turned into an integer here rather than passed on as
    # text, so the only thing that can reach the render is a number.
    try:
        number = int(workspace_id)
    except ValueError:
        raise HTTPException(status_code=404)
    try:
        html = dashboard.page_for_workspace(number)
    except (dashboard.WorkspaceMissing, dashboard.WorkspaceIdError):
        raise HTTPException(status_code=404)
    return _no_store(HTMLResponse(html))


@router.get("/host/{rest:path}", response_class=HTMLResponse)
def dashboard_host(request: Request, rest: str) -> Response:
    """A host address, refreshed. `rest` is never read: the page routes client
    side from the address bar, so the shell is the whole answer, and reading it
    here would be reading the request for something the session already
    decided."""
    return _dashboard(request)
