"""The ingest service: the one endpoint agents talk to.

Kept deliberately small, because this is the process the internet can reach.
It does four things: check the bearer credential, cap the size, check the
envelope, store the document verbatim. It draws no conclusion and answers
nothing an agent could act on: the response to a report is 204 with an empty
body, which matches the agent's side of the contract, where no response byte
is ever parsed (docs/PRODUCT.md 4f).

Errors to the agent are status codes only. What failed and why goes to this
process's own log, never into a response body an attacker could probe with.

One side effect hangs off a stored report, and it is the only part of this
file that reads a header: the address the report arrived from is handed to
`app/authz.py` as half of the agent-derived proof SI-6 needs. It changes no
response, it cannot fail a report, and its trust boundary is written out in
full above `observed_source_address`. Read that before touching it.
"""

import contextlib
import ipaddress
import json
import logging
import sqlite3
import time
from dataclasses import replace
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from . import (accounts, alerts, authz, betasignup_routes, channels, cvedismiss, db, dispatch,
               displayname, feedback_routes, finding_alerts,
               hetzner, intent, join, journal, metrics, notify, prober,
               proberapi_routes, proberproofs,
               publicurl, ratelimit, rarelydismiss, renderbridge, scan, senders,
               slack_oauth,
               store, tags,
               totp, totp_qr, web_auth, web_pages)

log = logging.getLogger(__name__)

# A full host document from a busy machine (341 nftables rules on the live
# test box) is well under 1 MB. 8 MB is generous headroom, and above it the
# request is more likely hostile than real.
MAX_DOCUMENT_BYTES = 8 * 1024 * 1024

# The ingest has no browsable surface: no docs pages, no schema endpoint.
# Agents know the one path they need.
@contextlib.asynccontextmanager
async def _when_the_service_runs(_app):
    """Info lines reach the journal from the moment the service starts
    (app/journal.py says why they did not). When it starts and not at import,
    so importing this module from a command line tool changes nothing it
    prints."""
    journal.configure()
    yield


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=_when_the_service_runs)

# Sign in and sign out (app/web_auth.py), plus GET /api/auth/check, the probe a
# future Caddy forward_auth asks before serving the dashboard. Since the
# catch-all on app.whichports.com became a proxy to this app on 2026-08-23
# (ops/caddyfile.reference), /login, /logout and the rest of these routes are
# reachable to a browser that passed the outer basic auth. Replacing that outer
# password with the session check is the forward_auth migration, written out in
# ops/RUNBOOK.md and made on the box by hand.
app.include_router(web_auth.router)

# The login rate limiters, one set for the process. They live on app.state so a
# test builds an isolated set instead of reaching into module globals.
app.state.limiters = ratelimit.Limiters()


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "up"}


# ---------------------------------------------------------------- admin
# The dashboard's write actions. An admin action is let through on one proof
# that the caller is an operator: a live session, which this application
# issued and can revoke. Caddy proxies these routes to the app with nothing in
# front since 2026-09-03, and since 2026-09-12 the app reads no header as a
# second proof, because a header Caddy no longer stamps is a header anybody
# can type (require_operator).
#
# The properties of the session are web_auth.py's to state: the cookie is
# HttpOnly and SameSite, the row behind it has a TTL and can be revoked from the
# CLI, and a session that still owes a second factor is refused by
# resolve_session, so every gate here keeps saying signed out until the code
# lands.

def require_operator(request: Request) -> None:
    """Pass when the caller holds a live operator session, and refuse with
    403 otherwise.

    Until 2026-09-12 a header stamped by Caddy under basic auth,
    X-Admin-Gate, was accepted on its own as the second proof. Caddy stopped
    stamping it on 2026-09-03, when basic auth came off the dashboard, and
    nothing stripped it, so a browser could send it itself and reach every
    write route here with no credential at all. Measured from outside that
    day: a forged header answered 200 on whoami (docs/RECORD.md 4.171). A
    header is text anybody can type. The session is the one proof, and it
    is checked against a row this application wrote.
    """
    # web_auth is already imported at module top (it is where router lives),
    # and web_auth does not import ingest, so this reference adds no cycle.
    if web_auth.signed_in_user(request) is None:
        raise HTTPException(status_code=403)


def operator_workspace(request: Request) -> int:
    """Which workspace this operator's admin action works in.

    **The session decides and the request never does.** A signed-in operator
    works in their own account's workspace, read from the session cookie the
    same way `require_operator` reads it, so there is no field, header or path
    segment a caller can set to reach somebody else's servers.

    A request with no session is refused here as well, even though
    `require_operator` has already refused it on every route that calls
    this. Until 2026-09-12 such a request fell back to workspace 1, which
    was the basic-auth path and became the forged-header path. The second
    refusal is so a route that forgets the first can still never act in
    anybody's workspace.
    """
    user = web_auth.signed_in_user(request)
    if user is None:
        raise HTTPException(status_code=403)
    return accounts.workspace_of(user)


@app.get("/metrics")
def prometheus_metrics(request: Request) -> Response:
    """Scraped by whatever already watches the estate. It sits behind the
    same basic auth as the dashboard, which every Prometheus can send
    (basic_auth in the scrape config), so no second credential exists to
    leak. No session is required here: a scraper is not a browser, and
    Caddy is what authenticates it."""
    con = db.connect()
    try:
        db.init(con)
        body = metrics.render(con)
    finally:
        con.close()
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


@app.get("/api/admin/whoami")
def admin_whoami(request: Request) -> Response:
    """Who is signed in, for the account menu, with the account Settings
    screen's facts beside it (docs/screens/account-settings): whether the
    authenticator app is on, when the password was last set, and the
    workspace's name. Facts the account holds, never a secret: the TOTP
    secret and the hash stay where they are.

    The name rides alongside for the avatar chip: the one the account has
    stored, and empty when none is stored. Empty is a real answer rather
    than a guess derived from the email, and the page falls back on its own.

    Until 2026-09-12 a request with no session could reach this and be
    answered from the x-auth-user header Caddy stamped under basic auth. That
    path is gone with the gate header (`require_operator`), so the session
    is the only thing that answers, and a value in that header is text a
    caller typed.

    An answer about who is signed in is never cached, the same rule
    app/web_auth.py applies to its own whoami.
    """
    require_operator(request)
    user = web_auth.signed_in_user(request)
    answer = user["email"]
    name = accounts.display_name_of(user)
    totp = accounts.totp_enabled(user)
    changed = accounts.password_changed_at(user)
    con = db.connect()
    try:
        db.init(con)
        row = db.workspace_by_id(con, accounts.workspace_of(user))
    finally:
        con.close()
    workspace = row["name"] if row is not None else ""
    response = JSONResponse({"user": answer, "name": name, "totp": totp,
                             "password_changed_at": changed, "workspace": workspace})
    response.headers["Cache-Control"] = "no-store"
    return response


def _signed_in_or_403(request: Request):
    """The account behind the session, for a route that edits the account
    itself. The basic-auth path carries no account, so there is nothing for
    it to edit and the answer is a refusal rather than a guess at workspace
    1's owner. The gate has already been passed and the body already read,
    so a body nobody can parse is refused in this file's words first, the
    same as on every other write route."""
    user = web_auth.signed_in_user(request)
    if user is None:
        raise HTTPException(status_code=403, detail="Sign in to change this.")
    return user


@app.post("/api/admin/account/name")
async def admin_account_name(request: Request) -> Response:
    """The name on the account, from the Settings screen's Profile field."""
    require_operator(request)
    body = json_body(await request.body())
    user = _signed_in_or_403(request)
    name = body.get("name") if isinstance(body, dict) else None
    if not isinstance(name, str):
        raise HTTPException(status_code=400, detail="A name is text.")
    con = db.connect()
    try:
        db.init(con)
        try:
            accounts.set_display_name(con, user["id"], name)
        except accounts.AccountError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/account/password")
async def admin_account_password(request: Request) -> Response:
    """A new password, given the current one. The current password is
    checked first, so a session left open on a shared machine cannot lock
    its owner out. Other sessions stay: this is the screen's own change, not
    the CLI's "the old one is in the wrong hands" path."""
    require_operator(request)
    body = json_body(await request.body())
    user = _signed_in_or_403(request)
    current = body.get("current") if isinstance(body, dict) else None
    new = body.get("new") if isinstance(body, dict) else None
    if not isinstance(current, str) or not isinstance(new, str):
        raise HTTPException(status_code=400, detail="Both passwords are needed.")
    if not accounts.verify_password(current, user["password_hash"]):
        raise HTTPException(status_code=400, detail="The current password is not right.")
    con = db.connect()
    try:
        db.init(con)
        try:
            accounts.set_password(con, user["id"], new)
        except accounts.AccountError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        con.close()
    return Response(status_code=204)


# ------------------------------------------------------------ integrations
#
# The provider tokens, per workspace since 2026-09-14 (record 4.178), and as
# many per workspace as it has projects since 2026-09-27 (record 4.206). Four
# acts, each scoped to the session's workspace like every write here, and
# none of them ever returns a token: a response carries what the screen
# shows, the token's id and hint and the outcome of the last read.
#
# Connect adds a token. Replace token, Read now and Disconnect act on one,
# named by `token_id` in the body. Without it they act on the workspace's
# only token, which is how the screen worked while there could be one, and a
# workspace holding several is asked which rather than guessed for.
#
# Connect and Replace token read the provider at once, inside the request,
# so the row appears with a real status rather than a promise: a refused
# token is refused on the spot with the HTTP status the provider answered.
# The read is one GET per endpoint with a twenty second bound
# (app/hetzner.py), which is what a click may wait for. SI-3 and SI-5 hold
# the way they hold in the sweep: the client can only GET, the token is a
# Read token the customer created and can revoke, and nothing here asks for
# more.

# How a client is made from a stored token. A module attribute so the tests
# hand in a fake provider without touching the network.
hetzner_client = hetzner.client_for

NO_PROVIDER = "No provider is connected."


def _provider_body(raw: bytes) -> dict:
    """The body of a provider act. Read now and Disconnect were sent with no
    body until tokens had ids, and still may be, so an empty one is {}."""
    if not raw.strip():
        return {}
    body = json_body(raw)
    return body if isinstance(body, dict) else {}


def _which_token(con, workspace_id: int, body: dict) -> int:
    """The token an act is about: the one the body names, or the workspace's
    only one. 404 when this workspace holds no such token, the same answer a
    token of another workspace gets, and 400 when it holds several and the
    body names none."""
    named = body.get("token_id")
    held = [token["id"] for token in hetzner.tokens(con, workspace_id)]
    if named is None:
        if not held:
            raise HTTPException(status_code=404, detail=NO_PROVIDER)
        if len(held) > 1:
            raise HTTPException(status_code=400, detail="Say which token.")
        return held[0]
    if isinstance(named, bool) or not isinstance(named, int) or named not in held:
        raise HTTPException(status_code=404, detail=NO_PROVIDER)
    return named


def _provider_read(con, workspace_id: int, token_id: int, now: datetime) -> dict:
    """Read the provider with one of this workspace's tokens, store what came
    back or the typed failure under that token, and say which. Never the
    token, never the provider's own text."""
    token = hetzner.token_for(con, workspace_id, token_id)
    if not token:
        raise HTTPException(status_code=404, detail=NO_PROVIDER)
    client = hetzner_client(token)
    try:
        snapshot = client.fetch_snapshot()
    except hetzner.ProviderError as exc:
        hetzner.record_fetch(con, now, exc, workspace_id=workspace_id, token_id=token_id)
        refused = exc.kind in (hetzner.ERROR_UNAUTHORIZED, hetzner.ERROR_FORBIDDEN)
        return {"status": "refused" if refused else "failed", "kind": exc.kind,
                "http_status": exc.status, "read_at": now.isoformat()}
    hetzner.store_snapshot(con, snapshot, workspace_id=workspace_id, token_id=token_id)
    hetzner.record_fetch(con, now, workspace_id=workspace_id, token_id=token_id)
    return {"status": "connected", "kind": None, "http_status": None,
            "read_at": now.isoformat(), "servers": len(snapshot.servers),
            "firewalls": len(snapshot.firewalls)}


def _provider_json(con, workspace_id: int, token_id: int, outcome: dict) -> dict:
    held = next((t for t in hetzner.tokens(con, workspace_id) if t["id"] == token_id), {})
    return {"provider": hetzner.PROVIDER, "token_id": token_id,
            "token_hint": held.get("hint", ""), "token_set_at": held.get("set_at", ""),
            **outcome}


@app.post("/api/admin/integrations/hetzner", status_code=201)
async def admin_connect_provider(request: Request) -> Response:
    """Connect: hold one more token for this workspace and read with it at
    once. A token the workspace already holds is not added twice, it is read
    with again."""
    require_operator(request)
    workspace_id = operator_workspace(request)
    body = json_body(await request.body())
    token = body.get("token") if isinstance(body, dict) else None
    con = db.connect()
    try:
        db.init(con)
        hetzner.init(con)
        try:
            token_id, _hint = hetzner.add_token(con, token, workspace_id)
        except hetzner.TokenError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        outcome = _provider_read(con, workspace_id, token_id, datetime.now(timezone.utc))
        answer = _provider_json(con, workspace_id, token_id, outcome)
    finally:
        con.close()
    return JSONResponse(answer, status_code=201)


@app.post("/api/admin/integrations/hetzner/token")
async def admin_replace_provider_token(request: Request) -> Response:
    """Replace token: a new value in one held token's place, read with at
    once. The old value, and everything read with it, is gone the moment the
    new one is stored. A workspace holding none simply gets one, as it
    always has."""
    require_operator(request)
    workspace_id = operator_workspace(request)
    body = _provider_body(await request.body())
    token = body.get("token")
    con = db.connect()
    try:
        db.init(con)
        hetzner.init(con)
        try:
            if not hetzner.tokens(con, workspace_id) and body.get("token_id") is None:
                token_id, _hint = hetzner.add_token(con, token, workspace_id)
            else:
                token_id = _which_token(con, workspace_id, body)
                hetzner.replace_token(con, token_id, token, workspace_id)
        except hetzner.TokenError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        outcome = _provider_read(con, workspace_id, token_id, datetime.now(timezone.utc))
        answer = _provider_json(con, workspace_id, token_id, outcome)
    finally:
        con.close()
    return JSONResponse(answer, status_code=200)


@app.post("/api/admin/integrations/hetzner/read")
async def admin_read_provider(request: Request) -> dict:
    """Read now, with one token. 404 when this workspace holds no such token."""
    require_operator(request)
    workspace_id = operator_workspace(request)
    body = _provider_body(await request.body())
    con = db.connect()
    try:
        db.init(con)
        hetzner.init(con)
        token_id = _which_token(con, workspace_id, body)
        outcome = _provider_read(con, workspace_id, token_id, datetime.now(timezone.utc))
        return _provider_json(con, workspace_id, token_id, outcome)
    finally:
        con.close()


@app.post("/api/admin/integrations/hetzner/disconnect", status_code=204)
async def admin_disconnect_provider(request: Request) -> Response:
    """Disconnect one token: it, its snapshots and its fetch row go. The
    workspace's other tokens stay, another workspace's stay, and a token this
    workspace does not hold is a 404, the same answer a host in another
    workspace gets."""
    require_operator(request)
    workspace_id = operator_workspace(request)
    body = _provider_body(await request.body())
    con = db.connect()
    try:
        db.init(con)
        hetzner.init(con)
        token_id = _which_token(con, workspace_id, body)
        if not hetzner.disconnect(con, workspace_id, token_id):
            raise HTTPException(status_code=404, detail=NO_PROVIDER)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/workspace/name")
async def admin_workspace_name(request: Request) -> Response:
    """The workspace's name, from the Settings screen's Workspace field.
    The session decides which workspace, as every admin route does."""
    require_operator(request)
    body = json_body(await request.body())
    user = _signed_in_or_403(request)
    name = body.get("name") if isinstance(body, dict) else None
    if not isinstance(name, str):
        raise HTTPException(status_code=400, detail="A name is text.")
    con = db.connect()
    try:
        db.init(con)
        try:
            done = db.rename_workspace(con, accounts.workspace_of(user), name)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        con.close()
    if not done:
        raise HTTPException(status_code=404, detail="No such workspace.")
    return Response(status_code=204)


# ------------------------------------------- turning two-factor on, in place
#
# The authenticator app is set up in a window on the account's Security
# settings (the owner, 2026-09-10, docs/RECORD.md 4.163), so these two routes
# are what that window
# talks to. The arithmetic and the storage are `app/totp.py` and
# `app/accounts.py`, unchanged and already tested: this is the way in.
#
# **Turning it off is not here.** `accounts.disable_totp` is the lockout path
# and stays with `users_cli 2fa disable` on the box, which is what makes a
# lost phone a conversation with somebody who has a shell there.


@app.post("/api/admin/account/2fa/start")
async def admin_2fa_start(request: Request) -> Response:
    """Begin an enrolment and hand back what the window draws.

    The secret is returned once, in the two forms the window shows: the key in
    the groups the command line prints, and a QR of the `otpauth:` URI. It is
    on the account row from this moment and does nothing until a code confirms
    it, so an abandoned window never turns anything on and never locks anybody
    out. Asking again replaces an unconfirmed secret.
    """
    user = _signed_in_or_403(request)
    con = db.connect()
    try:
        db.init(con)
        accounts.init(con)
        try:
            secret = accounts.begin_totp_enrollment(con, user["id"])
        except accounts.AccountError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        con.close()
    uri = totp.otpauth_uri(secret, user["email"])
    # The matrix rather than a picture: the window draws it. Nothing in the
    # browser parses markup out of an answer, and the page still holds no
    # image and fetches nothing (docs/DESIGN.md section 4).
    response = JSONResponse({"groups": totp.format_secret_groups(secret),
                             "qr": totp_qr.qr_matrix(uri)})
    # A secret is never cached, the same rule every answer about an account
    # here follows.
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/admin/account/2fa/confirm")
async def admin_2fa_confirm(request: Request) -> Response:
    """Turn it on, once a code proves the app really holds the secret, and
    hand back the recovery codes.

    **This is the only moment those codes exist in readable form anywhere.**
    They are stored as hashes and no route hands them out again, so the window
    shows them once and says so.
    """
    require_operator(request)
    body = json_body(await request.body())
    user = _signed_in_or_403(request)
    code = body.get("code") if isinstance(body, dict) else None
    if not isinstance(code, str):
        raise HTTPException(status_code=400, detail="A code is text.")
    limiters = web_auth._limiters(request)
    # The same two buckets the login's second step charges, keyed the same
    # way, so a window is not a fresh set of attempts.
    if not (limiters.totp_global.allow(ratelimit.GLOBAL_KEY)
            and limiters.totp_user.allow(str(user["id"]))):
        raise HTTPException(status_code=429,
                            detail="Too many attempts. Wait a minute, then try again.")
    con = db.connect()
    try:
        db.init(con)
        accounts.init(con)
        try:
            codes = accounts.confirm_totp_enrollment(con, user["id"], code,
                                                     at_time=time.time())
        except accounts.AccountError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        con.close()
    response = JSONResponse({"codes": codes})
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/api/admin/signout")
def admin_signout(request: Request) -> Response:
    """Sign out. app/web_auth.py's logout is the one owner of what that
    means: revoke the server-side session, clear the cookie, land on the
    login page. This route only gives the account menu that behaviour at a
    path Caddy already proxies, so it defers rather than reimplements.

    POST only, for logout's own reason: a bare link must not sign somebody
    out. No operator gate, because with no session there is nothing to
    revoke and the redirect is still the right answer. This route used to
    answer 401 with a different Basic realm, which popped the browser's own
    password dialog on every click (the owner, 2026-08-23). It must never
    answer 401 again.
    """
    return web_auth.logout(request)


# One owner for "read the request body as JSON", because there were ten copies
# of it and five of them were wrong.
#
# `json.loads` on bytes decodes them itself, and it raises UnicodeDecodeError
# rather than JSONDecodeError for bytes that are not UTF-8. Five routes caught
# only the second one, so a body carrying an invalid byte answered 500 on a
# surface where every other refusal is a status code with one sentence. The
# comment on admin_add_channel named that as a separate fix and this is it.
#
# Measured before it was written: `{"name": "\xff\xfe"}` posted to
# /api/admin/hosts answered 500. The interesting part is that `\xff\xfe` on
# its own answers 400, because json.loads reads the leading two bytes as a
# UTF-16 byte order mark and fails on the JSON instead, which is why a casual
# test of "send rubbish" never found this.


def json_body(body: bytes):
    """The request body parsed as JSON, or a 400 in this file's words.

    Both exceptions, always. Nothing else in the application may spell this
    pair out again: a sixth wrong copy is exactly what happened last time.
    """
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="not JSON") from None


@app.post("/api/admin/hosts", status_code=201)
async def admin_add_host(request: Request) -> dict:
    require_operator(request)
    payload = json_body(await request.body())
    name = payload.get("name") if isinstance(payload, dict) else None
    kind = payload.get("kind", db.HOST_KIND_AGENT) if isinstance(payload, dict) else None
    if kind not in db.HOST_KINDS:
        raise HTTPException(status_code=400,
                            detail=f"kind must be one of {', '.join(db.HOST_KINDS)}")
    if kind == db.HOST_KIND_AGENT:
        # Asked before a server is made, so a malformed address refuses
        # without leaving a server behind whose command nobody was shown.
        _install_base()
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        try:
            if kind == db.HOST_KIND_ADDRESS:
                # A server watched from outside only: no credential, so no
                # install command either. What it can be probed on comes from
                # the addresses proved through the routes below.
                if not isinstance(name, str):
                    raise ValueError("an address host needs a name")
                host_id = store.add_address_host(con, name, workspace_id=workspace_id)
                row = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()
                return {"name": row["name"], "kind": db.HOST_KIND_ADDRESS}
            host_id, credential = store.add_host(con, name,
                                                 workspace_id=workspace_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="a host by this name exists")
        row = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()
    finally:
        con.close()
    # The credential appears exactly once, in this response, for the person
    # who is looking at the dashboard. Only its hash is stored.
    # The id is what the Add server window asks about the server's arrival
    # with, because the placeholder name below stops existing at the first
    # report (`admin_host_arrival`).
    return {"id": host_id, "name": row["name"], "kind": db.HOST_KIND_AGENT,
            "credential": credential, **_install_commands(credential)}


@app.get("/api/admin/hosts/arrival/{host_id}")
def admin_host_arrival(host_id: int, request: Request) -> dict:
    """Has this new server reported, and has it been measured from outside.

    What the Add server window asks every few seconds while it is open on the
    install command (docs/screens/add-server/BRIEF-arrival.md). A read of
    three facts the same workspace's dashboard already shows: the server's
    name, when its newest report arrived, and when the first probing pass of
    it finished. "How many ports are reachable" is deliberately not answered
    here. The window reads that off the Fleet row of the page itself, so the
    two can never show different numbers.

    By id, because a server made by the Agent card is called `new-xxxxxx`
    until its first report renames it to its own hostname. Unknown, revoked
    and another workspace's all answer the same 404, like every admin route.
    """
    require_operator(request)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        prober.init(con)
        host = store.host_by_id(con, host_id, workspace_id=workspace_id)
        if host is None or host["revoked_at"] is not None:
            raise HTTPException(status_code=404)
        first_pass = con.execute(
            "SELECT MIN(finished_at) AS at FROM probe_runs"
            " WHERE host_id = ? AND finished_at IS NOT NULL",
            (host_id,)).fetchone()
    finally:
        con.close()
    return {"name": host["name"], "reported_at": host["last_report_at"],
            "probed_at": first_pass["at"]}


# What the Add server window says when the address is malformed. The
# setting's name goes to the log and never to a screen, because a screen does
# not name our machinery.
NO_INSTALL_COMMAND = ("No install command could be made. This dashboard's own"
                      " address is not set right.")


def _install_base() -> str:
    """Where the install command enrols a server: this control plane's own
    address (app/publicurl.py), or a 500 in plain words, with the setting
    named in the log line beside it."""
    try:
        return publicurl.base()
    except publicurl.PublicUrlError as exc:
        log.error("no install command made: %s", exc)
        raise HTTPException(status_code=500,
                            detail=NO_INSTALL_COMMAND) from None


def _install_commands(credential: str) -> dict:
    """The install command is one line so it is one paste on the server.

    One command since 2026-09-12. Until then a second one carried the
    installer's --full-visibility flag, which widened the unit to four
    capabilities so the process behind a port could be named; the unit
    behind a port comes from the kernel at no privilege now
    (docs/RECORD.md 4.169, docs/AGENT-PRIVILEGE.md 12). Shared by the create
    route and the reissue route, so the two can never hand out different
    lines.

    **One pipe, and the enrolment is the installer's arguments**, since the
    installer of agent 0.1.12 (docs/RECORD.md 4.243). Until then this line
    chained three commands after the pipe with `&&`: enrol, turn the timer
    on, collect once. A pipe's exit status is its last command's, and a shell
    given nothing exits 0, so a download that failed carried on to "sudo:
    whichports-agent: command not found" (4.228). The installer now does the
    same three things itself, in the same order, each only when the one
    before it worked, and a script that arrived cut off runs nothing. With
    nothing after the pipe there is nothing to carry on to.

    The one collection at the end is why a working install reports in seconds
    and not after up to seventeen minutes, the wait for the timer's quarter
    hour (4.184, 4.187). It is the installer's last step now.
    """
    return {
        "install_command":
            "curl -fsSL https://get.whichports.com/install.sh | sudo sh -s --"
            " enroll"
            # This control plane's own address, so a self-hosted instance
            # enrols its servers to itself. Unset, it is
            # https://app.whichports.com, the line this always was.
            f" --server={_install_base()}"
            f" --credential={credential}"
            # A self-hosted control plane that uses our probers hands every
            # server it enrols the proof key, so the agent proves its own
            # addresses to the prober API with nothing typed by anyone
            # (app/proberapi.py). Empty here, where neither setting is set.
            f"{dispatch.prober_enroll_flags()}",
    }


@app.post("/api/admin/hosts/{name}/credential")
async def admin_reissue_credential(name: str, request: Request) -> dict:
    """A fresh credential and its install command, for a server whose agent
    has never spoken. `store.reissue_credential` owns when that is allowed
    and refuses everything else in words the screen can show."""
    require_operator(request)
    _install_base()
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        try:
            credential = store.reissue_credential(con, name,
                                                  workspace_id=workspace_id)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        if credential is None:
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return {"name": name, "credential": credential,
            **_install_commands(credential)}


@app.post("/api/admin/hosts/{name}/display-name")
async def admin_set_host_display_name(name: str, request: Request) -> dict:
    """Give a server the display name in the body and answer with what was
    stored, so the page can show the stored spelling at once. An empty one
    clears it. The server is still found by `name`, never by its display
    name. `app/displayname.py` owns what a display name may be."""
    require_operator(request)
    payload = json_body(await request.body())
    wanted = payload.get("display_name") if isinstance(payload, dict) else None
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        displayname.init(con)
        try:
            stored = displayname.set_display_name(con, name, wanted,
                                                  workspace_id=workspace_id)
        except displayname.DisplayNameError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if stored is None:
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return {"display_name": stored}


@app.post("/api/admin/hosts/{name}/rarely/{protocol}/{port}")
async def admin_dismiss_rarely_mark(name: str, protocol: str, port: int,
                                    request: Request) -> dict:
    """Dismiss the mark on one port of one server that should rarely face the
    internet, with {"dismissed": true}, or bring it back with false, and
    answer with what is stored now so the page can draw it at once.
    `app/rarelydismiss.py` owns which ports can be dismissed."""
    require_operator(request)
    payload = json_body(await request.body())
    wanted = payload.get("dismissed") if isinstance(payload, dict) else None
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        rarelydismiss.init(con)
        try:
            stored = rarelydismiss.set_dismissed(con, name, protocol, port, wanted,
                                                 workspace_id=workspace_id)
        except rarelydismiss.DismissError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if stored is None:
            # Unknown, removed and another workspace's answer alike, the same
            # 404 the tags route gives.
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return {"dismissed": stored}


@app.post("/api/admin/hosts/{name}/cve-mark/{protocol}/{port}")
async def admin_dismiss_cve_mark(name: str, protocol: str, port: int,
                                 request: Request) -> dict:
    """Dismiss the CVE check's mark on one port of one server, with
    {"dismissed": true}, or bring it back with false, and answer with what is
    stored now so the page can draw it at once. The request names a port and
    a yes or a no: which CVEs the mark stands for is worked out here
    (`app/cvedismiss.py`), from the server's newest report."""
    require_operator(request)
    payload = json_body(await request.body())
    wanted = payload.get("dismissed") if isinstance(payload, dict) else None
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        cvedismiss.init(con)
        try:
            stored = cvedismiss.set_dismissed(con, name, protocol, port, wanted,
                                              workspace_id=workspace_id)
        except cvedismiss.DismissError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if stored is None:
            # Unknown, removed and another workspace's answer alike, as the
            # rarely-public mark's route does.
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return {"dismissed": stored}


@app.post("/api/admin/hosts/{name}/tags")
async def admin_set_host_tags(name: str, request: Request) -> dict:
    """Replace a server's tags with the list in the body and answer with what
    was stored, so the page can show the stored spelling at once. An empty
    list clears them. `app/tags.py` owns what a tag may be."""
    require_operator(request)
    payload = json_body(await request.body())
    wanted = payload.get("tags") if isinstance(payload, dict) else None
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        tags.init(con)
        try:
            stored = tags.set_tags(con, name, wanted, workspace_id=workspace_id)
        except tags.TagError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if stored is None:
            # Unknown, removed and another workspace's answer alike, the same
            # 404 the display name gives.
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return {"tags": stored}


def _end_server_on_our_api(con, host, act: str) -> JSONResponse | None:
    """On an instance with prober lines, Remove and Delete end the server's
    addresses on our prober API first, each one no other server holds
    (`proberproofs.end_server`). A refusal or no answer is the answer, which
    side and its class, and the caller changes nothing. None to go on."""
    if not authz.proved_by_server(con, host["id"]):
        return None
    api, broken = _prober_api()
    if api is None and not broken:
        return None
    code = broken
    if api is not None:
        try:
            proberproofs.end_server(con, api, host, opener=proberproofs.opener())
        except proberproofs.NotRevoked as refused:
            code = refused.code
    if code is None:
        return None
    return JSONResponse({"detail": proberproofs.server_words(host["name"], act, code),
                         "code": code, "refused_by": proberproofs.PROBER_API},
                        status_code=502)


@app.post("/api/admin/hosts/{name}/revoke", status_code=204)
async def admin_revoke_host(name: str, request: Request) -> Response:
    require_operator(request)
    workspace_id = operator_workspace(request)
    # In the threadpool, because on an instance with prober lines it waits on
    # our API.
    return await run_in_threadpool(_remove_server, name, workspace_id)


def _remove_server(name: str, workspace_id: int) -> Response:
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            raise HTTPException(status_code=404)
        refused = _end_server_on_our_api(con, host, "removed")
        if refused is not None:
            return refused
        if not store.revoke_host(con, name, workspace_id=workspace_id):
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/delete", status_code=204)
async def admin_delete_host(name: str, request: Request) -> Response:
    """Delete a removed server with everything stored about it.

    A server still live is refused with 409: Remove first, then Delete, two
    typed names for two acts (docs/PRODUCT.md 4f). The 409 says only what
    the caller's own workspace already shows it, because the live lookup is
    scoped to that workspace exactly as the delete is, so another
    workspace's server answers the 404 an unknown name gets.
    """
    require_operator(request)
    workspace_id = operator_workspace(request)
    return await run_in_threadpool(_delete_server, name, workspace_id)


def _delete_server(name: str, workspace_id: int) -> Response:
    """A server removed before its addresses were ended on our prober API,
    before this or before the prober lines were set, has them ended here."""
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        if store.active_host_by_name(con, name, workspace_id=workspace_id) is not None:
            raise HTTPException(status_code=409, detail="remove the server first")
        removed = store.removed_host_by_name(con, name, workspace_id=workspace_id)
        if removed is not None:
            refused = _end_server_on_our_api(con, removed, "deleted")
            if refused is not None:
                return refused
        if not store.delete_host(con, name, workspace_id=workspace_id):
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/pause", status_code=204)
async def admin_pause_host(name: str, request: Request) -> Response:
    require_operator(request)
    payload = json_body(await request.body())
    paused = payload.get("paused") if isinstance(payload, dict) else None
    if not isinstance(paused, bool):
        raise HTTPException(status_code=400, detail="paused must be true or false")
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        if not store.pause_host(con, name, paused, workspace_id=workspace_id):
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return Response(status_code=204)


# --------------------------------------------------------------- addresses
#
# The addresses a host may be probed on, proved by the operator. These wrap
# `app/authz.py` and add nothing to it: what is proof, how it expires and
# what the gate says are decided there and only there. What this layer adds
# is the same operator gate and workspace scoping every host route has, so
# a proof started here belongs to this host in this workspace and to nobody
# else. Nothing here probes. The one remote read, in verify, fetches evidence
# the operator themself published at the address they nominated.
#
# The token appears exactly once, in the start response, for the person who
# is looking at the dashboard. Only its hash is stored, the same rule the
# enrolment credential follows.

ADDRESS_METHODS = {"dns-txt": authz.METHOD_DNS_TXT, "http-token": authz.METHOD_HTTP_TOKEN}


def _address_host(con, name: str, workspace_id: int):
    """The host these routes act on, or a 404 that reads the same for a host
    that is unknown, revoked, or somebody else's."""
    host = store.active_host_by_name(con, name, workspace_id=workspace_id)
    if host is None:
        raise HTTPException(status_code=404)
    return host


def _iso(value):
    return value if isinstance(value, str) else None


def _authorization_view(row) -> dict:
    return {
        "address": row["target"],
        "family": row["family"],
        "method": row["method"],
        "verified_at": _iso(row["verified_at"]),
        "expires_at": _iso(row["expires_at"]),
        "revoked_at": _iso(row["revoked_at"]),
        "expired_at": _iso(row["expired_at"]),
    }


def _challenge_view(row) -> dict:
    return {
        "id": row["id"],
        "address": row["target"],
        "family": row["family"],
        "method": row["method"],
        "publish_at": row["publish_at"],
        "expires_at": row["expires_at"],
    }


@app.get("/api/admin/hosts/{name}/addresses")
async def admin_list_addresses(name: str, request: Request) -> dict:
    require_operator(request)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        host = _address_host(con, name, workspace_id)
        listing = authz.addresses_for_host(con, host["id"])
        live = {(r["target"], r["family"])
                for r in authz.live_addresses_for_host(con, host["id"])}
        out = []
        for row in listing["authorizations"]:
            view = _authorization_view(row)
            view["live"] = (row["target"], row["family"]) in live
            out.append(view)
    finally:
        con.close()
    return {"authorizations": out,
            "open_challenges": [_challenge_view(r) for r in listing["open_challenges"]]}


def _prober_api():
    """This instance's prober lines (`app/proberproofs.py`): None when it has
    none, and then nothing here is sent anywhere. Half of them is answered
    as our API not answering, and nothing is proved here as if it could."""
    try:
        return proberproofs.prober_api(), None
    except dispatch.TransportConfigError:
        log.warning("address proof: %s and %s go together as an https address"
                    " and a key, so nothing was sent", dispatch.PROBER_API_ENV,
                    dispatch.PROBER_API_KEY_ENV)
        return None, dispatch.NO_ANSWER


def _not_started(address: str, code: str) -> JSONResponse:
    """A start our API refused or did not answer: which side, and its class.
    An address our API will never prove is the operator's to change, and the
    rest are ours, so they are a 502."""
    status = 400 if code == "target_refused" else 502
    return JSONResponse({"detail": proberproofs.start_words(address, code),
                         "code": code, "refused_by": proberproofs.PROBER_API},
                        status_code=status)


@app.post("/api/admin/hosts/{name}/addresses", status_code=201)
async def admin_start_address_proof(name: str, request: Request):
    require_operator(request)
    payload = json_body(await request.body())
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="expected an object")
    address = payload.get("address")
    method = ADDRESS_METHODS.get(payload.get("method"))
    if not isinstance(address, str) or not address.strip():
        raise HTTPException(status_code=400, detail="address is required")
    if method is None:
        raise HTTPException(status_code=400,
                            detail=f"method must be one of {', '.join(ADDRESS_METHODS)}")
    workspace_id = operator_workspace(request)
    # In the threadpool, because on an instance with prober lines it waits on
    # our API.
    return await run_in_threadpool(_start_address_proof, name, workspace_id,
                                   address.strip(), method, payload.get("method"))


def _start_address_proof(name: str, workspace_id: int, address: str, method: str,
                         word: str):
    api, broken = _prober_api()
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        proberproofs.init(con)
        host = _address_host(con, name, workspace_id)
        try:
            if broken:
                # Checked here first, so the answer for an address that can
                # never be a target does not depend on the prober lines.
                return _not_started(authz.normalise_target(address)[0], broken)
            if api is None:
                challenge = authz.start_proof(con, address, method,
                                              account=authz.account_for_host(host),
                                              host_id=host["id"])
            else:
                challenge = proberproofs.start(con, api, host, address, method,
                                               opener=proberproofs.opener())
        except authz.TargetError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except proberproofs.NotStarted as refused:
            return _not_started(authz.normalise_target(address)[0], refused.code)
    finally:
        con.close()
    return {
        "id": challenge.id,
        "address": challenge.target,
        "family": challenge.family,
        "method": word,
        "token": challenge.token,
        "publish_at": challenge.publish_at,
        "expires_at": challenge.expires_at,
    }


# A plain `def`, so FastAPI runs it in the threadpool: reading the evidence
# takes a DNS or an HTTP timeout, and on an instance with prober lines our
# API's reading comes first.
@app.post("/api/admin/hosts/{name}/addresses/{challenge_id}/verify")
def admin_verify_address_proof(name: str, challenge_id: int,
                               request: Request) -> dict:
    require_operator(request)
    workspace_id = operator_workspace(request)
    api, broken = _prober_api()
    refused_by = None
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        proberproofs.init(con)
        host = _address_host(con, name, workspace_id)
        row = authz.challenge_for_host(con, challenge_id, host["id"],
                                       authz.account_for_host(host))
        if row is None:
            raise HTTPException(status_code=404)
        if broken:
            result = authz.ProofResult(False, proberproofs.verify_words(row["target"], broken),
                                       code=broken)
            refused_by = proberproofs.PROBER_API
        elif api is None:
            result = authz.verify_proof(con, challenge_id)
        else:
            verified = proberproofs.verify(con, api, row, opener=proberproofs.opener())
            result, refused_by = verified.result, verified.refused_by
        # The row the registry just wrote, read back and never written here.
        proved = [live for live in authz.live_addresses_for_host(con, host["id"])
                  if result.recorded and live["id"] == result.authorization_id]
    finally:
        con.close()
    # A proof that did not verify is an answer, not an error: the screen shows
    # the reason and the operator fixes what they published.
    #
    # `code` is the registry's own typed outcome (`authz.PROOF_CODES`), and it
    # is what the window acts on, never the wording of a sentence. For a
    # recorded proof the sentence is the one the address's row will carry,
    # from the renderer's own function: the registry's sentence names the way
    # by its code word, which no screen shows (docs/RECORD.md 4.379).
    #
    # On an instance with prober lines the answer also names the side that
    # did not prove it, `refused_by`, None when both did
    # (`app/proberproofs.py`). Without them it is the answer it always was.
    detail = result.reason
    if proved:
        detail = renderbridge.load().proof_yes_words(proved[0])
    answer = {"ok": result.recorded, "code": result.code, "detail": detail}
    if api is not None or broken:
        answer["refused_by"] = refused_by
    return answer


@app.post("/api/admin/hosts/{name}/addresses/revoke", status_code=204)
async def admin_revoke_address(name: str, request: Request) -> Response:
    require_operator(request)
    payload = json_body(await request.body())
    address = payload.get("address") if isinstance(payload, dict) else None
    if not isinstance(address, str) or not address.strip():
        raise HTTPException(status_code=400, detail="address is required")
    workspace_id = operator_workspace(request)
    # In the threadpool, because on an instance with prober lines it waits on
    # our API.
    return await run_in_threadpool(_revoke_address, name, workspace_id,
                                   address.strip())


def _not_revoked(address: str, code: str) -> JSONResponse:
    """A revoke our API refused or did not answer, which changed nothing
    here: which side, and its class, the shape a refused start has."""
    status = 400 if code == "target_refused" else 502
    return JSONResponse({"detail": proberproofs.revoke_words(address, code),
                         "code": code, "refused_by": proberproofs.PROBER_API},
                        status_code=status)


def _revoke_address(name: str, workspace_id: int, address: str) -> Response:
    """On an instance with prober lines our API is asked first, because its
    registry decides what our probers touch (`app/proberproofs.py`)."""
    api, broken = _prober_api()
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        host = _address_host(con, name, workspace_id)
        try:
            if broken:
                return _not_revoked(authz.normalise_target(address)[0], broken)
            if api is None:
                authz.revoke(con, address, account=authz.account_for_host(host))
            else:
                proberproofs.revoke(con, api, address,
                                    account=authz.account_for_host(host),
                                    opener=proberproofs.opener())
        except authz.TargetError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except proberproofs.NotRevoked as refused:
            return _not_revoked(authz.normalise_target(address)[0], refused.code)
    finally:
        con.close()
    return Response(status_code=204)


# ------------------------------------------------------------------- mute
#
# Stop one server mailing, from the dashboard's own button. The store and every
# rule about what a mute means are `app/finding_alerts.py`'s, including that a
# muted server still raises and still shows and only stops mailing
# (docs/PRODUCT.md 4c). These two routes read a body, check it, and hand it
# down.
#
# **Muting is not pausing.** Pausing suppresses the silence alert about the
# agent (`store.pause_host`), muting suppresses the letter about a finding.
# They are two controls over two different things and neither is a spelling of
# the other.

# The longest mute a request may ask for, and it exists for two reasons. A
# number with no ceiling overflows the date arithmetic that turns it into an
# expiry, which would be a 500 anybody could ask for. And past a year the
# honest control is the one that carries no expiry at all, because a date
# nobody will be here for is not a date.
MAX_MUTE_SECONDS = 365 * 24 * 60 * 60


def _mute_seconds(payload) -> int | None:
    """How long the mute lasts, from the request body, or None for no expiry.

    Two shapes and no others: `{"seconds": N}` with a whole number of them, and
    `{"indefinite": true}`. A body carrying both is refused rather than letting
    one half win quietly, because the two say different things and we cannot
    know which one the caller meant.
    """
    fields = payload if isinstance(payload, dict) else {}
    indefinite = fields.get("indefinite", False)
    if not isinstance(indefinite, bool):
        raise HTTPException(status_code=400,
                            detail="indefinite must be true or false")
    seconds = fields.get("seconds")
    if indefinite:
        if seconds is not None:
            raise HTTPException(status_code=400,
                                detail="say seconds or indefinite, not both")
        return None
    # bool is excluded explicitly because Python's bool is an int, the same
    # door parse_envelope puts in front of the envelope's own numbers.
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise HTTPException(status_code=400,
                            detail="seconds must be a whole number")
    if seconds <= 0:
        raise HTTPException(status_code=400,
                            detail="seconds must be more than zero")
    if seconds > MAX_MUTE_SECONDS:
        raise HTTPException(status_code=400,
                            detail="that is longer than a year, mute it until"
                                   " you turn it back on instead")
    return seconds


def _mute_tables(con: sqlite3.Connection) -> None:
    """The additive schema these two routes need, the same pattern
    admin_scan_host follows for the prober's. alerts first: a recorded change
    points at the alert it raised, so that table has to exist before the one
    referencing it."""
    alerts.init(con)
    finding_alerts.init(con)


@app.post("/api/admin/hosts/{name}/mute", status_code=204)
async def admin_mute_host(name: str, request: Request) -> Response:
    """Stop this server mailing, for a while or until it is turned back on."""
    require_operator(request)
    payload = json_body(await request.body())
    seconds = _mute_seconds(payload)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        _mute_tables(con)
        # Unknown, revoked and belonging to another workspace all 404, the same
        # as the other admin routes. Asked here rather than left to the store,
        # because the store's own lookup accepts a revoked host.
        if store.active_host_by_name(con, name, workspace_id=workspace_id) is None:
            raise HTTPException(status_code=404)
        finding_alerts.mute_host(con, name, seconds=seconds,
                                 workspace_id=workspace_id)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/unmute", status_code=204)
async def admin_unmute_host(name: str, request: Request) -> Response:
    """Let this server mail again.

    **Its own route rather than a zero on the one above.** Zero is not a
    length, so a request that lost its number on the way would read as "stop
    being quiet" instead of being refused, and that is the direction of failure
    that loses somebody's quiet without telling them. Here every number is a
    length and this path is the only way back.

    204 whether or not a mute was live, because the answer is about the state
    the caller asked for and that state holds either way. A mute that expired a
    minute before the click is not an error to show anybody.
    """
    require_operator(request)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        _mute_tables(con)
        if store.active_host_by_name(con, name, workspace_id=workspace_id) is None:
            raise HTTPException(status_code=404)
        finding_alerts.unmute_host(con, name, workspace_id=workspace_id)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/scan")
async def admin_scan_host(name: str, request: Request) -> dict:
    """Re-probe one host's joined port set from outside, on demand. Host page
    only and rate limited per host (app/scan.py, docs/PRODUCT.md 5f).

    It cannot refresh the inside view, because SI-2 forbids a command channel to
    the agent, so the response also carries the one-shot command the operator
    runs by hand on the box to refresh it. That command is a string they run,
    never something sent anywhere.
    """
    require_operator(request)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        scan.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            # Unknown, revoked and belonging to another workspace all 404, the
            # same as the other admin routes.
            raise HTTPException(status_code=404)
        result = scan.request_scan(con, host["id"], now=datetime.now(timezone.utc))
        if result.accepted:
            # Fire the responder immediately by touching the trigger file. Best
            # effort, and it must never fail the request: the request is already
            # recorded, and the next fast-lane pass covers it within about ten
            # minutes even if this write cannot happen. So a failure is logged
            # and swallowed rather than turned into an error the caller sees. It
            # is not a warning downgraded to keep output clean, it is a side
            # effect kept off the request's path (the shape _record_observed_proof
            # takes below, and for the same reason).
            try:
                scan.touch_trigger(scan.trigger_path())
            except Exception:
                log.exception("could not touch the scan trigger for host %s, the"
                              " request is recorded and the next fast-lane pass"
                              " will cover it", host["id"])
    finally:
        con.close()
    return {
        "accepted": result.accepted,
        "sentence": result.sentence,
        "retry_after": result.retry_after,
        # The inside view is refreshed by the operator, never by us (SI-2). The
        # host is already enrolled, so no credential is needed and none appears
        # here. Returned even on a refusal, because a person may still want to
        # refresh the inside view while the outside re-probe is on cooldown.
        "oneshot_command": "sudo whichports-agent --mode=oneshot",
    }


# --------------------------------------------------------- reviewing one port
#
# **An acknowledgement is about one finding and never about a server.** One
# host, one protocol, one port, one address family, which is the key
# `app/intent.py` has stored it under since the day it was written. There is no
# host-wide acknowledge in the store and there was never meant to be one.
# The owner, 2026-08-24, on the header button this route replaces: a review is
# of one rule, not of a whole server (docs/RECORD.md 4.101).
#
# **The path names the port, and that is why it is this long.**
# /api/admin/hosts/{name}/acknowledge would read as acknowledging the host, and
# that reading is the mistake being corrected. The four segments after the host
# name are the four parts of the store's key, in the order that module writes
# them, so the URL cannot be misread and cannot be pointed at anything wider.
#
# **The state is read here, never taken from the caller.**
# `app/intent_cli.py` does the same and says why: an acknowledgement can never
# be filed against a finding nobody produced. A body carrying a state would let
# a caller acknowledge one that does not exist, and the whole expiry rule rests
# on the stored state being the one that was really there.
#
# Everything else is the shape `admin_pause_host` has: the same operator gate,
# 403 without it, 404 for a host this operator cannot reach, 400 for an argument
# that is not a port. The one code it adds is 409, for a request that is well
# formed and names a real host and still cannot be honoured because the port has
# no finding to review. That is not the caller malformed and it is not a missing
# host, so neither 400 nor 404 says it.


def _port_number(port: str) -> int:
    """The port out of the path as a whole number, or a 400 in this file's words.

    Declared as text in the route signature on purpose. With `port: int`
    FastAPI answers 422 in its own validation shape, and every other refusal on
    this surface is a status code with one sentence.

    ASCII digits only. `str.isdigit` is true for other scripts' digits and
    `int` accepts them, so "٤٤٣" would quietly become 443 and a URL nobody
    typed would act on a port.
    """
    if not (port.isascii() and port.isdigit()):
        raise HTTPException(status_code=400, detail="port must be a whole number")
    return int(port)


def _finding_for_port(con: sqlite3.Connection, host_id: int, protocol: str,
                      port: int, family: str):
    """The finding the join engine produces for one port right now, or None.

    Read through `app/join.py` rather than rebuilt here, so the state an
    acknowledgement is filed against is the state the screen shows. The same
    shape `app/intent_cli.py._finding_for` takes and for the same reason.
    """
    result = join.host_findings(con, host_id)
    if result is None:
        return None
    for finding in result.findings:
        if (finding.protocol, finding.port, finding.family) == (protocol, port,
                                                                family):
            return finding
    return None


@app.post("/api/admin/hosts/{name}/first-look", status_code=204)
async def admin_first_look(name: str, request: Request) -> Response:
    """Record that this server's first-look window has been seen, so it opens
    on its own for nobody in the account again (docs/RECORD.md 4.150)."""
    require_operator(request)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        intent.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            raise HTTPException(status_code=404)
        intent.mark_first_look(con, name)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/ports/{protocol}/{port}/{family}/acknowledge",
          status_code=204)
async def admin_acknowledge_port(name: str, protocol: str, port: str,
                                 family: str, request: Request) -> Response:
    """Record that one port's finding on one address family has been read."""
    require_operator(request)
    port_number = _port_number(port)
    try:
        protocol, port_number, family = intent.normalise(protocol, port_number,
                                                         family)
    except intent.IntentError as exc:
        # intent.py already says which argument is wrong, in words an operator
        # can act on, so the sentence is passed through rather than restated.
        raise HTTPException(status_code=400, detail=str(exc))
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        # Both additive, the same reason admin_scan_host calls scan.init: the
        # join engine reads the prober's tables and the acknowledgement is
        # written into intent's, and neither pair exists on a box where only
        # the ingest has ever run.
        prober.init(con)
        intent.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            # Unknown, revoked and belonging to another workspace all 404, the
            # same as the other admin routes. **This is also the whole of the
            # workspace scoping for this route**: intent.acknowledge looks a
            # host up by name across every workspace, and a host name is unique
            # over the whole table (app/db.py), so the row gated here is the row
            # it will find.
            raise HTTPException(status_code=404)
        finding = _finding_for_port(con, host["id"], protocol, port_number,
                                    family)
        if finding is None:
            raise HTTPException(
                status_code=409,
                detail=f"nothing has raised {protocol}/{port_number} on {family}")
        if finding.state is None:
            # docs/PRODUCT.md 8a: a port whose evidence supports none of the
            # five states has no state, and there is no finding to file
            # against. intent.acknowledge would refuse the empty state anyway,
            # and refusing it here is what turns that into an answer the screen
            # can show.
            raise HTTPException(
                status_code=409,
                detail=f"{protocol}/{port_number} on {family} has no state")
        try:
            intent.acknowledge(con, host["name"], protocol, port_number, family,
                               finding.state)
        except intent.IntentError as exc:
            # The store has doors this route has already been through, so
            # reaching one means the two disagree. It is still surfaced as a
            # refusal carrying the store's own sentence rather than becoming a
            # 500.
            raise HTTPException(status_code=409, detail=str(exc))
    finally:
        con.close()
    return Response(status_code=204)


# --------------------------------------------------- the ports being watched
#
# **Without these routes the agentless tier cannot be probed at all.** A host
# with no agent has no document, so its probe plan takes its ports from the
# joined set alone (`app/dispatch.py`), which is what the operator declared
# plus what a previous pass measured. A host that has neither has an empty
# port set, `prober_cli` refuses to hand an empty plan to the engine, and
# nothing is ever measured, so nothing is ever measured again. These routes
# are the way out of that: the operator says which ports to watch and the
# next pass has something to probe.
#
# Every rule about what a declaration is belongs to `app/intent.py` and none
# of it is restated here. This layer reads the request, puts it through that
# module's own doors, and turns an IntentError into a refusal carrying that
# module's own sentence, the way the acknowledge route does.
#
# **The path is the acknowledge route's path.** Four segments after the host
# name, in the order `app/intent.py` keys a declaration, so one host's ports
# read the same way whichever of the two actions is being taken. `/declare`
# and `/clear` are two paths rather than one with a field, for the reason
# `admin_unmute_host` gives: a request that lost its body must not fall
# through to the other meaning.
#
# **Workspace scoping is the host lookup here and nowhere else**, the same as
# the acknowledge route: `intent.declare` looks a host up by name across every
# workspace, and a host name is unique over the whole table (`app/db.py`), so
# the row gated here is the row it will find.


def _declaration_view(row) -> dict:
    return {
        "protocol": row["protocol"],
        "port": row["port"],
        "family": row["family"],
        "intent": row["intent"],
        "declared_at": row["declared_at"],
    }


def _port_key(protocol: str, port: str, family: str) -> tuple[str, int, str]:
    """The three parts of a port's identity out of the path, or a 400.

    `intent.normalise` is the same door `app/intent_cli.py` and the
    acknowledge route go through, and its sentences already name the argument
    that is wrong, so they are passed through rather than restated.
    """
    number = _port_number(port)
    try:
        return intent.normalise(protocol, number, family)
    except intent.IntentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/admin/hosts/{name}/ports")
async def admin_list_ports(name: str, request: Request) -> dict:
    """Every port declaration live on this host right now."""
    require_operator(request)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        intent.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            raise HTTPException(status_code=404)
        rows = intent.list_declarations(con, host["name"])
    finally:
        con.close()
    return {"declarations": [_declaration_view(row) for row in rows]}


@app.post("/api/admin/hosts/{name}/ports/{protocol}/{port}/{family}/declare",
          status_code=204)
async def admin_declare_port(name: str, protocol: str, port: str, family: str,
                             request: Request) -> Response:
    """Say what one port on one address family is meant to be.

    204 rather than 201, because a declaration replaces any live one for the
    same port and the caller learns nothing from being told which of the two
    happened. What was there before is history in the table either way.
    """
    require_operator(request)
    protocol, port_number, family = _port_key(protocol, port, family)
    try:
        payload = json.loads(await request.body())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400, detail="not JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="expected an object")
    try:
        value = intent.normalise_intent(payload.get("intent"))
    except intent.IntentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        # Additive, the same reason admin_acknowledge_port calls it: these
        # tables arrive after the four production already had.
        intent.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            # Unknown, revoked and belonging to another workspace all 404, the
            # same as the other admin routes.
            raise HTTPException(status_code=404)
        try:
            intent.declare(con, host["name"], protocol, port_number, family,
                           value, account=authz.account_for_host(host))
        except intent.IntentError as exc:
            # The store has doors this route has already been through, so
            # reaching one means the two disagree. Surfaced as a refusal
            # carrying the store's own sentence rather than becoming a 500.
            raise HTTPException(status_code=409, detail=str(exc))
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/ports/{protocol}/{port}/{family}/clear",
          status_code=204)
async def admin_clear_port(name: str, protocol: str, port: str, family: str,
                           request: Request) -> Response:
    """Withdraw a declaration.

    204 whether or not one was live, the answer `admin_unmute_host` gives and
    for the same reason: the caller asked for this port to carry no
    declaration and it carries none either way.
    """
    require_operator(request)
    protocol, port_number, family = _port_key(protocol, port, family)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        intent.init(con)
        host = store.active_host_by_name(con, name, workspace_id=workspace_id)
        if host is None:
            raise HTTPException(status_code=404)
        intent.clear(con, host["name"], protocol, port_number, family)
    finally:
        con.close()
    return Response(status_code=204)


# --------------------------------------------- switching one port's alerts off
#
# `docs/PRODUCT.md` 4c asks for a permanent per-port silence "without an
# argument from a settings page". It has existed in `app/finding_alerts.py`
# since the alerting engine landed and `app/silence_cli.py` could reach it, so
# the only person who could switch a port's alerts off was one with a shell on
# the control plane. These two routes are the dashboard's way in, and the
# Alerts screen is where they are used: an open alert names a port, and the
# thing you want to say about a port you have decided you do not care about is
# said on the row that keeps telling you about it.
#
# **A silence is not a resolution and these routes do not touch the alert.** It
# stops the mail, the alert stays open and stays on the screen, which is
# `alerts.suppress_alert`'s own rule and 4c's wording: changes are still
# recorded, they just do not mail. A route here that closed the alert as well
# would be a monitoring tool hiding a live finding on a click, and the port's
# state on its own row would then disagree with the alerts screen.
#
# **Two paths rather than one carrying a field**, the reason `admin_unmute_host`
# gives: a request that lost its body must not fall through to the other
# meaning, and the direction of that failure is the one that loses somebody's
# quiet without telling them.
#
# Workspace scoping is the host lookup and nowhere else, the same as the
# acknowledge and declare routes above: `finding_alerts.silence_port` looks a
# host up by name across every workspace, and a host name is unique over the
# whole table (`app/db.py`), so the row gated here is the row it will find.


@app.post("/api/admin/hosts/{name}/ports/{protocol}/{port}/{family}/silence",
          status_code=204)
async def admin_silence_port(name: str, protocol: str, port: str, family: str,
                             request: Request) -> Response:
    """Never mail about this port on this address family again.

    204 whether or not one was already live, the answer `admin_clear_port` and
    `admin_unmute_host` both give: the caller asked for this port to be quiet
    and it is quiet either way. `finding_alerts.silence_port` withdraws any
    live silence before writing its own, so a second click leaves one row live
    rather than two.
    """
    require_operator(request)
    protocol, port_number, family = _port_key(protocol, port, family)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        # Additive, the same reason admin_mute_host calls it. alerts first: a
        # recorded change points at the alert it raised, so that table has to
        # exist before the one referencing it.
        _mute_tables(con)
        if store.active_host_by_name(con, name, workspace_id=workspace_id) is None:
            # Unknown, revoked and belonging to another workspace all 404, the
            # same as the other admin routes.
            raise HTTPException(status_code=404)
        finding_alerts.silence_port(con, name, protocol, port_number, family,
                                    workspace_id=workspace_id)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/hosts/{name}/ports/{protocol}/{port}/{family}/unsilence",
          status_code=204)
async def admin_unsilence_port(name: str, protocol: str, port: str, family: str,
                               request: Request) -> Response:
    """Let this port mail again.

    204 whether or not a silence was live, for the reason `admin_unmute_host`
    gives about its own pair: the answer is about the state the caller asked
    for and that state holds either way.
    """
    require_operator(request)
    protocol, port_number, family = _port_key(protocol, port, family)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        _mute_tables(con)
        if store.active_host_by_name(con, name, workspace_id=workspace_id) is None:
            raise HTTPException(status_code=404)
        finding_alerts.unsilence_port(con, name, protocol, port_number, family,
                                      workspace_id=workspace_id)
    finally:
        con.close()
    return Response(status_code=204)


# ------------------------------------------------------------- channels
#
# Where alerts go, managed from the dashboard. Every rule about what a channel
# may be lives in `app/channels.py` and this file adds none of its own: it
# reads the body, checks that each field is text, hands it down, and turns a
# ChannelError into a 400 carrying that module's own sentence and, beside it,
# the field and the reason the refusal names (`_channel_refusal`). The
# sentence is for a person at a terminal. The screen says its own words at
# the field.
#
# **There is no send-test endpoint here, and the next person will ask why.**
# Sending a test message needs the destination, and a destination lives in an
# environment variable that only the sweep unit reads. ops/whichports-sweep.service
# is the one unit carrying EnvironmentFile=-/etc/whichports/alerts.env, and
# ops/whichports-ingest.service carries no credential at all. That split is the
# design rather than an accident (docs/RECORD.md 4.87): the unit that renders
# and the unit that sends are separate units with separate environments, and
# only one of them should ever see a relay password. A test button here would
# mean handing this process every channel credential, so the set of processes
# holding secrets would grow to buy a convenience. Writing a row is fine,
# because a row holds a variable's name and never its value.
#
# The label in the path is used as a bound parameter by app/channels.py and is
# never built into SQL or into a message, so anything a request can put there
# either matches a live channel or is a 404.

# Every field of a create request is text. Checked here because JSON can carry
# a list where a string belongs and channels.py's rules are written for
# strings, so a list would raise AttributeError deep inside instead of the 400
# the operator should get. The same door admin_pause_host puts in front of
# `paused`. `chat_id` is optional, and a missing one is an empty one.
# `destination` is the ordinary way and `env` is the other one. A request
# carries one of the two, and `channels.add` refuses both together and neither.
CHANNEL_FIELDS = ("type", "label", "env", "chat_id", "destination")


def _channel_text_fields(payload) -> dict:
    fields = payload if isinstance(payload, dict) else {}
    out = {}
    for name in CHANNEL_FIELDS:
        value = fields.get(name)
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise HTTPException(status_code=400, detail=f"{name} must be text")
        out[name] = value
    return out


def _channel_events(payload):
    """The `events` field of a request, as a list of kind names.

    Absent or empty means every kind, which is the same answer `channels.py`
    gives, so a caller that has never heard of subscriptions keeps working.
    A list of anything but text is a 400 here rather than a confusing refusal
    from the validator two layers down.
    """
    fields = payload if isinstance(payload, dict) else {}
    events = fields.get("events")
    if events is None or events == "":
        return []
    if not isinstance(events, list):
        raise HTTPException(status_code=400, detail="events must be a list")
    for item in events:
        if not isinstance(item, str):
            raise HTTPException(status_code=400, detail="events must be text")
    return events


def _channel_refusal(exc: channels.ChannelError) -> JSONResponse:
    """A refused channel, as a 400.

    `detail` is channels.py's own sentence, where every caller has always
    read it. Beside it stand the field of the request the refusal is about
    and why, each one of that module's fixed words (`channels.FIELDS`,
    `channels.REASONS`) and never anything the request sent. A screen puts
    its own few words at the field they name, which a sentence alone never
    let it do (docs/RECORD.md 4.228).
    """
    return JSONResponse({"detail": str(exc), "field": exc.field,
                         "reason": exc.reason}, status_code=400)


def _channel_json(channel) -> dict:
    """The created channel, in the field names the request used, so the
    dashboard sends and receives one shape. `env` is the NAME of an environment
    variable and its value is never read here, which is what keeps this process
    free of channel credentials."""
    return {
        "type": channel.type,
        "label": channel.label,
        "env": channel.destination_env,
        "chat_id": channel.destination_extra,
        # The host, never the value. The browser just sent it and does not
        # need it back, and a response body is a place a credential should not
        # be (`app/channels.py`, and Slack revokes leaked webhook URLs).
        "destination": channel.hint(),
        "enabled": channel.enabled,
        # A list rather than the stored comma separated string, because the
        # screen ticks boxes. Empty means every kind, which is what the row
        # means (`app/channels.py`).
        "events": (channel.subscriptions.split(",")
                   if channel.subscriptions else []),
    }


@app.post("/api/admin/channels", status_code=201)
async def admin_add_channel(request: Request) -> dict:
    require_operator(request)
    workspace_id = operator_workspace(request)
    payload = json_body(await request.body())
    fields = _channel_text_fields(payload)
    con = db.connect()
    try:
        db.init(con)
        # The channels table has its own additive schema and db.init does not
        # create it, the same reason admin_scan_host calls scan.init.
        channels.init(con)
        # The window stopped asking for a label (the owner, 2026-08-23). Rows are
        # still keyed by label in every route here, so a request without one
        # gets a free label made from the type, the same way a Slack connect
        # gets one made from the channel name. A caller that names its own
        # label, the CLI included, keeps it.
        try:
            # Inside the try, because making a label up can be refused too:
            # a workspace can run out of free ones.
            label = (fields["label"].strip()
                     or channels.free_label(con, fields["type"], workspace_id))
            channel = channels.add(con, fields["type"], label,
                                   fields["env"],
                                   destination_extra=fields["chat_id"],
                                   subscriptions=_channel_events(payload),
                                   destination=fields["destination"],
                                   workspace_id=workspace_id)
        except channels.ChannelError as exc:
            # channels.py already says what is wrong in words an operator can
            # act on, including the duplicate label, so the sentence is passed
            # through rather than restated here, with the field and the
            # reason it names beside it.
            return _channel_refusal(exc)
    finally:
        con.close()
    return _channel_json(channel)


def _set_channel_enabled(label: str, enabled: bool,
                         workspace_id: int) -> Response:
    """Shared by enable and disable, which differ only in the flag. A label
    matching no live channel in this workspace is a 404, the same answer the
    host routes give for another workspace's host: not found, never forbidden,
    because a refusal that differs would say the label exists elsewhere."""
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        if not channels.set_enabled(con, label, enabled,
                                    workspace_id=workspace_id):
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/channels/{label}/enable", status_code=204)
async def admin_enable_channel(label: str, request: Request) -> Response:
    require_operator(request)
    return _set_channel_enabled(label, True, operator_workspace(request))


@app.post("/api/admin/channels/{label}/disable", status_code=204)
async def admin_disable_channel(label: str, request: Request) -> Response:
    """Off is not removed. The row and the label stay, because switching a
    channel off for an afternoon is a different act from deciding it should not
    exist."""
    require_operator(request)
    return _set_channel_enabled(label, False, operator_workspace(request))


# ------------------------------------------------------- connect to Slack
#
# Two routes, both under /api/admin/ deliberately: that prefix is already
# proxied to this app and already behind basic auth in Caddy, so the browser
# coming back from Slack is one that has already authenticated and **no Caddy
# change is needed**. Move these out of that prefix and they stop being
# reachable.
#
# `app/slack_oauth.py` owns the flow and the reasoning. These are the two ends
# of it and the writing of the row.

SLACK_REDIRECT_PATH = "/api/admin/channels/slack/callback"


def _slack_redirect_uri(request: Request) -> str:
    """The callback address, built from the request's own host.

    Slack requires it to match or be a subdirectory of a Redirect URL set in
    App Management, and to be HTTPS. The scheme is forced rather than taken
    from the request, because Caddy terminates TLS and proxies plain HTTP to
    this app, so the request's own scheme is http and would produce a URL Slack
    refuses.
    """
    host = request.headers.get("host") or "app.whichports.com"
    return f"https://{host}{SLACK_REDIRECT_PATH}"


@app.get("/api/admin/channels/slack/connect")
async def admin_slack_connect(request: Request) -> Response:
    """Start the flow: mint a state, park it in a cookie, go to Slack."""
    require_operator(request)
    if not slack_oauth.is_configured():
        # A feature that is absent says so. This is a page a person is looking
        # at, so it is words rather than a status code on its own.
        #
        # **It used to end by offering the other way in, and that sentence went
        # on 2026-08-24**: the window stopped asking for a webhook URL that day,
        # so a page telling an operator to paste one was pointing at a field
        # that is no longer on any screen.
        return HTMLResponse(
            web_pages.simple_page(
                "Slack is not set up on this control plane",
                "There is no Slack app configured here, so there is nothing to"
                f" connect to. Set {slack_oauth.CLIENT_ID_ENV} and"
                f" {slack_oauth.CLIENT_SECRET_ENV} in the ingest unit's"
                " environment, restart it, and this button works."),
            status_code=503)
    state = slack_oauth.new_state()
    try:
        where = slack_oauth.authorize_url(_slack_redirect_uri(request), state)
    except slack_oauth.SlackError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    answer = RedirectResponse(url=where, status_code=303)
    answer.set_cookie(
        slack_oauth.STATE_COOKIE, state, max_age=slack_oauth.STATE_TTL_SECONDS,
        httponly=True, samesite="lax", secure=True, path=SLACK_REDIRECT_PATH)
    return answer


@app.get(SLACK_REDIRECT_PATH)
async def admin_slack_callback(request: Request) -> Response:
    """Come back from Slack, check the state, exchange the code, write the row.

    **The operator never sees the webhook URL**, which is the whole point of
    doing this rather than asking them to paste one.
    """
    require_operator(request)
    params = request.query_params

    if params.get("error"):
        # **Bounded, because this one is attacker supplied.** Anybody can open
        # this URL with any query string, so what lands here is not Slack's
        # word for it, it is whatever was typed. `safe_error_code` reduces it
        # to a code or to nothing. The commonest real one is access_denied,
        # which is somebody clicking Cancel and is not a fault.
        code = slack_oauth.safe_error_code(params.get("error"))
        return _slack_done(request, "Slack did not complete the connect",
                           (f"Slack said: {code}. " if code else "")
                           + "Nothing was saved. You can start again from the"
                             " Integrations screen.", 200)

    expected = request.cookies.get(slack_oauth.STATE_COOKIE, "")
    if not slack_oauth.state_matches(expected, params.get("state", "")):
        # Slack's own instruction: "If it doesn't match what you sent, consider
        # the authorization a forgery."
        return _slack_done(request, "That connect did not come from here",
                           "The one-time value did not match, so nothing was"
                           " saved. Start the connect again from the"
                           " Integrations screen.", 400)

    try:
        raw = slack_oauth.exchange_raw(params.get("code", ""),
                                       _slack_redirect_uri(request))
        url = slack_oauth.webhook_url_from(raw)
    except slack_oauth.SlackError as exc:
        return _slack_done(request, "Slack could not finish the connect",
                           str(exc), 502)

    picked = slack_oauth.channel_name_from(raw)
    workspace_id = operator_workspace(request)
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        label = _free_slack_label(con, picked, workspace_id)
        try:
            channels.add(con, channels.TYPE_SLACK, label, "", destination=url,
                         workspace_id=workspace_id)
        except channels.ChannelError as exc:
            return _slack_done(request, "Slack connected and the channel was"
                               " not saved", str(exc), 400)
    finally:
        con.close()
    return _slack_done(
        request, "Slack is connected",
        f"Alerts will go to {picked or 'the channel you picked'}, saved as"
        f" \u201c{label}\u201d. The webhook URL is stored and is not shown"
        " here or anywhere else.", 200)


def _free_label(con, base: str, workspace_id: int) -> str:
    """A label the operator did not have to invent, and one that is free.

    Labels are unique among one workspace's live channels, so a second channel
    of the same kind would fail on the duplicate. A number is appended rather
    than refusing, because the operator did nothing wrong.
    """
    try:
        return channels.free_label(con, base, workspace_id)
    except channels.ChannelError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _free_slack_label(con, picked: str, workspace_id: int) -> str:
    """The Slack channel's own name, cleaned to what a label may hold."""
    base = (picked or "slack").lstrip("#") or "slack"
    base = "".join(c for c in base if c.isalnum() or c in " ._-")[:40] or "slack"
    return _free_label(con, base, workspace_id)


def _slack_done(request: Request, heading: str, body: str, status: int) -> Response:
    """The page the operator lands on, and it clears the state cookie.

    Cleared whatever the outcome: a one-time value that survives its one use is
    not one.
    """
    answer = HTMLResponse(web_pages.simple_page(heading, body),
                          status_code=status)
    answer.delete_cookie(slack_oauth.STATE_COOKIE, path=SLACK_REDIRECT_PATH)
    return answer


@app.post("/api/admin/channels/{label}/rename", status_code=204)
async def admin_rename_channel(label: str, request: Request) -> Response:
    """Change what a channel is called.

    **Safe to offer because the label is not the delivery key.**
    `alerts.channel_key` is built from the type, the variable and the extra, so
    a rename does not make this channel's open alerts look undelivered and
    re-post them. `channels.rename` says the same thing where it is enforced.
    """
    require_operator(request)
    payload = json_body(await request.body())
    fields = payload if isinstance(payload, dict) else {}
    new_label = fields.get("label")
    if not isinstance(new_label, str):
        raise HTTPException(status_code=400, detail="label must be text")
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        try:
            if not channels.rename(con, label, new_label,
                                   workspace_id=operator_workspace(request)):
                raise HTTPException(status_code=404)
        except channels.ChannelError as exc:
            return _channel_refusal(exc)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/channels/{label}/events", status_code=204)
async def admin_channel_events(label: str, request: Request) -> Response:
    """Change which kinds of alert one channel takes.

    An empty list means every kind, which is what an unticked screen means and
    what a row written before subscriptions existed already meant.
    """
    require_operator(request)
    payload = json_body(await request.body())
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        try:
            if not channels.set_subscriptions(
                    con, label, _channel_events(payload),
                    workspace_id=operator_workspace(request)):
                raise HTTPException(status_code=404)
        except channels.ChannelError as exc:
            return _channel_refusal(exc)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/channels/{label}/remove", status_code=204)
async def admin_remove_channel(label: str, request: Request) -> Response:
    """Marked removed rather than deleted, so an alert already delivered
    through this channel keeps a row its delivery can still be read against."""
    require_operator(request)
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        if not channels.remove(con, label,
                               workspace_id=operator_workspace(request)):
            raise HTTPException(status_code=404)
    finally:
        con.close()
    return Response(status_code=204)


@app.post("/api/admin/channels/{label}/destination")
async def admin_channel_destination(label: str, request: Request) -> dict:
    """Replace where one channel delivers.

    Validated by `channels.set_destination`, which applies exactly the rules
    `add` applies.

    **The answer carries the hint and never the value.** It used to be a bare
    204, on the reasoning that the browser just sent the value and a response
    body is not a place a credential should be (`app/channels.py`, and Slack
    revokes leaked webhook URLs). That reasoning is kept whole: `Channel.hint`
    is the summary with a webhook's last path segment elided, and it is what
    the create route above has always answered with under this same key.

    It is here because the row on the screen shows that summary and has to
    show the new one on the click rather than on a reload. The
    only other way for the browser to know it is a second copy of `hint` living
    in a page, which is where the elision would go wrong first.
    """
    require_operator(request)
    payload = json_body(await request.body())
    fields = payload if isinstance(payload, dict) else {}
    destination = fields.get("destination")
    chat_id = fields.get("chat_id")
    if chat_id is None:
        chat_id = ""
    if not isinstance(destination, str):
        raise HTTPException(status_code=400, detail="destination must be text")
    if not isinstance(chat_id, str):
        raise HTTPException(status_code=400, detail="chat_id must be text")
    # The kinds the Edit window holds, written with the destination. A
    # request without them leaves the row's kinds as they are.
    events = _channel_events(payload) if "events" in fields else None
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        workspace_id = operator_workspace(request)
        try:
            if not channels.set_destination(con, label, destination, chat_id,
                                            workspace_id=workspace_id,
                                            subscriptions=events):
                raise HTTPException(status_code=404)
        except channels.ChannelError as exc:
            return _channel_refusal(exc)
        # Read the row back rather than summarising what was sent. The hint
        # belongs to the stored row, so the stored row is what answers, and a
        # write that landed differently from the request cannot be reported as
        # the request. The kinds too, each named: the window says saved only
        # when they are the ones it sent (the second big test, finding E20).
        changed = [c for c in channels.live(con, workspace_id=workspace_id)
                   if c.label == label]
    finally:
        con.close()
    if not changed:
        return {"destination": "", "events": []}
    return {"destination": changed[0].hint(),
            "events": [kind for kind in channels.KIND_NAMES if changed[0].takes(kind)]}


# The line that exercises delivery on the box, for the rows this process
# cannot test itself, for exactly the rows whose secret this process does not
# hold (docs/RECORD.md #266: only the sweep unit reads alerts.env, and widening
# which processes hold secrets to power a button is the wrong trade).
#
# **It used to be `python -m app.sweep_cli --dry-run`, and that was wrong.**
# That flag is documented in its own module as "sweep, print, send nothing", so
# the answer telling an operator this process could not send their test handed
# them a command that would not send it either. `app/channels_cli.py test`
# sends one message to one channel, which is what the answer claims.
CHANNEL_TEST_COMMAND = "python -m app.channels_cli test --label"


@app.post("/api/admin/channels/{label}/test")
def admin_test_channel(label: str, request: Request) -> dict:
    """Send one short real test message through one channel, when this
    process can, and answer honestly when it cannot.

    **Plain `def` on purpose**: the send is a blocking network call with a
    ten second timeout, and a sync handler runs in the threadpool instead of
    holding the event loop open for it.

    Three answers, none carrying a destination back (the `#284` rule):

      sent true       the message went, through the same guarded path an
                      alert takes (`app/senders.py`, `app/webhook.py`)
      sent false      it did not, and `detail` says why in the sender's words
      sent false with `command`   this process cannot resolve the secret, so
                      the honest answer is the line to run on the box. That is
                      the case for a row naming a variable only the sweep
                      unit's environment holds, and for mail when the relay
                      credentials live in alerts.env, which this unit does not
                      read (docs/RECORD.md #266). The split is deliberate and
                      a button does not widen it.
    """
    require_operator(request)
    con = db.connect()
    try:
        db.init(con)
        channels.init(con)
        found = [c for c in channels.live(
            con, workspace_id=operator_workspace(request))
            if c.label == label]
    finally:
        con.close()
    if not found:
        raise HTTPException(status_code=404)
    channel = found[0]

    if channel.type == channels.TYPE_EMAIL:
        to = channel.resolve()
        if not to:
            return {"sent": False,
                    "detail": f"{channel.destination_env} is not set in this"
                              " process's environment, so the test has to run"
                              " on the box",
                    "command": f'{CHANNEL_TEST_COMMAND} "{channel.label}"'}
        config = notify.config_from_env()
        if not config.host:
            return {"sent": False,
                    "detail": "the mail relay is configured in alerts.env,"
                              " which only the sweep unit reads, so a mail"
                              " test has to run on the box",
                    "command": f'{CHANNEL_TEST_COMMAND} "{channel.label}"'}
        one = replace(config, to=to, sender=config.sender or to)
        subject, body, html = notify.format_test()
        sent, reason = notify.send(subject, body, one, html=html)
        return {"sent": sent, "detail": reason}

    if not channel.resolve():
        return {"sent": False,
                "detail": f"{channel.destination_env} is not set in this"
                          " process's environment, so the test has to run"
                          " on the box",
                "command": f'{CHANNEL_TEST_COMMAND} "{channel.label}"'}
    sent, reason = senders.deliver_test(channel)
    return {"sent": sent, "detail": reason}


# ------------------------------------------ the address a report arrived from
#
# Half of the agent-derived proof SI-6 rests on is the address the report
# arrived from, observed by us rather than asserted by the host (app/authz.py,
# "the three proofs", and docs/PRODUCT.md section 5). This is where the ingest
# learns it, and it is the only place in this file that reads a header a client
# could have written.
#
# **Every branch below returns None rather than a guess.** None means no proof
# is recorded, and an address nobody proved cannot be probed. Getting it wrong
# in the other direction would let an agent authorise an address it does not
# control, which is SI-6 broken completely, so this fails closed by
# construction and not by care.

# **The trust boundary, in one sentence: a forwarded address is believed only
# when the connection it arrived on came from loopback.**
#
# The ingest binds 127.0.0.1:8410 (ops/whichports-ingest.service) and Caddy
# reverse-proxies to it (ops/caddyfile.reference). Measured on the production
# box on 2026-08-16 with `ss -tlnp`: the only listening sockets reachable from
# off the box are sshd on 22 and Caddy on 80 and 443, and 8410 is loopback
# only. So nothing on the internet can open a socket to this process, and a
# request whose peer is loopback came through Caddy or from something already
# running on the box with a valid host credential in hand. That second half is
# the honest limit of this boundary.
#
# X-Forwarded-For is the header, because it is the one Caddy sets. Read from
# Caddy's own documentation on 2026-08-16 rather than remembered: reverse_proxy
# "sets or augments the X-Forwarded-For header field", and "for these
# X-Forwarded-* headers, by default, the proxy will ignore their values from
# incoming requests, to prevent spoofing". Believing an incoming value is
# opt-in through the global `trusted_proxies` option, whose documented default
# is "By default, no proxies are trusted", and the live Caddyfile sets no such
# option. So what reaches us is the address Caddy itself accepted the
# connection from.
#
# That is what Caddy promises. Nothing here relies on the promise: a value is
# taken only when there is exactly one header carrying exactly one globally
# routable address, so a Caddy that started appending, or a second proxy nobody
# told us about, records nothing instead of recording the wrong thing.
FORWARDED_FOR_HEADER = "x-forwarded-for"


def _peer_is_loopback(client) -> bool:
    """True only when this connection's own socket peer is a loopback address.

    `client` is what the server put in the ASGI scope. It is the peer of the
    TCP connection, not anything the request said, and that is the only reason
    it is worth checking. A missing peer, a unix socket and a peer that does
    not parse as an address are all "not loopback", which is the safe way
    round.

    **It is only the socket peer while uvicorn's proxy-header handling is off**,
    which is why ops/whichports-ingest.service passes --no-proxy-headers.
    uvicorn installs ProxyHeadersMiddleware by default (uvicorn 0.52.2,
    config.py `proxy_headers: bool = True`, trusted hosts defaulting to
    127.0.0.1) and that middleware overwrites the scope's client with an
    address it reads out of X-Forwarded-For itself. With it on, this check
    would be asking the header about the header. It still fails closed: the
    rewritten client is the agent's public address, which is not loopback, so
    nothing is recorded and the warning below says which flag is missing.
    """
    host = getattr(client, "host", None)
    if not host:
        return False
    try:
        peer = ipaddress.ip_address(host)
    except ValueError:
        return False
    # A dual-stack socket spells an IPv4 peer `::ffff:127.0.0.1`, and that is
    # still this machine. The mapping is done here rather than left to
    # `is_loopback` because the answer moved: CPython 3.12.3 says False for
    # `::ffff:127.0.0.1` and 3.12.13 says True, both of them "Python 3.12".
    # Asking the embedded address directly is the same answer on every
    # interpreter, which is what a check standing in front of SI-6 needs to be.
    if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
        peer = peer.ipv4_mapped
    return peer.is_loopback


def observed_source_address(request: Request) -> str | None:
    """The address this report arrived from, canonicalised, or None if we do
    not know it well enough to prove anything with it."""
    if not _peer_is_loopback(request.client):
        # Either something is in front of us that we did not expect, or the
        # proxy-header flag has gone missing from the unit. Both mean the peer
        # is unreadable, and an unreadable peer trusts no header.
        log.warning(
            "a report arrived on a connection from %r, which is not loopback,"
            " so no forwarded address was trusted and nothing was authorised."
            " This service expects to sit behind Caddy on 127.0.0.1 and to run"
            " with uvicorn --no-proxy-headers (ops/whichports-ingest.service)",
            getattr(request.client, "host", None))
        return None

    values = request.headers.getlist(FORWARDED_FOR_HEADER)
    if len(values) != 1:
        # Zero: nothing in front of us set it, so we never saw the address.
        # More than one: we cannot tell which one the proxy wrote, and picking
        # is guessing.
        log.info("a report carried %d %s headers, so nothing was authorised",
                 len(values), FORWARDED_FOR_HEADER)
        return None

    value = values[0]
    if "," in value:
        # A list is a chain. Taking the first entry trusts whatever a client
        # prepended, which is the classic way this gets broken. Taking the last
        # would trust a header shape we never configured Caddy to produce.
        # Refuse the whole value instead of choosing.
        log.info("a report's %s header held a list, so nothing was authorised",
                 FORWARDED_FOR_HEADER)
        return None

    try:
        # The observed address is data from outside, so it goes through the
        # same door every candidate target does. This is what refuses a
        # private, loopback, link-local, multicast, carrier-NAT, v4-mapped or
        # zone-indexed address, and what refuses a port hanging off the end,
        # because none of those parse as a bare address.
        target, _family = authz.normalise_target(value)
    except authz.TargetError as exc:
        # The class only. The error's own words quote the value, and the value
        # is text the request carried, which never goes into the journal
        # (SI-8).
        log.info("a report's %s header cannot be a probe target, %s, so"
                 " nothing was authorised", FORWARDED_FOR_HEADER,
                 type(exc).__name__)
        return None
    return target


def _record_observed_proof(con: sqlite3.Connection, host_id: int,
                           document: str, observed: str | None) -> None:
    """Record that this host proved the address its own report arrived from.

    **A side effect of storing the report, never a condition of it.** Storing
    the document is this endpoint's job, and an authorisation that could not be
    recorded leaves the address unauthorised, which is safe. So nothing in here
    is allowed to turn a stored report into an error the agent sees. The broad
    except is deliberate for that reason and it logs at exception level rather
    than swallowing anything: this is not a warning downgraded to keep output
    clean, it is a side effect kept off the report's path.
    """
    if observed is None:
        return
    try:
        result = authz.record_agent_proof(con, host_id, observed, document)
    except Exception:
        log.exception("recording the observed-address proof for host %s failed,"
                      " the report is stored and the address stays unauthorised",
                      host_id)
        return
    if not result.recorded:
        # The everyday case, and a person asking "why is my address not
        # authorised" reads this line. A host behind NAT lands here on every
        # report, which is correct rather than a fault.
        log.info("no authorisation recorded for host %s: %s", host_id,
                 result.reason)


@app.post("/api/v1/reports", status_code=204)
async def receive_report(request: Request) -> Response:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    credential = auth.removeprefix("Bearer ")

    # Refuse a declared-oversize request before buffering it. A client that
    # lies or sends chunked encoding still hits the check after the read, and
    # the hard backstop for both is Caddy's request body limit in front of
    # this service (README, deploy shape).
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=413)
    body = await request.body()
    if len(body) > MAX_DOCUMENT_BYTES:
        raise HTTPException(status_code=413)

    # Read before anything is stored, because it is a property of the
    # connection and the connection is what we are holding right now.
    observed = observed_source_address(request)

    con = db.connect()
    try:
        db.init(con)
        # The registry's own additive schema, the same pattern app/authz_cli.py
        # and app/sweep_cli.py follow. Without it the tables never come into
        # being on a box where the CLI has not been run, which is how the
        # production database reached 2026-08-16 with 833 reports and no
        # authorizations table at all.
        authz.init(con)
        host = store.host_for_credential(con, credential)
        if host is None:
            # Unknown and revoked look identical from outside, on purpose:
            # a 401 must not confirm whether a credential ever existed.
            raise HTTPException(status_code=401)

        envelope = parse_envelope(body)
        store.insert_report(
            con,
            host_id=host["id"],
            collected_at_unix=envelope["collected_at_unix"],
            schema_version=envelope["schema_version"],
            document=envelope["document"],
        )
        # A host still under its placeholder takes the hostname its own
        # document carries, once: naming pins it, and the name is its ID
        # from then on (store.auto_name_from_hostname).
        if host["auto_named"]:
            store.auto_name_from_hostname(con, host["id"], envelope["hostname"])
        # Last, so a stored report is never at the mercy of it, and after the
        # naming so the journal line names the host the way the dashboard does.
        _record_observed_proof(con, host["id"], envelope["document"], observed)
        # After the proof, because a scan of a host with no proved address
        # probes nothing. `host` was read before the report was stored, so
        # its `last_report_at` still says whether this one is the first.
        if host["last_report_at"] is None:
            _request_first_scan(con, host["id"])
    finally:
        con.close()
    return Response(status_code=204)


def _request_first_scan(con, host_id: int) -> None:
    """Ask for one outside scan of a server whose first report just arrived.

    So its first measurement follows in seconds instead of waiting for the
    ten minute lane, which is what lets the Add server window show a server
    arriving (docs/screens/add-server/BRIEF-arrival.md, the owner's yes of
    2026-09-20). It is exactly what the Scan now button records, a row in
    `scan_requests` and a touched trigger file (docs/PRODUCT.md 5f). Nothing
    is sent to the agent and nothing in its answer changes, so SI-1 and SI-2
    stand, and the durable two minute limit per host applies as it does to
    the button.

    **Never on the report's path.** The report is already stored. Whatever
    fails here is logged with the host id and swallowed, the same shape
    `_record_observed_proof` takes, because a first report refused over a
    convenience would be a server that never arrives. Without the request
    the next pass of the lane measures it within about ten minutes.
    """
    try:
        scan.init(con)
        result = scan.request_scan(con, host_id, now=datetime.now(timezone.utc))
        if result.accepted:
            scan.touch_trigger(scan.trigger_path())
    except Exception:
        log.exception("could not ask for the first scan of host %s, its report"
                      " is stored and the next fast-lane pass will measure it",
                      host_id)


@app.post("/api/v1/reports/presence", status_code=204)
async def receive_presence(request: Request) -> Response:
    """The agent saying "this is me, from this address", with no document.

    Since agent 0.1.11 a host sends one of these over each address family
    after every report, so a dual-stack host proves both of its addresses
    rather than only the one the report travelled over (docs/PRODUCT.md 5,
    the clause of 2026-09-18). Nothing in the request is stored. The one
    thing read from it is the address it arrived from, exactly as for a
    report, and that address is proved against the newest document this
    control plane already holds for the host, by the same function and the
    same rule: the host has to report holding it. A host with no document
    yet proves nothing here, because there is nothing to corroborate with.
    """
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    credential = auth.removeprefix("Bearer ")
    observed = observed_source_address(request)
    con = db.connect()
    try:
        db.init(con)
        authz.init(con)
        host = store.host_for_credential(con, credential)
        if host is None:
            raise HTTPException(status_code=401)
        newest = store.latest_report(con, host["id"])
        if newest is not None:
            _record_observed_proof(con, host["id"], newest["document"], observed)
    finally:
        con.close()
    return Response(status_code=204)


# The prober API, for self-hosted instances (app/proberapi.py). Registered
# here, after observed_source_address, because presence proves an address with
# exactly that function and the one trust rule written above it. The routes
# only check, charge and queue. Nothing in this process reaches a prober.
app.include_router(proberapi_routes.build_router(observed_source_address))
# The Feedback window's two routes (app/feedback_routes.py): ours, which an
# instance asks with its API key, and the one a signed-in person's browser
# asks on the instance it is signed in to. And the console's two, Done and
# Delete, for an account with the admin flag alone.


def require_admin(request: Request) -> None:
    """Pass when the caller holds a live session of an account with the
    admin flag. 403 with no session, as every `/api/admin/` route, and 404
    with a session that lacks the flag, the answer the console's other
    write, the address lookup, gives a signed-in stranger
    (app/web_auth.py): a 403 would confirm the route is there."""
    require_operator(request)
    if not accounts.is_admin(web_auth.signed_in_user(request)):
        raise HTTPException(status_code=404)


app.include_router(feedback_routes.build_router(require_operator, operator_workspace,
                                                require_admin))
# The landing page's beta form. Off, and a 404, unless the landing page's
# address is configured (app/betasignup.py), so a self-hosted instance never
# collects anybody's address.
app.include_router(betasignup_routes.build_router(_peer_is_loopback))


def parse_envelope(body: bytes) -> dict:
    """Validate only the envelope, store the rest verbatim.

    The agent is the authority on the document's content and the control
    plane must not silently reshape evidence (PRODUCT.md 4e). What is checked
    here is just enough to file the document: it is UTF-8, it is a JSON
    object, and the three envelope fields have the right types. bool is
    excluded explicitly because Python's bool is an int and a document with
    `"schema_version": true` should be a 400, not a stored curiosity.
    """
    try:
        text = body.decode("utf-8")
        doc = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HTTPException(status_code=400)
    if not isinstance(doc, dict):
        raise HTTPException(status_code=400)

    schema_version = doc.get("schema_version")
    collected = doc.get("collected_at_unix")
    hostname = doc.get("hostname")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise HTTPException(status_code=400)
    if isinstance(collected, bool) or not isinstance(collected, int):
        raise HTTPException(status_code=400)
    if not isinstance(hostname, str):
        raise HTTPException(status_code=400)

    return {
        "schema_version": schema_version,
        "collected_at_unix": collected,
        "hostname": hostname,
        "document": text,
    }
