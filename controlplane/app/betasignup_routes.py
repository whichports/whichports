"""POST /api/v1/beta-signup: the form on the landing page.

`app/betasignup.py` owns what is kept and why. This file is the route: what it
reads, what it answers, and what bounds it. It is the one route in this
application a stranger can write through, so each of those is kept small.

## The contract

    POST /api/v1/beta-signup
    Content-Type: application/json                    {"email": ..., "servers": ...}
              or  application/x-www-form-urlencoded   email=...&servers=...

`email` is required. `servers` is optional and one of `1-5`, `6-20`,
`21-100`, `100+`. Nothing else in the body is read.

A JSON request, or one that says `Accept: application/json`, gets JSON:

    200 {"ok": true}                     joined, or already on the list
    400 {"error": "invalid_email"}
    400 {"error": "invalid_servers"}
    400 {"error": "malformed_request"}   not JSON, not a form, or a field twice
    413 {"error": "too_large"}
    429 {"error": "slow_down"}           with Retry-After

A plain form post, the page without JavaScript, gets `303` to the landing
page at one of three fragments: `#beta-joined`, `#beta-invalid`, `#beta-slow`.
The landing page's address is configuration (`betasignup.landing`), never
something the request named, so this cannot be turned into a redirect to
anywhere else.

**Every answer is a class from a closed set**, the posture the prober API
takes on its own wire (`app/proberapi.py`). **A new address and one already
on the list get the same answer**, and the mail to the operator is sent after
the response has gone, so neither the body nor the time it took says which
it was.

## Who a request is counted against

A rate limit needs a key, and the only one a signup has is where it came
from. Behind our own proxy the connection is from loopback, so the address is
read from a header: `CF-Connecting-IP` first, because whichports.com is
proxied by Cloudflare, which "provides the client IP address connecting to
Cloudflare to the origin web server" in it (Cloudflare's HTTP headers
reference, read 2026-10-02), then `X-Forwarded-For`, which Caddy sets to its
own peer. Neither is trusted for anything but this count.

**`CF-Connecting-IP` is the client's own only because the proxy says so.**
Caddy passes it on as the client sent it (Caddy's reverse_proxy page, read
2026-10-16), and a client that connects to the box directly sends whatever it
likes. So the proxy in front removes it from every connection that is not
from Cloudflare's published ranges, and then this reads `X-Forwarded-For`,
which Caddy writes from the connection itself. On our box those are the
CF-Connecting-IP lines in `ops/caddyfile.reference`. Cloudflare's page does
not say a header of that name sent to Cloudflare is replaced, so the
per-client bucket stays the weak half and the global bucket behind it is the
bound (`app/ratelimit.py`).

**The address is a key in a dictionary in this process's memory and nothing
else.** It is not written to the database, a log line or a mail. An IPv6
client is counted by its /64, because one machine holds a whole /64.
"""
import ipaddress
import json
import logging
import urllib.parse

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.background import BackgroundTask

from . import betasignup, db, notify, ratelimit

log = logging.getLogger(__name__)

PATH = "/api/v1/beta-signup"

# An address is at most 254 characters and the size at most six. Two
# kilobytes is room for both, percent-encoded, with field names around them.
MAX_BODY_BYTES = 2048

# Every refusal and its status. Closed: a test holds it.
ERRORS = {
    "invalid_email": 400,
    "invalid_servers": 400,
    "malformed_request": 400,
    "too_large": 413,
    "slow_down": 429,
}

# Where a form post without JavaScript lands, per outcome.
FRAGMENT_JOINED = "#beta-joined"
FRAGMENT_INVALID = "#beta-invalid"
FRAGMENT_SLOW = "#beta-slow"

JSON_TYPE = "application/json"
FORM_TYPE = "application/x-www-form-urlencoded"


class Refused(Exception):
    """A request this route will not take, as one class from `ERRORS`."""

    def __init__(self, error: str, retry_after: int | None = None):
        super().__init__(error)
        self.error = error
        self.retry_after = retry_after


def client_key(request: Request, peer_is_loopback) -> str:
    """What this request is counted against. Never stored, never logged."""
    candidates = []
    if peer_is_loopback(request.client):
        for header in ("cf-connecting-ip", "x-forwarded-for"):
            values = request.headers.getlist(header)
            if len(values) == 1 and "," not in values[0]:
                candidates.append(values[0].strip())
    candidates.append(getattr(request.client, "host", None) or "")
    for value in candidates:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.version == 4:
            return str(address)
        if address.ipv4_mapped is not None:
            # A dual-stack socket spells an IPv4 peer this way.
            return str(address.ipv4_mapped)
        return str(ipaddress.ip_network((int(address) >> 64 << 64, 64)))
    # A unix socket or a peer nobody could read: everybody like that shares
    # one bucket, which is the tight way to be wrong.
    return "unknown"


def _content_type(request: Request) -> str:
    return request.headers.get("content-type", "").split(";", 1)[0].strip().lower()


def _wants_json(request: Request) -> bool:
    return _content_type(request) == JSON_TYPE \
        or JSON_TYPE in request.headers.get("accept", "").lower()


async def _read_body(request: Request) -> bytes:
    """The body, refused as too large before it is read when it says so, and
    while it is read when it does not."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise Refused("too_large")
    received = bytearray()
    async for chunk in request.stream():
        received += chunk
        if len(received) > MAX_BODY_BYTES:
            raise Refused("too_large")
    return bytes(received)


def _fields(content_type: str, body: bytes) -> tuple:
    """(email, servers) as the request gave them, unchecked. Nothing else in
    the body is looked at."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused("malformed_request") from None
    if content_type == JSON_TYPE:
        try:
            payload = json.loads(text)
        except ValueError:
            raise Refused("malformed_request") from None
        if not isinstance(payload, dict):
            raise Refused("malformed_request")
        return payload.get("email"), payload.get("servers")
    if content_type == FORM_TYPE:
        try:
            pairs = urllib.parse.parse_qs(text, keep_blank_values=True,
                                          max_num_fields=8)
        except ValueError:
            raise Refused("malformed_request") from None
        # A field given twice is not a form this page sends, and choosing
        # between the two would be guessing.
        if len(pairs.get("email", [])) > 1 or len(pairs.get("servers", [])) > 1:
            raise Refused("malformed_request")
        return (pairs.get("email", [None])[0], pairs.get("servers", [None])[0])
    raise Refused("malformed_request")


def tell_the_operator(servers: str | None, total: int) -> None:
    """One mail saying somebody joined: the size they gave, and how many are
    on the list now. No address, theirs or anybody's. Off unless alert mail
    is configured, like every other mail this application sends."""
    config = notify.config_from_env()
    if not config.host or not config.to:
        log.info("beta signup: no mail, none is configured")
        return
    subject = f"[whichports] The beta list has {total}"
    body = ("Somebody joined the beta list.\n"
            "\n"
            f"  servers:  {servers or 'not said'}\n"
            f"  on the list now:  {total}\n")
    sent, _reason = notify.send(subject, body, config)
    log.info("beta signup: mail %s", "sent" if sent else "not sent")


def build_router(peer_is_loopback) -> APIRouter:
    """The route, given the one question it needs the ingest to answer: is
    this connection from loopback. Passed in rather than imported, the way
    the prober API's router is handed `observed_source_address`."""
    router = APIRouter()

    def refuse(request: Request, landing: str, refused: Refused) -> Response:
        log.info("beta signup: %s", refused.error)
        if not _wants_json(request):
            fragment = FRAGMENT_SLOW if refused.error == "slow_down" \
                else FRAGMENT_INVALID
            return RedirectResponse(f"{landing}/{fragment}", status_code=303)
        response = JSONResponse({"error": refused.error},
                                status_code=ERRORS[refused.error])
        if refused.retry_after is not None:
            response.headers["Retry-After"] = str(refused.retry_after)
        response.headers["Cache-Control"] = "no-store"
        return response

    @router.post(PATH)
    async def beta_signup(request: Request) -> Response:
        try:
            landing = betasignup.landing()
        except betasignup.LandingMisconfigured as exc:
            log.error("beta signup is off: %s", exc)
            landing = None
        if landing is None:
            raise HTTPException(status_code=404)

        limiters: ratelimit.Limiters = request.app.state.limiters
        try:
            # The client's own bucket first, so one place in a loop spends its
            # own allowance and not everybody's.
            key = client_key(request, peer_is_loopback)
            if not limiters.beta_client.allow(key):
                raise Refused("slow_down",
                              limiters.beta_client.retry_after_seconds(key))
            if not limiters.beta_global.allow(ratelimit.GLOBAL_KEY):
                raise Refused("slow_down", limiters.beta_global.retry_after_seconds(
                    ratelimit.GLOBAL_KEY))
            email_given, servers_given = _fields(_content_type(request),
                                                 await _read_body(request))
            try:
                email = betasignup.normalise_email(email_given)
            except betasignup.InvalidEmail:
                raise Refused("invalid_email") from None
            try:
                servers = betasignup.normalise_servers(servers_given)
            except betasignup.InvalidServers:
                raise Refused("invalid_servers") from None
        except Refused as refused:
            return refuse(request, landing, refused)

        con = db.connect()
        try:
            betasignup.init(con)
            new = betasignup.add(con, email, servers)
            total = betasignup.count(con)
        finally:
            con.close()
        log.info("beta signup: %s", "joined" if new else "already on the list")

        # After the response has gone, so a new address and a known one take
        # the same time to answer. Bounded, so a burst of joins is a handful
        # of mails and not one each.
        background = None
        if new and limiters.beta_mail.allow(ratelimit.GLOBAL_KEY):
            background = BackgroundTask(tell_the_operator, servers, total)

        if not _wants_json(request):
            return RedirectResponse(f"{landing}/{FRAGMENT_JOINED}",
                                    status_code=303, background=background)
        response = JSONResponse({"ok": True}, background=background)
        response.headers["Cache-Control"] = "no-store"
        return response

    return router
