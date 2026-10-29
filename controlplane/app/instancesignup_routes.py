"""The open signup's routes, which the self-hosted installer calls.

`app/instancesignup.py` owns the rules and what is kept. This file is what
the routes read, what they answer, what bounds them, and the mails that
follow. The installer is the one client (selfhost/install.sh), and it is a
shell script, so every answer is one word of plain text and nothing in it
is parsed as anything else.

## The contract

    POST /api/v1/instance-signup           {"email": ..., "claim": ...}
    POST /api/v1/instance-signup/collect   {"claim": ..., "code": ...}
    POST /api/v1/instance-signup/done      {"claim": ...}

Each body is one JSON object, `Content-Type: application/json`, and nothing
else in it is read. The claim is 64 lowercase hex characters, the code
eight digits.

Every answer the installer has a line for comes with 200, because the
installer's curl runs with --fail, which drops the body of any other
status. The word is the answer:

    signup    sent | full_today | full | closed | invalid_email
    collect   the invite line | wrong | full_today | full | closed
    done      done

and for any of the three:

    400 malformed_request   not one JSON object, or, on the signup route,
                            a claim that is not one
    413 too_large
    429 slow_down           with Retry-After

A claim that is not one is `wrong` to collect and `done` to done, the
answers every claim nobody made gets.

The installer reads a 429, and any status it has no line for, as our API
not answering.

**Off, a 404, unless the landing page's address is set**, the same setting
the beta list reads, so a self-hosted instance never takes a signup.

**The code's mail goes after the answer has gone**, so neither the answer
nor the time it took says whether a code was mailed. Who a request is
counted against is the beta form's own rule (`betasignup_routes.client_key`):
the address a proxy on loopback set. It is a key in this process's memory
and nothing else, until it restarts or newer keys push it out. The signup
route has its own buckets, and the collect and done routes share theirs: one
per client, sized for a person who types a code a few times, and one in all.

**Nothing a stranger sent reaches a log line**: no address, no claim, no
code, no line. The journal gets the answer's class and nothing else (SI-8).
"""
import json
import logging

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.background import BackgroundTask

from . import (authz, betasignup, betasignup_routes, db, instances,
               instancesignup, invite, notify, publicurl, ratelimit)

log = logging.getLogger(__name__)

PATH = "/api/v1/instance-signup"
COLLECT_PATH = PATH + "/collect"
DONE_PATH = PATH + "/done"

# An address is at most 254 characters, a claim 64 and a code 8. Two
# kilobytes is room for any of the three bodies with their names around them.
MAX_BODY_BYTES = 2048

# The refusals that are not answers, and their status. Closed: a test holds it.
ERRORS = {
    "malformed_request": 400,
    "too_large": 413,
    "slow_down": 429,
}

JSON_TYPE = "application/json"
DONE = "done"


class Refused(Exception):
    """A request this route will not take, as one class from `ERRORS`."""

    def __init__(self, error: str, retry_after: int | None = None):
        super().__init__(error)
        self.error = error
        self.retry_after = retry_after


def _content_type(request: Request) -> str:
    return request.headers.get("content-type", "").split(";", 1)[0].strip().lower()


async def _read_body(request: Request) -> bytes:
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise Refused("too_large")
    received = bytearray()
    async for chunk in request.stream():
        received += chunk
        if len(received) > MAX_BODY_BYTES:
            raise Refused("too_large")
    return bytes(received)


async def _fields(request: Request) -> dict:
    """The body as one JSON object, unchecked beyond that. Anything else is
    malformed."""
    if _content_type(request) != JSON_TYPE:
        raise Refused("malformed_request")
    body = await _read_body(request)
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Refused("malformed_request") from None
    if not isinstance(payload, dict):
        raise Refused("malformed_request")
    return payload


def _relay_set() -> bool:
    return bool(notify.config_from_env().host)


def _landing_or_404() -> str:
    try:
        landing = betasignup.landing()
    except betasignup.LandingMisconfigured:
        # The setting's words name the value, which is ours, but the
        # line stays a class like every other line here.
        log.error("instance signup is off: the landing address is not one")
        landing = None
    if landing is None:
        raise HTTPException(status_code=404)
    return landing


def mail_the_code(email: str, code: str) -> None:
    """The one mail a signup sends the person. Its failure is a journal line
    with the class and no address (`web_auth._send`)."""
    from . import web_auth  # web_auth imports most of the app, so not at the top
    subject, body, html = notify.format_signup_code(code)
    web_auth._send(subject, body, html, email)


def tell_the_owner(subject: str, body: str) -> None:
    """A mail to the owner, the alert mail's address, with no address of
    anybody in it. Off unless alert mail is configured."""
    config = notify.config_from_env()
    if not config.host or not config.to:
        log.info("instance signup: no mail to the owner, none is configured")
        return
    sent, _reason = notify.send(subject, body, config)
    log.info("instance signup: owner mail %s", "sent" if sent else "not sent")


def full_mail_task(answer: str, con_factory=db.connect) -> BackgroundTask:
    """The owner's once-a-day mail that signup is full, with today's counts.
    `answer` is the full the person was given, `full_today` or `full`, so the
    mail says tomorrow only when tomorrow ends it."""
    con = con_factory()
    try:
        instances.init(con)
        instancesignup.init(con)
        counts = instancesignup.today(con)
        live = instances.live_count(con, authz.ORIGIN_SIGNUP)
    finally:
        con.close()
    subject, body = notify.format_signup_full(
        counts["signups"], counts["made"], live,
        today_only=answer != instancesignup.FULL)
    return BackgroundTask(tell_the_owner, subject, body)


def made_mail_task(con_factory=db.connect) -> BackgroundTask:
    """The owner's mail that an instance signed up, with how many are live."""
    con = con_factory()
    try:
        live = instances.live_count(con, authz.ORIGIN_SIGNUP)
    finally:
        con.close()
    subject, body = notify.format_signup_made(live)
    return BackgroundTask(tell_the_owner, subject, body)


def _our_host() -> str | None:
    """The host the invite line names: this control plane's own public
    address, never anything a request said."""
    try:
        host = publicurl.host()
    except publicurl.PublicUrlError:
        return None
    return host if invite.host_ok(host) else None


def build_router(peer_is_loopback) -> APIRouter:
    """The routes, given the one question they need the ingest to answer: is
    this connection from loopback."""
    router = APIRouter()

    def answer(word: str, status_code: int = 200, retry_after: int | None = None,
               background: BackgroundTask | None = None) -> Response:
        response = Response(word, status_code=status_code, media_type="text/plain",
                            background=background)
        if retry_after is not None:
            response.headers["Retry-After"] = str(retry_after)
        response.headers["Cache-Control"] = "no-store"
        return response

    def refused(error: Refused) -> Response:
        return answer(error.error, ERRORS[error.error], error.retry_after)

    def take(bucket: ratelimit.TokenBucket, key: str) -> None:
        if not bucket.allow(key):
            raise Refused("slow_down", bucket.retry_after_seconds(key))

    @router.post(PATH)
    async def instance_signup(request: Request) -> Response:
        _landing_or_404()
        limiters: ratelimit.Limiters = request.app.state.limiters
        try:
            take(limiters.signup_client,
                 betasignup_routes.client_key(request, peer_is_loopback))
            take(limiters.signup_global, ratelimit.GLOBAL_KEY)
            fields = await _fields(request)
            try:
                email = instancesignup.normalise_email(fields.get("email"))
            except instancesignup.InvalidEmail:
                log.info("instance signup: invalid_email")
                return answer("invalid_email")
            claim = fields.get("claim")
            if not instancesignup.claim_ok(claim):
                raise Refused("malformed_request")
        except Refused as error:
            log.info("instance signup: %s", error.error)
            return refused(error)

        if not instancesignup.is_open() or not _relay_set():
            # No relay means no code could reach anybody, so nothing is
            # kept, the same answer as the switch being off.
            log.info("instance signup: closed")
            return answer(instancesignup.CLOSED)

        con = db.connect()
        try:
            instances.init(con)
            instancesignup.init(con)
            asked = instancesignup.request_code(con, email, claim)
        finally:
            con.close()

        background = None
        if asked.code is not None:
            background = BackgroundTask(mail_the_code, email, asked.code)
        elif asked.tell_owner:
            background = full_mail_task(asked.answer)
        log.info("instance signup: %s", asked.answer)
        return answer(asked.answer, background=background)

    @router.post(COLLECT_PATH)
    async def instance_signup_collect(request: Request) -> Response:
        _landing_or_404()
        limiters: ratelimit.Limiters = request.app.state.limiters
        try:
            take(limiters.collect_client,
                 betasignup_routes.client_key(request, peer_is_loopback))
            take(limiters.collect_global, ratelimit.GLOBAL_KEY)
            fields = await _fields(request)
        except Refused as error:
            log.info("instance signup: collect %s", error.error)
            return refused(error)

        # Read before anything is made: an instance whose line could not be
        # written would be an instance nobody holds a key of.
        host = _our_host()
        if host is None:
            log.error("instance signup: the public address is not set, nothing was made")
            return answer(instancesignup.CLOSED)

        con = db.connect()
        try:
            instances.init(con)
            instancesignup.init(con)
            collected = instancesignup.collect(con, fields.get("claim"), fields.get("code"))
        finally:
            con.close()
        log.info("instance signup: collect %s%s", collected.answer,
                 " again" if collected.again else "")

        if collected.answer != instancesignup.MADE:
            background = None
            if collected.tell_owner:
                background = full_mail_task(collected.answer)
            return answer(collected.answer, background=background)
        issued = collected.issued
        line = invite.line(host, issued.api_key, issued.proof_key)
        background = None
        if not collected.again and limiters.signup_mail.allow(ratelimit.GLOBAL_KEY):
            background = made_mail_task()
        return answer(line, background=background)

    @router.post(DONE_PATH)
    async def instance_signup_done(request: Request) -> Response:
        _landing_or_404()
        limiters: ratelimit.Limiters = request.app.state.limiters
        try:
            take(limiters.collect_client,
                 betasignup_routes.client_key(request, peer_is_loopback))
            take(limiters.collect_global, ratelimit.GLOBAL_KEY)
            fields = await _fields(request)
        except Refused as error:
            log.info("instance signup: done %s", error.error)
            return refused(error)
        con = db.connect()
        try:
            instancesignup.init(con)
            instancesignup.done(con, fields.get("claim"))
        finally:
            con.close()
        log.info("instance signup: done")
        return answer(DONE)

    return router
