"""An instance's DNS TXT and token file proofs, made on our prober API too.

docs/PRODUCT.md 5g, the paragraph of 2026-10-24. A self-hosted instance
probes through our probers, and our probers touch only an address our own
registry holds for that instance (SI-6). An agent proves its address to both
registries by itself. A server with no agent is proved by a person, with a
TXT record or a token file, through the dashboard's two routes
(`ingest.admin_start_address_proof`, `admin_verify_address_proof`). Until
2026-10-24 those routes proved in the instance's own registry only, so such
an address was never probed: the second big test found it (finding B6).

## What this does, on an instance with the prober lines set

**Start.** The address is checked here first, so a private address or one
on this instance's own exclusion list is refused before anything is sent.
Then our API starts the proof, and this registry starts its own with the
token our API made (`authz.start_proof`, `adopt_token`). One published token
then proves the address to both. For a token file, the token the server's
file already holds is named, and our API gives it again when it made it for
this instance, so a second address of one server keeps one token. The number of our challenge is kept beside
this registry's, in `prober_challenges`. A start our API refused, or did not
answer, makes nothing here.

**Verify.** A challenge this registry has cancelled, or whose day is over, is
answered here and nothing is sent. Otherwise our API is asked first, and it
reads the record or the file itself, the same `authz.verify_proof` every
published proof goes through. It never takes this instance's word that it
did. Only when our API proved it is the evidence read here. So an address is
recorded here, and shown as proved, only when both proved it, and an answer
that is not a proof names the side that did not: `PROBER_API` or `INSTANCE`.

**Revoke.** Our API first, then here, and nothing changes here when our API
did not take it. Since the same day an instance's batch also takes the
addresses our registry holds live for it (`authz.snapshot_for_prober_api`,
the second big test's finding D1), so a revoke that stayed here would no
longer stop our probers.

**What leaves.** The address and the way it is proved, with the instance's
API key, the token a server's file already serves, which our API made, and
the number of our own challenge when it is verified. Nothing else (SI-8). Our box's answer is reduced to two values, and only a class of
a closed set ever reaches the window.

An instance with no prober lines never comes here.
"""

import dataclasses
import logging
import os
import sqlite3
from datetime import datetime, timezone

from . import authz, dispatch

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS prober_challenges (
    challenge_id INTEGER PRIMARY KEY,
    remote_id    INTEGER NOT NULL,
    created_at   TEXT NOT NULL
);
"""

# Which side did not prove it. Closed, so the window and a test can hold it.
PROBER_API = "prober_api"
INSTANCE = "instance"
REFUSERS = (PROBER_API, INSTANCE)

# The classes an answer here can carry: the registry's own codes, and the
# four that are about our API rather than about the address. Our API counts
# an instance's proofs by the hour and reads one challenge at most once
# every few seconds (`proberapi.PROOF_STARTS_PER_HOUR`), and says
# `over_instance_pace` past that.
API_CODES = frozenset({dispatch.NO_ANSWER, "unknown_key", "malformed_request",
                       "over_instance_pace"})
CODES = authz.PROOF_CODES | API_CODES


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


@dataclasses.dataclass(frozen=True)
class ProberApi:
    """Where our API is and the key this instance holds for it."""
    base_url: str
    key: str
    allow_http: bool = False


def prober_api(environ=None) -> ProberApi | None:
    """This instance's prober lines, or None when it has none, which is an
    instance that proves in its own registry only. Half of them, or an
    address that is not plain https, raises `dispatch.TransportConfigError`,
    the same rule a pass follows: such an instance cannot reach our probers,
    so nothing is proved here as if it could."""
    environ = os.environ if environ is None else environ
    base_url = environ.get(dispatch.PROBER_API_ENV, "").strip()
    key = environ.get(dispatch.PROBER_API_KEY_ENV, "").strip()
    if not base_url and not key:
        return None
    if not base_url or not key:
        raise dispatch.TransportConfigError(
            f"{dispatch.PROBER_API_ENV} and {dispatch.PROBER_API_KEY_ENV} go"
            " together, and only one of them is set")
    return ProberApi(dispatch._checked_base_url(base_url, allow_http=False), key)


def opener():
    """The opener the requests to our box go through. None is the client's
    own, which refuses a redirect. A test stands its own in here."""
    return None


class NotStarted(Exception):
    """Our API refused the start or did not answer. `code` is the class."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class NotRevoked(Exception):
    """Our API refused the revoke or did not answer. `code` is the class."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# Each class our side can answer, in the words the window says it in. The
# class is what crosses from our side (SI-8), and the window said it as it
# came: "not proved with the probers: evidence_unreadable", a code word on a
# screen (the second big test, 25 October 2026). A test holds every class of
# CODES to words with no code word in them.
CODE_WORDS = {
    "proved": "proved",
    "no_such_challenge": "this proof is not known, start a new one",
    "challenge_cancelled": "the challenge was cancelled, start a new one",
    "challenge_expired": "the challenge expired, start a new one",
    "not_a_published_method": "that is not a published way to prove an address",
    "target_refused": "this address is never proved",
    "challenge_mismatch": "this proof does not match the address it names, start a new one",
    "evidence_unreadable": "the token could not be read where it was published",
    "token_not_found": "the token was not found where it was published",
    "not_held": "the server does not say it holds this address",
    "address_held": "another account holds a live proof of this address",
    "no_answer": "no answer",
    "unknown_key": "the key of this instance is not known",
    "malformed_request": "the request could not be read",
    "over_instance_pace": "too many proofs asked for, try again in a while",
}


def _said(head: str, code: str) -> str:
    """`head`, and the class in words after it when it is one of ours. A
    class nobody wrote words for is left out, never shown as it came."""
    words = CODE_WORDS.get(code)
    return f"{head}: {words}" if words else head


def revoke_words(address: str, code: str) -> str:
    return _said(f"{address} not revoked with the probers", code)


def start_words(address: str, code: str) -> str:
    return _said(f"{address} not started with the probers", code)


# The words for an address our side does not hold. The window says them with
# the address and the class, and an address row says them alone when this
# registry holds the address and our side does not (render_live.proof_status).
NOT_PROVED_WITH_THE_PROBERS = "not proved with the probers"


def verify_words(address: str, code: str) -> str:
    return _said(f"{address} {NOT_PROVED_WITH_THE_PROBERS}", code)


def configured(environ=None) -> bool:
    """Whether this instance has prober lines, all of them or half. Its
    screen then reads an address as proved only when our side holds it too."""
    environ = os.environ if environ is None else environ
    return bool(environ.get(dispatch.PROBER_API_ENV, "").strip()
                or environ.get(dispatch.PROBER_API_KEY_ENV, "").strip())


def read_our_proofs(con: sqlite3.Connection, api: ProberApi, *, opener=None,
                    now: datetime | None = None) -> bool:
    """Read our API's listing of this instance's live proofs and keep it for
    the screen (`dispatch.remember_api_proofs`). Returns whether it was read.
    No answer changes nothing kept, and is no failure of what asked."""
    client = dispatch.ApiTransport("-", base_url=api.base_url, key=api.key,
                                   opener=opener, allow_http=api.allow_http)
    try:
        proofs = client.live_proofs()
    except dispatch.DispatchFailed:
        return False
    dispatch.remember_api_proofs(con, proofs, now)
    return True


def twin_of(con: sqlite3.Connection, challenge_id: int) -> int | None:
    """The number of our API's challenge for this registry's challenge, or
    None when our API never saw it."""
    row = con.execute("SELECT remote_id FROM prober_challenges WHERE challenge_id = ?",
                      (challenge_id,)).fetchone()
    return None if row is None else row[0]


def start(con: sqlite3.Connection, api: ProberApi, host, address: str,
          method: str, *, opener=None, now: datetime | None = None) -> authz.Challenge:
    """Start one proof of `address` for `host`, on our API and then here.
    Raises `authz.TargetError` for what this registry refuses itself, before
    anything is sent, and `NotStarted` when our API did not start it."""
    if method not in dispatch.PROOF_METHOD_WORDS:
        raise ValueError(f"{method!r} is not a published proof method")
    target, _family = authz.normalise_target(address)
    if authz.active_exclusion(con, target) is not None:
        raise authz.AddressExcluded(f"{target} is excluded, so it is never proved")
    # One token for one server's token file (docs/PRODUCT.md 5, the clause
    # of 2026-10-03): the token the file already holds is named, and our API
    # gives it again when it is one it made for this instance.
    named = (authz.server_token(con, host, now)
             if method == authz.METHOD_HTTP_TOKEN else None)
    started, code = dispatch.start_api_proof(api.base_url, api.key, target, method,
                                             token=named, opener=opener,
                                             allow_http=api.allow_http)
    if started is None:
        log.info("address proof not started with the prober API: %s", code)
        raise NotStarted(code)
    challenge = authz.start_proof(con, target, method,
                                  account=authz.account_for_host(host),
                                  now=now, host_id=host["id"],
                                  adopt_token=started["token"])
    con.execute("INSERT INTO prober_challenges (challenge_id, remote_id, created_at)"
                " VALUES (?, ?, ?)",
                (challenge.id, started["id"],
                 (now or datetime.now(timezone.utc)).isoformat()))
    con.commit()
    return challenge


@dataclasses.dataclass(frozen=True)
class Verified:
    """The registry's answer, and which side did not prove it: None when
    both did, otherwise one of `REFUSERS`."""
    result: authz.ProofResult
    refused_by: str | None


def verify(con: sqlite3.Connection, api: ProberApi, challenge, *, opener=None,
           now: datetime | None = None, resolver=None, fetcher=None) -> Verified:
    """Verify one of this registry's challenges, on our API first and then
    here. `challenge` is its row, already known to be this host's.
    `resolver` and `fetcher` are this registry's readers, for the tests, as
    on `authz.verify_proof`. Our API uses its own."""
    closed = authz.challenge_closed(challenge, now)
    if closed is not None:
        return Verified(closed, INSTANCE)
    target = challenge["target"]
    remote_id = twin_of(con, challenge["id"])
    if remote_id is None:
        # Started here alone, before an instance did both, or before its
        # prober lines were set. Our API has nothing to read it against.
        return Verified(authz.ProofResult(False, verify_words(target, "no_such_challenge"),
                                          code="no_such_challenge"), PROBER_API)
    proved, code = dispatch.verify_api_proof(api.base_url, api.key, remote_id,
                                             opener=opener, allow_http=api.allow_http)
    if not proved:
        log.info("address proof not proved with the prober API: %s", code)
        return Verified(authz.ProofResult(False, verify_words(target, code), code=code),
                        PROBER_API)
    result = authz.verify_proof(con, challenge["id"], now=now,
                                resolver=resolver, fetcher=fetcher)
    if result.recorded:
        # So the address row reads proved at once, not after the next pass.
        read_our_proofs(con, api, opener=opener, now=now)
    return Verified(result, None if result.recorded else INSTANCE)


def revoke(con: sqlite3.Connection, api: ProberApi, address: str, *,
           account: str | None = None, opener=None,
           now: datetime | None = None) -> int:
    """Revoke one address, on our API first and then here, so a revoke on
    the instance still stops our probers at once now that an instance's batch
    takes our registry's proofs (docs/PRODUCT.md 5g, 2026-10-24). `account`
    is passed on to `authz.revoke` as it is: the dashboard passes its
    workspace's, the command line none, which revokes for every workspace.

    **Our side has one account for the whole instance**, so a revoke there
    ends the address for every workspace of it. With `account` given it goes
    to our API only when that workspace holds the address and no other
    workspace does (`authz.holds_alone`), and otherwise this registry alone
    is changed, which is all that workspace's revoke means.

    Returns how many proofs this registry closed. Raises `authz.TargetError`
    before anything is sent, and `NotRevoked`, with nothing changed here,
    when our API did not take it."""
    target, _family = authz.normalise_target(address)
    if account is None or authz.holds_alone(con, target, account, now):
        _end_on_our_api(api, target, opener)
    return authz.revoke(con, target, now=now, account=account)


def exclude(con: sqlite3.Connection, api: ProberApi, address: str, *,
            opener=None, now: datetime | None = None) -> tuple[bool, int]:
    """Put an address on this instance's exclusion list, ending it on our
    API first, so taking it off again restores nothing for our probers
    either (docs/PRODUCT.md 5g, the challenge of 2026-10-24). The exclusion
    is for every workspace, so the request goes whoever holds the address.
    Returns what `authz.exclude` returns. Raises `authz.TargetError` before
    anything is sent, and `NotRevoked`, with nothing changed here, when our
    API did not take it."""
    target, _family = authz.normalise_target(address)
    _end_on_our_api(api, target, opener)
    return authz.exclude(con, target, now=now)


def end_server(con: sqlite3.Connection, api: ProberApi, host, *, opener=None,
               now: datetime | None = None) -> int:
    """For Remove server and Delete: end on our API every address this
    server's own proofs prove that no other server holds (`authz.held_by_another_server`).
    Returns how many. Raises `NotRevoked` at the first our API did not take,
    and the caller then changes nothing here."""
    ended = 0
    for target in authz.proved_by_server(con, host["id"], now):
        if not authz.held_by_another_server(con, target, host["id"], now):
            _end_on_our_api(api, target, opener)
            ended += 1
    return ended


def server_words(name: str, act: str, code: str) -> str:
    return f"{name} not {act} with the probers: {code}"


def _end_on_our_api(api: ProberApi, target: str, opener) -> None:
    """Every proof of this instance's of one address ends on our side, or
    `NotRevoked` with its class."""
    revoked, code = dispatch.revoke_api_proof(api.base_url, api.key, target,
                                              opener=opener, allow_http=api.allow_http)
    if not revoked:
        log.info("address not revoked with the prober API: %s", code)
        raise NotRevoked(code)
