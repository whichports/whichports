"""Drive a prober that lives on another machine, and store what it measured.

The control plane owns the database and the authorisation registry. The prober
owns an address and nothing else. This is the piece between them.

## The shape, and why it is this one

For each batch of ports: read the registry, build a snapshot, send the batch,
read the measurement back, and only then move on. **The snapshot is built per
batch rather than per run, and that is the whole point.** A target revoked
while a pass is running stops being probed at the next batch boundary rather
than at the end of the pass, which for a full port sweep is the difference
between seconds and half an hour. `docs/RECORD.md` has the reasoning.

## The direction of trust

The control plane reaches out to the prober and the prober never reaches back.
The prober holds no credential, no database and nothing it could use to reach
this machine. That direction is deliberate: the prober is the box that attracts
abuse reports and is therefore the one most likely to be taken, and a compromise
of it must not reach the control plane.

## What it refuses to do

A batch that comes back unreadable **fails the whole pass for that host** and
stores nothing. Storing the batches that did work would produce a run that
looks like a complete pass over a host and is not, which is `docs/RECORD.md`
4.46's shape and the thing this project keeps having to correct.

## More than one vantage, since 2026-09-08

`run_pass` drives every enabled vantage in `app/vantages.py` over every host,
**one transport call at a time, host by host, vantage by vantage.** That
ordering is the pace rule of `docs/PRODUCT.md` 5d written as control flow: the
40 connects a second is what one target host receives from us in total, across
every vantage, and two vantages probing one host at the same moment would put
80 on it. Each vantage's runner paces itself at the full rate, and because no
two of them are ever in flight against the same host, the host never sees more
than one runner's rate. A test holds a transport that fails the moment a second
call for the same host begins while one is open, so a future refactor towards
concurrency turns red rather than quietly doubling what a customer sees.

**That ordering holds inside one process, and `app/probelock.py` makes it hold
across processes.** The fast lane, the hourly lane and the scan responder are
three processes running this same pass, and until 2026-09-12 nothing stopped
two of them landing on one host together, each with a full allowance. Since
phase 1 of docs/SPEC-probe-locks.md each batch takes its prober's lock and its
addresses' before its snapshot is read (`run_host`), so passes run beside each
other and a host still never has more than one of our runners against it. A
self-hosted instance holds `probe.lock` whole for each pass instead, one pass
at a time.

**A vantage that cannot be reached is skipped for the rest of the pass, and the
others continue.** Its stored runs simply stop, which is what the dead-man
watch in `app/finding_alerts.py` looks for, and the pass says so per host. A
vantage that answers but refuses one host's batch is a fact about that host
and that vantage only, and the next host is still tried from it.

**Our own addresses are never targets.** Every address in the registry, of an
enabled vantage or a disabled one, is taken out of every plan before a batch is
built, and each one leaves a `not_tested` row per port with the typed reason
`prober.REASON_VANTAGE_ADDRESS`, so a screen says why rather than showing a
gap. `app/probe_runner.py` refuses its own address on the box as well, and the
two guards are deliberately both there: the runner knows its own interfaces
without being told, and only the control plane knows the other box.
"""
import asyncio
import contextlib
import dataclasses
import http.client
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from . import (alerts, authz, finding_alerts, intent as intent_store, join,
               probelock, prober)

# Ports per batch. Small enough that a revocation lands quickly, large enough
# that the round trip to the vantage host is a rounding error beside the pace
# limit: 200 connects at 40 a second is five seconds of probing against about
# 30 ms of transport.
BATCH_PORTS = 200

BATCH_VERSION = 1


class _RefuseEverything:
    """An authority for a pass that will not touch the network.

    Used only when a host has no probeable address, where there is nothing to
    ask about. **Verified rather than assumed: with an empty address list the
    engine never consults the authority at all**, so an empty snapshot would
    behave identically and mutation testing correctly reports the swap as
    surviving.

    It is here for two reasons that are not safety. It says what the path is,
    which an empty snapshot does not, and it needs no database read to build.
    If the empty path ever starts passing addresses, this refuses them and
    something turns red rather than a batch quietly going out.
    """

    def require(self, address, now=None):
        raise authz.NotAuthorized(
            "this host reports no address that can be a probe target")


class DispatchFailed(RuntimeError):
    """The prober could not be driven, or answered with something unusable."""


class VantageUnreachable(DispatchFailed):
    """The vantage host itself could not be reached or would not let us in.

    Its own type because a pass treats it differently from a refused batch:
    the box is not going to answer for the next host either, so `run_pass`
    stops trying it for the rest of the pass. `ssh` exits 255 for every
    failure of its own, a connection that did not open, a key that was not
    accepted, a host key that did not match, and that number is ssh's rather
    than the runner's, whose refusals exit 2.
    """


# ssh's own exit status, for any error of its own rather than of the command
# it ran. `man ssh`, EXIT STATUS: "ssh exits with the exit status of the remote
# command or with 255 if an error occurred."
SSH_ERROR_EXIT = 255

# How long ssh waits for the connection to open before giving up. A vantage
# host that is down would otherwise hold a pass for the TCP handshake timeout
# of the control plane's kernel, per host, before being skipped.
SSH_CONNECT_TIMEOUT_SECONDS = 30


def batches(ports, size: int = BATCH_PORTS):
    """Split ports into batches, order preserved, no batch empty.

    A pass with no ports still yields one empty batch, because a host with
    nothing listening is a real answer and has to reach the database as a run
    rather than as nothing at all.
    """
    ports = list(ports)
    if not ports:
        return [[]]
    if size < 1:
        raise ValueError("batch size must be at least one port")
    return [ports[i:i + size] for i in range(0, len(ports), size)]


def build_batch(con, vantage: str, addresses, ports, *, tls_ports=(),
                now: datetime | None = None,
                account: str = authz.DEFAULT_ACCOUNT,
                ours: dict | None = None) -> dict:
    """One batch, with the authorisation snapshot read at this moment.

    **Read fresh here, every batch.** Reusing a snapshot across batches would
    put the revocation window back to the length of the whole pass, which is
    the cost this design exists to avoid paying.

    `account` is the workspace's account. It only ever narrows the snapshot: an
    address the workspace did not prove is simply absent, and absence is a
    refusal (`authz.build_snapshot`).

    `ours` is set for a batch a self-hosted instance sends to our prober API:
    our registry's live proofs for that instance, as our API lists them
    (`ApiTransport.live_proofs`), which the snapshot takes beside this
    registry's own where the rules of `authz.snapshot_for_prober_api` allow
    (docs/PRODUCT.md 5g, 2026-10-24). Our own worker builds its batches
    without it, from our registry.
    """
    if ours is not None:
        snapshot = authz.snapshot_for_prober_api(con, addresses, ours, now=now,
                                                 account=account)
    else:
        snapshot = authz.build_snapshot(con, addresses, now=now, account=account)
    return {
        "version": BATCH_VERSION,
        "vantage": vantage,
        "addresses": list(addresses),
        "ports": list(ports),
        "tls_ports": list(tls_ports),
        "snapshot": authz.snapshot_to_json(snapshot),
    }


class SshTransport:
    """Runs the batch through `ssh` on the vantage host.

    **The local side is an argv array and never a shell string** (SI-4), so
    nothing on this machine parses a command.

    **Be accurate about the remote side.** `ssh` always hands its command to
    the login shell on the far end, so saying "no shell is involved" would be
    false. What is true, and what matters, is that every element below is a
    fixed constant: there is no metacharacter and nothing per-target is
    interpolated. `env` is used instead of `cd X && ...` precisely so that no
    `&&` has to be interpreted for this to work. The batch, which is the only
    part that varies, arrives on stdin where no shell ever sees it.

    The remote command takes no arguments, which is the other half of the same
    idea: there is nowhere for a target to arrive except inside the batch,
    where the snapshot governs it.
    """

    def __init__(self, destination: str, *, command=("python3", "-m",
                                                     "app.probe_runner"),
                 ssh: str = "ssh", directory: str = "/opt/whichports",
                 timeout: int = 900):
        self.destination = destination
        self.command = tuple(command)
        self.ssh = ssh
        self.directory = directory
        self.timeout = timeout

    def argv(self) -> list:
        return [
            self.ssh, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={SSH_CONNECT_TIMEOUT_SECONDS}",
            self.destination, "--",
            "env", f"PYTHONPATH={self.directory}", *self.command,
        ]

    def __call__(self, payload: str) -> str:
        try:
            done = subprocess.run(self.argv(), input=payload,
                                  capture_output=True, text=True,
                                  timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise VantageUnreachable(
                f"could not run the prober: {exc}") from None
        if done.returncode == SSH_ERROR_EXIT:
            raise VantageUnreachable(
                "ssh could not reach the vantage host or was not let in: "
                f"{(done.stderr or '').strip()[:300]}")
        if done.returncode != 0:
            # The runner's own stderr is a closed set of refusals, so it is
            # safe to pass on. It is truncated because a remote machine's
            # output is not something to log unbounded.
            raise DispatchFailed(
                f"the prober exited {done.returncode}: "
                f"{(done.stderr or '').strip()[:300]}")
        return done.stdout


# ================================================= through our prober API
#
# A self-hosted whichports has no prober of its own. It uses probe1 and probe2
# through the API on our control plane (`app/proberapi.py`), and this is the
# transport that makes that invisible to everything above it: the same batch
# goes in as `SshTransport` receives, and the same runner JSON comes out, so
# `run_host`, the storage and the dead-man watch do not change at all. One
# part of the batch differs since 2026-10-24: its snapshot also takes our
# registry's live proofs for the instance (`build_batch`, `ours`).
#
# Chosen by two settings in the instance's environment, and never by default,
# so a control plane that has them unset keeps using ssh exactly as before.

PROBER_API_ENV = "WHICHPORTS_PROBER_API"
PROBER_API_KEY_ENV = "WHICHPORTS_PROBER_API_KEY"

# Where the API's routes live under the base URL (`proberapi.PATH_PREFIX`,
# written again here because the self-hosted side must not import the server
# half of the API, and a test holds the two equal).
PROBER_API_PATH = "/api/v1/prober"

# How long a pass waits for one batch, the same fifteen minutes
# `SshTransport` gives a runner and the API keeps a batch for.
API_DEADLINE_SECONDS = 15 * 60

# How often the answer is asked for while the batch waits its turn.
API_POLL_SECONDS = 1.0

# One HTTP request. A request that takes longer is the API being down.
API_REQUEST_SECONDS = 30.0

# The most of an answer that is read. A batch is 200 ports and a few
# addresses, so its answer is well under a megabyte. Beyond this it is not an
# answer.
API_MAX_ANSWER_BYTES = 8 * 1024 * 1024

# The API's refusals that are about the vantage or the API rather than about
# this host, so the pass stops asking this vantage for the rest of it, the
# same as when ssh cannot reach the box. Every other class is about this
# batch, and the next host is still tried.
API_UNREACHABLE_ERRORS = frozenset({
    "unknown_key", "unknown_vantage", "batch_in_flight", "over_instance_pace",
    "vantage_unreachable",
})


class TransportConfigError(ValueError):
    """The prober API is half configured. A pass refuses rather than falling
    back to ssh, because a self-hosted box has nothing to ssh to."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """A 3xx is a failure, never a hop. urllib keeps the Authorization header
    when it follows a redirect to another host, so following one would hand
    the instance's key to wherever the redirect pointed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _Refused(Exception):
    """The API answered with an HTTP error. `error` is the class its body
    carried, or None when it carried none, a proxy's own page say."""

    def __init__(self, status: int, error):
        super().__init__(status)
        self.status = status
        self.error = error


class ApiTransport:
    """Runs the batch through our prober API instead of ssh.

    `destination` is the vantage's name at the API, which is what a vantage
    row on a self-hosted instance holds where ours holds `user@host`
    (`vantages_cli sync-api`). It replaces the batch's own vantage name,
    which is the instance's name for the row and may differ.

    The API answers in two steps, because a batch waits its turn behind every
    other probe we run (`app/proberapi.py`, "The pace"): the batch is queued,
    and its answer is asked for until it is there. Every failure raises one of
    the two exceptions `SshTransport` raises, with the API's error class in the
    message and nothing the API said beyond it.
    """

    def __init__(self, destination: str, *, base_url: str, key: str,
                 opener=None, deadline_seconds: float = API_DEADLINE_SECONDS,
                 poll_seconds: float = API_POLL_SECONDS,
                 clock=None, sleep=None, allow_http: bool = False):
        self.destination = destination
        self.base_url = _checked_base_url(base_url, allow_http)
        if not isinstance(key, str) or not key.strip():
            raise TransportConfigError("the prober API needs this instance's key")
        self._key = key.strip()
        self._opener = opener or urllib.request.build_opener(_RefuseRedirects())
        self._deadline = deadline_seconds
        self._poll = poll_seconds
        self._clock = clock or time.monotonic
        self._sleep = sleep or time.sleep

    def __call__(self, payload: str) -> str:
        try:
            batch = json.loads(payload)
        except ValueError:
            raise DispatchFailed("the batch handed to the prober API is not JSON") from None
        batch["vantage"] = self.destination
        status, body = self._request("POST", "/batches", json.dumps(batch).encode())
        if status != 202 or not isinstance(body.get("id"), str):
            raise VantageUnreachable(
                f"the prober API answered {status} to a batch, not a queued batch")
        path = "/batches/" + urllib.parse.quote(body["id"], safe="")
        started = self._clock()
        while True:
            status, body = self._request("GET", path)
            if status == 200 and body.get("state") == "done":
                answer = body.get("answer")
                if not isinstance(answer, dict):
                    raise DispatchFailed("the prober API's answer is not a measurement")
                return json.dumps(answer)
            if status == 200 and body.get("state") == "failed":
                self._raise_for(body.get("error"), "the batch")
            if status != 202:
                raise VantageUnreachable(
                    f"the prober API answered {status} while a batch waited")
            if self._clock() - started >= self._deadline:
                raise VantageUnreachable(
                    f"the prober API did not answer within {self._deadline:g}"
                    " seconds, so this vantage was not measured")
            self._sleep(self._poll)

    def live_proofs(self) -> dict:
        """Our registry's live proofs for this instance, as our API lists
        them (`GET /proofs`): {canonical address: (when our side last proved
        it, when the proof ends)}, the newest of each address's proofs.
        Asked once per batch, as the snapshot is built once per batch. An
        entry that does not read is left out, which only narrows. An answer
        that is not a listing stops this vantage for the pass, as any API
        failure does."""
        status, body = self._request("GET", "/proofs")
        listed = body.get("proofs")
        if status != 200 or not isinstance(listed, list):
            raise VantageUnreachable("the prober API did not list its proofs")
        proofs: dict = {}
        for entry in listed:
            if not isinstance(entry, dict):
                continue
            try:
                target, _family = authz.normalise_target(entry.get("address"))
                proved = datetime.fromisoformat(entry.get("verified_at"))
                ends = datetime.fromisoformat(entry.get("expires_at"))
            except (authz.TargetError, TypeError, ValueError):
                continue
            if proved.tzinfo is None or ends.tzinfo is None:
                continue
            before = proofs.get(target)
            if before is not None:
                proved, ends = max(proved, before[0]), max(ends, before[1])
            proofs[target] = (proved, ends)
        return proofs

    def _exchange(self, method: str, url: str, data: bytes | None,
                  timeout: float):
        """One request to our box, with this instance's key, and what came
        back: (status, the JSON object answered). An HTTP error is raised as
        `_Refused` with the class its body carries. This is the one place a
        request to our box is built, so every one of them is https, carries
        the key in the header and nothing else of this instance's, and never
        follows a redirect."""
        request = urllib.request.Request(
            url, data=data, method=method,
            headers={"Authorization": f"Bearer {self._key}",
                     "Content-Type": "application/json",
                     "User-Agent": "whichports-prober-api-client"})
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return response.status, _json_object(
                    response.read(API_MAX_ANSWER_BYTES + 1))
        except urllib.error.HTTPError as exc:
            # An error body that is not the API's JSON, a proxy's HTML page
            # for a 502 say, carries no class. Read here, inside its own try,
            # because an exception raised in this handler would not reach the
            # caller's handlers and would take the whole pass down.
            try:
                error = _json_object(exc.read(4096)).get("error")
            except (OSError, ValueError):
                error = None
            finally:
                exc.close()
            raise _Refused(exc.code, error) from None

    def _request(self, method: str, path: str, data: bytes | None = None):
        """(status, the JSON object answered). An HTTP error that carries one
        of the API's classes is raised as that class. Everything else that is
        not an answer is the API being unreachable."""
        try:
            return self._exchange(method, self.base_url + PROBER_API_PATH + path,
                                  data, API_REQUEST_SECONDS)
        except _Refused as refused:
            self._raise_for(refused.error, f"HTTP {refused.status}")
        except (OSError, ValueError) as exc:
            raise VantageUnreachable(
                f"the prober API could not be reached: {type(exc).__name__}") from None

    @staticmethod
    def _raise_for(error, what: str):
        """One of the API's classes as one of our two exceptions. A class
        this build does not know is read as the API being unreachable, which
        stops the pass asking and says so, rather than guessing."""
        if not isinstance(error, str) or not error.isidentifier() \
                or len(error) > 64:
            raise VantageUnreachable(f"the prober API refused {what} with no class")
        if error in API_UNREACHABLE_ERRORS:
            raise VantageUnreachable(f"the prober API refused {what}: {error}")
        raise DispatchFailed(f"the prober API refused {what}: {error}")


def _checked_base_url(base_url, allow_http: bool) -> str:
    """https, a host, and nothing after it. The key travels in a header, so
    plain http would send it in the clear. `allow_http` exists for the tests,
    which serve the real client from loopback, and nothing else sets it."""
    if not isinstance(base_url, str):
        raise TransportConfigError("the prober API's address is not text")
    parsed = urllib.parse.urlsplit(base_url.strip())
    schemes = ("https", "http") if allow_http else ("https",)
    if parsed.scheme not in schemes or not parsed.hostname \
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment \
            or parsed.username or parsed.password:
        raise TransportConfigError(
            f"{PROBER_API_ENV} is an https address with nothing after the host,"
            f" such as https://app.whichports.com. {base_url!r} is not")
    return f"{parsed.scheme}://{parsed.netloc}"


def _json_object(raw: bytes) -> dict:
    if len(raw) > API_MAX_ANSWER_BYTES:
        raise ValueError("the answer is larger than any answer")
    parsed = json.loads(raw.decode("utf-8")) if raw else {}
    if not isinstance(parsed, dict):
        raise ValueError("the answer is not an object")
    return parsed


def default_transport_factory(environ=None):
    """What a pass drives its vantages with: `SshTransport`, unless this
    control plane is configured to use our prober API.

    Both settings or neither. One without the other raises, because a
    self-hosted box that half set it up has nothing to ssh to, and a pass
    that quietly tried ssh would fail every vantage for a reason nobody
    configured.
    """
    environ = os.environ if environ is None else environ
    base_url = environ.get(PROBER_API_ENV, "").strip()
    key = environ.get(PROBER_API_KEY_ENV, "").strip()
    if not base_url and not key:
        return SshTransport
    if not base_url or not key:
        raise TransportConfigError(
            f"{PROBER_API_ENV} and {PROBER_API_KEY_ENV} go together, and only"
            " one of them is set")
    _checked_base_url(base_url, allow_http=False)
    return lambda destination: ApiTransport(destination, base_url=base_url, key=key)


def uses_prober_api(environ=None) -> bool:
    """Whether this control plane probes through our prober API, which is a
    self-hosted instance. Either setting counts, so an instance that half
    set it up is still taken for one.

    Such a control plane holds `probe.lock` whole for each pass, one pass at
    a time, and never the finer locks (docs/SPEC-probe-locks.md, point 7).
    Our API takes one batch of an instance at a time and refuses a second as
    `batch_in_flight`, which the instance reads as the vantage gone for the
    rest of its pass, so two of its passes at once would cost it a pass.
    """
    environ = os.environ if environ is None else environ
    return bool(environ.get(PROBER_API_ENV, "").strip()
                or environ.get(PROBER_API_KEY_ENV, "").strip())


# The third setting, and the only one an agent needs: the instance's proof
# key, which its install command hands to every server it enrols so the agent
# can prove its own addresses to the API (agent/internal/report/client.go,
# ProveToProber). It authorises nothing else.
PROBER_PROOF_KEY_ENV = "WHICHPORTS_PROBER_PROOF_KEY"

# The shape `app/instances.py` issues: its prefix and 64 hex characters. Read
# here rather than imported, because the self-hosted side does not carry the
# server half of the API. A test holds the two equal.
PROOF_KEY_RE = re.compile(r"^whpp_[0-9a-f]{64}$")


def prober_enroll_flags(environ=None) -> str:
    """The two flags `whichports-agent enroll` takes when this control plane
    uses our prober API, or "" when it does not.

    Both the API's address and the proof key have to be set, and set right,
    for the flags to appear. Anything less gives "", so our own control
    plane, which sets neither, hands out exactly the command it always has.
    Every value is checked to a shape with no space and no shell character in
    it before it goes into a line somebody pastes into a root shell.
    """
    environ = os.environ if environ is None else environ
    base_url = environ.get(PROBER_API_ENV, "").strip()
    proof_key = environ.get(PROBER_PROOF_KEY_ENV, "").strip()
    if not base_url or not PROOF_KEY_RE.fullmatch(proof_key):
        return ""
    try:
        server = _checked_base_url(base_url, allow_http=False)
    except TransportConfigError:
        return ""
    if not re.fullmatch(r"https://[A-Za-z0-9.:\[\]-]+", server):
        return ""
    return f" --prober-server={server} --prober-proof-key={proof_key}"


def fetch_api_vantages(base_url: str, key: str, opener=None,
                       allow_http: bool = False) -> list:
    """Our vantages as the API lists them: [{name, enabled, addresses}]. For
    `vantages_cli sync-api`, so an instance's registry names exactly the
    vantages it may ask for and keeps every one of their addresses out of
    its targets."""
    client = ApiTransport("-", base_url=base_url, key=key, opener=opener,
                          allow_http=allow_http)
    status, body = client._request("GET", "/vantages")
    listed = body.get("vantages")
    if status != 200 or not isinstance(listed, list):
        raise VantageUnreachable("the prober API did not list its vantages")
    return listed


# ---------------------------------------------------------------- feedback
#
# The Feedback window's one request from an instance to our box
# (app/feedback.py, docs/record 4.425). It goes out through the client above
# and no second one, so it is https, never follows a redirect with the key,
# and carries the key in the header and nothing else of this instance's.
FEEDBACK_PATH = "/api/v1/feedback"

# The window waits ten seconds for its answer. This gives up sooner, so that
# a person is not told "No answer" while our box stores the message a moment
# later. A message can still arrive twice when the answer is lost on its way
# back. Nothing is sent a second time from here.
FEEDBACK_REQUEST_SECONDS = 8.0

# What `send_feedback` says when our box did not answer with a class.
NO_ANSWER = "no_answer"


def send_feedback(base_url: str, key: str, body: dict, opener=None,
                  allow_http: bool = False) -> tuple[bool, str]:
    """Send one message to our box, once. Returns whether our box stored it,
    and when it did not, why: the class it refused with when it gave one,
    and `NO_ANSWER` for everything else: no connection, no answer in time,
    an answer that is not ours. Nothing is retried and nothing in the answer
    is kept.

    Two values and not one word, so that nothing our box could put in an
    error body can ever read as "stored".

    The body is written as UTF-8 and not escaped to ASCII. Escaped, a
    character outside ASCII is six bytes, and a message in another alphabet
    would hit our box's byte cap long before its 2,000 characters.

    Raises `TransportConfigError` for an address that is not plain https or
    for no key, before anything is sent.
    """
    client = ApiTransport("-", base_url=base_url, key=key, opener=opener,
                          allow_http=allow_http)
    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    try:
        status, _answer = client._exchange(
            "POST", client.base_url + FEEDBACK_PATH, data, FEEDBACK_REQUEST_SECONDS)
    except _Refused as refused:
        said = refused.error
        return False, said if isinstance(said, str) and said else NO_ANSWER
    except (OSError, ValueError):
        return False, NO_ANSWER
    if status != 200:
        return False, NO_ANSWER
    return True, ""


# ------------------------------------------------------------------ proofs
#
# An instance's DNS TXT and token file proofs, made on our prober API too
# (`app/proberproofs.py`, docs/PRODUCT.md 5g, 2026-10-24). The two requests
# go out through the client above and no second one, so they are https, never
# follow a redirect with the key, and carry the key in the header and nothing
# else of the instance's. Each answers two values and never raises for what
# our box said, the shape `send_feedback` has.

# The ways a proof is named on the wire, as our routes name them
# (`proberapi_routes.PROOF_METHODS`, held equal by a test).
PROOF_METHOD_WORDS = {authz.METHOD_DNS_TXT: "dns-txt",
                      authz.METHOD_HTTP_TOKEN: "http-token"}

# The shape of a token our registry makes (`authz.TOKEN_SHAPE`). A start
# whose answer carries anything else is no answer.
PROOF_TOKEN_RE = authz.TOKEN_SHAPE

# Starting reads nothing on our side, so it is quick or it is down.
PROOF_START_SECONDS = 10.0

# Verifying makes our box read the record or the file, ten seconds at most
# for each read, and the instance reads it again after. The window waits
# thirty seconds for the whole of it, so ours is given twenty.
PROOF_VERIFY_SECONDS = 20.0

# Our refusals passed on as they are. `unknown_challenge` is passed on as the
# registry's own word for it, `no_such_challenge`, which the window already
# knows means start again. Every other answer is no answer.
PROOF_REFUSALS = frozenset({"unknown_key", "malformed_request", "target_refused",
                            "over_instance_pace"})


def _proof_refusal(error) -> str:
    if error == "unknown_challenge":
        return "no_such_challenge"
    return error if error in PROOF_REFUSALS else NO_ANSWER


def start_api_proof(base_url: str, key: str, address: str, method: str,
                    token: str | None = None, opener=None,
                    allow_http: bool = False) -> tuple[dict | None, str]:
    """Start one DNS TXT or token file proof on our API, once. Returns
    ({"id", "token"} of the challenge our API made, "") or (None, the class
    it refused with, or `NO_ANSWER`).

    `address` is the canonical text and `method` the registry's word. `token`
    is the one a server's token file already holds, for a token file proof
    of another address of the same server, which our API gives again when it
    is one it made for this instance. An answer is ours only when it is a new
    challenge for exactly that address and that way, with a token of our
    shape. Anything else is no answer, so nothing our box could say is taken
    for a token.
    """
    word = PROOF_METHOD_WORDS[method]
    client = ApiTransport("-", base_url=base_url, key=key, opener=opener,
                          allow_http=allow_http)
    body = {"address": address, "method": word}
    if token is not None:
        body["token"] = token
    data = json.dumps(body).encode()
    try:
        status, answer = client._exchange(
            "POST", client.base_url + PROBER_API_PATH + "/proofs/challenges",
            data, PROOF_START_SECONDS)
    except _Refused as refused:
        return None, _proof_refusal(refused.error)
    except (OSError, ValueError, http.client.HTTPException):
        return None, NO_ANSWER
    challenge_id = answer.get("id")
    token = answer.get("token")
    if status != 201 or isinstance(challenge_id, bool) \
            or not isinstance(challenge_id, int) or challenge_id < 1 \
            or answer.get("address") != address or answer.get("method") != word \
            or not isinstance(token, str) or not PROOF_TOKEN_RE.fullmatch(token):
        return None, NO_ANSWER
    return {"id": challenge_id, "token": token}, ""


def verify_api_proof(base_url: str, key: str, challenge_id: int, opener=None,
                     allow_http: bool = False) -> tuple[bool, str]:
    """Ask our API to read the evidence of one challenge it made, once.
    Returns (whether it proved the address, the class): `proved`, a code of
    the registry's (`authz.PROOF_CODES`), one of `PROOF_REFUSALS`, or
    `NO_ANSWER`. Our box reads the record or the file itself. Nothing is sent
    but the challenge's number, and nothing in the answer is taken but those
    two values, and only when they agree with each other."""
    client = ApiTransport("-", base_url=base_url, key=key, opener=opener,
                          allow_http=allow_http)
    path = f"{PROBER_API_PATH}/proofs/challenges/{int(challenge_id)}/verify"
    try:
        status, answer = client._exchange("POST", client.base_url + path, b"",
                                          PROOF_VERIFY_SECONDS)
    except _Refused as refused:
        return False, _proof_refusal(refused.error)
    except (OSError, ValueError, http.client.HTTPException):
        return False, NO_ANSWER
    proved = answer.get("proved")
    code = answer.get("result")
    if status != 200 or not isinstance(proved, bool) \
            or code not in authz.PROOF_CODES or proved != (code == "proved"):
        return False, NO_ANSWER
    return proved, code


# Our registry's live proofs for this instance, as our API last listed them,
# kept on the instance for its screen (docs/PRODUCT.md 5g, the challenge of
# 2026-10-24): an address row reads proved only when our side holds it too.
# Replaced whole at every reading: every batch reads it, and so does a
# verify both sides proved. Nothing else of our answer is kept.
API_PROOFS_SCHEMA = """
CREATE TABLE IF NOT EXISTS prober_api_proofs (
    target     TEXT PRIMARY KEY,
    proved_at  TEXT NOT NULL,
    ends_at    TEXT NOT NULL,
    read_at    TEXT NOT NULL
);
"""


def remember_api_proofs(con: sqlite3.Connection, proofs: dict,
                        now: datetime | None = None) -> None:
    """Keep our API's listing (`ApiTransport.live_proofs`) in place of the
    one before, in one transaction."""
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    con.executescript(API_PROOFS_SCHEMA)
    with con:
        con.execute("DELETE FROM prober_api_proofs")
        con.executemany(
            "INSERT INTO prober_api_proofs (target, proved_at, ends_at, read_at)"
            " VALUES (?, ?, ?, ?)",
            [(target, proved.isoformat(), ends.isoformat(), stamp)
             for target, (proved, ends) in sorted(proofs.items())])


def api_proofs_held(con: sqlite3.Connection, now: datetime | None = None) -> set:
    """The addresses our API last listed as live for this instance whose
    proof has not ended since, read by position so a bare connection reads
    it too. Empty when it was never read, which says nothing is held."""
    moment = now or datetime.now(timezone.utc)
    try:
        rows = con.execute("SELECT target, ends_at FROM prober_api_proofs").fetchall()
    except sqlite3.OperationalError:
        return set()
    held = set()
    for target, ends_at in rows:
        try:
            ends = datetime.fromisoformat(ends_at)
        except (TypeError, ValueError):
            continue
        if ends.tzinfo is not None and ends > moment:
            held.add(target)
    return held


def revoke_api_proof(base_url: str, key: str, address: str, opener=None,
                     allow_http: bool = False) -> tuple[bool, str]:
    """Ask our API to end every proof this instance holds of one address,
    once, for a revoke on the instance's dashboard. Returns (whether our API
    took it, "") or (False, one of `PROOF_REFUSALS`, or `NO_ANSWER`). Nothing
    is sent but the address, in the path."""
    client = ApiTransport("-", base_url=base_url, key=key, opener=opener,
                          allow_http=allow_http)
    path = PROBER_API_PATH + "/proofs/" + urllib.parse.quote(address, safe="")
    try:
        status, answer = client._exchange("DELETE", client.base_url + path, None,
                                          PROOF_START_SECONDS)
    except _Refused as refused:
        return False, _proof_refusal(refused.error)
    except (OSError, ValueError, http.client.HTTPException):
        return False, NO_ANSWER
    revoked = answer.get("revoked")
    if status != 200 or isinstance(revoked, bool) or not isinstance(revoked, int):
        return False, NO_ANSWER
    return True, ""


def split_targets(targets, exclude) -> tuple[list, list]:
    """(the targets to probe, the ones that are our own vantage addresses).

    Compared canonical against canonical: the registry stores what
    `authz.normalise_target` returns and so does every plan, so a spelling
    difference cannot let one of ours through. A target that is not an address
    at all is kept, because the engine records those with its own reason.
    """
    kept, ours = [], []
    for target in targets:
        try:
            canonical, _family = authz.normalise_target(target)
        except authz.TargetError:
            kept.append(target)
            continue
        (ours if canonical in exclude else kept).append(target)
    return kept, ours


def _vantage_address_rows(ours, ports, stamp: str) -> list:
    """One `not_tested` row per port for each of our own addresses, so a
    screen says why the address was not measured rather than showing a gap."""
    rows = []
    entries = prober.normalise_ports(list(ports))
    for address in ours:
        _canonical, family = authz.normalise_target(address)
        for entry in entries:
            rows.append(prober.Result(
                family=family, target=address, port=entry.port,
                state=prober.STATE_NOT_TESTED,
                reason=entry.reason or prober.REASON_VANTAGE_ADDRESS,
                measured_at=stamp))
    return rows


@contextlib.contextmanager
def _batch_locked(locks, addresses, vantage: str, host_id):
    """Hold one batch's locks while it is built and sent (`probelock.Locks`),
    or take none when `locks` is None.

    A prober that stayed busy for the whole wait is the vantage not being
    there for this pass, so it is raised as `VantageUnreachable` and the pass
    skips it for the hosts after this one. An address that stayed busy is a
    fact about this host only, `DispatchFailed`, and the next host is tried.
    Either way nothing was sent, nothing is held, and the journal gets one
    typed line for it (`probelock.held_line`).
    """
    if locks is None:
        yield
        return
    held = locks.taking(addresses)
    try:
        held.acquire()
    except probelock.ProberBusy as exc:
        print(probelock.held_line(exc, vantage, host_id), file=sys.stderr)
        raise VantageUnreachable(str(exc)) from None
    except probelock.AddressBusy as exc:
        print(probelock.held_line(exc, vantage, host_id), file=sys.stderr)
        raise DispatchFailed(str(exc)) from None
    try:
        yield
    finally:
        held.release()


def run_host(con, plan, transport, vantage: str, *, tls_ports=(),
             batch_size: int = BATCH_PORTS,
             now: datetime | None = None,
             exclude=frozenset(),
             locks: probelock.BatchLocks | None = None) -> prober.Run:
    """One pass over one host, in batches, stored as a single run.

    Returns the stored run. Raises `DispatchFailed` without storing anything if
    any batch could not be run or could not be read.

    `exclude` is every vantage address in the registry. A target in it is never
    sent and leaves a typed `not_tested` row instead, per port, in the run.

    `locks` is how each batch takes its prober's lock and its addresses'
    (`app/probelock.py`, the finer locks). **The batch's snapshot is built
    only once they are held**, and so is our API's listing on an instance, so
    a revoke or an exclusion that lands while a batch waits holds for that
    batch. Let go as soon as the runner has answered. None takes no
    lock per batch, for a pass whose caller holds `probe.lock` whole for all
    of it, which is a self-hosted instance's.
    """
    addresses, ours = split_targets(plan.targets, exclude)
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    own_rows = _vantage_address_rows(ours, plan.ports, stamp)

    # A host with no probeable address is an answer, not a failure.
    #
    # Measured on 2026-08-18: one of our servers holds only Tailscale and
    # carrier-NAT addresses, so its target list is empty. The batch was sent anyway, the
    # runner correctly refused it as naming no addresses, and the whole host
    # read as "not measured" while the local path reports the same host as
    # `not_tested` per port. Two paths, two answers, and the wrong one also
    # made the pass exit non zero, so an hourly timer would have reported
    # failure forever for a host that simply cannot be reached.
    #
    # The engine already knows how to say this, so it is asked rather than
    # imitated. `measure` with no addresses produces one `not_tested` row per
    # port per family with `no_address_in_family`, which is what the local path
    # returns and therefore what this must return too.
    if not addresses:
        empty = asyncio.run(prober.Prober(vantage=vantage).measure(
            _RefuseEverything(), [], list(plan.ports), tls_ports=tls_ports))
        # A family whose only address was one of ours is not a family the host
        # has no address in, so the engine's no_address_in_family rows for
        # that family give way to the typed rows about our address.
        families_ours = {authz.normalise_target(a)[1] for a in ours}
        kept = tuple(r for r in empty.results if r.family not in families_ours)
        merged = dataclasses.replace(empty, results=kept + tuple(own_rows))
        return prober.store_measurement(con, plan.host_id, merged)

    results = []
    certificates = []
    started = None
    finished = None

    for ports in batches(plan.ports, batch_size):
        with _batch_locked(locks, addresses, vantage, plan.host_id):
            ours = None
            if isinstance(transport, ApiTransport):
                ours = transport.live_proofs()
                remember_api_proofs(con, ours, now)
            payload = build_batch(con, vantage, addresses, ports,
                                  tls_ports=tls_ports, now=now,
                                  account=getattr(plan, "account",
                                                  authz.DEFAULT_ACCOUNT),
                                  ours=ours)
            raw = transport(json.dumps(payload))
        try:
            measured = prober.run_from_json(json.loads(raw))
        except (ValueError, prober.RunUnreadable) as exc:
            raise DispatchFailed(
                f"the prober answered with something unusable: {exc}") from None
        results.extend(measured.results)
        certificates.extend(measured.certificates)
        started = measured.started_at if started is None else min(
            started, measured.started_at)
        finished = measured.finished_at if finished is None else max(
            finished, measured.finished_at)

    merged = prober.Run(id=None, vantage=vantage, started_at=started,
                        finished_at=finished,
                        results=tuple(results) + tuple(own_rows),
                        certificates=tuple(certificates))
    return prober.store_measurement(con, plan.host_id, merged)


# ====================================================== every vantage, in turn

# What a pass says about a server that was deleted after the pass took its
# list of servers. A typed line, the same every time, and never a failure.
SERVER_DELETED = "the server was deleted during the pass"


@dataclasses.dataclass(frozen=True)
class Outcome:
    """What one vantage said about one host in one pass. Exactly one of `run`
    and `failure` is set. A failure is our own sentence about the pass, never
    a finding about the host: the host was not measured from there."""
    host_name: str
    vantage: str
    run: prober.Run | None = None
    failure: str | None = None
    # True when this vantage was not even tried for this host, because an
    # earlier host in the same pass found it unreachable.
    skipped: bool = False
    # True when the server was deleted after the pass took its list. It was
    # not measured and that is no failure of the pass: `failure` holds
    # `SERVER_DELETED`, and no later vantage is sent to it.
    gone: bool = False

    @property
    def measured(self) -> bool:
        return self.run is not None


def run_pass(con, plans, vantage_list, *, tls_ports=(),
             transport_factory=SshTransport, exclude=frozenset(),
             now: datetime | None = None, batch_size: int = BATCH_PORTS,
             locks: probelock.BatchLocks | None = None) -> list:
    """Every host from every vantage, one transport call at a time.

    Returns one `Outcome` per (host, vantage), in the order they were tried:
    hosts outer, vantages inner. **Nothing here is concurrent, and that is the
    pace rule** (module docstring): a host is finished from one vantage before
    the next vantage starts on it, so the host never sees two of our runners
    at once.

    `vantage_list` is `app.vantages.Vantage` rows, already filtered to the
    enabled ones by the caller. `transport_factory` takes a destination and
    returns a callable transport, `SshTransport` in production and a fake in
    the tests. One transport per vantage is built up front, so a vantage whose
    destination the transport refuses fails before any host is tried.

    `locks`, when given, is set on each vantage's registry row and handed to
    `run_host`, so every batch takes its prober's lock and its addresses'.
    """
    transports = {v.name: transport_factory(v.destination) for v in vantage_list}
    prober_locks = {v.name: None if locks is None else locks.on_prober(v.id)
                    for v in vantage_list}
    unreachable: dict[str, str] = {}
    outcomes = []
    for plan in plans:
        for vantage in vantage_list:
            if vantage.name in unreachable:
                outcomes.append(Outcome(plan.name, vantage.name,
                                        failure=unreachable[vantage.name],
                                        skipped=True))
                continue
            try:
                run = run_host(con, plan, transports[vantage.name], vantage.name,
                               tls_ports=tls_ports, batch_size=batch_size,
                               now=now, exclude=exclude,
                               locks=prober_locks[vantage.name])
            except VantageUnreachable as exc:
                unreachable[vantage.name] = str(exc)
                outcomes.append(Outcome(plan.name, vantage.name, failure=str(exc)))
                continue
            except DispatchFailed as exc:
                outcomes.append(Outcome(plan.name, vantage.name, failure=str(exc)))
                continue
            except prober.HostGone:
                # Deleted in the dashboard after this pass took its list. One
                # server's delete ended the whole pass until 2026-10-03, for
                # every workspace (docs/RECORD.md 4.312). It is left out, the
                # outcome says so, and the next server is measured. Only this
                # is caught: any other refusal to store a run is still raised.
                outcomes.append(Outcome(plan.name, vantage.name,
                                        failure=SERVER_DELETED, gone=True))
                break
            outcomes.append(Outcome(plan.name, vantage.name, run=run))
    return outcomes


# ===================================================== probing what just moved
#
# The hourly pass is the floor, not the answer. `docs/CONTEXT.md` 5 says the
# pitch leads with debugging, and debugging is somebody editing a rule and
# wanting to know whether it worked. An hour is a useless answer to that.
#
# **Frequency is the wrong dial to turn.** Every pass puts connections in
# somebody else's log from a published address, so probing everything every few
# minutes buys a little latency and spends a lot of other people's patience.
# What is wanted is a fast answer when something moved and quiet when nothing
# did.
#
# **No new state, on purpose.** Whether a host needs reprobing is already
# derivable: the plan says which addresses and ports we would probe now, and
# the newest run records which it actually covered. A flag column would be a
# second copy of that fact, and a second copy is a thing that can disagree.


def covered_by_last_run(con, host_id: int) -> tuple[set, set] | None:
    """The addresses and ports the newest run actually covered.

    None when there is no finished run, which is different from a run that
    covered nothing and has to stay different: the first says we have never
    looked, the second says we looked and there was nothing to look at.
    """
    newest = prober.latest_run(con, host_id)
    if newest is None or not newest["finished_at"]:
        return None
    targets, ports = set(), set()
    for row in prober.run_results(con, newest["id"]):
        if row["target"]:
            targets.add(row["target"])
        if row["port"] is not None:
            ports.add(row["port"])
    return targets, ports


def needs_reprobe(con, plan, ports=None) -> bool:
    """Has what we would probe changed since the last pass covered it.

    A host never probed needs one. A host whose address set or port set has
    moved needs one. A host where neither moved does not, however long ago the
    last pass was, because the hourly floor already covers staleness and this
    is only about change.

    **It deliberately says nothing about the results.** A port that went from
    answering to silent is a finding, not a reason to reprobe: the pass that
    measured it already did its job.

    `ports` is the set this caller is about to probe, and it defaults to the
    plan's own. It is an argument because the port set stopped being one thing
    on 2026-08-21: a pass over the joined set covers more ports than the
    document names, so comparing a joined run against the document's ports
    would report every host as moved on every tick, forever. The comparison has
    to be against what this pass would actually cover.
    """
    covered = covered_by_last_run(con, plan.host_id)
    if covered is None:
        return True
    targets, covered_ports = covered
    wanted = plan.ports if ports is None else ports
    return targets != set(plan.targets) or covered_ports != set(wanted)


# ============================================================ the joined set
#
# The owner's decision, 2026-08-21: the fast lane probes the joined port set,
# meaning ports with a listener, a declared intent or a previous finding.
# `docs/RECORD.md` 4.78 holds the decision and the reasoning under it, and
# `docs/PRODUCT.md` section 5 holds the cadence it runs at.
#
# It is wider than what the documents alone offer, and the widening is the
# point. A port somebody declared closed, and a port that answered from
# outside while the host reports no listener for it, are both ports a person
# already cares about. Neither is in the document's socket list, so neither was
# probed before this existed, and the second one is `unexplained`, which is one
# of the five states.

# A per-host bound on the joined set, and it is not a performance guard.
#
# The set is partly derived from what the last run measured, so it feeds on its
# own output. Nothing today can make that grow: every lane probes this same
# set. The day a broad sweep lands, one 65,535 port pass would put every port
# on the host into the fast lane permanently, at every tick, forever. This is
# the thing that stops that, and it says so out loud when it bites rather than
# quietly returning a shorter list.
MAX_JOINED_PORTS = 512


def _declared_ports(con, host_id: int) -> set:
    """Every TCP port this host has a declaration against.

    Both words count. `closed` is a person saying this port should not answer,
    which is exactly a port worth measuring often, and reading only `open`
    would drop the half where a conflict is most likely to appear.
    """
    found = set()
    for (protocol, port, _family) in intent_store.intents_for_host(con, host_id):
        if protocol == intent_store.PROTOCOL_TCP:
            found.add(port)
    return found


def _previously_measured_ports(con, host_id: int) -> set:
    """Every TCP port the newest stored run holds a result for.

    Every result, not only the ones that answered. A port that answered last
    week and is silent now is the finding this lane exists to notice, and
    keeping only the ports that answered would drop it out of the set on the
    first tick after it went quiet, which is the tick where somebody wants to
    know.
    """
    covered = covered_by_last_run(con, host_id)
    return set() if covered is None else set(covered[1])


# How long a port that nothing names any more stays in the set. The owner,
# 2026-09-27 (docs/RECORD.md 4.207), on the finding that tcp/6767 on fart had
# been probed every ten minutes since 30 August with nothing listening, no rule
# and no declaration (4.200). The third source above is his of 4.78, "the tick
# where somebody wants to know whether it still answers", and it had no end.
# A day is that tick and plenty of ticks after it. One number with the day a
# forgotten port stays a row, so `app/join.py` owns it.
FORGOTTEN_AFTER_SECONDS = join.FORGOTTEN_AFTER_SECONDS


def _forgotten_ports(con, host_id: int, now: datetime) -> set:
    """Every TCP port whose state has been nothing, on every family, for a day.

    **Read off the sweep's own record rather than worked out again.** No state
    is exactly the port nothing names: nothing listens or publishes it, no rule
    permits it, and it did not answer, because any of those gives it a state
    (`join._decide`: a listener gives one, a permit gives `stale rule`, a
    connect gives `unexplained`). `finding_states.confirmed_at` is when the
    sweep confirmed that, after its window, so a port shut five minutes ago is
    not forgotten and a restart that flapped it is not either.

    A port with a change still held, or with a row on any family that has a
    state, is not forgotten. A port the sweep never recorded is not forgotten,
    because nothing says how long it has been quiet.
    """
    try:
        rows = con.execute(
            "SELECT port, state, confirmed_at, pending_change FROM finding_states"
            " WHERE host_id = ? AND protocol = ?",
            (host_id, intent_store.PROTOCOL_TCP)).fetchall()
    except sqlite3.OperationalError:
        # A database the sweep has never run on has no such table.
        return set()
    cutoff = now - timedelta(seconds=FORGOTTEN_AFTER_SECONDS)
    quiet: dict = {}
    for row in rows:
        confirmed = alerts.parse_stamp(row["confirmed_at"])
        forgotten = (row["state"] == finding_alerts.NO_STATE
                     and row["pending_change"] is None
                     and confirmed is not None and confirmed <= cutoff)
        quiet[row["port"]] = quiet.get(row["port"], True) and forgotten
    return {port for port, forgotten in quiet.items() if forgotten}


def _unmeasured_for_a_day(con, host_id: int, candidates: set, now: datetime) -> set:
    """Of `candidates`, ports that nothing in the document or a declaration
    names, those with no state for a day that no stored row says so of.

    **The sweep writes a state only for a port the prober measured**
    (`app/finding_alerts.py`), so a port whose every result is not tested
    keeps the state it was last measured in, and `_forgotten_ports` never
    lets it go. The second big test, 2026-10-25, case D7: five ports whose
    listeners and firewalld entries were removed a day before, every result
    `not tested, host unreachable`, 260 of 260 over 52 passes, still stored
    `intended` from when they listened and probed on every pass.

    Such a port leaves the set when all of these hold:

    - no pass measured it in the last day, on either family, while the
      probers did measure another port of this server in that day. A day in
      which nothing of the server could be measured, a lost authorization
      among them, is a day nobody looked, and it forgets nothing;
    - it was in a pass more than a day ago, so it has been probed for a day;
    - no change is held for it;
    - the engine gives it no state now, on any family. `stale rule` is the
      one state that stands with nothing measured, so a rule that still
      permits the port keeps it.

    The engine is asked only when a port meets the first three, which is
    rare and lasts until the port leaves the set.
    """
    if not candidates:
        return set()
    since = (now - timedelta(seconds=FORGOTTEN_AFTER_SECONDS)).isoformat()
    measured = tuple(prober.MEASURED_STATES)
    marks = ", ".join("?" for _ in measured)
    lately = {row[0] for row in con.execute(
        "SELECT DISTINCT r.port FROM probe_runs u JOIN probe_results r ON r.run_id = u.id"
        f" WHERE u.host_id = ? AND u.started_at >= ? AND r.state IN ({marks})",
        (host_id, since, *measured)).fetchall()}
    if not lately:
        return set()
    gone = {port for port in candidates
            if port not in lately and _probed_before(con, host_id, port, since)}
    if not gone:
        return set()
    gone -= _ports_with_a_change_held(con, host_id)
    if not gone:
        return set()
    found = join.host_findings(con, host_id)
    if found is None:
        return set()
    stated = {finding.port for finding in found.findings
              if finding.protocol == intent_store.PROTOCOL_TCP and finding.state}
    return gone - stated


def _probed_before(con, host_id: int, port: int, since: str) -> bool:
    """Whether a pass that started before `since` holds a result for this
    port, measured or not."""
    return con.execute(
        "SELECT 1 FROM probe_runs u JOIN probe_results r ON r.run_id = u.id"
        " WHERE u.host_id = ? AND u.started_at < ? AND r.port = ? LIMIT 1",
        (host_id, since, port)).fetchone() is not None


def _ports_with_a_change_held(con, host_id: int) -> set:
    try:
        rows = con.execute(
            "SELECT port FROM finding_states WHERE host_id = ? AND protocol = ?"
            " AND pending_change IS NOT NULL",
            (host_id, intent_store.PROTOCOL_TCP)).fetchall()
    except sqlite3.OperationalError:
        # A database the sweep has never run on has no such table.
        return set()
    return {row[0] for row in rows}


def joined_ports(con, plan, now: datetime | None = None) -> tuple[tuple, str]:
    """(the ports to probe, a sentence about the set or "").

    The sentence is empty unless the cap bit, and then it says so. A cap that
    narrows coverage silently reads afterwards as coverage, which is the shape
    `docs/RECORD.md` 4.46 keeps finding in this project.

    Ports the engine will refuse, which the document can carry as text or out
    of range, are kept exactly as `prober_cli.candidate_ports` produced them.
    Dropping one here would make it disappear between the document and the
    answer instead of being recorded as not tested with a typed reason.
    """
    numbered = set()
    odd = []
    for port in plan.ports:
        if isinstance(port, int) and not isinstance(port, bool):
            numbered.add(port)
        elif port not in odd:
            odd.append(port)

    numbered |= _declared_ports(con, plan.host_id)
    measured = _previously_measured_ports(con, plan.host_id)
    # An address host keeps every port it ever measured: it has no document to
    # say what listens, so the measurements are all it has to go on.
    if not getattr(plan, "agentless", False):
        clock = now or datetime.now(timezone.utc)
        measured -= _forgotten_ports(con, plan.host_id, clock)
        measured -= _unmeasured_for_a_day(con, plan.host_id, measured - numbered, clock)
    numbered |= measured

    ordered = sorted(numbered)
    note = ""
    if len(ordered) > MAX_JOINED_PORTS:
        note = (f"the joined set held {len(ordered)} ports and is capped at"
                f" {MAX_JOINED_PORTS}, so"
                f" {len(ordered) - MAX_JOINED_PORTS} were not probed")
        ordered = ordered[:MAX_JOINED_PORTS]
    return tuple(ordered) + tuple(odd), note
