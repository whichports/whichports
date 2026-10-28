"""The outside view: what a TCP connect from here observes, per address family,
and what certificate a TLS port presents.

`docs/PRODUCT.md` section 5 is the specification and section 5a is the half
this module owns. It answers one question per port and per address family, and
it is built so that it can never answer a question it did not ask.

Nothing here schedules anything and nothing here identifies the vantage point
to the internet. Those are two separate cards. The seams they attach to are
named at the bottom of this docstring.

## The four states, and why they are named this way

  - `connect_succeeded`   the three-way handshake completed
  - `connect_refused`     the address answered with a refusal
  - `no_response`         nothing came back before the timeout expired
  - `not_tested`          we did not measure this, and the reason says why

Each name says what was observed, never what it means. There is no `filtered`
and no `open`, because both are conclusions and neither is a measurement. A
firewall that drops and a host that is switched off produce the same
`no_response`, and this module has no way to tell them apart, so it does not.

**Only those first three outcomes are treated as measurements. Every other
outcome is `not_tested` with a typed reason.** That is the rule that keeps this
honest, and it is not conservatism for its own sake. An ICMP unreachable
arrives at this process as the same `EHOSTUNREACH` a missing route on our own
side produces, so treating that class as a finding would state something about
a customer's host on the strength of our own network. `docs/PRODUCT.md` 4b is a
retraction of exactly that shape of claim, an IPv6 conclusion that rested on
something never measured, and the reason is kept in the result so nothing is
lost by refusing to promote it.

## v4 and v6 are never inferred from each other

The result set always carries both families. A host with no address in a
family gets `not_tested` for that family, with the reason saying the host has
no address there. It never gets a state that reads as a finding.

Two facts make this more than a convention, and both were measured on
2026-08-15 rather than assumed:

  - `loop.sock_connect` on an `AF_INET6` socket, handed the text
    `127.0.0.1`, resolves it and connects to the v4-mapped form. On macOS that
    returned a refusal. A measurement about v4 would have been filed under v6,
    silently. So the socket family is always derived from the address itself
    and the primitive refuses a family that disagrees with its address.
  - a literal address that matches its socket family reaches no resolver at
    all, measured by spying on both `socket.getaddrinfo` and
    `loop.getaddrinfo` (zero calls). A name, or a mismatched literal, does go
    through the resolver. So this module probes literal addresses only. There
    is no name to resolve, nothing to rebind between the check and the packet,
    and no way for a packet to leave for an address the gate never saw.

## The authorisation gate is checked per port, immediately before the connect

SI-6, and `app/authz.py` is the only door. The choice between once per run and
once per port was made deliberately:

  - **once per run is a hole.** The whole-range run in `docs/PRODUCT.md`
    section 5 is 65,535 ports, which at monitoring pace is tens of minutes.
    Agent-derived authorisation lapses when the agent stops reporting from the
    address, and an operator who revokes an address expects the packets to
    stop, not to stop at the end of the run.
  - **once per port costs one indexed SELECT per connect.** At 40 connects a
    second that is 40 tiny reads a second against a local SQLite file, which
    is not a load. Contention is bounded further because the gate is called
    from the event loop thread, so the calls are serialised, and the query is
    the one `authz` already has an index for.

So the gate is called inside the coroutine that opens the socket, on the line
before it. There is a second call once per target before the ports are
scheduled, and it is an optimisation rather than the authority: it stops a
thousand ports on an unproved address from each waiting their turn only to be
refused. Removing it would change how long a refusal takes and nothing else.

The residual gap is one connect already in flight when an authorisation lapses,
which cannot be closed by any amount of checking because a packet cannot be
recalled. A refusal is a `not_tested` result, so a target that loses its
authorisation mid-run leaves a visible record of the ports that were not
measured instead of disappearing from the output.

## No bytes, either way

SI-7. The connect primitive creates a socket, connects, records how long that
took and closes. It never transfers a byte in either direction, and
`tests/test_prober.py` asserts that twice over: a real loopback listener sees
the connection close with zero bytes delivered, and an AST walk over this file
fails if the name of any transfer or TLS call appears outside the two functions
named in `TLS_FUNCTIONS` there.

## The certificate read, which is SI-7's other half

SI-7 in full: *no version detection. TCP connect, plus a TLS handshake to read
the certificate. Nothing beyond the handshake.* The second half is here, and
the invariant is the whole specification of it.

**What happens.** One TCP connection, one TLS handshake, take the certificate
the peer presented during that handshake, close. No application byte is ever
sent. `tests/test_prober_tls.py` measures that from the far end of a real
loopback handshake: the server reads until EOF and sees nothing.

**What deliberately does not happen**, because each of these is version
detection wearing a different hat:

  - no ALPN list, which is asking a server which protocols it speaks
  - no cipher list of our own, no minimum or maximum version of our own, and
    above all **no second handshake**. One ClientHello with this machine's own
    defaults, and whatever comes back. Retrying with different settings to find
    out what a server accepts is exactly the thing SI-7 forbids
  - no server name. We probe an address and an address is not a name, so no SNI
    extension is sent. **That is a real limitation and it is stated rather than
    hidden:** a server holding several certificates presents its default one to
    us, and it may present none at all
  - nothing is read after the handshake, so nothing here can see a banner, a
    version string or a response body

**Nothing is verified, and nothing here says valid.** Verification is off, and
this is the one place in the codebase where that is not a hole: we send nothing
and we trust nothing, so there is no session for a stranger to take over and no
decision resting on the certificate being genuine. It has to be off, because an
expired or self issued certificate is a fact we exist to report and a verifying
client would refuse the handshake and leave us with nothing to report. What
comes out is what was presented. `self_issued` means the issuer field equals the
subject field, which is not the same as a signature checked against the key
inside the certificate, and that difference is why it is not called self signed.

**The peer's text is treated as hostile**, because it is: a subject and an
issuer are chosen by whoever answered. Every field is length bounded,
unprintable characters are removed, and the separator characters in a rendered
name are escaped so a common name cannot pretend to be a second attribute.

**It is a second connection**, and section 5d's pace is what stops that becoming
twice the traffic. A certificate read takes a token from the same per target
bucket the connects take theirs from, so a host never sees more connections a
second because it has a TLS port. The run takes longer instead. What does grow
is packets per connection: a handshake carries the certificate itself, so it
moves several kilobytes where a bare connect moves four small segments.

## The bounds, stated where they bite

The three numbers below are one paragraph of arithmetic rather than three
independent knobs, so changing one means re-reading this.

40 connects a second per target is the pace from `docs/PRODUCT.md` section 5,
and it is a pace with no burst: a runner's first connect waits for a token
like every other, so the number holds in any one second a target can measure.
**It is 40 connects, not 40 packets, and those differ.** A completed handshake
is three segments (RFC 9293 section 3.5), plus the segment that closes it, so a
run against ports that all answer moves roughly four times as many packets as
connects. Refused and silent ports cost less. The rule of thumb in section 5 is
therefore a floor on the pace and not a ceiling on the packets, and this module
paces what it can actually count.

`MAX_CONCURRENT_CONNECTS` is what governs a silent target, not the pace. With
64 slots and a 5 second timeout, a target that answers nothing yields about 12
connects a second, so a whole-range run against a silent address takes hours
rather than the half hour the pace alone suggests. Sizing the slots at
pace times timeout, which is 200, would make the pace the binding constraint,
and that is deliberately not done: a slow monthly run is acceptable, and 200
sockets aimed at one address at once reads as a scan to anything watching even
though the packet rate is identical.

## The seams the other cards attach to

  - **the cadence scheduler.** The port list and the target list are
    arguments. Nothing here knows about five minutes, weekly or monthly.
  - **the ZMap identification set.** Reverse DNS, a page on port 80, a
    published range list and an abuse contact are properties of the machine
    this runs on. `vantage` records which machine measured a row so that a
    second vantage point cannot be confused with the first.
"""

import asyncio
import contextlib
import dataclasses
import errno
import hashlib
import ipaddress
import os
import socket
import sqlite3
import ssl
import time
from datetime import datetime, timezone

from . import authz, ratelimit

# The same two words the agent document, the authorisation registry and the
# dashboard already use. A second vocabulary for one fact is how a v4 answer
# ends up displayed as a v6 one.
FAMILY_V4 = authz.FAMILY_V4
FAMILY_V6 = authz.FAMILY_V6
FAMILIES = (FAMILY_V4, FAMILY_V6)

# A target whose family we could not read, because it is not an address. It is
# deliberately not one of FAMILIES: it must never count as either family's
# answer, and it must never be absent from the output either.
FAMILY_UNKNOWN = "unknown"

STATE_CONNECTED = "connect_succeeded"
STATE_REFUSED = "connect_refused"
STATE_NO_RESPONSE = "no_response"
STATE_NOT_TESTED = "not_tested"

# The three states that are measurements of the target. Everything else is
# not_tested, see the module docstring.
MEASURED_STATES = (STATE_CONNECTED, STATE_REFUSED, STATE_NO_RESPONSE)
STATES = MEASURED_STATES + (STATE_NOT_TESTED,)

# Typed reasons, a closed set (SI-8: classes, never free text). A reason is
# recorded next to the state rather than instead of it, so refusing to promote
# an error to a finding costs no information.
REASON_TIMEOUT_EXPIRED = "timeout_expired"
REASON_OS_TIMEOUT = "os_reported_timeout"
REASON_CONNECTION_RESET = "connection_reset"
REASON_NO_AUTHORIZATION = "no_authorization"
REASON_TARGET_NOT_AN_ADDRESS = "target_not_an_address"
REASON_FAMILY_MISMATCH = "family_does_not_match_address"
REASON_NO_ADDRESS_IN_FAMILY = "no_address_in_family"
REASON_PORT_OUT_OF_RANGE = "port_out_of_range"
REASON_PORT_NOT_AN_INTEGER = "port_not_an_integer"
REASON_HOST_UNREACHABLE = "host_unreachable"
REASON_NETWORK_UNREACHABLE = "network_unreachable"
REASON_LOCAL_PERMISSION_DENIED = "local_permission_denied"
# The kernel said EACCES and whose side that was is not known, so the name
# says neither. See `_ERRNO_NAMES`.
REASON_PERMISSION_DENIED = "permission_denied"
REASON_LOCAL_FAMILY_UNSUPPORTED = "no_local_support_for_family"
REASON_LOCAL_ADDRESS_UNAVAILABLE = "no_local_address_in_family"
REASON_LOCAL_RESOURCE_LIMIT = "local_resource_limit"
REASON_RESOLVER_INVOLVED = "resolver_involved"
REASON_UNCLASSIFIED_ERROR = "unclassified_error"
# The target is one of our own vantage hosts. Measured on 2026-08-18
# (docs/RECORD.md 4.62): a box connecting to its own public address reported
# connect_refused on ports the internet sees time out, because that traffic
# never traverses its firewall. Probing another vantage from this one is the
# same mistake with two boxes, so both are refused and recorded, never
# measured. app/dispatch.py writes it, from the registry in app/vantages.py.
REASON_VANTAGE_ADDRESS = "target_is_a_vantage_address"

REASONS = frozenset({
    REASON_TIMEOUT_EXPIRED, REASON_OS_TIMEOUT, REASON_CONNECTION_RESET,
    REASON_NO_AUTHORIZATION, REASON_TARGET_NOT_AN_ADDRESS,
    REASON_FAMILY_MISMATCH, REASON_NO_ADDRESS_IN_FAMILY,
    REASON_PORT_OUT_OF_RANGE, REASON_PORT_NOT_AN_INTEGER,
    REASON_HOST_UNREACHABLE, REASON_NETWORK_UNREACHABLE,
    REASON_LOCAL_PERMISSION_DENIED, REASON_PERMISSION_DENIED,
    REASON_LOCAL_FAMILY_UNSUPPORTED,
    REASON_LOCAL_ADDRESS_UNAVAILABLE, REASON_LOCAL_RESOURCE_LIMIT,
    REASON_RESOLVER_INVOLVED, REASON_UNCLASSIFIED_ERROR,
    REASON_VANTAGE_ADDRESS,
})

# Every reason, split by whether a packet ever reached the target.
#
# This pairing is the accuracy rule written as code: never state a reachability
# finding the prober did not measure. A result carrying an unmeasured reason
# has observed nothing about the target, so its state must be not_tested and
# must never be a measured one. Refusing authorisation and then reporting
# no_response would be the whole product lying.
#
# It is a declared set rather than a comment because of what happened when it
# was only a comment. The suite asserted the reason on the unauthorised path
# and never the state, so replacing not_tested with no_response there left all
# 112 tests passing (docs/RECORD.md 4.46 is the same shape twice over: the
# guard existed and nothing checked it). The tests below assert the pairing
# across every reason at once, and assert that these two sets exhaust REASONS,
# so a reason added later cannot slip past by being forgotten here.
UNMEASURED_REASONS = frozenset({
    REASON_NO_AUTHORIZATION, REASON_TARGET_NOT_AN_ADDRESS,
    REASON_FAMILY_MISMATCH, REASON_NO_ADDRESS_IN_FAMILY,
    REASON_PORT_OUT_OF_RANGE, REASON_PORT_NOT_AN_INTEGER,
    REASON_HOST_UNREACHABLE, REASON_NETWORK_UNREACHABLE,
    REASON_LOCAL_PERMISSION_DENIED, REASON_PERMISSION_DENIED,
    REASON_LOCAL_FAMILY_UNSUPPORTED,
    REASON_LOCAL_ADDRESS_UNAVAILABLE, REASON_LOCAL_RESOURCE_LIMIT,
    REASON_RESOLVER_INVOLVED, REASON_UNCLASSIFIED_ERROR,
    REASON_VANTAGE_ADDRESS,
})

# The other three, and each one is something the target itself did: it refused,
# it reset, or it stayed silent while we waited.
MEASURED_ONLY_REASONS = frozenset({
    REASON_TIMEOUT_EXPIRED, REASON_OS_TIMEOUT, REASON_CONNECTION_RESET,
})

# --------------------------------------------------- the certificate vocabulary

# Two states, and neither is a judgement. We either read what was presented or
# we did not, and the reason says why not. There is no valid, no trusted and no
# expired, because each of those is a conclusion drawn from a certificate rather
# than something read out of one. The writing rules.
TLS_STATE_READ = "certificate_read"
TLS_STATE_NOT_READ = "certificate_not_read"
TLS_STATES = (TLS_STATE_READ, TLS_STATE_NOT_READ)

# Typed, closed, and none of them carries a word from the far side (SI-8). An
# OpenSSL alert string is attacker influenced text and it stops here.
REASON_TLS_NO_CONNECT = "connect_did_not_succeed"
REASON_TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
REASON_TLS_NO_CERTIFICATE = "no_certificate_presented"
REASON_TLS_CERTIFICATE_UNREADABLE = "certificate_unreadable"

# A certificate read makes its own TCP connection, so it can fail every way a
# connect can fail as well as the four ways above. Those keep the connect
# engine's own reasons rather than being flattened into one, so a refusal by
# the gate still reads as a refusal by the gate.
TLS_REASONS = REASONS | frozenset({
    REASON_TLS_NO_CONNECT, REASON_TLS_HANDSHAKE_FAILED,
    REASON_TLS_NO_CERTIFICATE, REASON_TLS_CERTIFICATE_UNREADABLE,
})

# A handshake is slower than a connect: a round trip to open the connection,
# then two or three more to negotiate, and the certificate itself comes back
# over the wire. Five seconds is the connect budget and this is the whole read,
# the connection included.
TLS_TIMEOUT_SECONDS = 10.0

# A certificate is one to three kilobytes and the peer chooses the size, so
# there is a cap. Anything larger is refused before a byte of it is walked.
MAX_CERTIFICATE_BYTES = 16384

# How much of a subject, an issuer or a serial is kept. Text a stranger wrote,
# so it is bounded here rather than wherever it is eventually printed.
MAX_CERTIFICATE_TEXT = 256

# How many names from the subject alternative name are kept. A certificate can
# carry hundreds and a handful is what identifies the service.
MAX_CERTIFICATE_NAMES = 32

# How long to wait for an answer. Monitoring pace, and a target that has not
# answered in five seconds is not going to be called reachable on the sixth.
CONNECT_TIMEOUT_SECONDS = 5.0

# docs/PRODUCT.md section 5. Connects, not packets, and the module docstring
# says why those differ.
CONNECTS_PER_SECOND_PER_TARGET = 40.0

# The bound that actually governs a silent target. The arithmetic is in the
# module docstring, because a number like this is useless without it.
MAX_CONCURRENT_CONNECTS = 64

# One pacing bucket per target. The cap bounds memory and cannot be reached by
# a fleet: it is thousands of hosts. Eviction in ratelimit.TokenBucket hands a
# full bucket back to an evicted key, and a full bucket here is one token, so
# an eviction costs a target one connect ahead of the pace and no more. The
# cap is still far above anything real rather than tight.
PACE_BUCKET_MAX_KEYS = 10_000

# A port is 16 bits and 0 is not a port anything listens on. Verified on
# 2026-08-15 rather than assumed: the socket layer raises OverflowError for
# 65536 and EADDRNOTAVAIL for 0, and neither of those is a measurement. So
# both are refused here, before a socket exists.
MIN_PORT = 1
MAX_PORT = 65535

# An address is at most 45 characters. A target longer than this is not one, and
# the record keeps a bounded amount of whatever we were asked to probe so an
# operator can see what was refused.
MAX_TARGET_TEXT = 64

# Which machine measured a row. Two vantage points are planned
# (docs/PRODUCT.md section 5), and rows that cannot say who measured them
# cannot be told apart afterwards. "unnamed" means nobody said.
VANTAGE_ENV = "WHICHPORTS_VANTAGE"
UNNAMED_VANTAGE = "unnamed"

SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_runs (
    id           INTEGER PRIMARY KEY,
    host_id      INTEGER REFERENCES hosts(id),
    vantage      TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT
);

CREATE TABLE IF NOT EXISTS probe_results (
    id          INTEGER PRIMARY KEY,
    run_id      INTEGER NOT NULL REFERENCES probe_runs(id),
    target      TEXT,
    family      TEXT NOT NULL,
    port        INTEGER,
    state       TEXT NOT NULL,
    reason      TEXT,
    connect_ms  REAL,
    os_errno    INTEGER,
    measured_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS probe_tls (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES probe_runs(id),
    target       TEXT,
    family       TEXT NOT NULL,
    port         INTEGER,
    state        TEXT NOT NULL,
    reason       TEXT,
    subject      TEXT,
    issuer       TEXT,
    not_before   TEXT,
    not_after    TEXT,
    serial       TEXT,
    self_issued  INTEGER,
    names        TEXT,
    fingerprint  TEXT,
    read_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_probe_results_run
    ON probe_results(run_id, family, port);

CREATE INDEX IF NOT EXISTS idx_probe_runs_host
    ON probe_runs(host_id, started_at DESC);

CREATE INDEX IF NOT EXISTS idx_probe_tls_run
    ON probe_tls(run_id, family, port);
"""

# Everything above, under the name a test builds a database from before
# `probe_latest` existed with.
SCHEMA_BEFORE_LATEST = SCHEMA

# **The newest result per host, family, port, address and vantage, kept by the
# database itself.** Added 2026-09-20 (docs/RECORD.md 4.192).
#
# The join engine wants exactly that and nothing older, and it got it by
# reading every probe result a host ever had and keeping the newest of each in
# Python, on every page load. Measured on production: 476,000 rows read to
# keep 100, 85% of a 2.9 second page, growing with every pass. It is also the
# read that blinded the dashboard for seventeen days when its sort spilled to
# a temporary file the unit could not write (4.183).
#
# **A trigger and not a line in `_finish_run`**, so every writer keeps the
# table right: this module, a test that writes rows by hand, and whatever
# writes results next year. Newest is by when it was measured and never by
# the order rows arrive in, because two lanes interleave. `measured_at` is
# compared as text, which is time order for the UTC ISO strings this module
# writes (every row on production on 2026-09-20 had the one shape), and the
# row id breaks a tie. On those rows the table and the engine's own
# comparison picked identical rows for every host, measured before this was
# written.
#
# `target` is '' for a result that names no address, because NULLs never
# conflict in a primary key and those rows have to share one slot.
#
# **`result_id` is a foreign key on purpose.** Retention is not built. When
# it is, it must spare the rows this table points at or move the pointer
# first, and a delete that forgets fails here rather than leaving a slot that
# silently vanished from a page. `store.HOST_TABLES` deletes this table before
# `probe_results` for the same reason.
LATEST_SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_latest (
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    family      TEXT NOT NULL,
    port        INTEGER NOT NULL,
    target      TEXT NOT NULL,
    vantage     TEXT NOT NULL,
    result_id   INTEGER NOT NULL REFERENCES probe_results(id),
    measured_at TEXT NOT NULL,
    PRIMARY KEY (host_id, family, port, target, vantage)
);

CREATE TRIGGER IF NOT EXISTS probe_latest_keep
AFTER INSERT ON probe_results
WHEN NEW.port IS NOT NULL AND NEW.family IS NOT NULL
BEGIN
    INSERT INTO probe_latest (host_id, family, port, target, vantage,
                              result_id, measured_at)
    SELECT runs.host_id, NEW.family, NEW.port, COALESCE(NEW.target, ''),
           runs.vantage, NEW.id, NEW.measured_at
      FROM probe_runs runs
     WHERE runs.id = NEW.run_id AND runs.host_id IS NOT NULL
    ON CONFLICT (host_id, family, port, target, vantage) DO UPDATE SET
        result_id = excluded.result_id, measured_at = excluded.measured_at
     WHERE excluded.measured_at > probe_latest.measured_at
        OR (excluded.measured_at = probe_latest.measured_at
            AND excluded.result_id > probe_latest.result_id);
END;
"""

# The one-time fill for a database that held results before the table did.
_LATEST_BACKFILL = """
INSERT OR IGNORE INTO probe_latest (host_id, family, port, target, vantage,
                                    result_id, measured_at)
SELECT host_id, family, port, target, vantage, id, measured_at FROM (
    SELECT runs.host_id AS host_id, r.family AS family, r.port AS port,
           COALESCE(r.target, '') AS target, runs.vantage AS vantage,
           r.id AS id, r.measured_at AS measured_at,
           ROW_NUMBER() OVER (
               PARTITION BY runs.host_id, r.family, r.port,
                            COALESCE(r.target, ''), runs.vantage
               ORDER BY r.measured_at DESC, r.id DESC) AS rn
      FROM probe_results r JOIN probe_runs runs ON r.run_id = runs.id
     WHERE runs.host_id IS NOT NULL AND r.port IS NOT NULL
       AND r.family IS NOT NULL)
 WHERE rn = 1
"""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init, alerts.init and authz.init
    follow. `db.init` has to have run first, because probe_runs references
    hosts(id).

    `probe_latest` is filled once, the first time this meets a database that
    holds results and an empty table, which is production on the day it
    lands. After that the trigger keeps it and the check below is two cheap
    reads. Two processes doing the fill at once insert the same rows, and the
    second one's are ignored.
    """
    con.executescript(SCHEMA)
    con.executescript(LATEST_SCHEMA)
    empty = con.execute("SELECT 1 FROM probe_latest LIMIT 1").fetchone() is None
    if empty and con.execute("SELECT 1 FROM probe_results LIMIT 1").fetchone():
        con.execute(_LATEST_BACKFILL)
    con.commit()


def default_vantage() -> str:
    return os.environ.get(VANTAGE_ENV) or UNNAMED_VANTAGE


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RunUnreadable(ValueError):
    """A measurement that cannot be read back. Kept distinct from anything that
    means "the target refused", because a batch we cannot parse is our problem
    and must never be recorded as something the internet did."""


class TargetMismatch(ValueError):
    """The address is not a literal, or its family is not the one asked for.

    Its own type because it is the guard that keeps one family's measurement
    from being filed under the other, and a caller that hits it has a bug
    rather than a finding.
    """


# ------------------------------------------------------------- the primitive

def _socket_family(target: str, family: str) -> int:
    """The AF_ constant for this address, refusing anything that is not a
    literal address in the family the caller named.

    Both halves matter. A name would be resolved by the connect call, so a
    packet could leave for an address the gate never saw. A mismatched literal
    is worse than useless: measured on 2026-08-15, an AF_INET6 socket handed
    `127.0.0.1` connects to the v4-mapped form and returns a real answer, which
    would be a v4 measurement recorded as a v6 one.
    """
    if not isinstance(target, str):
        raise TargetMismatch("the target must be text")
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        raise TargetMismatch(f"{target[:MAX_TARGET_TEXT]!r} is not an IP address") from None
    own_family = FAMILY_V6 if ip.version == 6 else FAMILY_V4
    if own_family != family:
        raise TargetMismatch(f"{ip} is {own_family}, not {family}")
    return socket.AF_INET6 if ip.version == 6 else socket.AF_INET


async def tcp_connect(target: str, family: str, port: int) -> float:
    """Open a TCP connection, then close it. Returns how long the connect took,
    in seconds.

    This is the only thing in this package that puts a packet on the wire, and
    it is four lines long on purpose. It transfers no bytes in either
    direction, which is SI-7, and it holds no socket past its own return.

    It has no timeout of its own. The caller owns that, so that the timeout and
    the state it produces are decided in one place.
    """
    address_family = _socket_family(target, family)
    sock = socket.socket(address_family, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        loop = asyncio.get_running_loop()
        started = time.monotonic()
        await loop.sock_connect(sock, (target, port))
        return time.monotonic() - started
    finally:
        sock.close()


# ------------------------------------------------------------- classification

# Every errno this module is willing to name, by name rather than by number,
# because the numbers differ between Linux and macOS. The default for anything
# not listed is not_tested with REASON_UNCLASSIFIED_ERROR, so a kernel we have
# not met cannot invent a finding.
_ERRNO_NAMES = {
    # A refusal is an answer: something on the path said no, out loud.
    "ECONNREFUSED": (STATE_REFUSED, None),
    # A reset during the handshake is also an answer, and it is not the same
    # answer, so it keeps its own reason rather than being folded in.
    "ECONNRESET": (STATE_REFUSED, REASON_CONNECTION_RESET),
    # The kernel gave up on its own SYN retries before our timeout did. Same
    # observation, different clock, and the reason says which.
    "ETIMEDOUT": (STATE_NO_RESPONSE, REASON_OS_TIMEOUT),
    # The unreachable family. Indistinguishable from having no route on our
    # own side, so it is not a finding. See the module docstring.
    "EHOSTUNREACH": (STATE_NOT_TESTED, REASON_HOST_UNREACHABLE),
    "ENETUNREACH": (STATE_NOT_TESTED, REASON_NETWORK_UNREACHABLE),
    "EHOSTDOWN": (STATE_NOT_TESTED, REASON_HOST_UNREACHABLE),
    "ENETDOWN": (STATE_NOT_TESTED, REASON_NETWORK_UNREACHABLE),
    # Our own machine refused to let the packet out. EPERM is what the kernel
    # returns when one of its own packet filter's hooks drops a packet
    # (`nf_hook_slow` in net/netfilter/core.c, "-EPERM for NF_DROP", read
    # 2026-10-12). Reporting the target as anything would be reporting our
    # own rules.
    "EPERM": (STATE_NOT_TESTED, REASON_LOCAL_PERMISSION_DENIED),
    # EACCES is not ours alone, and until 2026-10-12 it was recorded as if it
    # were. The kernel hands a socket EACCES for an ICMPv6 destination
    # unreachable whose code is administratively prohibited, policy failed or
    # reject route (`tab_unreach` in net/ipv6/icmp.c, read the same day),
    # whoever on the way sent it: a server whose firewall rejects that way
    # answers a v6 connect so (docs/RECORD.md 4.220). The same errno is a
    # policy on our own machine saying no. So it stays no finding, and its
    # reason names nobody's side. On v4 the same refusal is in the
    # unreachable family above (`icmp_err_convert` in net/ipv4/icmp.c).
    "EACCES": (STATE_NOT_TESTED, REASON_PERMISSION_DENIED),
    # This vantage point has no support, or no address, in that family. The
    # case that matters: a prober with no IPv6 must not report every v6 port
    # as anything. docs/PRODUCT.md 4b is the retraction that shape caused.
    "EAFNOSUPPORT": (STATE_NOT_TESTED, REASON_LOCAL_FAMILY_UNSUPPORTED),
    "EPFNOSUPPORT": (STATE_NOT_TESTED, REASON_LOCAL_FAMILY_UNSUPPORTED),
    "EADDRNOTAVAIL": (STATE_NOT_TESTED, REASON_LOCAL_ADDRESS_UNAVAILABLE),
    # We ran out of something. Nothing was measured.
    "EMFILE": (STATE_NOT_TESTED, REASON_LOCAL_RESOURCE_LIMIT),
    "ENFILE": (STATE_NOT_TESTED, REASON_LOCAL_RESOURCE_LIMIT),
    "ENOBUFS": (STATE_NOT_TESTED, REASON_LOCAL_RESOURCE_LIMIT),
    "ENOMEM": (STATE_NOT_TESTED, REASON_LOCAL_RESOURCE_LIMIT),
}

# A name the running platform does not define is left out rather than crashing
# the import. Leaving one out can only ever move an outcome towards not_tested,
# never towards a finding, so this fails in the safe direction. A test asserts
# the ones that decide a state are all present, because losing ECONNREFUSED
# quietly would be the interesting kind of wrong.
_ERRNO_STATES = {getattr(errno, name): value
                 for name, value in _ERRNO_NAMES.items()
                 if hasattr(errno, name)}


def classify(exc: BaseException) -> tuple[str, str | None, int | None]:
    """What one failed connect observed: (state, reason, errno).

    The default is not_tested. A state is only ever returned for an outcome
    this function positively recognises.
    """
    # socket.gaierror is an OSError whose errno is a getaddrinfo code, not a
    # system errno, and the two number spaces collide (EAI_NONAME is 8 on this
    # machine, and 8 is ENOEXEC). Reading it through the errno table would
    # mis-name it, so it is handled before the table is consulted. Reaching
    # this at all means a name or a mismatched literal got through, which the
    # primitive refuses, so it is recorded as the resolver having been
    # involved rather than as anything about a target.
    if isinstance(exc, socket.gaierror):
        return STATE_NOT_TESTED, REASON_RESOLVER_INVOLVED, None
    if isinstance(exc, TargetMismatch):
        return STATE_NOT_TESTED, REASON_TARGET_NOT_AN_ADDRESS, None
    if isinstance(exc, TimeoutError) and getattr(exc, "errno", None) is None:
        # Our own timeout. Since Python 3.11 asyncio.TimeoutError is the
        # builtin TimeoutError, which is also the OSError the kernel raises
        # for ETIMEDOUT, so the two are told apart by whether there is an
        # errno at all rather than by type.
        return STATE_NO_RESPONSE, REASON_TIMEOUT_EXPIRED, None
    if isinstance(exc, OSError):
        state, reason = _ERRNO_STATES.get(
            exc.errno, (STATE_NOT_TESTED, REASON_UNCLASSIFIED_ERROR))
        return state, reason, exc.errno
    return STATE_NOT_TESTED, REASON_UNCLASSIFIED_ERROR, None


# ------------------------------------------------------ reading a certificate
#
# A certificate arrives as DER, which is bytes a stranger chose, and there is
# no X.509 parser in the standard library. The three ways out of that were
# weighed and written down here because the choice is not obvious:
#
#   - **a dependency.** Rejected. This project wants a justification for
#     every one, and the thing being sold is a small attack surface. Pulling a
#     cryptography library in so that four fields can be read is the wrong
#     trade in this codebase specifically.
#   - **let OpenSSL parse it.** `SSLSocket.getpeercert()` returns a parsed
#     dictionary, but only for a certificate that was *validated*, and
#     validating is the one thing we must not do. The documented way round it,
#     loading the bytes into a throwaway store and reading them back with
#     `SSLContext.get_ca_certs()`, was tried on 2026-08-16 and does not work:
#     that call skips anything that is not a CA, so it returns an empty list
#     for exactly the leaf certificates a server presents. The remaining route
#     is `ssl._ssl._test_decode_cert`, a private test helper that needs the
#     bytes written to a file first. A private underscore API in production is
#     not a thing to build on.
#   - **read the four fields ourselves.** What follows. It is a walker rather
#     than a general parser: it descends a fixed number of levels, so it does
#     not recurse and cannot be made to. Every length a stranger wrote is
#     checked against the buffer before it is used, the whole input is capped
#     first, and every element consumes at least two bytes, so the cursor
#     always advances and no loop here can be made to spin.
#
# X.509 is RFC 5280, and the shape being walked is section 4.1:
#
#   Certificate     ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
#   TBSCertificate  ::= SEQUENCE { [0] version, serialNumber, signature,
#                                  issuer, validity, subject,
#                                  subjectPublicKeyInfo, ... [3] extensions }
#
# The signature is never looked at. Nothing here checks that anything was
# signed by anybody, which is the whole posture: we report what was presented.


class CertificateUnreadable(ValueError):
    """These bytes are not a certificate this module can read.

    Its own type so that a parse failure can never be mistaken for a network
    failure. It carries our own words and never the peer's (SI-8).
    """


# DER tags, written as the number that is in the byte, because that is what a
# person looking at a hex dump of a certificate sees.
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_OID = 0x06
_TAG_UTC_TIME = 0x17
_TAG_GENERALIZED_TIME = 0x18
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31
_TAG_VERSION = 0xA0          # [0] EXPLICIT, the optional version
_TAG_EXTENSIONS = 0xA3       # [3] EXPLICIT, the optional extensions
_TAG_SAN_DNS = 0x82          # [2] dNSName inside a subject alternative name
_TAG_SAN_IP = 0x87           # [7] iPAddress inside a subject alternative name

# The string types an attribute value may carry, and how to read each one.
# TeletexString is read as latin-1: that is not what T.61 says, but latin-1
# cannot fail to decode, so a certificate is never lost over one.
_STRING_ENCODINGS = {
    0x0C: "utf-8",       # UTF8String
    0x13: "ascii",       # PrintableString
    0x16: "ascii",       # IA5String
    0x14: "latin-1",     # TeletexString
    0x1E: "utf-16-be",   # BMPString
    0x1C: "utf-32-be",   # UniversalString
}

# The attribute types worth a short name. Anything else keeps its number, which
# is honest and is what OpenSSL does with an OID it has never met.
_ATTRIBUTE_SHORT_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.25": "DC",
    "1.2.840.113549.1.9.1": "emailAddress",
}

_OID_SUBJECT_ALT_NAME = "2.5.29.17"

# An arc larger than this is not something any real certificate carries, and
# refusing it stops a long run of continuation bytes turning into a very large
# integer.
_MAX_OID_ARC = 2 ** 64


def _element(der: bytes, start: int, end: int) -> tuple[int, int, int]:
    """The one DER element at `start`: (tag, content start, content end).

    Every length is checked against `end` before it is used, so a length a
    stranger wrote can never make anything below read past its buffer.
    """
    if start >= end:
        raise CertificateUnreadable("an element was expected and the data ended")
    tag = der[start]
    cursor = start + 1
    if tag & 0x1F == 0x1F:
        raise CertificateUnreadable("a multi-byte tag, which X.509 does not use")
    if cursor >= end:
        raise CertificateUnreadable("an element carries no length")
    first = der[cursor]
    cursor += 1
    if first == 0x80:
        raise CertificateUnreadable("an indefinite length, which is BER not DER")
    if first < 0x80:
        length = first
    else:
        width = first & 0x7F
        if width > 4:
            raise CertificateUnreadable("a length wider than four bytes")
        if cursor + width > end:
            raise CertificateUnreadable("a length field runs past the end")
        length = int.from_bytes(der[cursor:cursor + width], "big")
        cursor += width
    if length > end - cursor:
        raise CertificateUnreadable("an element runs past the end")
    return tag, cursor, cursor + length


def _children(der: bytes, start: int, end: int):
    """Every element between `start` and `end`, in order.

    An element is at least two bytes, so the cursor always advances and this
    cannot be made to loop forever by anything the peer sends.
    """
    cursor = start
    while cursor < end:
        tag, content_start, content_end = _element(der, cursor, end)
        yield tag, content_start, content_end
        cursor = content_end


def _expect(der: bytes, start: int, end: int, tag: int) -> tuple[int, int]:
    """One element that has to be of a particular type."""
    found, content_start, content_end = _element(der, start, end)
    if found != tag:
        raise CertificateUnreadable(
            f"expected tag {tag:#04x} and found {found:#04x}")
    return content_start, content_end


def _oid_text(der: bytes, start: int, end: int) -> str:
    """An object identifier as dotted decimal."""
    if start >= end:
        raise CertificateUnreadable("an empty object identifier")
    first = der[start]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    unfinished = False
    for byte in der[start + 1:end]:
        value = (value << 7) | (byte & 0x7F)
        if value > _MAX_OID_ARC:
            raise CertificateUnreadable("an object identifier arc is too large")
        unfinished = bool(byte & 0x80)
        if not unfinished:
            parts.append(str(value))
            value = 0
    if unfinished:
        raise CertificateUnreadable("an object identifier ends mid-arc")
    return ".".join(parts)


def _readable(value: str) -> str:
    """Text from a stranger, made safe to store and to print.

    Unprintable characters are removed rather than escaped, which covers the
    newline that would break a log line in two and the right-to-left override
    that would reverse what a person reads. Python calls every category the
    Unicode database files under Other or Separator unprintable, and the ASCII
    space is the one exception, which is exactly the set that has to go.
    """
    kept = "".join(character if character.isprintable() else " "
                   for character in value)
    return kept.strip()[:MAX_CERTIFICATE_TEXT]


def _escaped(value: str) -> str:
    """The separator characters of a rendered name, escaped.

    Without this a common name of `x,O=Somebody Else` renders as
    `CN=x,O=Somebody Else` and reads on a screen as an organisation the
    certificate never carried. RFC 4514 escapes with a backslash and so does
    this.
    """
    for character in ("\\", ",", "=", "+", ";", "<", ">", '"'):
        value = value.replace(character, "\\" + character)
    return value


def _string_value(tag: int, der: bytes, start: int, end: int) -> str | None:
    """One attribute value as text, or None when it is not text at all.

    Decoding never fails: bad bytes become replacement characters, because
    losing a whole certificate over one byte in an organisation name would be
    the wrong trade.
    """
    encoding = _STRING_ENCODINGS.get(tag)
    if encoding is None:
        return None
    return der[start:end].decode(encoding, errors="replace")


def _name_text(der: bytes, start: int, end: int) -> str:
    """A Name rendered the way `openssl x509 -subject` renders one.

        Name ::= SEQUENCE OF RelativeDistinguishedName
        RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
        AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }

    Attributes stay in the order the certificate carries them, so two readings
    of one certificate always produce the same string.
    """
    rendered: list[str] = []
    for set_tag, set_start, set_end in _children(der, start, end):
        if set_tag != _TAG_SET:
            continue
        for pair_tag, pair_start, pair_end in _children(der, set_start, set_end):
            if pair_tag != _TAG_SEQUENCE:
                continue
            fields = list(_children(der, pair_start, pair_end))
            if len(fields) < 2:
                continue
            oid_tag, oid_start, oid_end = fields[0]
            if oid_tag != _TAG_OID:
                continue
            value_tag, value_start, value_end = fields[1]
            text = _string_value(value_tag, der, value_start, value_end)
            if text is None:
                continue
            oid = _oid_text(der, oid_start, oid_end)
            label = _ATTRIBUTE_SHORT_NAMES.get(oid, oid)
            rendered.append(f"{label}={_escaped(_readable(text))}")
    return _readable(",".join(rendered))


def _time_text(tag: int, der: bytes, start: int, end: int) -> str | None:
    """A certificate's own time field as an ISO 8601 string in UTC, or None.

    RFC 5280 4.1.2.5 allows two forms and requires both to end in Z. A field
    that is neither returns None: the rest of the certificate is still worth
    reading, so an odd date must not cost us the subject as well.
    """
    raw = der[start:end].decode("ascii", errors="replace")
    if tag == _TAG_UTC_TIME and len(raw) == 13 and raw.endswith("Z"):
        # RFC 5280 4.1.2.5.1: 00 to 49 is 20xx and 50 to 99 is 19xx. Without
        # this a certificate from 1998 would be filed under 2098.
        two_digit_year = int(raw[0:2]) if raw[0:2].isdigit() else None
        if two_digit_year is None:
            return None
        century = 2000 if two_digit_year < 50 else 1900
        stamp = f"{century + two_digit_year:04d}{raw[2:]}"
    elif tag == _TAG_GENERALIZED_TIME and len(raw) == 15 and raw.endswith("Z"):
        stamp = raw
    else:
        return None
    try:
        moment = datetime.strptime(stamp, "%Y%m%d%H%M%SZ")
    except ValueError:
        return None
    return moment.replace(tzinfo=timezone.utc).isoformat()


def _alternative_names(der: bytes, start: int, end: int) -> list[str]:
    """The dNSName and iPAddress entries of a subject alternative name.

    Only those two, because they are what a port answers on. An email address
    or a URI in there is a different kind of fact and is left rather than half
    read.
    """
    found: list[str] = []
    for tag, name_start, name_end in _children(der, start, end):
        if len(found) >= MAX_CERTIFICATE_NAMES:
            break
        if tag == _TAG_SAN_DNS:
            text = der[name_start:name_end].decode("ascii", errors="replace")
            found.append(_readable(text))
        elif tag == _TAG_SAN_IP:
            packed = der[name_start:name_end]
            if len(packed) not in (4, 16):
                continue
            found.append(str(ipaddress.ip_address(packed)))
    return [entry for entry in found if entry]


def _extension_names(der: bytes, start: int, end: int) -> list[str]:
    """Walk the extensions and read the one this module cares about.

        Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER,
                                 critical BOOLEAN DEFAULT FALSE,
                                 extnValue OCTET STRING }
    """
    for outer_tag, outer_start, outer_end in _children(der, start, end):
        if outer_tag != _TAG_SEQUENCE:
            continue
        for tag, ext_start, ext_end in _children(der, outer_start, outer_end):
            if tag != _TAG_SEQUENCE:
                continue
            fields = list(_children(der, ext_start, ext_end))
            if not fields or fields[0][0] != _TAG_OID:
                continue
            if _oid_text(der, fields[0][1], fields[0][2]) != _OID_SUBJECT_ALT_NAME:
                continue
            value = fields[-1]
            if value[0] != _TAG_OCTET_STRING:
                continue
            inner_start, inner_end = _expect(der, value[1], value[2], _TAG_SEQUENCE)
            return _alternative_names(der, inner_start, inner_end)
    return []


@dataclasses.dataclass(frozen=True)
class Certificate:
    """What one certificate said about itself.

    Every field here came from the peer and none of it has been checked against
    anything. There is deliberately no field saying whether it is valid,
    trusted or expired: the dates are the measurement and the conclusion is the
    reader's (the writing rules).

    `self_issued` is the issuer field equalling the subject field, compared as
    the bytes the certificate carries. It is **not** a checked signature, which
    is why it is not called self signed.
    """
    subject: str
    issuer: str
    not_before: str | None
    not_after: str | None
    serial: str | None
    self_issued: bool
    names: tuple[str, ...]
    fingerprint_sha256: str


def parse_certificate(der: bytes) -> Certificate:
    """Read the fields `docs/PRODUCT.md` section 5 names, out of DER.

    Raises `CertificateUnreadable` and nothing else for anything that is not a
    certificate. Every other outcome would be classified as an unknown failure
    and read as a network problem, which it is not.
    """
    if not isinstance(der, (bytes, bytearray)) or not der:
        raise CertificateUnreadable("no certificate bytes at all")
    if len(der) > MAX_CERTIFICATE_BYTES:
        raise CertificateUnreadable(
            f"a certificate of {len(der)} bytes, over the"
            f" {MAX_CERTIFICATE_BYTES} byte bound")
    der = bytes(der)
    end = len(der)

    outer_start, outer_end = _expect(der, 0, end, _TAG_SEQUENCE)
    tbs_start, tbs_end = _expect(der, outer_start, outer_end, _TAG_SEQUENCE)

    fields = list(_children(der, tbs_start, tbs_end))
    if fields and fields[0][0] == _TAG_VERSION:
        # Version is optional and a v1 certificate leaves it out entirely.
        # Reading the serial as the version would shift every field by one.
        fields = fields[1:]
    if len(fields) < 6:
        raise CertificateUnreadable("a certificate body with too few fields")

    serial_tag, serial_start, serial_end = fields[0]
    if serial_tag != _TAG_INTEGER:
        raise CertificateUnreadable("no serial number where one belongs")
    serial = der[serial_start:serial_end].hex()[:MAX_CERTIFICATE_TEXT]

    issuer_tag, issuer_start, issuer_end = fields[2]
    validity_tag, validity_start, validity_end = fields[3]
    subject_tag, subject_start, subject_end = fields[4]
    for tag in (issuer_tag, validity_tag, subject_tag):
        if tag != _TAG_SEQUENCE:
            raise CertificateUnreadable("a certificate body of the wrong shape")

    validity = list(_children(der, validity_start, validity_end))
    if len(validity) < 2:
        raise CertificateUnreadable("a validity period missing one of its ends")
    not_before = _time_text(validity[0][0], der, validity[0][1], validity[0][2])
    not_after = _time_text(validity[1][0], der, validity[1][1], validity[1][2])

    names: list[str] = []
    for tag, start, stop in fields[6:]:
        if tag == _TAG_EXTENSIONS:
            names = _extension_names(der, start, stop)
            break

    return Certificate(
        subject=_name_text(der, subject_start, subject_end),
        issuer=_name_text(der, issuer_start, issuer_end),
        not_before=not_before,
        not_after=not_after,
        serial=serial,
        # The encoded bytes of the two Name fields, compared whole. Comparing
        # the rendered text instead would let two different names that render
        # the same be called equal.
        self_issued=der[issuer_start:issuer_end] == der[subject_start:subject_end],
        # Already bounded where the walk stops. Cutting the list a second time
        # here would be a second owner of one bound, and the test that proves
        # the bound holds would then pass with either one of them gone.
        names=tuple(names),
        fingerprint_sha256=hashlib.sha256(der).hexdigest())


# --------------------------------------------------------- the TLS primitive

def _certificate_reading_context() -> ssl.SSLContext:
    """A client context that completes a handshake and trusts nothing.

    **Verification is off and that is not a hole here.** Three things make it
    safe, and all three have to stay true:

      - **we send nothing.** There is no request, no credential and no session
        to hand to whoever answered. A man in the middle gets to show us a
        certificate, which is the same thing the real server would do, and
        nothing else happens.
      - **we trust nothing.** No answer here decides anything. It is stored as
        what was presented, and the operator draws the conclusion.
      - **it has to be off to do the job at all.** An expired or self issued
        certificate is a fact we exist to report, and a verifying client
        refuses the handshake and leaves us with nothing to report.

    A fresh context each time on purpose: a shared one caches sessions, and a
    resumed session hands back the certificate from the earlier handshake
    rather than this one.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Order matters: check_hostname has to go first, because turning
    # verification off underneath it raises.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Nothing else is set. No protocol list, no cipher list, no version floor
    # or ceiling of our own, and no server name. Each one of those is us asking
    # the far side what it supports, which is SI-7's version detection under
    # another name. One handshake with this machine's defaults, and whatever
    # comes back.
    return context


def _read_certificate_der(target: str, family: str, port: int,
                          timeout: float) -> bytes:
    """Connect, complete one handshake, take the certificate, close.

    Blocking, and run in a worker thread by the caller. The alternative is
    driving OpenSSL's handshake by hand around a non-blocking socket, and a
    hand-rolled state machine is exactly the clever code this project
    does not write.

    The timeout is a deadline over the whole read rather than a budget for each
    step, so a peer that answers slowly forever cannot hold the thread.
    """
    address_family = _socket_family(target, family)
    context = _certificate_reading_context()
    deadline = time.monotonic() + timeout
    sock = socket.socket(address_family, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((target, port))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("the connection used the whole budget")
        sock.settimeout(remaining)
        # wrap_socket performs the handshake and stops. Nothing below it reads
        # or writes, so no application byte is ever transferred.
        tls = context.wrap_socket(sock)
        try:
            presented = tls.getpeercert(binary_form=True)
        finally:
            # Say goodbye properly, then close.
            #
            # This used to close abruptly, on the reasoning that unwrap sends a
            # close alert and fewer bytes is better. Measured on 2026-08-21,
            # that reasoning was buying the wrong thing. In TLS 1.3 the server
            # sends session tickets after the handshake. We never read them, and
            # closing a socket that still has unread data in its receive queue
            # sends a TCP reset rather than an ordinary FIN. On CPython 3.14,
            # which is what the vantage host runs, that happened on every single
            # TLS 1.3 connection. The target logs a reset, which reads as an
            # error at their end rather than as a client hanging up.
            #
            # So the abrupt close traded about thirty encrypted bytes for an
            # error line in the log of every TLS 1.3 host we touch, and this
            # product's whole posture is a small and quiet footprint.
            #
            # SI-7 is untouched either way. A close alert is the TLS protocol's
            # own goodbye. It carries nothing about the target, reads nothing
            # from it, and is not a byte of application data: the tests measure
            # the server receiving exactly b"" before and after this change.
            #
            # unwrap can raise when the peer has already gone, which is not a
            # failure of the read that already succeeded, so it is swallowed.
            try:
                tls.unwrap()
            except OSError:
                pass
            tls.close()
        return presented or b""
    finally:
        # wrap_socket takes the file descriptor over, which leaves this one
        # detached and its close a no-op. It is here for the paths where the
        # handshake never happened.
        sock.close()


async def tls_certificate(target: str, family: str, port: int,
                          timeout: float = TLS_TIMEOUT_SECONDS) -> bytes:
    """The certificate a TLS port presented, in DER. The second thing in this
    package that puts a packet on the wire, and the last."""
    return await asyncio.to_thread(_read_certificate_der, target, family, port,
                                   timeout)


def classify_tls(exc: BaseException) -> tuple[str, str]:
    """What one failed certificate read observed: (state, reason).

    Every failure is `certificate_not_read`. There is no state here that says
    the port is not TLS, because a handshake can fail on our side as easily as
    on theirs, and `docs/PRODUCT.md` 4b is a retraction of exactly that shape
    of claim.
    """
    if isinstance(exc, CertificateUnreadable):
        return TLS_STATE_NOT_READ, REASON_TLS_CERTIFICATE_UNREADABLE
    if isinstance(exc, ssl.SSLError):
        # SSLError is an OSError, so it is caught before the errno table sees
        # it. Its own text names an OpenSSL alert and that text stops here
        # (SI-8): what crosses the boundary is this one class.
        return TLS_STATE_NOT_READ, REASON_TLS_HANDSHAKE_FAILED
    # Anything else failed the way a connect fails, so it keeps the connect
    # engine's own reason. A refusal and a reset have no reason there, because
    # there the state carries the whole answer, and here that becomes the one
    # reason saying the connection never happened.
    _state, reason, _os_errno = classify(exc)
    return TLS_STATE_NOT_READ, reason or REASON_TLS_NO_CONNECT


async def _measure(connect, target: str, family: str, port: int,
                   timeout: float) -> tuple[str, str | None, float | None, int | None]:
    """One connect and the state it produced: (state, reason, ms, errno).

    **It does not check authorisation. Its only caller does, on the line
    before.** It is separate from that caller for one reason: the tests need to
    point the real primitive at a real socket, and the only addresses a test can
    bind are loopback ones, which the gate refuses to authorise and is right to
    refuse. So this is where a real socket gets exercised and `_probe_one_port`
    is where the gate is.
    """
    try:
        async with asyncio.timeout(timeout):
            elapsed = await connect(target, family, port)
    except Exception as exc:  # every failure is classified, none is a finding
        state, reason, os_errno = classify(exc)
        return state, reason, None, os_errno
    return STATE_CONNECTED, None, elapsed * 1000.0, None


# ------------------------------------------------------------------- results

@dataclasses.dataclass(frozen=True)
class Result:
    """One answer, for one port, on one address family.

    `state` is the only field anything may draw a picture from, and `reason` is
    the typed detail behind a not_tested. `target` is None when there was no
    address to probe in this family, and `port` is None when what we were
    handed was not a port number.
    """
    family: str
    target: str | None
    port: int | None
    state: str
    reason: str | None = None
    connect_ms: float | None = None
    os_errno: int | None = None
    measured_at: str = ""

    @property
    def measured(self) -> bool:
        return self.state in MEASURED_STATES


@dataclasses.dataclass(frozen=True)
class TlsResult:
    """One certificate read, for one port, on one address family.

    The pairing is the invariant, and it is asserted over every row rather than
    described: a row that read a certificate carries no reason, and a row that
    did not always carries one and never a certificate. A read that produced
    neither would be the silent absence this project keeps finding.
    """
    family: str
    target: str | None
    port: int | None
    state: str
    reason: str | None = None
    certificate: Certificate | None = None
    read_at: str = ""


@dataclasses.dataclass(frozen=True)
class Run:
    """One pass over one target's ports. `results` is complete by
    construction: every family in FAMILIES appears, always.

    `certificates` is empty unless the caller named ports to read one from, and
    holds exactly one row per named port per family when it did.
    """
    # None until something stores it. A measurement taken on a vantage host
    # has no row anywhere yet, and calling that 0 would be a row id that means
    # something else.
    id: int | None
    vantage: str
    started_at: str
    finished_at: str
    results: tuple[Result, ...]
    certificates: tuple[TlsResult, ...] = ()


# --------------------------------------------------------------- port hygiene

@dataclasses.dataclass(frozen=True)
class PortEntry:
    """A requested port after normalisation. `reason` is None for a port we
    are willing to connect to, and set for one we are not."""
    port: int | None
    reason: str | None


def normalise_ports(ports) -> tuple[PortEntry, ...]:
    """Deduplicate, order, and refuse what is not a port.

    Nothing is dropped. A port that cannot be probed becomes an entry carrying
    the reason, so it appears in the output as not_tested rather than going
    missing between the request and the answer.

    Ordering is: every probeable port ascending, then the refused entries in
    the order they arrived. Deterministic, because a run's output is compared
    with the last one.
    """
    probeable: list[int] = []
    refused: list[PortEntry] = []
    seen_ports: set[int] = set()
    seen_refusals: set[tuple] = set()

    for value in ports:
        # bool is an int in Python and True would silently become port 1.
        if isinstance(value, bool) or not isinstance(value, int):
            key = (REASON_PORT_NOT_AN_INTEGER, repr(value)[:MAX_TARGET_TEXT])
            if key not in seen_refusals:
                seen_refusals.add(key)
                refused.append(PortEntry(None, REASON_PORT_NOT_AN_INTEGER))
            continue
        if value < MIN_PORT or value > MAX_PORT:
            key = (REASON_PORT_OUT_OF_RANGE, value)
            if key not in seen_refusals:
                seen_refusals.add(key)
                refused.append(PortEntry(value, REASON_PORT_OUT_OF_RANGE))
            continue
        if value not in seen_ports:
            seen_ports.add(value)
            probeable.append(value)

    return tuple([PortEntry(port, None) for port in sorted(probeable)] + refused)


def _as_list(value, name: str) -> list:
    """A sequence of items, refusing the one mistake that would otherwise pass.

    A single address handed in where a list belongs iterates into characters,
    and every character becomes a target we could not read. The run would
    "work" and answer nothing about anything, which is the quiet shape this
    project keeps finding (`docs/RECORD.md` 4.45). So a bare string is a
    TypeError at the door rather than fifteen useless rows.
    """
    if isinstance(value, (str, bytes)):
        raise TypeError(f"{name} must be a sequence of items, not one string")
    try:
        return list(value)
    except TypeError:
        raise TypeError(f"{name} must be a sequence of items") from None


def _group_by_family(addresses) -> tuple[dict[str, list[str]], list[str]]:
    """Canonical addresses per family, plus whatever was not an address.

    The family comes from the address, through `authz.normalise_target`, which
    is the same function the gate uses. Deriving it any other way is how a v4
    answer gets filed under v6.
    """
    by_family: dict[str, list[str]] = {family: [] for family in FAMILIES}
    unreadable: list[str] = []
    for address in addresses:
        try:
            target, family = authz.normalise_target(address)
        except authz.TargetError:
            text = address if isinstance(address, str) else repr(address)
            unreadable.append(text[:MAX_TARGET_TEXT])
            continue
        if target not in by_family[family]:
            by_family[family].append(target)
    return by_family, unreadable


# -------------------------------------------------------------------- storage

class HostGone(sqlite3.IntegrityError):
    """A run could not be stored because its server is not in the database.

    A pass takes its list of servers before it measures the first one, and a
    server can be deleted in the dashboard while the pass is under way. Its
    run then points at a host that does not exist, and the database refuses
    the row. That is not a fault in the pass, and it has a name of its own so
    a caller can leave that one server out and go on (docs/RECORD.md 4.312).

    **It is still the database's refusal**, an `IntegrityError` and nothing
    softer: a run cannot name a host that does not exist, and code that does
    not ask for this name gets the error it always got. Every other refusal
    from the database is raised as itself.
    """


@contextlib.contextmanager
def _storing_for(con: sqlite3.Connection, host_id: int | None):
    """Around the writes of one host's run. A refused write for a host that is
    gone becomes `HostGone`, and nothing else is caught or renamed.

    The check is made after the refusal, never before the write: a server can
    go between a check and the write, and then the check was worth nothing.
    """
    try:
        yield
    except sqlite3.IntegrityError:
        con.rollback()
        gone = host_id is not None and con.execute(
            "SELECT 1 FROM hosts WHERE id = ?", (host_id,)).fetchone() is None
        if gone:
            raise HostGone(f"host {host_id} is not in the database") from None
        raise


def _start_run(con: sqlite3.Connection, host_id: int | None, vantage: str,
               started_at: str) -> int:
    """The run row exists before the first packet, and `finished_at` stays NULL
    until the results are written. A run that dies half way therefore reads as
    a run that did not finish, rather than as a short list of measurements."""
    cur = con.execute(
        "INSERT INTO probe_runs (host_id, vantage, started_at) VALUES (?, ?, ?)",
        (host_id, vantage, started_at))
    con.commit()
    return cur.lastrowid


def _finish_run(con: sqlite3.Connection, run_id: int, results, certificates,
                finished_at: str) -> None:
    """One transaction for the results, the certificates and the finish stamp,
    so a run can never be marked finished without all of them being there.

    The results are held in memory until here. The largest run
    `docs/PRODUCT.md` section 5 contemplates is 65,535 ports across two
    families, which is 131,070 rows, and that is the bound this choice accepts
    rather than a limit it imposes.
    """
    con.executemany(
        "INSERT INTO probe_results (run_id, target, family, port, state, reason,"
        " connect_ms, os_errno, measured_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(run_id, r.target, r.family, r.port, r.state, r.reason, r.connect_ms,
          r.os_errno, r.measured_at) for r in results])
    con.executemany(
        "INSERT INTO probe_tls (run_id, target, family, port, state, reason,"
        " subject, issuer, not_before, not_after, serial, self_issued, names,"
        " fingerprint, read_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [_tls_row(run_id, r) for r in certificates])
    con.execute("UPDATE probe_runs SET finished_at = ? WHERE id = ?",
                (finished_at, run_id))
    con.commit()


def _tls_row(run_id: int, result: TlsResult) -> tuple:
    """One certificate row, flattened for storage.

    A row that read nothing stores nothing but its reason. Leaving a stale
    subject beside a not-read state is how a row starts saying two things at
    once.
    """
    certificate = result.certificate
    if certificate is None:
        return (run_id, result.target, result.family, result.port, result.state,
                result.reason, None, None, None, None, None, None, None, None,
                result.read_at)
    return (run_id, result.target, result.family, result.port, result.state,
            result.reason, certificate.subject, certificate.issuer,
            certificate.not_before, certificate.not_after, certificate.serial,
            1 if certificate.self_issued else 0, " ".join(certificate.names),
            certificate.fingerprint_sha256, result.read_at)


def latest_run(con: sqlite3.Connection, host_id: int) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM probe_runs WHERE host_id = ?"
        " ORDER BY started_at DESC, id DESC LIMIT 1", (host_id,)).fetchone()


def latest_finished_run_from(con: sqlite3.Connection, host_id: int,
                             vantage: str) -> sqlite3.Row | None:
    """The newest run one vantage finished for one host, or None.

    Finished only, because a run with a start and no finish is a pass that
    died, and the dead-man watch that calls this must not count it as a
    refresh. `latest_run` above answers a different question, the newest
    row whatever its state and whoever took it.
    """
    return con.execute(
        "SELECT * FROM probe_runs WHERE host_id = ? AND vantage = ?"
        " AND finished_at IS NOT NULL"
        " ORDER BY finished_at DESC, id DESC LIMIT 1", (host_id, vantage)).fetchone()


def run_results(con: sqlite3.Connection, run_id: int) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM probe_results WHERE run_id = ? ORDER BY id", (run_id,)
    ).fetchall()


def host_results(con: sqlite3.Connection, host_id: int) -> list[sqlite3.Row]:
    """Every probe result for a host, across every run, with its run's vantage.

    `run_results` answers "what did this one run see". This answers "what has
    ever been measured for this host", which is what the join engine needs once
    two lanes probe two different port sets: a port only the older lane covers
    still has to be found. The vantage rides along because where a connect was
    attempted from decides what its result means (`docs/PRODUCT.md` 5e), so a
    caller resolving one port across runs cannot go back to the run row for it.

    Ordered by `measured_at` then `id` only so a read is deterministic. The
    engine decides which measurement is newest by `measured_at` itself, never
    by this order, because two lanes interleave and row order does not.
    """
    return con.execute(
        "SELECT r.*, runs.vantage AS vantage"
        " FROM probe_results r JOIN probe_runs runs ON r.run_id = runs.id"
        " WHERE runs.host_id = ?"
        " ORDER BY r.measured_at, r.id", (host_id,)).fetchall()


def has_latest(con: sqlite3.Connection) -> bool:
    """Whether this database has `probe_latest`, which is every database
    `init` has run against since 2026-09-20."""
    return con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table'"
                       " AND name = 'probe_latest'").fetchone() is not None


def host_latest_results(con: sqlite3.Connection, host_id: int) -> list[sqlite3.Row]:
    """The newest probe result per family, port, address and vantage for one
    host, in the shape `host_results` returns a row in.

    What the join engine reads per page load instead of every row the host
    ever had (`LATEST_SCHEMA` says why). The rows are the stored results
    themselves, so nothing about a measurement is restated in a second place.
    """
    return con.execute(
        "SELECT r.*, runs.vantage AS vantage"
        " FROM probe_latest latest"
        " JOIN probe_results r ON r.id = latest.result_id"
        " JOIN probe_runs runs ON runs.id = r.run_id"
        " WHERE latest.host_id = ?"
        " ORDER BY r.measured_at, r.id", (host_id,)).fetchall()


def run_certificates(con: sqlite3.Connection, run_id: int) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM probe_tls WHERE run_id = ? ORDER BY id", (run_id,)
    ).fetchall()


# --------------------------------------------------------------------- prober

def _allows(authority, target: str, gate_clock: datetime | None) -> bool:
    """The non-raising form, for the pre-flight refusal only.

    `ProbeAuthority` has one method on purpose, so a caller cannot reach for a
    boolean and forget to use the canonical target it returns. This wrapper
    exists for the one place that genuinely wants a yes or no and throws the
    target away, and it is deliberately not a method for that reason.
    """
    try:
        authority.require(target, now=gate_clock)
    except authz.NotAuthorized:
        return False
    return True


class Prober:
    """Holds the pace and the primitive. One of these per process.

    Everything that could touch the network or the clock is an argument, which
    is why the tests are deterministic without mocking a socket library.

    Two clocks on purpose. `clock` is monotonic and paces the connects, because
    a wall clock that steps backwards would let a burst through. `utcnow` is
    the wall clock and only ever stamps a row.
    """

    def __init__(self, *, connect=tcp_connect, tls_read=tls_certificate,
                 timeout: float = CONNECT_TIMEOUT_SECONDS,
                 tls_timeout: float = TLS_TIMEOUT_SECONDS,
                 concurrency: int = MAX_CONCURRENT_CONNECTS,
                 rate_per_second: float = CONNECTS_PER_SECOND_PER_TARGET,
                 clock=time.monotonic, sleep=asyncio.sleep,
                 utcnow=_utcnow, vantage: str | None = None) -> None:
        if concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self._connect = connect
        self._tls_read = tls_read
        self._tls_timeout = tls_timeout
        self._timeout = timeout
        self._concurrency = concurrency
        self._sleep = sleep
        self._utcnow = utcnow
        self.vantage = vantage or default_vantage()
        # One bucket, reused across runs, so two runs against one target share
        # the pace instead of doubling it. Reused from app/ratelimit.py rather
        # than written again, because a second rate limiter in one codebase is
        # how two different limits end up believed at once.
        #
        # **Capacity one, so there is no burst.** Until 2026-09-12 the bucket
        # held a full second's worth of tokens at birth, and every batch on a
        # vantage host is a fresh process with a fresh bucket, so each batch
        # opened with 40 connects in the same instant and a host with 30 ports
        # saw 63 in one second from three back-to-back batches that never
        # overlapped. With one token the first connect of a fresh runner is
        # paced like the hundredth, and "40 a second" is true in every second
        # a target can measure, not only on average.
        self._pace = ratelimit.TokenBucket(
            1.0, rate_per_second, clock=clock, max_keys=PACE_BUCKET_MAX_KEYS)
        # TokenBucket.retry_after_seconds answers in whole seconds, which is 25
        # times too coarse at 40 a second, so the wait is computed from the
        # refill rate. Only `allow` is used, so there is still one bucket
        # deciding the pace and this is only the waiting shape around it.
        self._pace_interval = 1.0 / rate_per_second

    # ------------------------------------------------------------- pacing

    async def _take_pace_token(self, key: str) -> None:
        while not self._pace.allow(key):
            await self._sleep(self._pace_interval)

    @staticmethod
    def pace_key(host_id: int | None, targets) -> str:
        """What the pace is counted against.

        `docs/PRODUCT.md` section 5 says per host, and a host's v4 and v6
        addresses are one host, so both families share one bucket. The key is
        the host id when there is one, and the set of addresses otherwise.

        The limit this leaves, stated rather than discovered: a caller that
        splits one host across two runs with no host id paces each half
        separately. Probe a host in one run.
        """
        if host_id is not None:
            return f"host:{host_id}"
        return "targets:" + ",".join(sorted(targets))

    # -------------------------------------------------------------- one port

    async def _probe_one_port(self, authority, target: str,
                              family: str, port: int, pace_key: str,
                              gate_clock: datetime | None) -> Result:
        """One connect, from the gate to the closed socket.

        The order is: wait for the pace, then ask the gate, then connect. The
        wait comes first so that nothing sits between the gate's answer and the
        packet, which is the whole point of checking per port.

        `authority` answers the same question the database always answered. On
        the control plane it is that database. On a prober it is a snapshot the
        control plane built by asking it. **Neither can be asked once per run
        instead of once per connect without changing what SI-6 means**, which is
        why the call is here rather than above the loop.
        """
        await self._take_pace_token(pace_key)
        try:
            authorised = authority.require(target, now=gate_clock)
        except authz.NotAuthorized:
            return self._result(family, target, port, STATE_NOT_TESTED,
                                REASON_NO_AUTHORIZATION)
        state, reason, connect_ms, os_errno = await _measure(
            self._connect, authorised, family, port, self._timeout)
        return self._result(family, authorised, port, state, reason,
                            connect_ms=connect_ms, os_errno=os_errno)

    def _result(self, family, target, port, state, reason=None, *,
                connect_ms=None, os_errno=None) -> Result:
        return Result(family=family, target=target, port=port, state=state,
                      reason=reason, connect_ms=connect_ms, os_errno=os_errno,
                      measured_at=self._utcnow().isoformat())

    # ------------------------------------------------------ one certificate

    async def _read_one_certificate(self, authority,
                                    connected: Result, pace_key: str,
                                    gate_clock: datetime | None) -> TlsResult:
        """One handshake, from the gate to the closed socket.

        The order is the connect path's order for the same reason: wait for the
        pace, ask the gate, then open the connection, so nothing sits between
        the gate's answer and the packet. **The gate is asked again here even
        though the connect asked a moment ago.** A certificate read is its own
        connection, and an authorisation that lapsed in between has to stop it.
        """
        if connected.state != STATE_CONNECTED or connected.target is None:
            # No handshake was attempted. The connect row beside this one says
            # why the connect did not succeed, so this does not repeat it.
            return self._tls_result(connected.family, connected.target,
                                    connected.port, TLS_STATE_NOT_READ,
                                    REASON_TLS_NO_CONNECT)
        await self._take_pace_token(pace_key)
        try:
            authorised = authority.require(connected.target, now=gate_clock)
        except authz.NotAuthorized:
            return self._tls_result(connected.family, connected.target,
                                    connected.port, TLS_STATE_NOT_READ,
                                    REASON_NO_AUTHORIZATION)
        try:
            presented = await self._tls_read(authorised, connected.family,
                                             connected.port, self._tls_timeout)
        except Exception as exc:  # every failure is typed, none is an absence
            state, reason = classify_tls(exc)
            return self._tls_result(connected.family, authorised,
                                    connected.port, state, reason)
        if not presented:
            # A handshake can complete with no certificate at all. That is a
            # fact about the peer, and it is not a certificate.
            return self._tls_result(connected.family, authorised,
                                    connected.port, TLS_STATE_NOT_READ,
                                    REASON_TLS_NO_CERTIFICATE)
        try:
            certificate = parse_certificate(presented)
        except CertificateUnreadable:
            return self._tls_result(connected.family, authorised,
                                    connected.port, TLS_STATE_NOT_READ,
                                    REASON_TLS_CERTIFICATE_UNREADABLE)
        return self._tls_result(connected.family, authorised, connected.port,
                                TLS_STATE_READ, None, certificate=certificate)

    def _tls_result(self, family, target, port, state, reason,
                    certificate=None) -> TlsResult:
        return TlsResult(family=family, target=target, port=port, state=state,
                         reason=reason, certificate=certificate,
                         read_at=self._utcnow().isoformat())

    # ------------------------------------------------------------------ run

    async def measure(self, authority, addresses, ports, *,
                      host_id: int | None = None,
                      gate_clock: datetime | None = None,
                      tls_ports=(), started: str | None = None) -> Run:
        """Probe every port on every address, and answer for both families.

        **Measures and stores nothing.** The returned Run has `id` None,
        because nothing has recorded it. This is the half that can run on a
        vantage host, where there is no database to record into and the gate
        arrives as a snapshot instead.

        `addresses` is the literal addresses of one target host, at most one
        per family in practice. `ports` is whatever the caller has, including
        duplicates and rubbish.

        `tls_ports` names the ports a certificate is read from, and it is empty
        by default. **A certificate read is a second connection to the port**,
        so it happens where the caller asked for it and nowhere else. Handshaking
        every port that answered would double the fleet's connections to find
        out something nobody asked.

        `gate_clock` is passed to the authorisation gate and exists so a test
        can place a run before or after an expiry. Left alone it is the real
        clock, decided inside the gate.
        """
        entries = normalise_ports(_as_list(ports, "ports"))
        by_family, unreadable = _group_by_family(_as_list(addresses, "addresses"))
        started = started or self._utcnow().isoformat()

        all_targets = [t for targets in by_family.values() for t in targets]
        pace_key = self.pace_key(host_id, all_targets)

        results: list[Result] = []
        # A slow target must not stall the others, so the connects run
        # concurrently under one semaphore. It is created here rather than on
        # the Prober because an asyncio primitive belongs to one event loop:
        # the bound is therefore per run, while the pace above is per target
        # across runs. Two concurrent runs can hold twice the sockets and
        # still cannot exceed the pace, which is the half that reaches anybody
        # else's network.
        slots = asyncio.Semaphore(self._concurrency)

        async def probe_with_slot(target, family, port):
            async with slots:
                return await self._probe_one_port(authority, target, family,
                                                  port, pace_key, gate_clock)

        tasks = []
        for family in FAMILIES:
            targets = by_family[family]
            if not targets:
                # The one rule this module exists for: a family with no address
                # is not tested, and never a state that reads as a finding.
                for entry in entries:
                    results.append(self._result(
                        family, None, entry.port, STATE_NOT_TESTED,
                        entry.reason or REASON_NO_ADDRESS_IN_FAMILY))
                continue
            for target in targets:
                # An unauthorised target is refused once here rather than once
                # per port, so a thousand ports on an address nobody proved do
                # not spend a thousand pace tokens waiting to be refused.
                # **This is an optimisation and never the authority.** A target
                # allowed here is asked again immediately before every single
                # connect, which is what makes a revocation mid-run stop the
                # packets, and a target refused here is refused for every port
                # by the same answer.
                if not _allows(authority, target, gate_clock):
                    for entry in entries:
                        results.append(self._result(
                            family, target, entry.port, STATE_NOT_TESTED,
                            entry.reason or REASON_NO_AUTHORIZATION))
                    continue
                for entry in entries:
                    if entry.reason is not None:
                        # A port that is not a port is not a port in either
                        # family, so the port's reason wins over anything about
                        # the address.
                        results.append(self._result(family, target, entry.port,
                                                    STATE_NOT_TESTED, entry.reason))
                        continue
                    tasks.append(probe_with_slot(target, family, entry.port))

        for text in unreadable:
            # Not a family's answer and not absent either. It appears under
            # FAMILY_UNKNOWN so nothing can read it as a v4 or v6 result.
            for entry in entries:
                results.append(self._result(
                    FAMILY_UNKNOWN, text, entry.port, STATE_NOT_TESTED,
                    entry.reason or REASON_TARGET_NOT_AN_ADDRESS))

        if tasks:
            results.extend(await asyncio.gather(*tasks))

        results.sort(key=lambda r: (r.family, r.target or "",
                                    MAX_PORT + 1 if r.port is None else r.port))

        # The certificate reads come after every connect, because a handshake
        # only happens on a port the connect already found answering, and
        # because keeping the two phases apart is what makes "one connect, then
        # at most one handshake" a shape a reader can check.
        certificates = await self._read_certificates(
            authority, results, _as_list(tls_ports, "tls_ports"), pace_key,
            slots, gate_clock)

        finished = self._utcnow().isoformat()
        return Run(id=None, vantage=self.vantage, started_at=started,
                   finished_at=finished, results=tuple(results),
                   certificates=tuple(certificates))

    async def run(self, con: sqlite3.Connection, addresses, ports, *,
                  host_id: int | None = None,
                  gate_clock: datetime | None = None,
                  account: str = authz.DEFAULT_ACCOUNT,
                  tls_ports=()) -> Run:
        """Measure, and record what was measured. The control plane's path.

        The gate is the live database, which is what it has always been here,
        so nothing about how this behaves changed when `measure` was split out.

        `account` is the workspace's account (`authz.account_for_workspace`),
        and it narrows the gate rather than widening it: an address proved in
        another workspace is not in this account and is refused with the same
        words as an address nobody proved. The default is workspace 1's, which
        is what every caller written before workspaces asked for.

        The run row is opened **before** the first connect and closed after the
        last one, deliberately. A run that dies halfway leaves a row with a
        start and no finish, and that row is the only evidence the pass ever
        began.
        """
        started = self._utcnow().isoformat()
        with _storing_for(con, host_id):
            run_id = _start_run(con, host_id, self.vantage, started)
        measured = await self.measure(
            authz.DatabaseAuthority(con, account), addresses, ports, host_id=host_id,
            gate_clock=gate_clock, tls_ports=tls_ports, started=started)
        with _storing_for(con, host_id):
            _finish_run(con, run_id, measured.results, measured.certificates,
                        measured.finished_at)
        return dataclasses.replace(measured, id=run_id)

    async def _read_certificates(self, authority, results, tls_ports, pace_key, slots,
                                 gate_clock) -> list[TlsResult]:
        """One certificate row for every named port, in every family.

        Mirrors the connect results exactly rather than only covering the ports
        that answered, so a port the caller asked about always has an answer.
        A port that has no row is a port nobody can see was not measured, which
        is the quiet shape `docs/RECORD.md` 4.45 keeps finding.
        """
        wanted = {port for port in tls_ports
                  if isinstance(port, int) and not isinstance(port, bool)}
        if not wanted:
            return []

        async def read_with_slot(connected):
            async with slots:
                return await self._read_one_certificate(authority, connected,
                                                        pace_key, gate_clock)

        tasks = [read_with_slot(row) for row in results
                 if row.port in wanted and row.family in FAMILIES]
        if not tasks:
            return []
        certificates = list(await asyncio.gather(*tasks))
        certificates.sort(key=lambda r: (r.family, r.target or "",
                                         MAX_PORT + 1 if r.port is None else r.port))
        return certificates


async def probe(con: sqlite3.Connection, addresses, ports, *,
                host_id: int | None = None, tls_ports=(), **kwargs) -> Run:
    """One run with a fresh Prober. Convenience for a caller with one target.

    Anything probing repeatedly should hold a Prober, because the pace lives
    there and a fresh one per target starts with a full bucket.
    """
    return await Prober(**kwargs).run(con, addresses, ports, host_id=host_id,
                                      tls_ports=tls_ports)


# ------------------------------------------------------- results on the wire
#
# A measurement taken on a vantage host has to reach the control plane as text.
# These are the only two functions that decide that shape, so the runner and
# the ingest cannot drift into two spellings of one result.

RUN_VERSION = 1


def run_to_json(measured: Run) -> dict:
    """One completed measurement, as text.

    **Every field here is already a closed set or a number** (SI-8): states and
    reasons are module constants, `os_errno` is an integer, and nothing carries
    a free text error or anything read from inside a service.
    """
    return {
        "version": RUN_VERSION,
        "vantage": measured.vantage,
        "started_at": measured.started_at,
        "finished_at": measured.finished_at,
        "results": [dataclasses.asdict(r) for r in measured.results],
        "certificates": [dataclasses.asdict(c) for c in measured.certificates],
    }


def _certificate_from_json(raw) -> "Certificate | None":
    """One certificate rebuilt from the shape `run_to_json` writes, or None.

    **A nested dataclass does not come back on its own, and nothing said so
    until it broke.** `dataclasses.asdict` flattens the Certificate inside a
    TlsResult into a plain dict on the way out, and `TlsResult(**row)` put that
    dict straight back into the field on the way in. The row then reached
    `_tls_row`, which reads `certificate.subject`, and the whole pass for that
    host died with an AttributeError before anything was stored.

    It never showed up because it needs two things at once: a certificate that
    was actually read, and the wire. The local prober path builds the object
    and never serialises it, and the round-trip test in the suite probed with
    no `--tls-port`, so it round-tripped an empty certificate list. On the
    remote path, which is the only one the fleet uses, the first port that
    answered a handshake would have taken the run down.

    The same two rules the rows around it follow: a field this build does not
    know and a field it needs and cannot find are both refusals, never a
    partial certificate stored as though it were read.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise RunUnreadable("a certificates row carries a certificate that is"
                            " not an object")
    fields = {f.name for f in dataclasses.fields(Certificate)}
    unknown = set(raw) - fields
    if unknown:
        raise RunUnreadable(
            f"a certificate carries unknown fields {sorted(unknown)}")
    missing = fields - set(raw)
    if missing:
        raise RunUnreadable(f"a certificate is missing {sorted(missing)}")
    names = raw["names"]
    # A list or a tuple, because both arrive here. Over the wire JSON makes it
    # a list, and `run_from_json(run_to_json(run))` in the same process hands
    # back the tuple `dataclasses.asdict` preserved. Refusing the tuple would
    # break the round trip nothing serialises, which is how the tests and
    # `app/probe_runner.py` both call this.
    if not isinstance(names, (list, tuple)) or not all(isinstance(n, str)
                                                       for n in names):
        raise RunUnreadable("a certificate's names are not a list of text")
    # A tuple, because that is what the field is declared as and what the
    # locally built object holds. A list here would make the same certificate
    # two different values depending on which path it arrived by.
    return Certificate(**{**raw, "names": tuple(names)})


def run_from_json(payload) -> Run:
    """Rebuild a measurement from text, refusing anything that is not one.

    The control plane calls this on whatever a prober sent back, so it is
    parsing input from a machine it should not have to trust more than it has
    to. Every unexpected shape raises rather than producing a partial Run that
    would be stored as though it were measured.
    """
    if not isinstance(payload, dict):
        raise RunUnreadable("the run is not an object")
    if payload.get("version") != RUN_VERSION:
        raise RunUnreadable(
            f"the run is version {payload.get('version')!r} and this build"
            f" reads version {RUN_VERSION}")
    for key in ("vantage", "started_at", "finished_at"):
        if not isinstance(payload.get(key), str):
            raise RunUnreadable(f"the run has no readable {key}")

    def rows(name, cls):
        raw = payload.get(name)
        if not isinstance(raw, list):
            raise RunUnreadable(f"the run has no {name} list")
        fields = {f.name for f in dataclasses.fields(cls)}
        out = []
        for row in raw:
            if not isinstance(row, dict):
                raise RunUnreadable(f"a {name} row is not an object")
            unknown = set(row) - fields
            if unknown:
                # A row carrying fields this build does not know is a row from
                # a different contract. Storing what we recognise and dropping
                # the rest is how a silent mismatch becomes a stored fact.
                raise RunUnreadable(
                    f"a {name} row carries unknown fields {sorted(unknown)}")
            missing = fields - set(row)
            if missing:
                raise RunUnreadable(
                    f"a {name} row is missing {sorted(missing)}")
            if cls is TlsResult:
                row = {**row, "certificate": _certificate_from_json(row["certificate"])}
            out.append(cls(**row))
        return tuple(out)

    return Run(id=None, vantage=payload["vantage"],
               started_at=payload["started_at"],
               finished_at=payload["finished_at"],
               results=rows("results", Result),
               certificates=rows("certificates", TlsResult))


def store_measurement(con: sqlite3.Connection, host_id: int | None,
                      measured: Run) -> Run:
    """Record a measurement that was taken somewhere else.

    `Prober.run` opens its row before the first connect, so a run that dies
    halfway leaves evidence it began. **This cannot do that**, because by the
    time a remote measurement arrives it is already finished. The two write the
    same rows and the difference is only when the row appears, which is worth
    knowing when a run is missing: a local one that died leaves a row with no
    finish, and a remote one that died leaves nothing at all.
    """
    with _storing_for(con, host_id):
        run_id = _start_run(con, host_id, measured.vantage, measured.started_at)
        _finish_run(con, run_id, measured.results, measured.certificates,
                    measured.finished_at)
    return dataclasses.replace(measured, id=run_id)
