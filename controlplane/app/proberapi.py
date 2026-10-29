"""The prober API: a self-hosted whichports asks, our registry decides.

`untilbeta.md` item 3. A self-hosted instance has no prober of its own and
must not need one. Its control plane builds the same batch it would send over
ssh (`dispatch.build_batch`) and hands it to this API instead
(`dispatch.ApiTransport`). This file checks the batch, charges it to the
instance, queues it, and hands the answer back. `app/proberapi_worker.py`
drives the prober. `app/proberapi_routes.py` is the HTTP half.

## What our side decides, and what the instance's side can only narrow

**Our registry decides what may be probed.** The snapshot the prober carries
is built by the worker from this database, under the instance's own account
(`authz.account_for_instance`), so an instance can make our probers probe
only an address it proved to us. That is SI-6 as it has always been, with the
instance as the account. Anything else turns our probers into a free scanner,
and our providers' terms make the abuse reports ours.

**The instance's own snapshot can only narrow ours.** Its batch carries a
snapshot. We read the targets out of it and never the permission: an address
is in the snapshot the prober receives only when our registry allows it for
this instance **and** the instance's snapshot let it through, so nothing the
instance writes into its snapshot can add an address. Since 2026-10-24 an
instance's snapshot also takes the addresses `GET /proofs` lists live for it,
where its own registry allows that (`authz.snapshot_for_prober_api`,
docs/PRODUCT.md 5g), and a revoke on its dashboard reaches our registry first
(`app/proberproofs.py`). Its expiry times are not used, because they were read
off another machine's clock and ours is the one the gate trusts.

## The pace, both of them

**Per target, 40 connects a second in total, across every instance, both
vantages and our own timers** (`docs/PRODUCT.md` 5d). The worker runs one
batch at a time on each prober, a thread per prober, and each batch holds the
locks of its addresses, the same finer locks every probing pass on this box
takes (`app/probelock.py`). So no address ever has two of our runners against
it, whoever asked, and a target never sees more than one runner's pace. An
instance and our own timers watching one address is the case this exists
for: since 2026-10-20 one address belongs to one instance (`docs/PRODUCT.md`
5), and our own fleet is never held out. The cost is throughput: an
instance's batch waits for its prober.

**Per instance, a budget and one batch at a time.** An instance may have one
batch not yet finished, which is what its own pass does anyway, and may spend
`CONNECTS_PER_HOUR` in any hour. A batch is charged when it is queued, at the
most it could cost: every address times every port, plus a certificate read
on every TLS port it names. Charges are rows, kept for the hour they count
in, so a restart forgets nothing.

**And the seconds its batches held the lock, since 2026-10-26.** The
connects bound what a target sees. They do not bound how long one
instance's batches keep every other instance waiting: a connect to an
address that drops everything holds one of the runner's 64 slots for the
whole five second timeout, so the same connects can hold the lock many times
longer. The worker times each batch and writes the seconds on its charge row
(`charge_lock_seconds`), and an instance whose batches held the lock
`LOCK_SECONDS_PER_HOUR` or more in the last hour is refused with the same
`over_instance_pace` and a Retry-After. A batch is charged after it ran, so
one batch can pass the cap by its own length. The number was set from a
synthetic run of many instances, `ops/locksim.py`, and docs/PRODUCT.md 5g
has what it found.

## What is stored, and for how long

As little as serves the answer, the pace and an abuse report. Their host
documents, host names and measurement history stay on their instance.

  - **the queued batch and its answer**, until the answer is fetched and never
    longer than `BATCH_TTL_SECONDS`, whatever state it is in
  - **the charges**: one row per batch, instance, connects, the seconds it
    held the lock and time, kept for the hour the pace reads them and then
    gone
  - **the proof counts**: one row per proof an instance started or read, its
    challenge for a read and the time, kept for the hour the pace reads them
    (`PROOF_STARTS_PER_HOUR`) and then gone
  - **the abuse log**: one row per instance, vantage, address and day, with
    the first and last time a batch that could reach it ran, how many did,
    and the connects they could have made. No ports, no results. Kept
    `LOG_RETENTION_SECONDS`, because an abuse report to Vultr or Akamai names
    an address and a time, and this is what ties that to one instance and to
    the proof behind it. A row per batch would be hundreds of thousands of
    rows a month to answer a question asked by the day

## Every refusal is a class, never a sentence

The API answers a closed set of error classes (`ERRORS`, `FAILURES`), SI-8
applied to a wire that faces another operator's machine. What went wrong in
detail is in this box's journal. **An unknown key and a revoked key are the
same refusal**, so the answer never confirms that a key was ever real, and an
instance asking for another's batch gets the refusal for a batch that does
not exist.
"""

import dataclasses
import json
import math
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from . import authz, dispatch, prober

PATH_PREFIX = "/api/v1/prober"

# A batch is 200 ports and a handful of addresses. 64 KiB is room for that
# many times over, and above it the request is not a batch. Caddy's 8 MB cap
# on /api/v1/* is the backstop for a body that lies about its length.
MAX_BODY_BYTES = 64 * 1024

# One host's addresses. A host holds one or two public ones in practice, and
# a batch naming more than this is not one host.
MAX_ADDRESSES = 16

# The ports in one batch. Owned by dispatch, which splits every pass into
# batches of this size, so a batch from an honest instance is never refused
# for its length.
MAX_PORTS = dispatch.BATCH_PORTS

# The TLS ports named in one batch. `prober_cli.KNOWN_TLS_PORTS` is seven.
MAX_TLS_PORTS = 64

# A port that is not a number still travels, because the engine records it as
# not tested with a typed reason (prober.normalise_ports). It cannot be long.
MAX_PORT_TEXT = 16

# How long a batch and its answer may sit here. The same fifteen minutes
# `dispatch.SshTransport` waits for a runner, so an instance has given up on a
# batch by the time it goes.
BATCH_TTL_SECONDS = 15 * 60

# The abuse log. Thirty days, the default accepted on 2026-09-30
# (docs/RECORD.md 4.217). Longer is the owner's call.
LOG_RETENTION_SECONDS = 30 * 24 * 60 * 60

# What one instance may spend in any hour, accepted the same day. Worked from
# a large beta instance: 20 servers x 30 ports x 2 families x 2 vantages x 7
# passes an hour (six fast, one hourly) is 16,800, and the rest is Scan now.
CONNECTS_PER_HOUR = 30_000
PACE_WINDOW_SECONDS = 60 * 60

# How many seconds of a prober's lock one instance's batches may hold in any
# hour, the one pass lock until the finer locks of 28 October (phase 1 of
# docs/SPEC-probe-locks.md). A sixth of the hour, set from the synthetic run
# of 27 October (ops/locksim.py, docs/PRODUCT.md 5g): about what an instance
# of five servers of thirty ports holds, and it bounded an instance sending
# the longest batch nonstop to its cap and one batch past it.
LOCK_SECONDS_PER_HOUR = 600

# The proofs an instance may start and read in any hour, and how often one
# challenge may be read. Since the open signup a stranger holds an API key,
# and a start writes a row and a verify makes our side read a DNS record or
# a file at an address the instance names. Worked from an honest instance:
# forty addresses proved in an hour, each started once and verified a few
# times while its record or file is published, fits with room left. Every
# instance is held to them, invited or signed up (docs/PRODUCT.md 5g).
PROOF_STARTS_PER_HOUR = 60
PROOF_VERIFIES_PER_HOUR = 240
PROOF_VERIFY_SPACING_SECONDS = 5

PROOF_START = "start"
PROOF_VERIFY = "verify"

# Every refusal the API gives, and its HTTP status. Closed: a test holds it.
ERRORS = {
    "unknown_key": 401,
    "malformed_request": 400,
    "unsupported_version": 400,
    "too_large": 413,
    "unknown_vantage": 404,
    "names_a_vantage_address": 400,
    "target_refused": 400,
    "batch_in_flight": 409,
    "over_instance_pace": 429,
    "unknown_batch": 404,
    "unknown_challenge": 404,
}

# What a batch that was taken but not measured says instead of an answer.
FAILURES = frozenset({
    # ssh could not reach the vantage, or it is no longer in our registry
    "vantage_unreachable",
    # the runner refused the batch
    "prober_refused",
    # the runner answered with something that is not a measurement
    "prober_answer_unreadable",
    # the registry changed under a queued batch and one of its addresses is
    # now ours
    "names_a_vantage_address",
    # the worker stopped while it ran, and whether the prober answered is not
    # known, so nothing is handed back as a measurement
    "interrupted",
})

STATE_QUEUED = "queued"
STATE_RUNNING = "running"
STATE_DONE = "done"
STATE_FAILED = "failed"

SCHEMA = """
CREATE TABLE IF NOT EXISTS prober_api_batches (
    id           TEXT PRIMARY KEY,
    instance_id  INTEGER NOT NULL,
    vantage      TEXT NOT NULL,
    request      TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    answer       TEXT,
    failure      TEXT
);

CREATE INDEX IF NOT EXISTS idx_prober_api_batches_instance
    ON prober_api_batches(instance_id, finished_at);

CREATE TABLE IF NOT EXISTS prober_api_charges (
    id           INTEGER PRIMARY KEY,
    instance_id  INTEGER NOT NULL,
    connects     INTEGER NOT NULL,
    submitted_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_prober_api_charges_instance
    ON prober_api_charges(instance_id, submitted_at);

CREATE TABLE IF NOT EXISTS prober_api_log (
    instance_id  INTEGER NOT NULL,
    vantage      TEXT NOT NULL,
    target       TEXT NOT NULL,
    day          TEXT NOT NULL,
    first_at     TEXT NOT NULL,
    last_at      TEXT NOT NULL,
    batches      INTEGER NOT NULL,
    connects     INTEGER NOT NULL,
    PRIMARY KEY (instance_id, vantage, target, day)
);

CREATE INDEX IF NOT EXISTS idx_prober_api_log_target
    ON prober_api_log(target, day);

-- One row per proof an instance started or read, kept for the hour the
-- pace reads it. `challenge_id` is the challenge a verify read, so one
-- challenge is read at most once every few seconds.
CREATE TABLE IF NOT EXISTS prober_api_proof_uses (
    id           INTEGER PRIMARY KEY,
    instance_id  INTEGER NOT NULL,
    action       TEXT NOT NULL,
    challenge_id INTEGER,
    used_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_prober_api_proof_uses_instance
    ON prober_api_proof_uses(instance_id, action, used_at);
"""


class Refused(Exception):
    """A request the API will not take, as one class from `ERRORS`."""

    def __init__(self, error: str, retry_after: int | None = None):
        if error not in ERRORS:
            raise ValueError(f"{error!r} is not an error class")
        super().__init__(error)
        self.error = error
        self.status = ERRORS[error]
        self.retry_after = retry_after


# Columns added to the charges after first release, the way `db.init` adds
# one: SQLite has no ADD COLUMN IF NOT EXISTS, so the duplicate-column error
# is the idempotence check. A row written before them has no batch and held
# the lock for none of its seconds, which is what the defaults say.
ADDED_CHARGE_COLUMNS = (
    "batch_id TEXT",
    "lock_seconds REAL NOT NULL DEFAULT 0",
)


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    for column in ADDED_CHARGE_COLUMNS:
        try:
            con.execute(f"ALTER TABLE prober_api_charges ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    con.commit()


def stamp(moment: datetime) -> str:
    """Every time this module writes, in one fixed-width spelling.

    Fixed width because the sweep and the pace compare these as text, and two
    spellings of one instant, with and without microseconds, would sort by
    accident rather than by construction.
    """
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds")


# --------------------------------------------------------------- the request

@dataclasses.dataclass(frozen=True)
class BatchRequest:
    """A batch as the API accepted it. `allowed` is the canonical targets the
    instance's own snapshot allowed, which is all that is read out of it."""
    vantage: str
    addresses: tuple
    ports: tuple
    tls_ports: tuple
    allowed: tuple

    def per_address(self) -> int:
        """The most one address in this batch can receive, in connects. A
        certificate is read only on a port that is also probed."""
        numbered = {p for p in self.ports
                    if isinstance(p, int) and not isinstance(p, bool)}
        return len(self.ports) + len(numbered & set(self.tls_ports))

    def charge(self) -> int:
        """The most this batch can cost in connects, which is what is charged."""
        return len(self.addresses) * self.per_address()

    def to_json(self) -> str:
        return json.dumps({"vantage": self.vantage,
                           "addresses": list(self.addresses),
                           "ports": list(self.ports),
                           "tls_ports": list(self.tls_ports),
                           "allowed": list(self.allowed)})

    @classmethod
    def from_json(cls, text: str) -> "BatchRequest":
        data = json.loads(text)
        return cls(data["vantage"], tuple(data["addresses"]), tuple(data["ports"]),
                   tuple(data["tls_ports"]), tuple(data["allowed"]))


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def parse_batch(payload, enabled_vantages, vantage_addresses) -> BatchRequest:
    """The batch `dispatch.build_batch` makes, checked, or `Refused`.

    `enabled_vantages` is the names an instance may ask for and
    `vantage_addresses` every address of every vantage, enabled or not,
    because a vantage never probes itself and never another vantage
    (`app/vantages.py`). Nothing defaults: a field that is missing or the
    wrong shape is a refusal, never an empty list.
    """
    if not isinstance(payload, dict):
        raise Refused("malformed_request")
    if payload.get("version") != dispatch.BATCH_VERSION:
        raise Refused("unsupported_version")

    vantage = payload.get("vantage")
    if not isinstance(vantage, str):
        raise Refused("malformed_request")
    if vantage not in enabled_vantages:
        raise Refused("unknown_vantage")

    addresses = payload.get("addresses")
    if (not isinstance(addresses, list) or not addresses
            or len(addresses) > MAX_ADDRESSES):
        raise Refused("malformed_request")
    for address in addresses:
        if not isinstance(address, str) or len(address) > prober.MAX_TARGET_TEXT:
            raise Refused("malformed_request")
        try:
            canonical, _family = authz.normalise_target(address)
        except authz.TargetError:
            # Not an address at all. It travels, and the engine records it as
            # not tested with its own reason, the same as on an ssh pass.
            continue
        if canonical in vantage_addresses:
            raise Refused("names_a_vantage_address")

    ports = payload.get("ports")
    if not isinstance(ports, list) or len(ports) > MAX_PORTS:
        raise Refused("malformed_request")
    for port in ports:
        if not (_is_int(port) or (isinstance(port, str)
                                  and len(port) <= MAX_PORT_TEXT)):
            raise Refused("malformed_request")

    tls_ports = payload.get("tls_ports")
    if not isinstance(tls_ports, list) or len(tls_ports) > MAX_TLS_PORTS:
        raise Refused("malformed_request")
    for port in tls_ports:
        if not _is_int(port) or not prober.MIN_PORT <= port <= prober.MAX_PORT:
            raise Refused("malformed_request")

    try:
        theirs = authz.snapshot_from_json(payload.get("snapshot"))
    except authz.SnapshotUnreadable:
        raise Refused("malformed_request") from None

    return BatchRequest(vantage=vantage, addresses=tuple(addresses),
                        ports=tuple(ports), tls_ports=tuple(tls_ports),
                        allowed=tuple(sorted(theirs.targets)))


# ------------------------------------------------------------------ the queue

def new_batch_id() -> str:
    """Unguessable, so a batch id is not a number another instance could walk.
    The instance check in `fetch` is what actually refuses, this only means
    there is nothing to walk."""
    return secrets.token_urlsafe(24)


def _charged_in_window(con, instance_id: int, now: datetime) -> list:
    """(submitted_at, connects) for this instance's batches in the last hour,
    oldest first."""
    cutoff = stamp(now - timedelta(seconds=PACE_WINDOW_SECONDS))
    return [(row["submitted_at"], row["connects"]) for row in con.execute(
        "SELECT submitted_at, connects FROM prober_api_charges"
        " WHERE instance_id = ? AND submitted_at > ? ORDER BY submitted_at",
        (instance_id, cutoff))]


def lock_seconds_spent(con: sqlite3.Connection, instance_id: int,
                       now: datetime) -> float:
    """The seconds this instance's batches held their prober's lock, of the batches
    it queued in the last hour."""
    return sum(seconds for _, seconds in _lock_in_window(con, instance_id, now))


def _lock_in_window(con, instance_id: int, now: datetime) -> list:
    """(submitted_at, lock_seconds) for this instance's batches in the last
    hour that held the lock at all, oldest first."""
    cutoff = stamp(now - timedelta(seconds=PACE_WINDOW_SECONDS))
    return [(row[0], row[1]) for row in con.execute(
        "SELECT submitted_at, lock_seconds FROM prober_api_charges"
        " WHERE instance_id = ? AND submitted_at > ? AND lock_seconds > 0"
        " ORDER BY submitted_at", (instance_id, cutoff))]


def _seconds_until_lock_room(held: list, now: datetime) -> int:
    """How long until enough of the last hour's seconds have aged out for the
    instance to be under its cap again. Whole seconds, at least one."""
    spent = sum(seconds for _, seconds in held)
    for submitted_at, seconds in held:
        spent -= seconds
        if spent < LOCK_SECONDS_PER_HOUR:
            frees = datetime.fromisoformat(submitted_at) + timedelta(
                seconds=PACE_WINDOW_SECONDS)
            return max(1, int((frees - now).total_seconds()) + 1)
    return PACE_WINDOW_SECONDS


def charge_lock_seconds(con: sqlite3.Connection, batch_id: str,
                        seconds: float) -> bool:
    """Write how long a batch held its prober's lock on its charge row. Called by
    the worker once the batch has run. It sets the number rather than adding
    to it, so a batch is never charged twice, and less than nothing is
    nothing. False when no charge row names this batch: it was queued before
    the rows named their batch, or the hour has swept it."""
    held = max(0.0, float(seconds))
    changed = con.execute(
        "UPDATE prober_api_charges SET lock_seconds = ? WHERE batch_id = ?",
        (held, batch_id)).rowcount
    con.commit()
    return changed == 1


def charge_proof(con: sqlite3.Connection, instance_id: int, action: str,
                 now: datetime, challenge_id: int | None = None) -> None:
    """Count one proof start or one read against this instance, or refuse it
    as `over_instance_pace` with a Retry-After. Called before the start or
    the read happens, so a refused one does nothing at all. The check and
    the row are one write transaction, as in `submit`, so a burst of
    requests from one instance cannot all find room."""
    if action not in (PROOF_START, PROOF_VERIFY):
        raise ValueError(f"{action!r} is not a proof action")
    cap = PROOF_STARTS_PER_HOUR if action == PROOF_START else PROOF_VERIFIES_PER_HOUR
    sweep(con, now)
    con.execute("BEGIN IMMEDIATE")
    try:
        used = [row[0] for row in con.execute(
            "SELECT used_at FROM prober_api_proof_uses"
            " WHERE instance_id = ? AND action = ? AND used_at > ?"
            " ORDER BY used_at",
            (instance_id, action,
             stamp(now - timedelta(seconds=PACE_WINDOW_SECONDS))))]
        if len(used) >= cap:
            # Room comes back when the oldest that keeps it full is an hour old.
            frees = datetime.fromisoformat(used[len(used) - cap]) + timedelta(
                seconds=PACE_WINDOW_SECONDS)
            raise Refused("over_instance_pace",
                          retry_after=max(1, int((frees - now).total_seconds()) + 1))
        if action == PROOF_VERIFY:
            last = con.execute(
                "SELECT MAX(used_at) FROM prober_api_proof_uses"
                " WHERE instance_id = ? AND action = ? AND challenge_id = ?",
                (instance_id, action, challenge_id)).fetchone()[0]
            if last is not None:
                waited = (now - datetime.fromisoformat(last)).total_seconds()
                if waited < PROOF_VERIFY_SPACING_SECONDS:
                    raise Refused("over_instance_pace", retry_after=max(
                        1, math.ceil(PROOF_VERIFY_SPACING_SECONDS - waited)))
        con.execute(
            "INSERT INTO prober_api_proof_uses (instance_id, action, challenge_id,"
            " used_at) VALUES (?, ?, ?, ?)",
            (instance_id, action, challenge_id, stamp(now)))
    except BaseException:
        con.rollback()
        raise
    con.commit()


def _seconds_until_room(charged: list, charge: int, now: datetime) -> int:
    """How long until enough of the last hour's charge has aged out for this
    batch to fit. Whole seconds, at least one, for a Retry-After header."""
    spent = sum(connects for _, connects in charged)
    for submitted_at, connects in charged:
        spent -= connects
        if spent + charge <= CONNECTS_PER_HOUR:
            frees = datetime.fromisoformat(submitted_at) + timedelta(
                seconds=PACE_WINDOW_SECONDS)
            return max(1, int((frees - now).total_seconds()) + 1)
    return PACE_WINDOW_SECONDS


def submit(con: sqlite3.Connection, instance_id: int, request: BatchRequest,
           now: datetime) -> str:
    """Queue one batch for this instance and charge it. Returns its id.

    The check and the insert are one write transaction, `BEGIN IMMEDIATE`, so
    two requests from one instance arriving together cannot both find the
    queue empty. SQLite takes the write lock at BEGIN and the other waits.
    """
    sweep(con, now)
    charge = request.charge()
    con.execute("BEGIN IMMEDIATE")
    try:
        busy = con.execute(
            "SELECT 1 FROM prober_api_batches"
            " WHERE instance_id = ? AND finished_at IS NULL LIMIT 1",
            (instance_id,)).fetchone()
        if busy is not None:
            raise Refused("batch_in_flight")
        charged = _charged_in_window(con, instance_id, now)
        if sum(c for _, c in charged) + charge > CONNECTS_PER_HOUR:
            raise Refused("over_instance_pace",
                          retry_after=_seconds_until_room(charged, charge, now))
        # The seconds are known only after a batch ran, so what is checked is
        # what the last hour's batches already held.
        held = _lock_in_window(con, instance_id, now)
        if sum(seconds for _, seconds in held) >= LOCK_SECONDS_PER_HOUR:
            raise Refused("over_instance_pace",
                          retry_after=_seconds_until_lock_room(held, now))
        batch_id = new_batch_id()
        con.execute(
            "INSERT INTO prober_api_charges (instance_id, connects, submitted_at,"
            " batch_id) VALUES (?, ?, ?, ?)",
            (instance_id, charge, stamp(now), batch_id))
        con.execute(
            "INSERT INTO prober_api_batches (id, instance_id, vantage, request,"
            " submitted_at) VALUES (?, ?, ?, ?, ?)",
            (batch_id, instance_id, request.vantage, request.to_json(),
             stamp(now)))
    except BaseException:
        con.rollback()
        raise
    con.commit()
    return batch_id


def fetch(con: sqlite3.Connection, instance_id: int, batch_id,
          now: datetime) -> dict:
    """The state of one of this instance's batches, and its answer once there
    is one. A finished batch is deleted as it is handed over, so an answer is
    kept here exactly as long as it takes to be collected.

    Another instance's batch, an expired one, a collected one and one that
    never existed all raise the same `unknown_batch`.
    """
    sweep(con, now)
    if not isinstance(batch_id, str) or not batch_id or len(batch_id) > 64:
        raise Refused("unknown_batch")
    row = con.execute(
        "SELECT * FROM prober_api_batches WHERE id = ? AND instance_id = ?",
        (batch_id, instance_id)).fetchone()
    if row is None:
        raise Refused("unknown_batch")
    if row["finished_at"] is None:
        return {"state": STATE_RUNNING if row["started_at"] else STATE_QUEUED}
    con.execute("DELETE FROM prober_api_batches WHERE id = ?", (batch_id,))
    con.commit()
    if row["failure"]:
        return {"state": STATE_FAILED, "error": row["failure"]}
    return {"state": STATE_DONE, "answer": json.loads(row["answer"])}


def sweep(con: sqlite3.Connection, now: datetime) -> dict:
    """Forget what has outlived its purpose. Run by every submit, every fetch
    and every turn of the worker, so no timer has to exist for it and a
    stopped worker cannot make batches outlive their limit for long."""
    batches = con.execute(
        "DELETE FROM prober_api_batches WHERE submitted_at < ?",
        (stamp(now - timedelta(seconds=BATCH_TTL_SECONDS)),)).rowcount
    charges = con.execute(
        "DELETE FROM prober_api_charges WHERE submitted_at < ?",
        (stamp(now - timedelta(seconds=PACE_WINDOW_SECONDS)),)).rowcount
    logged = con.execute(
        "DELETE FROM prober_api_log WHERE last_at < ?",
        (stamp(now - timedelta(seconds=LOG_RETENTION_SECONDS)),)).rowcount
    proof_uses = con.execute(
        "DELETE FROM prober_api_proof_uses WHERE used_at < ?",
        (stamp(now - timedelta(seconds=PACE_WINDOW_SECONDS)),)).rowcount
    con.commit()
    return {"batches": batches, "charges": charges, "log": logged,
            "proof_uses": proof_uses}


# ---------------------------------------------------------- the worker's half

def next_queued(con: sqlite3.Connection, now: datetime, vantage: str | None = None,
                skip=()) -> sqlite3.Row | None:
    """The oldest batch nobody has started, if it is still inside its limit.
    Oldest first across every instance, and an instance has at most one, so
    this is round robin without having to be written as one.

    `vantage` narrows it to one prober's batches, for the worker's thread of
    that prober. `skip` passes over batches that thread could not start in
    this round because one of their addresses was busy, so the next one gets
    its turn and they wait for the next round."""
    sql = ("SELECT * FROM prober_api_batches WHERE started_at IS NULL"
           " AND finished_at IS NULL AND submitted_at >= ?")
    params = [stamp(now - timedelta(seconds=BATCH_TTL_SECONDS))]
    if vantage is not None:
        sql += " AND vantage = ?"
        params.append(vantage)
    skipped = sorted(skip)
    if skipped:
        sql += f" AND id NOT IN ({', '.join('?' for _ in skipped)})"
        params.extend(skipped)
    return con.execute(sql + " ORDER BY submitted_at, id LIMIT 1", params).fetchone()


def queued_for_others(con: sqlite3.Connection, vantages, now: datetime) -> list:
    """The batches nobody has started whose vantage is none of `vantages`,
    the names in our registry. A vantage taken out of the registry after
    they were queued has no thread of the worker to serve it."""
    names = sorted(vantages)
    sql = ("SELECT * FROM prober_api_batches WHERE started_at IS NULL"
           " AND finished_at IS NULL AND submitted_at >= ?")
    params = [stamp(now - timedelta(seconds=BATCH_TTL_SECONDS))]
    if names:
        sql += f" AND vantage NOT IN ({', '.join('?' for _ in names)})"
        params.extend(names)
    return con.execute(sql + " ORDER BY submitted_at, id", params).fetchall()


def mark_started(con: sqlite3.Connection, batch_id: str, now: datetime) -> bool:
    """Claim a batch. False when it is gone or already claimed, so two workers
    that somehow both run never both drive one batch."""
    claimed = con.execute(
        "UPDATE prober_api_batches SET started_at = ?"
        " WHERE id = ? AND started_at IS NULL", (stamp(now), batch_id)).rowcount
    con.commit()
    return claimed == 1


def record_answer(con: sqlite3.Connection, row, answer: str,
                  now: datetime) -> None:
    """The runner's answer, verbatim, until the instance collects it."""
    con.execute(
        "UPDATE prober_api_batches SET answer = ?, finished_at = ? WHERE id = ?",
        (answer, stamp(now), row["id"]))
    con.commit()


def record_failure(con: sqlite3.Connection, row, failure: str,
                   now: datetime) -> None:
    if failure not in FAILURES:
        raise ValueError(f"{failure!r} is not a failure class")
    con.execute(
        "UPDATE prober_api_batches SET failure = ?, finished_at = ? WHERE id = ?",
        (failure, stamp(now), row["id"]))
    con.commit()


def fail_interrupted(con: sqlite3.Connection, now: datetime) -> int:
    """Close every batch that was started and never finished. Called once when
    the worker starts, and only once it holds its life lock
    (`proberapi_worker.WorkerLock`): there is one worker, so a batch it did
    not finish was cut off by its last stop, and leaving it open would hold
    that instance's one slot for the rest of the fifteen minutes."""
    closed = con.execute(
        "UPDATE prober_api_batches SET failure = 'interrupted', finished_at = ?"
        " WHERE started_at IS NOT NULL AND finished_at IS NULL",
        (stamp(now),)).rowcount
    con.commit()
    return closed


def drop(con: sqlite3.Connection, row) -> None:
    """A batch that will never run, because its instance was revoked."""
    con.execute("DELETE FROM prober_api_batches WHERE id = ?", (row["id"],))
    con.commit()


def log_sent(con: sqlite3.Connection, instance_id: int, vantage: str, targets,
             per_target: int, now: datetime) -> None:
    """Write down that a batch which could reach these addresses went to the
    prober. Called before the batch is sent, not after it answers, so a batch
    whose answer never came back is still in the log: an abuse report does not
    care whether we collected the result.

    `targets` is the addresses in the snapshot, the only ones the runner will
    connect to. One row per address and day, counted up.
    """
    moment = stamp(now)
    day = moment[:10]
    for target in sorted(set(targets)):
        con.execute(
            "INSERT INTO prober_api_log (instance_id, vantage, target, day,"
            " first_at, last_at, batches, connects) VALUES (?, ?, ?, ?, ?, ?, 1, ?)"
            " ON CONFLICT (instance_id, vantage, target, day) DO UPDATE SET"
            " last_at = excluded.last_at, batches = batches + 1,"
            " connects = connects + excluded.connects",
            (instance_id, vantage, target, day, moment, moment, per_target))
    con.commit()


def log_for_target(con: sqlite3.Connection, address: str) -> list[sqlite3.Row]:
    """Every day an instance's batch could reach this address, newest first,
    with the instance's name, for answering an abuse report."""
    canonical, _family = authz.normalise_target(address)
    return con.execute(
        "SELECT l.*, i.name AS instance_name FROM prober_api_log l"
        " LEFT JOIN probe_instances i ON i.id = l.instance_id"
        " WHERE l.target = ? ORDER BY l.day DESC, l.vantage",
        (canonical,)).fetchall()
