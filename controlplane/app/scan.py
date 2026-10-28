"""On-demand outside re-probe of one host's joined port set: recording the
request, rate limiting it durably, and handing the responder its work.

The owner's decision, 2026-08-22 (docs/PRODUCT.md 5f): the host page carries a
"Scan now" that re-probes from outside immediately. It is host page only,
secondary weight, rate limited per host, and it refuses with a sentence when it
is asked too soon.

**It cannot refresh the inside view.** SI-2 forbids any command channel to the
agent, so nothing here reaches the box. The inside view is refreshed by the
operator running the agent once by hand, and the endpoint returns that command
as a string for them to run. Nothing is sent to any agent.

## Why the rate limit lives in a table and not in memory

`app/ratelimit.py` holds the login buckets in this process's memory, and its own
docstring says a restart forgets every bucket. That is fine for a password form
that refills in a minute. It is wrong here: "you just scanned, wait two minutes"
has to survive an ingest restart, or a restart becomes a way to scan as often as
the process can be bounced. So the limit is the most recent `requested_at` for
the host, read from the table every time rather than kept in memory.

## The request is only half the feature

The internet-facing ingest records the request and touches a trigger file. It
never probes, because probing happens on the vantage host and the ingest has no
channel to it and must never get one (app/dispatch.py, the direction of trust).
`app/scan_cli.py drain`, run on the box that does hold that channel, reads the
pending requests and probes them.
"""

import dataclasses
import math
import os
import sqlite3
from datetime import datetime, timezone

from . import db

# Two minutes between scans of one host. This is politeness to the target and to
# the prober, not a cost guard: a scan is a handful of connects. It is durable
# (read from the table below) rather than a bucket a restart would forget, and
# the owner can tune it.
SCAN_MIN_INTERVAL_SECONDS = 120

# whichports-scan.path watches this file. An accepted request touches it, which
# fires an immediate drain. It sits beside the database, under the directory the
# ingest unit already lists in ReadWritePaths.
TRIGGER_FILENAME = "scan-requested"

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_requests (
    id           INTEGER PRIMARY KEY,
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    requested_at TEXT NOT NULL,
    drained_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_requests_host
    ON scan_requests(host_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_scan_requests_pending
    ON scan_requests(drained_at, requested_at);
"""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init, authz.init and prober.init
    follow. db.init has to have run first, because scan_requests references
    hosts(id)."""
    con.executescript(SCHEMA)
    con.commit()


# ------------------------------------------------------------------- clock

def _as_utc(now: datetime | None) -> datetime:
    """Read the caller's clock as aware UTC. Mirrors authz._as_utc rather than
    importing it, because lifting a shared helper out is its own PR, and a naive datetime slipping into a comparison below would
    raise in the middle of a request."""
    if now is None:
        return datetime.now(timezone.utc)
    return now if now.tzinfo else now.replace(tzinfo=timezone.utc)


def _parse(value) -> datetime | None:
    """A stored ISO timestamp as aware UTC, or None if it cannot be read. The
    same posture authz._parse takes: a row we cannot read must not take a
    decision down."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------- the request

@dataclasses.dataclass(frozen=True)
class ScanRequest:
    """The answer to "may this host be scanned now". `accepted` is the only
    field anything branches on. `retry_after` is whole seconds and is 0 when
    accepted. `sentence` is for a person and says, plainly, what happened."""
    accepted: bool
    retry_after: int
    sentence: str


def request_scan(con: sqlite3.Connection, host_id: int | None, now: datetime,
                 min_interval_seconds: int = SCAN_MIN_INTERVAL_SECONDS) -> ScanRequest:
    """Record a scan request for one host, unless it was scanned too recently.

    The limit is durable: the most recent requested_at for this host is read
    from the table, so a restart cannot forget it. `now` is injected so a test
    moves time without sleeping through it.
    """
    now = _as_utc(now)
    if host_id is None:
        # The endpoint resolves the host and 404s an unknown or revoked one
        # before this is reached, so a None host is defence rather than a path a
        # request takes. It cannot be rate limited and must not become a row.
        return ScanRequest(False, 0, "No such host, so there is nothing to scan.")

    row = con.execute(
        "SELECT requested_at FROM scan_requests WHERE host_id = ?"
        " ORDER BY requested_at DESC, id DESC LIMIT 1",
        (host_id,),
    ).fetchone()
    last = _parse(row["requested_at"]) if row is not None else None
    if last is not None:
        elapsed = (now - last).total_seconds()
        if elapsed < min_interval_seconds:
            # Round up, so "about N seconds" never tells a person to try again a
            # moment before the limit has actually cleared.
            retry_after = max(1, math.ceil(min_interval_seconds - elapsed))
            return ScanRequest(
                False, retry_after,
                f"Just scanned. Try again in about {retry_after} seconds.")

    con.execute(
        "INSERT INTO scan_requests (host_id, requested_at) VALUES (?, ?)",
        (host_id, now.isoformat()),
    )
    con.commit()
    return ScanRequest(
        True, 0,
        "Scanning now from outside. The outside view refreshes when the pass"
        " finishes.")


# -------------------------------------------------------------- the drain

def pending_requests(con: sqlite3.Connection) -> list[int]:
    """The host_ids that have at least one un-drained request, oldest request
    first. A host that asked several times in a burst appears once: the drain
    probes it once and clears all of its requests together."""
    rows = con.execute(
        "SELECT host_id, MIN(requested_at) AS first_at FROM scan_requests"
        " WHERE drained_at IS NULL"
        " GROUP BY host_id ORDER BY first_at ASC, host_id ASC"
    ).fetchall()
    return [row["host_id"] for row in rows]


def pending_ids_for_host(con: sqlite3.Connection, host_id: int) -> list[int]:
    """The un-drained request ids for one host, so the drain can clear the whole
    burst once it has measured the host."""
    rows = con.execute(
        "SELECT id FROM scan_requests WHERE host_id = ? AND drained_at IS NULL"
        " ORDER BY id ASC",
        (host_id,),
    ).fetchall()
    return [row["id"] for row in rows]


def mark_drained(con: sqlite3.Connection, request_ids, now: datetime) -> None:
    """Mark these requests handled, so a later drain does not probe for them
    again. Idempotent: a request already drained keeps its first drain time. An
    empty list is a no-op."""
    now = _as_utc(now)
    stamp = now.isoformat()
    con.executemany(
        "UPDATE scan_requests SET drained_at = ?"
        " WHERE id = ? AND drained_at IS NULL",
        [(stamp, request_id) for request_id in request_ids],
    )
    con.commit()


# ------------------------------------------------------------ the trigger

def trigger_path() -> str:
    """The trigger file beside the database. Derived from the database path so
    the ingest and the path unit agree on it without a second setting."""
    directory = os.path.dirname(os.path.abspath(db.db_path()))
    return os.path.join(directory, TRIGGER_FILENAME)


def touch_trigger(path: str) -> None:
    """Modify the trigger file so whichports-scan.path (PathModified=) fires.

    The file's content is not read by anything, the write event is the whole
    point, so this truncates and writes the current time. A person looking at
    the file then sees when a scan was last asked for.

    This must never fail an accepted request: the caller wraps it, because the
    request is already recorded and the next fast-lane pass covers it even if
    this write cannot happen (docs/RUNBOOK.md, the scan units).
    """
    with open(path, "w") as handle:
        handle.write(datetime.now(timezone.utc).isoformat())
