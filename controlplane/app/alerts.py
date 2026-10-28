"""The dead-man switch: a silent agent is itself an alert.

`docs/PRODUCT.md` 4c owns the design and the owner pulled it into scope on
2026-08-13. The reasoning, in one line: a monitoring tool that dies quietly is
worse than none, because the quiet reads as healthy.

The heartbeat costs nothing extra. Every report the timer already sends is
proof of life (PRODUCT.md 4f), so this module never asks an agent for
anything. It reads `hosts.last_report_at` and the clock.

## What the sweep may and may not do

  - **One alert per silence, not one per sweep.** An open alert for a host is
    the de-duplication key. A host silent for a week has one row, not one every
    five minutes.
  - **A paused host never raises.** Pausing means the operator knows it is
    down, so silence is expected rather than a fault. Pausing also closes an
    alert that was already open, instead of leaving a red row behind for
    something the operator has just explained. A paused host shows as paused
    and never as healthy, which is the display half already built.
  - **A revoked host is not monitored at all**, and revoking closes its open
    alert for the same reason. Its credential no longer works, so it cannot
    report by definition and alerting on that is noise.
  - **A host that has never reported never raises.** This alert says an agent
    stopped reporting. A row the add-server flow created and nobody ever
    installed never started, so the sentence would be about something nobody
    measured. Production had nine such rows and two open alerts against them
    when this rule was written. They are reported as pending instead, and an
    alert an older build raised against one is retracted, because only a
    report resolves an alert and that host will never send one.
  - **Closed is not the same as resolved.** Resolved means the host started
    reporting again. Closed means it stopped being watched. They are separate
    lists in the result because printing one as the other had the sweep
    announcing that a revoked host was reporting again.
  - **Our own outage never becomes their alert.** This is the guard an
    earlier project of the author's learned the hard way, in July 2026, after
    a redeploy fired one alert per server and every one resolved a minute later.
    If the gap since the last sweep is longer than the silence threshold, the
    control plane itself was down, so every agent looks silent through no
    fault of its own.

    **The guard delays a detection, it does not cancel one.** It works by
    measuring silence from the moment we could see again rather than from the
    host's last report, so a genuinely dead agent crosses the threshold one
    window after our recovery and is raised then. Only a *detected gap* moves
    that moment: a first-ever sweep does not, because a fresh database has
    nothing to be wrong about yet.

    The first version of this used a "hold new alerts until a deadline" flag
    instead, and a test caught it re-arming its own deadline every sweep, which
    turned "delay" into "never". Measuring from the recovery point has no
    deadline to re-arm and is why it is written this way.

    **The one case it genuinely cannot cover**, stated rather than hidden: a
    sweeper that never stays up for a whole silence window cannot make the
    observation at all, because it is blind for longer than the thing it is
    looking for. That is a fault in this control plane rather than in any
    agent, and `sweep_cli` prints it on every sweep that detects a gap.
"""

import logging
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

from . import notify

log = logging.getLogger("whichports.alerts")

# The packaged agent timer runs every 15 minutes, so a host that is well has
# answered twice inside this window. Two ticks of slack rather than one,
# because a single missed run is a retry, not an outage.
#
# THIS IS THE OWNING DEFINITION of the silence threshold. site/app/render_live.py
# carries the same number for the display half and a test in this suite fails if
# the two ever disagree, because a dashboard that says silent while the sweep
# says fine is worse than either answer alone.
SILENT_AFTER_SECONDS = 35 * 60

# Resolving needs a tighter bound than raising, or a host hovering at the
# threshold raises and resolves on alternate sweeps. It has to have genuinely
# reported again, which on a 15 minute timer means inside one interval.
ONLINE_WITHIN_SECONDS = 20 * 60

# A gap longer than the silence threshold means the sweeper did not run, which
# at this scale means the control plane was down. Sized at the threshold on
# purpose: a shorter gap cannot have made any host cross it, so no false
# positive was possible and no grace is needed.
SWEEP_RECOVERY_GAP_SECONDS = SILENT_AFTER_SECONDS

KIND_SILENT = "silent"

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL,
    raised_at   TEXT NOT NULL,
    resolved_at TEXT,
    notified_at TEXT,
    subject     TEXT,
    suppressed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_open ON alerts(host_id, kind, resolved_at);

-- Delivery on every channel that is not email.
--
-- **Email keeps `alerts.notified_at` and this table does not duplicate it.**
-- That column means one exact thing, that a relay accepted the message, and
-- two screens say "mailed" in those words from it (`site/app/render_live.py`).
-- Writing an email row here as well would put one fact in two places, which is
-- the drift of one fact kept in two places. So email is recorded there,
-- every other channel is recorded here, and neither is a copy of the other.
--
-- One row per alert per channel, because the question this answers is per
-- channel: a mail that was accepted beside a webhook that timed out has to
-- leave the webhook retryable without sending the mail twice.
CREATE TABLE IF NOT EXISTS alert_deliveries (
    id           INTEGER PRIMARY KEY,
    alert_id     INTEGER NOT NULL REFERENCES alerts(id),
    channel      TEXT NOT NULL,
    delivered_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_deliveries_once
    ON alert_deliveries(alert_id, channel);

-- A channel that accepted the message that an agent stopped reporting.
--
-- **Written beside the send and nowhere else** (`log_sent`), so a row is a
-- message that went out. `alert_deliveries` cannot say that: it also holds
-- an alert a channel let go because it does not take the kind. This is what
-- says who is told when the agent reports again (`app/reportingagain.py`):
-- the channels that heard it stop, and no others.
--
-- `again_at` is when that was settled for this channel, told or let go, so
-- it is asked once.
CREATE TABLE IF NOT EXISTS silence_told (
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    channel  TEXT NOT NULL,
    told_at  TEXT NOT NULL,
    again_at TEXT,
    PRIMARY KEY (alert_id, channel)
);

CREATE TABLE IF NOT EXISTS sweep_state (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    last_sweep_at TEXT,
    recovered_at  TEXT
);

-- What went out, one row per message a channel accepted. The Sent list and
-- each destination's Sent number read this table and nothing else.
--
-- **It names the server as text and links to nothing**, so deleting a server
-- cannot take it along. The two tables above hang off the host, and a Delete
-- empties them for that host (`store.HOST_TABLES`), which sent a workspace's
-- Sent count back to 0 with every server it deleted (docs/RECORD.md 4.228).
-- What went out is a log of what this product did, not a fact about the
-- server, and it stays after the server is gone (the owner, 2026-10-03,
-- docs/PRODUCT.md 4f).
--
-- **It is not kept for ever.** A row older than `SENT_LOG_DAYS` is dropped
-- by the sweep, which is the longest range the Sent list offers, so a
-- deleted server's name and the words of its alerts are stored for that
-- long and no longer.
--
-- `channel` is the delivery key of the two tables above, or the plain word
-- `email` for the environment's single recipient, who has no row.
CREATE TABLE IF NOT EXISTS sent_log (
    id           INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    host_name    TEXT NOT NULL,
    detail       TEXT NOT NULL,
    channel      TEXT NOT NULL,
    sent_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sent_log_when ON sent_log(workspace_id, sent_at);

-- An email destination the relay is refusing, for the Fleet's banner
-- (docs/screens/fleet/SPEC.md section 1, the second big test's finding E22).
-- One row per destination while the relay refuses it: written when the relay
-- refuses a mail to it, and deleted when the relay takes one (`note_mail_answer`).
--
-- `channel` is the delivery key, a digest of the address and never the
-- address. `error` is the class of the refusal, one of `notify.RELAY_REFUSALS`,
-- and never the relay's own words (SI-8). `refused_at` is when this run of
-- refusals began, so a banner a person dismissed stays dismissed while they
-- go on, and a new run after a mail was taken shows again.
CREATE TABLE IF NOT EXISTS mail_refusals (
    workspace_id INTEGER NOT NULL,
    channel      TEXT NOT NULL,
    error        TEXT NOT NULL,
    refused_at   TEXT NOT NULL,
    PRIMARY KEY (workspace_id, channel)
);
"""

# How long a line stays in `sent_log`. The Sent list's longest range is 30
# days (`SENT_RANGES` in site/app/build.py), and a test there holds the two
# numbers together.
SENT_LOG_DAYS = 30

# The channel a mail to the environment's single recipient is logged under.
# A stored email channel is logged under its own key, like every other.
SENT_BY_ENVIRONMENT_MAIL = "email"

# Columns added after this table first shipped. Production has an alerts table
# without them, so they are ALTERed in the way db.init does it: SQLite has no
# ADD COLUMN IF NOT EXISTS, so the duplicate-column error is the idempotence
# check.
#
#   subject       which thing inside a kind the alert is about. NULL for the
#                 dead-man switch, which has one stream per host, and the port
#                 for a finding alert, which has one per port and family.
#   suppressed_at recorded and deliberately not mailed. Different from
#                 notified_at, which claims a relay accepted the message, and
#                 different from resolved_at, which claims the condition ended.
LATER_COLUMNS = ("subject TEXT", "suppressed_at TEXT")


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init follows."""
    # Asked before the schema runs: the log is filled from the older tables
    # on the one run that creates it, and never again.
    log_is_new = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sent_log'"
    ).fetchone() is None
    con.executescript(SCHEMA)
    for column in LATER_COLUMNS:
        try:
            con.execute(f"ALTER TABLE alerts ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    con.execute("INSERT OR IGNORE INTO sweep_state (id, last_sweep_at, recovered_at)"
                " VALUES (1, NULL, NULL)")
    if log_is_new:
        fill_sent_log(con)
    con.commit()


# A stored email channel's delivery key starts with its type and a colon
# (`channel_key`). Spelled as a length for SQLite's substr.
_EMAIL_KEY_START = "email:"


def fill_sent_log(con: sqlite3.Connection) -> int:
    """Copy what the two older tables say went out into `sent_log`. Returns
    how many lines it wrote.

    Run once, by `init`, on the run that creates the table. Without it every
    workspace's Sent list would read empty after the upgrade, which is the
    fault the table exists to end, from the other side.

    **It writes nothing when the log already holds a line**, so two
    processes that both saw no table cannot fill it twice: the second one's
    statement runs after the first one's and finds rows.

    **One mail is one line.** Mail was `alerts.notified_at`, and since mail
    became a stored channel (docs/RECORD.md 4.186) such a channel's mail is
    a row in `alert_deliveries` as well. Reading both listed one mail twice
    (4.228). So the column is copied only for an alert no stored email
    channel has a row for, which is a mail the environment's recipient got.

    A delivery row the sweep wrote for a kind the channel does not take
    cannot be told from a real one, so those few are copied as sent. Nothing
    written after this run can be one, see `log_sent`.
    """
    written = con.execute(
        "INSERT INTO sent_log (workspace_id, host_name, detail, channel, sent_at)"
        " SELECT h.workspace_id, h.name, a.detail, ?, a.notified_at"
        "   FROM alerts a JOIN hosts h ON h.id = a.host_id"
        "  WHERE a.notified_at IS NOT NULL"
        "    AND NOT EXISTS (SELECT 1 FROM alert_deliveries d"
        "                     WHERE d.alert_id = a.id"
        "                       AND substr(d.channel, 1, ?) = ?)"
        "    AND NOT EXISTS (SELECT 1 FROM sent_log)"
        " UNION ALL"
        " SELECT h.workspace_id, h.name, a.detail, d.channel, d.delivered_at"
        "   FROM alert_deliveries d JOIN alerts a ON a.id = d.alert_id"
        "   JOIN hosts h ON h.id = a.host_id"
        "  WHERE NOT EXISTS (SELECT 1 FROM sent_log)",
        (SENT_BY_ENVIRONMENT_MAIL, len(_EMAIL_KEY_START), _EMAIL_KEY_START)).rowcount
    return written


def parse_stamp(value):
    """Timestamps are ISO strings in the database. A row written by an older
    build, or by hand, must not take the sweep down."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    # Rows written before this module existed may lack an offset. Treating a
    # naive stamp as UTC matches how store.now_utc writes them.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# The old name, kept because `tests/test_authz.py` pins this helper against
# `authz._parse` so the two can never drift, and lifting the shared one out is
# its own PR (that test says so itself). New callers use parse_stamp.
_parse = parse_stamp


def open_alert(con: sqlite3.Connection, host_id: int, kind: str, subject: str | None = None):
    """The open alert for one host, kind and subject, or None.

    SQL NULL is never equal to anything, not even to NULL, so a NULL subject
    has to be matched with IS NULL and the branch is spelled out rather than
    left to a parameter that happens to be None. The earlier project this
    guard came from carries the same comment for the same reason, and
    the cost of getting it wrong is the same here: de-duplication stops
    working quietly and one condition becomes one alert per sweep.
    """
    if subject is None:
        return con.execute(
            "SELECT * FROM alerts WHERE host_id = ? AND kind = ? AND subject IS NULL"
            " AND resolved_at IS NULL ORDER BY id DESC LIMIT 1",
            (host_id, kind)).fetchone()
    return con.execute(
        "SELECT * FROM alerts WHERE host_id = ? AND kind = ? AND subject = ?"
        " AND resolved_at IS NULL ORDER BY id DESC LIMIT 1",
        (host_id, kind, subject)).fetchone()


def raise_alert(con: sqlite3.Connection, host_id: int, kind: str, detail: str,
                now: datetime, subject: str | None = None):
    """Open an alert, or return the existing open one untouched. Returning the
    existing row rather than opening a second is the whole de-duplication
    story, so one silence is one alert however long it lasts."""
    existing = open_alert(con, host_id, kind, subject)
    if existing is not None:
        return existing, False
    cur = con.execute(
        "INSERT INTO alerts (host_id, kind, detail, raised_at, subject)"
        " VALUES (?, ?, ?, ?, ?)",
        (host_id, kind, detail, now.isoformat(), subject))
    return con.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone(), True


def record_notice(con: sqlite3.Connection, host_id: int, kind: str, detail: str,
                  now: datetime, subject: str | None = None):
    """An alert that asks for nothing: raised and resolved in the same moment.

    The owner's decision of 2026-09-27 (`docs/PRODUCT.md` 4c): whether a port
    needs an answer and whether you are told are two questions. A port a rule
    you wrote already answers is told once and asks nothing. So the row is
    born resolved, which keeps it off every list of what is open, out of the
    count beside Alerts and out of a server's header, and it is still a row,
    so the mail it goes out in is stamped on it and the Sent list shows it
    like any other.

    Never de-duplicated against an open alert the way `raise_alert` is. There
    is nothing open to join: the caller resolved this port's previous alert
    first, and a notice is about one moment, not a condition that lasts.
    """
    stamp = now.isoformat()
    cur = con.execute(
        "INSERT INTO alerts (host_id, kind, detail, raised_at, resolved_at, subject)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, kind, detail, stamp, stamp, subject))
    return con.execute("SELECT * FROM alerts WHERE id = ?", (cur.lastrowid,)).fetchone()


def resolve_alert(con: sqlite3.Connection, host_id: int, kind: str, now: datetime) -> bool:
    """Every open alert of this kind for this host, whatever its subject.

    This is what a host leaving the watch needs: revoking closes all of them.
    A caller that means one port wants resolve_subject instead, and the two
    are separate functions rather than one with a sentinel because reading
    `resolve_alert(con, host_id, kind, now)` and guessing which it meant is
    exactly how a de-duplication key goes wrong.
    """
    cur = con.execute(
        "UPDATE alerts SET resolved_at = ? WHERE host_id = ? AND kind = ?"
        " AND resolved_at IS NULL", (now.isoformat(), host_id, kind))
    return cur.rowcount > 0


def resolve_subject(con: sqlite3.Connection, host_id: int, kind: str,
                    subject: str | None, now: datetime) -> bool:
    """One subject's open alert. The NULL branch is spelled out for the same
    reason it is in open_alert."""
    if subject is None:
        cur = con.execute(
            "UPDATE alerts SET resolved_at = ? WHERE host_id = ? AND kind = ?"
            " AND subject IS NULL AND resolved_at IS NULL",
            (now.isoformat(), host_id, kind))
    else:
        cur = con.execute(
            "UPDATE alerts SET resolved_at = ? WHERE host_id = ? AND kind = ?"
            " AND subject = ? AND resolved_at IS NULL",
            (now.isoformat(), host_id, kind, subject))
    return cur.rowcount > 0


def suppress_alert(con: sqlite3.Connection, alert_id: int, now: datetime) -> None:
    """Recorded, and deliberately not mailed. The alert stays open and stays
    on the screen, which is the half of a mute `docs/PRODUCT.md` 4c keeps:
    changes are still recorded, they just do not mail.

    Not spelled as notified_at, because that says a relay accepted the
    message and no relay saw this one.
    """
    con.execute("UPDATE alerts SET suppressed_at = ? WHERE id = ?",
                (now.isoformat(), alert_id))


def recovery_point(con: sqlite3.Connection):
    """When this control plane last came back from its own outage, or None.

    Written by sweep and read by anything else that measures an age against
    our own clock. There is one recovery point rather than one per feature,
    because two would drift and the guard is only worth having if it is the
    same guard everywhere.
    """
    row = con.execute("SELECT recovered_at FROM sweep_state WHERE id = 1").fetchone()
    return parse_stamp(row["recovered_at"]) if row is not None else None


def _sweep_state(con: sqlite3.Connection):
    row = con.execute("SELECT * FROM sweep_state WHERE id = 1").fetchone()
    if row is None:
        con.execute("INSERT INTO sweep_state (id) VALUES (1)")
        row = con.execute("SELECT * FROM sweep_state WHERE id = 1").fetchone()
    return row


def silent_detail(minutes: int) -> str:
    """The sentence stored on a silence alert. `notify.silent_minutes` reads
    the number back out of it for the message, and a test holds the two to
    each other."""
    return (f"no report for {minutes} minutes, "
            f"past the {SILENT_AFTER_SECONDS // 60} minute threshold")


def sweep(con: sqlite3.Connection, now: datetime | None = None) -> dict:
    """One pass over the fleet. Returns what it did, for the caller to log and
    for the tests to assert on.

    The order of the checks below is the order of the rules in this module's
    docstring, deliberately, so the code reads as the policy does.
    """
    now = now or datetime.now(timezone.utc)
    state = _sweep_state(con)

    last_sweep = parse_stamp(state["last_sweep_at"])
    recovered_at = parse_stamp(state["recovered_at"])
    # Only a detected gap moves the recovery point. A first-ever sweep has no
    # baseline and does not, because a database with no history has nothing to
    # be wrong about.
    self_outage = (last_sweep is not None
                   and (now - last_sweep).total_seconds() > SWEEP_RECOVERY_GAP_SECONDS)
    if self_outage:
        recovered_at = now

    # resolved means the host started reporting again. closed means it is no
    # longer monitored, because it was paused or revoked. retracted means an
    # alert should never have been raised. Three different facts, and printing
    # one as another would have the sweep announce that a revoked host "is
    # reporting again", which it is not.
    #
    # pending and unreadable are not alerts. They are the two reasons this
    # sweep declined to measure a host, named so a host it cannot judge is
    # visible in the log rather than silently skipped.
    result = {"raised": [], "resolved": [], "closed": [], "retracted": [], "held": [],
              "pending": [], "unreadable": [], "checked": 0, "self_outage": self_outage}

    for host in con.execute("SELECT * FROM hosts ORDER BY name").fetchall():
        # A revoked credential cannot report, so silence is arithmetic rather
        # than a fault. Revoking also closes an alert that was already open,
        # for the same reason pausing does: leaving a red row behind for
        # something the operator has just decided is not a bug report, it is
        # a thing they will learn to ignore.
        if host["revoked_at"]:
            if resolve_alert(con, host["id"], KIND_SILENT, now):
                result["closed"].append(host["name"])
            continue
        result["checked"] += 1

        # Paused: the operator has said this one is intentionally down.
        if ("paused" in host.keys()) and host["paused"]:
            if resolve_alert(con, host["id"], KIND_SILENT, now):
                result["closed"].append(host["name"])
            continue

        # A host that has never reported has not gone quiet. This alert says an
        # agent stopped reporting, and a row the add-server flow created that
        # nobody ever installed never started, so raising it there states
        # something nobody measured. That is the accuracy rule broken inside
        # the product rather than in prose.
        #
        # It is worth naming what this deliberately gives up: an installer that
        # was run and never worked now raises nothing. That case is a host
        # waiting for its first report, which belongs on the screen the
        # operator is already looking at, not in a mail at three in the morning
        # about a server that does not exist.
        #
        # An alert an older build already raised is retracted here, because
        # only a report resolves an alert and this host will never send one.
        if host["last_report_at"] is None:
            result["pending"].append(host["name"])
            if resolve_alert(con, host["id"], KIND_SILENT, now):
                result["retracted"].append(host["name"])
            continue

        # A stamp that exists and cannot be read is a fault in our own data.
        # Silence cannot be measured from it, and the previous code measured
        # from created_at instead, which put a number nobody observed into the
        # alert text. Named rather than guessed at.
        last = parse_stamp(host["last_report_at"])
        if last is None:
            result["unreadable"].append(host["name"])
            continue
        # This is the self-outage guard, and it is one line on purpose. While
        # the control plane was down it could not have seen a report, so the
        # honest clock starts when it came back rather than at the host's last
        # report. A host that really is dead crosses the threshold one window
        # after recovery and is raised then.
        observed_from = max(last, recovered_at) if recovered_at else last
        age = (now - observed_from).total_seconds()

        if age > SILENT_AFTER_SECONDS:
            detail = silent_detail(int((now - last).total_seconds() // 60))
            _, is_new = raise_alert(con, host["id"], KIND_SILENT, detail, now)
            if is_new:
                result["raised"].append(host["name"])
        elif (now - last).total_seconds() > SILENT_AFTER_SECONDS:
            # Past the threshold on its own clock, but inside the window we
            # have actually been able to watch. Held rather than raised, and
            # named so the log shows the guard working instead of silence.
            result["held"].append(host["name"])
        elif age <= ONLINE_WITHIN_SECONDS:
            if resolve_alert(con, host["id"], KIND_SILENT, now):
                result["resolved"].append(host["name"])

    con.execute("UPDATE sweep_state SET last_sweep_at = ?, recovered_at = ? WHERE id = 1",
                (now.isoformat(), recovered_at.isoformat() if recovered_at else None))
    con.commit()
    return result


def pending_notifications(con: sqlite3.Connection,
                          workspace_id: int | None = None):
    """Open alerts that have not been delivered. A delivery failure leaves
    notified_at NULL so the next sweep tries again, which is one alert
    retried rather than a second alert raised.

    A suppressed alert leaves this list and never comes back. A mute
    suppresses rather than queues, so a mail held until the mute expires is
    a mail about work that finished two hours ago, which is what
    `docs/PRODUCT.md` 4c exists to prevent.

    `workspace_id` narrows to one workspace's servers. None is every
    workspace, which is what the sweep prints from and never what it mails
    from.
    """
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = () if workspace_id is None else (workspace_id,)
    return con.execute(
        "SELECT a.*, h.name AS host_name FROM alerts a JOIN hosts h ON h.id = a.host_id"
        " WHERE a.resolved_at IS NULL AND a.notified_at IS NULL"
        " AND a.suppressed_at IS NULL" + scope + " ORDER BY a.id",
        params).fetchall()


# The channels that are not email. Email is `alerts.notified_at`, above.
#
# **A key is one destination, not one kind of destination.** It was
# `CHANNEL_WEBHOOK` alone until a test posted to two webhooks and got one post:
# the first delivery marked the alert delivered for "webhook" and the second
# channel found nothing pending. That is the bug `alert_deliveries` exists to
# prevent, one level further down.
#
# The key is the name of the environment variable the destination is read from,
# rather than the channel row's id, and that is deliberate. Two rows reading
# one variable are one destination and should not both be posted to. And the
# environment-only arrangement that predates channel rows reads exactly that
# variable, so adding a row for it produces the same key and re-posts nothing.
CHANNEL_WEBHOOK = "webhook"


def key_for_channel(channel) -> str:
    """The delivery key for a channel row, whichever way it is configured.

    **A row that holds its own destination is keyed on a digest of it, never on
    the row id.** `docs/RECORD.md` 4.87 records why the id is wrong: adding a
    second row for a destination already configured would look like a new
    destination and re-post every open alert to it. A digest keeps the property
    the variable name gave, that two rows pointing at one place are one
    destination, without the key itself being a credential.

    SHA-256 truncated to 16 hex characters. Truncated because a key is read by
    a person debugging a delivery and 64 characters is not, and 64 bits is far
    past any collision that could happen between the handful of channels one
    operator configures. The digest is not reversible, so a key in a log or on
    a screen discloses nothing.
    """
    if channel.destination:
        digest = hashlib.sha256(channel.destination.encode("utf-8")).hexdigest()
        return channel_key(channel.type, f"#{digest[:16]}",
                           channel.destination_extra)
    return channel_key(channel.type, channel.destination_env,
                       channel.destination_extra)


def channel_key(channel_type: str, destination_env: str,
                destination_extra: str = "") -> str:
    """The delivery key for one channel: its type, and what it points at.

    **The type is part of the key**, so a Slack row and a webhook row that
    happen to name one variable are two destinations and each is delivered to
    once. That is the same reasoning as the note above, one level out.

    **The extra is part of it too, when the type has one.** Telegram is the
    case: one bot token can post to any number of chats, so the token alone
    does not name a destination and two rows sharing it are two destinations.
    Every other type has no extra and the key is two parts, exactly as it was.

    A webhook row produces `webhook:NAME`, byte for byte what
    `webhook_channel` produced before this function existed. That is not a
    coincidence and a test asserts it: changing the spelling of an existing key
    would make every open alert look undelivered and post it a second time.
    """
    if destination_extra:
        return f"{channel_type}:{destination_env}:{destination_extra}"
    return f"{channel_type}:{destination_env}"


def webhook_channel(destination_env: str) -> str:
    """The webhook key, still spelled where the old callers look for it."""
    return channel_key(CHANNEL_WEBHOOK, destination_env)


def mark_delivered(con: sqlite3.Connection, alert_id: int, channel: str,
                   now: datetime) -> None:
    """Record that one channel accepted one alert.

    `INSERT OR IGNORE` against the unique index, so a second call for the same
    pair is a no-op rather than a second row. Delivery is retried per sweep and
    a retry that raced a success must not double-record.
    """
    con.execute(
        "INSERT OR IGNORE INTO alert_deliveries (alert_id, channel, delivered_at)"
        " VALUES (?, ?, ?)", (alert_id, channel, now.isoformat()))
    con.commit()


def log_sent(con: sqlite3.Connection, alert_id: int, channel: str,
             now: datetime) -> None:
    """Write down that `channel` accepted a message about this alert.

    **Only where a send succeeded.** `mark_delivered` is also called for an
    alert of a kind the channel does not take, so its queue lets go of it,
    and the Sent list read those rows as sent to that channel. This is
    called beside a real send and nowhere else.

    The server's name, its workspace and the alert's words are copied as
    they are at this moment, because the line has to stand without them
    later (`sent_log` in SCHEMA says why).

    A message that an agent stopped reporting is also written down as told
    to this channel (`silence_told`), here because this is the one place
    every real send passes.
    """
    con.execute(
        "INSERT INTO sent_log (workspace_id, host_name, detail, channel, sent_at)"
        " SELECT h.workspace_id, h.name, a.detail, ?, ?"
        "   FROM alerts a JOIN hosts h ON h.id = a.host_id WHERE a.id = ?",
        (channel, now.isoformat(), alert_id))
    con.execute(
        "INSERT OR IGNORE INTO silence_told (alert_id, channel, told_at)"
        " SELECT id, ?, ? FROM alerts WHERE id = ? AND kind = ?",
        (channel, now.isoformat(), alert_id, KIND_SILENT))
    con.commit()


def note_mail_answer(con: sqlite3.Connection, channel, ok: bool, reason: str,
                     now: datetime) -> None:
    """What the relay did with a mail to one email channel row, for the
    Fleet's banner. A mail taken ends a refusal. A refusal by the relay
    (`notify.refused_by_the_relay`) starts one, or goes on with the one
    there is. Anything else, a relay out of reach or none configured, is not
    the relay refusing and leaves the row as it was.

    Every path of the sweep that mails a row calls this: the alerts, the CVE
    message and the reporting again message."""
    key = key_for_channel(channel)
    if ok:
        con.execute("DELETE FROM mail_refusals WHERE workspace_id = ? AND channel = ?",
                    (channel.workspace_id, key))
    elif notify.refused_by_the_relay(reason):
        con.execute("INSERT OR IGNORE INTO mail_refusals (workspace_id, channel, error, refused_at)"
                    " VALUES (?, ?, ?, ?)", (channel.workspace_id, key, reason, now.isoformat()))
    else:
        return
    con.commit()


def forget_mail_refusals_but(con: sqlite3.Connection, rows) -> None:
    """Forget the refusals of every email destination but `rows`, the ones
    the sweep mails. A destination removed or switched off is mailed no
    more, so no mail could end its refusal and its row would stay for ever."""
    kept = {(row.workspace_id, key_for_channel(row)) for row in rows}
    for workspace_id, key in con.execute("SELECT workspace_id, channel FROM mail_refusals").fetchall():
        if (workspace_id, key) not in kept:
            con.execute("DELETE FROM mail_refusals WHERE workspace_id = ? AND channel = ?",
                        (workspace_id, key))
    con.commit()


def mail_refusals(con: sqlite3.Connection, workspace_id: int | None) -> dict:
    """One workspace's email destinations the relay is refusing, as
    {delivery key: when the refusals began}, and None for every workspace,
    as the page reads every other table. A database from before the table
    has none. Read by position, so a connection whose rows are tuples reads
    it too."""
    scope, params = ("", ()) if workspace_id is None else (" WHERE workspace_id = ?", (workspace_id,))
    try:
        rows = con.execute("SELECT channel, refused_at FROM mail_refusals" + scope, params).fetchall()
    except sqlite3.OperationalError:
        return {}
    return {key: refused_at for key, refused_at in rows}


def prune_sent_log(con: sqlite3.Connection, now: datetime) -> int:
    """Drop every line older than `SENT_LOG_DAYS`. Returns how many went.

    The bound is compared as text, which is right because every `sent_at` is
    `datetime.isoformat()` of an aware UTC datetime, one offset, so the
    strings sort as the instants they name.
    """
    cutoff = (now - timedelta(days=SENT_LOG_DAYS)).isoformat()
    gone = con.execute("DELETE FROM sent_log WHERE sent_at < ?", (cutoff,)).rowcount
    con.commit()
    return gone


def pending_for_channel(con: sqlite3.Connection, channel: str,
                        workspace_id: int | None = None, added_at: str | None = None):
    """Open alerts this channel has not accepted yet.

    The same three exclusions `pending_notifications` makes, for the same
    reasons, and one more: an alert this channel already took is left out.
    A suppressed alert never appears, because a mute suppresses rather than
    queues (`docs/PRODUCT.md` 4c).

    `workspace_id` is the channel row's own workspace, so a workspace's
    channel is only ever asked about that workspace's servers. None is every
    workspace and belongs to exactly one caller, the synthetic legacy row the
    environment-only arrangement gets, which is the operator's and watches
    the fleet.

    `added_at` is when the channel row was added, and an alert raised before
    it is not this channel's to hear: a destination hears what is raised
    after it was added (decided on 26 October 2026, after the second big
    test's E10a, where a Webhook added during an open silence was sent that
    silence at the next sweep). Compared as text, sound because both stamps
    are `isoformat()` of an aware UTC time. None is no such limit.
    """
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = (channel,) if workspace_id is None else (channel, workspace_id)
    if added_at:
        scope += " AND a.raised_at >= ?"
        params += (added_at,)
    return con.execute(
        "SELECT a.*, h.name AS host_name FROM alerts a"
        " JOIN hosts h ON h.id = a.host_id"
        " LEFT JOIN alert_deliveries d"
        "   ON d.alert_id = a.id AND d.channel = ?"
        " WHERE a.resolved_at IS NULL AND a.suppressed_at IS NULL"
        "   AND d.id IS NULL" + scope +
        " ORDER BY a.id", params).fetchall()


def mark_notified(con: sqlite3.Connection, alert_id: int, now: datetime) -> None:
    con.execute("UPDATE alerts SET notified_at = ? WHERE id = ?", (now.isoformat(), alert_id))
    con.commit()
