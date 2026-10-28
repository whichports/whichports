"""Alert when a finding changes.

`docs/PRODUCT.md` 4c owns the design. The dead-man switch in `app/alerts.py`
watches whether an agent reports at all. This watches what the reports and the
probes add up to: a port that became reachable, one that stopped being
reachable, and one that now disagrees with what the operator declared. The owner's
decision of `docs/RECORD.md` 4.55 is what made the third of those reachable at
all, and until this module nothing told him.

It is a second reader of `app/join.py` and never a second engine. It stores no
judgement of its own: it stores the state word the join engine produced, and it
compares today's against the one it stored last time.

## The line it may never cross

**A port whose outside view is `not tested` produces no alert of any kind,
ever.** Not a held one, not a recorded one, not a row. Every one of the five
states except `stale rule` asserts something about what the internet did with
this port, and an alert about a state nobody measured is `docs/PRODUCT.md` 4b
happening inside the product instead of in prose. So the first thing this
module does with a finding is ask whether the prober measured it, and a `no`
means it is invisible here. That is why the whole fleet is silent today: three
hosts, real documents, and no probe run anywhere (`docs/RECORD.md` 4.53).

## What it may and may not raise

  - **A first measurement records and raises nothing, per address family.**
    There is no previous state, so nothing changed. This is the same rule the
    dead-man switch follows for a host that has never reported, and the cost
    is stated rather than hidden: a port that was already in conflict when the
    prober first reached it is on the screen and not in a mail. It is per
    family because the two families start at different times on a real
    server: a dual-stack server proves the address its agent reports from and
    the other one later (`docs/RECORD.md` 4.184), and fart's v6 was first
    measured eight hours after its v4 on 2026-08-28. Read per host, every port
    of the later family looked new, which would tell somebody a port "became
    reachable" that had only started being measured. After that first
    measurement a port appearing **is** a change, because the family has a
    history to be new against, and a new reachable port is the alert this
    product exists to send.
  - **Only real transitions.** The state word changing. Not a rule edit, not
    a new report, not a sweep. A state that stays the same for a week is one
    row in `finding_states` and nothing else.
  - **Three states ask for attention and the others do not.** `conflict`,
    `unreviewed` and `unexplained` say the internet did something with this
    port that nobody has agreed to. `intended` says reality matches the
    declaration, and `stale rule` says a rule permits a port with nothing
    behind it, which is worth showing and is not one of 4c's three
    transitions. Moving into one of those resolves the open alert instead of
    raising a new one, so the open list carries one row per port and it says
    what is true now.
  - Asking and telling are two questions. The owner, 2026-09-27: whether a
    port needs an answer is `docs/PRODUCT.md` 8d's, and whether you are told
    is 4c's. So a port that becomes reachable and settles as `intended`,
    because a rule you wrote or your own yes already answers it, is told once
    and asks nothing: a notice (`alerts.record_notice`), resolved the moment
    it is raised, delivered by the same queue as every other change on that
    server. "Became reachable" means the stored state said it was not, which
    is `NOT_REACHABLE_BEFORE`. Before this, the commonest way a port gets
    opened, a listener and `ufw allow`, was never mailed at all
    (`docs/RECORD.md` 4.200).
  - **Debounce, 15 minutes.** A change is written to history the moment it is
    seen and mailed only if it is still true a window later. A stack being
    recreated moves a port twice inside a minute and neither move is news.
    This is the `for:` clause every alerting system ends up with, and the
    revert is recorded rather than dropped so the history stays honest.
  - **Coalesce.** Recreating a stack moves eight ports at once, and those
    eight confirm on the same pass, so they leave as one mail. Per server,
    because one letter about two machines buries the reader's own hostname in
    the middle of a list.
  - **Mute and permanent silence.** A muted server still raises and still
    shows, it just does not mail, which is 4c's own wording. Mute suppresses
    rather than queues: a letter delivered when the mute expires is a letter
    about work that finished two hours ago. A mute carries a length, and one
    carrying none lasts until somebody turns it back on. `app/silence_cli.py`
    is the command and `app/ingest.py` holds the route the dashboard posts to.
  - **Our own outage never becomes their alert.** Same hole as the dead-man's
    silence clock and closed with the same mechanism rather than a second
    one. While this control plane was down it could not have seen a revert,
    so a candidate is held for one window measured from the recovery point
    `app/alerts.py` already maintains. It delays a mail, it never cancels
    one.

## What it deliberately does not do

The environment policy of 4c, where a server marked as in development does not
mail at all or mails only into a morning summary, is not here. It needs a field
on the server that `app/db.py` and `app/store.py` own and a delivery mode that
holds a mail until the morning, and both are their own card. A notice rides
the same queue as every other change, so the policy covers it when it lands.
"""

import re
import sqlite3
from datetime import datetime, timedelta, timezone

from . import alerts, alertwords, join, notify, prober, vantages
from . import intent as intent_store

# The alert kind, and the word the dashboard prints beside the host name. One
# word per kind, the way `silent` is, so the metric's label stays countable.
KIND_FINDING = "finding changed"

# `docs/PRODUCT.md` 4c: a change that reverts within 15 minutes is written to
# history and never mailed. THIS IS THE OWNING DEFINITION of that number.
DEBOUNCE_SECONDS = 15 * 60

# 4c again: mute while you work, per server, two hours by default.
DEFAULT_MUTE_SECONDS = 2 * 60 * 60

# The states that say the internet did something with this port that nobody
# has agreed to. `intended` and `stale rule` are deliberately absent and the
# module docstring says why.
ALERTABLE_STATES = (join.STATE_CONFLICT, join.STATE_UNREVIEWED,
                    join.STATE_UNEXPLAINED)

# The stored states that say, on their own, that the port did not answer the
# internet: measured with no state, measured shut with something listening,
# and a rule with nothing behind it. A move from one of these into `intended`
# with the outside view connected is a port that became reachable.
#
# `conflict` and `intended` are left out because each means both things,
# depending on the declaration: `conflict` is a closed port you said yes to or
# an open one you said no to. A move from either is a person changing their
# answer, and guessing which reachability it had would put a sentence in a
# mail that nothing measured.
NOT_REACHABLE_BEFORE = ("", join.STATE_NOT_REACHABLE, join.STATE_STALE_RULE)

# How long a notice stays deliverable. A mail that could not be handed to the
# relay is retried on every sweep inside this window, and a channel added
# inside it still receives the notice. Past it the notice is history on the
# Sent list and nothing more. Without a bound, a channel added today would be
# sent every notice ever recorded for a port that has not moved since, which
# is months of news in one afternoon. A day covers a relay that was down
# overnight. THIS IS THE OWNING DEFINITION.
NOTICE_KEPT_SECONDS = 24 * 60 * 60

# A finding can be measured and still have no state, when the evidence
# supports none of the five (`docs/PRODUCT.md` 8a). Stored as the empty string
# so the column is never NULL and the comparison is always a comparison of two
# words. It is also what a port that this module has never seen reads as, and
# the two mean the same thing here: there was no state, and now there is one.
NO_STATE = ""

# Why an alert was not mailed. Typed, a closed set, never free text, the same
# posture as the join engine's notes and the prober's reasons (SI-8).
SILENCE_MUTE = "mute"
SILENCE_PORT = "silence"
SILENCE_KINDS = (SILENCE_MUTE, SILENCE_PORT)

# What became of a change. Also typed, and also a closed set.
#
#   raised      confirmed, an alert is open and a mail is due
#   suppressed  confirmed, an alert is open, and a mute or a per-port silence
#               means no mail is due and none ever will be for this change
#   noted       confirmed, and the new state does not ask for attention, so
#               the open alert for that port was resolved
#   told        confirmed, the port became reachable and a rule or a yes
#               already answers it, so one mail is due and nothing is open
#   reverted    the state went back before the window elapsed, never mailed
#   superseded  a different state arrived before this one confirmed
#   pending     first seen, still inside the window
OUTCOME_PENDING = "pending"
OUTCOME_RAISED = "raised"
OUTCOME_SUPPRESSED = "suppressed"
OUTCOME_NOTED = "noted"
OUTCOME_TOLD = "told"
OUTCOME_REVERTED = "reverted"
OUTCOME_SUPERSEDED = "superseded"
# A change on a rate-limited port that a rate limit alone could have produced.
# Its own word rather than reusing `suppressed`, because that one means a person
# asked for quiet and this one means the measurement is expected to disagree
# with itself. Reading them as one would make a screen say somebody muted a port
# nobody touched.
OUTCOME_RATE_LIMITED = "rate limited"
OUTCOMES = (OUTCOME_PENDING, OUTCOME_RAISED, OUTCOME_SUPPRESSED, OUTCOME_NOTED,
            OUTCOME_TOLD, OUTCOME_REVERTED, OUTCOME_SUPERSEDED)

SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_changes (
    id           INTEGER PRIMARY KEY,
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    protocol     TEXT NOT NULL,
    port         INTEGER NOT NULL,
    family       TEXT NOT NULL,
    from_state   TEXT NOT NULL,
    to_state     TEXT NOT NULL,
    outside      TEXT NOT NULL,
    vantage      TEXT,
    measured_at  TEXT,
    description  TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    alert_id     INTEGER REFERENCES alerts(id),
    seen_at      TEXT NOT NULL,
    settled_at   TEXT
);

CREATE INDEX IF NOT EXISTS idx_finding_changes_port
    ON finding_changes(host_id, protocol, port, family, id DESC);

CREATE TABLE IF NOT EXISTS finding_states (
    id             INTEGER PRIMARY KEY,
    host_id        INTEGER NOT NULL REFERENCES hosts(id),
    protocol       TEXT NOT NULL,
    port           INTEGER NOT NULL,
    family         TEXT NOT NULL,
    state          TEXT NOT NULL,
    confirmed_at   TEXT NOT NULL,
    pending_change INTEGER REFERENCES finding_changes(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_states_port
    ON finding_states(host_id, protocol, port, family);

CREATE TABLE IF NOT EXISTS alert_silences (
    id         INTEGER PRIMARY KEY,
    host_id    INTEGER NOT NULL REFERENCES hosts(id),
    kind       TEXT NOT NULL,
    protocol   TEXT,
    port       INTEGER,
    family     TEXT,
    until      TEXT,
    created_at TEXT NOT NULL,
    cleared_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_silences_live
    ON alert_silences(host_id, cleared_at);
"""

# Columns added after `finding_changes` first shipped, ALTERed the way
# `alerts.LATER_COLUMNS` are, because production has the table without them.
# Both are frozen when the change is first seen, for the reason the
# description is: they are what was measured then.
#
#   program      what answers on the port, named the way a screen names it,
#                or empty when nothing names it
#   rule         the rule that answered for the port, quoted with where it
#                sits, or empty when the answer was a person's yes or there
#                was none
#   was_program  on a change of program, what answered before, named the same
#                way. Empty on a change of state
#   program_key  on a change of program, the new `program_key`, which is what
#                the window compares against on the next pass. NULL on a
#                change of state, and that NULL is how the two are told apart
#
# And for what a message says (docs/screens/mails/SPEC-alert-messages.md).
# A message is built from these and from nothing worked out when it is sent,
# so a rule edited after the change cannot rewrite it. A row from before
# them holds NULL in each, which a message reads as no field.
#
#   allowed_by        the layer whose rule lets the port answer (`allowed_by`)
#   other_family      what the port's other address family did on the same
#                     pass (`other_family`)
#   outside_source    1 when the port answered an address its own rule does
#                     not allow (`join.Finding.answered_outside_the_rules_source`)
#   program_said      `program` in the words a message may carry, or empty
#                     when a name behind the port is not plain (`said_program`)
#   was_program_said  the same for `was_program`
CHANGE_LATER_COLUMNS = ("program TEXT", "rule TEXT", "was_program TEXT",
                        "program_key TEXT", "allowed_by TEXT",
                        "other_family TEXT", "outside_source INTEGER",
                        "program_said TEXT", "was_program_said TEXT")

# And after `finding_states` first shipped.
#
#   program  the `program_key` last confirmed for the port. NULL on every row
#            written before 2026-09-27, which reads as not known, so the
#            deploy that adds it compares nothing and mails nothing
STATE_LATER_COLUMNS = ("program TEXT",)


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init follows. `alerts.init` has
    to have run first, because a change points at the alert it raised."""
    con.executescript(SCHEMA)
    for table, columns in (("finding_changes", CHANGE_LATER_COLUMNS),
                           ("finding_states", STATE_LATER_COLUMNS)):
        for column in columns:
            try:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc):
                    raise
    con.commit()


# ============================================================ mute and silence
#
# One table for two controls, because they differ only in scope and in whether
# they expire. `docs/PRODUCT.md` 4c asks for both and asks for the second one
# without an argument from a settings page.


def mute_host(con: sqlite3.Connection, host_name, *,
              seconds: int | None = DEFAULT_MUTE_SECONDS,
              now: datetime | None = None, workspace_id=None) -> int:
    """Stop mailing about this server for a while. Two hours by default.

    Changes are still recorded and still raise, which is 4c's own wording:
    they just do not mail. An unknown host is refused rather than muted
    silently, because a typo that quietly mutes nothing is worse than an
    error.

    **`seconds=None` mutes until somebody turns it back on.** It stores no
    expiry at all, which is what a NULL `until` already means to
    `_live_silences` and what `silence_port` has always written, so there is
    one convention in this column and not two. A far-future date would have
    been a second one, and one nobody could tell apart from a mute somebody
    really did set for a hundred years.

    Zero or fewer seconds is refused. A mute that was over before it began is
    not a mute, and storing one would read on a screen as quiet that is not
    there.
    """
    if seconds is not None and int(seconds) <= 0:
        raise ValueError("a mute needs a positive number of seconds")
    now = now or datetime.now(timezone.utc)
    host_id = intent_store.host_id_for(con, host_name, workspace_id)
    _clear(con, host_id, SILENCE_MUTE, None, None, None, now)
    until = None
    if seconds is not None:
        until = (now + timedelta(seconds=int(seconds))).isoformat()
    cur = con.execute(
        "INSERT INTO alert_silences (host_id, kind, until, created_at)"
        " VALUES (?, ?, ?, ?)",
        (host_id, SILENCE_MUTE, until, now.isoformat()))
    con.commit()
    return cur.lastrowid


def unmute_host(con: sqlite3.Connection, host_name, *,
                now: datetime | None = None, workspace_id=None) -> bool:
    now = now or datetime.now(timezone.utc)
    host_id = intent_store.host_id_for(con, host_name, workspace_id)
    cleared = _clear(con, host_id, SILENCE_MUTE, None, None, None, now)
    con.commit()
    return cleared


def silence_port(con: sqlite3.Connection, host_name, protocol, port, family, *,
                 now: datetime | None = None, workspace_id=None) -> int:
    """Never mail about this port on this address family again.

    v4 and v6 are separate silences and so are tcp and udp on the same
    number, for the same reason they are separate declarations
    (`docs/PRODUCT.md` 4b). It never expires, which is what permanent means.
    """
    now = now or datetime.now(timezone.utc)
    host_id = intent_store.host_id_for(con, host_name, workspace_id)
    protocol, port, family = intent_store.normalise(protocol, port, family)
    _clear(con, host_id, SILENCE_PORT, protocol, port, family, now)
    cur = con.execute(
        "INSERT INTO alert_silences (host_id, kind, protocol, port, family,"
        " created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, SILENCE_PORT, protocol, port, family, now.isoformat()))
    con.commit()
    return cur.lastrowid


def unsilence_port(con: sqlite3.Connection, host_name, protocol, port, family, *,
                   now: datetime | None = None, workspace_id=None) -> bool:
    now = now or datetime.now(timezone.utc)
    host_id = intent_store.host_id_for(con, host_name, workspace_id)
    protocol, port, family = intent_store.normalise(protocol, port, family)
    cleared = _clear(con, host_id, SILENCE_PORT, protocol, port, family, now)
    con.commit()
    return cleared


def _clear(con, host_id, kind, protocol, port, family, now) -> bool:
    """Withdraw a live silence. A timestamp rather than a delete, so the
    history of what was muted and when stays readable, the same rule
    `app/intent.py` follows for a withdrawn declaration."""
    if protocol is None:
        cur = con.execute(
            "UPDATE alert_silences SET cleared_at = ? WHERE host_id = ?"
            " AND kind = ? AND protocol IS NULL AND cleared_at IS NULL",
            (now.isoformat(), host_id, kind))
    else:
        cur = con.execute(
            "UPDATE alert_silences SET cleared_at = ? WHERE host_id = ?"
            " AND kind = ? AND protocol = ? AND port = ? AND family = ?"
            " AND cleared_at IS NULL",
            (now.isoformat(), host_id, kind, protocol, port, family))
    return cur.rowcount > 0


def _live_silences(con, host_id, now):
    """Every silence that has not been withdrawn and has not expired.

    The expiry is compared in Python rather than in SQL. Both are ISO strings,
    and comparing ISO strings only works while every one of them carries the
    same offset, which is a property nobody is enforcing on this column.
    """
    rows = con.execute(
        "SELECT * FROM alert_silences WHERE host_id = ? AND cleared_at IS NULL"
        # A port silence first, so a log line about a port says the port
        # rather than the server it happens to sit on.
        " ORDER BY (port IS NULL), id", (host_id,)).fetchall()
    live = []
    for row in rows:
        if row["until"] is None:
            live.append(row)
            continue
        until = alerts.parse_stamp(row["until"])
        # A stamp we cannot read is not treated as "for ever". A silence that
        # never expires because of a typo is the failure mode that loses an
        # alert, and losing one is worse than sending one.
        if until is not None and until > now:
            live.append(row)
    return live


def silenced(con: sqlite3.Connection, host_id: int, protocol, port, family, *,
             now: datetime | None = None) -> str | None:
    """The kind of silence covering this port, or None. `mute` covers every
    port on the server, `silence` covers one."""
    now = now or datetime.now(timezone.utc)
    for row in _live_silences(con, host_id, now):
        if row["protocol"] is not None and row["protocol"] != protocol:
            continue
        if row["port"] is not None and row["port"] != port:
            continue
        if row["family"] is not None and row["family"] != family:
            continue
        return row["kind"]
    return None


def list_silences(con: sqlite3.Connection, *, now: datetime | None = None,
                  workspace_id=None):
    """Every live mute and silence, for the command line to print.

    `workspace_id=None` is the whole fleet, which is what the sweeps need. An
    integer lists one workspace's servers only.
    """
    now = now or datetime.now(timezone.utc)
    scope, params = ("", ())
    if workspace_id is not None:
        scope, params = (" WHERE workspace_id = ?", (workspace_id,))
    out = []
    for host in con.execute(
            "SELECT id FROM hosts" + scope + " ORDER BY name", params).fetchall():
        out.extend(_live_silences(con, host["id"], now))
    return out


# ================================================================== one pass


def _key(finding) -> tuple[str, int, str]:
    return finding.protocol, finding.port, finding.family


def subject_for(protocol, port, family) -> str:
    """The de-duplication key inside the kind. One open alert per port per
    address family, so two ports in conflict on one host are two rows."""
    return f"{protocol}/{port} {family}"


def where_for(protocol, port, family) -> str:
    """The same port, phrased the way `join.describe` phrases it, so the mail
    and the sentence inside it agree."""
    return f"{protocol}/{port} on {family}"


def _detail(protocol, port, family, from_state, to_state) -> str:
    was = f"was {from_state}" if from_state else "had no state"
    return f"{where_for(protocol, port, family)} {was}, now {to_state}"


# Units the kernel names that are not the program on the port. Docker's own
# unit holds every port Docker publishes, and the container is the program.
# The same one word `site/app/render_live.py` keeps as NOT_A_SERVICE_UNIT.
NOT_A_PROGRAM_UNIT = ("docker.service",)
UNIT_SUFFIXES = (".service", ".socket")


def program_of(finding) -> str:
    """What answers on this port, in the words the Services tab uses, or empty.

    A container that publishes the port is named as the container, never as
    the runtime's unit behind the host socket. Otherwise each listening
    socket's process name, or its systemd unit without the suffix, so
    `porttest-a.service` reads `porttest-a` as it does on the Overview. A
    socket named by nothing, or only by its owning user, gives no name: a
    user is who owns a socket, not what serves it, and the line is left out
    rather than filled with a guess.
    """
    names, are_containers = _program_names(finding)
    if are_containers:
        return ", ".join(f"container {name}" for name in names)
    return ", ".join(names)


def _program_names(finding) -> tuple[list, bool]:
    """The names behind a port, still apart, and whether they are containers.
    `program_of` joins them for a screen. `said_program` holds each one to
    what a message may carry before any of them is joined."""
    containers = sorted({p.container for p in finding.inside.publications
                         if p.container})
    if containers:
        return containers, True
    names = []
    for socket in _sockets_serving(finding):
        name = socket.process_name or _unit_as_name(socket.unit)
        if name and name not in names:
            names.append(name)
    return names, False


def said_program(finding) -> str:
    """`program_of` in the words a message may carry, or empty when a name
    behind the port is not plain (`alertwords.program_words`)."""
    names, are_containers = _program_names(finding)
    return alertwords.program_words(names, container=are_containers)


def said_program_of_key(key) -> str:
    """The same for the program that answered before, which only its
    `program_key` still names.

    A key joins its names with a comma. No container and no unit can hold
    one, so those are taken apart again. A process name can, so a process
    key with a comma in it cannot be told from two processes and says
    nothing, rather than a name being said in pieces.
    """
    kind, _, joined = (key or "").partition(":")
    if kind == KEY_CONTAINER:
        return alertwords.program_words(joined.split(","), container=True)
    if kind == KEY_UNIT:
        return alertwords.program_words(
            [_unit_as_name(name) for name in joined.split(",")])
    if kind == KEY_PROCESS and "," not in joined:
        return alertwords.program_words([joined])
    return ""


def allowed_by(finding) -> str:
    """Which firewall holds a rule that lets this port answer, or empty.

    The engine's own predicate, asked in one more case. `join._permits` is
    every unconditional permit for the port and family, and `join._decide`
    asks it only for a port nobody declared, where the rule is the answer.
    A port somebody marked closed and that answers is a conflict whatever a
    rule says, and the engine names the service there. The rule is still
    the thing to change, so a message about that port says which firewall
    holds it.

    Empty for a port that does not answer, because the engine does not say
    what dropped a packet. Empty unless the state is `conflict` or
    `intended`: for `unexplained` naming a layer would be picking one, and
    for `unreviewed` no rule permits the port. Empty for a port the server
    does not own. And empty for a port a container publishes: the engine
    does not walk the forward hook (docs/RECORD.md 4.88), so a rule it found
    on input is one the packet may never meet.
    """
    if not finding.outside.connected:
        return ""
    if finding.state not in (join.STATE_CONFLICT, join.STATE_INTENDED):
        return ""
    if not finding.inside.owns_the_port or finding.inside.publications:
        return ""
    if not join._permits(finding.inside, finding.provider):
        return ""
    return join._permit_layer(finding.provider)


def other_family(finding, findings) -> str:
    """What this port's other address family did on the same pass, one of
    `alertwords.OTHER_FAMILY`, or empty when it has no finding.

    "Does not answer" may be said of a port without naming a family only
    when its other family does not answer either. So the other family's
    answer is kept with the change, as it was when the change was seen.
    """
    for other in findings:
        if ((other.protocol, other.port) != (finding.protocol, finding.port)
                or other.family == finding.family):
            continue
        if not other.outside.measured:
            return alertwords.OTHER_NOT_MEASURED
        if other.outside.connected:
            return alertwords.OTHER_ANSWERS
        return alertwords.OTHER_DOES_NOT_ANSWER
    return ""


def _sockets_serving(finding):
    """The sockets that can be answering this port in this family. On v4 a
    socket on the IPv6 wildcard counts when nothing listens on v4 itself,
    the way `join` counts it as owning the port."""
    return finding.inside.sockets or getattr(finding.inside, "wildcard_sockets", ())


def _unit_as_name(unit) -> str:
    if not unit or unit in NOT_A_PROGRAM_UNIT or not unit.endswith(UNIT_SUFFIXES):
        return ""
    return unit.rsplit(".", 1)[0]


# ============================================= which program answers a port
#
# The owner, 2026-09-27: a different program taking over a port that already has
# an answer, by a click or by a rule, is told once, naming the old program and
# the new one, and the answer stays as it was. The fault it closes: on fart on
# 2026-09-26 a yes given while python served tcp/3000 went on covering perl
# with nothing said anywhere (`docs/RECORD.md` 4.200, case B).
#
# **The key compares like with like, or not at all.** A program can be known
# by three kinds of name: the container that publishes the port, the systemd
# unit the kernel names for the socket, or the process name. An agent upgrade
# swaps one kind for another with nothing on the host moving: the fleet went
# from process names to units with 0.1.10 (`docs/RECORD.md` 4.169). Compared
# across that, every answered port on a server would mail on the morning of an
# upgrade. So a process name and a unit are never compared. A container
# against either is, because a port moving between a container and a host
# service is a different program by any reading.
#
# **Only a unit that names a service counts.** A `.scope` is a login session,
# `session-4.scope` today and `session-7.scope` after the next ssh, and
# systemd-run gives a unit "an automatically generated" name when it is not
# given one (systemd-run(1), `--unit=`, whose example is `run-19945.service`).
# Both change when nothing but a restart happened, so a port they hold has no
# key and nothing is compared for it.
KEY_CONTAINER = "container"
KEY_UNIT = "unit"
KEY_PROCESS = "process"
_GENERATED_UNIT = re.compile(r"^run-[a-z]?\d")


def program_key(finding) -> str:
    """What answers this port, as something two passes can be compared by,
    `kind:name[,name]`, or empty when it cannot be said."""
    containers = sorted({p.container for p in finding.inside.publications
                         if p.container})
    if containers:
        return f"{KEY_CONTAINER}:" + ",".join(containers)
    sockets = _sockets_serving(finding)
    if not sockets:
        return ""
    if all(_unit_is_a_program(s.unit) for s in sockets):
        return f"{KEY_UNIT}:" + ",".join(sorted({s.unit for s in sockets}))
    if all(s.process_name for s in sockets):
        return f"{KEY_PROCESS}:" + ",".join(sorted({s.process_name for s in sockets}))
    return ""


def _unit_is_a_program(unit) -> bool:
    return bool(_unit_as_name(unit)) and not _GENERATED_UNIT.match(unit)


def program_name(key) -> str:
    """A `program_key` in the words `program_of` uses, for the program that
    answered before, which no current finding can name any more."""
    kind, _, names = (key or "").partition(":")
    if kind == KEY_CONTAINER:
        return ", ".join(f"container {name}" for name in names.split(","))
    if kind == KEY_UNIT:
        return ", ".join(_unit_as_name(name) for name in names.split(","))
    return names


def comparable(old_key, new_key) -> bool:
    """Whether two keys can say the program changed: both known, and not the
    one pair an agent upgrade produces on its own."""
    if not old_key or not new_key:
        return False
    kinds = {old_key.partition(":")[0], new_key.partition(":")[0]}
    return kinds != {KEY_UNIT, KEY_PROCESS}


def rule_of(finding) -> str:
    """The rule that answered for this port, quoted with where it sits, or
    empty when the layer that decided is not a firewall.

    `docs/PRODUCT.md` 8d names the firewall layer as the one that decided when
    a rule is the answer, so the quote is the first one of that layer. The
    listening socket is quoted first in the cause and is never the rule, which
    is the fault `join.describe` still has (`docs/RECORD.md` 4.200).
    """
    layer = finding.cause.layer
    if layer not in (join.LAYER_HOST_FIREWALL, join.LAYER_PROVIDER):
        return ""
    for quote in finding.cause.quotes:
        if quote.layer == layer:
            return f"{quote.text} in {quote.source}"
    return ""


def _state_row(con, host_id, protocol, port, family):
    return con.execute(
        "SELECT * FROM finding_states WHERE host_id = ? AND protocol = ?"
        " AND port = ? AND family = ?",
        (host_id, protocol, port, family)).fetchone()


def _change_row(con, change_id):
    if change_id is None:
        return None
    return con.execute("SELECT * FROM finding_changes WHERE id = ?",
                       (change_id,)).fetchone()


def _open_change(con, host_id, finding, from_state, to_state, now, *,
                 findings=(), was_program="", program_key=None,
                 was_program_said="") -> int:
    """Write the change to history the moment it is seen, not when it settles.

    That order is what makes `docs/PRODUCT.md` 4c's debounce sentence literally
    true: a change that reverts inside the window was written to history and
    never mailed. The description is frozen here as well, because it is what
    was measured at this moment and recomputing it later from newer data would
    put a different sentence under the same timestamp.

    A change of program passes `program_key`, and its `from_state` and
    `to_state` are the same word, because the state did not move.

    `findings` are the server's findings of this pass, which is where the
    port's other address family is read from. What a message will say is
    frozen here with the rest (`CHANGE_LATER_COLUMNS`).
    """
    cur = con.execute(
        "INSERT INTO finding_changes (host_id, protocol, port, family,"
        " from_state, to_state, outside, vantage, measured_at, description,"
        " outcome, seen_at, program, rule, was_program, program_key,"
        " allowed_by, other_family, outside_source, program_said,"
        " was_program_said)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
        " ?, ?, ?, ?, ?)",
        (host_id, finding.protocol, finding.port, finding.family,
         from_state, to_state, finding.outside.state, finding.outside.vantage,
         finding.outside.measured_at, join.describe(finding),
         OUTCOME_PENDING, now.isoformat(), program_of(finding),
         rule_of(finding), was_program, program_key,
         allowed_by(finding), other_family(finding, findings),
         1 if finding.answered_outside_the_rules_source else 0,
         said_program(finding), was_program_said))
    return cur.lastrowid


def _settle(con, change_id, outcome, now, alert_id=None) -> None:
    con.execute(
        "UPDATE finding_changes SET outcome = ?, settled_at = ?, alert_id = ?"
        " WHERE id = ?", (outcome, now.isoformat(), alert_id, change_id))


def evaluate(con: sqlite3.Connection, *, now: datetime | None = None) -> dict:
    """One pass over every host's findings. Returns what it did, for the
    caller to log and for the tests to assert on.

    The order of the checks below is the order of the rules in this module's
    docstring, deliberately, so the code reads as the policy does.
    """
    now = now or datetime.now(timezone.utc)
    recovered_at = alerts.recovery_point(con)

    result = {"raised": [], "suppressed": [], "noted": [], "told": [],
              "new_program": [], "reverted": [], "superseded": [],
              "holding": [], "closed": [], "unreadable": [], "baselines": 0,
              "not_measured": 0, "checked": 0, "first_pass": [],
              "rate_limited": [], "gone": []}

    for host in join.fleet_findings(con):
        # A revoked credential means nothing new will ever be measured for
        # this host, so every finding it has is frozen and none of them can
        # change again. Revoking closes its open alerts for the same reason
        # the dead-man switch closes its silence alert: leaving a red row
        # behind for something the operator has just decided is a row they
        # will learn to ignore.
        if host.revoked_at:
            if alerts.resolve_alert(con, host.host_id, KIND_FINDING, now):
                result["closed"].append(host.host_name)
            continue
        if not host.document_readable:
            continue

        # Pausing is not muting. `docs/PRODUCT.md` 4c guard 1: a per-server
        # monitoring pause suppresses only the silence alert, never a real
        # finding. So `host.paused` is deliberately not read here.
        result["checked"] += 1
        # Read once, before any row of this pass is written, so every port of
        # a family measured for the first time on this pass is part of that
        # first measurement and not the second port of it looking new.
        known_families = {row["family"] for row in con.execute(
            "SELECT DISTINCT family FROM finding_states WHERE host_id = ?",
            (host.host_id,)).fetchall()}

        try:
            for finding in host.findings:
                # The line this module may never cross. A port the prober did
                # not measure has no reachability answer, so there is nothing
                # here to have changed and nothing that may be said about it.
                if not finding.outside.measured:
                    result["not_measured"] += 1
                    continue
                first_measurement = finding.family not in known_families
                _one_finding(con, host, finding, now, recovered_at,
                             first_measurement, result)
        except sqlite3.IntegrityError:
            if _host_is_there(con, host.host_id):
                raise
            # Deleted in the dashboard after the fleet's findings were worked
            # out above and before this server's rows were written. Its rows
            # went with it, so the first write for it is refused, and that
            # ended the whole run for everybody (docs/RECORD.md 4.315). It is
            # left out and named, and the next server is written. Nothing is
            # rolled back: SQLite undoes the refused statement alone, and
            # what the servers before this one wrote stays to be committed.
            # A refusal for a server that is still there is raised, above.
            result["gone"].append(host.host_name)
            result["checked"] -= 1
            continue
        if not known_families:
            result["first_pass"].append(host.host_name)

    con.commit()
    return result


def _host_is_there(con: sqlite3.Connection, host_id: int) -> bool:
    return con.execute("SELECT 1 FROM hosts WHERE id = ?",
                       (host_id,)).fetchone() is not None


def _one_finding(con, host, finding, now, recovered_at, first_measurement,
                 result) -> None:
    protocol, port, family = _key(finding)
    label = f"{host.host_name} {subject_for(protocol, port, family)}"
    observed = finding.state or NO_STATE
    row = _state_row(con, host.host_id, protocol, port, family)

    # A family this module has never recorded anything for on this host gets
    # a baseline and nothing else. There is no previous state, so nothing
    # changed. A whole new server is the case where both families start here
    # on the same pass.
    if first_measurement:
        if row is None:
            con.execute(
                "INSERT INTO finding_states (host_id, protocol, port, family,"
                " state, confirmed_at, program) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (host.host_id, protocol, port, family, observed, now.isoformat(),
                 program_key(finding)))
            result["baselines"] += 1
        return

    # A port appearing in a family that already has a history is a real
    # change, from having no state to having one. The row starts empty so the
    # ordinary path below does the rest, including the debounce, so a port
    # that appears and vanishes inside the window mails nothing either.
    if row is None:
        cur = con.execute(
            "INSERT INTO finding_states (host_id, protocol, port, family,"
            " state, confirmed_at) VALUES (?, ?, ?, ?, ?, ?)",
            (host.host_id, protocol, port, family, NO_STATE, now.isoformat()))
        row = con.execute("SELECT * FROM finding_states WHERE id = ?",
                          (cur.lastrowid,)).fetchone()

    pending = _change_row(con, row["pending_change"])

    if observed == row["state"]:
        if pending is not None and not _is_program_change(pending):
            # Back where it started. This is the revert `docs/PRODUCT.md` 4c
            # describes: written to history already, and never mailed.
            _settle(con, pending["id"], OUTCOME_REVERTED, now)
            con.execute("UPDATE finding_states SET pending_change = NULL WHERE id = ?",
                        (row["id"],))
            result["reverted"].append(label)
            return
        # The state held, so the one thing left that can have moved is the
        # program answering the port.
        _one_program(con, host, finding, row, pending, now, recovered_at,
                     result, label)
        return

    if pending is not None and pending["to_state"] != observed:
        # A third state before the second confirmed. The old candidate never
        # happened as far as anyone outside is concerned, and the clock
        # restarts, because what the window holds for is 15 minutes of the
        # same new state. A change of program being held is overtaken the same
        # way: its `to_state` is the state that just moved.
        _settle(con, pending["id"], OUTCOME_SUPERSEDED, now)
        pending = None
        result["superseded"].append(label)

    if pending is None:
        change_id = _open_change(con, host.host_id, finding, row["state"],
                                 observed, now, findings=host.findings)
        con.execute("UPDATE finding_states SET pending_change = ? WHERE id = ?",
                    (change_id, row["id"]))
        result["holding"].append(label)
        return

    if _held(pending, now, recovered_at, result, label):
        return

    _confirm(con, host, finding, row, pending, now, result, label)


def _held(pending, now, recovered_at, result, label) -> bool:
    """Whether a change is still inside its window, and so held.

    One window for a change of state and a change of program, because 4c's
    debounce is about anything a mail would be sent for.
    """
    seen_at = alerts.parse_stamp(pending["seen_at"])
    if seen_at is None:
        # A stamp that exists and cannot be read is a fault in our own data.
        # The window cannot be measured from it, and measuring from anything
        # else would put a number nobody observed into the decision, which is
        # `docs/RECORD.md` 4.51's correction. Named rather than guessed at.
        result["unreadable"].append(label)
        return True

    # The self-outage guard, and it is one line on purpose. While this control
    # plane was down it could not have seen a revert, so the window is
    # measured from the moment we could see again rather than from when the
    # change was first seen. Same mechanism as the dead-man's silence clock
    # (`app/alerts.py`), because two guards for one hole would drift.
    held_from = max(seen_at, recovered_at) if recovered_at else seen_at
    if (now - held_from).total_seconds() < DEBOUNCE_SECONDS:
        result["holding"].append(label)
        return True
    return False


def _is_program_change(change) -> bool:
    return change["program_key"] is not None


def program_changed(finding, state, old_key, new_key) -> bool:
    """Whether the program on this port changed in a way that is told.

    The port already has an answer, a rule or a yes, which is `intended`, and
    it answers the internet, so the answer is now covering what answers. A
    port that asks for an answer is on the list already and a shut port
    serves nobody outside, so neither is told about. And the two keys have to
    be comparable, see the note above `program_key`.
    """
    return (state == join.STATE_INTENDED and finding.outside.connected
            and old_key != new_key and comparable(old_key, new_key))


def _one_program(con, host, finding, row, pending, now, recovered_at,
                 result, label) -> None:
    """The program half of a pass on a port whose state did not move."""
    stored = row["program"] or ""
    key = program_key(finding)

    if key == stored:
        if pending is not None:
            # The first program came back inside the window, a restart that
            # briefly showed something else. Written to history, never mailed.
            _settle(con, pending["id"], OUTCOME_REVERTED, now)
            con.execute("UPDATE finding_states SET pending_change = NULL WHERE id = ?",
                        (row["id"],))
            result["reverted"].append(label)
        return

    if not program_changed(finding, row["state"], stored, key):
        # Nothing anybody is told about, so the newest name is simply kept and
        # the next pass compares against what answers now. That is also how a
        # row from before 2026-09-27, with no program at all, gets its first.
        if pending is not None:
            _settle(con, pending["id"], OUTCOME_SUPERSEDED, now)
            result["superseded"].append(label)
        con.execute("UPDATE finding_states SET program = ?, pending_change = NULL"
                    " WHERE id = ?", (key, row["id"]))
        return

    if pending is not None and pending["program_key"] != key:
        # A third program before the second confirmed. The clock restarts.
        _settle(con, pending["id"], OUTCOME_SUPERSEDED, now)
        pending = None
        result["superseded"].append(label)

    if pending is None:
        change_id = _open_change(con, host.host_id, finding, row["state"],
                                 row["state"], now, findings=host.findings,
                                 was_program=program_name(stored),
                                 was_program_said=said_program_of_key(stored),
                                 program_key=key)
        con.execute("UPDATE finding_states SET pending_change = ? WHERE id = ?",
                    (change_id, row["id"]))
        result["holding"].append(label)
        return

    if _held(pending, now, recovered_at, result, label):
        return

    protocol, port, family = _key(finding)
    subject = subject_for(protocol, port, family)
    con.execute("UPDATE finding_states SET program = ?, pending_change = NULL"
                " WHERE id = ?", (key, row["id"]))
    # Told once and asking nothing, the same notice as a port that became
    # reachable. Its sentence is the Alerts screen's to parse, so the old and
    # the new names are in it (`site/app/render_live.py`, PROGRAM_RE).
    detail = (f"{where_for(protocol, port, family)} program was "
              f"{pending['was_program']}, now {pending['program']}")
    alert = alerts.record_notice(con, host.host_id, KIND_FINDING, detail, now,
                                 subject=subject)
    if silenced(con, host.host_id, protocol, port, family, now=now):
        alerts.suppress_alert(con, alert["id"], now)
        _settle(con, pending["id"], OUTCOME_SUPPRESSED, now, alert["id"])
        result["suppressed"].append(label)
        return
    _settle(con, pending["id"], OUTCOME_TOLD, now, alert["id"])
    result["new_program"].append(label)


# The transitions a rate limit alone can produce, and only these.
#
# **The narrow rule, and the width is the whole design.** A rate limit changes
# whether the prober's connection got through and changes nothing else. With a
# declaration against the port that flips the finding between `intended` and
# `conflict` on every pass that happens to land inside the window, and those two
# words are the flap the owner's decision of 2026-08-21 is about.
#
# Without a declaration there is no flap to stop: `_decide` answers `unreviewed`
# whether the port answered or not, so the state never moves and nothing was
# ever mailed.
#
# Everything else still mails, and that is deliberate. A port going `stale rule`
# means its listener went away and a rate limit cannot cause that. A port going
# `unexplained` means nothing on the host owns it, and a rate limit cannot cause
# that either. Suppressing every change on a rate-limited port would silence
# tcp/22 on every ufw host there is, which is the port people most want to hear
# about.
#
# **What this does cost**, said plainly rather than left to be discovered: a
# genuine outage on a declared-open port that also carries a rate limit reads as
# `conflict`, which is in this set, so it is recorded and shown and not mailed.
# `docs/RECORD.md` 4.81 has the reasoning and names it as the open question.
#
# **The undeclared pair joined the set on 2026-08-28**, with `not reachable`
# (`docs/RECORD.md` 4.112). Before that an undeclared port read `unreviewed`
# whether it answered or not, so it could not flap and did not need to be
# here. Now it moves, and a rate limit is exactly as good an explanation for
# an undeclared port moving as it is for a declared one. Leaving the pair out
# would have made this change a new source of the flapping mail 4.81 exists to
# stop, and on the one port everybody has a rate limit on.
#
# **The pair a rule answers joined on 2026-09-27**, with the notice that a
# port became reachable (`docs/PRODUCT.md` 4c). A port a rule permits reads
# `intended` when it answers and `not reachable` when it does not, and
# `not reachable` to `intended` now mails. On a port behind a rate limit that
# is the same flap again, so it is stopped for the same reason.
RATE_LIMIT_FLAP = frozenset({
    (join.STATE_INTENDED, join.STATE_CONFLICT),
    (join.STATE_CONFLICT, join.STATE_INTENDED),
    (join.STATE_UNREVIEWED, join.STATE_NOT_REACHABLE),
    (join.STATE_NOT_REACHABLE, join.STATE_UNREVIEWED),
    (join.STATE_INTENDED, join.STATE_NOT_REACHABLE),
    (join.STATE_NOT_REACHABLE, join.STATE_INTENDED),
})


def rate_limit_flap(finding, from_state: str, to_state: str) -> bool:
    """Whether this confirmed change is one a rate limit alone explains."""
    return bool(getattr(finding, "rate_limited", False)) and (
        (from_state, to_state) in RATE_LIMIT_FLAP)


def _confirm(con, host, finding, row, pending, now, result, label) -> None:
    protocol, port, family = _key(finding)
    subject = subject_for(protocol, port, family)
    observed = pending["to_state"]

    # The program is recorded with the state, so a later change of program on
    # this port is compared against what answered when the state settled.
    con.execute(
        "UPDATE finding_states SET state = ?, confirmed_at = ?,"
        " pending_change = NULL, program = ? WHERE id = ?",
        (observed, now.isoformat(), program_key(finding), row["id"]))

    # Whatever was open for this port described the state before this one, so
    # it is resolved first. It has to happen before the raise: `raise_alert`
    # returns the existing open row rather than opening a second, which is the
    # de-duplication that makes one silence one alert, and here it would leave
    # the detail describing the state before last.
    alerts.resolve_subject(con, host.host_id, KIND_FINDING, subject, now)

    detail = _detail(protocol, port, family, pending["from_state"], observed)
    if observed in ALERTABLE_STATES:
        alert, _ = alerts.raise_alert(con, host.host_id, KIND_FINDING, detail,
                                      now, subject=subject)
        done = OUTCOME_RAISED
    elif became_reachable(finding, pending["from_state"], observed):
        # Told once and asking nothing: the row is born resolved, so nothing
        # waits for a click, and it is mailed like the rest.
        alert = alerts.record_notice(con, host.host_id, KIND_FINDING, detail,
                                     now, subject=subject)
        done = OUTCOME_TOLD
    else:
        _settle(con, pending["id"], OUTCOME_NOTED, now)
        result["noted"].append(label)
        return

    # Asked before the mute, because the two answers are different facts and
    # the more specific one should be the one recorded. A muted port that also
    # carries a rate limit is muted, and reading it the other way round would
    # lose the operator's own decision behind a fact about the ruleset.
    if silenced(con, host.host_id, protocol, port, family, now=now):
        # Recorded, on the screen, and no letter. Suppressed rather than
        # queued: a mute that only delays delivers a letter about work that
        # finished two hours ago, which is the thing 4c exists to prevent.
        alerts.suppress_alert(con, alert["id"], now)
        _settle(con, pending["id"], OUTCOME_SUPPRESSED, now, alert["id"])
        result["suppressed"].append(label)
        return

    if rate_limit_flap(finding, pending["from_state"], observed):
        # Recorded, on the screen, and no letter. The same shape as a mute and
        # for the opposite reason: nobody asked for quiet, the measurement is
        # expected to disagree with itself on this port.
        alerts.suppress_alert(con, alert["id"], now)
        _settle(con, pending["id"], OUTCOME_RATE_LIMITED, now, alert["id"])
        result["rate_limited"].append(label)
        return

    _settle(con, pending["id"], done, now, alert["id"])
    result["raised" if done == OUTCOME_RAISED else "told"].append(label)


def became_reachable(finding, from_state: str, to_state: str) -> bool:
    """Whether a confirmed change is a port that became reachable and that a
    rule or a yes already answers.

    All three halves are read from what was measured: the new state is
    `intended`, the outside view connected, and the stored state before it
    said the port did not answer (`NOT_REACHABLE_BEFORE`). `intended` alone is
    not enough, because a port you said no to that stays shut is `intended`
    too.
    """
    return (to_state == join.STATE_INTENDED
            and finding.outside.connected
            and from_state in NOT_REACHABLE_BEFORE)


# ================================================================ the delivery


def pending_deliveries(con: sqlite3.Connection, channel=None,
                       workspace_id: int | None = None,
                       now: datetime | None = None, added_at: str | None = None):
    """Every finding alert that is due, grouped by server.

    One group is one mail, which is `docs/PRODUCT.md` 4c's coalescing rule:
    eight ports moving at once confirm on the same pass, so they are due
    together and leave together. Returns
    `[(host_name, [(alert_id, notify.Change), ...]), ...]` in host order, and
    the caller stamps every alert in a group once the channel accepted it.

    `channel` picks which queue is read. Left alone it is the mail queue,
    which is `alerts.notified_at`, because that column means a relay accepted
    the message and two screens say "mailed" from it in those words. Any other
    channel reads `alert_deliveries` instead. The two are separate facts about
    separate channels and neither is a copy of the other.

    **A notice is due while it is still news.** It is resolved from birth, so
    the open-alert rule that stops a mail about a state that has since ended
    cannot apply to it. Its own two rules do the same job: it is due for
    `NOTICE_KEPT_SECONDS` after it was raised, and only while no later change
    on the same port has confirmed. A port that became reachable and was shut
    again before the relay took the mail is not mailed as reachable.
    """
    now = now or datetime.now(timezone.utc)
    if channel is None:
        due = ("AND a.notified_at IS NULL", ())
    else:
        due = ("AND NOT EXISTS (SELECT 1 FROM alert_deliveries d"
               " WHERE d.alert_id = a.id AND d.channel = ?)", (channel,))
    # The channel row's own workspace, exactly as `alerts.pending_for_channel`
    # scopes it: a workspace's channel is asked about its own servers only.
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    ws = () if workspace_id is None else (workspace_id,)
    # A destination hears what is raised after it was added, as
    # `alerts.pending_for_channel` has it.
    if added_at:
        scope += " AND a.raised_at >= ?"
        ws += (added_at,)
    # Compared as text, which is sound because the sweep writes every stamp
    # in this table as `isoformat()` on an aware UTC datetime.
    kept_since = (now - timedelta(seconds=NOTICE_KEPT_SECONDS)).isoformat()
    later_settled = (OUTCOME_RAISED, OUTCOME_SUPPRESSED, OUTCOME_NOTED,
                     OUTCOME_TOLD, OUTCOME_RATE_LIMITED)
    rows = con.execute(
        "SELECT a.id AS alert_id, h.name AS host_name, c.protocol, c.port,"
        " c.family, c.from_state, c.to_state, c.description, c.vantage,"
        " c.measured_at, c.outcome, c.program, c.rule, c.was_program,"
        " c.outside, c.allowed_by, c.other_family, c.outside_source,"
        " c.program_said, c.was_program_said"
        " FROM alerts a"
        " JOIN hosts h ON h.id = a.host_id"
        " JOIN finding_changes c ON c.alert_id = a.id"
        " WHERE a.kind = ? AND a.suppressed_at IS NULL"
        " AND (a.resolved_at IS NULL"
        "      OR (c.outcome = ? AND a.raised_at >= ?"
        "          AND NOT EXISTS (SELECT 1 FROM finding_changes n"
        "              WHERE n.host_id = c.host_id AND n.protocol = c.protocol"
        "              AND n.port = c.port AND n.family = c.family"
        "              AND n.id > c.id AND n.outcome IN (?, ?, ?, ?, ?)))) "
        + due[0] + scope +
        " ORDER BY h.name, c.port, c.protocol, c.family",
        (KIND_FINDING, OUTCOME_TOLD, kept_since) + later_settled
        + due[1] + ws).fetchall()

    grouped: list[tuple[str, list]] = []
    for row in rows:
        change = notify.Change(
            where=where_for(row["protocol"], row["port"], row["family"]),
            was=row["from_state"], now=row["to_state"],
            description=row["description"],
            vantage=row["vantage"] or "", measured_at=row["measured_at"] or "",
            became_reachable=(row["outcome"] == OUTCOME_TOLD
                              and not row["was_program"]),
            program=row["program"] or "", rule=row["rule"] or "",
            was_program=row["was_program"] or "",
            port=row["port"], protocol=row["protocol"], family=row["family"],
            answers=row["outside"] == prober.STATE_CONNECTED,
            other_family=row["other_family"] or "",
            allowed_by=row["allowed_by"] or "",
            outside_source=bool(row["outside_source"]),
            program_said=row["program_said"] or "",
            was_program_said=row["was_program_said"] or "")
        if grouped and grouped[-1][0] == row["host_name"]:
            grouped[-1][1].append((row["alert_id"], change))
        else:
            grouped.append((row["host_name"], [(row["alert_id"], change)]))
    return grouped


# ============================================ nothing was watching the prober
#
# `docs/PRODUCT.md` 4c: a monitoring tool that dies silently is worse than
# none, because the quiet reads as healthy. That principle had a dead-man
# switch for agents and nothing at all for the prober.
#
# **What goes wrong without this.** The prober box dies, or ssh breaks, or the
# timer stops. The last results stay in the database. `app/join.py` keeps
# reporting them as the outside view, findings keep their states, the screen
# keeps saying what was true yesterday, and nobody is told. That is the same
# shape as a host that stopped reporting, and it is worse, because the agent at
# least has a switch watching it.
#
# **Per host, not one alert for the fleet.** The alerts table requires a host
# id, but that is not why. When the first real pass failed on 2026-08-18 it
# failed per host, and a host whose address stopped being routable goes stale
# on its own while the rest keep measuring. The fact really is per host.

KIND_OUTSIDE_STALE = "outside view stale"

# Three missed passes at the hourly cadence in `whichports-probe.timer`.
#
# **This constant and that timer have to be changed together**, which is a
# coupling worth naming rather than hiding: nothing here can read a systemd
# schedule. Two missed passes would fire on one slow run plus jitter, since the
# timer carries ten minutes of it. THIS IS THE OWNING DEFINITION.
OUTSIDE_STALE_AFTER_SECONDS = 3 * 60 * 60


def sweep_outside_views(con: sqlite3.Connection, *,
                        now: datetime | None = None) -> dict:
    """Raise for a host whose outside view has stopped being refreshed.

    Returns what it did, for the caller to print and the tests to assert on.
    """
    now = now or datetime.now(timezone.utc)
    recovered_at = alerts.recovery_point(con)
    result = {"stale": [], "resolved": [], "never_probed": [], "held": [],
              "suppressed": [], "checked": 0}

    result["stale_from"] = []
    watched_vantages = _watched_vantages(con)

    for host in join.fleet_findings(con):
        if host.revoked_at:
            # Nothing will ever be measured for it again, so a stale outside
            # view is not news. Revoking closes it for the same reason the
            # dead-man switch closes its silence alert.
            if alerts.resolve_alert(con, host.host_id, KIND_OUTSIDE_STALE, now):
                result["resolved"].append(host.host_name)
            continue

        watched = _runs_to_watch(con, host.host_id, watched_vantages)
        if not watched:
            # **A host never probed never raises this**, exactly as a host that
            # never reported never raises the silence alert (`docs/RECORD.md`
            # 4.51). The alert says refreshing stopped, and a view that never
            # started has not stopped. The cost is stated rather than hidden: a
            # host that probing never once reached is invisible here and shows
            # on a screen instead.
            result["never_probed"].append(host.host_name)
            continue

        result["checked"] += 1
        stale = []
        unreadable = False
        for vantage_name, run in watched:
            finished = _parse_stamp(run["finished_at"])
            if finished is None:
                # An unreadable stamp is not evidence of freshness and not
                # evidence of staleness either, so it says so and raises
                # nothing on its own.
                unreadable = True
                continue
            age = (now - finished).total_seconds()
            if age >= OUTSIDE_STALE_AFTER_SECONDS:
                stale.append((vantage_name, int(age // 3600)))

        if not stale:
            if unreadable:
                result["held"].append(host.host_name)
                continue
            if alerts.resolve_alert(con, host.host_id, KIND_OUTSIDE_STALE, now):
                result["resolved"].append(host.host_name)
            continue

        # The same self-outage guard the silence clock uses, and the same
        # reasoning: while this control plane was down no pass could have been
        # recorded, so the gap is ours rather than the prober's. It delays a
        # detection and never cancels one.
        if recovered_at is not None:
            since_recovery = (now - recovered_at).total_seconds()
            if since_recovery < OUTSIDE_STALE_AFTER_SECONDS:
                result["held"].append(host.host_name)
                continue

        alert, _opened = alerts.raise_alert(
            con, host.host_id, KIND_OUTSIDE_STALE,
            _stale_detail(host.host_name, stale), now)
        for vantage_name, _hours in stale:
            if vantage_name is not None:
                result["stale_from"].append((host.host_name, vantage_name))

        # A muted server still raises and still shows, it just does not mail,
        # which is `docs/PRODUCT.md` 4c's own wording and the same treatment a
        # finding change gets. Mute is a whole-server instruction, so it is
        # asked with a port only because `silenced` takes one, and a `mute` row
        # names no port and therefore covers every one.
        if silenced(con, host.host_id, None, None, None,
                    now=now) == SILENCE_MUTE:
            alerts.suppress_alert(con, alert["id"], now)
            result["suppressed"].append(host.host_name)
            continue
        result["stale"].append(host.host_name)

    con.commit()
    return result


def _watched_vantages(con) -> list:
    """The names of the enabled vantages in the registry, or an empty list on
    a database from before the registry existed. Empty means the watch reads
    the newest run whoever took it, which is what it did until 2026-09-08."""
    if not vantages.table_exists(con):
        return []
    return [v.name for v in vantages.enabled(con)]


def _runs_to_watch(con, host_id, watched_vantages) -> list:
    """[(vantage name or None, its newest finished run)] for one host.

    **Every enabled vantage is watched on its own**, so a second vantage going
    quiet is noticed while the first keeps refreshing the screen: with two
    boxes, the newest run of either is always fresh, and reading only that
    would mean a dead probe2 is never seen. A vantage that never finished a
    run for this host is left out, by the same rule as a host never probed.

    When no enabled vantage has a finished run for the host, the newest run
    whoever took it is watched instead, under the name None. That is the
    pre-registry behaviour, and it is kept as the fallback so a registry
    whose names do not match the stored runs cannot switch the watch off.
    """
    watched = []
    for name in watched_vantages:
        run = prober.latest_finished_run_from(con, host_id, name)
        if run is not None:
            watched.append((name, run))
    if watched:
        return watched
    newest = prober.latest_run(con, host_id)
    if newest is None or not newest["finished_at"]:
        return []
    return [(None, newest)]


def _stale_detail(host_name, stale) -> str:
    """The sentence on the alert. It names the vantage when there is one to
    name, because with two boxes the reader's first question is which."""
    if len(stale) == 1 and stale[0][0] is None:
        hours = stale[0][1]
        return (f"no probing pass has finished for {host_name} in {hours}"
                " hours, so what the screen says about reachability is that old")
    parts = [f"{name} in {hours} hours" for name, hours in stale if name is not None]
    return (f"no probing pass has finished for {host_name} from "
            + ", ".join(parts)
            + ", so what the screen says about reachability from there is"
            " that old")


def _parse_stamp(value):
    """A stored timestamp, or None. Never raises, because one unreadable stamp
    must not stop the sweep looking at the rest of the fleet."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
