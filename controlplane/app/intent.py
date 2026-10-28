"""What the operator meant, what they call things, and what they have seen
and left alone.

`docs/PRODUCT.md` section 8 item 2 is "intent as code" and this is the storage
underneath it. `app/join.py` had an `intent` argument from the day it was
written and nothing produced one, so every finding on the fleet came back
`unreviewed` and two of the five states, `conflict` and `intended`, could not
be reached outside a test. This module is what fills that argument.

## Three things, deliberately in three tables

**An intent is about a port.** "tcp/443 on v4 is meant to be reachable." It
stands until the operator changes their mind, it is one value per port per
address family, and it is the thing `join._decide` turns into `intended` or
`conflict`.

**An acknowledgement is about a finding.** "I have read this and I am not
acting on it." It is not a declaration of what should be, it is a note that a
particular answer has been seen, so it is stored with **the state it was given
for** and it stops applying the moment that state changes. Acknowledging
`unreviewed` on a port and then declaring that port closed produces `conflict`,
which is a different finding, and it goes back on the list.

**A declared name is what the operator calls the service on a port.** The owner's own suggestion (`docs/RECORD.md` 4.64): tcp/22 on almabox is ssh. The
agent's process name column is absent under a non-root agent, and even root
reads "systemd" for a socket-activated service, so let the operator say the
name once. It is one name per port per protocol and **not per address
family**, because it names the service behind the port and the service does
not change between v4 and v6. It carries no state, `join._decide` never sees
it, and every screen that shows it says it was declared, because a name a
person typed is that person's statement and never a measurement.

They are three tables because they have different subjects, different
lifetimes and different rules for going stale. One table with extra columns
would mean clearing an intent silently clears an acknowledgement or a name,
and re-declaring one would have to decide whether the others survive it. None
of those questions has an obvious answer, and three tables means none has to
be asked.

## What this module may never do

**A declaration is not a measurement.** Nothing here changes what
`join._decide` concludes from the three views. It supplies the `declared`
value that function already takes and stops. A port the prober never touched
keeps no state at all however loudly it was declared open, which is
`docs/PRODUCT.md` 4b and 8a, and `tests/test_intent.py` asserts it on the
state rather than on the note.

**A declaration does not put a port on the screen.** Candidate ports come from
what a view observed: a listening socket, a container publication, a rule that
names the port, a provider rule, a probe result. A declaration is a thing a
person typed, so declaring an intent for a port nothing else mentions raises no
finding. The CLI listing is where a declaration is always visible.

## Everything a person typed is checked at the door

A host name, a protocol, a port and an address family arrive from a person and
from a command line. The protocol is one of two words, the family is one of
two words, the port is a whole number in range and a `bool` is not one, and the
host has to exist and not be revoked. Case and surrounding spaces are
normalised here so that `TCP` and `tcp` cannot become two rows for one port.

A declared name is the one input that is free text, so it gets its own door:
surrounding whitespace is stripped, empty is refused, the length is bounded,
and a character that does not print is refused rather than silently removed,
because the name is shown as the operator's own words and a store that edits
those words is showing something nobody typed. Case is kept for the same
reason.

Declaring on a revoked host is refused. Its reports are refused by the ingest
and `authz.may_probe` refuses its addresses, so nothing new will ever be
measured for it. Clearing a declaration on a revoked host still works, or one
made before the revocation could never be withdrawn.

## History rather than deletion

Clearing writes `cleared_at` and leaves the row, the same posture
`hosts.revoked_at` takes: visible history rather than a deleted row. A partial
unique index over the live rows is what makes a second live declaration for one
port impossible, and it holds against SQL written by hand rather than only
against the function below it.

## The five state words are written twice

`app/join.py` owns the vocabulary (`docs/RECORD.md` 4.50, and they are
the owner's own choice). The join engine imports this module, so this module
cannot import it back, and the acknowledgement has to validate the state it is
handed. `STATES` below is therefore a second copy, and
`tests/test_intent.py` pins it equal to `join.STATES` so the two can never
drift. `app/authz.py` keeps its copy of `alerts._parse` under the same rule and
for the same reason: lifting a shared home out is its own change.
"""

import sqlite3
from dataclasses import dataclass

from . import authz, store

# The two words a declaration can carry. Absent is not a third value, it is the
# absence of a declaration, and it is spelled None. `app/join.py` takes these
# from here so there is one spelling.
INTENT_OPEN = "open"
INTENT_CLOSED = "closed"
INTENTS = (INTENT_OPEN, INTENT_CLOSED)

# The protocols a declaration can be about. The prober measures TCP and the
# host document carries TCP and UDP, so a declaration about anything else would
# sit beside a finding that cannot exist.
PROTOCOL_TCP = "tcp"
PROTOCOL_UDP = "udp"
PROTOCOLS = (PROTOCOL_TCP, PROTOCOL_UDP)

# From the registry, so the whole control plane spells a family one way.
FAMILY_V4 = authz.FAMILY_V4
FAMILY_V6 = authz.FAMILY_V6
FAMILIES = (FAMILY_V4, FAMILY_V6)

# A copy of `join.STATES`, pinned equal by a test. See the docstring.
STATES = ("conflict", "unreviewed", "intended", "stale rule", "unexplained",
          "not reachable")

MIN_PORT = 1
MAX_PORT = 65535

# The bound on a declared service name. Long enough for "the grafana behind
# the metrics team's dashboards", short enough that a pasted log line or a
# whole sentence of markup is refused at the door instead of widening every
# column it is shown in.
MAX_NAME_LENGTH = 64

# v1 is single tenant, the same column and the same default `app/authz.py`
# carries, so growing an account model is a migration of values rather than a
# change of shape.
DEFAULT_ACCOUNT = authz.DEFAULT_ACCOUNT

SCHEMA = """
CREATE TABLE IF NOT EXISTS port_intents (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    protocol    TEXT NOT NULL,
    port        INTEGER NOT NULL,
    family      TEXT NOT NULL,
    intent      TEXT NOT NULL,
    account     TEXT NOT NULL,
    declared_at TEXT NOT NULL,
    cleared_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_intents_live
    ON port_intents(host_id, protocol, port, family)
    WHERE cleared_at IS NULL;

CREATE TABLE IF NOT EXISTS port_acknowledgements (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts(id),
    protocol        TEXT NOT NULL,
    port            INTEGER NOT NULL,
    family          TEXT NOT NULL,
    state           TEXT NOT NULL,
    account         TEXT NOT NULL,
    acknowledged_at TEXT NOT NULL,
    cleared_at      TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_acknowledgements_live
    ON port_acknowledgements(host_id, protocol, port, family)
    WHERE cleared_at IS NULL;

-- No family column on purpose: a name is about the service behind the port,
-- and the service does not change between v4 and v6. See the module docstring.
CREATE TABLE IF NOT EXISTS port_names (
    id          INTEGER PRIMARY KEY,
    host_id     INTEGER NOT NULL REFERENCES hosts(id),
    protocol    TEXT NOT NULL,
    port        INTEGER NOT NULL,
    name        TEXT NOT NULL,
    account     TEXT NOT NULL,
    declared_at TEXT NOT NULL,
    cleared_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_port_names_live
    ON port_names(host_id, protocol, port)
    WHERE cleared_at IS NULL;

-- The first-look window a server's page opens on its own, once. The owner,
-- 2026-09-06: once per account, not once per browser. One row per host
-- once anybody in the account has seen it.
CREATE TABLE IF NOT EXISTS first_looks (
    host_id  INTEGER PRIMARY KEY REFERENCES hosts(id),
    account  TEXT NOT NULL,
    seen_at  TEXT NOT NULL
);
"""


class IntentError(ValueError):
    """The declaration cannot be recorded as asked.

    One type for every refusal, because every one of them has the same answer
    for the operator: fix the argument and run it again. The message says
    which argument.
    """


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule `db.init`, `authz.init`,
    `alerts.init` and `prober.init` follow. `db.init` has to have run first,
    because both tables reference hosts(id)."""
    con.executescript(SCHEMA)
    con.commit()


# --------------------------------------------------------------- the doorway

def _word(value, name: str) -> str:
    """One lower case word, or a refusal. Everything a person typed goes
    through here before it is compared with anything."""
    if not isinstance(value, str):
        raise IntentError(f"{name} must be text")
    word = value.strip().lower()
    if not word:
        raise IntentError(f"{name} is empty")
    return word


def normalise_port(port) -> int:
    """A whole number inside the port range.

    `bool` is checked first and on purpose. `True` is an `int` in Python, so an
    `isinstance(port, int)` test on its own would accept `True` and store a
    declaration for port 1.
    """
    if isinstance(port, bool) or not isinstance(port, int):
        raise IntentError("port must be a whole number")
    if not MIN_PORT <= port <= MAX_PORT:
        raise IntentError(f"port must be between {MIN_PORT} and {MAX_PORT}")
    return port


def normalise_protocol(protocol) -> str:
    """One of the two protocol words. Its own function because a declared name
    is keyed by protocol and port without a family, so the name path needs this
    check without the family one."""
    protocol_word = _word(protocol, "protocol")
    if protocol_word not in PROTOCOLS:
        raise IntentError(f"protocol must be one of {', '.join(PROTOCOLS)}")
    return protocol_word


def normalise(protocol, port, family) -> tuple[str, int, str]:
    """The three parts of a port's identity, checked and canonicalised."""
    family_word = _word(family, "address family")
    if family_word not in FAMILIES:
        raise IntentError(f"address family must be one of {', '.join(FAMILIES)}")
    return normalise_protocol(protocol), normalise_port(port), family_word


def normalise_intent(value) -> str:
    word = _word(value, "intent")
    if word not in INTENTS:
        raise IntentError(f"intent must be one of {', '.join(INTENTS)}")
    return word


def normalise_state(value) -> str:
    word = _word(value, "state")
    if word not in STATES:
        raise IntentError(f"state must be one of {', '.join(STATES)}")
    return word


def normalise_name(value) -> str:
    """The name the operator gives a port's service, checked at the door.

    Not `_word`: a name keeps its case and its inner spaces, because it is
    shown as the operator's own words. For the same reason nothing in it is
    silently removed. A character that does not print, which is every control
    character, is refused with the reason said out loud, so what is stored is
    exactly what was typed apart from surrounding whitespace.
    """
    if not isinstance(value, str):
        raise IntentError("name must be text")
    name = value.strip()
    if not name:
        raise IntentError("name is empty")
    if len(name) > MAX_NAME_LENGTH:
        raise IntentError(
            f"name is longer than {MAX_NAME_LENGTH} characters")
    for character in name:
        if not character.isprintable():
            raise IntentError(
                "name holds a control character or another character that"
                " does not print")
    return name


def _host(con: sqlite3.Connection, name, workspace_id=None) -> sqlite3.Row:
    """The host row this declaration is about, or a refusal naming it.

    `workspace_id=None` reaches every workspace, which is what the commands run
    on the box do: they belong to whoever already has a shell there. An integer
    narrows it, and a host in another workspace is then refused in exactly the
    words a name nobody enrolled gets, so the refusal cannot be read as a way
    to ask which names exist elsewhere.
    """
    wanted = _word(name, "host name")
    scope, params = ("", ())
    if workspace_id is not None:
        scope, params = (" AND workspace_id = ?", (workspace_id,))
    row = con.execute("SELECT * FROM hosts WHERE name = ?" + scope,
                      (wanted,) + params).fetchone()
    if row is None:
        raise IntentError(f"no host named {wanted!r}")
    return row


def _writable_host(con: sqlite3.Connection, name, workspace_id=None) -> sqlite3.Row:
    row = _host(con, name, workspace_id)
    if row["revoked_at"]:
        raise IntentError(
            f"{row['name']} was revoked on {row['revoked_at']}, so nothing new"
            " is measured for it and there is nothing to declare against")
    return row


def host_id_for(con: sqlite3.Connection, host_name, workspace_id=None) -> int:
    """The id of the host with this name, or a refusal naming it.

    Public because `app/intent_cli.py` has to look a finding up before it can
    acknowledge one, and the name has to go through the same door on that path
    as on this one.
    """
    return _host(con, host_name, workspace_id)["id"]


def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    """Asked rather than caught, the same posture `join._table_exists` takes.

    These two tables arrive after the four production already had, so every
    read below has to answer on a database this module has never been run
    against. Catching OperationalError instead would also swallow a corrupt
    file, which is not the same thing and should be loud.
    """
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,)).fetchone()
    return row is not None


# ------------------------------------------------------------- what is stored

@dataclass(frozen=True)
class Declaration:
    host_id: int
    host_name: str
    protocol: str
    port: int
    family: str
    intent: str
    declared_at: str
    # What was live before this one, so the command line can say plainly that
    # it replaced something rather than leaving the operator to guess.
    previous: str | None = None


@dataclass(frozen=True)
class Acknowledgement:
    host_id: int
    host_name: str
    protocol: str
    port: int
    family: str
    state: str
    acknowledged_at: str
    previous: str | None = None


@dataclass(frozen=True)
class NameDeclaration:
    """No family field, see the module docstring: a name is about the service
    behind the port, and the service does not change between v4 and v6."""
    host_id: int
    host_name: str
    protocol: str
    port: int
    name: str
    declared_at: str
    previous: str | None = None


# ------------------------------------------------------------------ declaring

def _live_value(con, table, column, host_id, protocol, port, family):
    row = con.execute(
        f"SELECT {column} FROM {table} WHERE host_id = ? AND protocol = ?"
        " AND port = ? AND family = ? AND cleared_at IS NULL",
        (host_id, protocol, port, family)).fetchone()
    return row[0] if row is not None else None


def declare(con: sqlite3.Connection, host_name, protocol, port, family, value,
            *, account: str = DEFAULT_ACCOUNT) -> Declaration:
    """Record that this port on this address family is meant to be open or
    closed. Replaces any live declaration for the same port.

    The clear and the insert are one transaction. Without that, a failed
    insert would leave the previous declaration cleared and no new one in its
    place, which is a port that silently stopped being declared.
    """
    protocol, port, family = normalise(protocol, port, family)
    value = normalise_intent(value)
    host = _writable_host(con, host_name)
    stamp = store.now_utc()

    with con:
        previous = _live_value(con, "port_intents", "intent", host["id"],
                               protocol, port, family)
        con.execute(
            "UPDATE port_intents SET cleared_at = ? WHERE host_id = ?"
            " AND protocol = ? AND port = ? AND family = ? AND cleared_at IS NULL",
            (stamp, host["id"], protocol, port, family))
        con.execute(
            "INSERT INTO port_intents (host_id, protocol, port, family, intent,"
            " account, declared_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host["id"], protocol, port, family, value, account, stamp))
    return Declaration(host_id=host["id"], host_name=host["name"],
                       protocol=protocol, port=port, family=family,
                       intent=value, declared_at=stamp, previous=previous)


def clear(con: sqlite3.Connection, host_name, protocol, port, family) -> bool:
    """Withdraw a declaration. True when one was live, False when there was
    nothing to withdraw.

    A revoked host is allowed here on purpose. Declaring on one is refused, so
    refusing to clear as well would leave a declaration made before the
    revocation with no way out.
    """
    protocol, port, family = normalise(protocol, port, family)
    host = _host(con, host_name)
    cur = con.execute(
        "UPDATE port_intents SET cleared_at = ? WHERE host_id = ? AND protocol = ?"
        " AND port = ? AND family = ? AND cleared_at IS NULL",
        (store.now_utc(), host["id"], protocol, port, family))
    con.commit()
    return cur.rowcount == 1


def list_declarations(con: sqlite3.Connection,
                      host_name: str | None = None) -> list[sqlite3.Row]:
    """Every live declaration, host name included, in the order a person reads
    them. Cleared rows stay in the table as history and are not listed."""
    if not _table_exists(con, "port_intents"):
        return []
    sql = ("SELECT i.*, h.name AS host_name FROM port_intents i"
           " JOIN hosts h ON h.id = i.host_id WHERE i.cleared_at IS NULL")
    params: list = []
    if host_name is not None:
        sql += " AND i.host_id = ?"
        params.append(_host(con, host_name)["id"])
    sql += " ORDER BY h.name, i.port, i.protocol, i.family"
    return con.execute(sql, params).fetchall()


def intents_for_host(con: sqlite3.Connection, host_id: int) -> dict:
    """The live declarations for one host, keyed the way `join._intent_for`
    asks: (protocol, port, family) to `open` or `closed`."""
    if not _table_exists(con, "port_intents"):
        return {}
    rows = con.execute(
        "SELECT protocol, port, family, intent FROM port_intents"
        " WHERE host_id = ? AND cleared_at IS NULL", (host_id,)).fetchall()
    return {(row["protocol"], row["port"], row["family"]): row["intent"]
            for row in rows}


# ------------------------------------------------------------------- naming

def _live_name(con, host_id, protocol, port):
    row = con.execute(
        "SELECT name FROM port_names WHERE host_id = ? AND protocol = ?"
        " AND port = ? AND cleared_at IS NULL",
        (host_id, protocol, port)).fetchone()
    return row[0] if row is not None else None


def declare_name(con: sqlite3.Connection, host_name, protocol, port, value,
                 *, account: str = DEFAULT_ACCOUNT) -> NameDeclaration:
    """Record what the operator calls the service on this port. Replaces any
    live name for the same port.

    The clear and the insert are one transaction, for the same reason
    `declare` makes them one: a failure between the two must not leave the
    port silently unnamed.
    """
    protocol = normalise_protocol(protocol)
    port = normalise_port(port)
    value = normalise_name(value)
    host = _writable_host(con, host_name)
    stamp = store.now_utc()

    with con:
        previous = _live_name(con, host["id"], protocol, port)
        con.execute(
            "UPDATE port_names SET cleared_at = ? WHERE host_id = ?"
            " AND protocol = ? AND port = ? AND cleared_at IS NULL",
            (stamp, host["id"], protocol, port))
        con.execute(
            "INSERT INTO port_names (host_id, protocol, port, name, account,"
            " declared_at) VALUES (?, ?, ?, ?, ?, ?)",
            (host["id"], protocol, port, value, account, stamp))
    return NameDeclaration(host_id=host["id"], host_name=host["name"],
                           protocol=protocol, port=port, name=value,
                           declared_at=stamp, previous=previous)


def clear_name(con: sqlite3.Connection, host_name, protocol, port) -> bool:
    """Withdraw a declared name. True when one was live.

    A revoked host is allowed here, the same posture `clear` takes: naming on
    one is refused, so refusing to clear as well would leave a name declared
    before the revocation with no way out.
    """
    protocol = normalise_protocol(protocol)
    port = normalise_port(port)
    host = _host(con, host_name)
    cur = con.execute(
        "UPDATE port_names SET cleared_at = ? WHERE host_id = ? AND protocol = ?"
        " AND port = ? AND cleared_at IS NULL",
        (store.now_utc(), host["id"], protocol, port))
    con.commit()
    return cur.rowcount == 1


def list_names(con: sqlite3.Connection,
               host_name: str | None = None) -> list[sqlite3.Row]:
    """Every live declared name, host name included. Cleared rows stay in the
    table as history and are not listed."""
    if not _table_exists(con, "port_names"):
        return []
    sql = ("SELECT n.*, h.name AS host_name FROM port_names n"
           " JOIN hosts h ON h.id = n.host_id WHERE n.cleared_at IS NULL")
    params: list = []
    if host_name is not None:
        sql += " AND n.host_id = ?"
        params.append(_host(con, host_name)["id"])
    sql += " ORDER BY h.name, n.port, n.protocol"
    return con.execute(sql, params).fetchall()


def names_for_host(con: sqlite3.Connection, host_id: int) -> dict:
    """The live declared names for one host, keyed (protocol, port).

    The table-exists guard is what keeps a database from before this table
    answering, the same posture the other reads here take: production ran for
    days without it and must keep working without a migration step.
    """
    if not _table_exists(con, "port_names"):
        return {}
    rows = con.execute(
        "SELECT protocol, port, name FROM port_names"
        " WHERE host_id = ? AND cleared_at IS NULL", (host_id,)).fetchall()
    return {(row["protocol"], row["port"]): row["name"] for row in rows}


# ------------------------------------------------------------ acknowledging

def acknowledge(con: sqlite3.Connection, host_name, protocol, port, family,
                state, *, account: str = DEFAULT_ACCOUNT) -> Acknowledgement:
    """Record that this finding has been seen and is not being acted on.

    `state` is the state that was on screen. It is stored rather than assumed,
    because that is what makes the acknowledgement lapse honestly: when the
    state changes the finding is a different one and the acknowledgement stops
    applying to it. `app/intent_cli.py` reads the state from the join engine
    rather than taking it from the operator, so nobody can acknowledge a
    finding that was never produced.
    """
    protocol, port, family = normalise(protocol, port, family)
    state = normalise_state(state)
    host = _writable_host(con, host_name)
    stamp = store.now_utc()

    with con:
        previous = _live_value(con, "port_acknowledgements", "state",
                               host["id"], protocol, port, family)
        con.execute(
            "UPDATE port_acknowledgements SET cleared_at = ? WHERE host_id = ?"
            " AND protocol = ? AND port = ? AND family = ? AND cleared_at IS NULL",
            (stamp, host["id"], protocol, port, family))
        con.execute(
            "INSERT INTO port_acknowledgements (host_id, protocol, port, family,"
            " state, account, acknowledged_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (host["id"], protocol, port, family, state, account, stamp))
    return Acknowledgement(host_id=host["id"], host_name=host["name"],
                           protocol=protocol, port=port, family=family,
                           state=state, acknowledged_at=stamp,
                           previous=previous)


def clear_acknowledgement(con: sqlite3.Connection, host_name, protocol, port,
                          family) -> bool:
    """Put a finding back on the list. True when one was live."""
    protocol, port, family = normalise(protocol, port, family)
    host = _host(con, host_name)
    cur = con.execute(
        "UPDATE port_acknowledgements SET cleared_at = ? WHERE host_id = ?"
        " AND protocol = ? AND port = ? AND family = ? AND cleared_at IS NULL",
        (store.now_utc(), host["id"], protocol, port, family))
    con.commit()
    return cur.rowcount == 1


def list_acknowledgements(con: sqlite3.Connection,
                          host_name: str | None = None) -> list[sqlite3.Row]:
    if not _table_exists(con, "port_acknowledgements"):
        return []
    sql = ("SELECT a.*, h.name AS host_name FROM port_acknowledgements a"
           " JOIN hosts h ON h.id = a.host_id WHERE a.cleared_at IS NULL")
    params: list = []
    if host_name is not None:
        sql += " AND a.host_id = ?"
        params.append(_host(con, host_name)["id"])
    sql += " ORDER BY h.name, a.port, a.protocol, a.family"
    return con.execute(sql, params).fetchall()


def acknowledgements_for_host(con: sqlite3.Connection, host_id: int) -> dict:
    """The live acknowledgements for one host, keyed (protocol, port, family)
    to (the state they were given for, when they were given).

    The state travels with the timestamp because the caller has to compare it
    with the state it just decided. An acknowledgement that does not match is
    not applied, and that is the whole of its expiry rule.
    """
    if not _table_exists(con, "port_acknowledgements"):
        return {}
    rows = con.execute(
        "SELECT protocol, port, family, state, acknowledged_at"
        " FROM port_acknowledgements WHERE host_id = ? AND cleared_at IS NULL",
        (host_id,)).fetchall()
    return {(row["protocol"], row["port"], row["family"]):
            (row["state"], row["acknowledged_at"]) for row in rows}


# --------------------------------------------------------------- the first look

def mark_first_look(con: sqlite3.Connection, host_name, *,
                    account: str = DEFAULT_ACCOUNT) -> bool:
    """Record that this server's first-look window has been seen. True the
    first time, False when it was already recorded."""
    host = _writable_host(con, host_name)
    with con:
        cur = con.execute(
            "INSERT OR IGNORE INTO first_looks (host_id, account, seen_at)"
            " VALUES (?, ?, ?)", (host["id"], account, store.now_utc()))
    return cur.rowcount == 1


def first_looks_seen(con: sqlite3.Connection) -> set:
    """The ids of every host whose first look has been seen."""
    return {row[0] for row in con.execute("SELECT host_id FROM first_looks")}
