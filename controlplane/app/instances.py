"""Self-hosted instances that may use our probers, and the keys they hold.

    python -m app.instances_cli add --name freedom
    python -m app.instances_cli list
    python -m app.instances_cli revoke --name freedom

A self-hosted whichports has no prober of its own. It asks the prober API on
this control plane to probe its servers from probe1 and probe2
(`app/proberapi.py`), and this file is who is allowed to ask. An instance
exists because the owner added it by hand, or, since the owner opened the
beta on 26 October 2026, because somebody's installer signed up for one and
they typed the code we mailed them (`app/instancesignup.py`). Nothing else
makes one.

## Two keys per instance, and why not one

**The API key** sits on the instance's own control plane, in one environment
file. It sends batches and reads their answers.

**The proof key** sits on every one of the instance's servers, in the agent's
configuration, and does exactly one thing: it lets an agent prove to us the
address its request arrived from (`authz.record_presence_claim`). A proof key
that leaks from one server lets whoever took it prove an address they send
from themselves, which is an address they hold, and nothing else. It cannot
send a batch, read an answer or see a proof. Keeping it apart from the API
key is what makes a key copied onto every server cheap to lose.

Both are shown once and only their SHA-256 is stored, the same posture as a
host credential in `app/store.py`: a copy of the database holds nothing that
can send a batch or prove an address. Each has its own prefix so a leaked key
says what it is, and so neither can be mistaken for a host credential
(`whp_`) or a proof token (`whpa_`). **The prefix is for people. What a key
may do is decided by the `kind` on its row**, never by how it is spelled.

## How an instance was made

**Each instance records it, since 2026-10-20** (`docs/PRODUCT.md` 5, the
clauses of that day): `invited` when the owner added it by hand, `signup`
when a stranger made it for themself through the open signup.
Only an invited instance's agents prove by presence
(`authz.proves_by_presence`), because presence proves a shared address for
whoever sends from it. A signup instance proves by DNS TXT or a token file.
`add` writes the word on every row and takes it from its caller with no
default, and a row with any other value, or none, does not prove by
presence.

## The address of an instance that signed up

An instance a stranger made through the open signup keeps the address its
code was mailed to (`app/instancesignup.py`), in `contact_email`, and nothing
else of theirs. It is what holds one live instance to one address, and the
one way to reach whoever runs it when an abuse report names it. It is kept
while the instance is live and for `CONTACT_KEPT_AFTER_REVOKE` after its
revoke, then the sweep empties it (`forget_contacts`). The instance's name
holds nothing of it. An instance made by hand has none.

## Revoking

Revoking an instance ends both keys at once and closes every authorisation
its account holds (`authz.revoke_account`). A key
that is revoked and a key that never existed get the same refusal from the
API, so a 401 never confirms that a key was once real. Rows are kept, not
deleted: they are the record of who could probe what, and when, which is what
an abuse report to one of our providers needs answered.
"""

import dataclasses
import hashlib
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from . import authz, db

KIND_API = "api"
KIND_PROOF = "proof"
KINDS = (KIND_API, KIND_PROOF)

PREFIXES = {KIND_API: "whpi_", KIND_PROOF: "whpp_"}

# The same shape a vantage name has (app/vantages.py): it is printed in the
# CLI and in the abuse log, so it is restricted here rather than escaped later.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# How long an instance that signed up keeps its address after its revoke.
# Thirty days, the first guess of docs/SPEC-open-beta.md. Longer is the
# owner's call.
CONTACT_KEPT_AFTER_REVOKE = timedelta(days=30)

# A key is a prefix and 64 hex characters. Anything longer is not a key, and
# refusing it before hashing keeps a megabyte header from being hashed at all.
MAX_KEY_LENGTH = 128

SCHEMA = """
CREATE TABLE IF NOT EXISTS probe_instances (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS probe_instance_keys (
    id          INTEGER PRIMARY KEY,
    instance_id INTEGER NOT NULL REFERENCES probe_instances(id),
    kind        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_probe_instance_keys_instance
    ON probe_instance_keys(instance_id);
"""


class InstanceError(ValueError):
    """Refused. The message is for a person at a terminal and names what to fix."""


@dataclasses.dataclass(frozen=True)
class Instance:
    id: int
    name: str
    created_at: str
    revoked_at: str | None
    # How it was made, `authz.ORIGINS`. None reads as not invited.
    origin: str | None = None

    @property
    def account(self) -> str:
        """The account this instance's proofs are recorded under. Derived,
        never stored or passed, so no caller can hand in another's."""
        return authz.account_for_instance(self.id)

    @property
    def proves_by_presence(self) -> bool:
        """Whether its agents' presence may prove an address. Decided by the
        registry from the word on this row, never by a request."""
        return authz.proves_by_presence(self.origin)


@dataclasses.dataclass(frozen=True)
class Issued:
    """An instance and its two keys, returned once. The keys exist here and on
    the terminal that printed them, never in the database."""
    instance: Instance
    api_key: str
    proof_key: str


# A column added after first release, the way `db.init` adds one: SQLite has
# no ADD COLUMN IF NOT EXISTS, so the duplicate-column error is the
# idempotence check. The first request after the deploy that carries it is
# the one that adds the column, and that request takes the write lock for it.
#
# `last_used_at` is when the API key last passed the check every prober API
# route makes: the heartbeat of a self-hosted instance on the admin console
# (docs/screens/admin/SPEC.md, his level 2 of docs/record 4.425). A timestamp
# and nothing else, on the API key's row only.
ADDED_COLUMNS = ("last_used_at TEXT",)

# The address an instance that signed up keeps (the section of the module
# docstring above). Written as (table, column) the way `db.py` writes its
# own, so a test that looks for every column holding a mail address finds
# this one too. And when the sweep ended a signup instance for sending no
# batch and making no proof (`instancesignup.UNUSED_FOR`), which a revoke by
# hand leaves empty.
ADDED_INSTANCE_COLUMNS = (("probe_instances", "contact_email TEXT"),
                          ("probe_instances", "ended_unused_at TEXT"))


def init(con: sqlite3.Connection) -> None:
    """Idempotent and additive, the same rule every other init follows."""
    con.executescript(SCHEMA)
    for column in ADDED_COLUMNS:
        try:
            con.execute(f"ALTER TABLE probe_instance_keys ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    con.commit()
    # A read on every call, and the write lock only on the first call ever.
    if not _has_origin(con):
        _add_origin(con)
    for table, column in ADDED_INSTANCE_COLUMNS:
        if not _has_column(con, column.split()[0]):
            try:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
            except sqlite3.OperationalError as exc:
                if "duplicate column" not in str(exc):
                    raise
            con.commit()


def _has_column(con: sqlite3.Connection, column: str) -> bool:
    return column in {row[1] for row in
                      con.execute("PRAGMA table_info(probe_instances)")}


def _has_origin(con: sqlite3.Connection) -> bool:
    return _has_column(con, "origin")


def _add_origin(con: sqlite3.Connection) -> None:
    """Add how an instance was made, and write `invited` on every instance
    that exists when the column arrives, in one transaction.

    Every one of them was added by hand with `instances_cli add`, because
    there has never been another way to make one, so `invited` is what they
    are. Written in the same transaction as the column, because a row the
    column reaches with nothing on it reads as not invited, and an invited
    instance whose agents could no longer prove would stop being probed
    within the hour. A row written after this, which `add` never leaves
    blank, is not touched by it. The question is asked again once the write
    lock is held, for the process that waited for it.
    """
    con.execute("BEGIN IMMEDIATE")
    try:
        if not _has_origin(con):
            con.execute("ALTER TABLE probe_instances ADD COLUMN origin TEXT")
            con.execute("UPDATE probe_instances SET origin = ? WHERE origin IS NULL",
                        (authz.ORIGIN_INVITED,))
    except BaseException:
        con.rollback()
        raise
    con.commit()


# How often a key's use is stamped at most. An instance's worker asks every
# fifteen minutes and a batch comes every ten, so once a minute loses nothing
# the console reads, and a burst of requests costs the write lock once.
STAMP_EVERY_SECONDS = 60

# How long the stamp's own connection waits for the write lock. A busy
# database costs a stamp, never an answer, and never the five seconds the
# routes' own connection would wait.
STAMP_WAIT_SECONDS = 0.05


def instance_and_key_use(con: sqlite3.Connection, key, kind: str):
    """`instance_for_key`'s answer together with when that key was last
    stamped, so a route can decide whether to stamp it from the row it has
    already read and never from a second one. `(None, None)` for every way
    the key is not a live key of this kind."""
    if kind not in KINDS:
        return None, None
    if not isinstance(key, str) or not key or len(key) > MAX_KEY_LENGTH:
        return None, None
    row = con.execute(
        "SELECT i.id, i.name, i.created_at, i.revoked_at, i.origin,"
        " k.last_used_at FROM probe_instance_keys k"
        " JOIN probe_instances i ON i.id = k.instance_id"
        " WHERE k.key_hash = ? AND k.kind = ?"
        "   AND k.revoked_at IS NULL AND i.revoked_at IS NULL",
        (key_hash(key), kind)).fetchone()
    if row is None:
        return None, None
    return _instance(row), row[5]


def stamp_due(last_used_at, now: datetime | None = None) -> bool:
    """Whether a key with this stamp is stamped again now: never within a
    minute of the last one."""
    if not last_used_at:
        return True
    try:
        then = datetime.fromisoformat(last_used_at)
    except ValueError:
        return True
    moment = now or datetime.now(timezone.utc)
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (moment - then).total_seconds() >= STAMP_EVERY_SECONDS


def stamp_api_key_use(db_path: str, key: str, now: datetime | None = None) -> bool:
    """Write the API key's last use, on a connection of its own.

    Not the route's connection: the route's commit or rollback then says
    nothing about the stamp, and a read route that takes no write lock today
    still takes none. The wait is a twentieth of a second and a locked
    database is dropped, so the stamp can neither fail nor slow a request.
    Returns whether it was written. The API key only: a proof key is never
    stamped.
    """
    try:
        own = sqlite3.connect(db_path, timeout=STAMP_WAIT_SECONDS)
    except sqlite3.OperationalError:
        return False
    try:
        # Not a connection from `db.connect`, and it writes, so it sets the
        # same two settings itself (docs/RECORD.md 4.444). Neither waits for
        # a lock, so the stamp is no slower for them.
        db.forget_what_is_deleted(own)
        own.execute(
            "UPDATE probe_instance_keys SET last_used_at = ?"
            " WHERE key_hash = ? AND kind = ? AND revoked_at IS NULL",
            (_now(now), key_hash(key), KIND_API))
        own.commit()
        return True
    except sqlite3.OperationalError:
        return False
    finally:
        own.close()


def _now(now: datetime | None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()


def new_key(kind: str) -> str:
    return PREFIXES[kind] + secrets.token_hex(32)


def key_hash(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def check_name(name) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name.strip()):
        raise InstanceError(
            "an instance name is lowercase letters, digits, dot, dash and"
            " underscore, starting with a letter or digit, at most 64"
            f" characters. {name!r} is not")
    return name.strip()


_COLUMNS = "id, name, created_at, revoked_at, origin"


def _instance(row) -> Instance:
    """From a row of `_COLUMNS`, read by position, so a connection with no
    row factory reads it the same."""
    return Instance(id=row[0], name=row[1], created_at=row[2],
                    revoked_at=row[3], origin=row[4])


def _insert_key(con, instance_id: int, kind: str, stamp: str) -> str:
    key = new_key(kind)
    con.execute(
        "INSERT INTO probe_instance_keys (instance_id, kind, key_hash, created_at)"
        " VALUES (?, ?, ?, ?)", (instance_id, kind, key_hash(key), stamp))
    return key


def add(con: sqlite3.Connection, name: str, now: datetime | None = None, *,
        origin: str, contact: str | None = None, commit: bool = True) -> Issued:
    """One instance with a fresh key of each kind. Every check runs before the
    first write, so a refused add leaves nothing behind.

    `origin` is how it was made, and it has no default, so no caller makes
    an instance without saying how. `instances_cli add`, by hand, passes
    `authz.ORIGIN_INVITED`. Anything a stranger reaches, a signup or a keys
    page, passes `authz.ORIGIN_SIGNUP` unless the owner decides otherwise,
    and its agents then never prove by presence.

    `contact` is the address a signup's code went to, already checked by
    its caller, written in the same insert so an instance that signed up
    never exists without it. A commit at the end, as always: a caller that
    began a transaction of its own has its writes committed with this one.
    `commit=False` leaves the commit to that caller, for a write of its own
    that names the new instance and must land in the same commit
    (`instancesignup.collect`, the claim that made it).
    """
    name = check_name(name)
    if not isinstance(origin, str) or origin not in authz.ORIGINS:
        raise InstanceError(
            f"an instance is made by one of {', '.join(authz.ORIGINS)}, not {origin!r}")
    if by_name(con, name) is not None:
        raise InstanceError(f"an instance called {name!r} already exists")
    stamp = _now(now)
    cur = con.execute(
        "INSERT INTO probe_instances (name, created_at, origin, contact_email)"
        " VALUES (?, ?, ?, ?)", (name, stamp, origin, contact))
    instance_id = cur.lastrowid
    api_key = _insert_key(con, instance_id, KIND_API, stamp)
    proof_key = _insert_key(con, instance_id, KIND_PROOF, stamp)
    if commit:
        con.commit()
    return Issued(by_name(con, name), api_key, proof_key)


def reissue(con: sqlite3.Connection, name: str, kind: str,
            now: datetime | None = None) -> str:
    """Replace one key of a live instance. The old key of that kind stops
    working in the same transaction, so there is never a moment with two.

    **A new proof key reaches no agent by itself.** Agents that still hold the
    old one stop proving, and their addresses lapse an hour after the last
    proof (`authz.HOUR_TTL_SECONDS`), so reissuing it means re-enrolling
    the instance's servers. The CLI says so when it prints the key.
    """
    if kind not in KINDS:
        raise InstanceError(f"a key is one of {', '.join(KINDS)}, not {kind!r}")
    instance = _require_live(con, name)
    stamp = _now(now)
    con.execute(
        "UPDATE probe_instance_keys SET revoked_at = ?"
        " WHERE instance_id = ? AND kind = ? AND revoked_at IS NULL",
        (stamp, instance.id, kind))
    key = _insert_key(con, instance.id, kind, stamp)
    con.commit()
    return key


def reissue_both(con: sqlite3.Connection, name: str,
                 now: datetime | None = None) -> Issued:
    """Replace both keys of a live instance in one commit, so whoever held
    the old pair loses it the moment the new pair exists, and there is never
    one key of each. The open signup's recollect uses it
    (`instancesignup.collect`). A caller that began a transaction of its own
    has its writes committed with this one, as with `add`."""
    instance = _require_live(con, name)
    stamp = _now(now)
    con.execute(
        "UPDATE probe_instance_keys SET revoked_at = ?"
        " WHERE instance_id = ? AND revoked_at IS NULL", (stamp, instance.id))
    api_key = _insert_key(con, instance.id, KIND_API, stamp)
    proof_key = _insert_key(con, instance.id, KIND_PROOF, stamp)
    con.commit()
    return Issued(instance, api_key, proof_key)


def revoke(con: sqlite3.Connection, name: str, now: datetime | None = None, *,
           unused: bool = False) -> Instance:
    """End an instance: both keys, every authorisation it holds, and whatever
    it had queued. Returns the revoked instance. Revoking twice is refused
    rather than repeated, so the stamp keeps saying when it first happened.

    `unused` is the sweep's, for a signup instance that sent no batch and
    made no proof (`instancesignup.end_unused`). It is written down, because
    an address whose instance was revoked by hand may not sign up again
    while its address is kept, and one that ended unused may."""
    instance = _require_live(con, name)
    moment = now or datetime.now(timezone.utc)
    stamp = _now(moment)
    con.execute("UPDATE probe_instances SET revoked_at = ?, ended_unused_at = ?"
                " WHERE id = ?", (stamp, stamp if unused else None, instance.id))
    con.execute(
        "UPDATE probe_instance_keys SET revoked_at = ?"
        " WHERE instance_id = ? AND revoked_at IS NULL", (stamp, instance.id))
    con.commit()
    authz.revoke_account(con, instance.account, now=moment)
    return by_name(con, name)


def _require_live(con, name: str) -> Instance:
    instance = by_name(con, check_name(name))
    if instance is None:
        raise InstanceError(f"no instance called {name!r}")
    if instance.revoked_at:
        raise InstanceError(f"{name!r} was revoked at {instance.revoked_at}")
    return instance


# ------------------------------------------------------------------ reading

def by_name(con: sqlite3.Connection, name: str) -> Instance | None:
    row = con.execute(f"SELECT {_COLUMNS} FROM probe_instances WHERE name = ?",
                      (name,)).fetchone()
    return None if row is None else _instance(row)


def by_id(con: sqlite3.Connection, instance_id: int) -> Instance | None:
    row = con.execute(f"SELECT {_COLUMNS} FROM probe_instances WHERE id = ?",
                      (instance_id,)).fetchone()
    return None if row is None else _instance(row)


def list_all(con: sqlite3.Connection) -> list[Instance]:
    return [_instance(row) for row in
            con.execute(f"SELECT {_COLUMNS} FROM probe_instances ORDER BY name")]


def contact_of(con: sqlite3.Connection, instance_id: int) -> str | None:
    """The address an instance that signed up keeps, or None."""
    row = con.execute("SELECT contact_email FROM probe_instances WHERE id = ?",
                      (instance_id,)).fetchone()
    return None if row is None else row[0]


def address_taken(con: sqlite3.Connection, email: str) -> bool:
    """Whether this address may not sign up for another instance: it has a
    live one, or one the owner revoked by hand whose address is still kept
    (`CONTACT_KEPT_AFTER_REVOKE`), decided 27 October 2026. An instance the
    sweep ended for sending no batch and making no proof does not hold it."""
    return con.execute(
        "SELECT 1 FROM probe_instances WHERE contact_email = ?"
        " AND (revoked_at IS NULL OR ended_unused_at IS NULL) LIMIT 1",
        (email,)).fetchone() is not None


def live_count(con: sqlite3.Connection, origin: str) -> int:
    """How many instances made this way are not revoked."""
    return con.execute(
        "SELECT COUNT(*) FROM probe_instances WHERE origin = ?"
        " AND revoked_at IS NULL", (origin,)).fetchone()[0]


def forget_contacts(con: sqlite3.Connection, now: datetime | None = None) -> int:
    """Empty the address of every instance revoked longer ago than
    `CONTACT_KEPT_AFTER_REVOKE`. Returns how many. The instance's row stays,
    as the record of who could probe what. The connections this runs on
    overwrite what they delete (`db.forget_what_is_deleted`)."""
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    # Compared as times and not as text: a stamp with no fraction of a
    # second and one with a fraction do not sort as text by when they are.
    due = []
    for instance_id, revoked_at in con.execute(
            "SELECT id, revoked_at FROM probe_instances"
            " WHERE contact_email IS NOT NULL AND revoked_at IS NOT NULL"):
        try:
            revoked = datetime.fromisoformat(revoked_at)
        except (TypeError, ValueError):
            # A stamp nothing can read: the address goes, the safe way round.
            due.append(instance_id)
            continue
        if revoked.tzinfo is None:
            revoked = revoked.replace(tzinfo=timezone.utc)
        if moment - revoked >= CONTACT_KEPT_AFTER_REVOKE:
            due.append(instance_id)
    for instance_id in due:
        con.execute("UPDATE probe_instances SET contact_email = NULL WHERE id = ?",
                    (instance_id,))
    con.commit()
    return len(due)


def instance_for_key(con: sqlite3.Connection, key, kind: str) -> Instance | None:
    """The live instance this key belongs to, when the key is of this kind.

    None for everything else, and the caller cannot tell which: not text, too
    long, unknown, revoked, belonging to a revoked instance, or a key of the
    other kind. A proof key handed to the batch endpoint is therefore refused
    exactly like a key nobody issued.
    """
    # One query says which key is a live key, and it lives in
    # `instance_and_key_use` since 2026-10-07: a second copy of the sentence
    # the whole API's door rests on could drift from the first.
    found, _used = instance_and_key_use(con, key, kind)
    return found


def key_rows(con: sqlite3.Connection, instance_id: int) -> list[sqlite3.Row]:
    """Every key an instance was ever issued, for the listing. Hashes only."""
    return con.execute(
        "SELECT kind, created_at, revoked_at FROM probe_instance_keys"
        " WHERE instance_id = ? ORDER BY id", (instance_id,)).fetchall()
