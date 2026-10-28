"""Database access for the whichports control plane.

SQLite on purpose, for v1. The fleet is a handful of hosts reporting every
fifteen minutes, and SQLite from the standard library means one file to back
up, no second service to run, and nothing new to patch. The moment this is
wrong (many tenants, many writers) is a visible, deliberate migration, not a
config change. WAL mode is set so the ingest process and the dashboard
process can read and write the same file without blocking each other.

Every fact lives in one of three tables:

    workspaces one row per workspace: the thing a signed-in person sees the
             inside of. Every host and every account belongs to exactly one.
    hosts    one row per enrolled host: its name, the SHA-256 of its
             credential (never the credential itself), when it last
             reported, and the workspace it belongs to. Revocation is a
             timestamp, so it is visible history rather than a deleted row.
    reports  one row per received host document, verbatim. The document is
             evidence and is stored exactly as the agent sent it; conclusions
             are drawn at read time, never at write time.

There is one derived table beside them:

    report_digests  the few hundred bytes of a stored document that the
             dashboard's change detection reads, for one report row. A stored
             document is never edited (PRODUCT.md 4e), so this can be computed
             once instead of on every page load. It is a cache and holds no
             fact of its own: every row can be deleted and the next render
             rebuilds it from the documents. `version` is what the renderer
             computed it with, and a row from another version is ignored
             rather than served, because a cache handing back an old format is
             worse than no cache. `site/app/render_live.py` owns the format
             and the version, and this file owns the table.

## Where scoping happens, and why it is only here

**Everything hangs off `hosts` by `host_id`, so scoping happens at `hosts`.**
Services, rules, findings, intents, authorisations, silences and stored
documents all reach a host row and none of them carries a workspace of its
own. A read is correct when it cannot reach a host row outside the caller's
workspace, which is one column in one WHERE clause rather than a column
repeated on nine tables that could disagree with each other.

The reads that take a workspace are the ones a signed-in person drives. The
background jobs (the dead-man sweep, the finding alerts, the prober dispatch,
the ingest) run with no session at all and stay fleet-wide on purpose: a sweep
scoped to a workspace nobody is signed in to would stop watching every other
workspace's hosts.
"""

import os
import sqlite3
from datetime import datetime, timezone

# Owned by `app/workspace.py` and re-exported here, because every caller in the
# control plane reaches for `db.DEFAULT_WORKSPACE_ID` and there is no reason to
# make them all learn a new name. That file says why the owner is not this one:
# `app/authz.py` needs the same constant and has to stay importable on a box
# with no database.
from .workspace import DEFAULT_WORKSPACE_ID, DEFAULT_WORKSPACE_NAME  # noqa: F401

# The dashboard and the CLI resolve the same environment variable, so all
# three processes agree on the file without any of them passing paths around.
DB_ENV = "WHICHPORTS_DB"
DEFAULT_DB = "whichports.db"

HOST_KIND_AGENT = "agent"
HOST_KIND_ADDRESS = "address"
HOST_KINDS = (HOST_KIND_AGENT, HOST_KIND_ADDRESS)

# The hosts table, written once. The rebuild below has to create the same
# table under a temporary name, and until this was one string it was two: the
# copy in SCHEMA and a second one for the rebuild, which is how one fact
# drifts into two. A CHECK added to one of two copies is a CHECK that
# holds on a fresh database and not on an upgraded one.
#
# **The CHECK is the invariant rather than a comment about it.** An agent host
# enrols with a credential and an address host has none, and until this
# existed the table accepted an agent host with no credential, an address host
# holding one, and a kind nobody defined. Those three were measured, not
# feared. `store.py` still writes the right thing, and now the database
# refuses the wrong thing rather than trusting every INSERT ever written
# against it.
HOSTS_TABLE_BODY = """(
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT UNIQUE,
    kind        TEXT NOT NULL DEFAULT 'agent',
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    last_report_at TEXT,
    paused      INTEGER NOT NULL DEFAULT 0,
    auto_named  INTEGER NOT NULL DEFAULT 0,
    workspace_id INTEGER NOT NULL DEFAULT 1,
    CHECK ((kind = 'agent'   AND token_hash IS NOT NULL)
        OR (kind = 'address' AND token_hash IS NULL))
)"""

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS workspaces (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts {HOSTS_TABLE_BODY};

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts(id),
    received_at     TEXT NOT NULL,
    collected_at_unix INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL,
    document        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_host_received
    ON reports(host_id, received_at DESC);

CREATE TABLE IF NOT EXISTS report_digests (
    report_id INTEGER PRIMARY KEY REFERENCES reports(id),
    version   TEXT NOT NULL,
    digest    TEXT NOT NULL
);
"""

# Created after the ALTER below, never inside SCHEMA. On a database that
# predates workspaces the hosts table already exists, so `CREATE TABLE IF NOT
# EXISTS` no-ops and the column is not there yet: an index over it inside the
# same script fails with "no such column" and takes the whole init down. The
# order is the fix and the reason it is written here is that nothing about the
# statement itself shows it.
WORKSPACE_INDEX = ("CREATE INDEX IF NOT EXISTS idx_hosts_workspace"
                   " ON hosts(workspace_id, name)")


def db_path() -> str:
    return os.environ.get(DB_ENV, DEFAULT_DB)


def connect(path: str | None = None) -> sqlite3.Connection:
    """One connection per request or per CLI invocation. Short-lived
    connections keep locking simple and correct; at this scale the open cost
    is irrelevant."""
    con = sqlite3.connect(path or db_path())
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    # WAL lets the dashboard read while the ingest writes. The busy timeout
    # means a moment of contention waits briefly instead of erroring.
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA busy_timeout = 5000")
    forget_what_is_deleted(con)
    return con


def forget_what_is_deleted(con: sqlite3.Connection) -> None:
    """Two settings for every connection that writes to this database, so
    that a deleted row's bytes go when the row goes (docs/RECORD.md 4.444).

    A delete in SQLite takes the row away and leaves its bytes where they
    were until something else is written over them. A queued probe batch is
    kept fifteen minutes at most (`proberapi.BATCH_TTL_SECONDS`), and the
    nightly backup copies the file as it is, so the bytes have to go too.

      - `secure_delete = ON`: SQLite writes zeros over what a delete frees.
        Some distributions build SQLite to do this by itself and others do
        not, and what is kept here must not rest on how a library was built.
      - `journal_size_limit = 0`: the -wal file beside the database is cut
        back every time SQLite starts it over. Left alone it keeps its
        longest length for good, and a batch written while it was long sat
        in its tail for as long as anybody counted.

    **Both belong to the connection and not to the file**, so nothing is
    switched on once and for all: each connection sets them, also the two
    that open the file by themselves and write (`instances.stamp_api_key_use`
    and the renderer's `store_digests`). Whether the -wal is cut is decided by
    whichever connection writes first after it started over, so one writer
    without the setting is enough to leave a tail.

    Neither statement reads the file or waits for a lock. Measured on
    2026-10-09 with the write lock held by somebody else: both answered at
    once. A connection that only reads deletes nothing and writes nothing to
    the -wal, so the read-only ones are left as they are.

    `tests/test_deleted_bytes.py` counts the bytes.
    """
    con.execute("PRAGMA secure_delete = ON")
    con.execute("PRAGMA journal_size_limit = 0")


def init(con: sqlite3.Connection) -> None:
    """Idempotent: CREATE IF NOT EXISTS only. Schema changes are additive,
    the same rule the host document follows (PRODUCT.md 4e). Columns added
    after first release are ALTERed in below; SQLite has no ADD COLUMN IF
    NOT EXISTS, so the duplicate-column error is the idempotence check.

    **The upgrade to workspaces happens here and needs no manual step.** The
    added column carries `NOT NULL DEFAULT 1`, and SQLite fills every existing
    row with a new column's default as part of the ALTER, so hosts enrolled
    before workspaces existed land in workspace 1 the first time this runs.
    Workspace 1 itself is created just below, so the row those hosts point at
    is there. `app/accounts.py` does the same for existing accounts.

    The added column deliberately carries no REFERENCES clause. SQLite refuses
    to add a column with a foreign key unless its default is NULL, and a
    nullable workspace is exactly what this is not.
    """
    con.executescript(SCHEMA)
    for column in ("paused INTEGER NOT NULL DEFAULT 0",
                   "auto_named INTEGER NOT NULL DEFAULT 0",
                   "workspace_id INTEGER NOT NULL DEFAULT 1",
                   f"kind TEXT NOT NULL DEFAULT '{HOST_KIND_AGENT}'"):
        try:
            con.execute(f"ALTER TABLE hosts ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    if _hosts_needs_rebuild(con):
        _rebuild_hosts_table(con)
    con.execute(WORKSPACE_INDEX)
    ensure_default_workspace(con)
    con.commit()


# ------------------------------------------------ a host without a credential
#
# Since 2026-08-26 a host is either an agent host, which enrols with a
# credential and sends documents, or an address host, which is watched from
# outside only and never sends anything (docs/PRODUCT.md 3a, tier 1, decided
# in docs/RECORD.md 4.104). An address host has no credential, so token_hash
# has to be allowed to be NULL, and the two kinds have to be kept from mixing.
#
# **Why the table is rebuilt rather than altered.** Two reasons, both read
# from <https://www.sqlite.org/lang_altertable.html> on 2026-08-27:
#
#   - the table carries a CHECK constraint tying kind to token_hash, and that
#     page lists what ALTER TABLE can do to an existing table: rename it,
#     rename a column, add a column, drop a column, and set or drop NOT NULL.
#     Adding a table constraint is not on the list, so a CHECK can only arrive
#     with a CREATE TABLE.
#   - dropping NOT NULL by ALTER does exist, and it is recent. That page dates
#     `ALTER TABLE ... ALTER COLUMN DROP NOT NULL` to SQLite 3.53.0
#     (2026-04-09), and we do not control which SQLite the Python on a given
#     box links against. A rebuild works on every version.
#
# An earlier version of this comment said SQLite cannot drop a constraint with
# ALTER, full stop. That is what a rebuild was justified with, and it is false
# as of 3.53.0.
#
# The procedure is the one that page gives under "Making Other Kinds Of Table
# Schema Changes": copy into a new table, drop the old one, rename, put the
# indexes back, check every foreign key still resolves.

HOST_COLUMNS = ("id", "name", "token_hash", "kind", "created_at", "revoked_at",
                "last_report_at", "paused", "auto_named", "workspace_id")


def host_columns(con: sqlite3.Connection) -> set:
    return {row[1] for row in con.execute("PRAGMA table_info(hosts)")}


def _credential_is_required(con: sqlite3.Connection) -> bool:
    """Whether hosts.token_hash still carries NOT NULL. Read from the table
    itself rather than remembered, so the rebuild runs exactly once per
    database and a second init finds nothing to do."""
    for row in con.execute("PRAGMA table_info(hosts)"):
        if row[1] == "token_hash":
            return bool(row[3])
    raise RuntimeError("the hosts table has no token_hash column")


def _kinds_are_checked(con: sqlite3.Connection) -> bool:
    """Whether the table itself refuses a row that mixes the two kinds.

    Read from the CREATE TABLE statement SQLite stores for the table, which is
    a text match and is said out loud because it looks like one. There is no
    pragma that lists CHECK constraints, and the alternative, writing a
    deliberately invalid row and seeing whether it is refused, would mean the
    schema check does a write. This is the boring one.
    """
    row = con.execute("SELECT sql FROM sqlite_schema WHERE type = 'table'"
                      " AND name = 'hosts'").fetchone()
    return bool(row and row[0] and "CHECK" in row[0].upper())


def _hosts_needs_rebuild(con: sqlite3.Connection) -> bool:
    """A database gets one rebuild for both facts if it needs both.

    A box that has never run the address-host code needs the NOT NULL dropped
    and the CHECK added, and does them in one pass. A box that ran the first
    version of this migration already has the nullable column and needs only
    the CHECK, so it rebuilds once more and then never again.
    """
    return _credential_is_required(con) or not _kinds_are_checked(con)


def _rebuild_hosts_table(con: sqlite3.Connection) -> None:
    """Rebuild hosts in the shape HOSTS_TABLE_BODY describes, keeping every
    row and every id.

    Foreign keys are switched off for the copy because reports and
    authorisations reference hosts, and dropping a referenced table with the
    checks on is refused. The pragma is ignored inside a transaction
    (<https://www.sqlite.org/pragma.html#pragma_foreign_keys>: "This pragma is
    a no-op within a transaction"), which is why any open one is committed
    first and the switch sits outside the BEGIN. It is then read back rather
    than assumed. After the rename the children point at the rebuilt table by
    name again, and foreign_key_check proves it before anything is committed.

    **Two things it refuses to do quietly**, because this is the one
    irreversible operation in this file and both failures are invisible:

      - a column it does not carry across stops it. The copy names its
        columns, so a column absent from HOST_COLUMNS would be dropped with
        its data and nothing would say so.
      - the indexes are read before the drop and replayed after the rename
        rather than recreated by name. A lost index is not a wrong answer, so
        nothing fails and nobody finds out.
    """
    con.commit()
    con.execute("PRAGMA foreign_keys = OFF")
    if con.execute("PRAGMA foreign_keys").fetchone()[0]:
        raise RuntimeError(
            "cannot rebuild the hosts table while foreign keys are enforced")
    try:
        con.execute("BEGIN")
        unknown = host_columns(con) - set(HOST_COLUMNS)
        if unknown:
            raise RuntimeError(
                "the hosts table holds columns this migration does not carry"
                f" across: {sorted(unknown)}. Add them to HOST_COLUMNS and to"
                " HOSTS_TABLE_BODY.")
        # `sql IS NOT NULL` skips the indexes UNIQUE creates for itself. They
        # have no statement to replay and come back with the CREATE TABLE.
        saved_indexes = [row[0] for row in con.execute(
            "SELECT sql FROM sqlite_schema WHERE type = 'index'"
            " AND tbl_name = 'hosts' AND sql IS NOT NULL")]
        con.execute(f"CREATE TABLE hosts_rebuilt {HOSTS_TABLE_BODY}")
        columns = ", ".join(HOST_COLUMNS)
        con.execute(f"INSERT INTO hosts_rebuilt ({columns}) SELECT {columns} FROM hosts")
        con.execute("DROP TABLE hosts")
        con.execute("ALTER TABLE hosts_rebuilt RENAME TO hosts")
        for statement in saved_indexes:
            con.execute(statement)
        con.execute(WORKSPACE_INDEX)
        broken = con.execute("PRAGMA foreign_key_check").fetchall()
        if broken:
            raise RuntimeError(f"foreign keys broke during the hosts rebuild: {broken[:3]}")
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    finally:
        con.execute("PRAGMA foreign_keys = ON")


# ------------------------------------------------------------- workspaces

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_default_workspace(con: sqlite3.Connection) -> None:
    """Make sure workspace 1 exists, without ever overwriting it.

    `INSERT OR IGNORE` rather than an upsert on purpose: this runs on every
    init, and a workspace somebody has renamed must not have its name put back
    every time an ingest handles a request.
    """
    con.execute(
        "INSERT OR IGNORE INTO workspaces (id, name, created_at) VALUES (?, ?, ?)",
        (DEFAULT_WORKSPACE_ID, DEFAULT_WORKSPACE_NAME, now_utc()))


def create_workspace(con: sqlite3.Connection, name: str) -> int:
    """A new workspace, returning its id. The name is a label a person reads
    and nothing derives a path or a query from it, so it is only checked for
    being non-empty text."""
    name = (name or "").strip()
    if not name:
        raise ValueError("workspace name is empty")
    cur = con.execute(
        "INSERT INTO workspaces (name, created_at) VALUES (?, ?)",
        (name, now_utc()))
    con.commit()
    return cur.lastrowid


def workspace_by_id(con: sqlite3.Connection, workspace_id: int):
    return con.execute("SELECT * FROM workspaces WHERE id = ?",
                       (workspace_id,)).fetchone()


WORKSPACE_NAME_MAX_CHARS = 80


def rename_workspace(con: sqlite3.Connection, workspace_id: int, name: str) -> bool:
    """Set a workspace's name. A label a person reads, so the only checks are
    a trim and a bound, the same rule a display name has. False when no such
    workspace exists."""
    name = (name or "").strip()
    if not name:
        raise ValueError("A workspace needs a name.")
    if len(name) > WORKSPACE_NAME_MAX_CHARS:
        raise ValueError(f"Use at most {WORKSPACE_NAME_MAX_CHARS} characters.")
    cur = con.execute("UPDATE workspaces SET name = ? WHERE id = ?", (name, workspace_id))
    con.commit()
    return cur.rowcount == 1


def list_workspaces(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM workspaces ORDER BY id").fetchall()
