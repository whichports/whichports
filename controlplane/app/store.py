"""Host and report storage.

The credential design mirrors the agent side (agent/internal/report, and the
decision in docs/PRODUCT.md 4f): the dashboard or the CLI generates
`whp_` + 64 hex characters, shows it exactly once, and only its SHA-256 is
stored. A database copy therefore never contains anything that can post a
report. Lookup is by exact hash through a unique index, the same shape API
key storage takes everywhere.

## Workspaces, and what `workspace_id=None` means here

Every host belongs to one workspace and `app/db.py` explains why scoping
happens at this table and nowhere else. The reads below take an optional
`workspace_id`, and the two values mean different things on purpose:

  - **an integer** is a read on behalf of a signed-in person. It cannot reach
    a host row in another workspace, which is the whole property.
  - **`None` is the whole fleet**, and only a background job may ask for it.
    The dead-man sweep, the finding alerts, the prober dispatch and the ingest
    all run with no session, and a sweep scoped to one workspace would stop
    watching every other workspace's hosts.

`host_for_credential` takes no workspace at all, and that is deliberate: an
agent proves which host it is with its own credential, and a workspace it
could pass would be a workspace it could pass wrongly.

**Host names are unique across the whole database, not per workspace.** That
is the pre-workspace UNIQUE index left alone, so two workspaces cannot both
have a host called `web1`, and a name already taken elsewhere is refused with
the same conflict a name taken in your own workspace gives. Changing it means
rebuilding the table, which is its own decision and its own pull request.
"""

import hashlib
import re
import secrets
import sqlite3
from datetime import datetime, timezone

from . import db

CREDENTIAL_PREFIX = "whp_"

# A host name becomes a DOM id, a URL path segment and a shell argument, so
# it is restricted at the door rather than escaped in three places later.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_credential() -> str:
    return CREDENTIAL_PREFIX + secrets.token_hex(32)


def credential_hash(credential: str) -> str:
    return hashlib.sha256(credential.encode()).hexdigest()


# The name a server carries until its first report names it: "new-" and six
# hex digits. One definition, so `add_host` and `is_placeholder` cannot drift.
_PLACEHOLDER_PREFIX = "new-"
_PLACEHOLDER = re.compile(r"new-[0-9a-f]{6}\Z")


def add_host(con: sqlite3.Connection, name: str | None = None,
             workspace_id: int = db.DEFAULT_WORKSPACE_ID) -> tuple[int, str]:
    """Create a host in one workspace and return (id, credential). The
    credential exists in memory here and on the caller's screen, never in the
    database.

    Without a name the host starts under a placeholder and takes its own
    hostname from the first document that carries a usable one (auto naming).
    A name given here pins it, and so does that first naming: the name is
    the server's ID and does not change afterwards
    (`auto_name_from_hostname`).

    The workspace defaults to 1, which is where every host enrolled before
    workspaces existed was backfilled, so `hosts_cli add` with no `--workspace`
    keeps doing exactly what it did before."""
    auto_named = 0
    if name is None:
        name = _PLACEHOLDER_PREFIX + secrets.token_hex(3)
        auto_named = 1
    else:
        name = checked_name(name)
    if db.workspace_by_id(con, workspace_id) is None:
        raise ValueError(f"there is no workspace {workspace_id}")
    credential = new_credential()
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, kind, created_at, auto_named, workspace_id)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (name, credential_hash(credential), db.HOST_KIND_AGENT, now_utc(),
         auto_named, workspace_id),
    )
    con.commit()
    return cur.lastrowid, credential


def reissue_credential(con: sqlite3.Connection, name: str,
                       workspace_id: int | None = None) -> str:
    """A fresh credential for an agent host that has never reported, replacing
    the one whose install command nobody can see again.

    The add-server window mints the credential when a card is picked and shows
    it once, so a window closed too early leaves a row whose command is gone
    for good (the 2026-08-23 audit, control 3). For a host that has never
    spoken that is recoverable by construction: no agent holds the old
    credential, so replacing the hash breaks nothing and the new command is as
    good as the first.

    **A host that has reported is refused**, with ValueError so the route can
    say why: its agent holds the working credential, and replacing that from a
    screen would silently cut a healthy server off at the next report. The
    same refusal covers a revoked host, whose whole point is that its
    credential stopped working on purpose. An address host or a host in
    another workspace returns None, the same not-found every host route
    answers.
    """
    scope = "" if workspace_id is None else " AND workspace_id = ?"
    params = (name,) if workspace_id is None else (name, workspace_id)
    row = con.execute(
        "SELECT id, kind, revoked_at, last_report_at FROM hosts"
        " WHERE name = ?" + scope, params).fetchone()
    if row is None or row["kind"] != db.HOST_KIND_AGENT:
        return None
    if row["revoked_at"]:
        raise ValueError("this server is revoked. Add a new server instead")
    if row["last_report_at"]:
        raise ValueError(
            "this server has reported, so its agent holds a working"
            " credential and it stays. To replace it, remove the server and"
            " add it again")
    credential = new_credential()
    con.execute("UPDATE hosts SET token_hash = ? WHERE id = ?",
                (credential_hash(credential), row["id"]))
    con.commit()
    return credential


def checked_name(name: str) -> str:
    """The one host name rule, so an address host and an agent host cannot
    drift apart on what a name may be."""
    name = name.strip()
    if not name:
        raise ValueError("host name is empty")
    if not NAME_RE.match(name):
        raise ValueError("host name: lowercase letters, digits, - and _, "
                         "starting with a letter or digit, at most 32 characters")
    return name


def add_address_host(con: sqlite3.Connection, name: str,
                     workspace_id: int = db.DEFAULT_WORKSPACE_ID) -> int:
    """Create a server that is watched from outside only and returns its id.

    It has no credential, because nothing on it will ever report: the agent
    is not installed there, by the operator's choice (docs/PRODUCT.md 3a,
    tier 1). What it can be probed on comes from the addresses the operator
    proves control of, recorded in `app/authz.py`, never from a document.
    A name is required, since there is no hostname to take one from later.
    """
    name = checked_name(name)
    if db.workspace_by_id(con, workspace_id) is None:
        raise ValueError(f"there is no workspace {workspace_id}")
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, kind, created_at, auto_named, workspace_id)"
        " VALUES (?, NULL, ?, ?, 0, ?)",
        (name, db.HOST_KIND_ADDRESS, now_utc(), workspace_id),
    )
    con.commit()
    return cur.lastrowid


def _workspace_clause(workspace_id: int | None) -> tuple[str, tuple]:
    """The extra WHERE fragment and its parameters for one workspace.

    `None` adds nothing, which is the whole fleet. An integer adds the one
    column that decides what a signed-in person can reach. This is one helper
    rather than the same two lines written out in six queries, because six
    copies are six places one of them can be left out.
    """
    if workspace_id is None:
        return "", ()
    return " AND workspace_id = ?", (workspace_id,)


def is_placeholder(name: str) -> bool:
    """Whether a name is one `add_host` made up for a server nobody named."""
    return _PLACEHOLDER.match(name) is not None


def auto_name_from_hostname(con: sqlite3.Connection, host_id: int, hostname: str) -> None:
    """Name a server by the hostname its own document carries, once, and pin
    it. The name is the server's ID: the one in the address, in a command and
    in the remove window.

    Decided 2026-10-03 (`docs/RECORD.md` 4.298): the ID is what the agent
    first says, and a constant. Until that day this ran on every
    report and left `auto_named` at 1, so the ID was what the agent last
    said: a server whose hostname changed got a new ID on its next report.
    Now the update that names a server clears the flag in the same statement.

    Three cases:

    - A server still under its placeholder takes the hostname, made
      fleet-safe: lowered, foreign characters replaced, deduplicated with a
      numeric suffix. That is its ID from then on.
    - A hostname that yields nothing usable leaves the placeholder and the
      flag as they are, so a later report with a usable hostname still names
      the server, once.
    - A server that an earlier report already named, before naming pinned,
      keeps the name it carries and is pinned under it. The hostname in this
      report does not rename it, even when it changed since: one more change
      of address is what nobody asked for.
    """
    row = con.execute(
        "SELECT name FROM hosts WHERE id = ? AND auto_named = 1", (host_id,)).fetchone()
    if row is None:
        return
    if not is_placeholder(row["name"]):
        con.execute("UPDATE hosts SET auto_named = 0 WHERE id = ? AND auto_named = 1",
                    (host_id,))
        con.commit()
        return
    derived = "".join(
        c if c.isascii() and (c.isalnum() or c in "-_") else "-"
        for c in hostname.lower()).strip("-_")[:32]
    if not derived or not NAME_RE.match(derived):
        return
    for candidate in [derived] + [f"{derived[:29]}-{i}" for i in range(2, 10)]:
        taken = con.execute(
            "SELECT id FROM hosts WHERE name = ? AND id != ?", (candidate, host_id)
        ).fetchone()
        if taken is None:
            con.execute(
                "UPDATE hosts SET name = ?, auto_named = 0 WHERE id = ? AND auto_named = 1",
                (candidate, host_id),
            )
            con.commit()
            return


def host_for_credential(con: sqlite3.Connection, credential: str) -> sqlite3.Row | None:
    """The ingest auth check. A revoked host does not match, so revocation is
    immediate and needs no separate state on the agent side."""
    # An address host stores NULL, and NULL never equals anything in SQL, so
    # it could not match anyway. Said out loud rather than relied on: the one
    # row without a credential must never be the row a credential unlocks.
    return con.execute(
        "SELECT * FROM hosts WHERE token_hash = ? AND token_hash IS NOT NULL"
        " AND revoked_at IS NULL",
        (credential_hash(credential),),
    ).fetchone()


def revoke_host(con: sqlite3.Connection, name: str,
                workspace_id: int | None = None) -> bool:
    scope, params = _workspace_clause(workspace_id)
    cur = con.execute(
        "UPDATE hosts SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL" + scope,
        (now_utc(), name) + params,
    )
    con.commit()
    return cur.rowcount == 1


def pause_host(con: sqlite3.Connection, name: str, paused: bool,
               workspace_id: int | None = None) -> bool:
    """The monitoring pause from PRODUCT.md 4c: it will suppress only the
    silence alert once alerting exists, and a paused host shows as paused,
    never as healthy. Documents keep arriving and keep being stored."""
    scope, params = _workspace_clause(workspace_id)
    cur = con.execute(
        "UPDATE hosts SET paused = ? WHERE name = ? AND revoked_at IS NULL" + scope,
        (1 if paused else 0, name) + params,
    )
    con.commit()
    return cur.rowcount == 1


def prune_never_reported(con: sqlite3.Connection,
                         workspace_id: int | None = None) -> list[str]:
    """Delete every agent host that has never reported, and return their
    names. This is the cleanup for the ghost rows the add-server window
    leaves: it POSTs a host the moment a card is picked, so a window closed
    before the agent is enrolled leaves a permanent `new-XXXXXX` row nobody
    can use (the 2026-08-23 audit, control 3; measured on the fleet
    2026-08-30 at thirteen).

    **Only a never-reported agent host, and delete rather than revoke.** A
    host that has ever reported is left alone: it has stored documents,
    findings and history that a delete would orphan, and its agent holds a
    working credential. A never-reported one has no document and no
    finding, so the row can go rather than linger as a revoked ghost.
    Address hosts are left alone too: they carry proofs, and `no proof` is a
    real state to act on, not litter.

    A host with any report is excluded by the WHERE, and the test deletes one
    with a report present to prove it stays.
    """
    scope, params = _workspace_clause(workspace_id)
    rows = con.execute(
        "SELECT id, name FROM hosts"
        " WHERE last_report_at IS NULL AND revoked_at IS NULL"
        " AND kind = ?" + scope,
        (db.HOST_KIND_AGENT,) + params).fetchall()
    # Its rows first, from every table that can hold one, then the host. Until
    # 2026-09-15 this deleted the host row alone on the belief that a host
    # which never reported has nothing referencing it, and the box refused
    # with "FOREIGN KEY constraint failed": the probe lanes give every host a
    # run row whether or not it ever reported. One transaction for the whole
    # prune, rolled back whole on any error, like delete_host.
    present = _tables_present(con)
    try:
        for row in rows:
            _delete_rows_of(con, row["id"], present)
            con.execute("DELETE FROM hosts WHERE id = ?", (row["id"],))
        con.commit()
    except sqlite3.Error:
        con.rollback()
        raise
    return [r["name"] for r in rows]


# Every table that can hold a row of one host's, and the order they empty
# in: a child before the table it points at, because foreign keys are on
# (`db.connect`) and nothing cascades. The WHERE names the host's rows and
# the one parameter is the host's id.
#
# A table that references hosts and is not named here makes `delete_host`
# fail with an IntegrityError rather than leave rows pointing at nothing,
# and `tests/test_delete_host.py` walks the schema's foreign keys and every
# `host_id` column, so a table added later is named here before it can
# orphan anything. `authz_challenges.host_id` carries no REFERENCES clause,
# because it arrived through ALTER TABLE, which cannot add one; the walk
# finds it by its name.
HOST_TABLES = (
    # Before probe_results, which it points at: a result the newest-result
    # table still names cannot be deleted (`prober.LATEST_SCHEMA`).
    ("probe_latest", "host_id = ?"),
    ("probe_results", "run_id IN (SELECT id FROM probe_runs WHERE host_id = ?)"),
    ("probe_tls", "run_id IN (SELECT id FROM probe_runs WHERE host_id = ?)"),
    ("probe_runs", "host_id = ?"),
    ("report_digests", "report_id IN (SELECT id FROM reports WHERE host_id = ?)"),
    ("reports", "host_id = ?"),
    ("finding_states", "host_id = ?"),
    ("finding_changes", "host_id = ?"),
    ("alert_deliveries", "alert_id IN (SELECT id FROM alerts WHERE host_id = ?)"),
    ("silence_told", "alert_id IN (SELECT id FROM alerts WHERE host_id = ?)"),
    ("alerts", "host_id = ?"),
    ("alert_silences", "host_id = ?"),
    ("port_intents", "host_id = ?"),
    ("port_acknowledgements", "host_id = ?"),
    ("port_names", "host_id = ?"),
    ("first_looks", "host_id = ?"),
    ("host_tags", "host_id = ?"),
    ("host_display_names", "host_id = ?"),
    ("rarely_dismissed", "host_id = ?"),
    ("authorizations", "host_id = ?"),
    ("authz_challenges", "host_id = ?"),
    ("scan_requests", "host_id = ?"),
    # What the CVE check has looked at and told for this server
    # (`app/cvetell.py`). A batch names its servers as text and stays.
    ("cve_started", "host_id = ?"),
    ("cve_told", "host_id = ?"),
    # The CVEs a person dismissed the check's mark for (`app/cvedismiss.py`).
    ("cve_dismissed", "host_id = ?"),
)


def delete_host(con: sqlite3.Connection, name: str,
                workspace_id: int | None = None) -> bool:
    """Delete a removed host with every row stored about it, and say whether
    one went.

    Only a host that Remove has already revoked. A live server's documents,
    findings, proofs, declarations and outside measurements go with a
    second act behind a second typed name, never with the first (the owner,
    2026-09-13, docs/RECORD.md 4.179). Unknown, still live and another
    workspace's all return False, the same three-way silence
    active_host_by_name keeps, so this is no way to ask which names exist.

    All or nothing. The deletes run in one transaction and any error from
    one of them, an IntegrityError from a table HOST_TABLES does not know
    included, rolls every one back: the host is gone with all of its rows
    or exactly as it was.
    """
    row = removed_host_by_name(con, name, workspace_id)
    if row is None:
        return False
    host_id = row["id"]
    try:
        _delete_rows_of(con, host_id, _tables_present(con))
        con.execute("DELETE FROM hosts WHERE id = ?", (host_id,))
        con.commit()
    except sqlite3.Error:
        con.rollback()
        raise
    return True


def removed_host_by_name(con: sqlite3.Connection, name: str,
                         workspace_id: int | None = None) -> sqlite3.Row | None:
    """The removed host `delete_host` would delete, or None. Unknown, still
    live and another workspace's all return None."""
    scope, params = _workspace_clause(workspace_id)
    return con.execute(
        "SELECT * FROM hosts WHERE name = ? AND revoked_at IS NOT NULL" + scope,
        (name,) + params).fetchone()


def _tables_present(con: sqlite3.Connection) -> set[str]:
    """A table this database never created holds nothing of any host's: a
    module's init runs only where that module is used, so a fresh or a
    trimmed database can lack some of them."""
    return {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def _delete_rows_of(con: sqlite3.Connection, host_id: int, present: set[str]) -> None:
    """Every row of one host's from HOST_TABLES, children first. The caller
    owns the transaction and deletes the host row after."""
    for table, where in HOST_TABLES:
        if table in present:
            con.execute(f"DELETE FROM {table} WHERE {where}", (host_id,))


def list_hosts(con: sqlite3.Connection,
               workspace_id: int | None = None) -> list[sqlite3.Row]:
    """Every host, or every host in one workspace. `None` is the fleet and only
    a background job asks for it, which the module docstring spells out."""
    scope, params = _workspace_clause(workspace_id)
    return con.execute(
        "SELECT * FROM hosts WHERE 1 = 1" + scope + " ORDER BY name",
        params).fetchall()


def active_host_by_name(con: sqlite3.Connection, name: str,
                        workspace_id: int | None = None) -> sqlite3.Row | None:
    """The host with this name that we still accept, or None. Revoked, unknown
    and belonging to another workspace all return None, so a caller 404s them
    identically, the same way revoke_host and pause_host refuse them.

    That the three are indistinguishable is the point. Answering differently
    for "that host is somebody else's" would turn this into a way to ask which
    names exist in other workspaces."""
    scope, params = _workspace_clause(workspace_id)
    return con.execute(
        "SELECT * FROM hosts WHERE name = ? AND revoked_at IS NULL" + scope,
        (name,) + params,
    ).fetchone()


def host_by_id(con: sqlite3.Connection, host_id: int,
               workspace_id: int | None = None) -> sqlite3.Row | None:
    """The host with this id, revoked or not, or None. The scan drain reads it
    to name a host and to see whether it was revoked after the request landed,
    and it is a background job, so it passes no workspace."""
    scope, params = _workspace_clause(workspace_id)
    return con.execute(
        "SELECT * FROM hosts WHERE id = ?" + scope, (host_id,) + params
    ).fetchone()


def insert_report(
    con: sqlite3.Connection,
    host_id: int,
    collected_at_unix: int,
    schema_version: int,
    document: str,
) -> None:
    """One transaction for the report row and the freshness stamp, so the
    fleet view can never show a host as reporting without its report existing."""
    received_at = now_utc()
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix,"
        " schema_version, document) VALUES (?, ?, ?, ?, ?)",
        (host_id, received_at, collected_at_unix, schema_version, document),
    )
    con.execute(
        "UPDATE hosts SET last_report_at = ? WHERE id = ?",
        (received_at, host_id),
    )
    con.commit()


def latest_report(con: sqlite3.Connection, host_id: int) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM reports WHERE host_id = ?"
        " ORDER BY received_at DESC, id DESC LIMIT 1",
        (host_id,),
    ).fetchone()
