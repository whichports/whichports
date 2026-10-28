"""Erase one account, its workspace and its servers, with every row about them.

    python -m app.users_cli erase someone@example.com          says what would go
    python -m app.users_cli erase someone@example.com --yes    deletes it

The privacy page says an account and its workspace have no end of their own,
and that we delete them when asked. `users_cli disable` keeps every row and
`hosts_cli delete` keeps the account, so this is the one that takes all of it.

## What goes

- The account: its row, its sessions, its two-factor recovery codes, its
  Google or Microsoft sign-ins and a sign-in being connected to it.
- Links that work once: made for it, mailed to its address, sent by it as an
  invitation, and every invitation into its workspace.
- The beta list row with the same address.
- Its workspace: the row, its alert destinations, what went out and what a
  relay refused, its CVE messages, its Hetzner tokens with what they read,
  and the Feedback messages sent from it.
- Every server in the workspace with every row about it, through
  `store.HOST_TABLES`, the list `hosts_cli delete` uses too.
- The workspace's proofs and challenges, through `app/authz.py`, the only
  module that may touch them, and the row a self-hosted instance keeps
  beside a challenge (`prober_challenges`).

**Every table is named below, once**: in what goes, or in `LEFT` with the
reason it stays. `tests/test_erase.py` builds the schema from every module
that makes a table, and fails when a table is in neither, or when a table
that can hold an account, a workspace or a server is not in what goes. On a
box, a table in neither is a refusal: this code does not know what it holds,
so it could not say everything went.

## The dry run is the same run

Without --yes the deletes run all the same, in one transaction, and are
rolled back. The counts it prints are the deletes' own, not a second set of
queries that could disagree with them. With --yes the same transaction is
committed. Foreign keys are on and nothing cascades (`db.connect`), so a
table that points at the account and was missed makes the run fail, and the
rollback leaves every row as it was.

## The bytes go too

A delete leaves a row's bytes in the file until something writes over them,
and the nightly snapshot copies the file as it is (docs/RECORD.md 4.444).
Every connection overwrites what it deletes since then
(`db.forget_what_is_deleted`), but a row deleted before that day, or by a
connection that does not, can still be in a free page. So after the commit
VACUUM writes the file again from the rows that are left, and a checkpoint
empties the -wal beside it. Then the file and the -wal are read and the
address counted, so the last line says what the file holds, not what was
meant to happen.

## What it refuses, in one line, changing nothing

An address with no account. An account in workspace 1, the workspace every
account made without --workspace is in, which `db.init` makes again. The only
account with the admin flag. A workspace another account also uses, whose
servers are that account's too. A database another process is writing to.
A database that holds a table this code has no rule for.

## What it does not reach

The nightly snapshots and their copies, which hold what they held until they
are pruned (`app/backup.py`, `ops/offbox/pull.sh`), and the journal.
"""

import dataclasses
import os
import sqlite3
import sys

from . import accounts, authz, store
from .workspace import DEFAULT_WORKSPACE_ID

# What goes from each table, and in which order. The WHERE takes three named
# values: :user_id, :email and :workspace_id. A row goes before the row it
# points at, because foreign keys are on and nothing cascades.
ACCOUNT_TABLES = (
    ("sessions", "user_id = :user_id"),
    ("totp_recovery_codes", "user_id = :user_id"),
    ("oidc_identities", "user_id = :user_id"),
    # Only a flow that connects a sign-in to this account. Any other flow
    # names nobody and is gone ten minutes after it began.
    ("oidc_flows", "link_user_id = :user_id"),
    ("oidc_link_tickets", "user_id = :user_id"),
    # Made for the account, mailed to its address, sent by it, or an
    # invitation into its workspace. An invitation to this address from
    # another workspace goes as well: it is about this person.
    ("one_time_links", "user_id = :user_id OR email = :email"
                       " OR invited_by = :email OR workspace_id = :workspace_id"),
    ("beta_signups", "email = :email"),
)

WORKSPACE_TABLES = (
    # Sent from this workspace's Feedback window. A message from a
    # self-hosted instance names the instance instead, and stays.
    ("feedback", "workspace_id = :workspace_id"),
    ("notification_channels", "workspace_id = :workspace_id"),
    ("mail_refusals", "workspace_id = :workspace_id"),
    # What went out names a server as text and links to nothing, so deleting
    # one server leaves it (`alerts.py`). Erasing the workspace does not.
    ("sent_log", "workspace_id = :workspace_id"),
    ("cve_batch_deliveries", "batch_id IN"
                             " (SELECT id FROM cve_batches WHERE workspace_id = :workspace_id)"),
    ("cve_batches", "workspace_id = :workspace_id"),
    ("provider_fetches", "workspace_id = :workspace_id"),
    ("provider_snapshots", "workspace_id = :workspace_id"),
    ("provider_tokens", "workspace_id = :workspace_id"),
)

# Last, once nothing points at them any more.
OWNER_TABLES = (
    ("hosts", "workspace_id = :workspace_id"),
    ("users", "id = :user_id"),
    ("workspaces", "id = :workspace_id"),
)

# A self-hosted instance keeps the number of our prober API's challenge
# beside its own (`app/proberproofs.py`). The row goes with its challenge.
PROBER_CHALLENGES = "prober_challenges"

ERASED_TABLES = frozenset(
    [table for table, _where in store.HOST_TABLES]
    + list(authz.WORKSPACE_PROOF_TABLES) + [PROBER_CHALLENGES]
    + [table for table, _where in ACCOUNT_TABLES + WORKSPACE_TABLES + OWNER_TABLES])

# Every table that stays, and why. None of them names an account, a workspace
# or a server, which tests/test_erase.py checks.
LEFT = {
    "authz_exclusions": "the exclusion list, addresses somebody asked us to stop"
                        " probing. It names no account, a row taken out would let"
                        " the address be proved again, and the privacy page says"
                        " it has no end",
    "probe_instances": "self-hosted instances that may use our probers. An instance"
                       " is not an account here, and it is kept after a revoke as"
                       " the record of who could probe what",
    "probe_instance_keys": "an instance's two keys, as hashes. They go with the"
                           " instance, not with an account",
    "prober_api_batches": "an instance's queued batches, fifteen minutes at most",
    "prober_api_charges": "an instance's connections, counted for the hour",
    "prober_api_log": "the abuse log, one row per instance, prober, address and"
                      " day, kept thirty days",
    "prober_api_proofs": "on a self-hosted instance, the proofs our API last"
                         " listed for it, replaced whole at every batch",
    "sweep_state": "one row, when the sweep last ran",
    "vantages": "our probers",
    "vantage_addresses": "our probers' addresses",
}

# How long the rewrite waits, in milliseconds, for another process's write to
# end before VACUUM, and for its reads to end before the -wal is emptied. The
# ingest and the dashboard write and read in short requests, so a minute is
# long enough to be let through and short enough to watch.
REWRITE_WAIT_MS = 60_000


class Refused(Exception):
    """Why nothing was changed, in one line."""


@dataclasses.dataclass(frozen=True)
class Erased:
    email: str
    workspace_id: int
    counts: dict    # table: rows that went, only tables that had any

    @property
    def total(self) -> int:
        return sum(self.counts.values())


@dataclasses.dataclass(frozen=True)
class Rewritten:
    size_before: int
    size_after: int
    wal_after: int
    in_file: int
    in_wal: int
    trouble: str    # what kept the file from being written again, or ""


def erase(con: sqlite3.Connection, email: str, delete: bool) -> Erased:
    """Delete the account's rows in one transaction, and commit when `delete`
    is true or roll back when it is not. Raises Refused before any delete."""
    email = accounts.normalize_email(email)
    _take_the_write_lock(con)
    try:
        user_id, workspace_id = _account_that_may_go(con, email)
        present = _tables_present(con)
        unknown = sorted(present - ERASED_TABLES - set(LEFT))
        if unknown:
            raise Refused("the database holds a table this command has no rule for: "
                          + ", ".join(unknown) + ", nothing was changed")
        counts = _delete(con, present, {"user_id": user_id, "email": email,
                                        "workspace_id": workspace_id})
    except BaseException:
        con.rollback()
        raise
    if delete:
        con.commit()
    else:
        con.rollback()
    return Erased(email, workspace_id, {t: n for t, n in counts.items() if n})


def _take_the_write_lock(con: sqlite3.Connection) -> None:
    """Before anything is read, so the rows checked and counted are the rows
    deleted, and no other process writes in between."""
    try:
        con.execute("BEGIN IMMEDIATE")
    except sqlite3.OperationalError as exc:
        if "locked" not in str(exc) and "busy" not in str(exc):
            raise
        raise Refused("the database is locked by another process,"
                      " nothing was changed") from exc


def _account_that_may_go(con: sqlite3.Connection, email: str) -> tuple[int, int]:
    """(the account's id, its workspace), or Refused. Read by position, so a
    plain connection without the row factory reads it too."""
    row = con.execute("SELECT id, workspace_id, is_admin FROM users WHERE email = ?",
                      (email,)).fetchone()
    if row is None:
        raise Refused(f"no account for {email}, nothing was changed")
    user_id, workspace_id, is_admin = row[0], row[1], row[2]
    if workspace_id == DEFAULT_WORKSPACE_ID:
        raise Refused(f"{email} is in workspace {DEFAULT_WORKSPACE_ID}, which is"
                      " never erased, nothing was changed")
    if is_admin == 1:
        others = con.execute("SELECT count(*) FROM users WHERE is_admin = 1"
                             " AND id != ?", (user_id,)).fetchone()[0]
        if others == 0:
            raise Refused(f"{email} is the only account with the admin flag,"
                          " nothing was changed")
    sharing = con.execute("SELECT count(*) FROM users WHERE workspace_id = ?"
                          " AND id != ?", (workspace_id, user_id)).fetchone()[0]
    if sharing:
        raise Refused(f"workspace {workspace_id} is also used by {sharing} other"
                      f" account{'s' if sharing != 1 else ''}, nothing was changed")
    return user_id, workspace_id


def _tables_present(con: sqlite3.Connection) -> set[str]:
    """The tables this database has. A module's tables are made only where it
    runs, so a table that is not there holds nothing of the account's."""
    return {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
        " AND name NOT LIKE 'sqlite_%'")}


def _delete(con: sqlite3.Connection, present: set[str], values: dict) -> dict:
    """Every delete, in order, inside the caller's transaction. Returns how
    many rows went from each table."""
    counts = {}

    def add(table, n):
        counts[table] = counts.get(table, 0) + n

    workspace_id = values["workspace_id"]
    # The challenge numbers first: the rows kept beside them are found by
    # them, and the next step deletes the challenges.
    if set(authz.WORKSPACE_PROOF_TABLES) <= present:
        if PROBER_CHALLENGES in present:
            for challenge_id in authz.workspace_challenge_ids(con, workspace_id):
                add(PROBER_CHALLENGES, con.execute(
                    f"DELETE FROM {PROBER_CHALLENGES} WHERE challenge_id = ?",
                    (challenge_id,)).rowcount)
        for table, n in authz.erase_workspace_proofs(con, workspace_id).items():
            add(table, n)
    # Each server with every row about it, from the list `hosts_cli delete`
    # uses, so a table added to that list is erased here too.
    host_ids = [r[0] for r in con.execute(
        "SELECT id FROM hosts WHERE workspace_id = ? ORDER BY id", (workspace_id,))]
    for host_id in host_ids:
        for table, where in store.HOST_TABLES:
            if table in present:
                add(table, con.execute(f"DELETE FROM {table} WHERE {where}",
                                       (host_id,)).rowcount)
    for table, where in ACCOUNT_TABLES + WORKSPACE_TABLES + OWNER_TABLES:
        if table in present:
            add(table, con.execute(f"DELETE FROM {table} WHERE {where}", values).rowcount)
    return counts


def database_path(con: sqlite3.Connection) -> str:
    """The file this connection has open, as SQLite says it."""
    for row in con.execute("PRAGMA database_list"):
        if row[1] == "main":
            return row[2]
    return ""


def file_size(path: str) -> int:
    return os.path.getsize(path) if path and os.path.exists(path) else 0


def times_in(path: str, needle: bytes, chunk: int = 1 << 20) -> int:
    """How often these bytes are in this file, read a megabyte at a time so a
    large database is never in memory whole. Each piece keeps the last bytes
    of the one before, so a copy across two pieces is counted once."""
    if not path or not os.path.exists(path) or not needle:
        return 0
    found, tail = 0, b""
    with open(path, "rb") as f:
        while True:
            piece = f.read(chunk)
            if not piece:
                return found
            window = tail + piece
            found += window.count(needle)
            # What was already counted cannot be counted again: the kept tail
            # is shorter than the needle, so no whole copy fits in it.
            tail = window[-(len(needle) - 1):] if len(needle) > 1 else b""


def rewrite(con: sqlite3.Connection, email: str, size_before: int) -> Rewritten:
    """Write the file again from the rows that are left, empty the -wal, and
    count the address in both."""
    path = database_path(con)
    trouble = ""
    con.execute(f"PRAGMA busy_timeout = {REWRITE_WAIT_MS}")
    try:
        con.execute("VACUUM")
        # TRUNCATE copies the -wal into the file and cuts it to nothing. It
        # waits for readers that still need the old pages, and says busy when
        # they did not finish in time.
        busy = con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0]
        if busy:
            trouble = "another process was still reading, so the -wal was not emptied"
    except sqlite3.OperationalError as exc:
        trouble = f"the file was not written again: {exc}"
    wal = path + "-wal" if path else ""
    needle = email.encode()
    return Rewritten(size_before=size_before, size_after=file_size(path),
                     wal_after=file_size(wal), in_file=times_in(path, needle),
                     in_wal=times_in(wal, needle), trouble=trouble)


def run(con: sqlite3.Connection, email: str, yes: bool) -> int:
    """The command: refuse in one line, or list what goes, and with `yes`
    delete it, write the file again and say what the file holds."""
    size_before = file_size(database_path(con))
    try:
        erased = erase(con, email, delete=yes)
    except Refused as refusal:
        print(refusal, file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        # A row that still points at something being deleted, most likely a
        # table that came after this code. `erase` rolled every delete back.
        print(f"the erase failed and was rolled back: {exc}, nothing was changed",
              file=sys.stderr)
        return 1
    servers = erased.counts.get("hosts", 0)
    print(f"{erased.email}: workspace {erased.workspace_id},"
          f" {servers} server{'s' if servers != 1 else ''}")
    for table in sorted(erased.counts):
        print(f"  {table:<24} {erased.counts[table]:>6}")
    if not yes:
        print(f"nothing was changed. {erased.total} rows would go."
              " Run it again with --yes to delete them.")
        return 0
    print(f"{erased.total} rows deleted.")
    done = rewrite(con, erased.email, size_before)
    print(f"database file: {done.size_before} bytes before, {done.size_after}"
          f" bytes after, -wal {done.wal_after} bytes")
    print(f"the address is in the database file {done.in_file} times and in"
          f" its -wal {done.in_wal} times")
    if done.trouble:
        print(done.trouble, file=sys.stderr)
        return 1
    return 0
