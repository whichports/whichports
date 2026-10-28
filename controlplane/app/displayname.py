"""The name a person gives a server to read it by.

The owner, 2026-10-02 (`docs/RECORD.md` 4.238): a server may carry a name like
"Webshop", with capitals and spaces, and its hostname is shown under it.

**It is a label and never the identifier.** A server is still found by its
name in `hosts.name`, the one `store.NAME_RE` restricts, which is what a URL,
a DOM id, the command line and every route here carry. Nothing looks a server
up by its display name, so two servers may carry the same one, and a server
without one reads exactly as it did before there were any.

**Its own table rather than a column on hosts.** A column would have to be
carried through `db._rebuild_hosts_table`, the one irreversible operation in
`app/db.py`, for a value nothing else depends on. One row per server that has
a display name, and no row means none. `store.HOST_TABLES` names the table,
so deleting a server takes it along.
"""

import sqlite3

from . import store

MAX_CHARS = 40

# What a display name may hold beside letters and digits. Listed rather than
# described, so "plain punctuation" is this string and nothing else. No angle
# bracket, quote or backslash is in it: a display name is drawn on screens and
# in an alert's first line, and although every one of those escapes it, the
# door refuses markup as well.
PUNCTUATION = " -_.,:/()&+'#@"

SCHEMA = """
CREATE TABLE IF NOT EXISTS host_display_names (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts(id),
    display_name TEXT NOT NULL
);
"""


class DisplayNameError(ValueError):
    """The display name cannot be saved as typed. The message says why, in
    words the screen can show."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule `db.init` and `tags.init` follow.
    `db.init` has to have run first, because the table references hosts(id)."""
    con.executescript(SCHEMA)
    con.commit()


def checked(value) -> str:
    """A display name as it is stored, or a refusal. Empty means none.

    Trimmed, and runs of spaces inside it become one. Letters in any case,
    digits, and the characters in PUNCTUATION, 1 to 40 of them. A tab, a line
    break or any other control character is refused rather than turned into a
    space, so what is stored is what was typed. A name of spaces only is
    empty, which clears it.
    """
    if not isinstance(value, str):
        raise DisplayNameError("a display name must be text")
    trimmed = value.strip(" ")
    for char in trimmed:
        if not (char.isalnum() or char in PUNCTUATION):
            raise DisplayNameError(
                "a display name: letters, digits, spaces and"
                f" {PUNCTUATION.strip()} only")
    # A run of spaces splits into empty pieces, which are dropped, so the
    # words come back with one space between them.
    name = " ".join(piece for piece in trimmed.split(" ") if piece)
    if len(name) > MAX_CHARS:
        raise DisplayNameError(f"a display name is at most {MAX_CHARS} characters")
    return name


def set_display_name(con: sqlite3.Connection, host_name: str, value,
                     workspace_id: int | None = None) -> str | None:
    """Give a server this display name and return what was stored, which is
    empty when the name was cleared.

    None when there is no such live server in this workspace, the same
    three-way silence `store.active_host_by_name` keeps for unknown, removed
    and somebody else's.
    """
    name = checked(value)
    host = store.active_host_by_name(con, host_name, workspace_id=workspace_id)
    if host is None:
        return None
    with con:
        if name:
            con.execute(
                "INSERT INTO host_display_names (host_id, display_name) VALUES (?, ?)"
                " ON CONFLICT(host_id) DO UPDATE SET display_name = excluded.display_name",
                (host["id"], name))
        else:
            con.execute("DELETE FROM host_display_names WHERE host_id = ?",
                        (host["id"],))
    return name


def display_names_by_host(con: sqlite3.Connection,
                          workspace_id: int | None = None) -> dict[str, str]:
    """Every live server's display name, by server name. A server without
    one is not in the answer.

    A database from before display names has no table, and that is no
    display names rather than an error. Asked rather than caught, the posture
    `tags.tags_by_host` takes.
    """
    if not _table_exists(con):
        return {}
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = () if workspace_id is None else (workspace_id,)
    rows = con.execute(
        "SELECT h.name AS host_name, d.display_name FROM host_display_names d"
        " JOIN hosts h ON h.id = d.host_id"
        " WHERE h.revoked_at IS NULL" + scope, params).fetchall()
    return {row["host_name"]: row["display_name"] for row in rows}


def shown_name(names: dict[str, str], host_name: str) -> str:
    """What a reader is shown for a server: its display name when it has one,
    its name otherwise. For the places that say a server in words, the alert's
    first line among them."""
    return names.get(host_name) or host_name


def _table_exists(con: sqlite3.Connection) -> bool:
    return con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table'"
        " AND name = 'host_display_names'").fetchone() is not None
