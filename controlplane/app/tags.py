"""Tags a person puts on a server.

The owner, 2026-08-18 (`docs/RECORD.md` 4.64): each server carries tags its user
makes up and applies, and the fleet can be filtered on them, by `production`,
`internal`, `web` or `hetzner` for example.

A tag is free text a person typed. It is never a measurement and never a
state, and nothing in the join engine, the alerts or the prober reads it.
There is no vocabulary and no meaning of ours: the examples above span
environment, exposure, role and provider, and any list we wrote would be
wrong for somebody.

**A tag belongs to a server, so it belongs to the server's workspace.**
Everyone in the workspace sees the same tags, because scoping happens at
`hosts` and nowhere else (`app/db.py`). Only a person sets one. Nothing
applies a tag by rule, and a provider's own labels are not imported.

One row per server per tag. `store.HOST_TABLES` names the table, so deleting
a server takes its tags with it.

**At most three per server**, the owner's limit of 2026-10-03 (`docs/RECORD.md`
4.274). It was ten before. A server tagged then may carry more than
three, and it keeps them: it may drop some, and it takes no new tag until it
carries three or fewer.
"""

import sqlite3

from . import store

MAX_TAGS_PER_HOST = 3

SCHEMA = """
CREATE TABLE IF NOT EXISTS host_tags (
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    tag     TEXT NOT NULL,
    PRIMARY KEY (host_id, tag)
);
"""


class TagError(ValueError):
    """The tags cannot be saved as typed. The message says why, in words the
    screen can show."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule `db.init` and `intent.init` follow.
    `db.init` has to have run first, because the table references hosts(id)."""
    con.executescript(SCHEMA)
    con.commit()


def checked_tag(value) -> str:
    """One tag as it is stored, or a refusal.

    **A tag follows the server name's own rule**, `store.NAME_RE`: lowercase
    letters, digits, - and _, starting with a letter or digit, at most 32
    characters. One rule to remember, nothing to escape on a screen and
    nothing odd to search for. It is lowercased on save, so `Production` and
    `production` are one tag.
    """
    if not isinstance(value, str):
        raise TagError("a tag must be text")
    tag = value.strip().lower()
    if not tag:
        raise TagError("a tag is empty")
    if not store.NAME_RE.match(tag):
        raise TagError("a tag: lowercase letters, digits, - and _, "
                       "starting with a letter or digit, at most 32 characters")
    return tag


def checked_tags(values, current=()) -> list[str]:
    """The whole set for one server, in the order typed, each tag once.

    At most MAX_TAGS_PER_HOST, counting the tags kept rather than the words
    typed. `current` is what the server carries now. A set past the limit is
    still taken when every tag in it is one the server already has, which is
    how a server tagged before the limit keeps its tags and can drop some.
    Adding a tag past the limit is what is refused, and so is swapping one,
    because that adds one too.
    """
    if not isinstance(values, (list, tuple)):
        raise TagError("tags must be a list")
    out = []
    for value in values:
        tag = checked_tag(value)
        if tag not in out:
            out.append(tag)
    if len(out) > MAX_TAGS_PER_HOST and any(tag not in current for tag in out):
        raise TagError(f"a server carries at most {MAX_TAGS_PER_HOST} tags")
    return out


def set_tags(con: sqlite3.Connection, host_name: str, values,
             workspace_id: int | None = None) -> list[str] | None:
    """Replace a server's tags with these and return what was stored.

    None when there is no such live server in this workspace, the same
    three-way silence `store.active_host_by_name` keeps for unknown, revoked
    and somebody else's. An empty list clears the tags.

    The delete and the inserts are one transaction, so a refusal or an error
    leaves the server with exactly the tags it had. The server is looked up
    first because the limit depends on the tags it carries now.
    """
    host = store.active_host_by_name(con, host_name, workspace_id=workspace_id)
    if host is None:
        return None
    current = [row["tag"] for row in con.execute(
        "SELECT tag FROM host_tags WHERE host_id = ? ORDER BY rowid", (host["id"],))]
    wanted = checked_tags(values, current)
    with con:
        con.execute("DELETE FROM host_tags WHERE host_id = ?", (host["id"],))
        con.executemany(
            "INSERT INTO host_tags (host_id, tag) VALUES (?, ?)",
            [(host["id"], tag) for tag in wanted])
    return wanted


def tags_by_host(con: sqlite3.Connection,
                 workspace_id: int | None = None) -> dict[str, list[str]]:
    """Every live server's tags by server name, each list in the order saved.

    A database from before tags has no table, and that is no tags rather
    than an error: the page that calls this has to render either way.
    """
    if not _table_exists(con):
        return {}
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = () if workspace_id is None else (workspace_id,)
    # set_tags deletes and inserts the whole set on every save, so the order
    # the rows were written in is the order the tags were typed in.
    rows = con.execute(
        "SELECT h.name AS host_name, t.tag FROM host_tags t"
        " JOIN hosts h ON h.id = t.host_id"
        " WHERE h.revoked_at IS NULL" + scope + " ORDER BY t.rowid",
        params).fetchall()
    out: dict[str, list[str]] = {}
    for row in rows:
        out.setdefault(row["host_name"], []).append(row["tag"])
    return out


def _table_exists(con: sqlite3.Connection) -> bool:
    """Asked rather than caught, the posture `intent._table_exists` takes: a
    caught OperationalError would also swallow a locked database."""
    return con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'host_tags'"
    ).fetchone() is not None
