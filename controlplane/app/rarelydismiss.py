"""A person dismissing the rarely-public mark on one port of one server.

The mark (`docs/RECORD.md` 4.258) is drawn on a reachable port that is on the
list in `app/rarelypublic.py`. The owner, 2026-10-03 (`docs/RECORD.md` 4.274):
when such a port truly should be open, the mark can be suppressed.

**Only a person dismisses it, one port of one server at a time.** Nothing
here is inferred. A rule that allows the port does not dismiss it, because a
rule allows most of the ports the mark is drawn on, and the mark would then
never show. The same port on another server keeps its mark. A dismissal is
undone the same way it was made, and it stays when the port stops answering,
so a port that comes back is not marked again behind the person's back.

One row per dismissed port, and no row means the mark shows. `store.HOST_TABLES`
names the table, so deleting a server takes its dismissals with it.
"""

import datetime
import sqlite3

from . import rarelypublic, store

SCHEMA = """
CREATE TABLE IF NOT EXISTS rarely_dismissed (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    protocol     TEXT NOT NULL,
    port         INTEGER NOT NULL,
    dismissed_at TEXT NOT NULL,
    PRIMARY KEY (host_id, protocol, port)
);
"""


class DismissError(ValueError):
    """The port cannot be dismissed as asked. The message says why, in words
    the screen can show."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule `tags.init` follows. `db.init` has to
    have run first, because the table references hosts(id)."""
    con.executescript(SCHEMA)
    con.commit()


def checked_port(protocol, port) -> tuple[str, int]:
    """The protocol and port as stored, or a refusal. Only a port on the list
    can carry the mark, so only a port on the list can be dismissed."""
    if not isinstance(protocol, str) or not isinstance(port, int) or isinstance(port, bool):
        raise DismissError("not a port")
    found = rarelypublic.lookup(protocol, port)
    if found is None:
        raise DismissError("this port carries no mark to dismiss")
    return found.protocol, found.port


def set_dismissed(con: sqlite3.Connection, host_name: str, protocol, port,
                  dismissed, workspace_id: int | None = None,
                  now: datetime.datetime | None = None) -> bool | None:
    """Dismiss the mark on one port of one server, or bring it back, and
    return whether it is dismissed now.

    None when there is no such live server in this workspace, the same
    three-way silence `store.active_host_by_name` keeps for unknown, removed
    and somebody else's. Dismissing twice keeps the first time it was done.
    """
    if not isinstance(dismissed, bool):
        raise DismissError("dismissed must be true or false")
    protocol, port = checked_port(protocol, port)
    host = store.active_host_by_name(con, host_name, workspace_id=workspace_id)
    if host is None:
        return None
    when = (now or datetime.datetime.now(datetime.timezone.utc)).isoformat()
    with con:
        if dismissed:
            con.execute(
                "INSERT INTO rarely_dismissed (host_id, protocol, port, dismissed_at)"
                " VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (host["id"], protocol, port, when))
        else:
            con.execute(
                "DELETE FROM rarely_dismissed WHERE host_id = ? AND protocol = ? AND port = ?",
                (host["id"], protocol, port))
    return dismissed


def dismissed_by_host(con: sqlite3.Connection,
                      workspace_id: int | None = None) -> dict[str, frozenset[str]]:
    """Every live server's dismissed ports by server name, each as the label
    the dashboard keys a port on, "tcp/6379". A server with none is not in the
    answer.

    A database from before dismissals has no table, and that is none rather
    than an error. Asked rather than caught, the posture `tags.tags_by_host`
    takes.
    """
    exists = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'rarely_dismissed'"
    ).fetchone()
    if exists is None:
        return {}
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = () if workspace_id is None else (workspace_id,)
    rows = con.execute(
        "SELECT h.name AS host_name, d.protocol, d.port FROM rarely_dismissed d"
        " JOIN hosts h ON h.id = d.host_id"
        " WHERE h.revoked_at IS NULL" + scope, params).fetchall()
    out: dict[str, set[str]] = {}
    for row in rows:
        out.setdefault(row["host_name"], set()).add(f"{row['protocol']}/{row['port']}")
    return {name: frozenset(labels) for name, labels in out.items()}
