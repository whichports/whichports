"""A person dismissing the CVE check's mark on one port of one server.

The mark stands on a port for whose package a newer version fixes a CVE
(`app/cvecard.py`). The owner, 2026-10-03 (`docs/RECORD.md` 4.338): it can be
dismissed, with the control and the words the rarely-public mark has
(`app/rarelydismiss.py`): Dismiss on the port's opened row, and Restore once
it is dismissed.

**A dismissal belongs to the port and to the CVEs the mark stood for at that
moment.** It says "I know about these", not "never tell me about this port".
So a CVE that joins the set later brings the mark back, and one click does
not keep a port quiet for good, whatever a later update fixes. The card
keeps its lines either way: only the mark goes.

**Which CVEs those are is worked out here**, from the server's newest report
and the release's data, and never taken from the request: a request names a
port and a yes or a no. A port that carries no mark has nothing to dismiss.

One row per dismissed CVE of a port. `store.HOST_TABLES` names the table, so
deleting a server takes its dismissals with it.
"""

import datetime
import json
import sqlite3

from . import alerts, cvecard, cvestore, store

SCHEMA = """
CREATE TABLE IF NOT EXISTS cve_dismissed (
    host_id      INTEGER NOT NULL REFERENCES hosts(id),
    protocol     TEXT NOT NULL,
    port         INTEGER NOT NULL,
    cve          TEXT NOT NULL,
    dismissed_at TEXT NOT NULL,
    PRIMARY KEY (host_id, protocol, port, cve)
);
"""


class DismissError(ValueError):
    """The mark cannot be dismissed as asked. The message says why, in words
    the screen can show."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent. `db.init` has to have run first, because the table
    references hosts(id)."""
    con.executescript(SCHEMA)
    con.commit()


def is_dismissed(card, dismissed) -> bool:
    """Whether a port's mark is dismissed: it stands for something, and
    everything it stands for was dismissed. `dismissed` is the port's set
    from `dismissed_by_host`, or None."""
    return bool(card.cves) and bool(dismissed) and set(card.cves) <= set(dismissed)


def set_dismissed(con: sqlite3.Connection, host_name: str, protocol, port, dismissed,
                  workspace_id: int | None = None, now: datetime.datetime | None = None,
                  extract_for=cvestore.kept) -> bool | None:
    """Dismiss the mark on one port of one server, or bring it back, and
    return whether it is dismissed now.

    None when there is no such live server in this workspace, the same
    three-way silence `store.active_host_by_name` keeps for unknown, removed
    and somebody else's. Dismissing twice keeps the first time it was done.
    """
    if not isinstance(protocol, str) or not isinstance(port, int) or isinstance(port, bool):
        raise DismissError("not a port")
    if not isinstance(dismissed, bool):
        raise DismissError("dismissed must be true or false")
    host = store.active_host_by_name(con, host_name, workspace_id=workspace_id)
    if host is None:
        return None
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not dismissed:
        with con:
            con.execute("DELETE FROM cve_dismissed WHERE host_id = ? AND protocol = ? AND port = ?",
                        (host["id"], protocol, port))
        return False
    cves = _marked(con, host["id"], protocol, port, now, extract_for)
    if not cves:
        raise DismissError("this port carries no mark to dismiss")
    with con:
        con.executemany(
            "INSERT INTO cve_dismissed (host_id, protocol, port, cve, dismissed_at)"
            " VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            [(host["id"], protocol, port, cve, now.isoformat()) for cve in cves])
    return True


def _marked(con, host_id, protocol, port, now, extract_for) -> tuple:
    """The CVEs the mark of this port stands for now, or none."""
    report = store.latest_report(con, host_id)
    if report is None:
        return ()
    try:
        doc = json.loads(report["document"])
    except ValueError:
        return ()
    cards = cvecard.cards_of(doc, extract_for, now, alerts.parse_stamp(report["received_at"]))
    card = cards.get((protocol, port))
    return card.cves if card is not None else ()


def dismissed_by_host(con: sqlite3.Connection, workspace_id: int | None = None) -> dict:
    """Every live server's dismissed CVEs, by server name and then by port:
    {"web-07": {("tcp", 22): frozenset({...})}}. A server with none is not in
    the answer.

    A database from before dismissals has no table, and that is none rather
    than an error. Asked rather than caught, as `rarelydismiss` does.
    """
    exists = con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'cve_dismissed'").fetchone()
    if exists is None:
        return {}
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = () if workspace_id is None else (workspace_id,)
    rows = con.execute(
        "SELECT h.name, d.protocol, d.port, d.cve FROM cve_dismissed d"
        " JOIN hosts h ON h.id = d.host_id WHERE h.revoked_at IS NULL" + scope, params).fetchall()
    out: dict = {}
    for name, protocol, port, cve in rows:
        out.setdefault(name, {}).setdefault((protocol, port), set()).add(cve)
    return {name: {key: frozenset(cves) for key, cves in ports.items()} for name, ports in out.items()}
