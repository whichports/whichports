"""Which CVEs a workspace was told, so each is told once for a port.

The CVE check's message ends "Nothing else will be sent about these CVEs on
the same ports" (`app/cvewords.py`). This module is what keeps that: it works
out what is new on each port, writes down what is told in the same
transaction as the batch that tells it, and never says the same CVE for the
same port twice (`docs/SPEC-cve-check.md`, section 2, point 7, and section
4, point 11). The same CVE on another port, or on another server, is another
thing to tell, which is why the line names the ports.

**What is new is asked of the card.** The card of a port
(`app/cvecard.py`) is the one answer a page and a message share, so a CVE is
told exactly when the page marks it. A port whose card is not checked says
nothing here: no package named, not the distribution's package, lists not
read, no data for the release, or data older than three days.

**The first look at a port is a starting point and tells nobody.** The day
the check ships, the day an agent first sends its packages, and the day a
port is first checked for any other reason, what is already there is written
down as known and no message goes out. It is on the screen. Told is what
becomes new after that: the distribution published a fix, or the server went
back to a version the fix is not in. It does not matter which side moved.

**What is never a message**, each by a rule `docs/PRODUCT.md` 4c already
has: a set that shrinks, a CVE that comes back on a port it was told for, a
muted server, a silenced port, a revoked server, and another workspace's
servers.

**A mute records and does not queue.** What becomes new on a muted server
or a silenced port is written down as known, with no batch, and is on the
page. It is not said when the mute ends: 4c's rule for every other alert,
where a message held until a mute expires is a message about something a
person chose not to hear (the second challenge, 2026-10-12, section 7.12).

**What is kept is the server, the port and the CVE's id, and nothing
else.** No package, no version and no text out of a report: which CVEs a
package is open to is worked out each time. A batch keeps the names of the
servers it tells about, so a server deleted within the day does not unsay a
message that is still going out, and a batch is deleted a day after it was
written, when it is handed to nobody any more (`app/cvesend.py`).

This module sends nothing. The sweep hands a batch to every destination of
its workspace that takes the kind.
"""

import dataclasses
import json
import sqlite3
from datetime import datetime, timezone

from . import alerts, cvecard, cvedismiss, cvestore, finding_alerts, store

SCHEMA = """
-- A port the check has looked at once. What it found then was not told.
CREATE TABLE IF NOT EXISTS cve_started (
    host_id    INTEGER NOT NULL REFERENCES hosts(id),
    protocol   TEXT NOT NULL,
    port       INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    PRIMARY KEY (host_id, protocol, port)
);

-- A CVE known for a port: met at the port's first look, with no batch, or
-- told in the batch named.
CREATE TABLE IF NOT EXISTS cve_told (
    host_id  INTEGER NOT NULL REFERENCES hosts(id),
    protocol TEXT NOT NULL,
    port     INTEGER NOT NULL,
    cve      TEXT NOT NULL,
    told_at  TEXT NOT NULL,
    batch_id INTEGER,
    PRIMARY KEY (host_id, protocol, port, cve)
);

-- One message for one workspace. `told` is what it tells, as JSON: for each
-- server its id and name, the ports with the CVE ids new on each, and what
-- the server's mark stood for when it was written. It names the server as
-- text and links to nothing, so deleting a server cannot take a message
-- along that is still going out. `app/cvesend.py` deletes a batch a day
-- after it was written.
CREATE TABLE IF NOT EXISTS cve_batches (
    id           INTEGER PRIMARY KEY,
    workspace_id INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    told         TEXT NOT NULL
);
"""


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


@dataclasses.dataclass(frozen=True)
class ToldServer:
    """One server's part of a batch: the ports with something new as
    (protocol, port), the CVE ids that are new on them, and whether this
    server's own lists offer every one of their fixes.

    `marked` is every CVE the server's mark stood for when the batch was
    written, the new ones among them, and `mark_offered` whether that mark
    said an update. They are what the page shows, so a message's count is
    the count its button opens. `by_port` is the new CVEs of each port, as
    ((protocol, port), (cve, ...)), so a port silenced later is left out
    with its own CVEs and no other's. `mark_by_port` is what the mark stood
    for port by port, as ((protocol, port), (cve, ...), says an update), so
    a port silenced later leaves the count as well (finding G9)."""
    host_id: int
    host_name: str
    ports: tuple
    cves: tuple
    offered: bool
    marked: tuple = ()
    mark_offered: bool = True
    by_port: tuple = ()
    mark_by_port: tuple = ()


@dataclasses.dataclass(frozen=True)
class Batch:
    """What one message tells one workspace."""
    workspace_id: int
    told: tuple


def told(con: sqlite3.Connection, host_id: int) -> set:
    """Every (protocol, port, cve) known for one server."""
    return {(row[0], row[1], row[2]) for row in con.execute(
        "SELECT protocol, port, cve FROM cve_told WHERE host_id = ?", (host_id,))}


def batch(con: sqlite3.Connection, batch_id: int) -> Batch:
    row = con.execute("SELECT workspace_id, told FROM cve_batches WHERE id = ?", (batch_id,)).fetchone()
    servers = tuple(_from_json(one) for one in json.loads(row[1]))
    return Batch(workspace_id=row[0], told=servers)


def _from_json(one) -> ToldServer:
    """A server's part of a batch as it was stored. A part that does not say
    what the mark stood for is read as standing for what it tells."""
    return ToldServer(
        host_id=one["host_id"], host_name=one["host_name"],
        ports=tuple((protocol, port) for protocol, port in one["ports"]),
        cves=tuple(one["cves"]), offered=one["offered"],
        marked=tuple(one.get("marked", one["cves"])),
        mark_offered=one.get("mark_offered", one["offered"]),
        by_port=tuple(((protocol, port), tuple(cves)) for protocol, port, cves in one.get("port_cves", ())),
        mark_by_port=tuple(((protocol, port), tuple(cves), says_update)
                           for protocol, port, cves, says_update in one.get("mark_ports", ())))


def to_json(server: ToldServer) -> dict:
    return {"host_id": server.host_id, "host_name": server.host_name,
            "ports": [list(port) for port in server.ports],
            "cves": list(server.cves), "offered": server.offered,
            "marked": list(server.marked), "mark_offered": server.mark_offered,
            "port_cves": [[protocol, port, list(cves)] for (protocol, port), cves in server.by_port],
            "mark_ports": [[protocol, port, list(cves), says_update]
                           for (protocol, port), cves, says_update in server.mark_by_port]}


def evaluate(con: sqlite3.Connection, now: datetime | None = None, extract_for=cvestore.kept) -> list:
    """Look at every server's newest report once, write down what is new,
    and return the ids of the batches written, one a workspace at most.

    All of it is one transaction: the starting points, the rows that say a
    CVE was told and the batches that tell them. A failure leaves nothing
    half written, so no CVE is marked told that no batch carries.
    """
    now = now or datetime.now(timezone.utc)
    stamp = now.isoformat()
    new_by_workspace = {}
    try:
        dismissed = cvedismiss.dismissed_by_host(con)
        for host in store.list_hosts(con):
            if host["revoked_at"]:
                continue
            for server in _new_on(con, host, now, stamp, extract_for, dismissed.get(host["name"], {})):
                new_by_workspace.setdefault(host["workspace_id"], []).append(server)
        ids = [_write_batch(con, workspace_id, servers, stamp)
               for workspace_id, servers in sorted(new_by_workspace.items())]
        con.commit()
    except Exception:
        con.rollback()
        raise
    return ids


def _new_on(con, host, now, stamp, extract_for, dismissed) -> list:
    """What is new on one server, as a list of none or one `ToldServer`.
    Writes the starting point of every port looked at for the first time,
    and what is new on a muted server or a silenced port as known.
    `dismissed` is this server's dismissed marks, by port."""
    report = store.latest_report(con, host["id"])
    if report is None:
        return []
    try:
        doc = json.loads(report["document"])
    except ValueError:
        return []
    # A report older than three days says what was installed then. Its
    # ports are not checked, so nothing is told from it.
    cards = cvecard.cards_of(doc, extract_for, now, alerts.parse_stamp(report["received_at"]))
    if not cards:
        return []
    known = told(con, host["id"])
    started = {(row[0], row[1]) for row in con.execute(
        "SELECT protocol, port FROM cve_started WHERE host_id = ?", (host["id"],))}
    ports, cves, offered, by_port = [], set(), True, []
    for (protocol, port), card in sorted(cards.items()):
        if not card.checked:
            continue
        if (protocol, port) not in started:
            con.execute("INSERT INTO cve_started (host_id, protocol, port, started_at) VALUES (?, ?, ?, ?)",
                        (host["id"], protocol, port, stamp))
            _mark(con, host["id"], protocol, port, card.cves, stamp, None)
            continue
        new = sorted(cve for cve in card.cves if (protocol, port, cve) not in known)
        if not new:
            continue
        # A mute covers every port of its server and a silence one port, and
        # `silenced` answers for both. What is new there is recorded as
        # known and is in no batch, now or when the mute ends.
        if quiet(con, host["id"], protocol, port, now):
            _mark(con, host["id"], protocol, port, new, stamp, None)
            continue
        ports.append((protocol, port))
        by_port.append(((protocol, port), tuple(new)))
        cves.update((protocol, port, cve) for cve in new)
        offered = offered and not set(new) & set(card.apart)
    if not ports:
        return []
    # What the page's mark for this server stands for at this moment: every
    # marked port whose mark a person has not dismissed (`cvedismiss`) and
    # that no silence covers. A silenced port keeps its own mark on its row
    # and leaves the server's count, as an alert it silenced leaves the
    # count beside Alerts (docs/PRODUCT.md 4c, the second big test's G9).
    mark_by_port = tuple(
        (key, tuple(card.cves), card.mark.startswith("an update fixes "))
        for key, card in sorted(cards.items())
        if card.mark and not cvedismiss.is_dismissed(card, dismissed.get(key))
        and not quiet(con, host["id"], key[0], key[1], now))
    marked, mark_offered = what_the_mark_stands_for(mark_by_port)
    return [(ToldServer(host_id=host["id"], host_name=host["name"], ports=tuple(ports),
                        cves=tuple(sorted({cve for _protocol, _port, cve in cves})), offered=offered,
                        marked=marked, mark_offered=mark_offered, by_port=tuple(by_port),
                        mark_by_port=mark_by_port),
             sorted(cves))]


def what_the_mark_stands_for(mark_by_port) -> tuple:
    """The CVEs a server's mark stands for, each once, and whether it says
    an update, from what each of its ports' marks stands for. The words are
    `cvecard.server_mark`'s rule: an update only when every mark says so."""
    marked = tuple(sorted({cve for _port, cves, _says_update in mark_by_port for cve in cves}))
    return marked, all(says_update for _port, _cves, says_update in mark_by_port)


def quiet(con, host_id, protocol, port, now) -> bool:
    """Whether a mute or a silence covers this port now, over either
    address family."""
    return any(finding_alerts.silenced(con, host_id, protocol, port, family, now=now)
               for family in cvecard.FAMILIES)


def _write_batch(con, workspace_id, servers, stamp) -> int:
    """One batch for one workspace, and the rows that say each of its CVEs
    was told for its port."""
    payload = [to_json(server) for server, _rows in sorted(servers, key=lambda pair: pair[0].host_name)]
    batch_id = con.execute(
        "INSERT INTO cve_batches (workspace_id, created_at, told) VALUES (?, ?, ?)",
        (workspace_id, stamp, json.dumps(payload))).lastrowid
    for server, rows in servers:
        for protocol, port, cve in rows:
            _mark(con, server.host_id, protocol, port, [cve], stamp, batch_id)
    return batch_id


def _mark(con, host_id, protocol, port, cves, stamp, batch_id) -> None:
    con.executemany(
        "INSERT OR IGNORE INTO cve_told (host_id, protocol, port, cve, told_at, batch_id)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        [(host_id, protocol, port, cve, stamp, batch_id) for cve in cves])
