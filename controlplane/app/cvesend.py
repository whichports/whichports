"""Handing what a workspace is told about CVEs to its destinations, once.

`app/cvetell.py` writes down what is new on each port as a batch, one a
workspace, and `app/cvewords.py` says a batch as a message. This module
hands each batch to every destination of its workspace that takes the kind,
and keeps for each destination that it took it, so:

- **one destination's failure is never another's.** A webhook that timed
  out is tried at the next sweep, and the mail that was accepted beside it
  is not sent twice. The same per-destination queue every other alert has
  (`app/alerts.py`, `alert_deliveries`).
- **a destination that does not take the kind lets the batch go.** It is
  written down as done for it, so choosing the kind later does not bring old
  batches back.
- **a batch a day old is sent to nobody any more, and is deleted.** A
  destination that could not be reached for a day does not get the message
  a day late.
- **a destination added after a batch was written lets it go**, as it
  hears no alert raised before it was added (decided on 26 October 2026,
  after the second big test's E10a). It is written down as done for it. The CVEs are
  on the server's page. A batch holds servers' names, ports and CVE ids, and
  nothing reads it after that day, so each pass deletes what is older with
  its delivery rows. What a workspace was told stays in `cve_told`, which
  goes with its server.
- **a mute is asked at every try.** A server muted after its batch was
  written is taken out of the batch, and a port silenced since then with it,
  for good: a mute records and does not queue (`docs/PRODUCT.md` 4c). A
  batch with nobody left in it is deleted.
- **so is what still stands.** A message says what is true now (4c). At
  every try each port's card is read again from its server's newest report,
  and a port whose card no longer marks a CVE the batch told for it leaves,
  with those CVEs: its package removed, upgraded past the fix, or nothing
  listening there any more. A Webhook added an hour after nginx and apache2
  were removed was sent the morning's two messages about them (the second
  big test, 2026-10-25, case E10a). A report the check cannot read, with no
  packages or no data for its release, leaves the batch as it was written,
  because nothing read says the CVEs went.
- **a display name is the batch's own workspace's.** A batch names its
  servers as text and outlives them for a day. The display name is said
  only while the server it was written for still stands in that workspace,
  under that id and that name, so a name another workspace gave to a server
  of its own is never said.

The message is one description for every channel (`cvewords.said`), so a
chat says what the mail says. The generic webhook's JSON carries the same
and no CVE id: the servers by the name they are found by, their ports, and
how many CVEs.

What went out is written to the sent log, one line a destination that took
it, as every other message is.
"""

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta

import json

from . import (alerts, channels, cvecard, cvestore, cvetell, cvewords, db, displayname,
               finding_alerts, notify, senders, store, webhook)

SCHEMA = """
-- One row per batch per destination that is done with it: it took the
-- message, or it does not take the kind.
CREATE TABLE IF NOT EXISTS cve_batch_deliveries (
    batch_id     INTEGER NOT NULL REFERENCES cve_batches(id),
    channel      TEXT NOT NULL,
    delivered_at TEXT NOT NULL,
    PRIMARY KEY (batch_id, channel)
);
"""

# How long a batch is still handed out after it was written.
SEND_WITHIN = timedelta(hours=24)


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


def deliver(con: sqlite3.Connection, now: datetime, *, config=None, use_environment=False,
            mail_rows=(), chat_rows=(), env=None,
            send_mail=None, send_chat=None, extract_for=cvestore.kept) -> int:
    """Hand every batch still to be sent to each destination that has not
    had it. Returns how many messages went out.

    The destinations are the sweep's own (`sweep_cli.mail_targets` and
    `channel_targets`): the environment's single recipient for the
    operator's workspace when `use_environment` says so, every email row,
    and every chat row. The two senders are arguments so the tests stand
    where the relay and the chat services stand.
    """
    config = config or notify.config_from_env()
    # Looked up at the call and not at the definition, as the sweep's own
    # sends are, so whoever stands in for the relay stands in here too.
    send_mail = send_mail or notify.send
    send_chat = send_chat or senders.deliver
    since = (now - SEND_WITHIN).isoformat()
    forget_before(con, since)
    sent = 0
    for batch_id, workspace_id, written in con.execute(
            "SELECT id, workspace_id, created_at FROM cve_batches WHERE created_at >= ? ORDER BY id",
            (since,)).fetchall():
        done = {row[0] for row in con.execute(
            "SELECT channel FROM cve_batch_deliveries WHERE batch_id = ?", (batch_id,))}
        # Every destination done with it: nothing reads the batch again, so
        # its servers' cards are not worked out again for nobody.
        # A destination added after the batch was written lets it go, as
        # it hears no alert raised before it was added either.
        for channel in list(mail_rows) + list(chat_rows):
            key = alerts.key_for_channel(channel)
            if (key not in done and channel.workspace_id in (None, workspace_id)
                    and channel.created_at and channel.created_at > written):
                _mark(con, batch_id, key, now)
                done.add(key)
        waiting = [key for key in _keys(use_environment, workspace_id, mail_rows, chat_rows)
                   if key not in done]
        if not waiting:
            continue
        told = _still_told(con, batch_id, now, extract_for)
        if not told:
            continue
        names = _display_names(con, workspace_id, told)
        said = cvewords.said([
            cvewords.Told(one.host_name, ports=one.ports, cves=frozenset(one.cves),
                          offered=one.offered, display=names.get(one.host_name, ""),
                          marked=frozenset(one.marked), mark_offered=one.mark_offered)
            for one in told])
        subject, body, html = notify.mail(said)

        def took(key, really=True):
            _mark(con, batch_id, key, now)
            if really:
                _log(con, workspace_id, said, key, now)

        if (use_environment and workspace_id == db.DEFAULT_WORKSPACE_ID
                and alerts.SENT_BY_ENVIRONMENT_MAIL not in done):
            ok, reason = send_mail(subject, body, config, html)
            if ok:
                took(alerts.SENT_BY_ENVIRONMENT_MAIL)
                sent += 1
            else:
                print(f"not sent, CVEs for workspace {workspace_id}: {reason}")
        for channel in list(mail_rows) + list(chat_rows):
            key = alerts.key_for_channel(channel)
            if key in done or channel.workspace_id not in (None, workspace_id):
                continue
            if not channel.takes(channels.KIND_CVE):
                took(key, really=False)
                continue
            if channel.type == channels.TYPE_EMAIL:
                to = channel.resolve(env)
                if not to:
                    continue
                ok, reason = send_mail(subject, body, replace(config, to=to, sender=config.sender or to), html)
                alerts.note_mail_answer(con, channel, ok, reason, now)
            else:
                message = senders.message(said)
                ok, reason = send_chat(channel, senders.plain(message), _payload(told, names),
                                       env, message=message)
            if ok:
                took(key)
                sent += 1
            else:
                print(f"not sent, CVEs on {channel.label}: {reason}")
    return sent


def _keys(use_environment, workspace_id, mail_rows, chat_rows) -> list:
    """The delivery key of every destination this workspace's batch goes
    to, the ones that do not take the kind among them."""
    keys = []
    if use_environment and workspace_id == db.DEFAULT_WORKSPACE_ID:
        keys.append(alerts.SENT_BY_ENVIRONMENT_MAIL)
    for channel in list(mail_rows) + list(chat_rows):
        if channel.workspace_id in (None, workspace_id):
            keys.append(alerts.key_for_channel(channel))
    return keys


def forget_before(con, since: str) -> int:
    """Delete every batch written before `since`, with its delivery rows,
    and return how many batches went. Such a batch is handed to nobody any
    more, so nothing reads it."""
    old = "SELECT id FROM cve_batches WHERE created_at < ?"
    con.execute(f"DELETE FROM cve_batch_deliveries WHERE batch_id IN ({old})", (since,))
    gone = con.execute("DELETE FROM cve_batches WHERE created_at < ?", (since,)).rowcount
    con.commit()
    return gone


def _host_of(con, workspace_id, one):
    """The server a part of a batch was written for, while it still stands:
    in the batch's workspace, under the id and the name the batch kept. A
    deleted server's id and its name can each go to another server, also to
    another workspace's, so all three are asked."""
    return con.execute("SELECT id FROM hosts WHERE id = ? AND name = ? AND workspace_id = ?",
                       (one.host_id, one.host_name, workspace_id)).fetchone()


def _still_told(con, batch_id, now, extract_for=cvestore.kept) -> tuple:
    """A batch's servers as they are told at this try. A server muted now is
    taken out, and a port silenced now with the CVEs that were new on it, a
    port whose card no longer marks them too, and the batch is written back
    without them. A batch with nobody left is deleted and answers
    nothing."""
    batch = cvetell.batch(con, batch_id)
    kept = []
    for one in batch.told:
        host = _host_of(con, batch.workspace_id, one)
        if host is None:
            # Deleted within the day. Nobody can mute it any more, and what
            # was written about it is still told (`app/cvetell.py`).
            kept.append(one)
            continue
        still = _unsilenced(con, host["id"], one, now)
        if still is not None:
            still = _still_marked(con, host["id"], still, now, extract_for)
        if still is not None:
            kept.append(still)
    kept = tuple(kept)
    if kept == batch.told:
        return kept
    if kept:
        con.execute("UPDATE cve_batches SET told = ? WHERE id = ?",
                    (json.dumps([cvetell.to_json(one) for one in kept]), batch_id))
    else:
        con.execute("DELETE FROM cve_batch_deliveries WHERE batch_id = ?", (batch_id,))
        con.execute("DELETE FROM cve_batches WHERE id = ?", (batch_id,))
    con.commit()
    return kept


def _unsilenced(con, host_id, one, now):
    """One server's part of a batch with what a silence covers now taken
    out, or None when nothing of it is left to tell.

    A port silenced since the batch was written leaves with the CVEs that
    were new on it, and its mark leaves the count, as it leaves the
    server's mark on the page (the second big test, finding G9). A part
    written before the batch kept its ports' CVEs apart cannot say which
    CVE was whose, so it leaves whole when one of its ports is silenced."""
    def quiet(port):
        return cvetell.quiet(con, host_id, port[0], port[1], now)

    ports = tuple(port for port in one.ports if not quiet(port))
    if not ports or (ports != one.ports and not one.by_port):
        return None
    by_port = tuple((port, cves) for port, cves in one.by_port if port in ports)
    cves = tuple(sorted({cve for _port, new in by_port for cve in new})) if ports != one.ports else one.cves
    marked, mark_offered = one.marked, one.mark_offered
    if one.mark_by_port:
        mark_by_port = tuple(entry for entry in one.mark_by_port if not quiet(entry[0]))
        marked, mark_offered = cvetell.what_the_mark_stands_for(mark_by_port)
    else:
        mark_by_port = ()
    return replace(one, ports=ports, cves=cves, by_port=by_port, marked=marked,
                   mark_offered=mark_offered, mark_by_port=mark_by_port)


def _cards_now(con, host_id, now, extract_for):
    """The card of each listening port of the server's newest report, or
    None when that report says nothing of the check: no report, one that
    cannot be read, or one with no packages section."""
    report = store.latest_report(con, host_id)
    if report is None:
        return None
    try:
        doc = json.loads(report["document"])
    except ValueError:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("packages"), dict):
        return None
    return cvecard.cards_of(doc, extract_for, now, alerts.parse_stamp(report["received_at"]))


def _still_marked(con, host_id, one, now, extract_for):
    """One server's part of a batch with what its cards no longer mark
    taken out, or None when nothing of it is left to tell.

    A port keeps the CVEs it told that its card marks now. A port with no
    card, nothing listening there any more, keeps none. A card that is not
    checked now, data too old or none for the release, says nothing either
    way, so its port is kept as written. A part written before the batch
    kept its ports' CVEs apart leaves whole when one of its ports goes, as
    it does for a silence."""
    cards = _cards_now(con, host_id, now, extract_for)
    if cards is None:
        return one

    def standing(port, cves):
        card = cards.get(tuple(port))
        if card is None:
            return ()
        if not card.checked:
            return tuple(cves)
        return tuple(cve for cve in cves if cve in set(card.cves))

    if not one.by_port:
        if all(standing(port, one.cves) for port in one.ports):
            return one
        return None
    by_port = tuple((port, standing(port, cves)) for port, cves in one.by_port)
    by_port = tuple((port, cves) for port, cves in by_port if cves)
    if not by_port:
        return None
    if by_port == one.by_port:
        return one
    ports = tuple(port for port, _cves in by_port)
    cves = tuple(sorted({cve for _port, new in by_port for cve in new}))
    marked, mark_offered = one.marked, one.mark_offered
    mark_by_port = one.mark_by_port
    if one.mark_by_port:
        mark_by_port = tuple((port, standing(port, marks), says_update)
                             for port, marks, says_update in one.mark_by_port)
        mark_by_port = tuple(entry for entry in mark_by_port if entry[1])
        marked, mark_offered = cvetell.what_the_mark_stands_for(mark_by_port)
    return replace(one, ports=ports, cves=cves, by_port=by_port, marked=marked,
                   mark_offered=mark_offered, mark_by_port=mark_by_port)


def _display_names(con, workspace_id, told) -> dict:
    """The display name of each server of a batch that still stands, by the
    name the server is found by. Read for the batch's own workspace."""
    own = displayname.display_names_by_host(con, workspace_id=workspace_id)
    return {one.host_name: own[one.host_name] for one in told
            if one.host_name in own and _host_of(con, workspace_id, one) is not None}


def _payload(told, names) -> dict:
    """The generic webhook's JSON for a batch. `server` is the name a server
    is found by, as in every other payload, with its display name beside it
    when it has one. The CVEs are two counts, as in the message: `cves` is
    what the marks on the servers' pages stand for, and `new` how many of
    them this message is about."""
    servers = []
    new, standing = set(), set()
    for one in told:
        entry = {"server": one.host_name,
                 "ports": [str(port) if protocol == "tcp" else f"{port}/{protocol}"
                           for protocol, port in one.ports]}
        if names.get(one.host_name):
            entry["server_name"] = names[one.host_name]
        servers.append(entry)
        new.update(one.cves)
        standing.update(one.marked)
    return {"version": webhook.PAYLOAD_VERSION, "kind": channels.KIND_CVE,
            "servers": servers, "cves": len(standing | new), "new": len(new)}


def _mark(con, batch_id, key, now) -> None:
    con.execute("INSERT OR IGNORE INTO cve_batch_deliveries (batch_id, channel, delivered_at)"
                " VALUES (?, ?, ?)", (batch_id, key, now.isoformat()))
    con.commit()


def _log(con, workspace_id, said, key, now) -> None:
    """One line in the sent log, as `alerts.log_sent` writes one for an
    alert: the servers as the message names them, and its title."""
    servers = dict(said.fields).get("servers") or dict(said.fields).get("server", "")
    con.execute("INSERT INTO sent_log (workspace_id, host_name, detail, channel, sent_at)"
                " VALUES (?, ?, ?, ?, ?)", (workspace_id, servers, said.title, key, now.isoformat()))
    con.commit()
