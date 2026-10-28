"""One short message when a silent agent reports again.

A person who was told an agent stopped reporting was never told it reports
again, and silence then quiet reads as still broken (`docs/RECORD.md` 4.228,
decided 4.452). The silence's own message already ends "Nothing else will be
sent about this server until it reports again." This module is that message.

**Who is told: the channels that were told of the silence, and no others.**
`alerts.log_sent` writes a channel down as told at the moment it accepts the
silence's message (`silence_told`). A channel added later, one that failed,
and one that does not take the kind were not told and hear nothing.

**When.** All of these hold:

- the silence is resolved, and a report arrived after it was raised. A
  silence closed by a pause or by removing the server is not a report, and a
  server that never reported has none. A paused server whose agent then
  reports is said to report, because that is what was measured;
- the server is not removed and no silence is open on it. A server that
  came back and stopped again is not said to report;
- it was resolved inside the last day. A destination that could not be
  reached for a day does not hear a day later that an agent came back.

**Once.** One message for a server and a channel, however many silences of
that server the channel was told of, and the row is settled when the channel
accepts it. A failure is tried again at the next sweep, and one channel's
failure is never another's.

**What is let go, and settled without a message**, each by a rule
`docs/PRODUCT.md` 4c already has: a server that is muted now, because a mute
records and does not queue, a channel that no longer takes the kind, a
removed server, and a silence resolved more than a day ago.

It says what was measured: the agent reports, and how long no report came,
from the last report before the silence to the first after. Never that the
server was down. The words are `alertwords.said_reporting_again`, one
description for every channel.
"""

import dataclasses
import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta

from . import alerts, alertwords, channels, db, displayname, finding_alerts, notify, senders, webhook

# How long after a silence was resolved its message is still sent.
SEND_WITHIN = timedelta(hours=24)

# What the generic webhook's JSON says its kind is. Not a kind a destination
# chooses: whoever takes "An agent stopped reporting" hears this too.
KIND_AGAIN = "reporting again"


@dataclasses.dataclass(frozen=True)
class Back:
    """One server a channel is told about: the silences this settles, when
    the newest of them was raised, and how many minutes no report came, or
    None when one of the two reports that bound it is not held."""
    host_id: int
    host_name: str
    workspace_id: int
    alert_ids: tuple
    raised_at: str
    minutes: int | None


def detail(minutes) -> str:
    """The line the sent log and the webhook's JSON carry."""
    if minutes is None:
        return "reporting again"
    return f"reporting again, no report for {alertwords.lasted(minutes)}"


def due(con: sqlite3.Connection, channel: str, now: datetime, workspace_id: int | None = None) -> list:
    """The servers this channel is to be told about now, one `Back` each.
    What can never be told any more is settled on the way, with no message.

    `workspace_id` is the channel row's own workspace, so a row is asked
    about its own workspace's servers only, also when two workspaces post to
    one address and so share a delivery key. None is every workspace, for
    the operator's own arrangement, as `alerts.pending_for_channel` has it.
    """
    scope = "" if workspace_id is None else " AND h.workspace_id = ?"
    params = (channel,) if workspace_id is None else (channel, workspace_id)
    rows = con.execute(
        "SELECT t.alert_id, a.host_id, a.raised_at, a.resolved_at, h.name, h.workspace_id,"
        "       h.revoked_at"
        "  FROM silence_told t JOIN alerts a ON a.id = t.alert_id JOIN hosts h ON h.id = a.host_id"
        " WHERE t.channel = ? AND t.again_at IS NULL AND a.resolved_at IS NOT NULL" + scope +
        " ORDER BY a.id", params).fetchall()
    by_host = {}
    for row in rows:
        resolved = alerts.parse_stamp(row["resolved_at"])
        if row["revoked_at"] or resolved is None or now - resolved > SEND_WITHIN:
            settle(con, [row["alert_id"]], channel, now)
            continue
        if alerts.open_alert(con, row["host_id"], alerts.KIND_SILENT) is not None:
            continue
        if _first_report_after(con, row["host_id"], row["raised_at"]) is None:
            continue
        if finding_alerts.silenced(con, row["host_id"], None, None, None,
                                   now=now) == finding_alerts.SILENCE_MUTE:
            settle(con, [row["alert_id"]], channel, now)
            continue
        by_host.setdefault(row["host_id"], []).append(row)
    out = []
    for host_id, of_host in by_host.items():
        newest = of_host[-1]
        out.append(Back(host_id=host_id, host_name=newest["name"], workspace_id=newest["workspace_id"],
                        alert_ids=tuple(row["alert_id"] for row in of_host), raised_at=newest["raised_at"],
                        minutes=_minutes_without(con, host_id, newest["raised_at"])))
    return sorted(out, key=lambda back: back.host_name)


def _first_report_after(con, host_id, raised_at):
    """When the first report after the silence was raised arrived, or None.
    Compared as text: both stamps are `isoformat()` of an aware UTC time, so
    the strings sort as the instants they name (`store.now_utc`)."""
    row = con.execute("SELECT MIN(received_at) FROM reports WHERE host_id = ? AND received_at > ?",
                      (host_id, raised_at)).fetchone()
    return alerts.parse_stamp(row[0])


def _minutes_without(con, host_id, raised_at):
    """Whole minutes from the last report before the silence was raised to
    the first after, from the reports' own arrival times."""
    row = con.execute("SELECT MAX(received_at) FROM reports WHERE host_id = ? AND received_at <= ?",
                      (host_id, raised_at)).fetchone()
    before, after = alerts.parse_stamp(row[0]), _first_report_after(con, host_id, raised_at)
    if before is None or after is None:
        return None
    return int((after - before).total_seconds() // 60)


def settle(con: sqlite3.Connection, alert_ids, channel: str, now: datetime) -> None:
    """Write down that this channel is done with these silences: it was
    told, or it is let go."""
    con.executemany("UPDATE silence_told SET again_at = ? WHERE alert_id = ? AND channel = ?"
                    " AND again_at IS NULL", [(now.isoformat(), alert_id, channel) for alert_id in alert_ids])
    con.commit()


def _log(con, back: Back, channel: str, now: datetime) -> None:
    """One line in the sent log, as `alerts.log_sent` writes one."""
    con.execute("INSERT INTO sent_log (workspace_id, host_name, detail, channel, sent_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (back.workspace_id, back.host_name, detail(back.minutes), channel, now.isoformat()))
    con.commit()


def deliver(con: sqlite3.Connection, now: datetime, *, config=None, use_environment=False,
            mail_rows=(), chat_rows=(), env=None, send_mail=None, send_chat=None) -> int:
    """Tell every channel that is due. Returns how many messages went out.

    The destinations are the sweep's own (`sweep_cli.mail_targets` and
    `channel_targets`): the environment's single recipient for the
    operator's workspace when `use_environment` says so, every email row
    and every chat row. The two senders are arguments so the tests stand
    where the relay and the chat services stand.
    """
    config = config or notify.config_from_env()
    # Looked up at the call, as the sweep's own sends are, so whoever stands
    # in for the relay stands in here too.
    send_mail = send_mail or notify.send
    send_chat = send_chat or senders.deliver
    names = displayname.display_names_by_host(con)
    sent = 0

    def tell(back, key, hand_over) -> int:
        said = alertwords.said_reporting_again(back.host_name, back.minutes,
                                               names.get(back.host_name, ""))
        ok, reason = hand_over(back, said)
        if not ok:
            print(f"not sent, {back.host_name} reporting again: {reason}")
            return 0
        settle(con, back.alert_ids, key, now)
        _log(con, back, key, now)
        return 1

    if use_environment:
        key = alerts.SENT_BY_ENVIRONMENT_MAIL
        for back in due(con, key, now, workspace_id=db.DEFAULT_WORKSPACE_ID):
            sent += tell(back, key, lambda _back, said: send_mail(*notify.mail(said)[:2], config,
                                                                 notify.mail(said)[2]))
    for channel in list(mail_rows) + list(chat_rows):
        key = alerts.key_for_channel(channel)
        backs = due(con, key, now, workspace_id=channel.workspace_id)
        if not channel.takes(channels.KIND_SILENT):
            for back in backs:
                settle(con, back.alert_ids, key, now)
            continue
        for back in backs:
            if channel.type == channels.TYPE_EMAIL:
                to = channel.resolve(env)
                if not to:
                    continue
                one = replace(config, to=to, sender=config.sender or to)

                def mailed(_back, said, one=one, channel=channel):
                    ok, reason = send_mail(*notify.mail(said)[:2], one, notify.mail(said)[2])
                    alerts.note_mail_answer(con, channel, ok, reason, now)
                    return ok, reason

                sent += tell(back, key, mailed)
            else:
                sent += tell(back, key, lambda back, said, channel=channel: send_chat(
                    channel, senders.plain(senders.message(said)),
                    webhook.payload_for_alert(KIND_AGAIN, back.host_name, detail(back.minutes),
                                              back.raised_at, names.get(back.host_name, "")),
                    env, message=senders.message(said)))
    return sent
