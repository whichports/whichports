"""The service-wide numbers, counted for the Admin screen.

## What this is for

Before an open beta the question is whether anybody signs up, and then whether
anybody who signs up ever gets as far as a server that reports. Every screen in
this product is one workspace's own servers, so nothing in it could answer
either question. This module counts across every workspace, and the
renderer draws what it counts: `admin_sections` in
`site/app/render_live.py`, over the template in `site/app/build.py`.

## The split, and why it is here rather than in the renderer

The renderer already reads this database, so putting the queries there would
have worked. Two things are true only here, though: whether new accounts are
open is `app/signup.py`'s answer, and how long a host may be quiet before it is
silent is `app/alerts.py`'s. Counting there would have meant a second copy of
both in a tree that cannot import this one, which is how one fact drifts
into two. So the control plane counts and the site draws.

## Read only, and provably so

The connection is opened `mode=ro`, so nothing reached from this module can
write, whatever a later change to it does. That is the same connection the
renderer opens for the same reason.

## Why a missing table counts as zero

Every table read here is created by the code path that produces its rows: the
sweep creates `alerts`, the prober creates `probe_runs`, provider sign-in
creates `oidc_identities`. A database that has no such table is one where that
path has never run, so no rows exist to count and zero is the measurement
rather than a guess. This is not the reachability case of the accuracy
rule: there, an unmeasured port has to say so, because a port that was never
probed is not a port that answered nothing.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

from . import alerts, authz, db, feedback, proberapi, signup, vantages

# The accounts list is whole since 2026-10-07. It was capped at 25 with the
# total beside it, and the screen then showed its first rows with a hint of
# more and no way to the rest (docs/screens/admin/SPEC.md, his `yes admin`).
# None means every row.
NEWEST_ACCOUNTS = None

# The two windows every count on the screen uses. Two rather than one, because
# "is anybody here today" and "is anybody here this week" are different
# questions and a single window answers neither well.
RECENT_HOURS = 24
RECENT_DAYS = 7

# The second window the signup counts use. A month is the honest unit for
# "did the beta bring anybody", where a week is noise.
MONTH_DAYS = 30


def _iso(moment: datetime) -> str:
    """Timestamps in this database are ISO-8601 in UTC, written by
    `datetime.isoformat()`. Strings in one offset sort as the instants they
    name, which is what lets these counts bound a window in SQL."""
    return moment.isoformat()


def _count(con: sqlite3.Connection, sql: str, params=()) -> int:
    """One COUNT(*), or zero when the table is not there yet.

    The module docstring says why zero is the measurement rather than a guess.
    Only OperationalError is caught, which is the missing-table error: a
    malformed query here is a bug and stays loud.
    """
    try:
        row = con.execute(sql, params).fetchone()
    except sqlite3.OperationalError:
        return 0
    return int(row[0]) if row and row[0] is not None else 0


def _rows(con: sqlite3.Connection, sql: str, params=()) -> list:
    """Rows, or none at all when the table is not there yet."""
    try:
        return con.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _parse(value):
    """A stored stamp as a datetime, or None for anything unreadable.

    Nothing here is allowed to end a page. A hand-edited row holding text where
    a timestamp belongs makes one host uncounted, not a screen that 500s.
    """
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def account_numbers(con, now):
    """Accounts, and the four things worth knowing about them before a beta.

    `last_login_at` is written by a password login and by a provider sign-in,
    so "never signed in" is an account that was created and never used. Before
    an open beta that is the number that says whether the register form is
    producing people or rows.
    """
    week = now - timedelta(days=RECENT_DAYS)
    month = now - timedelta(days=MONTH_DAYS)
    users = _rows(con, "SELECT * FROM users")
    # A column added after the first release is absent on a Row read before
    # `accounts.init` has run against this file. Asked once here rather than
    # guarded at every use.
    columns = set(users[0].keys()) if users else set()
    total = len(users)
    disabled = 0
    never = 0
    signed_in_week = 0
    new_week = 0
    new_month = 0
    two_factor = 0
    for user in users:
        if user["disabled_at"]:
            disabled += 1
        last_login = _parse(user["last_login_at"])
        if last_login is None:
            never += 1
        elif last_login >= week:
            signed_in_week += 1
        created = _parse(user["created_at"])
        if created is not None:
            if created >= week:
                new_week += 1
            if created >= month:
                new_month += 1
        if {"totp_secret", "totp_enabled_at"} <= columns \
                and user["totp_secret"] and user["totp_enabled_at"]:
            two_factor += 1
    providers = {}
    for row in _rows(con, "SELECT provider, COUNT(DISTINCT user_id) AS c"
                          " FROM oidc_identities GROUP BY provider ORDER BY provider"):
        providers[row["provider"]] = int(row["c"])
    return {
        "total": total,
        "disabled": disabled,
        "never_signed_in": never,
        "signed_in_week": signed_in_week,
        "new_week": new_week,
        "new_month": new_month,
        "two_factor": two_factor,
        "providers": providers,
    }


def workspace_numbers(con):
    """The funnel, which is the one thing on this screen that is not a count.

    An account that signed up and never added a server is a different failure
    from one that added a server which never reported, and that is a different
    failure again from a server that reported and was never measured from
    outside. Four numbers, each a subset of the one before it.
    """
    total = _count(con, "SELECT COUNT(*) FROM workspaces")
    with_server = _count(
        con, "SELECT COUNT(DISTINCT workspace_id) FROM hosts"
             " WHERE revoked_at IS NULL")
    with_report = _count(
        con, "SELECT COUNT(DISTINCT workspace_id) FROM hosts"
             " WHERE revoked_at IS NULL AND last_report_at IS NOT NULL")
    with_probe = _count(
        con, "SELECT COUNT(DISTINCT h.workspace_id) FROM hosts h"
             " JOIN probe_runs p ON p.host_id = h.id"
             " WHERE h.revoked_at IS NULL")
    return {
        "total": total,
        "with_server": with_server,
        "with_report": with_report,
        "with_probe": with_probe,
    }


def server_numbers(con, now):
    """Hosts by kind and by whether they are still saying anything.

    The silence threshold is `app/alerts.py`'s, imported rather than repeated,
    so this screen and the sweep can never disagree about which hosts are
    quiet. Revoked hosts are counted separately and are in no other number
    here: revoking is the operator saying this is not a server of theirs.
    """
    rows = _rows(con, "SELECT * FROM hosts")
    live = [h for h in rows if not h["revoked_at"]]
    counts = {
        "total": len(live),
        "revoked": len(rows) - len(live),
        "agent": sum(1 for h in live if h["kind"] == db.HOST_KIND_AGENT),
        "address": sum(1 for h in live if h["kind"] == db.HOST_KIND_ADDRESS),
        "paused": sum(1 for h in live if h["paused"]),
        "reporting": 0,
        "silent": 0,
        "never_reported": 0,
    }
    for host in live:
        last = _parse(host["last_report_at"])
        if last is None:
            counts["never_reported"] += 1
        elif (now - last).total_seconds() > alerts.SILENT_AFTER_SECONDS:
            counts["silent"] += 1
        else:
            counts["reporting"] += 1
    return counts


def activity_numbers(con, now):
    """What the service did lately: documents in, probe runs out, alerts open."""
    day = _iso(now - timedelta(hours=RECENT_HOURS))
    week = _iso(now - timedelta(days=RECENT_DAYS))
    return {
        "documents_day": _count(
            con, "SELECT COUNT(*) FROM reports WHERE received_at >= ?", (day,)),
        "documents_week": _count(
            con, "SELECT COUNT(*) FROM reports WHERE received_at >= ?", (week,)),
        "documents_total": _count(con, "SELECT COUNT(*) FROM reports"),
        "probe_runs_day": _count(
            con, "SELECT COUNT(*) FROM probe_runs WHERE started_at >= ?", (day,)),
        "probe_runs_total": _count(con, "SELECT COUNT(*) FROM probe_runs"),
        "alerts_open": _count(
            con, "SELECT COUNT(*) FROM alerts WHERE resolved_at IS NULL"),
        "channels": _count(
            con, "SELECT COUNT(*) FROM notification_channels"),
    }


def newest_accounts(con, limit=NEWEST_ACCOUNTS):
    """The most recent accounts, each with what became of it.

    `servers` is how many live servers that account's workspace holds, which is
    the join that turns a list of addresses into an answer about whether
    anybody got anywhere. Two accounts in one workspace both show that
    workspace's count, because that is what each of them can see.
    """
    users = _rows(con, "SELECT * FROM users ORDER BY created_at DESC, id DESC"
                       + (" LIMIT ?" if limit else ""), (limit,) if limit else ())
    servers = {}
    for row in _rows(con, "SELECT workspace_id, COUNT(*) AS c FROM hosts"
                          " WHERE revoked_at IS NULL GROUP BY workspace_id"):
        servers[row["workspace_id"]] = int(row["c"])
    out = []
    for user in users:
        workspace = user["workspace_id"] if "workspace_id" in user.keys() else 1
        out.append({
            "email": user["email"],
            "created_at": user["created_at"],
            "last_login_at": user["last_login_at"] or "",
            "workspace_id": workspace,
            "servers": servers.get(workspace, 0),
            "disabled": bool(user["disabled_at"]),
        })
    return out


def workspace_rows(con, now):
    """One row per workspace, with what is in it.

    This is what "look into their workspace" needs before anything opens: how
    many accounts, how many servers, how many of those are still reporting, and
    when the newest document arrived. A workspace with an account and no server
    is the first drop in the funnel, and this is where you can see which one it
    was.

    Revoked hosts are left out, the same rule every other count here follows.
    """
    rows = {}
    for workspace in _rows(con, "SELECT * FROM workspaces ORDER BY id"):
        rows[workspace["id"]] = {
            "id": workspace["id"],
            "name": workspace["name"],
            "created_at": workspace["created_at"],
            "accounts": 0,
            "servers": 0,
            "reporting": 0,
            "last_report_at": "",
        }
    for row in _rows(con, "SELECT workspace_id, COUNT(*) AS c FROM users"
                          " GROUP BY workspace_id"):
        if row["workspace_id"] in rows:
            rows[row["workspace_id"]]["accounts"] = int(row["c"])
    for host in _rows(con, "SELECT workspace_id, last_report_at FROM hosts"
                           " WHERE revoked_at IS NULL"):
        entry = rows.get(host["workspace_id"])
        if entry is None:
            continue
        entry["servers"] += 1
        last = _parse(host["last_report_at"])
        if last is None:
            continue
        if (now - last).total_seconds() <= alerts.SILENT_AFTER_SECONDS:
            entry["reporting"] += 1
        if not entry["last_report_at"] or host["last_report_at"] > entry["last_report_at"]:
            entry["last_report_at"] = host["last_report_at"]
    return list(rows.values())


# The quiet-server list is whole since 2026-10-07, for the reason the
# accounts list is. None means every row.
QUIET_SERVERS = None


def quiet_servers(con, now, limit=QUIET_SERVERS):
    """Servers that are not reporting, worst first, with what is known of them.

    **This is the number that had no names behind it.** On 2026-08-28 the real
    box read seventeen servers, three reporting and fourteen never reported, and
    the screen could say only that. Fourteen enrolled servers that have never
    spoken is either a pile of abandoned add-server flows or an install that
    does not work, and before an open beta those are not the same fact at all.

    Never-reported first and silent after, because a server that spoke once and
    stopped is a different and less urgent story than one that never did.
    Inside each group, oldest first: the one added longest ago and still silent
    is the one that has been wrong for longest.

    A revoked host is left out. Revoking is the operator saying this is not a
    server of theirs, and `docs/RECORD.md` records that abandoned add-server
    flows are exactly what gets revoked, so including them would fill this list
    with rows nobody wants.
    """
    rows = []
    for host in _rows(con, "SELECT * FROM hosts WHERE revoked_at IS NULL"):
        last = _parse(host["last_report_at"])
        if last is not None and (now - last).total_seconds() <= alerts.SILENT_AFTER_SECONDS:
            continue
        rows.append({
            "name": host["name"],
            "workspace_id": host["workspace_id"] if "workspace_id" in host.keys() else 1,
            "kind": host["kind"],
            "created_at": host["created_at"],
            "last_report_at": host["last_report_at"] or "",
            "never": last is None,
            "paused": bool(host["paused"]),
        })
    # never-reported before silent, then oldest first inside each group. The
    # created stamp is text and sorts as the instant it names, the same
    # property every other window in this module rests on.
    rows.sort(key=lambda r: (not r["never"], r["created_at"] or ""))
    return (rows[:limit] if limit else rows), len(rows)


def watchdog_stamps(con):
    """When the two background jobs last ran, or empty when they never have.

    **The dead-man sweep had no dead man.** `sweep_state.last_sweep_at` is
    written on every run and was on no screen and not in `/metrics` either, so a
    stopped timer looked exactly like a quiet fleet: the one thing whose job is
    to say a host went silent goes silent itself and nothing says so. The
    prober is the same shape, and worse in one way, because `probe runs, 24
    hours` decays over a whole day without ever being wrong.

    Empty rather than a guess in both cases, the rule the render stamp already
    follows: a screen that invented a time here would be worse than one that
    says nothing.
    """
    sweep = ""
    rows = _rows(con, "SELECT last_sweep_at FROM sweep_state WHERE id = 1")
    if rows and rows[0]["last_sweep_at"]:
        sweep = rows[0]["last_sweep_at"]
    probe = ""
    rows = _rows(con, "SELECT started_at FROM probe_runs"
                      " ORDER BY started_at DESC, id DESC LIMIT 1")
    if rows and rows[0]["started_at"]:
        probe = rows[0]["started_at"]
    return {"sweep": sweep, "probe": probe, "vantages": vantage_stamps(con)}


def vantage_stamps(con):
    """One entry per vantage in the registry: its name, whether it is driven,
    and when it last finished a pass anywhere, or empty when never.

    **Per vantage, because `probe` above cannot see a dead second box.** The
    newest run of any vantage stays fresh while the other keeps running, so
    with two vantages the single stamp says all is well while one of them
    has been silent for a day. A database from before the registry existed
    answers an empty list.
    """
    if not vantages.table_exists(con):
        return []
    out = []
    for vantage in vantages.list_all(con):
        rows = _rows(con, "SELECT finished_at FROM probe_runs WHERE vantage = ?"
                          " AND finished_at IS NOT NULL"
                          " ORDER BY finished_at DESC, id DESC LIMIT 1",
                     (vantage.name,))
        last = rows[0]["finished_at"] if rows and rows[0]["finished_at"] else ""
        out.append({"name": vantage.name, "enabled": vantage.enabled,
                    "last_run": last})
    return out


# --------------------------------------------- the beta's numbers, 2026-10-06
#
# The screen was revised for the self-hosted beta (docs/screens/admin/SPEC.md,
# his picks of docs/record 4.425): a self-hosted instance asks our probers
# through the prober API, and the questions are whether each one is alive,
# what it proved, what it spent, and which one asked for an address somebody
# complained about. Everything here is read on the same read-only connection.
#
# One query per table, never one per instance: the page is read on every
# request and a hundred instances must stay under a second (4.194).

# The sweep timer runs every five minutes with up to thirty seconds of random
# delay (controlplane/ops/whichports-sweep.timer), so two runs fit inside
# eleven minutes and the box cannot flap between runs.
SWEEP_STALE_SECONDS = 11 * 60

# How many days of the abuse log an instance's open row shows per vantage.
LOG_DAYS = 7


def _table_exists(con, name):
    return con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                       (name,)).fetchone() is not None


def instance_rows(con, now):
    """One row per instance ever added, revoked ones included, with what the
    box knows of it.

    **The key's last use is the heartbeat, the batch is a second fact.** An
    instance with nothing to probe sends no batch (`dispatch.py`, no address
    means no batch), but its worker syncs our prober list every fifteen
    minutes through the same key check a batch passes, so `last_used_at` on
    its API key says whether it is alive and `last_batch_at` says whether it
    had anything to probe. The batches themselves are forgotten fifteen
    minutes after they are submitted (`proberapi.sweep`), so the last batch
    comes from the abuse log's `last_at`, which is kept thirty days, or from
    a batch still on the box when that is newer.

    A database written before the stamp's column exists reads it as empty,
    the same way `account_numbers` reads a column added after first release.
    """
    if not _table_exists(con, "probe_instances"):
        return []
    today = _iso(now)[:10]
    hour = _iso(now - timedelta(seconds=3600))
    week = _iso(now - timedelta(days=LOG_DAYS))
    rows = {}
    for inst in _rows(con, "SELECT * FROM probe_instances ORDER BY name"):
        rows[inst["id"]] = {
            "id": inst["id"], "name": inst["name"],
            "created_at": inst["created_at"], "revoked_at": inst["revoked_at"],
            "last_used_at": "", "last_batch_at": "", "proofs": 0,
            "targets_today": 0, "connects_hour": 0,
            "keys": [], "log": [], "failure": None,
        }
    for key in _rows(con, "SELECT * FROM probe_instance_keys ORDER BY id"):
        entry = rows.get(key["instance_id"])
        if entry is None:
            continue
        entry["keys"].append({"kind": key["kind"], "created_at": key["created_at"],
                              "revoked_at": key["revoked_at"]})
        used = key["last_used_at"] if "last_used_at" in key.keys() else None
        if key["kind"] == "api" and used and used > entry["last_used_at"]:
            entry["last_used_at"] = used
    # The abuse log: the newest batch per instance from every row kept, and
    # the last week's rows summed per vantage for the open row.
    for row in _rows(con, "SELECT instance_id, MAX(last_at) AS last FROM prober_api_log"
                          " GROUP BY instance_id"):
        entry = rows.get(row["instance_id"])
        if entry is not None and row["last"]:
            entry["last_batch_at"] = row["last"]
    per_vantage = {}
    targets_today = {}
    for row in _rows(con, "SELECT instance_id, vantage, target, day, batches, connects"
                          " FROM prober_api_log WHERE last_at >= ?"
                          " ORDER BY instance_id, vantage", (week,)):
        if row["instance_id"] not in rows:
            continue
        agg = per_vantage.setdefault((row["instance_id"], row["vantage"]),
                                     {"targets": set(), "batches": 0, "connects": 0})
        agg["targets"].add(row["target"])
        agg["batches"] += int(row["batches"])
        agg["connects"] += int(row["connects"])
        if row["day"] == today:
            targets_today.setdefault(row["instance_id"], set()).add(row["target"])
    for (instance_id, vantage), agg in sorted(per_vantage.items()):
        rows[instance_id]["log"].append({"vantage": vantage, "targets": len(agg["targets"]),
                                         "batches": agg["batches"], "connects": agg["connects"]})
    for instance_id, targets in targets_today.items():
        rows[instance_id]["targets_today"] = len(targets)
    # Batches still on the box: newer than the log when one is in flight, and
    # the only place a failure class is kept.
    for row in _rows(con, "SELECT instance_id, vantage, submitted_at, finished_at, failure"
                          " FROM prober_api_batches ORDER BY submitted_at"):
        entry = rows.get(row["instance_id"])
        if entry is None:
            continue
        if row["submitted_at"] > entry["last_batch_at"]:
            entry["last_batch_at"] = row["submitted_at"]
        if row["failure"]:
            entry["failure"] = {"error": row["failure"], "vantage": row["vantage"],
                                "at": row["finished_at"] or row["submitted_at"]}
    for row in _rows(con, "SELECT instance_id, SUM(connects) AS c FROM prober_api_charges"
                          " WHERE submitted_at >= ? GROUP BY instance_id", (hour,)):
        entry = rows.get(row["instance_id"])
        if entry is not None:
            entry["connects_hour"] = int(row["c"] or 0)
    # Live proofs per instance account, in one query, through the one module
    # that may read the registry's tables (`authz.live_proof_counts`).
    # `test_the_proof_count_is_live_for_accounts_own` holds the two together.
    try:
        counts = authz.live_proof_counts(con, now)
    except sqlite3.OperationalError:
        counts = {}
    for instance_id, entry in rows.items():
        entry["proofs"] = counts.get(authz.account_for_instance(instance_id), 0)
    return list(rows.values())


def beta_list(con):
    """Who asked for an invitation, newest first, and how many."""
    rows = [{"email": r["email"], "servers": r["servers"] or "",
             "created_at": r["created_at"]}
            for r in _rows(con, "SELECT email, servers, created_at FROM beta_signups"
                                " ORDER BY created_at DESC, email")]
    return {"rows": rows, "total": len(rows)}


# The one word the lookup answers with for input that is not a public address.
NOT_AN_ADDRESS = "not an address"


def address_lookup(db_path, address):
    """Which instance asked our probers to reach this address, and when.

    The read he needs when a complaint names an address and an hour. The
    address is normalised the way the registry normalises a target, so one
    spelling finds every row, and read by the log's own index through
    `proberapi.log_for_target`. The address is written nowhere: this opens the
    read-only connection every other number here uses.
    """
    text = address.strip() if isinstance(address, str) else ""
    if not text or len(text) > 64:
        return {"address": text[:64], "error": NOT_AN_ADDRESS, "rows": []}
    try:
        canonical, _family = authz.normalise_target(text)
    except authz.TargetError:
        return {"address": text, "error": NOT_AN_ADDRESS, "rows": []}
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        if not _table_exists(con, "prober_api_log"):
            return {"address": canonical, "error": "", "rows": []}
        found = proberapi.log_for_target(con, canonical)
    finally:
        con.close()
    rows = [{"instance": r["instance_name"] or "", "vantage": r["vantage"], "day": r["day"],
             "first_at": r["first_at"], "last_at": r["last_at"],
             "batches": int(r["batches"]), "connects": int(r["connects"])}
            for r in found]
    # Newest first: the day, then the last time inside it.
    rows.sort(key=lambda r: (r["day"], r["last_at"]), reverse=True)
    return {"address": canonical, "error": "", "rows": rows}


def feedback_rows(con: sqlite3.Connection) -> dict:
    """The Feedback tab's rows as `feedback.listing` gives them, the open
    ones and the done ones, newest first in each, and none of either on a
    box without the table, by the missing-table rule above."""
    try:
        return {"open": feedback.listing(con, done=False),
                "done": feedback.listing(con, done=True)}
    except sqlite3.OperationalError:
        return {"open": [], "done": []}


def collect(db_path, now=None):
    """Every number the Admin screen shows, from one read-only connection.

    Returned as plain data rather than as rows, so the renderer that draws it
    never holds a database handle and the site tests can build one of these by
    hand. The two thresholds travel with the numbers: the renderer cannot
    import this tree (`site/app/joinbridge.py` says why), and a second copy of
    a threshold is how one fact drifts into two.
    """
    now = now or datetime.now(timezone.utc)
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        stats = {
            "accounts": account_numbers(con, now),
            "workspaces": workspace_numbers(con),
            "servers": server_numbers(con, now),
            "activity": activity_numbers(con, now),
            "newest": newest_accounts(con),
            "workspace_rows": workspace_rows(con, now),
            "watchdog": watchdog_stamps(con),
            "accounts_total": _count(con, "SELECT COUNT(*) FROM users"),
            # Whether the front door is open, from the one module that decides
            # it. A word, so the screen never has to know how it is configured.
            "signups": signup.mode(),
            "signups_allowed": len(signup.allow_list()),
            "instances": instance_rows(con, now),
            "beta": beta_list(con),
            "thresholds": {"silent_after": alerts.SILENT_AFTER_SECONDS,
                           "sweep_stale": SWEEP_STALE_SECONDS},
            # Open feedback messages, zero until the wire's table exists
            # (docs/screens/feedback/BRIEF.md), by the missing-table rule above.
            "feedback_open": _count(
                con, "SELECT COUNT(*) FROM feedback WHERE done_at IS NULL"),
            # The Feedback tab's rows, open and done, from the same table.
            "feedback": feedback_rows(con),
            # Filled by the lookup route and nothing else.
            "lookup": None,
        }
        # Two values from one walk, so the list and its total cannot disagree.
        stats["quiet_servers"], stats["quiet_servers_total"] = \
            quiet_servers(con, now)
    finally:
        con.close()
    return stats
