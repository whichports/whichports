#!/usr/bin/env python3
"""Render the dashboard from the control plane's database.

    python3 render_live.py --db /var/lib/whichports-controlplane/whichports.db \
                           --out-dir /srv/whichports/app

Same template as build.py, fed with what the agents actually reported instead
of the sample lists.

## Rendered per request, one page per workspace

**On the production box the control plane calls `render()` when a browser
asks**, one page per workspace, because a page rendered once for the whole
fleet physically cannot show two people different things and a page rendered
on a timer cannot show an action's result on the reload after it
(`docs/RECORD.md` 4.102). Which workspace comes from the browser's session,
read where the session is (`controlplane/app/dashboard.py` and the route in
`controlplane/app/web_auth.py`), and how this module is importable from there
at all is `controlplane/app/renderbridge.py`. Every read below that reaches a
host row carries the workspace, and `controlplane/app/db.py` explains why
scoping at `hosts` is enough for everything hanging off it.

The command line above still writes files, one per workspace under
`<out-dir>/w/<workspace_id>/`. Nothing on the box serves those any more: the
CLI is for development and the tests, where a file to open and diff is worth
having.

`workspace_id=None` renders the whole fleet into one page. Nothing serves that
to a browser: it is what the tests use when the workspace is not what they are
about.

The honesty rules of docs/PRODUCT.md govern every string built here:

  - Nothing invented. A live page never shows sample data. Screens whose
    machinery is not built (alerting's channels, the provider API) say so with
    the planned treatment instead of pretending.
  - A reachability claim only where the prober measured one, and the port says
    `not tested` everywhere else rather than inheriting a neighbour's answer
    (PRODUCT.md 4b and 8b). The join engine decides that, not this file:
    `site/app/joinbridge.py` reaches it and `load_findings` calls it.
  - A silent agent is itself worth the warn tone (PRODUCT.md 4c): a host
    whose last document is older than two timer ticks says so.
  - Nothing leaves the screen quietly. A host's Changes tab reads a bounded
    window of documents and says on screen what period it covers and which cap
    ended it.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import sqlite3
import sys
from collections import namedtuple
from datetime import datetime, timedelta, timezone

# Two ways into this module, and the difference is the name it carries.
#
# Run as a script, or imported bare from site/app the way the tests do, it has
# no package, so it puts site/ on the path and reaches its neighbours through
# the `app` namespace package, exactly as it always has.
#
# Loaded as part of a package it uses relative imports instead, and that is
# what lets the control plane render a page per request:
# `controlplane/app/renderbridge.py` loads this file as a submodule of its own
# alias package, because in that process the name `app` is already the control
# plane's own package and `import app.build` would look for the template in
# the wrong tree. `site/app/joinbridge.py` explains the collision in the other
# direction. `theme` is not beside this file, so the bridge registers it in
# sys.modules before loading this, and a bridge that forgot would fail loudly
# on the import below rather than render without the design system.
if __package__:
    import theme  # noqa: E402
    from . import build as tpl  # noqa: E402  (site/app/build.py, the template)
    from . import packetpath as pp  # noqa: E402  (the walk, and where its order comes from)
    from . import joinbridge  # noqa: E402  (the control plane's join engine)
else:
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    import theme  # noqa: E402
    import app.build as tpl  # noqa: E402  (site/app/build.py, the template)
    import app.packetpath as pp  # noqa: E402  (the walk, and where its order comes from)
    import app.joinbridge as joinbridge  # noqa: E402  (the control plane's join engine)

# A host on the packaged 15 minute timer has answered twice inside this
# window. Beyond it the row takes the warn tone and says silent.
#
# `controlplane/app/alerts.py` OWNS this number. It is repeated here because
# the two packages are both called `app` and neither can import the other, and
# a test in the control plane suite fails if they ever disagree. Change it
# there first: a dashboard that says silent while the sweep says fine is worse
# than either answer on its own.
SILENT_AFTER = 35 * 60

# How far back a host's Changes tab reads.
#
# This used to be a count of twelve documents per host. On the packaged
# fifteen minute timer that is a window of about two and three quarter hours,
# and every change older than that left the screen without the screen saying
# anything. The store keeps the documents, only the read was capped.
#
# Seven days is the bound now and the screen states it. Reading a document
# out of SQLite and digesting it costs about 0.35 ms, measured on a laptop
# against a week of three hosts replayed from a production snapshot: 2,322
# documents, 762 ms to read them all, 815 ms for the whole render. The timer
# gives it a minute. The cost is linear in hosts and in days, so widening this
# a lot is a decision to take with a measurement, not a guess.
HISTORY_DAYS = 7

# A backstop per host, so a host reporting far more often than the packaged
# timer cannot make one render unbounded. Seven days at fifteen minutes is
# 672 documents, so this only bites on a host reporting more often than about
# every ten minutes, and when it bites the screen names the host and says how
# far its history actually reaches.
HISTORY_MAX_DOCS = 1000

# Change rows shown in one host's Changes tab. A row is about 290 bytes of
# HTML, measured, so the cap is worth about 88 kB on a page that is already
# about 1.1 MB. When it bites the screen says how many changes there were in
# the period.
CHANGES_LIMIT = 300


class Window:
    """The three bounds the change views run under, carried together.

    They travel as one object so every sentence on the screen is built from
    the numbers this render actually used, rather than from a constant read
    somewhere else that a caller may have overridden.
    """

    def __init__(self, days=HISTORY_DAYS, max_docs=HISTORY_MAX_DOCS, limit=CHANGES_LIMIT):
        self.days = days
        self.max_docs = max_docs
        self.limit = limit


# What the Add window says about mail today. The recipient is set in
# the config file on the box and the dead-man sweep is what mails it, so the
# dialog says that instead of taking an address the page cannot store.

# ---------------------------------------------------------------- Admin
#
# The screen an account with the admin flag gets, and nobody else. The numbers
# behind it are counted by `controlplane/app/adminstats.py`, which says why the
# counting lives there and the drawing lives here. This function only turns a
# dict into sections, so it is testable with a dict written by hand and holds
# no database access of its own.


def short_date(value):
    """A stored ISO stamp as a date somebody reads, or empty when there is
    nothing stored. Anything unparseable prints as it was stored rather than
    as a guess: a row nobody can read is still a row that exists."""
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value)).strftime("%d %b %Y")
    except ValueError:
        return str(value)


def quiet_state(row, now):
    """The tone and the word for a server that is not reporting.

    **It defers to `freshness` rather than deciding for itself.** That function
    is what the fleet row uses, and DESIGN.md section 3 is explicit that a
    status keeps one meaning across the product: the first version of this
    table gave `never reported` the fail tone while the fleet gives it `off`,
    so the same server read as a red problem on one screen and a grey fact on
    the other. `test_the_quiet_list_agrees_with_the_fleet` holds it.

    The dict is turned back into the shape `freshness` reads, which is cheaper
    than a second copy of its three rules and cannot disagree with them.
    """
    return freshness({
        "revoked_at": None,
        "paused": row["paused"],
        "last_report_at": row["last_report_at"] or None,
    }, now)


def ago(value, now):
    """How long ago a stored stamp was, or `never` when there is none.

    `never` rather than a dash or an empty cell, because this is read as an
    answer: the whole point of the two cards it feeds is that a job which has
    stopped must not look like a job with nothing to do.
    """
    if not value:
        return "never"
    try:
        then = datetime.fromisoformat(str(value))
    except ValueError:
        return "unreadable"
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return f"{age_text(then, now)} ago"


def instance_state(row, now, silent_after):
    """The tone and the word for a self-hosted instance, from its API key's
    last use: the freshness axis's own four words at the same ages, so he
    reads nothing new (docs/screens/admin/SPEC.md, decided 2026-10-06). The
    batch is a second fact and its own column: an instance with nothing to
    probe sends none and is not called silent for it."""
    if row.get("revoked_at"):
        return "off", "revoked"
    if not row.get("last_used_at"):
        return "off", "not watched"
    last = datetime.fromisoformat(row["last_used_at"])
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    if (now - last).total_seconds() > silent_after:
        return "warn", f"silent {age_text(last, now)}"
    return "ok", "reporting"


def workspace_state(row, now):
    """The tone and the word for a tenant: the freshness word of its newest
    document, because the question of a tenant is whether anybody is home,
    and the one abandoned enrolment that would paint it `not watched` is
    named on the Servers tab."""
    if not row["servers"]:
        return "off", "no server"
    if row["reporting"]:
        return "ok", "reporting"
    if row["last_report_at"]:
        last = datetime.fromisoformat(row["last_report_at"])
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        return "warn", f"silent {age_text(last, now)}"
    return "off", "not watched"


def _age_seconds(value, now):
    """How old a stored stamp is, or None when there is none or it is not
    readable, so the caller's threshold cannot be met by a guess."""
    if not value:
        return None
    try:
        then = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (now - then).total_seconds()


def admin_strip(stats, now):
    """The four boxes and their tones, from the thresholds that came with
    the numbers (docs/screens/admin/SPEC.md 2). A box is a fault when the
    thing it watches is behind its timer by more than two periods, and a
    zero of zero is never one."""
    thresholds = stats.get("thresholds") or {}
    silent_after = thresholds.get("silent_after", SILENT_AFTER)
    sweep_stale = thresholds.get("sweep_stale", 11 * 60)
    live = [i for i in stats.get("instances", ()) if not i.get("revoked_at")]
    reporting = [i for i in live if instance_state(i, now, silent_after)[1] == "reporting"]
    watchdog = stats.get("watchdog") or {}
    vantages = [v for v in watchdog.get("vantages", ()) if v.get("enabled", True)]
    passed = [v for v in vantages
              if (age := _age_seconds(v.get("last_run"), now)) is not None and age <= silent_after]
    sweep_age = _age_seconds(watchdog.get("sweep"), now)
    activity = stats.get("activity") or {}
    beta_total = (stats.get("beta") or {}).get("total", 0)
    boxes = [
        ("Instances reporting", len(reporting), [f"of {len(live)} live"],
         "fail" if live and len(reporting) < len(live) else "", "instances"),
        ("Waiting for an invite", beta_total, ["on the beta list"], "", "betalist"),
        ("Probers", f"{len(passed)} of {len(vantages)}",
         [f"{v['name']} {ago(v.get('last_run'), now)}" for v in vantages]
         + [f"{activity.get('probe_runs_day', 0)} runs in 24h"],
         "fail" if vantages and len(passed) < len(vantages) else "", "instances"),
        ("Sweep", ago(watchdog.get("sweep"), now),
         [f"{activity.get('documents_day', 0)} documents in 24h"],
         "fail" if sweep_age is None or sweep_age > sweep_stale else "", "servers"),
    ]
    return boxes


def admin_badge_count(stats, now):
    """What the Admin entry in the top bar carries: the strip's fault boxes
    plus the open feedback messages, none when both are zero."""
    faults = sum(1 for _l, _n, _lines, tone, _k in admin_strip(stats, now) if tone == "fail")
    return faults + int(stats.get("feedback_open") or 0)


def admin_sections(stats, now=None, csrf=""):
    """The Admin screen's tabs, as the template wants them: `(key, label,
    body)` per tab, keys from `tpl.ADMIN_TABS`, in B's shape
    (docs/screens/admin/SPEC.md).

    The thresholds come with the numbers: this tree cannot import the control
    plane, and a second copy of a threshold is how one fact drifts into two.
    """
    now = now or datetime.now(timezone.utc)
    thresholds = stats.get("thresholds") or {}
    silent_after = thresholds.get("silent_after", SILENT_AFTER)

    # ---- Instances: the lookup, then the table, state first
    lookup = stats.get("lookup")
    lookup_html = tpl.lookup_form_html(csrf, (lookup or {}).get("address", ""))
    if lookup is not None:
        rows = [(r["instance"], r["vantage"], r["day"], ago(r["first_at"], now),
                 ago(r["last_at"], now), r["batches"], r["connects"])
                for r in lookup.get("rows", ())]
        lookup_html += tpl.lookup_result_html(lookup.get("address", ""),
                                              lookup.get("error", ""), rows)
    # The worse word first, as the Fleet sorts, and a revoked instance last:
    # it is gone the way a removed server is.
    def instance_rank(row):
        tone, word = instance_state(row, now, silent_after)
        order = {"revoked": 3, "reporting": 2, "not watched": 1}
        return (order.get(word, 0), row["name"])

    instance_rows = []
    live = revoked = 0
    for row in sorted(stats.get("instances", ()), key=instance_rank):
        tone, word = instance_state(row, now, silent_after)
        if row.get("revoked_at"):
            revoked += 1
        else:
            live += 1
        opened = tpl.instance_open_html(
            [(k["kind"], short_date(k["created_at"]), short_date(k["revoked_at"]))
             for k in row.get("keys", ())],
            [(entry["vantage"], entry["targets"], entry["batches"], entry["connects"])
             for entry in row.get("log", ())],
            ((row["failure"]["error"], row["failure"]["vantage"], ago(row["failure"]["at"], now))
             if row.get("failure") else None))
        instance_rows.append(tpl.instance_row_html(
            tone, word, row["name"], ago(row.get("last_used_at"), now),
            ago(row.get("last_batch_at"), now),
            tpl.plural(row.get("proofs", 0), "address", "addresses"),
            row.get("targets_today", 0),
            f"{row.get('connects_hour', 0):,} of {CONNECTS_PER_HOUR:,}", opened))
    instances_body = lookup_html + tpl.sec_block(
        "", tpl.admin_table_html("irow", tpl.INSTANCE_COLUMNS, "".join(instance_rows),
                                 "no instance yet"),
        hint=f"{live} live, {revoked} revoked" if (live or revoked) else "")

    # ---- Beta list
    beta = stats.get("beta") or {"rows": [], "total": 0}
    beta_rows = [(r["email"], r.get("servers", ""), short_date(r["created_at"]))
                 for r in beta.get("rows", ())]
    beta_body = tpl.sec_block("", tpl.admin_beta_html(beta_rows),
                              hint=f"{beta['total']} waiting" if beta.get("total") else "")

    # ---- Workspaces, each with its word, then the newest accounts
    workspace_rows = []
    for row in stats.get("workspace_rows", ()):
        tone, word = workspace_state(row, now)
        workspace_rows.append(tpl.workspace_row_html(
            tone, word, row["id"], row["name"], row["accounts"], row["servers"],
            row["reporting"], short_date(row["last_report_at"]) or "never"))
    # A workspace is a name on this screen, never a bare number.
    names = {row["id"]: row["name"] for row in stats.get("workspace_rows", ())}

    def workspace_name(workspace_id):
        return names.get(workspace_id) or f"workspace {workspace_id}"

    accounts = [(row["email"], short_date(row["created_at"]), row["workspace_id"],
                 workspace_name(row["workspace_id"]),
                 row["servers"], short_date(row["last_login_at"]) or "never")
                for row in stats["newest"]]
    workspaces_body = (
        tpl.sec_block("", tpl.admin_table_html("wrow2", tpl.WORKSPACE_COLUMNS,
                                               "".join(workspace_rows), "no workspace yet"))
        + tpl.sec_block("Accounts", tpl.admin_accounts_html(accounts),
                        hint=str(len(accounts)) if accounts else ""))

    # ---- Servers: the three cards he acts on, then the names behind them
    servers = stats["servers"]
    server_cards = [("servers reporting", servers["reporting"]),
                    ("silent", servers["silent"]),
                    ("not watched", servers["never_reported"])]
    quiet_rows = []
    for row in stats.get("quiet_servers", ()):
        tone, word = quiet_state(row, now)
        quiet_rows.append((row["name"], row["workspace_id"],
                           workspace_name(row["workspace_id"]),
                           short_date(row["created_at"]),
                           ago(row["last_report_at"], now), tone, word))
    # The list is whole, so the hint is how many and never "of more".
    quiet_hint = str(len(quiet_rows)) if quiet_rows else ""
    servers_body = (tpl.stats_html(server_cards)
                    + tpl.sec_block("Not reporting", tpl.admin_quiet_html(quiet_rows),
                                    hint=quiet_hint))

    # ---- Feedback: the open messages, then the done ones under a fold.
    # The sender is the instance's name as the registry has it, or the
    # workspace's name when the row was written on this box, the same
    # rule as the quiet list: a name on this screen, never a bare number.
    instance_names = {row["id"]: row["name"] for row in stats.get("instances", ())}

    def sender_name(row):
        if row.get("instance_id") is not None:
            return instance_names.get(row["instance_id"]) or f"instance {row['instance_id']}"
        return workspace_name(row.get("workspace_id"))

    def feedback_cells(row):
        return (row["id"], when_text(row["received_at"]), sender_name(row),
                row["kind"], row["screen"], row["instance_version"], row["words"])

    messages = stats.get("feedback") or {"open": [], "done": []}
    feedback_body = tpl.admin_feedback_html(
        [feedback_cells(row) for row in messages.get("open", ())],
        [feedback_cells(row) for row in messages.get("done", ())])

    return [
        ("instances", tpl.ADMIN_TAB_LABELS["instances"], instances_body),
        ("betalist", tpl.ADMIN_TAB_LABELS["betalist"], beta_body),
        ("feedback", tpl.ADMIN_TAB_LABELS["feedback"], feedback_body),
        ("workspaces", tpl.ADMIN_TAB_LABELS["workspaces"], workspaces_body),
        ("servers", tpl.ADMIN_TAB_LABELS["servers"], servers_body),
        ("billing", tpl.ADMIN_TAB_LABELS["billing"], tpl.ADMIN_PLANNED_BODY),
    ]


# What one instance may spend in any hour, the prober API's own number
# (`controlplane/app/proberapi.py`, CONNECTS_PER_HOUR). Written here because
# this tree cannot import that one; test_admin_view holds the two together
# through the control plane's own suite.
CONNECTS_PER_HOUR = 30_000


# ---------------------------------------------------------------- reading

def utc_from_unix(value):
    """A unix timestamp as a UTC datetime, or None when it is not one.

    mtime_unix is a number the host chose and the shape check can only say it
    is a number. 10**30 is a number, and it raises OverflowError or OSError out
    of fromtimestamp depending on the platform, which ended the render for the
    whole fleet until 2026-08-16. A date nobody can compute is reported as
    such rather than guessed at.
    """
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def age_text(then, now):
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{seconds // 86400}d"


def host_kind(row) -> str:
    """"agent" or "address". A row from before kinds existed is an agent host,
    which is what every row was."""
    return row["kind"] if "kind" in row.keys() else "agent"


def address_freshness(row, proof, findings, now):
    """The state word of a host with no agent, and when it was last probed.

    An address host cannot be reporting or silent: nothing on it reports.
    What it can be is proved, so a pass can look at it, and looked at. So the
    words are about those two facts and nothing else. Revoked and paused keep
    their meanings from `freshness`.

    Returns (tone, word, last probe as an age or "").
    """
    if row["revoked_at"]:
        return "off", "revoked", ""
    if ("paused" in row.keys()) and row["paused"]:
        return "off", "paused", ""
    measured = [f.outside.measured_at for f in findings
                if f.outside.measured and f.outside.measured_at]
    last = ""
    if measured:
        try:
            last = age_text(datetime.fromisoformat(max(measured)), now)
        except ValueError:
            last = ""
    if not proof.get("live"):
        return "warn", "no proof", last
    if not measured:
        # `not probed yet` until 2026-10-09 (docs/record 4.447).
        return "off", "not watched", ""
    return "ok", "watched", last


def last_report_text(row, now):
    """How long ago the host last reported, as an age, or empty when it never
    did or the stamp will not read."""
    if not row["last_report_at"]:
        return ""
    try:
        return f"{age_text(datetime.fromisoformat(row['last_report_at']), now)} ago"
    except ValueError:
        return ""


def is_paused(row):
    """Whether this server is paused. Databases written before the column
    existed lack it, and absent is not paused."""
    return ("paused" in row.keys()) and bool(row["paused"])


def freshness(row, now):
    if row["revoked_at"]:
        return "off", "revoked"
    # Databases written before the paused column existed lack it until the
    # ingest migrates them; the read-only renderer treats absent as false.
    if ("paused" in row.keys()) and row["paused"]:
        return "off", "paused"
    if not row["last_report_at"]:
        # `never reported` until 2026-10-09: one word with an address host
        # nobody has probed, since both say nothing is known of this server
        # yet (docs/DESIGN.md section 3, docs/record 4.447).
        return "off", "not watched"
    last = datetime.fromisoformat(row["last_report_at"])
    if (now - last).total_seconds() > SILENT_AFTER:
        return "warn", f"silent {age_text(last, now)}"
    return "ok", "reporting"


class History:
    """One host's change history window, and the truth about its edges.

    `digests` is newest first. `oldest` is when the oldest document in the
    window was received, or None when the host has none. `capped` is True only
    when HISTORY_MAX_DOCS ended the read before the time window did, which is
    the one case where the covered period is shorter than the page says and
    the screen has to name the host.

    `unreadable` counts documents in this window that would not read at all.
    It is a separate field rather than a shorter `digests` list on purpose: a
    document nobody could read and a document that was never sent are
    different facts, and merging them is the mistake docs/RECORD.md 4.46
    records, where a denied firewall read and an empty firewall looked
    identical.
    """

    def __init__(self, digests, oldest, capped, unreadable=0):
        self.digests = digests
        self.oldest = oldest
        self.capped = capped
        self.unreadable = unreadable


def log_unreadable(host_id, received_at):
    """Say it out loud on stderr, which on the box is the journal the sweep
    already writes to. A document we could not read is a fault worth someone
    seeing, and swallowing it to keep the render quiet is downgrading an
    error to make output cleaner, which this project never does."""
    when = received_at.isoformat() if received_at else "at a time that would not parse"
    print(f"host {host_id}: a document received {when} could not"
          " be read and is not in the history", file=sys.stderr)


def walks(doc):
    """Whether the packet path can actually walk this document.

    Called once per host, on the newest document only, so the cost is one walk
    of one port rather than a second full render. It exists because every tab
    walks that document and a failure in any of them would end the render for
    the whole fleet, and because proving it here means the answer is known
    before any HTML is built.
    """
    try:
        pp.traced_ports(doc)
        pp.path_for(doc, "tcp", 0, "v4")
        return True
    except Exception:
        return False


def unreadable_documents(history):
    """The hosts with at least one document nobody could read, for a caller
    that wants to name them rather than show a blank."""
    return sorted(name for name, h in history.items() if getattr(h, "unreadable", 0))


def digest(doc):
    """The slice of a document that change detection reads, and nothing else.

    Only this much of an older document is kept. A parsed host document costs
    about 150 kB of Python objects, measured on a production snapshot, so
    holding a week of whole documents for every host would cost hundreds of
    megabytes on a box that also runs Caddy and the ingest. A digest is a few
    hundred bytes.
    """
    listeners = {}
    for s in pp._dicts(pp._mapping(doc.get("sockets")).get("listening")):
        listeners[(s.get("protocol"), s.get("family"), s.get("bind_address"),
                   s.get("port"))] = socket_named(s)

    publications = {}
    containers = pp._mapping(doc.get("containers"))
    for runtime in ("docker", "podman"):
        for c in pp._dicts(containers.get(runtime)):
            for p in pp._dicts(c.get("ports")):
                publications[(runtime, c.get("name", ""), p.get("host_port"),
                              p.get("protocol"))] = p.get("host_ip", "")

    mtimes = {f.get("path"): f.get("mtime_unix")
              for f in pp._dicts(pp._mapping(doc.get("rule_files")).get("files"))}

    nft_counts = {}
    for t in pp._dicts(pp._mapping(doc.get("nftables")).get("tables")):
        nft_counts[f"{t.get('family')} {t.get('name')}"] = sum(
            len(pp._dicts(c.get("rules"))) for c in pp._dicts(t.get("chains")))

    # Which of the four above were read from a section this page could not
    # read, so the diff never turns an unread section into a fleet of services
    # that stopped. Kept as part of the digest because the diff compares two
    # documents and needs the answer for both, and the older one is gone by
    # then: only the digest survives.
    return {"listeners": listeners, "publications": publications,
            "mtimes": mtimes, "nft_counts": nft_counts,
            "unreadable": not_readable_sections(doc)}


def socket_named(s):
    """What a Changes line calls a socket: its process, else the unit the
    kernel named for it, verbatim, else nothing, which the line says as an
    unnamed process. The same order as the alerts' (`Socket.name` in
    controlplane/app/join.py). The agent's own user reads no process name, so
    until 2026-10-27 every line read "an unnamed process" beside a Services
    tab that named the service (the second big test, 26 October)."""
    unit = s.get("unit")
    return s.get("process_name") or (unit if isinstance(unit, str) else "") or ""


# --------------------------------------------- a stored document is digested once
#
# A stored document is written once and never edited (docs/PRODUCT.md 4e), so
# the digest of one cannot change either. Until 2026-08-27 every page load
# recomputed all of them: a week of four hosts meant reading 2,688 documents
# out of SQLite, parsing each one, checking its shape and digesting it, on
# every request. Measured with `site/app/bench_render_live.py` on generated
# data of that size, that was 2.5 s of a 2.7 s render.
#
# So a digest is computed once and kept in `report_digests`, keyed on the
# report row it came from. `controlplane/app/db.py` owns the table and creates
# it. This file owns what goes in it and what the row means, which is nothing:
# every row can be deleted and the next render rebuilds it from the documents,
# because the documents are where the facts are.


def digest_version():
    """What a stored digest was computed with.

    A row carrying any other version is ignored and computed again, because a
    cache handing back last release's format is worse than no cache at all: it
    is wrong on a screen and nothing says a word.

    It is the SHA-256 of this file and packetpath.py rather than a number
    somebody has to remember to raise, and the number nobody raised is exactly
    the failure above. Those two files are the whole of what a digest is
    computed from: `digest`, `read_view` and the shape table live here,
    `_mapping` and `_dicts` live there. It invalidates on a comment change too,
    and the cost of that is one cold render after the deploy that made it.

    None means this file cannot read its own source, which switches the cache
    off rather than stamping rows with a version that is not one.
    """
    try:
        stamp = hashlib.sha256()
        for path in (__file__, pp.__file__):
            stamp.update(pathlib.Path(path).read_bytes())
        return stamp.hexdigest()[:16]
    except (OSError, TypeError) as exc:
        print("stored digests are off, this renderer cannot read its own"
              f" source: {exc}", file=sys.stderr)
        return None


DIGEST_VERSION = digest_version()


def encode_digest(entry):
    """A digest as the text a `report_digests` row holds, or None when it will
    not survive the trip.

    Three of the four mappings are keyed on tuples and JSON has no such key, so
    every mapping is stored as a list of [key, value] pairs and read back the
    same way rather than as an object. `unreadable` is a tuple of section names
    and comes back a tuple, because a decoded digest has to equal a computed
    one exactly.

    `allow_nan=False` is what returns None. A document carrying NaN or Infinity
    is valid JSON to Python's parser and does not compare equal to itself
    afterwards, so it is not stored, and it is digested again on every render
    the way every document was before this table existed.
    """
    try:
        return json.dumps({
            "listeners": [[list(k), v] for k, v in entry["listeners"].items()],
            "publications": [[list(k), v] for k, v in entry["publications"].items()],
            "mtimes": [[k, v] for k, v in entry["mtimes"].items()],
            "nft_counts": [[k, v] for k, v in entry["nft_counts"].items()],
            "unreadable": list(entry["unreadable"]),
        }, allow_nan=False)
    except ValueError:
        return None


def decode_digest(text):
    """A stored digest back as the dict the diff reads, or None when the row
    will not read as one.

    None is a miss and not a fault. The document it was computed from is still
    in the store, so the caller reads that and overwrites the row. Everything
    that can be wrong with the text stops here rather than reaching the diff,
    because a half-decoded digest is a Changes tab inventing ports that started
    and stopped, which is the one thing this cache must never be able to do.
    """
    try:
        raw = json.loads(text)
        return {"listeners": {tuple(key): value for key, value in raw["listeners"]},
                "publications": {tuple(key): value for key, value in raw["publications"]},
                "mtimes": dict(raw["mtimes"]),
                "nft_counts": dict(raw["nft_counts"]),
                "unreadable": tuple(raw["unreadable"])}
    except (ValueError, TypeError, KeyError, RecursionError):
        return None


def digests_are_stored(con):
    """Whether this database carries the digest table.

    Asked by trying the read, the same way `load_alerts` asks about the alerts
    table. A database the control plane's `db.init` has not run against since
    the table was added simply has no table, and the render then reads and
    digests every document itself exactly as it did before.
    """
    if DIGEST_VERSION is None:
        return False
    try:
        con.execute("SELECT report_id, version, digest FROM report_digests LIMIT 0")
        return True
    except sqlite3.OperationalError:
        return False


def store_digests(db_path, fresh):
    """Write the digests this render had to compute, and say how many.

    Its own connection, because the render's is opened read only, and it runs
    after the render has closed that one so the two never wait on each other.

    **A write that fails must not fail the page.** This table holds no fact
    that is not in the documents, so a store that refuses the write costs the
    next render the same work again and nothing else. It is said on stderr,
    which on the box is the journal the sweep already writes to, rather than
    swallowed.
    """
    if not fresh:
        return 0
    rows = [(report_id, DIGEST_VERSION, text) for report_id, text in fresh.items()]
    try:
        con = sqlite3.connect(db_path)
    except sqlite3.Error as exc:
        print(f"digests could not be stored: {exc}", file=sys.stderr)
        return 0
    try:
        con.execute("PRAGMA busy_timeout = 5000")
        # Not a connection the control plane's `db.connect` made, and it
        # writes, so it sets the same two settings itself. That function owns
        # them and says why (docs/RECORD.md 4.444). Neither waits for a lock.
        joinbridge.module("db").forget_what_is_deleted(con)
        # The report id is the primary key, so a row left by an older version
        # is replaced rather than joined by a second row for the same report.
        con.executemany(
            "INSERT OR REPLACE INTO report_digests (report_id, version, digest)"
            " VALUES (?, ?, ?)", rows)
        con.commit()
        return len(rows)
    except sqlite3.Error as exc:
        print(f"digests could not be stored: {exc}", file=sys.stderr)
        return 0
    finally:
        con.close()


class Unreadable:
    """What stands in for a host's report when the stored document itself
    could not be read: empty, truncated, not JSON, valid JSON that is not an
    object, or nested too deep to parse.

    A class of its own rather than None on purpose. None already means the
    host never sent anything, and the two must never look the same on a
    screen: "no document yet" over a document that arrived is docs/RECORD.md
    4.46 one level up, the absence of a thing and a thing nobody could read
    presented as one fact.
    """

    def __init__(self, received_at):
        # When the store received the document, or None when even that column
        # would not parse. It is the one fact about the report that does not
        # come from the document itself, so it is the one fact still worth
        # showing.
        self.received_at = received_at


def received_at_or_none(value):
    """The stored `received_at` as a datetime, or None when it will not parse.

    Its own function because two readers need the answer: `parse_report`,
    which is about to read the document beside it, and `load_history`, which
    on a cached digest never reads that document at all.
    """
    try:
        return datetime.fromisoformat(value)
    except (ValueError, TypeError):
        return None


def parse_report(row):
    """(received_at, document) from a reports row, or Unreadable when the
    stored document will not read as a JSON object. A single malformed
    document must not take the page down, and must not read as one that
    never arrived.

    This is the one place a stored document becomes objects, so it is where the
    shape check runs. Everything downstream reads the view rather than the raw
    document, which is what stops a section nobody could read from reaching a
    screen as an empty one.

    The catch list, and why each entry is in it:

      ValueError      json.JSONDecodeError for empty, truncated and non-JSON
                      text, and fromisoformat for a received_at that is not a
                      date. Both are subclasses.
      TypeError       a document column holding something json.loads does not
                      take at all. The schema says TEXT NOT NULL, so this is a
                      store somebody interfered with, which is exactly when
                      the render must keep going.
      RecursionError  json.loads parses nesting recursively, so a document
                      nested deep enough raises this rather than
                      JSONDecodeError. Before this guard one such document
                      ended the render for the whole fleet: the timer's unit
                      failed and the page went stale for every host.
    """
    received_at = received_at_or_none(row["received_at"])
    if received_at is None:
        return Unreadable(None)
    try:
        doc = json.loads(row["document"])
    except (ValueError, TypeError, RecursionError):
        return Unreadable(received_at)
    if not isinstance(doc, dict):
        # Valid JSON and still not a host document: a list, a string, a
        # number, null. Nothing downstream can ask a list for its sections,
        # so it is refused here, where the answer can still be honest.
        return Unreadable(received_at)
    return received_at, read_view(doc)


# The window, newest first, carrying the digest already stored for each row
# where there is one of this version.
#
# **The CASE is what makes this worth doing.** A document is about 45 kB and a
# digest a few hundred bytes, so a row whose digest is stored must not read its
# document at all, and a row without one has to. SQLite reads a column when the
# expression it is in is evaluated, so the document is fetched on exactly the
# rows the branch is taken for. The alternative was a second query per missing
# row, which cost a measurable third of a second on a cold render of four hosts
# and is the reason this is one statement.
HISTORY_SQL = (
    "SELECT r.id AS id, r.received_at AS received_at, d.digest AS digest,"
    " CASE WHEN d.digest IS NULL THEN r.document END AS document"
    " FROM reports r"
    " LEFT JOIN report_digests d ON d.report_id = r.id AND d.version = ?"
    " WHERE r.host_id = ? AND r.received_at >= ?"
    " ORDER BY r.received_at DESC, r.id DESC LIMIT ?")

# The same window on a database with no digest table, which reads every
# document because it has to. Written out rather than assembled from the one
# above, because a query built by string arithmetic is a query nobody can read.
HISTORY_SQL_UNSTORED = (
    "SELECT r.id AS id, r.received_at AS received_at, NULL AS digest,"
    " r.document AS document"
    " FROM reports r"
    " WHERE r.host_id = ? AND r.received_at >= ?"
    " ORDER BY r.received_at DESC, r.id DESC LIMIT ?")


def load_history(con, host_id, since, max_docs, fresh=None):
    """One host's digested history, newest first.

    The window is bounded in SQL by `since`, which is compared as text.
    received_at is written by the ingest as an ISO-8601 UTC string, and ISO
    strings in one offset sort the same way as the instants they name, which
    is why the index on (host_id, received_at DESC) can serve this.

    One extra row is asked for beyond max_docs. If it comes back the cap is
    what ended the read rather than the time window, and the caller has to say
    so on screen.

    The cursor is walked row by row rather than fetchall()ed. A week of one
    host is 672 documents of roughly 55 kB each, so fetching them all at once
    would hold about 37 MB of JSON text per host for no reason. Measured on
    the week-long replay: peak memory for the whole render fell from 208 MB
    to 72 MB when this stopped being a fetchall().

    `fresh` is where the digests this render had to compute go, keyed on report
    id, for the caller to store once every read is finished. `None` means this
    database has no digest table, so every document in the window is read and
    digested here, which is what every render did before the table existed.
    """
    if fresh is None:
        cur = con.execute(HISTORY_SQL_UNSTORED,
                          (host_id, since.isoformat(), max_docs + 1))
    else:
        cur = con.execute(HISTORY_SQL,
                          (DIGEST_VERSION, host_id, since.isoformat(), max_docs + 1))
    digests = []
    read = 0
    capped = False
    unreadable = 0
    for row in cur:
        read += 1
        if read > max_docs:
            capped = True
            break
        received_at = received_at_or_none(row["received_at"])
        if received_at is None:
            # The row's own timestamp will not read, so whatever the document
            # holds has no place on a timeline. Counted and said out loud like
            # every case below, never quietly skipped.
            unreadable += 1
            log_unreadable(host_id, None)
            continue
        stored = decode_digest(row["digest"]) if row["digest"] is not None else None
        if stored is not None:
            digests.append((received_at, stored))
            continue
        # No usable digest for this row, so the document is read. This is the
        # whole cost the table exists to pay once instead of per request, and
        # on a warm database it is reached only by documents that arrived
        # since the last render.
        #
        # **The document may not be in this row.** HISTORY_SQL fetches it only
        # when no digest row exists, which is what stops a warm render pulling
        # 45 kB per document it is not going to read. A row whose digest
        # exists and will not decode lands here with the document left behind,
        # and reading NULL as a document would count it unreadable and drop it
        # off the timeline. That is the cache changing what the page says
        # happened, so the document is fetched for that one row instead. It
        # costs a query per corrupt row, and a corrupt row is not a thing that
        # should be happening.
        if row["document"] is None:
            row = con.execute(
                "SELECT id, received_at, NULL AS digest, document"
                " FROM reports WHERE id = ?", (row["id"],)).fetchone()
            if row is None:
                # Deleted between the two reads. Nothing to digest and nothing
                # wrong with it, so it is counted like any other row this pass
                # could not read rather than passed over in silence.
                unreadable += 1
                log_unreadable(host_id, received_at)
                continue
        parsed = parse_report(row)
        if isinstance(parsed, Unreadable):
            # The stored document itself would not read. Counted and said out
            # loud like the case below, because before this branch existed a
            # document that was not JSON fell out of the history with no count
            # and no line in the journal, which is a quiet skip.
            unreadable += 1
            log_unreadable(host_id, parsed.received_at)
            continue
        # The whole document is dropped here on purpose. Only the digest
        # is kept, which is what makes a week of history affordable.
        try:
            entry = digest(parsed[1])
        except Exception:
            # A document whose envelope was valid and whose body is not the
            # shape the schema says. The ingest stores it verbatim by
            # design (PRODUCT.md 4e), so any enrolled host can send one,
            # and before this guard it raised out of here and ended the
            # render for the whole fleet rather than for one host. It is
            # counted, never quietly skipped. Nothing is stored for it, so a
            # document nobody can digest is never a row anybody reads back.
            unreadable += 1
            log_unreadable(host_id, parsed[0])
            continue
        digests.append((parsed[0], entry))
        if fresh is not None:
            text = encode_digest(entry)
            if text is not None:
                fresh[row["id"]] = text
    oldest = digests[-1][0] if digests else None
    return History(digests, oldest, capped, unreadable)


def workspace_clause(workspace_id, column="workspace_id"):
    """The extra SQL and its parameters for one workspace, or nothing at all.

    `None` adds nothing, which is the whole fleet. An integer adds the one
    column that decides what this page can reach. `column` is spelled by the
    caller because some of these queries reach hosts through a join and have to
    say `h.workspace_id`, and it is never built from anything a request
    supplied: every call site passes a literal written here in this file.
    """
    if workspace_id is None:
        return "", ()
    return f" AND {column} = ?", (workspace_id,)


def load(db_path, now=None, window=None, workspace_id=None, with_prober_api=False):
    """Hosts, the newest document each one sent, the digested history behind
    it, and the open alerts against them.

    The newest document is read on its own and without a time bound, because
    every tab renders it and a host that has been silent for longer than the
    history window must still show the last thing it said.

    `workspace_id` scopes every read that can reach a host. `None` is the whole
    fleet and is never what a browser gets, see the module docstring.

    `with_prober_api` is an instance that uses our probers, whose address
    rows read proved only when our side holds the address too (`load_proofs`).
    """
    now = now or datetime.now(timezone.utc)
    window = window or Window()
    since = now - timedelta(days=window.days)
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    # Revoked hosts leave the fleet. Revoking is the operator saying this row is
    # not a server of mine, and the leftovers from an abandoned add-server flow
    # are exactly what gets revoked, so listing them anyway put seven dead rows
    # on the owner's page above his three real ones (2026-08-16). The row stays in
    # the database, so nothing is destroyed and a future screen can show them
    # deliberately, but the fleet is the working fleet.
    scope, params = workspace_clause(workspace_id)
    hosts = con.execute(
        "SELECT * FROM hosts WHERE revoked_at IS NULL" + scope + " ORDER BY name",
        params).fetchall()
    # A server the Add server window made is shown once its agent has
    # reported (the owner, 2026-09-20, `awaiting_first_report`).
    hosts = [h for h in hosts if not awaiting_first_report(h)]
    # The servers Remove took out, for the list under the table where Delete
    # is offered (docs/PRODUCT.md 4f). The newest removal first.
    removed = con.execute(
        "SELECT name, revoked_at FROM hosts WHERE revoked_at IS NOT NULL" + scope
        + " ORDER BY revoked_at DESC, name", params).fetchall()
    newest = {}
    history = {}
    # Where the digests this render has to compute for itself collect, written
    # once at the end. None when this database has no digest table, which is
    # every database the control plane's db.init has not run against since the
    # table was added, and the render then works exactly as it did before.
    fresh = {} if digests_are_stored(con) else None
    for h in hosts:
        row = con.execute(
            "SELECT received_at, document FROM reports WHERE host_id = ?"
            " ORDER BY received_at DESC, id DESC LIMIT 1", (h["id"],)).fetchone()
        newest[h["name"]] = parse_report(row) if row else None
        history[h["name"]] = load_history(con, h["id"], since, window.max_docs, fresh)
        # The newest document is the one every tab walks. Proving here that it
        # walks means a later tab cannot be the thing that ends the render.
        # A document that parsed and still will not walk becomes Unreadable
        # rather than None: it arrived, so the page must never say it did not.
        report = newest[h["name"]]
        if isinstance(report, tuple) and not walks(report[1]):
            newest[h["name"]] = Unreadable(report[0])
            history[h["name"]].unreadable += 1
    alerts = load_alerts(con, workspace_id)
    names = load_names(con, workspace_id)
    tags = load_tags(con, workspace_id)
    display_names = load_display_names(con, workspace_id)
    declarations = load_declarations(con, workspace_id)
    when_declared = load_declaration_dates(con, workspace_id)
    # `hosts` is already scoped, so the findings are scoped by construction:
    # nothing here can reach a host row this page did not already read.
    findings = load_findings(con, hosts, newest)
    alerts = alerts_still_asking(alerts, findings)
    mutes = load_mutes(con, hosts, now)
    silenced = load_port_silences(con, hosts, now)
    proofs = load_proofs(con, hosts, now, with_prober_api)
    # The reachability transitions, over the same window the document history
    # uses, so a reader looking at one tab is looking at one period.
    transitions = load_finding_changes(con, hosts, since, workspace_id)
    # The Fleet's fourth box, over its own 24 hour window (SPEC.md section 3).
    changed = load_reachability_changes(con, hosts, now - timedelta(hours=24))
    first_seen = load_first_looks(con, hosts)
    moved_ports = load_moved_ports(con, workspace_id)
    dismissed_marks = load_rarely_dismissed(con, workspace_id)
    probing = load_probing(con, hosts)
    channels = load_channels(con, workspace_id)
    # The email destinations the relay is refusing, for the Fleet's banner.
    refusals = joinbridge.module("alerts").mail_refusals(con, workspace_id)
    # Counted here rather than at the call site, because the connection is
    # opened and closed inside this function and nothing outside it has one.
    mailed = mail_count(con, workspace_id)
    ever_alerted = alerts_ever(con, workspace_id)
    provider = load_provider(con, workspace_id)
    # The addresses each host has proved, beside the snapshot, because they
    # are what names a host's server at the provider (`provider_server`).
    provider["addresses"] = {name: sorted(target for target, _family in proof["live"])
                             for name, proof in proofs.items()}
    vantages = load_vantages(con)
    # The delivery list, as (rows, how many fell in the period). Its own window,
    # not the history window: this reads two small alert tables rather than a
    # week of documents, so widening or narrowing one is no reason to move the
    # other.
    sent_rows, sent_total = load_sent(
        con, now - timedelta(days=tpl.SENT_READ_DAYS), SENT_LIMIT, workspace_id)
    # Each channel's number is the past `build.SENT_DAYS` days, which is what
    # the Sent column is headed, and it is counted here and not from the list.
    sent = (sent_rows, sent_total,
            load_sent_counts(con, now - timedelta(days=tpl.SENT_DAYS), workspace_id))
    con.close()
    # After the read connection is closed, so this render's own reads and this
    # write never wait on each other.
    store_digests(db_path, fresh)
    return (hosts, newest, history, alerts, names, findings, channels,
            mailed, sent, mutes, proofs, declarations, transitions, silenced,
            changed, when_declared, first_seen, ever_alerted, provider, removed,
            refusals, vantages, probing, tags, display_names, moved_ports, dismissed_marks)


# The banner's sentence for a refused destination, the Fleet SPEC's own
# words (docs/screens/fleet/SPEC.md section 1), with the address in bold.
RELAY_REFUSED = "Alert mail to <b>{}</b> was refused by the relay."


def relay_refusal_notes(channels, refusals):
    """One banner for each email destination of this workspace the relay is
    refusing, from `load_channels`'s rows and {delivery key: when the
    refusals began}. A row switched off is left out, since nothing is sent
    to it. The class of the refusal is kept by the sweep and never drawn.

    The note's key is the delivery key and when the refusals began, so a
    dismissal holds while the relay goes on refusing, a new run shows again,
    and no address goes into the browser's storage."""
    email = joinbridge.module("channels").TYPE_EMAIL
    out = []
    for channel, _last, _used, key in channels:
        if channel.type != email or not channel.enabled or key not in refusals:
            continue
        shown = channel.destination_hint or channel.label
        out.append(("fail", f"relay-refused:{key}:{refusals[key]}",
                    RELAY_REFUSED.format(tpl.esc(shown)), "Open channel", "integrations"))
    return out


def load_probing(con, hosts):
    """The names of the servers being probed right now, for the turning mark
    beside their Probed fact (docs/RECORD.md 4.196).

    Two facts, neither of them stored for this purpose. A probing pass of
    ours holds `probe.ours` shared for its whole length, every lane and Scan
    now alike, and a pass covers the fleet, so while one runs every server
    here is being probed or about to be (`probelock.is_held`, which answers
    no whenever it cannot tell). The worker that serves self-hosted
    instances never takes it, so their batches mark nothing here. And a
    scan somebody asked for that no pass has picked up yet marks its own
    server alone (`scan_requests.drained_at`).

    A database with no scan table yet has no such request, which is every
    database Scan now was never pressed on.
    """
    probelock = joinbridge.module("probelock")
    if probelock.is_held(probelock.ours_path_for(con)):
        return {h["name"] for h in hosts}
    try:
        waiting = {row[0] for row in con.execute(
            "SELECT DISTINCT host_id FROM scan_requests WHERE drained_at IS NULL")}
    except sqlite3.OperationalError:
        return set()
    return {h["name"] for h in hosts if h["id"] in waiting}


def load_vantages(con):
    """Every enabled vantage by name, in registry order, for the prober card
    (docs/screens/host-evidence/SPEC.md, decided 2026-09-08). Empty on a
    database from before the registry existed, and the card then names the
    vantages that measured the host."""
    registry = joinbridge.module("vantages")
    if not registry.table_exists(con):
        return ()
    return tuple(v.name for v in registry.enabled(con))


def awaiting_first_report(host) -> bool:
    """Whether this row is a server the Add server window made that has not
    reported yet, which no screen shows.

    The owner, 2026-09-20: a server belongs in the list once the agent is
    installed and reporting, not when the button is clicked. The row is made
    when the Agent card is
    clicked and has to be: the credential in the install command lives on it
    and the agent's first report is authenticated against it. So the row
    stays, and what changed is that nothing draws it until that report. The
    Add server window shows the arrival meanwhile, by id
    (docs/screens/add-server/BRIEF-arrival.md). A window opened and closed
    leaves nothing on the screen, which is where the ghost rows came from.

    Told by two facts the row holds: the window named it and no person did
    (`auto_named`), and it never reported. A server a person named, with
    `hosts_cli add`, is theirs to see before it reports. An address server
    has no agent and is never hidden. A database from before `auto_named`
    hides nothing, having nothing to tell by.
    """
    keys = host.keys()
    if "auto_named" not in keys or not host["auto_named"]:
        return False
    if "kind" in keys and host["kind"] == "address":
        return False
    return not host["last_report_at"]


def load_provider(con, workspace_id=None):
    """One workspace's provider, as one project per token it holds: each
    token's hint, its stored snapshot, parsed, and what its last read did.

    Read through the module that stores them (`controlplane/app/hetzner.py`),
    the way the join engine reads the same rows, and scoped to the workspace
    the way every other load here is (record 4.178): a customer's inventory
    is read with their token and is never on another customer's page.
    **The token itself is never read here.** `tokens` hands back the hint
    each row stored beside its token and nothing else, and
    `test_integrations_live.py` reads this file's source to hold that the
    one function in `hetzner.py` that returns the value is not named in it.
    A database from before the tables is the same as a provider nobody
    connected.

    **One project per token since 2026-09-29** (record 4.206): a workspace
    whose servers sit in two Hetzner projects holds a token for each, and
    until then this read the first one only. A workspace holding none gets
    one project with no token, carrying whatever a database from before the
    store read, so that still shows.
    """
    hetzner = joinbridge.module("hetzner")
    if workspace_id is None:
        workspace_id = hetzner.DEFAULT_WORKSPACE_ID
    try:
        held = hetzner.tokens(con, workspace_id)
    except sqlite3.OperationalError:
        held = []
    refs = [(token["id"], {"hint": token["hint"], "set_at": token["set_at"]})
            for token in held]
    if not refs:
        refs = [(hetzner.NO_TOKEN, None)]
    return {"projects": [load_project(con, hetzner, workspace_id, token_id, token)
                         for token_id, token in refs]}


def load_project(con, hetzner, workspace_id, token_id, token):
    """One token's project: its snapshot, parsed, and its last read. `ref` is
    the token's id, which the row's menu names, and empty with no token."""
    project = {"ref": token_id if token is not None else "", "token": token,
               "snapshot": None, "inventory": None, "fetch": None}
    try:
        project["snapshot"] = hetzner.latest_snapshot(
            con, workspace_id=workspace_id, token_id=token_id)
    except sqlite3.OperationalError:
        project["snapshot"] = None
    if project["snapshot"] is not None:
        try:
            project["inventory"] = hetzner.parse_snapshot(project["snapshot"])
        except hetzner.ProviderError:
            project["inventory"] = None
    try:
        project["fetch"] = hetzner.latest_fetch(
            con, workspace_id=workspace_id, token_id=token_id)
    except sqlite3.OperationalError:
        pass
    return project


# The typed kinds a failed read leaves in `provider_fetches`, and the word the
# Read column shows beside the age. A refused credential is the two that
# mean the provider said no to the token, and those two alone turn the status
# tag. Anything else is a read that did not happen, said in one word.
REFUSED_KINDS = ("unauthorized", "forbidden")
FETCH_WORDS = {"rate_limited": "rate limited", "network": "no answer",
               "malformed": "unreadable", "redirected": "redirected",
               "too_many_pages": "too many pages", "http": "error"}


def read_age(then, now):
    """How long ago, in the Read column's unit: minutes, hours or days."""
    seconds = max(0, int((now - then).total_seconds()))
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def provider_lines(provider, host_names, now):
    """The Providers table's lines, as `build.ProviderLine`s, one per project
    the workspace holds a token for (record 4.206).

    A server counts as in the fleet on the row of the project that holds it,
    by the one rule every screen and the join engine share
    (`provider_match`, by proved address and then by name, across every
    project), so no server is counted on two rows and a row's number and a
    host page cannot disagree about which project a server is in.
    """
    projects = provider_projects(provider)
    in_fleet = {}
    for name in host_names:
        found = provider_match(provider, name)
        if found is not None:
            place, server = found
            in_fleet.setdefault(place, set()).add(server.id)
    lines = []
    for place, project in enumerate(projects):
        line = project_line(project, len(in_fleet.get(place, ())), now)
        if line is not None:
            lines.append(line)
    return lines


def project_line(project, in_fleet_count, now):
    """One project's line, or None when nothing is connected for it.

    Nothing connected is no snapshot and no read ever tried, or a read that
    found no token. Every count is the snapshot's own: how many servers the
    provider lists and how many of those are in the fleet, how many
    firewalls, and how many servers have none attached. The status is
    `refused` only when the last read was newer than the snapshot and the
    provider refused the token, and the Read column then carries that status
    in amber.
    """
    snapshot, inventory, fetch = project["snapshot"], project["inventory"], project["fetch"]
    token = project.get("token")
    if fetch is not None and fetch["error_kind"] == "not_configured":
        fetch = None
    if snapshot is None and fetch is None and token is None:
        return None
    servers = in_fleet = firewalls = without = ""
    if inventory is not None:
        servers = len(inventory.servers)
        in_fleet = in_fleet_count
        firewalls = len(inventory.firewalls)
        without = sum(1 for s in inventory.servers if not s.firewalls)
    word, tone, read, warn = "connected", "ok", "", False
    if snapshot is not None:
        try:
            read = read_age(datetime.fromisoformat(snapshot.fetched_at), now)
        except (TypeError, ValueError):
            read = ""
    failed = (fetch is not None and fetch["error_kind"]
              and (snapshot is None or fetch["tried_at"] > snapshot.fetched_at))
    if failed:
        try:
            read = read_age(datetime.fromisoformat(fetch["tried_at"]), now)
        except (TypeError, ValueError):
            read = ""
        warn = True
        if fetch["error_kind"] in REFUSED_KINDS:
            word, tone = "refused", "fail"
            if fetch["error_status"]:
                read = f"{read}, {fetch['error_status']}"
        else:
            read = f"{read}, {FETCH_WORDS.get(fetch['error_kind'], fetch['error_kind'])}"
    key = "hetzner"
    # The Token column is the hint the row stored when the token was set, its
    # last four characters after an ellipsis, and never the token. A snapshot
    # with no token behind it is a database from before the store, and its
    # column is empty rather than a word that claims one.
    shown = token["hint"] if token else ""
    return tpl.ProviderLine(key, tpl.PROVIDER_NAMES[key], shown, word, tone,
                            servers, in_fleet, firewalls, without, read, warn,
                            ref=project.get("ref", ""))


def load_alerts(con, workspace_id=None):
    """Open alerts by host name, newest first, each carrying the non-mail
    channels that took it.

    The table is created by the sweep (controlplane/app/alerts.py), which runs
    on its own timer. A database this renderer meets before the sweep has ever
    run simply has no table, and a dashboard that 500s because a feature is not
    switched on yet is worse than one that shows nothing.

    **notified_at stays the mail fact and only that** (docs/RECORD.md 4.83).
    Whether any other channel took the alert is a separate fact, read here from
    alert_deliveries, so the screen can say a webhook delivered without widening
    what "mailed" means. Each row is returned as a plain dict carrying a
    `deliveries` list of the `type:ENVVAR` keys the sweep wrote for it, empty
    when nothing but mail was tried.
    """
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        rows = con.execute(
            "SELECT a.*, h.name AS host_name FROM alerts a JOIN hosts h ON h.id = a.host_id"
            " WHERE a.resolved_at IS NULL" + scope
            + " ORDER BY a.raised_at DESC, a.id DESC", params).fetchall()
    except sqlite3.OperationalError:
        return {}
    deliveries = load_deliveries(con, workspace_id)
    out = {}
    for row in rows:
        alert = dict(row)
        alert["deliveries"] = deliveries.get(row["id"], [])
        out.setdefault(row["host_name"], []).append(alert)
    return out


def alerts_still_asking(alerts, findings):
    """The open alerts, less a finding alert whose port no longer asks.

    The owner, 2026-09-27 (docs/RECORD.md 4.207). A finding alert closes when its
    port's new state has held through the sweep's 15 minute window, which is
    what stops a flapping port resolving and raising again. So on fart the
    header said ALERT OPEN, and Open now said reachable, for 22 minutes after
    the port was measured shut (4.200). The alert is still open in the table
    and the mail is untouched: this only decides what the screens draw, and
    they draw a finding alert while its port's state now is one of the three
    it is raised for. A port that answers again inside the window was never
    resolved, so its alert is drawn again on the next render.

    A port the engine has no finding for keeps its alert, because nothing says
    it stopped asking, and the dead-man switch's alert is never touched.
    """
    finding_alerts = joinbridge.module("finding_alerts")
    out = {}
    for host, rows in alerts.items():
        states = {(f.protocol, f.port, f.family): f.state or ""
                  for f in findings.get(host, ())}
        kept = []
        for row in rows:
            port = alert_port(row.get("subject"))
            if (row["kind"] == finding_alerts.KIND_FINDING and port in states
                    and states[port] not in finding_alerts.ALERTABLE_STATES):
                continue
            kept.append(row)
        if kept:
            out[host] = kept
    return out


def load_deliveries(con, workspace_id=None):
    """The non-mail channels that accepted each open alert, keyed by alert id.

    `alert_deliveries` holds one row per alert per channel for every channel
    that is not email, because email is alerts.notified_at and this table does
    not copy it (docs/RECORD.md 4.83). The channel string is `type:ENVVAR`, and
    only the type is ever surfaced: the environment variable is infrastructure
    configuration and belongs on the box, not on a screen (docs/RECORD.md 4.87).

    A database from before webhook delivery landed has no table, handled the
    same way load_alerts handles a missing alerts table. This is only reached
    once the alerts table has already been read, so the alerts join is safe.
    """
    # Joined through to hosts as well, so this cannot name an alert the caller
    # is not allowed to see. It only ever decorates rows load_alerts already
    # scoped, so this is the second answer to the same question rather than the
    # only one, and that is the shape a leak here would have to get past.
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        rows = con.execute(
            "SELECT d.alert_id AS alert_id, d.channel AS channel"
            " FROM alert_deliveries d JOIN alerts a ON a.id = d.alert_id"
            " JOIN hosts h ON h.id = a.host_id"
            " WHERE a.resolved_at IS NULL" + scope, params).fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for row in rows:
        out.setdefault(row["alert_id"], []).append(row["channel"])
    return out


# The most delivery rows the Alerts page prints. A week of a flapping fleet can
# be thousands of them and the panel is read from the top, so the read is
# bounded and the heading says how many there were when the bound bites. The
# period itself is `build.SENT_DAYS`, which owns it because the heading states
# it.
SENT_LIMIT = 50


def _sent_rows(con, since, workspace_id=None):
    """Every message that went out since `since`, newest first.

    One table, `sent_log`, written by the sweep at the moment a channel
    accepts a message (`controlplane/app/alerts.py` says why it stands
    alone). It names the server as text and links to nothing, so a deleted
    server's lines are still here, and a line is in it only for a send that
    happened. Until 2026-10-03 this read `alerts.notified_at` and
    `alert_deliveries` and merged them, which said three things that were not
    so: a deleted server's sends were gone and each channel's number with
    them, a mail from a stored email channel was listed twice, and an alert
    of a kind a channel does not take was listed as sent to it
    (`docs/RECORD.md` 4.228).

    **A resolved alert's line stays.** This is a log of what went out, and an
    alert that has since come back is still something somebody was told
    about.

    A database from before the table has nothing sent, the same rule
    `load_alerts` follows for a missing table. The control plane creates the
    table, and fills it from the two older ones, when it starts.

    The bound is compared as text. `sent_at` is written by the sweep as
    `datetime.isoformat()` on an aware UTC datetime, so the strings are in one
    offset and sort as the instants they name. `load_history` documents the
    same reasoning for `received_at`.
    """
    scope, params = workspace_clause(workspace_id)
    try:
        return con.execute(
            "SELECT host_name, detail, sent_at, channel FROM sent_log"
            " WHERE sent_at >= ?" + scope + " ORDER BY sent_at DESC, id DESC",
            (since.isoformat(), *params)).fetchall()
    except sqlite3.OperationalError:
        return []


def load_sent(con, since, limit, workspace_id=None):
    """The Sent list: (rows, total). `rows` is no longer than `limit` and
    `total` is how many fell in the period, so a cut list can say it was cut."""
    rows = _sent_rows(con, since, workspace_id)
    return rows[:limit], len(rows)


def load_sent_counts(con, since, workspace_id=None):
    """How many deliveries each channel key took since `since`.

    Counted over every delivery of the period. Until 2026-10-03 the Sent
    column counted the rows of the list after the list had been cut to
    `SENT_LIMIT`, so a channel that took sixty in a week read fifty.
    """
    counts = {}
    for row in _sent_rows(con, since, workspace_id):
        counts[row["channel"]] = counts.get(row["channel"], 0) + 1
    return counts


def load_findings(con, hosts, newest):
    """Every port's joined finding, by host name.

    The join engine lives in the control plane and this renderer cannot import
    it the ordinary way. `site/app/joinbridge.py` is the one place that knows
    why and how, and it is worth reading before changing anything here.

    **This is computed on every render rather than read from a table.** The
    engine derives the state from the newest document, the newest probe run and
    the declarations, and all three are already in this database. A stored copy
    would be a second answer that can disagree with the first, and whether that
    copy is worth having is a decision on the board rather than one taken here.

    **A host whose document this renderer already judged unreadable is not
    asked about.** The engine parses the stored document itself and its own
    guard catches less: measured on 2026-08-21, a document nested too deep
    raises `RecursionError` inside `json.loads`, which `host_findings` does not
    catch, and one such row on one host ended the whole render. `parse_report`
    above has already made that judgement for every host, so it is reused
    rather than made a second time in a second place with a second answer.

    **And one host still cannot take the page down.** The check above is the
    documents this renderer knows about. The engine also reads probe runs,
    declarations and a provider snapshot, and a fault in any of those is one
    host's fault. It is said out loud on stderr rather than swallowed, which is
    what `log_unreadable` exists for: an error is never downgraded to keep
    the output clean.

    `IndexError` is in that list because a `sqlite3.Row` raises it, not a
    `KeyError`, when a column is absent. A database old enough to be missing
    one the engine reads is a real thing to survive, and dying on it would take
    every other host's page down with it.
    """
    join = joinbridge.load()
    out = {}
    for host in hosts:
        report = newest.get(host["name"])
        # An address host has no document by design and its findings come
        # from the probe runs alone, so the document check above does not
        # apply to it: the engine knows what to do with a host of that kind.
        if not isinstance(report, tuple) and host_kind(host) != "address":
            out[host["name"]] = ()
            continue
        try:
            result = join.host_findings(con, host["id"])
        except (ValueError, TypeError, RecursionError, IndexError,
                sqlite3.Error) as exc:
            # The type and the message. The type alone, "OperationalError",
            # sat in the journal every minute from 2026-08-29 to 2026-09-15
            # and named nothing anyone could act on; the message is what says
            # which file could not be opened.
            print(f"host {host['id']}: the three views could not be joined"
                  f" ({type(exc).__name__}: {exc}), so this host's ports show"
                  " no state", file=sys.stderr)
            out[host["name"]] = ()
            continue
        out[host["name"]] = result.findings if result is not None else ()
    return out


def load_proofs(con, hosts, now, with_prober_api=False):
    """Every proof of control per host name, and which of them are live.

    Read through the registry's own readers (`app/authz.py` via the bridge),
    so what the screen calls live is exactly what the gate would let a pass
    probe. A database the registry has never touched has no table, handled
    the way `load_mutes` handles a missing silences table: no proofs.

    **On an instance that uses our probers** a live proof whose address our
    side does not hold is listed in `ours_missing`, and its row says so
    rather than proved (docs/PRODUCT.md 5g, the challenge of 2026-10-24).
    What our side holds is its own listing as the instance last read it, at
    every batch and after every verify both sides proved
    (`dispatch.api_proofs_held`).

    Returns {name: {"rows": [authorisation rows, newest first],
                    "live": {(target, family)},
                    "live_ids": {the ids of the rows that are live},
                    "ours_missing": {the ids of live rows our side does
                                     not hold},
                    "proved": {(target, family) the header counts}}}.
    """
    authz = joinbridge.module("authz")
    held = (joinbridge.module("dispatch").api_proofs_held(con, now)
            if with_prober_api else None)
    out = {}
    for host in hosts:
        try:
            listing = authz.addresses_for_host(con, host["id"])
            live = authz.live_addresses_for_host(con, host["id"], now=now)
        except sqlite3.OperationalError:
            return {}
        out[host["name"]] = {
            "rows": listing["authorizations"],
            "live": {(r["target"], r["family"]) for r in live},
            "live_ids": {r["id"] for r in live},
            "ours_missing": (set() if held is None else
                             {r["id"] for r in live if r["target"] not in held}),
            # The addresses the header counts as proved: live here and, on
            # an instance that uses our probers, held by our side too, so
            # the number never disagrees with the rows below it.
            "proved": {(r["target"], r["family"]) for r in live
                       if held is None or r["target"] in held},
        }
    return out


def load_mutes(con, hosts, now):
    """The names of the hosts a live mute covers right now.

    **What counts as live is the control plane's answer and not a second one
    written here.** `finding_alerts.silenced` walks the rows, drops the ones
    that were withdrawn, drops the ones whose expiry has passed, and reads a
    row with no expiry as one that has not ended. Asking it with no port is how
    `sweep_outside_views` asks whether a whole server is muted, so the screen
    and the sweep cannot disagree about it.

    A database the sweep has never run against has no `alert_silences` table,
    handled the way `load_alerts` handles a missing alerts table: nothing has
    ever been muted on it, so nothing is muted on it now.
    """
    silences = joinbridge.module("finding_alerts")
    muted = set()
    for host in hosts:
        try:
            kind = silences.silenced(con, host["id"], None, None, None, now=now)
        except sqlite3.OperationalError:
            return set()
        if kind == silences.SILENCE_MUTE:
            muted.add(host["name"])
    return muted


# What each outcome the sweep records means, as one short line a reader can
# act on. `controlplane/app/finding_alerts.py` owns the words themselves and
# this owns what a screen says about them, once, so two screens cannot end up
# with two phrasings of the same fact.
#
# Every one of these is a status or a refusal, which is what the rule for customer screens
# allows on a screen. None of them explains how the sweep works.
def load_finding_changes(con, hosts, since, workspace_id=None):
    """Every reachability transition per host name, newest first.

    **The sweep has written these since finding alerts landed and no screen
    has ever read them** (`docs/RECORD.md` 4.119). `finding_changes` is one
    row per port per address family every time its state moved, with what it
    moved from, what to, and what was done about it. It drives the mail and
    the webhook and it was invisible in the product.

    Meanwhile the Changes tab showed differences between one stored document
    and the next, which is where "the rule file's mtime moved" and "nftables
    table ip filter went from 70 to 71 rules" came from. Those are facts about
    a document. "tcp/5432 became reachable from the internet at 14:02" is the
    fact somebody is paying for, and it lived in a table nothing rendered.

    A database the sweep has never run against has no table, handled the way
    `load_alerts` handles a missing alerts table: nothing has ever changed on
    it, so there is nothing to show.
    """
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        # `before` is the previous row's outside view on the same port and
        # family, whatever its age: a row whose outside view moved is a
        # measurement, a row whose outside view stayed is somebody's answer,
        # and the Changes tab lists the first kind only.
        rows = con.execute(
            "SELECT c.*, h.name AS host_name,"
            " (SELECT p.outside FROM finding_changes p"
            "  WHERE p.host_id = c.host_id AND p.protocol = c.protocol"
            "  AND p.port = c.port AND p.family = c.family AND p.id < c.id"
            "  ORDER BY p.id DESC LIMIT 1) AS before"
            " FROM finding_changes c"
            " JOIN hosts h ON h.id = c.host_id"
            " WHERE c.seen_at >= ?" + scope
            + " ORDER BY c.seen_at DESC, c.id DESC",
            (since.isoformat(),) + tuple(params)).fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for row in rows:
        out.setdefault(row["host_name"], []).append(dict(row))
    return out


def load_moved_ports(con, workspace_id=None):
    """The ports whose answer from outside has moved at least once since the
    server's first report, by host name, as {(protocol, port), ...}.

    The first-look window puts the ports most like a forgotten one first
    (docs/RECORD.md 4.221), and one sign of those is that nothing about them
    has changed since the server joined. `finding_changes` holds one row per
    port and family every time its state moved, with what the outside view
    said then. A port and family whose rows say more than one thing has
    moved. A row written because somebody answered carries the same outside
    view as the row before it, so an answer alone does not count as a move.

    No time bound, on purpose: it is since the first report, not since last
    week. A database the sweep has never run against has no table, and then
    nothing has moved.
    """
    if con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table'"
                   " AND name = 'finding_changes'").fetchone() is None:
        return {}
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    rows = con.execute(
        "SELECT h.name AS host_name, c.protocol, c.port FROM finding_changes c"
        " JOIN hosts h ON h.id = c.host_id WHERE 1 = 1" + scope
        + " GROUP BY c.host_id, c.protocol, c.port, c.family"
        " HAVING COUNT(DISTINCT c.outside) > 1", params).fetchall()
    out = {}
    for row in rows:
        out.setdefault(row["host_name"], set()).add((row["protocol"], row["port"]))
    return out


def answered_before(from_state):
    """Whether a port answered from outside before a change, read off the
    state the change left: True, False, or None when the state does not say.

    The engine's own meanings (`controlplane/app/join.py`): `conflict`,
    `unreviewed`, `intended` and `unexplained` each need a connect from
    outside, `not reachable` is a measured silence, and a `stale rule` has
    nothing behind it to answer. No state, and a word this does not know,
    say nothing.
    """
    join = joinbridge.module("join")
    if from_state in (join.STATE_CONFLICT, join.STATE_UNREVIEWED,
                      join.STATE_INTENDED, join.STATE_UNEXPLAINED):
        return True
    if from_state in (join.STATE_NOT_REACHABLE, join.STATE_STALE_RULE):
        return False
    return None


def outside_moved(outside, before, from_state):
    """Whether a change row is the prober's: what it measured from outside
    differs from what was there before. A row whose outside view stayed is
    somebody's answer moving a state.

    `before` is the outside view of the row before it on the same port and
    family, or None when it is the first. A first row says what was before
    through the state it left (`answered_before`), and when that state says
    nothing the row counts, as a first row always did.
    """
    prober_mod = joinbridge.module("prober")
    if outside not in prober_mod.MEASURED_STATES:
        return False
    if before is not None:
        return outside != before
    answered = answered_before(from_state)
    return answered is None or answered != (outside == prober_mod.STATE_CONNECTED)


def load_reachability_changes(con, hosts, since):
    """The ports whose reachability changed since `since`, as a set of
    (host name, protocol, port).

    The fourth box on the Fleet counts these (docs/screens/fleet/SPEC.md
    section 3). A change row in `finding_changes` is one state moving to
    another, and a declaration moves a state too: `unreviewed` to `intended`
    is somebody typing, not the internet reaching a port. So a row counts only
    when its outside view was measured and differs from the previous row's
    outside view on the same port and family.

    **A port's first row has no row before it, and says what was before
    through the state it left** (docs/RECORD.md 4.453). A port's first
    measurement writes a baseline and no row, so the row an answer wrote was
    often the first: Yes on a port that had answered since its first
    measurement read as a port measured for the first time, and the page
    said it became reachable (docs/RECORD.md 4.220). A first row counts when
    what it measured differs from what the state it left says
    (`answered_before`). When that state says nothing, which is a port
    appearing on a server that has a history, the row counts as it always
    did: a reachability nobody knew before. `outside_moved` is the one place
    this is decided, for this count and for the Changes tab's lines.

    A database the sweep has never run against has no table and nothing has
    changed on it. `hosts` is already scoped to the workspace, so a change on
    any other host is dropped here rather than read through a join.
    """
    try:
        rows = con.execute(
            "SELECT c.host_id, c.protocol, c.port, c.outside, c.from_state,"
            " (SELECT p.outside FROM finding_changes p"
            "  WHERE p.host_id = c.host_id AND p.protocol = c.protocol"
            "  AND p.port = c.port AND p.family = c.family AND p.id < c.id"
            "  ORDER BY p.id DESC LIMIT 1) AS before"
            " FROM finding_changes c WHERE c.seen_at >= ?",
            (since.isoformat(),)).fetchall()
    except sqlite3.OperationalError:
        return set()
    names = {h["id"]: h["name"] for h in hosts}
    out = set()
    for row in rows:
        if row["host_id"] not in names:
            continue
        if outside_moved(row["outside"], row["before"], row["from_state"]):
            out.add((names[row["host_id"]], row["protocol"], row["port"]))
    return out


def load_port_silences(con, hosts, now):
    """The (protocol, port, family) triples a live per-port silence covers,
    per host name.

    **A silenced port never alerts and looked exactly like one that would**
    (`docs/RECORD.md` 4.119). `load_mutes` asked the control plane about
    whole-server mutes and nothing ever asked about `SILENCE_PORT`, which
    `python -m app.silence_cli` writes. For a tool whose job is to say when
    something changed, a switch that turns that off with no trace on the
    screen is the worst failure it has.

    Asked of `finding_alerts.silenced` per port rather than read out of the
    table here, for the reason `load_mutes` gives: the control plane decides
    what counts as live, and a second answer written here could disagree with
    the sweep about whether a letter is going to be sent.
    """
    silences = joinbridge.module("finding_alerts")
    out = {}
    for host in hosts:
        try:
            rows = silences._live_silences(con, host["id"], now)
        except sqlite3.OperationalError:
            return {}
        for row in rows:
            if row["kind"] != silences.SILENCE_PORT:
                continue
            # keyed the way the Overview asks (`in silenced`), the value the
            # end the Settings tab shows, None for a silence with no end
            out.setdefault(host["name"], {})[
                (row["protocol"], row["port"], row["family"])] = row["until"]
    return out


def load_channels(con, workspace_id=None):
    """One workspace's channels, as (channel, last delivery) pairs.

    Scoped since 2026-08-29: rows were fleet-wide while the owner was the only
    account, and the moment a second workspace can exist an unscoped read is a
    tenant leak, every workspace's Alerts page listing every other workspace's
    channel labels. None still means every row, and no page passes None: the
    dashboard hands this its session's workspace the same way every host read
    already works.

    The rows come from `controlplane/app/channels.py`, reached the same way the
    join engine is (`site/app/joinbridge.py`). A row carries the type, the
    label, whether it is on, and the NAME of the environment variable its
    destination lives in. **It never carries the destination**, which is what
    makes this readable from here at all: this renderer and the sweep are
    separate units with separate environments and only one of them should ever
    hold a relay password (`docs/RECORD.md` 4.86).

    **This process cannot tell whether that variable is set**, and does not
    pretend to. It runs in the render unit, which has no `alerts.env`, so the
    screen says which variable a channel reads and leaves "is it actually set"
    to `python -m app.channels_cli list` on the box.

    What it can say without holding anything is when a channel last delivered,
    from `alert_deliveries`, which is a fact about our own machinery rather
    than about the operator's configuration.
    """
    channels = joinbridge.module("channels")
    out = []
    for stored in channels.live(con, workspace_id=workspace_id):
        # **The renderer never holds a destination.** A row may carry one since
        # 2026-08-22, and `for_display()` is the object without it. This is the
        # guard that replaced the old schema having no such column at all, and
        # a test asserts no destination reaches the rendered page.
        channel = stored.for_display()
        # The delivery key is the type, the variable, and the non-secret half
        # where the type has one, which is `alerts.channel_key`. Spelled here
        # rather than imported because this module reaches the control plane
        # only through joinbridge, and getting it wrong shows up as a channel
        # that has never delivered rather than as an error.
        # Built from the stored row, because a row holding its own destination
        # is keyed on a digest of it (`alerts.key_for_channel`). The digest is
        # not reversible, so the key is safe to hold here even though the
        # destination it came from is not.
        key = joinbridge.module("alerts").key_for_channel(stored)
        try:
            row = con.execute(
                "SELECT MAX(delivered_at) AS last, COUNT(*) AS used"
                " FROM alert_deliveries WHERE channel = ?", (key,)).fetchone()
        except sqlite3.OperationalError:
            row = None
        out.append((channel, row["last"] if row else None,
                    row["used"] if row else 0, key))
    return out


def alerts_ever(con, workspace_id=None):
    """Whether any alert was ever raised on a server this workspace still
    has, open or resolved. A database from before the sweep has no table,
    which is the same answer as none.

    This is half of the Alerts screen's nothing-yet state and never the whole
    of it. An alert hangs off its server, so a deleted server takes its
    alerts out of this answer, while what was sent about it stays in the
    Sent list (docs/RECORD.md 4.228). The page asks both."""
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        row = con.execute("SELECT 1 FROM alerts a JOIN hosts h ON h.id = a.host_id"
                          " WHERE 1 = 1" + scope + " LIMIT 1", params).fetchone()
    except sqlite3.OperationalError:
        return False
    return row is not None


def mail_count(con, workspace_id=None):
    """How many alerts mail has been accepted for.

    `alerts.notified_at` is the mail fact and means one exact thing, that a
    relay accepted the message (`docs/RECORD.md` 4.83). Counting rows carrying
    it is therefore a real number about mail and not a second spelling of the
    delivery table beside it.

    An alert hangs off a host, so this counts through that join and is a number
    about this workspace's own servers rather than about the box.
    """
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        row = con.execute("SELECT COUNT(*) AS used FROM alerts a"
                          " JOIN hosts h ON h.id = a.host_id"
                          " WHERE a.notified_at IS NOT NULL" + scope,
                          params).fetchone()
    except sqlite3.OperationalError:
        return 0
    return row["used"] if row else 0


def load_names(con, workspace_id=None):
    """The live declared names by host name, keyed (protocol, port).

    A declared name is what the operator calls the service on a port, written
    by `python -m app.intent_cli name` (controlplane/app/intent.py owns the
    storage and the reasoning). It is a thing a person typed, never a
    measurement, so every place this page shows one says it was named by the
    operator and keeps the measured process name beside it.

    The table is created the first time that command runs, so a database from
    before it has no table. That is the same situation load_alerts handles the
    same way: the page renders, with the measured names alone.
    """
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        rows = con.execute(
            "SELECT n.protocol, n.port, n.name, h.name AS host_name"
            " FROM port_names n JOIN hosts h ON h.id = n.host_id"
            " WHERE n.cleared_at IS NULL" + scope, params).fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for row in rows:
        out.setdefault(row["host_name"], {})[(row["protocol"], row["port"])] = row["name"]
    return out


def load_tags(con, workspace_id=None):
    """Each server's tags by host name, in the order they were saved.

    A tag is a word a person put on a server (controlplane/app/tags.py owns
    the storage and the rule). It is never a measurement and decides nothing
    on this page: the Fleet draws it beside the name and the Settings tab
    edits it.

    The table is created the first time a tag is saved, so a database from
    before tags has none, and the page renders with no tags. Asked rather
    than caught, so a real read error is not mistaken for that.
    """
    if con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table'"
                   " AND name = 'host_tags'").fetchone() is None:
        return {}
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    rows = con.execute(
        "SELECT t.tag, h.name AS host_name FROM host_tags t"
        " JOIN hosts h ON h.id = t.host_id"
        " WHERE h.revoked_at IS NULL" + scope + " ORDER BY t.rowid", params).fetchall()
    out = {}
    for row in rows:
        out.setdefault(row["host_name"], []).append(row["tag"])
    return out


def load_display_names(con, workspace_id=None):
    """Each server's display name by host name, for the servers that have one.

    A display name is the label a person gave a server to read it by
    (controlplane/app/displayname.py owns the storage and the rule). It is
    never what a server is found by: every link, id and control on this page
    carries the host name, and the display name is only ever drawn as text.

    A database from before display names has no table, and the page renders
    with the host names. Asked rather than caught, as `load_tags` does.
    """
    if con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table'"
                   " AND name = 'host_display_names'").fetchone() is None:
        return {}
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    rows = con.execute(
        "SELECT d.display_name, h.name AS host_name FROM host_display_names d"
        " JOIN hosts h ON h.id = d.host_id"
        " WHERE h.revoked_at IS NULL" + scope, params).fetchall()
    return {row["host_name"]: row["display_name"] for row in rows}


def load_rarely_dismissed(con, workspace_id=None):
    """Each server's ports whose rarely-public mark a person dismissed, by
    host name, as frozensets of labels such as "tcp/6379"
    (controlplane/app/rarelydismiss.py owns the storage and the rule). A
    server with none is not in the answer.

    A database from before dismissals has no table, and every mark is drawn.
    Asked rather than caught, as `load_tags` does.
    """
    if con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table'"
                   " AND name = 'rarely_dismissed'").fetchone() is None:
        return {}
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    rows = con.execute(
        "SELECT d.protocol, d.port, h.name AS host_name FROM rarely_dismissed d"
        " JOIN hosts h ON h.id = d.host_id"
        " WHERE h.revoked_at IS NULL" + scope, params).fetchall()
    out = {}
    for row in rows:
        out.setdefault(row["host_name"], set()).add(f"{row['protocol']}/{row['port']}")
    return {name: frozenset(labels) for name, labels in out.items()}


def day_month(value):
    """A date as the Host Overview says it beside "you": the day and the
    month, no year, as the sketch draws it. Empty when it cannot be read."""
    then = received_at_or_none(value)
    return f"{then.day} {then:%b}" if then else ""


def load_declaration_dates(con, workspace_id=None):
    """When each live declaration was made, by host name, keyed
    (protocol, port) to a short date. The newest of the two families, because
    the Host Overview's row is per port and its opened row says `answered
    13 Aug` once (docs/record 4.447). Read beside `load_declarations` rather
    than folded into it, so every reader of the words keeps the shape it has."""
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        rows = con.execute(
            "SELECT i.protocol, i.port, i.declared_at, h.name AS host_name"
            " FROM port_intents i JOIN hosts h ON h.id = i.host_id"
            " WHERE i.cleared_at IS NULL" + scope + " ORDER BY i.declared_at", params).fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for row in rows:
        out.setdefault(row["host_name"], {})[(row["protocol"], row["port"])] = day_month(row["declared_at"])
    return out


def load_declarations(con, workspace_id=None):
    """The live port declarations by host name, keyed (protocol, port) to
    {family: the word declared for it}.

    A declaration is what the operator said a port is meant to be, written by
    `python -m app.intent_cli` or by the Probing section of a server's
    settings (controlplane/app/intent.py owns the storage and the reasoning).
    It is a thing a person typed, never a measurement.

    **Keyed by port with the families under it, and that is deliberate.** The
    store is keyed per address family because v4 and v6 are answered
    separately, and the screen that offers a port to watch is about the port.
    Folding the two families into one word here would say something nobody
    declared, so they are kept apart and the row prints them apart when they
    differ.

    The table is created the first time a declaration is made, so a database
    from before that has no table. Handled the way load_names handles the
    same situation: the page renders, with no declarations on it.
    """
    scope, params = workspace_clause(workspace_id, "h.workspace_id")
    try:
        rows = con.execute(
            "SELECT i.protocol, i.port, i.family, i.intent, h.name AS host_name"
            " FROM port_intents i JOIN hosts h ON h.id = i.host_id"
            " WHERE i.cleared_at IS NULL" + scope, params).fetchall()
    except sqlite3.OperationalError:
        return {}
    out = {}
    for row in rows:
        ports = out.setdefault(row["host_name"], {})
        ports.setdefault((row["protocol"], row["port"]), {})[row["family"]] = row["intent"]
    return out


# ------------------------------------------- is this section the shape we read
#
# docs/RECORD.md 4.46 in the renderer, and the half #127 deliberately left open.
#
# The ingest stores a host document verbatim and validates only the envelope
# (PRODUCT.md 4e), so any enrolled host can post a section holding anything at
# all. #127 made the walk survive that by dropping what it could not use, which
# turned a wrong-typed section into an *empty* one, so "the agent found no
# sockets" and "the agent sent something we could not make sense of" read the
# same. That is the conflation 4.46 records in the agent, where a firewall the
# agent was not allowed to open looked identical to a firewall with nothing in
# it, and it fakes a real finding.
#
# So the caller asks first, before it walks: is this section the shape this page
# reads? It asks once, at the one place a stored document becomes objects
# (`parse_report`), and a section that is not the shape gets replaced by a
# marker section carrying the NOT_READABLE status. From there on it travels as
# one more value of the agent's own status enum, which every screen already
# knows how to show, so nothing derived from a section nobody could read can
# reach a screen through a path somebody forgot to guard.
#
# The marker is computed here and never read from the document, so a host
# cannot label its own sections either way.
#
# The table below is written from the reading code, not from the agent's schema.
# It names only the fields this page actually touches, and a field it does not
# name is not checked, because a field nobody reads cannot break a render and
# calling a document unreadable over one would be a fault we invented. The
# schema itself is owned by agent/internal/hostdoc/hostdoc.go.


# The sections, in the order every screen shows them, and what each one is
# called on screen.
SECTION_LABELS = [
    ("sockets", "listening sockets"),
    ("socket_units", "socket units"),
    ("nftables", "nftables"),
    ("iptables", "iptables (legacy)"),
    ("ip6tables", "ip6tables (legacy)"),
    ("ufw", "ufw"),
    ("firewalld", "firewalld"),
    ("containers", "containers"),
    ("overlays", "overlay interfaces"),
    ("rule_files", "rule file mtimes"),
]

SECTION_LABEL = dict(SECTION_LABELS)

# The sections the Rules tab quotes, which is every filtering layer plus the
# mtimes beside them. sockets, containers and overlays are not firewall layers
# and are named on their own screens instead.
RULE_LAYERS = ("nftables", "iptables", "ip6tables", "ufw", "firewalld", "rule_files")


class _Number:
    """Marks a field this page does arithmetic or date maths on. bool is a
    Python int and is not one of these, which is why isinstance is not enough
    on its own."""


NUMBER = _Number()

# Kinds, in the spec language below:
#   str        the value must be a string
#   NUMBER     an int or a float, and not a bool
#   {}         an object, whose contents this page does not read
#   {"k": s}   an object, and if it holds "k" then that value matches s
#   {"*": s}   an object, and every value in it matches s
#   [s]        a list, and every entry in it matches s
# A field that is absent, or null, is absence rather than a fault: Go marshals
# a nil slice as null and `Listening []ListeningSocket` carries no omitempty,
# so every host with nothing listening sends one.

# Every section carries these two, and `sources` is where a per-source read is
# reported. sections_panel walks it and asks each source for its status.
_COMMON = {"status": str, "cause": str, "sources": {"*": {"status": str, "cause": str}}}

_RULES = [{"text": str, "rendered": str, "comment": str}]
_TABLES = [{"family": str, "name": str,
            "chains": [{"name": str, "type": str, "hook": str, "priority": NUMBER,
                        "policy": str, "rules": _RULES}]}]
_PUBLISHED = [{"host_ip": str, "host_port": NUMBER, "container_port": NUMBER, "protocol": str}]
_CONTAINERS = [{"id": str, "name": str, "image": str, "ports": _PUBLISHED}]

SECTION_SHAPE = {
    "sockets": {**_COMMON,
                "listening": [{"protocol": str, "family": str, "bind_address": str,
                               "port": NUMBER, "process_name": str, "pid": NUMBER,
                               "owner_uid": NUMBER, "owner_name": str}]},
    # Only the fields `socket_unit_names` reads, per the note above this table.
    # `masked`, `template` and `alias_of` are read for their truth alone, and a
    # unit carrying any of them is skipped whatever they hold, so a wrong type
    # there costs a name rather than a wrong one. `enable_links` counts only
    # as a list with something in it, for the same reason
    # (`enabled_socket_unit_files`).
    "socket_units": {**_COMMON,
                     "units": [{"name": str, "service_unit": str,
                                "listen": [{"directive": str, "kind": str,
                                            "port": NUMBER}]}]},
    "nftables": {**_COMMON, "tables": _TABLES},
    "iptables": {**_COMMON, "tables": _TABLES},
    "ip6tables": {**_COMMON, "tables": _TABLES},
    # ufw's two rules files arrive as lines of text, not as objects, and the
    # page splits each line, so a non-string in there is a section it cannot
    # read rather than a rule it can skip.
    "ufw": {**_COMMON, "conf": {"*": str}, "defaults": {"*": str},
            "rules": [str], "rules6": [str]},
    "firewalld": {**_COMMON, "conf": {"*": str},
                  "zones": [{"name": str, "origin": str, "target": str,
                             "services": [str], "interfaces": [str], "source_addrs": [str],
                             "ports": [{"port": str, "protocol": str}],
                             "forward_ports": [{}]}]},
    "containers": {**_COMMON, "docker": _CONTAINERS, "podman": _CONTAINERS},
    "overlays": {**_COMMON,
                 "interfaces": [{"name": str, "type": str, "devtype": str}],
                 "tailscale": {}, "netbird": {}},
    "rule_files": {**_COMMON, "files": [{"path": str, "mtime_unix": NUMBER}]},
}


def reads_as(value, shape):
    """Whether `value` is the shape this page reads, per the table above.

    Cost, measured on a production snapshot of three hosts: 0.4 ms for one
    75 kB document of about 1,240 values, which is roughly what reading that
    document out of SQLite and digesting it costs. A week of three hosts is
    855 documents, and the whole render went from about 0.51 s to 0.86 s on a
    laptop. It is linear in documents, like everything else the history window
    does, so widening HISTORY_DAYS costs proportionally more of this too.
    """
    if shape is str:
        return isinstance(value, str)
    if shape is NUMBER:
        # bool is a subclass of int in Python, and a True where a timestamp
        # belongs is not a timestamp.
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if isinstance(shape, list):
        return isinstance(value, list) and all(reads_as(v, shape[0]) for v in value)
    if not isinstance(value, dict):
        return False
    for key, inner in shape.items():
        if key == "*":
            if not all(reads_as(v, inner) for v in value.values()):
                return False
        elif value.get(key) is not None and not reads_as(value[key], inner):
            return False
    return True


def unreadable_sections(doc):
    """The sections of `doc` this page cannot read, in the order they are shown.

    A section that is absent is not in here. Absent is a fact the agent
    reported and the trust view already says it. This is the other fact: the
    section is present and is not the shape the page reads, so nothing can be
    concluded from what it holds, least of all that it holds nothing.
    """
    if not isinstance(doc, dict):
        return ()
    return tuple(key for key, _label in SECTION_LABELS
                 if doc.get(key) is not None
                 and not reads_as(doc[key], SECTION_SHAPE[key]))


# One more value of the agent's status enum, added by us rather than by a host.
# hostdoc.go's SectionStatus does not carry it, which is the point: the agent
# says how its read went and this says how ours did.
NOT_READABLE = "not_readable"


def read_view(doc):
    """The document as this page is allowed to read it.

    Every section that is not the shape above is replaced by a section holding
    the NOT_READABLE status and nothing else, so no screen can show a fact
    derived from it and every screen that shows a status shows this one. The
    stored document is untouched: this is a view built for one render, the
    ingest keeps what the host actually sent, and the API still serves it.

    A document with nothing wrong is returned as it came, so the common case
    copies nothing.
    """
    faults = unreadable_sections(doc)
    if not faults:
        return doc
    view = dict(doc)
    for key in faults:
        view[key] = {"status": NOT_READABLE}
    return view


def sockets_not_read(doc):
    """Whether this read view carries a sockets section that was not read:
    one the agent says it did not get, or one this page could not read.

    The engine reads the stored document with checks of its own, so its
    findings can still hold sockets from a section this page marked
    NOT_READABLE (26 October 2026, a number where an owner's name belongs).
    The Overview and the Evidence matrix ask this first, and then draw no
    socket and no absence of one (docs/PRODUCT.md 4e, docs/RECORD.md 4.17).

    No document, or one with no sockets section, is not this fact: an address
    host has nothing to read and says "no agent" instead."""
    if not isinstance(doc, dict) or doc.get("sockets") is None:
        return False
    return pp._mapping(doc["sockets"]).get("status") != "collected"


# The Overview's words for it, on a row's Service and on a card's agent line.
SOCKETS_NOT_READ = "sockets not read"


def not_readable_sections(doc):
    """The sections of a read view that carry the marker, in display order."""
    return tuple(key for key, _label in SECTION_LABELS
                 if pp._mapping(doc.get(key)).get("status") == NOT_READABLE)


# ---------------------------------------------- how a server is watched
#
# The owner, 2026-08-27: a server's page differs with how it is watched, in
# full, by a partial agent or from outside only, and the page says which.
#
# **Nothing that arrives here says which agent was installed, and these words
# never claim it does.** `agent/internal/hostdoc/hostdoc.go` has no privilege
# field: no document states "I ran as root" or "I am the limited agent". What a
# document does state is how each read went, and `permission_denied` means one
# thing, "the read needed a privilege the agent did not have". So the words
# below are about the reads, which were measured, and never about the install,
# which was not.
#
# The two consequences are named rather than papered over. A full-visibility
# install that is refused one read for some other reason says `partial read`.
# A limited agent on a host whose files are readable, or one carrying the read
# grants of docs/RECORD.md 4.72, says `full read`. Both sentences are true of
# the reads on that run, which is all either of them claims.
MODE_NO_AGENT = "no agent"
MODE_AGENT = "agent"
MODE_FULL_READ = "full read"
MODE_PARTIAL_READ = "partial read"

# The agent's own word for a read it did not have the privilege for, and the
# cause that travels with it (hostdoc.go StatusPermissionDenied, CausePermission).
REFUSED_STATUS = "permission_denied"
REFUSED_CAUSE = "permission"

# The two section statuses that are a complete answer. `collected` is the read
# that worked and `not_present` is the layer this host does not have, which is
# just as final. Everything else is a section the agent did not get.
READ_COMPLETE = ("collected", "not_present")


def read_was_refused(section):
    """Whether one section or one source says its read was refused."""
    return (section.get("status") == REFUSED_STATUS
            or section.get("cause") == REFUSED_CAUSE)


def refused_reads(doc):
    """Every section whose read was refused, with the refused sources named,
    in display order. `((key, ("rules", "rules6")), ...)`, and an empty tuple
    of sources means the section itself carried the refusal.

    **The section status alone is not enough and reading only it is a bug this
    project has already shipped twice.** `aggregateSources` in the agent
    reports a section as collected when any one of its sources collected, so
    on a host where the agent could not read ufw's two rules files the section
    still says collected, because `ufw.conf` is world readable. The page then
    prints nought rules over files it never saw. Measured on the fleet in
    docs/RECORD.md 4.72, which says the same green headline fooled two
    sessions. So both levels are asked.

    The walk is `SECTION_LABELS`, which is the same list the Evidence tab
    reports on, so a mark saying a read was refused and that tab always name
    the same sections. A section this page does not read at all is in neither.
    """
    out = []
    for key, _label in SECTION_LABELS:
        section = pp._mapping(doc.get(key))
        sources = tuple(sorted(
            name for name, src in pp._mapping(section.get("sources")).items()
            if read_was_refused(pp._mapping(src))))
        if sources or read_was_refused(section):
            out.append((key, sources))
    return tuple(out)


def unfinished_reads(doc):
    """Sections the document carries whose status is neither complete answer,
    in display order.

    A section the document does not carry at all is not in here. Absent is an
    agent that does not produce that section, and the fleet runs more than one
    agent version, so absence is ordinary. A section that is present and says
    it was not read is the other fact, and it is the one that stops this page
    calling a document a full read.
    """
    return tuple(key for key, _label in SECTION_LABELS
                 if doc.get(key) is not None
                 and pp._mapping(doc.get(key)).get("status") not in READ_COMPLETE)


def monitoring_mode(row, report):
    """How this server is watched, in the one word a screen shows.

    `row` is the hosts row and `report` is what `documents` holds for it: the
    (received_at, read view) pair, an `Unreadable`, or None.

    The rules, in order, and each one is a fact somebody recorded:

      no agent      the host has no agent and never will: it is an address
                    host (`hosts.kind`, controlplane/app/db.py), so the whole
                    of what is known about it comes from outside
      partial read  at least one read on this host was refused
      agent         there is an agent and no full answer about its reads: no
                    document, a document that would not read, a section that
                    says it was not read, or nothing collected at all
      full read     the document was read, something in it collected, and
                    nothing in it was refused

    `full read` says every read this document reports came back. It does not
    say the agent tried every source that exists, because a document cannot
    say that, and the header rule above is why this page will not pretend it
    can.
    """
    if host_kind(row) == "address":
        return MODE_NO_AGENT
    if not isinstance(report, tuple):
        return MODE_AGENT
    _received_at, doc = report
    if refused_reads(doc):
        return MODE_PARTIAL_READ
    if unfinished_reads(doc):
        return MODE_AGENT
    # A document that collected nothing is not a full read of anything. Without
    # this an envelope with no sections in it at all, which is what a host
    # sending a hostname and a timestamp would be, would read as the best
    # answer on the fleet.
    if not any(pp._mapping(doc.get(key)).get("status") == "collected"
               for key, _label in SECTION_LABELS):
        return MODE_AGENT
    return MODE_FULL_READ


# What every screen says about one of them. One sentence, stated once, so the
# places that have to say it cannot drift into several wordings.
SECTION_UNREADABLE = ("This section could not be read. It arrived in a shape this page does "
                      "not read, so nothing in it was counted or shown.")

# The same fact one level up, for a whole stored document nobody could read.
# Two registers, each stated once: the host page's full sentence, and the short
# form a fleet row's note column uses.
DOCUMENT_UNREADABLE = ("The newest document from this host could not be read. It is not a "
                       "JSON object this page can parse, so nothing in it was counted or "
                       "shown. The document is kept in the store exactly as it arrived, and "
                       "the next readable one replaces this notice.")


# How many chips a fleet row shows before it folds. A host with forty sockets
# would otherwise make one row taller than the rest of the table. The rest are
# counted rather than dropped, because a strip that quietly stops is a strip
# that lies about how much is listening.
# The chip's bar per family, from what the prober measured. Three values and no
# fourth.
#
# **`silent` is a measured silence and `not tested` is nobody having looked**,
# and the bar keeps them apart because that difference is the product. A hollow
# bar is only ever the second one. Filling a bar for a port nobody probed is
# `docs/PRODUCT.md` 4b happening inside the product instead of in prose, and a
# hollow bar for a measured silence would throw away a measurement that was
# taken.
def _bar(outside):
    """`outside` is the finding's OutsideView, or None for a family with no
    finding at all. The engine's own two properties decide, never a second
    spelling of its four state constants here.
    """
    if outside is None or not outside.measured:
        return tpl.NOT_TESTED
    return tpl.ANSWERED if outside.connected else tpl.SILENT


def rarely_reachable(findings, dismissed=frozenset()):
    """The ports of one server that answer from outside and are on the list of
    ports that should rarely face the internet, as {"tcp/6379": ["v4"], ...}
    with the families that answered. A port in `dismissed`, labels such as
    "tcp/6379", is left out: a person dismissed the mark on it
    (controlplane/app/rarelydismiss.py, docs/RECORD.md 4.274).

    **Two things have to be true and both are somebody else's to say.** That
    the port answered is the prober's measurement, the engine's
    `outside.connected`, and a port nobody probed or that measured silent is
    not here. That the port is on the list is `controlplane/app/rarelypublic.py`,
    where every entry carries its source. The list is keyed on protocol and
    port, so this says nothing about what is listening there.
    """
    listed = joinbridge.module("rarelypublic")
    out = {}
    for finding in findings:
        if not finding.outside.connected:
            continue
        if listed.lookup(finding.protocol, finding.port) is None:
            continue
        if f"{finding.protocol}/{finding.port}" in dismissed:
            continue
        out.setdefault(f"{finding.protocol}/{finding.port}", []).append(finding.family)
    return {label: sorted(families) for label, families in out.items()}


def fleet_facts(doc, findings=(), dismissed=frozenset()):
    """What one server's Reachable and Needs a decision cells hold, from the
    joined findings and the document (docs/screens/fleet/SPEC.md section 5).

    Returns (reach, chips): `reach` is (ports open from outside, ports
    observed) and `chips` is ((label, tone), ...) worst first for the ports
    whose state needs somebody.

    **The document is read as well as the findings, and it has to be.** The
    engine proposes ports from sockets, publications, rules and probe results,
    and a host whose document it could not digest would lose its listening
    ports from the count. The document's own ports are the floor and the
    findings add to it, which is what the port strip did before this table.

    A port counts as open from outside when either family answered (the owner,
    2026-09-05, answer 4). A chip names its family only when the port has a
    finding in both families and one of them needs a decision (answer 7), so
    "tcp/22 v6" says the v6 side is the one to look at and "tcp/22" says the
    whole port is.

    **A reachable port on the rarely-public list is a chip too**, after the
    others, whatever its state: it sits under Needs a decision while the
    server's word stays what it is (docs/RECORD.md 4.229). A port that is
    already a chip for its state is not drawn twice.
    """
    ports = {}

    def port(label):
        return ports.setdefault(label, {"states": {}, "families": set(), "open": False})

    for sock in pp._dicts(pp._mapping(doc.get("sockets")).get("listening")):
        port(f'{sock.get("protocol")}/{sock.get("port")}')
    for finding in findings:
        entry = port(f"{finding.protocol}/{finding.port}")
        entry["families"].add(finding.family)
        if finding.state:
            entry["states"][finding.family] = finding.state
        if finding.outside.connected:
            entry["open"] = True
    labels = sorted(ports, key=_port_sort_key)

    chips = []
    for label in labels:
        states = ports[label]["states"]
        worst = next((s for s in STATE_SEVERITY if s in states.values()), "")
        if worst not in tpl.NEEDS_DECISION:
            continue
        deciding = sorted(fam for fam, state in states.items() if state in tpl.NEEDS_DECISION)
        text = label
        if len(ports[label]["families"]) == 2 and len(deciding) == 1:
            text = f"{label} {deciding[0]}"
        chips.append((STATE_SEVERITY.index(worst), text, tpl.PORT_TONE[worst]))
    already = {text.split(" ")[0] for _rank, text, _tone in chips}
    for label, answered in sorted(rarely_reachable(findings, dismissed).items(),
                                  key=lambda item: _port_sort_key(item[0])):
        if label in already:
            continue
        text = label
        if len(ports[label]["families"]) == 2 and len(answered) == 1:
            text = f"{label} {answered[0]}"
        chips.append((len(STATE_SEVERITY), text, "warn"))
    chips.sort(key=lambda c: c[0])
    reach = (sum(1 for label in labels if ports[label]["open"]), len(labels))
    return (reach if labels else None,
            tuple((text, tone) for _rank, text, tone in chips))


# Worst first. A row shows one word for a port that has two families, so this
# decides which. It is the order `docs/DESIGN.md` section 3 lists the states in
# and the same order `tpl.sort_fleet_rows` puts rows in, so a reader meets one
# ranking on the page rather than two.
# `not reachable` sits between `unreviewed` and `intended`, added 2026-08-28
# with the state (`docs/RECORD.md` 4.112). Above `intended` because a port
# nobody has declared is less settled than one somebody has, and below
# `unreviewed` because that word means the internet reached the port and this
# one means it did not. A row showing `not reachable` while its other family
# answered would hide the half that is reachable, which is the fault this
# ordering exists to prevent.
# **Realigned 2026-08-29.** It held `unexplained` above `unreviewed`, while
# `build.FLEET_BANDS`, the ranking this comment has always claimed to match,
# holds the opposite. Two rankings on one page is what the sentence above
# forbids, and FLEET_BANDS is the decided one, band by band with reasons.
# **`stale rule` moved under `unexplained` on 2026-09-21**, to the head of the
# quiet states. A rule with nothing listening behind it is worth knowing and
# is not a decision anybody owes (the owner, docs/RECORD.md 4.198), so it must
# never be the worst thing about a server that also has something that is.
STATE_SEVERITY = ("conflict", "unreviewed", "unexplained",
                  "stale rule", "not reachable", "intended")


# ------------------------------------------------- the two axes of a fleet row
#
# A server is two facts at once and the fleet row has one State cell. What is
# reachable on it, and how our own monitoring of it is doing. Until 2026-08-28
# the cell showed only the second one for an agent host: `freshness()` decided
# the word, the joined findings reached the Ports cell and nothing else, so a
# server with a port in `conflict` rendered green reading `REPORTING` and the
# finding was a coloured chip two columns to the right (`docs/RECORD.md`
# 4.115).
#
# **The worse of the two takes the cell and the other sits beside it.** One
# ranking decides which, `build.FLEET_BANDS`, which already held both
# vocabularies and already put the port states above the agent ones. That
# keeps three properties the screen depends on:
#
#   - one row is in exactly one filter bucket, so the counts still add up and
#     `test_every_fleet_row_is_reachable_by_a_filter` still holds
#   - the sort is unchanged, because it reads the same word out of the same
#     ranking
#   - neither fact is ever lost, because the one that did not win is drawn as
#     a second tag rather than dropped
#
# `docs/DESIGN.md` section 3 is what allows two tags: both axes use the same
# box on purpose. What that section retires is two elements spelling ONE fact,
# which is not this.

# The liveness words that mean nothing is wrong with our monitoring. A second
# tag saying one of these would be shouting "working" on every healthy row,
# which is the rule that section calls healthy stays quiet.
ORDINARY_LIVENESS = ("reporting", "watched")

# What the State cell says when the engine has no state for any port on this
# server and there is nothing wrong with the monitoring either.
#
# **It is not `reporting`, and that is the point of this whole change.** The
# cell answers what is reachable. A host whose agent is talking to us and that
# nobody has probed has no answer to that question, and `reporting` in the ok
# tone spends the one green word in the system on "we have not looked yet".
# A fleet screenshot on 2026-08-28 had a row reading REPORTING in green
# directly under two red ones, and it was the row nothing was known about.
#
# It is the word an address host in the same position already used, so both
# kinds of host say the same thing about the same situation.
NOT_PROBED = ("off", "not watched")


def fleet_state(port, live):
    """(primary, secondary) for one row, each a (tone, word) pair or None.

    `port` is the worst finding state on this server, or None when the engine
    has no state for any of its ports. `live` is how the monitoring is doing
    and is never None: every host has an answer to that, even if it is
    `not watched`.

    The secondary is dropped when it is an ordinary liveness word, and when
    there is no port state at all, in which case `live` is already the
    primary and repeating it would be the retired two-elements-one-fact.
    """
    if port is None:
        return (NOT_PROBED if live[1] in ORDINARY_LIVENESS else live), None
    if tpl.fleet_band(port[1]) <= tpl.fleet_band(live[1]):
        return port, (None if live[1] in ORDINARY_LIVENESS else live)
    return live, port


def worst_port_state(findings):
    """The state of the worst-off port on one server, as (tone, word), or None
    when the engine has no state for any port on it.

    `STATE_SEVERITY` decides, which is the order the port strip and the port
    row already use, so a reader meets one ranking on the page rather than
    three. A finding with no state is skipped rather than counted as calm:
    `docs/PRODUCT.md` 8a says a port whose evidence supports none of the six
    has no state, and a server whose ports are all like that has nothing to
    put in this cell.
    """
    states = {f.state for f in findings if f.state}
    word = next((w for w in STATE_SEVERITY if w in states), "")
    if not word:
        return None
    return tpl.PORT_TONE.get(word, "off"), word


def _port_sort_key(label):
    """tcp before udp, then by number, so a row reads in a stable order rather
    than in whatever order /proc happened to list."""
    proto, _, number = label.partition("/")
    return (proto, int(number) if number.isdigit() else 0)


def doc_counts(doc):
    listening = len(pp._dicts(pp._mapping(doc.get("sockets")).get("listening")))
    cont = pp._mapping(doc.get("containers"))
    containers = len(pp._dicts(cont.get("docker"))) + len(pp._dicts(cont.get("podman")))
    # A section that said collected and did not survive the read carries the
    # marker instead by now, so it is not one of the sections that were read.
    sections = sum(1 for key, _label in SECTION_LABELS
                   if pp._mapping(doc.get(key)).get("status") == "collected")
    return listening, containers, sections


def firewall_intent(doc):
    """What the host says it intends, in its own words, or its absence.

    A layer whose section could not be read is named here rather than left
    out, because this string is the Evidence tab's filtering row and "none
    found" over an unread section is a finding nobody measured.
    """
    parts = []
    ufw = pp._mapping(doc.get("ufw"))
    if ufw.get("status") == NOT_READABLE:
        parts.append("the ufw section could not be read")
    elif ufw.get("status") == "collected":
        enabled = pp._mapping(ufw.get("conf")).get("ENABLED", "")
        parts.append("ufw enabled" if enabled == "yes" else "ufw present, not enabled")
    fwd = pp._mapping(doc.get("firewalld"))
    if fwd.get("status") == NOT_READABLE:
        parts.append("the firewalld section could not be read")
    elif fwd.get("status") == "collected":
        zone = pp._mapping(fwd.get("conf")).get("DefaultZone", "")
        parts.append(f"firewalld, zone {zone}" if zone else "firewalld present")
    return " + ".join(parts) if parts else "none found"


# ---------------------------------------------------------------- changes

# Which digest field each section feeds, so a section nobody could read takes
# its own comparison out rather than reading as everything in it disappearing.
DIGEST_SOURCE = {"listeners": "sockets", "publications": "containers",
                 "mtimes": "rule_files", "nft_counts": "nftables"}


def comparable(older, newer, field):
    """Whether the two documents can be compared on `field` at all.

    They cannot when the section behind it was unreadable in either of them: an
    unread section holds nothing this page can see, and comparing it against a
    section that was read reports every entry as having appeared or gone. That
    is a transition nobody measured, which is worse than a blank (the
    accuracy rule).
    """
    section = DIGEST_SOURCE[field]
    return (section not in older.get("unreadable", ())
            and section not in newer.get("unreadable", ()))


def readability_events(older, newer):
    """The change that is itself a change: a section that could be read
    before and cannot now, or the other way round. Neither is one of the
    spec's eight kinds, so both wear the marker."""
    events = []
    was, now = set(older.get("unreadable", ())), set(newer.get("unreadable", ()))
    for key, label in SECTION_LABELS:
        if key in now and key not in was:
            events.append(tpl.Change(None, label, "agent", "not readable", detail=label,
                                     off=True))
        elif key in was and key not in now:
            events.append(tpl.Change(None, label, "agent", "readable again", detail=label))
    return events


def diff_digests(older, newer):
    """What moved between two consecutive documents of one host, as Changes
    with no time (the caller stamps the newer document's). Facts only: these
    are agent-side observations, never reachability claims, and each is in
    the layer's own words."""
    events = readability_events(older, newer)

    if comparable(older, newer, "listeners"):
        old_l, new_l = older["listeners"], newer["listeners"]
        for key in sorted(new_l.keys() - old_l.keys(), key=str):
            proto, fam, addr, port = key
            who = new_l[key] or "an unnamed process"
            events.append(tpl.Change(None, "process", "agent", "started", proto, port, (fam,),
                                     f"{who} on {_address_and_port(addr, port)}"))
        for key in sorted(old_l.keys() - new_l.keys(), key=str):
            proto, fam, addr, port = key
            who = old_l[key] or "an unnamed process"
            events.append(tpl.Change(None, "process", "agent", "stopped", proto, port, (fam,),
                                     f"{who} on {_address_and_port(addr, port)}", off=True))

    if comparable(older, newer, "publications"):
        old_p, new_p = older["publications"], newer["publications"]
        for key in sorted(new_p.keys() - old_p.keys(), key=str):
            runtime, cname, port, proto = key
            # A runtime that holds no host address for it, as rootful Podman
            # does for -p with no address, ends the line at the port. It read
            # "host port 8095 on" with nothing after it (the second big test,
            # 26 October, the same words the card lost on 25 October).
            where = f" on {new_p[key]}" if new_p[key] else ""
            events.append(tpl.Change(None, "container", "agent", "published", proto, port, (),
                                     f"{runtime} {cname}, host port {port}{where}"))
        for key in sorted(old_p.keys() - new_p.keys(), key=str):
            runtime, cname, port, proto = key
            events.append(tpl.Change(None, "container", "agent", "unpublished", proto, port, (),
                                     f"{runtime} {cname}, host port {port}", off=True))

    # The digest keeps a rule file's mtime and a table's rule count, not the
    # rules, so what these lines can say is that the file moved or the count
    # moved. The kinds are not the spec's eight and wear the marker.
    if comparable(older, newer, "mtimes"):
        old_m, new_m = older["mtimes"], newer["mtimes"]
        for path in sorted(new_m.keys() & old_m.keys()):
            if old_m[path] != new_m[path]:
                events.append(tpl.Change(None, "host firewall", "agent", "file changed",
                                         detail=path))

    if comparable(older, newer, "nft_counts"):
        old_n, new_n = older["nft_counts"], newer["nft_counts"]
        for name in sorted(old_n.keys() | new_n.keys()):
            a, b = old_n.get(name), new_n.get(name)
            if a is not None and b is not None and a != b:
                kind = "rule added" if b > a else "rule removed"
                events.append(tpl.Change(None, "host firewall", "agent", kind,
                                         detail=f"nftables {name}: {a} to {b} rules",
                                         off=b < a))
            elif a is None:
                events.append(tpl.Change(None, "host firewall", "agent", "rule added",
                                         detail=f"nftables {name} appeared, {n_of(b, 'rule')}"))
            elif b is None:
                events.append(tpl.Change(None, "host firewall", "agent", "rule removed",
                                         detail=f"nftables {name} disappeared, had {n_of(a, 'rule')}",
                                         off=True))

    return events


def diff_documents(older, newer):
    """The same comparison, given two whole documents.

    The view is built here as well as in `parse_report`, because this one takes
    documents from a caller rather than from the store and must not be the way
    an unchecked one gets in. `read_view` on a document that has already been
    through it changes nothing.
    """
    return diff_digests(digest(read_view(older)), digest(read_view(newer)))


def reachability_changes(transitions, now=None):
    """The prober's lines of the log: every transition whose outside view
    moved, as a Change, newest first. A transition whose outside view stayed
    is somebody's answer moving a state, which is not a line here
    (docs/screens/host-changes/SPEC.md). Both families measured in one
    sweep are one line with both families on it."""
    prober_mod = joinbridge.module("prober")
    out = {}
    for row in transitions:
        when = received_at_or_none(row.get("seen_at"))
        if when is None:
            continue
        # A port's first row is read by the state it left, so the row an
        # answer wrote is not a line here either (docs/RECORD.md 4.453).
        if not outside_moved(row["outside"], row.get("before"), row.get("from_state")):
            continue
        reachable = row["outside"] == prober_mod.STATE_CONNECTED
        word = joinbridge.load()._OUTSIDE_WORDS.get(row["outside"], row["outside"])
        detail = f"{word} from {row['vantage']}" if row.get("vantage") else word
        key = (when, row["protocol"], row["port"], reachable, detail)
        change = out.setdefault(key, tpl.Change(
            when, "from outside", "prober", "reachable" if reachable else "unreachable",
            row["protocol"], row["port"], (), detail, off=not reachable))
        change.families = tuple(f for f in FAMILIES
                                if f in change.families or f == row["family"])
    return sorted(out.values(), key=lambda c: c.when, reverse=True)


def document_changes(story):
    """The agent's lines of the log: what moved between one document and the
    next, stamped with the newer document's time, newest first."""
    rows = []
    for (when_new, newer), (_, older) in zip(story.digests, story.digests[1:]):
        for change in diff_digests(older, newer):
            change.when = when_new
            rows.append(change)
    return rows


def host_log(transitions, story):
    """Every line of one server's log, newest first."""
    rows = reachability_changes(transitions) + (document_changes(story) if story else [])
    return sorted(rows, key=lambda c: c.when, reverse=True)


def changes_tab_body(slug, transitions, story, window, now):
    """The Changes tab. A read that stopped short of the window says the
    oldest document it did reach in place of the period, so a short list
    never reads as a quiet week."""
    since = (story.oldest.strftime("%d %b %H:%M")
             if story and story.capped and story.oldest else "")
    return tpl.changes_table_html(slug, host_log(transitions, story), now, since,
                                  shown=window.limit)


# ------------------------------------------------- what the window leaves out
#
# The reason this section exists: a change that falls out of the window has to
# fall out visibly. It is built from the numbers the render actually used
# rather than written down as a constant somewhere.
#
# **It is a field on the heading line and never a sentence in the panel**
# (the owner, 2026-08-29). It used to be four sentences under the list. Two of
# them taught how a change is worked out and why the list was short, naming
# the documents, our read window and our read limit, which is the machinery
# the rule for customer screens keeps off a customer screen. What a reader actually needs out
# of all four is the period and the counts, and those are values. The Alerts
# screen already puts exactly this in exactly this place, as `last 7 days ·
# 3 deliveries`, so the tab now says it the way the rest of the product does.

# ---------------------------------------------------------------- host views

# The agent's own status enum shown as the Tag treatment. A failed read takes
# the fail tone, a denied one warns, an absent source is neutral, collected
# stays quiet (DESIGN.md section 3).
SECTION_TONES = {
    "collected": ("ok", "collected"),
    "not_present": ("off", "not present"),
    "permission_denied": ("warn", "permission denied"),
    "read_error": ("fail", "read error"),
    "not_collected": ("off", "not collected"),
    # Ours rather than the agent's, and it takes the fail tone for the same
    # reason a read error does: something that was supposed to be read was not.
    NOT_READABLE: ("fail", "not readable"),
}


# --------------------------------------------------------- the ufw comment
#
# ufw stores a rule's comment inside the tuple line hex-encoded. Its own writer
# appends ` comment=%s` with the encoded value and its own reader splits the
# line on ` comment=` and unhexlifies what follows, so the hex is the file
# format rather than a corrupted file:
#
#   git.launchpad.net/ufw/plain/src/util.py            hex_encode, hex_decode
#   git.launchpad.net/ufw/plain/src/backend_iptables.py  _write_rules, _read_rules
#
# So a tuple quoted verbatim carries the operator's own note as hex, which is
# the least readable thing on the row and usually the most useful. It is decoded
# here, for display only. **The stored document keeps the raw value**, because
# the document is the evidence we quote from and we do not rewrite it.
#
# This decode is deliberately stricter than ufw's own, which truncates an
# odd-length string and falls back to backslashreplace. This is untrusted text
# out of a file on somebody else's host, so anything that is not unambiguously
# hex is shown exactly as it arrived. Showing mojibake, or half a note, would be
# worse than showing the hex.
HEX_ONLY = re.compile(r"\A(?:[0-9a-fA-F]{2})+\Z")

# ufw puts the comment last and separates it with this, which is the same split
# its own reader does, so we cannot disagree with ufw about where the rule ends.
UFW_COMMENT_MARK = " comment="


def decoded_hex_comment(raw):
    """The text behind a hex-encoded ufw comment, or `raw` unchanged.

    Decoded only when the value is unambiguously hex: an even number of hex
    digits and nothing else, which decodes as UTF-8, and whose every character
    is printable. Every other value is returned untouched, so the page never
    shows a guess.
    """
    if not HEX_ONLY.match(raw or ""):
        return raw
    try:
        text = bytes.fromhex(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return raw
    # A control character means what came out was not text. A comment is one
    # line in a file, so a newline or a tab in it is not a comment either.
    # str.isprintable() is False for all of those and True for a plain space.
    return text if text.isprintable() else raw


def ufw_tuple(line):
    """One ufw tuple line as (the rule, the operator's comment).

    The comment is empty when the line carries none. A hex comment is decoded
    for display, anything else is passed through.
    """
    rule, mark, comment = line.partition(UFW_COMMENT_MARK)
    if not mark:
        return line, ""
    return rule, decoded_hex_comment(comment.strip())


def code_block(text):
    return f'<div class="code">{tpl.esc(text)}</div>'


def disclosure(label, summary_right, body_text):
    """A verbatim quote behind a click: the summary line carries the counts,
    the body is the host's own text, escaped and untouched."""
    return (f'<details class="rs"><summary><span>{tpl.esc(label)}</span>'
            f'<span class="grades">{tpl.esc(summary_right)}</span></summary>'
            f'{code_block(body_text)}</details>')


def rule_rows(chain):
    """One chain's rules as (text, comment, grade), plus the grade counts.

    Every rule in the chain gets a row, in the order the document lists them,
    which is the order the kernel evaluates them. A rule the agent did not fully
    render keeps its grade so it can never read as a fully quoted one
    (RECORD 4.18), and the rule author's own comment comes along, because it is
    the one part of a rule somebody wrote for a person to read.
    """
    counts = {"rules": 0, "full": 0, "partial": 0, "none": 0}
    rows = []
    for rule in pp._dicts(chain.get("rules")):
        counts["rules"] += 1
        grade = rule.get("rendered", "")
        if grade in ("full", "partial", "none"):
            counts[grade] += 1
        rows.append((rule.get("text", ""),
                     # nftables comments arrive already decoded: the agent reads
                     # them out of the rule's userdata TLV as text. Only ufw
                     # stores its comments hex-encoded, see decoded_hex_comment.
                     rule.get("comment") or "",
                     "" if grade == "full" else grade))
    return rows, counts


def chain_meta(chain, rules, with_hook=True):
    """What a chain is, in the fields the document has: its hook, its policy and
    how many rules are in it."""
    bits = []
    if with_hook and chain.get("hook"):
        bits.append(f"hook {chain['hook']}")
    if chain.get("policy"):
        bits.append(f"policy {chain['policy']}")
    elif with_hook and chain.get("hook"):
        bits.append("no policy")
    bits.append(n_of(len(rules), "rule"))
    return " · ".join(bits)


def kernel_groups(tables):
    """Every chain of every table of one kernel layer as (name, meta, rows).

    The heading's counts are taken off this rather than off the rendered
    markup, so the number at the top of the tab and the rules under it come
    from one read of the document.
    """
    out = []
    for table in pp._dicts(tables):
        for chain in pp._dicts(table.get("chains")):
            rows, _counts = rule_rows(chain)
            out.append((chain.get("name", ""), "", rows))
    return out


def chain_groups(chains, with_hook=True, table=""):
    """Every chain of one table as its own group, and the table's grade counts.

    `table` is the table's own label, and it is what makes the plain name
    resolvable: the vocabulary is keyed `inet filter input`, because `INPUT`
    alone means a different thing in every table. A caller that does not pass
    one gets the technical name, which is the honest default.

    A chain with no rules keeps its group and says so, because a chain that
    exists and is empty is a real answer about the host.
    """
    out = []
    total = {"rules": 0, "full": 0, "partial": 0, "none": 0}
    for chain in chains or []:
        rows, counts = rule_rows(chain)
        for key in total:
            total[key] += counts[key]
        name = chain.get("name", "")
        out.append(tpl.rule_group_html(f"chain {name}",
                                       chain_meta(chain, rows, with_hook), rows,
                                       key=f"{table} {name}".strip()))
    return "".join(out), total


def table_disclosures(tables, label_fn, with_hook=True):
    """One disclosure per table, the first open. The summary carries the counts,
    so a closed table still says how much is behind it and a host with a dozen
    tables is scanned at this level rather than read at this level."""
    out = []
    for i, table in enumerate(tables or []):
        groups, c = chain_groups(table.get("chains"), with_hook, label_fn(table))
        out.append(tpl.rules_disclosure(
            label_fn(table),
            f"{n_of(len(table.get('chains') or []), 'chain')}, "
            f"{n_of(c['rules'], 'rule')} "
            f"({c['full']} full, {c['partial']} partial, {c['none']} none)",
            groups, is_open=(i == 0)))
    return "".join(out)


def firewalld_zone_rows(zones):
    rows = []
    for z in zones or []:
        detail = []
        if z.get("services"):
            detail.append("services: " + ", ".join(z["services"]))
        if z.get("ports"):
            detail.append("ports: " + ", ".join(
                f"{p.get('port', '')}/{p.get('protocol', '')}" for p in z["ports"]))
        if z.get("interfaces"):
            detail.append("interfaces: " + ", ".join(z["interfaces"]))
        if z.get("source_addrs"):
            detail.append("sources: " + ", ".join(z["source_addrs"]))
        if z.get("forward_ports"):
            detail.append(f"{len(z['forward_ports'])} forward rules")
        if not z.get("parsed", True):
            detail.append("file did not parse, reported unparsed")
        target = f" · target {z['target']}" if z.get("target") else ""
        rows.append(
            tpl.three_cell_row(
                f'{tpl.esc(z.get("name", ""))}'
                f'{tpl.tag("planned", tpl.esc(z.get("origin", "")))}',
                tpl.esc(("; ".join(detail) if detail else "no entries") + target),
                "", first_cls="d", middle_cls="", last_cls=""))
    return "".join(rows)


def ufw_groups(section):
    """ufw's two rules files as two groups, v4 and v6 kept apart.

    ufw keeps them in separate files and the agent reads them separately, so
    they stay separate here. One merged list would be this page inferring that
    the two files say the same thing, which is exactly what it must not do.
    """
    out = []
    groups = []
    for key, name, family in (("rules", "user.rules", "IPv4"),
                              ("rules6", "user6.rules", "IPv6")):
        lines = section.get(key) or []
        if not lines:
            continue
        rows = [(rule, comment, "") for rule, comment in (ufw_tuple(x) for x in lines)]
        out.append(tpl.rule_group_html(name, f'{family} · {n_of(len(rows), "rule")}', rows,
                                       grammar=tpl.UFW))
        groups.append((name, "", rows, "file"))
    return "".join(out), groups


# ufw's two rules files, the source name each one is reported under, and the
# family it holds. The agent reads them separately and reports them separately
# (SocketSources' sibling list in ufw.go), so this page keeps them apart too.
# Corrected 2026-09-10: the source names were `rules` and `rules6`, which the
# agent never writes, so a refused file was never found here and the count it
# guards printed anyway. The names it does write are in `UFW_RULE_FILES`.
UFW_RULE_SOURCES = (("rules", "user.rules", "v4"), ("rules6", "user6.rules", "v6"))


def ufw_hint(section):
    """What the ufw panel says it holds, per family.

    **A refused file says refused and never nought rules.** Non-root cannot
    read `user.rules` or `user6.rules` on Ubuntu, and the section still says
    collected because `ufw.conf` is world readable, so counting the lines that
    arrived printed "0 rules on v4" over a file nobody had seen. Root reads
    three on the same host (docs/RECORD.md 4.72). A count nobody measured is
    the one thing this page may not print.
    """
    sources = pp._mapping(section.get("sources"))
    bits = []
    for key, source, family in UFW_RULE_SOURCES:
        if read_was_refused(pp._mapping(sources.get(source))):
            bits.append(f"not read on {family}")
        else:
            bits.append(f'{n_of(len(ufw_lines(section, key)), "rule")} on {family}')
    return " · ".join(bits)


def ruleset_totals(tables):
    """How many tables and how many rules a layer reported, for the heading."""
    rules = sum(len(pp._dicts(c.get("rules")))
                for t in pp._dicts(tables) for c in pp._dicts(t.get("chains")))
    return len(tables or []), rules


def layer_hint(tables):
    t, r = ruleset_totals(tables)
    return f'{n_of(t, "table")} · {n_of(r, "rule")}'


# ------------------------------------------------------------ the Rules tab
#
# docs/screens/host-rules/SPEC.md, approved 2026-09-09. The one question the
# tab answers: which firewalls does this server have, and what are their
# rules. One bordered list per firewall, in the order a packet from outside
# meets them, and every rule numbered in the order its firewall lists them,
# because that order is what the firewall applies.
#
# Nothing here says why a packet is dropped or where. That is the Overview's
# answer and the packet path's (the owner, 2026-09-08: all the rules, as they
# are, and no reason why or where a packet is dropped).

# Every address, in either family. ufw's own manual says Anywhere is
# synonymous with 0.0.0.0/0 and ::/0, which is where the plain word comes
# from, and Hetzner writes the same two.
ANY_ADDRESSES = ("0.0.0.0/0", "::/0", "0.0.0.0", "::")
ANYWHERE = "anywhere"
SOME_ADDRESSES = "a set of addresses"
# What a firewall's box on the Packet path says for a rule that lets some
# sources in and not all. It is the word the Evidence tab already has for a
# provider rule with a source (`_provider_token` below), used here for ufw's.
PERMITS_SOME = "permits some"

# ufw's tuple line, in the field order ufw's own backend writes it in
# (`git.launchpad.net/ufw/plain/src/backend_iptables.py`, read 2026-09-10):
#
#     action protocol dport dst sport src [dapp sapp] [direction and interface]
#
# Six fields, or eight when the rule names an application, and one more on the
# end when ufw recorded a direction or an interface. **Field 3 is the
# destination and field 5 is the source.** Worth writing down: both are
# 0.0.0.0/0 on the common rule, so reading the wrong one looks right until
# somebody writes a rule naming an address, and then every such rule is wrong.
#
# ufw itself skips a tuple with fewer than six fields as malformed, so this
# refuses one too rather than reading whichever fields happen to be there.
#
# The `### tuple ### ` marker is already gone: the agent strips it as it reads
# the file (`agent/internal/collect/ufw.go`).
UFW_ACTION, UFW_PROTOCOL, UFW_DPORT, UFW_SRC = 0, 1, 2, 5
UFW_MIN_FIELDS = 6
UFW_WITH_DIRECTION = (7, 9)

# The four actions ufw writes, from its own `set_action` (ufw's `src/common.py`,
# read 2026-09-10). Each may carry a log type after an underscore, `allow_log`
# and `deny_log-all`, and a forward rule is written `route:<action>`.
#
# **The list is the guard.** Field count alone is not enough: an iptables line
# has fields too, and reading one as a tuple prints `-A` as an action and a
# chain name as a protocol. A line that does not start with one of these is
# not a tuple, so it is shown as a rule this page could not read, with its own
# text on the row.
UFW_ACTIONS = ("allow", "deny", "reject", "limit")

UfwRule = namedtuple(
    "UfwRule",
    "action protocol port source direction forwarded interface_in interface_out")


def ufw_direction_field(field):
    """The last field of a ufw tuple as (direction, interface in, interface
    out).

    ufw writes `in` or `out`, and after an underscore the interface the rule
    is written for: `in_wt0`, `out_eth1`, and `in_eth0!out_eth1` for a route
    rule that names both. This is how ufw's own reader takes the field apart
    (`src/backend_iptables.py` in ufw's source, read 2026-10-03): the
    direction is what stands before the first underscore, and each interface
    is what follows `in_` or `out_`.
    """
    direction = field.split("_", 1)[0]
    coming_in = going_out = ""
    for half in field.split("!"):
        way, _sep, name = half.partition("_")
        if way == "in":
            coming_in = name
        elif way == "out":
            going_out = name
    return direction, coming_in, going_out


def ufw_interface_words(parts):
    """The interfaces a ufw rule is written for, in our words, or "" for a
    rule for every interface: "on wt0", "out on eth1", or both.

    A rule for one interface holds for packets on that interface and for no
    others. Drawn with no word for it, it read as a rule for all of them
    (the sweep of 2026-09-21, C7 in docs/RECORD.md 4.199).
    """
    words = []
    if parts.interface_in:
        words.append(f"on {parts.interface_in}")
    if parts.interface_out:
        # An outgoing rule is said to be outgoing beside this, so its
        # interface needs no "out" of its own.
        words.append(f"on {parts.interface_out}" if ufw_is_outgoing(parts)
                     else f"out on {parts.interface_out}")
    return ", ".join(words)


def ufw_is_outgoing(parts):
    """Whether a ufw rule is for traffic this host sends, `ufw allow out ...`.

    ufw writes the direction as the start of the tuple's last field, `in` or
    `out` (`src/backend_iptables.py` in ufw's source, read 2026-10-03, where
    the tuple is written from the rule's direction). A route rule is for
    traffic passing through and is said to be forwarded, whichever interface
    it names. A rule for what leaves says nothing about what may come in,
    and it was drawn and counted like a rule for incoming traffic.
    """
    return parts.direction == "out" and not parts.forwarded


def ufw_rule_parts(text):
    """One ufw tuple line as its parts, or None when this cannot read it.

    Every value handed back is ufw's own word and never ours: a field ufw
    wrote as `any` comes back as `any` and the caller decides how to draw it.

    None is the honest answer for a line in a shape ufw does not write. The
    caller keeps the line and marks it not fully readable, because a rule
    nobody can read is exactly the thing this tab exists to show.
    """
    fields = str(text or "").split()
    if len(fields) < UFW_MIN_FIELDS:
        return None
    action = fields[UFW_ACTION]
    # ufw writes a forward rule as `route:allow`. It is a rule about traffic
    # passing through this host rather than to it, and both halves are kept.
    forwarded = ":" in action
    if forwarded:
        action = action.split(":", 1)[1]
    # `allow_log` is allow with logging on. The word before the underscore is
    # the action and the rest is how loudly it is logged, which is not a fact
    # about which packets the rule matches.
    action = action.split("_", 1)[0].lower()
    if action not in UFW_ACTIONS:
        return None
    direction, coming_in, going_out = ufw_direction_field(
        fields[-1] if len(fields) in UFW_WITH_DIRECTION else "in")
    return UfwRule(action=action, protocol=fields[UFW_PROTOCOL],
                   port=fields[UFW_DPORT], source=fields[UFW_SRC],
                   direction=direction, forwarded=forwarded,
                   interface_in=coming_in, interface_out=going_out)


def from_words(source):
    """How a rule's source is drawn: (the words, whether it is a machine's).

    An address takes the mono face because it is a machine's word
    (docs/DESIGN.md section 1). "anywhere" is ours and stays in the page face.
    """
    text = str(source or "").strip()
    if not text or text in ANY_ADDRESSES or text.lower() == "any":
        return ANYWHERE, False
    return text, True


def port_text(value):
    """A port field as the firewall wrote it, or None for a rule with none.

    None is drawn as "any port". A range or a list stays exactly as written,
    because rewriting `80:90` into words would be this page restating a rule
    rather than quoting one.
    """
    text = str(value or "").strip()
    if not text or text.lower() == "any":
        return None
    return text


def ufw_port_names(field, port):
    """Whether ufw's port field names this one port.

    ufw writes several ports as a list, `80,443`, and a range as `low:high`,
    and it turns a service name into its number before it writes the tuple.
    This is ufw's own `_match_ports` (`src/common.py`, read 2026-10-03): a
    list item that equals the port, or a range that holds it, both ends
    included. Comparing the field as one string read `80,443` as no rule for
    443 (docs/RECORD.md 4.199, C7).
    """
    want = str(port)
    for item in str(field or "").split(","):
        if item == want:
            return True
        low, sep, high = item.partition(":")
        if sep and low.isdigit() and high.isdigit() and want.isdigit():
            if int(low) <= int(want) <= int(high):
                return True
    return False


def ufw_file_names(families):
    """Which of ufw's two files a merged rule came from, by name."""
    names = {"v4": "/etc/ufw/user.rules", "v6": "/etc/ufw/user6.rules"}
    return " and ".join(names[f] for f in families if f in names)


def merged_ufw_rules(section):
    """ufw's two rules files as one numbered list, the families merged.

    ufw keeps v4 in `user.rules` and v6 in `user6.rules` and writes one tuple
    into each for a rule somebody wrote once, the two differing only in which
    any-address they name. So a rule saying the same thing in both files is
    one row carrying both families.

    **Nothing else is merged.** Two tuples merge when their action, protocol,
    port, direction and forwarded flag are equal and their sources are either
    both their own family's any-address or the same literal text. Anything
    else stays two rows, because merging on a resemblance would be this page
    inferring that two files agree, which is the one thing it must not do.

    Returns (parts, families, lines, comment) per rule, where `lines` is
    (family, the line as ufw wrote it) so an opened rule quotes both files.
    `parts` is None for a line this could not read.
    """
    merged, order = {}, []
    for key, family in (("rules", "v4"), ("rules6", "v6")):
        for raw in ufw_lines(section, key):
            rule, comment = ufw_tuple(raw)
            parts = ufw_rule_parts(rule)
            if parts is None:
                # An unreadable line never merges with anything. It keeps its
                # own row, with its own text on it.
                slot = ("unreadable", family, len(order))
                merged[slot] = (None, [family], [(family, rule)], comment)
                order.append(slot)
                continue
            words, _machine = from_words(parts.source)
            slot = (parts.action, parts.protocol, parts.port, parts.direction,
                    parts.forwarded, ANYWHERE if words == ANYWHERE else parts.source,
                    parts.interface_in, parts.interface_out)
            if slot in merged:
                was, families, lines, note = merged[slot]
                merged[slot] = (was, families + [family], lines + [(family, rule)],
                                note or comment)
                continue
            merged[slot] = (parts, [family], [(family, rule)], comment)
            order.append(slot)
    return [merged[slot] for slot in order]


# The two files ufw keeps its rules in, under the names the agent reports them
# by (`agent/internal/collect/ufw.go` writes `sec.Sources["user.rules"]` and
# `["user6.rules"]`, and `hostdoc.UfwSources` lists all four).
UFW_RULE_FILES = ("user.rules", "user6.rules")


def ufw_rules_refused(section):
    """Whether ufw's rules files were there and the agent was not allowed in.

    **This is what keeps an empty list honest.** Non-root cannot read
    `user.rules` on Ubuntu and the section still says collected, because
    `ufw.conf` is world readable, so a block drawn from the rules alone shows
    ufw with no rules at all over files nobody ever saw. Root reads three on
    the same host (docs/RECORD.md 4.72). A firewall that says "not readable"
    is a different screen from one that says nothing, and only one of them is
    true.
    """
    sources = pp._mapping(section.get("sources"))
    return any(read_was_refused(pp._mapping(sources.get(name)))
               for name in UFW_RULE_FILES)


def ufw_state(section):
    """Whether ufw is on, in its own word from its own file.

    `ENABLED` in `/etc/ufw/ufw.conf`. A file that did not say is not a claim
    that ufw is off, so the state word says the read did not answer, and a
    refused rules file says that instead of anything about ufw being on.
    """
    if ufw_rules_refused(section):
        return ("fail", "not readable")
    enabled = ufw_enabled_word(section)
    if enabled == "yes":
        return ("ok", "active")
    if enabled == "no":
        return ("off", "not enabled")
    return ("warn", "did not say")


def ufw_enabled_word(section):
    """`ENABLED` as `/etc/ufw/ufw.conf` holds it, lower case, or "" when the
    file did not say."""
    conf = pp._mapping(pp._mapping(section).get("conf"))
    return str(conf.get("ENABLED", "")).strip().lower()


def ufw_enabled(section):
    """Whether ufw's own file says it is on. Only a yes is a yes: a no, a
    file that did not say and any other word are all not enabled here.

    A ufw that is not enabled filters nothing, whatever its files hold. On a
    fresh server with ufw installed and never enabled this page counted it as
    a firewall that is active and named its default for incoming on every
    tab, beside the words not enabled (docs/RECORD.md 4.220).
    """
    return ufw_enabled_word(section) == "yes"


# ufw's own two defaults, from `/etc/default/ufw`, in the words the firewall
# row shows them in. Nothing is inferred: a key the file did not carry is a
# default this page does not print.
UFW_DEFAULT_KEYS = (("incoming", "DEFAULT_INPUT_POLICY"),
                    ("outgoing", "DEFAULT_OUTPUT_POLICY"))


def firewall_defaults(mapping, keys):
    """The (word, value) pairs a firewall's own configuration carries."""
    out = []
    for word, key in keys:
        value = str(mapping.get(key, "")).strip().lower()
        if value:
            out.append((word, value))
    return tuple(out)


# The file holds ACCEPT, DROP and REJECT, and ufw says them as allow, deny and
# reject (`_get_default_policy` in ufw's own src/backend.py, read 2026-10-09).
# The page says them as ufw does. A word ufw does not write is shown as the
# file has it and never guessed into one of the three.
UFW_POLICY_WORDS = {"accept": "allow", "drop": "deny", "reject": "reject"}


def ufw_policy_word(value):
    word = str(value or "").strip().lower()
    return UFW_POLICY_WORDS.get(word, word)


def ufw_defaults(section):
    """ufw's defaults as (direction, ufw's own word), read from where the
    agent sends them: `defaults`, which is `/etc/default/ufw`. The one place
    every tab takes the default from, so no two can word it differently
    (docs/RECORD.md 4.443).

    None while ufw is not enabled. The file still holds the words, and they
    are what ufw would do once it is switched on, not what happens to a
    packet today (docs/RECORD.md 4.220)."""
    if not ufw_enabled(section):
        return ()
    raw = firewall_defaults(pp._mapping(pp._mapping(section).get("defaults")), UFW_DEFAULT_KEYS)
    return tuple((direction, ufw_policy_word(value)) for direction, value in raw)


def ufw_block(slug, section, reported):
    """ufw as one firewall block: its state, its defaults, its rules."""
    rows = []
    for index, (parts, families, lines, comment) in enumerate(
            merged_ufw_rules(section), 1):
        card_lines = [("read from", tpl.mono(ufw_file_names(families)))]
        card_lines += [(family, tpl.mono(text)) for family, text in lines]
        if comment:
            card_lines.append(("your note", tpl.esc(comment)))
        if reported:
            card_lines.append(("read", tpl.esc(f"agent reported {reported}")))
        card = tpl.rule_card_html("ufw", "as you wrote it", card_lines)
        if parts is None:
            rows.append(tpl.rule_row_html(
                slug, "ufw", index, "",
                tpl.rule_port_html(None, "", families, unreadable=True),
                tpl.rule_from_html(lines[0][1], True, "", unread=True), card))
            continue
        words, machine = from_words(parts.source)
        note = ", ".join(word for word in (
            "forwarded" if parts.forwarded else "",
            "outgoing" if ufw_is_outgoing(parts) else "",
            ufw_interface_words(parts)) if word)
        rows.append(tpl.rule_row_html(
            slug, "ufw", index, parts.action,
            tpl.rule_port_html(port_text(parts.port), parts.protocol, families),
            tpl.rule_from_html(words, machine, note), card))
    return tpl.firewall_block_html(
        "linux-logo", "ufw", "", ufw_state(section),
        ufw_defaults(section),
        "".join(rows)), len(rows)


# firewalld's zone target, as its own word. `%%REJECT%%` is firewalld's
# spelling of its built-in reject and is the one that needs translating; the
# rest are printed as the zone wrote them. A zone with no target set is not a
# zone that said anything, so nothing is printed for it: firewalld's own
# default is in its documentation and not in this document.
FIREWALLD_TARGETS = {"%%REJECT%%": "reject"}


# Where firewalld keeps its zones, under the names the agent reports them by
# (`hostdoc.FirewalldSources`). Its own configuration file is not in this: a
# zone directory nobody could read is what turns an empty list into a claim.
FIREWALLD_ZONE_SOURCES = ("etc_zones", "vendor_zones")


def firewalld_zones_refused(section):
    """Whether firewalld's zone directories were there and refused."""
    sources = pp._mapping(section.get("sources"))
    return any(read_was_refused(pp._mapping(sources.get(name)))
               for name in FIREWALLD_ZONE_SOURCES)


# A zone's target as the row a zone with no rule of its own gets. `default`
# and a zone with no target set are not in this: firewalld's own default is in
# its documentation and not in this document.
FIREWALLD_TARGET_ROWS = {"ACCEPT": "accept", "DROP": "drop", "%%REJECT%%": "reject"}


def firewalld_zone_from(zone):
    """Who a zone takes, for the from column: `(words, is an address)`. Its
    own sources when it has any, else anywhere."""
    sources = [str(a) for a in (zone.get("source_addrs") or []) if str(a)]
    if not sources:
        return ANYWHERE, False
    if len(sources) == 1:
        return sources[0], True
    return SOME_ADDRESSES, False


def firewalld_zone_rules(zone):
    """One zone's entries as rules, in the order the tab lists them.

    A zone's `source_addrs` narrow every rule in it, so they are the from
    column rather than a rule of their own. A service names a port only in
    firewalld's own service files, which the agent does not read, so a service
    rule carries the service's name where a port would go and never a number
    nobody measured.
    """
    frm, machine = firewalld_zone_from(zone)
    out = []
    for service in zone.get("services") or []:
        out.append(("allow", str(service), "", (), frm, machine, "service"))
    for entry in pp._dicts(zone.get("ports")):
        out.append(("allow", port_text(entry.get("port")),
                    str(entry.get("protocol") or ""), (), frm, machine, ""))
    for entry in pp._dicts(zone.get("forward_ports")):
        out.append(("forward", port_text(entry.get("port")),
                    str(entry.get("protocol") or ""), (), frm, machine,
                    "forwarded"))
    return out


# Where firewalld's own nftables table sends a packet for this host into a
# zone, and how it writes that. Measured by running firewalld for real and
# reading the kernel with nft, 2026-10-03 (docs/RECORD.md 4.342):
#
#   firewalld 0.9.11 and 1.3.4   chain filter_INPUT_ZONES
#                                iifname "eth0" goto filter_IN_public
#                                goto filter_IN_public
#   firewalld 2.1.2 and later    chain filter_INPUT_POLICIES
#                                iifname "eth0" jump filter_IN_public
#                                jump filter_IN_public
#
# The line with no condition is the default zone, which takes whatever no
# other line took. A zone entered for a source is `ip saddr 192.0.2.0/24 jump
# filter_IN_internal`, read on a real server with firewalld 2.4.0 (4.213).
# 0.9.11 keeps its source lines in a chain of their own, which is named here
# and whose lines were not measured. A chain named filter_IN_policy_ is one
# of firewalld's policies and not a zone.
FIREWALLD_TABLE = ("inet", "firewalld")
FIREWALLD_DISPATCH_CHAINS = ("filter_INPUT_POLICIES", "filter_INPUT_ZONES_SOURCE",
                             "filter_INPUT_ZONES")
FIREWALLD_POLICY_CHAIN = "policy_"
_FIREWALLD_ENTERS_ZONE = re.compile(r"^(?P<when>.*?)\s*(?:jump|goto) filter_IN_(?P<zone>\S+)$")
_FIREWALLD_ON_INTERFACE = re.compile(r'^iifname "([^"\s]+)"$')


def firewalld_zones_in_effect(doc):
    """Which zones the kernel sends packets into, and on which interfaces:
    `{zone name: [interface, ...]}`, or None when the kernel does not say.

    **firewalld keeps a file for every zone it ships, and only the zones
    something is bound to are in effect.** The files alone cannot say which.
    Until 2026-10-03 the tab listed every zone's rules as if all applied: 27
    rows from a Fedora 44 server's document where three were in effect, one
    of them the whole port range of a zone nothing used (docs/RECORD.md
    4.223 and 4.342). The kernel's ruleset is in the same document and does
    say, so it is asked.

    A zone is in effect when a line of the dispatch chain enters it, whatever
    that line's condition. The interfaces are kept because they are what the
    tab says about a zone. A zone entered only as the default, or only for a
    source, is in effect with no interface to name.

    None is its own answer and never an empty list: no nftables section, no
    table of firewalld's in it, or a table with none of these lines, which is
    firewalld on its iptables backend among other things. The caller then
    draws every zone as it did before, because that claims nothing new.
    """
    nft = pp._mapping(doc.get("nftables"))
    if nft.get("status") != "collected":
        return None
    entered = {}
    for table in pp._dicts(nft.get("tables")):
        if (table.get("family"), table.get("name")) != FIREWALLD_TABLE:
            continue
        for chain in pp._dicts(table.get("chains")):
            if chain.get("name") not in FIREWALLD_DISPATCH_CHAINS:
                continue
            for rule in pp._dicts(chain.get("rules")):
                found = _FIREWALLD_ENTERS_ZONE.match(str(rule.get("text") or "").strip())
                if not found or found.group("zone").startswith(FIREWALLD_POLICY_CHAIN):
                    continue
                interfaces = entered.setdefault(found.group("zone"), [])
                on = _FIREWALLD_ON_INTERFACE.match(found.group("when").strip())
                if on and on.group(1) not in interfaces:
                    interfaces.append(on.group(1))
    return entered or None


# A line of firewalld's way into its zones that enters a zone for a source:
# `ip saddr 10.88.0.0/16`, the whole of the line's condition.
_FIREWALLD_FOR_SOURCE = re.compile(r"^(?:meta nfproto ipv[46] )?ip6? saddr (\S+)$")

FirewalldEntry = namedtuple("FirewalldEntry", "sources open")


def firewalld_zone_entries(doc):
    """How the kernel's way into firewalld's zones enters each zone:
    `{zone: FirewalldEntry(sources, open)}`, or None when the kernel does not
    say (`firewalld_zones_in_effect` has the same cases).

    `sources` are the addresses of the lines that enter the zone for a
    source alone, in the kernel's order. `open` is whether any other line
    enters it: on an interface, or with no condition, which is the default
    zone. A zone that is not open takes those sources and nobody else
    (docs/PRODUCT.md 8d).

    **The kernel and not the zone's file**, because a source can be put into
    a zone while firewalld runs and never be written to its file. Netavark
    does that with the container network: rootful Podman's 10.88.0.0/16 in
    zone trusted, whose row read "accept any port anywhere" on an AlmaLinux
    10.2 server (the second big test, 24 October, case C6).
    """
    nft = pp._mapping(doc.get("nftables"))
    if nft.get("status") != "collected":
        return None
    found = {}
    for table in pp._dicts(nft.get("tables")):
        if (table.get("family"), table.get("name")) != FIREWALLD_TABLE:
            continue
        for chain in pp._dicts(table.get("chains")):
            if chain.get("name") not in FIREWALLD_DISPATCH_CHAINS:
                continue
            for rule in pp._dicts(chain.get("rules")):
                line = _FIREWALLD_ENTERS_ZONE.match(str(rule.get("text") or "").strip())
                if not line or line.group("zone").startswith(FIREWALLD_POLICY_CHAIN):
                    continue
                sources, is_open = found.get(line.group("zone"), ((), False))
                source = _FIREWALLD_FOR_SOURCE.match(line.group("when").strip())
                if source and source.group(1) not in sources:
                    sources += (source.group(1),)
                elif not source:
                    is_open = True
                found[line.group("zone")] = FirewalldEntry(sources, is_open)
    return found or None


def firewalld_zone_reach(zone, entries):
    """Who a zone's rows apply to, `(from words, is an address, families)`:
    its file's sources, or anywhere when it has none, as
    `firewalld_zone_from` says, unless the kernel enters the zone for
    sources alone and its file names none. Then those sources, since nobody
    else reaches the zone.

    The families are the one family of every source the kernel enters such
    a zone for, or none to name. A v4 source jump is never taken by a v6
    packet (docs/PRODUCT.md 8d), so a zone entered for v4 sources alone has
    v4 rules alone."""
    frm, machine = firewalld_zone_from(zone)
    entry = (entries or {}).get(str(zone.get("name") or ""))
    if entry is None or entry.open or not entry.sources:
        return frm, machine, ()
    if frm == ANYWHERE:
        frm, machine = (entry.sources[0], True) if len(entry.sources) == 1 \
            else (SOME_ADDRESSES, False)
    families = {_source_family(source) for source in entry.sources}
    return frm, machine, (families.pop(),) if len(families) == 1 and None not in families else ()


def _source_family(source):
    """v4 or v6 for an address or a network, None for anything else."""
    try:
        return "v6" if ipaddress.ip_network(source, strict=False).version == 6 else "v4"
    except ValueError:
        return None


def firewalld_loaded_zones(zones):
    """One zone a name: the file firewalld reads. The agent reports a zone's
    file from /etc/firewalld/zones and the one of the same name from
    /usr/lib/firewalld/zones, and the first is read: "The files will
    overload the default configuration files" (firewalld(1), DIRECTORIES,
    at firewalld.org, read 2026-10-26). Both were drawn, so a zone's
    services read twice, the vendor copy's from anywhere (the second big
    test, 24 October, case C6)."""
    chosen = {}
    for zone in zones:
        name = str(zone.get("name") or "")
        held = chosen.get(name)
        if held is None or (zone.get("origin") == "etc" and held.get("origin") != "etc"):
            chosen[name] = zone
    return [zone for zone in zones if chosen.get(str(zone.get("name") or "")) is zone]


# A policy of firewalld's that decides forwarded packets, as its table holds
# it on firewalld 2.4.4 with Docker (a Fedora 44 server's document,
# docs/RECORD.md 4.344):
#
#   chain filter_FORWARD_POLICIES
#       iifname "eth0" oifname "docker0" jump filter_FWD_policy_docker-forwarding
#       oifname "docker0" jump filter_FWD_policy_docker-forwarding
#   chain filter_FWD_policy_docker-forwarding
#       jump filter_FWD_policy_docker-forwarding_pre   (and _log, _deny, _allow, _post)
#       accept
#
# The last line is the policy's own target. Docker's packaging ships this
# policy so that what is forwarded to its bridge is accepted, which is how a
# published port passes firewalld whatever the zones say. Other versions of
# firewalld were not read for this, so only this chain name is looked for.
FIREWALLD_FORWARD_CHAIN = "filter_FORWARD_POLICIES"
FIREWALLD_FORWARD_POLICY = "filter_FWD_policy_"
FIREWALLD_POLICY_VERDICTS = ("accept", "drop")
_FIREWALLD_FORWARDS_TO_POLICY = re.compile(
    r'^(?:iifname "[^"\s]+" )?(?:oifname "(?P<out>[^"\s]+)" )?jump '
    + FIREWALLD_FORWARD_POLICY + r"(?P<name>\S+)$")


def firewalld_forward_policies(doc):
    """firewalld's policies that end every forwarded packet they take with
    one verdict: `[(name, verdict, interfaces it is forwarded to)]`, in the
    kernel's order. The interfaces are empty when a line sends packets to the
    policy whatever they leave on.

    Only what the kernel states is read. A policy is listed when the chain
    that sends forwarded packets to policies names it, and when its own chain
    ends on a bare `accept` or `drop` that the agent rendered in full. A
    policy that ends on anything else, a reject the agent could not render
    among them, is not listed, because its verdict is not known here.
    """
    nft = pp._mapping(doc.get("nftables"))
    if nft.get("status") != "collected":
        return []
    found = []
    for table in pp._dicts(nft.get("tables")):
        if (table.get("family"), table.get("name")) != FIREWALLD_TABLE:
            continue
        chains = {str(c.get("name") or ""): pp._dicts(c.get("rules"))
                  for c in pp._dicts(table.get("chains"))}
        sent = {}
        for rule in chains.get(FIREWALLD_FORWARD_CHAIN, []):
            line = _FIREWALLD_FORWARDS_TO_POLICY.match(str(rule.get("text") or "").strip())
            if not line:
                continue
            outs = sent.setdefault(line.group("name"), [])
            # None stands for a line with no interface to leave on.
            out = line.group("out")
            if out not in outs:
                outs.append(out)
        for name, outs in sent.items():
            own = chains.get(FIREWALLD_FORWARD_POLICY + name, [])
            last = own[-1] if own else {}
            verdict = str(last.get("text") or "").strip()
            if verdict not in FIREWALLD_POLICY_VERDICTS or last.get("rendered") != "full":
                continue
            found.append((name, verdict, () if None in outs else tuple(outs)))
    return found


def firewalld_block(slug, section, reported, in_effect=None, policies=(), entries=None):
    """firewalld as one firewall block, the zones in effect in it and the
    rest behind one fold.

    One block, not one per zone: the strip counts firewalls and firewalld is
    one firewall however many zones it keeps. A zone's name rides on its rules
    when more than one zone holds anything, and on the block's own line when
    only one does. The interface a zone is bound to rides with its name.

    `in_effect` is `firewalld_zones_in_effect`'s answer. With None every zone
    is drawn and none is called in effect or not, which is what this block
    did before the kernel was asked.

    A zone in effect that holds a target and no rule is one row, its target:
    Docker's zone, which accepts whatever arrives on Docker's bridge. Only
    with `in_effect` known, since a target is drawn as a rule that applies.
    `policies` is `firewalld_forward_policies`' answer, one row each.
    `entries` is `firewalld_zone_entries`' answer: a zone the kernel enters
    for some sources alone has its rows from those sources.
    """
    zones = [z for z in firewalld_loaded_zones(pp._dicts(section.get("zones")))
             if firewalld_zone_rules(z) or z.get("target")]
    if in_effect is None:
        drawn, folded = zones, []
    else:
        drawn = [z for z in zones if str(z.get("name") or "") in in_effect]
        folded = [z for z in zones if str(z.get("name") or "") not in in_effect
                  and firewalld_zone_rules(z)]

    def listed_rules(zone):
        """A zone's rows: its rules, or its target alone when it is in effect
        and holds no rule."""
        rules = firewalld_zone_rules(zone)
        frm, machine, families = firewalld_zone_reach(zone, entries)
        if rules and (frm, machine, families) != firewalld_zone_from(zone) + ((),):
            rules = [(action, port, protocol, families, frm, machine, note)
                     for action, port, protocol, _fams, _frm, _machine, note in rules]
        target = FIREWALLD_TARGET_ROWS.get(str(zone.get("target") or ""))
        # Only a zone in effect gets here without a rule: the fold holds
        # zones that have rules, and nothing else is listed.
        if rules or in_effect is None or not target:
            return rules
        # A zone bound to interfaces that takes no source of its own: the
        # interface is where its packets come from, so it stands in the from
        # column, where "anywhere" would read as the server being open.
        interfaces = (in_effect or {}).get(str(zone.get("name") or "")) or []
        if frm == ANYWHERE and interfaces:
            frm, machine = ", ".join(interfaces), True
        return [(target, "", "", (), frm, machine, "target")]

    filled = [z for z in drawn if listed_rules(z)]

    def zone_words(zone):
        """`zone public`, with `on eth0` when the kernel names an interface."""
        name = str(zone.get("name") or "")
        interfaces = (in_effect or {}).get(name) or []
        on = f"on {', '.join(interfaces)}" if interfaces else ""
        return " ".join(w for w in (f"zone {name}" if name else "", on) if w)

    def rows_of(some_zones, index, name_each):
        rows = []
        for zone in some_zones:
            name = str(zone.get("name") or "")
            for action, port, protocol, families, frm, machine, note in listed_rules(zone):
                index += 1
                # A target row with the interface in its from column names
                # the zone alone, since the column has said the interface.
                interfaces = (in_effect or {}).get(name) or []
                in_from = note == "target" and interfaces and frm == ", ".join(interfaces)
                words = (f"zone {name}" if in_from else zone_words(zone)) if name_each else ""
                note = ", ".join(w for w in (note, words) if w)
                card_lines = [("read from", tpl.mono(str(zone.get("file") or "")))] \
                    if zone.get("file") else []
                card_lines.append(("zone", tpl.esc(name)))
                for interface in (in_effect or {}).get(name) or []:
                    card_lines.append(("interface", tpl.mono(interface)))
                if zone.get("target"):
                    card_lines.append(("target", tpl.mono(str(zone.get("target")))))
                card_lines.append(("origin", tpl.esc(str(zone.get("origin") or ""))))
                if reported:
                    card_lines.append(("read", tpl.esc(f"agent reported {reported}")))
                rows.append(tpl.rule_row_html(
                    slug, "fwd", index, action,
                    tpl.rule_port_html(port, protocol, families),
                    tpl.rule_from_html(frm, machine, note),
                    tpl.rule_card_html("firewalld", "as the zone holds it", card_lines)))
        return rows

    rows = rows_of(drawn, 0, len(filled) > 1)
    for name, verdict, outs in policies:
        to = f"forwarded to {', '.join(outs)}" if outs else "forwarded"
        card_lines = [("policy", tpl.esc(name))]
        card_lines += [("forwarded to", tpl.mono(out)) for out in outs]
        if reported:
            card_lines.append(("read", tpl.esc(f"agent reported {reported}")))
        rows.append(tpl.rule_row_html(
            slug, "fwd", len(rows) + 1, verdict,
            tpl.rule_port_html("", "", ()),
            tpl.rule_from_html(ANYWHERE, False, f"policy {name}, {to}"),
            tpl.rule_card_html("firewalld", "as it is enforced", card_lines)))
    # The zones nothing is bound to, one click down. They are not counted:
    # the strip counts rules that apply.
    rest = rows_of(folded, len(rows), True)
    # The fold's rows stand in the block's own columns, so the column titles
    # are drawn once: above the rules in effect, or here when there are none.
    fold = tpl.fold_html(
        f"{len(folded)} zone{'' if len(folded) == 1 else 's'} not in effect",
        ("" if rows else tpl.RULE_HEAD_HTML) + "".join(rest)) if rest else ""
    one = filled[0] if len(filled) == 1 else None
    sub = zone_words(one) if one is not None else ""
    # The one zone's target at the right, unless the target is that zone's
    # own row, which has just said it.
    target = str(one.get("target") or "") \
        if one is not None and firewalld_zone_rules(one) else ""
    defaults = (("incoming", FIREWALLD_TARGETS.get(target, target.lower())),) if target else ()
    # The same guard ufw's block carries, for the same reason: a zone
    # directory the agent was not allowed into leaves no zones, and a block
    # drawn from that alone says firewalld has no rules over files nobody saw.
    state = ("fail", "not readable") if firewalld_zones_refused(section) else (
        ("ok", "active") if rows else ("off", "no rules"))
    return tpl.firewall_block_html("linux-logo", "firewalld", sub, state,
                                   defaults, "".join(rows), fold), len(rows)


# What a container runtime is called on the screen, and the order the two are
# listed in. They are never merged: two runtimes on one host are two answers
# (docs/PRODUCT.md 4d).
CONTAINER_RUNTIMES = (("docker", "Docker"), ("podman", "Podman"))

# What the runtime says it published on, and which family that is. An empty
# host_ip is the runtime not saying, never a wildcard, so it earns neither.
PUBLISH_FAMILIES = {"0.0.0.0": ("v4",), "::": ("v6",)}


def container_block(slug, section, key, name, reported):
    """One container runtime's published ports as a firewall block.

    A container publishing a port opens it before ufw is asked
    (docs/PRODUCT.md 4a), so it is a list of its own. Leaving it out would
    hide an open port from the one tab that promises all the rules
    (the owner, 2026-09-09, asked for the container to be added).
    """
    rows, index = [], 0
    for container in pp._dicts(section.get(key)):
        cname = str(container.get("name") or container.get("id") or "")
        for published in pp._dicts(container.get("ports")):
            index += 1
            host_ip = str(published.get("host_ip") or "")
            families = PUBLISH_FAMILIES.get(host_ip, ())
            frm, machine, unread = ANYWHERE, False, False
            if host_ip and host_ip not in PUBLISH_FAMILIES:
                frm, machine = host_ip, True
            elif not host_ip:
                # The runtime did not say where it published this, so neither
                # does the page. It is a rule read in part, which is what the
                # tag says.
                frm, machine, unread = "", False, True
            card_lines = [("container", tpl.esc(cname)),
                          ("image", tpl.esc(str(container.get("image") or ""))),
                          ("publishes", tpl.mono(
                              f'{published.get("host_port", "")}/'
                              f'{published.get("protocol", "")}'
                              + (f" on {host_ip}" if host_ip else ""))),
                          ("to", tpl.mono(
                              f'{published.get("container_port", "")}/'
                              f'{published.get("protocol", "")} in the container'))]
            if reported:
                card_lines.append(("read", tpl.esc(f"agent reported {reported}")))
            rows.append(tpl.rule_row_html(
                slug, key, index, "publish",
                tpl.rule_port_html(port_text(published.get("host_port")),
                                   str(published.get("protocol") or ""), families),
                tpl.rule_from_html(frm, machine,
                                   f"to {cname}" if cname else "", unread),
                tpl.rule_card_html(name, "as the runtime publishes it", card_lines)))
    if not rows:
        return "", 0
    return tpl.firewall_block_html("cube", name, "publishes", ("ok", "active"),
                                   (), "".join(rows)), len(rows)


# Which firewall wrote a kernel table or chain. This is the one piece of
# judgement the tab adds, and it is a short list somebody decided rather than a
# pattern that guesses: a chain nobody named here counts as written by nobody,
# which is what puts its rules in the kernel's own list.
#
# firewalld names its own nftables tables `firewalld`, `firewalld_policy_drop`
# and `firewalld_probe` (firewalld's own `src/firewall/core/nftables.py`, read
# 2026-09-10). ufw and docker are named by their chains, which is what
# `build.rule_author` already reads for the same two.
FIREWALLD_TABLE_PREFIX = "firewalld"


def kernel_chain_author(table_name, chain_name):
    """Which named firewall wrote this chain, or "" for none of them."""
    if str(table_name or "").startswith(FIREWALLD_TABLE_PREFIX):
        return "firewalld"
    return tpl.rule_author(chain_name)


# The agent writes a reject it cannot spell out as this bracket, last in the
# rule (`fall("reject")` in agent/internal/collect/nftrender_linux.go).
_BRACKET_REJECT = re.compile(r"(?:^|\s)\[reject\]$")


def kernel_rule_action(text):
    """The word in a kernel rule's action column: the verdict the rule ends
    on, or reject where the agent wrote the reject in brackets.

    The agent renders an nftables reject as `[reject]`, because it does not
    render what the reject answers with, and the walk's own reader of verdicts
    does not take a bracket for one. So a rule that rejects had no action on
    this tab (docs/RECORD.md 4.220). The bracket still says which statement
    it is, and that is all this column prints. It is read as the last thing
    in the rule only: `jump` followed by a bracket is a jump.
    """
    text = text or ""
    if _BRACKET_REJECT.search(text) and not pp._JUMP.search(text):
        return "reject"
    return pp.rule_verdict(text)


# A rule that is a jump and nothing else, as the agent writes one: `counter
# jump ufw-before-input` out of nftables, `jump ufw-before-input` out of the
# older tables. Anything in front of the jump is a condition somebody set,
# and then the whole line is not matched.
_ONLY_A_JUMP = re.compile(r"^(?:counter )?(?:jump|goto) (?P<chain>\S+)$")


def named_firewalls_way_in(table_name, rule):
    """The named firewall this rule hands every packet to, or "" for none.

    ufw hangs its chains on the kernel's own INPUT, FORWARD and OUTPUT with
    six lines each, once for v4 and once for v6: 36 on Ubuntu 26.04.1 with ufw
    0.36.2, read on 2026-10-11 (docs/RECORD.md 4.453). They sit in chains ufw
    did not name, and they are how its rules are reached at all, so they are
    ufw's and not a rule nobody wrote. Docker does the same with two lines
    in FORWARD, `counter jump DOCKER-USER` and `counter jump DOCKER-FORWARD`,
    read the same day in the document of a Fedora 44 test server.

    Only the jump and nothing else. A jump behind a condition, or one with a
    note on it, is a line somebody wrote and it stays in the kernel's list.
    """
    if rule.get("comment"):
        return ""
    only_a_jump = _ONLY_A_JUMP.match(str(rule.get("text") or ""))
    if not only_a_jump:
        return ""
    return kernel_chain_author(table_name, only_a_jump.group("chain"))


# The three sections of a document that hold kernel rules, in the order the
# tab lists them.
KERNEL_SECTIONS = ("nftables", "iptables", "ip6tables")


# The family each of the older tables is for, said after every row out of
# it: their v4 and v6 rules stood in one list with nothing to tell them apart
# (docs/RECORD.md 4.220). An nftables table says its own families in the
# opened row.
LEGACY_FAMILY = {"iptables": "v4", "ip6tables": "v6"}


def kernel_leftover_chains(doc, counted=()):
    """Every kernel chain that no named firewall wrote, in the order the tab
    lists them, as (section, table, chain name, its listed rules, its policy).

    One walk, for the block that draws them and for whoever has to know
    whether a section holds anything (`rules_tab_body`). `counted` is as
    `kernel_leftovers_block` says.

    The policy is the chain's own word when it is not accept, and "" when it
    is accept or the chain has none. It is "" too for a chain a counted
    firewall hangs its own chains on: ufw sets INPUT's policy itself and its
    block says it as its default, so a row here would say it a second time.
    """
    for key in KERNEL_SECTIONS:
        section = pp._mapping(doc.get(key))
        if section.get("status") != "collected":
            continue
        for table in pp._dicts(section.get("tables")):
            for chain in pp._dicts(table.get("chains")):
                chain_name = str(chain.get("name") or "")
                if kernel_chain_author(table.get("name"), chain_name):
                    continue
                rules = pp._dicts(chain.get("rules"))
                listed = []
                for rule in rules:
                    way_in = named_firewalls_way_in(table.get("name"), rule)
                    if not (way_in and way_in in counted):
                        listed.append(rule)
                policy = str(chain.get("policy") or "").lower()
                if policy == "accept" or len(listed) < len(rules):
                    policy = ""
                yield key, table, chain_name, listed, policy


def kernel_leftovers_block(slug, doc, reported, counted=()):
    """Everything in the kernel that no named firewall wrote.

    ufw writes its rules into the kernel, so listing both would show every
    rule twice in two dialects, which is the jargon this tab exists to keep
    out. The kernel appears only for what no named firewall wrote
    (docs/screens/host-rules/SPEC.md, confirmed 2026-09-09).

    `counted` names the firewalls that have a block of their own on this tab
    and are counted there. Their way in is left out with their rules
    (`named_firewalls_way_in`) and nobody else's is. A ufw that its own file
    says is off, with its lines still in the kernel, keeps them in this list,
    so leaving a line out never takes the last firewall off the page
    (docs/RECORD.md 4.453).

    **A chain whose policy is not accept gets one row for it, after its
    rules** (docs/RECORD.md 4.454), drawn like the row a firewalld zone's
    target gets: the policy's word, any port, anywhere, noted `policy, chain
    INPUT`. A server on the older iptables with INPUT set to DROP showed its
    four accepts and nothing of what happens to everything else
    (docs/RECORD.md 4.220).
    """
    rows, index = [], 0
    for key, table, chain_name, listed, policy in kernel_leftover_chains(doc, counted):
        label = " ".join(w for w in (str(table.get("family") or ""),
                                     str(table.get("name") or "")) if w)
        family = LEGACY_FAMILY.get(key, "")
        for rule in listed:
            index += 1
            text = str(rule.get("text") or "")
            grade = str(rule.get("rendered") or "")
            port, readable = pp.rule_port_claim(text, grade)
            protocol, _, number = port.partition("/")
            if not number:
                protocol, number = "", port
            card_lines = [("table", tpl.mono(label)),
                          ("chain", tpl.mono(chain_name)),
                          ("rule", tpl.mono(text))]
            if rule.get("comment"):
                card_lines.append(("your note", tpl.esc(str(rule["comment"]))))
            if reported:
                card_lines.append(("read", tpl.esc(f"agent reported {reported}")))
            # A rule whose port this page could not read claims no port: the
            # cell is empty and the row carries the tag. "any port" stood
            # there, on rules that name a port in a set, a range or beside a
            # limit (docs/RECORD.md 4.220).
            rows.append(tpl.rule_row_html(
                slug, "kernel", index, kernel_rule_action(text),
                tpl.rule_port_html(port_text(number), protocol, (),
                                   unreadable=not readable),
                tpl.rule_from_html(text, True, family,
                                   grade != "full" or not readable),
                tpl.rule_card_html("in the kernel", "as it is enforced",
                                   card_lines)))
        if policy:
            index += 1
            note = ", ".join(w for w in ("policy", f"chain {chain_name}", family) if w)
            card_lines = [("table", tpl.mono(label)),
                          ("chain", tpl.mono(chain_name)),
                          ("policy", tpl.mono(policy))]
            if reported:
                card_lines.append(("read", tpl.esc(f"agent reported {reported}")))
            rows.append(tpl.rule_row_html(
                slug, "kernel", index, policy,
                tpl.rule_port_html("", "", ()),
                tpl.rule_from_html(ANYWHERE, False, note),
                tpl.rule_card_html("in the kernel", "as it is enforced",
                                   card_lines)))
    if not rows:
        return "", 0
    return tpl.firewall_block_html("hard-drives", "In the kernel",
                                   "not written by a named firewall",
                                   ("ok", "active"), (), "".join(rows)), len(rows)


# Hetzner's own defaults, from its firewall overview (read 2026-09-09): with
# no matching rule all inbound is blocked and all outbound is permitted.
PROVIDER_DEFAULTS = {"hetzner": (("incoming", "deny"), ("outgoing", "allow"))}

# What an attachment's status means for the block's state word. Hetzner says
# `applied` or `pending`, and pending is never read as a permit.
ATTACHED_STATES = {"applied": ("ok", "active"), "pending": ("warn", "pending")}


def provider_read_words(provider, host_name, now):
    """How long ago this host's project's snapshot was read, in words, or "".

    A card says when what it quotes was read, and for a provider rule that is
    the snapshot's own time and not the agent's. With a token per project
    each project is read on its own, so it is the project that lists this
    host whose time is said.
    """
    found = provider_match(provider, host_name)
    snapshot = provider_projects(provider)[found[0]].get("snapshot") if found else None
    if snapshot is None:
        return ""
    try:
        return f"snapshot taken {read_age(datetime.fromisoformat(snapshot.fetched_at), now)}"
    except (TypeError, ValueError):
        return ""


def provider_projects(provider):
    """The projects `load_provider` read, one per token, or none."""
    return (provider or {}).get("projects") or []


def provider_match(provider, host_name):
    """(this host's project's place in `provider_projects`, its server), or
    None.

    By the addresses the host proved, and by name only when no address names
    a server, across every project the workspace holds a token for:
    `hetzner.match_in_projects`, the one rule the join engine uses too, which
    says why. `provider["addresses"]` holds each host's live proved
    addresses, put there when the page is loaded. It was whole-name equality
    here until 2026-09-20 (`docs/RECORD.md` 4.190), and one project until
    2026-09-29 (4.206). A project whose snapshot could not be parsed takes no
    part, the way it takes none in the engine.
    """
    if not host_name:
        return None
    places = [place for place, project in enumerate(provider_projects(provider))
              if project.get("inventory") is not None]
    if not places:
        return None
    inventories = [provider_projects(provider)[place]["inventory"] for place in places]
    addresses = (provider.get("addresses") or {}).get(host_name, ())
    found = joinbridge.module("hetzner").match_in_projects(
        inventories, str(host_name), addresses)
    if found is None:
        return None
    index, server = found
    return places[index], server


def provider_server(provider, host_name):
    """The provider's own server row for this host, or None."""
    found = provider_match(provider, host_name)
    return found[1] if found is not None else None


def provider_source_words(addresses):
    """A provider rule's sources: (the words, machine, not fully readable)."""
    every = tuple(addresses.v4) + tuple(addresses.v6)
    unparsed = tuple(addresses.unparsed)
    if any(a in ANY_ADDRESSES for a in every):
        return ANYWHERE, False, bool(unparsed)
    if len(every) == 1 and not unparsed:
        return every[0], True, False
    if not every and not unparsed:
        return ANYWHERE, False, False
    return SOME_ADDRESSES, False, bool(unparsed)


def provider_families(addresses):
    return tuple(f for f, has in (("v4", addresses.has_v4),
                                  ("v6", addresses.has_v6)) if has)


def provider_empty_words(provider, host_name):
    """The one grey line where the provider's firewall would be, when there is
    no block to draw. Three different facts, so three lines: nothing is
    connected, the provider does not list this server, or it lists it with no
    firewall attached. It said "No provider connected" for all three until
    2026-09-20, including about a provider that had just read six servers."""
    if not any(project.get("inventory") is not None
               for project in provider_projects(provider)):
        return tpl.NO_PROVIDER_FIREWALL
    if provider_server(provider, host_name) is None:
        return tpl.PROVIDER_SERVER_NOT_FOUND
    return tpl.NO_FIREWALL_AT_PROVIDER


def provider_rule_count(provider, host_name):
    """How many rules the provider's firewalls on this server hold, or None
    when the provider does not list the server.

    Counted the way `provider_blocks` counts the rows it draws on the Rules
    tab, from the same stored firewalls, so the Evidence card and that tab say
    one number (docs/RECORD.md 4.395). A firewall the server names that the
    snapshot does not hold has no rules to count, as it has no rows there.
    """
    found = provider_match(provider, host_name)
    if found is None:
        return None
    place, server = found
    inventory = provider_projects(provider)[place]["inventory"]
    return sum(len(firewall.rules)
               for _attached, firewall in inventory.firewalls_for_server(server.id)
               if firewall is not None)


# The protocols a firewall rule names a port for. Any other one, icmp, esp or
# gre, carries no port, and a provider rule for it is named by its protocol.
PROTOCOLS_WITH_PORTS = ("tcp", "udp")


def provider_blocks(slug, provider, host_name, read_age_words):
    """One block per firewall the provider has attached to this server,
    looked up in the project that listed the server: firewall ids are the
    provider's per project, so another project's firewall 3 is another
    firewall."""
    found = provider_match(provider, host_name)
    if found is None:
        return "", 0, 0
    place, server = found
    inventory = provider_projects(provider)[place]["inventory"]
    out, rules, firewalls = [], 0, 0
    for attached, firewall in inventory.firewalls_for_server(server.id):
        state = ATTACHED_STATES.get(str(attached.status), ("warn", str(attached.status)))
        if firewall is None:
            # The two reads that build a snapshot are separate requests, so a
            # firewall attached between them is a real answer and never a
            # server without one.
            out.append(tpl.firewall_block_html(
                "hetzner", tpl.PROVIDER_NAMES["hetzner"], "",
                ("warn", "not in the snapshot"), (), ""))
            continue
        firewalls += 1
        rows = []
        for index, rule in enumerate(firewall.rules, 1):
            rules += 1
            words, machine, unread = provider_source_words(rule.source_ips)
            note = "outgoing" if rule.direction == "out" else ""
            # A rule for a protocol with no ports, icmp for one, draws as "any
            # port", so the protocol goes in the note or the row reads as a
            # rule that opens every port (docs/screens/host-rules/SPEC.md, the
            # from column, and the sweep of 2026-09-21 in docs/RECORD.md 4.199).
            protocol = str(rule.protocol or "")
            if protocol and protocol not in PROTOCOLS_WITH_PORTS:
                note = ", ".join(w for w in (protocol.upper(), note) if w)
            if rule.description:
                note = ", ".join(w for w in (note, str(rule.description)) if w)
            card_lines = [("firewall", tpl.esc(firewall.name)),
                          ("direction", tpl.mono(str(rule.direction))),
                          ("rule", tpl.mono(
                              f'{rule.protocol} {rule.port or "any port"}')),
                          ("source", tpl.mono(", ".join(
                              tuple(rule.source_ips.v4) + tuple(rule.source_ips.v6)
                              + tuple(rule.source_ips.unparsed)) or "none given"))]
            if read_age_words:
                card_lines.append(("read", tpl.esc(read_age_words)))
            rows.append(tpl.rule_row_html(
                slug, f"prov{firewall.id}", index, rule.direction == "out"
                and "allow out" or "allow",
                tpl.rule_port_html(port_text(rule.port), rule.protocol,
                                   provider_families(rule.source_ips)),
                tpl.rule_from_html(words, machine, note, unread),
                tpl.rule_card_html(tpl.PROVIDER_NAMES["hetzner"],
                                   "as the firewall holds it", card_lines)))
        out.append(tpl.firewall_block_html(
            "hetzner", tpl.PROVIDER_NAMES["hetzner"], firewall.name, state,
            PROVIDER_DEFAULTS["hetzner"], "".join(rows)))
    return "".join(out), rules, firewalls


# Which firewall a rule file belongs to, by the directory it lives in. The
# strip's third fact names one, and naming it from the path is reading the
# host's own answer rather than deciding it here.
RULE_FILE_OWNERS = (("/etc/ufw/", "ufw"), ("/etc/default/ufw", "ufw"),
                    ("/etc/firewalld/", "firewalld"),
                    ("/etc/nftables", "nftables"), ("/etc/iptables/", "iptables"))


def rule_file_owner(path):
    for prefix, owner in RULE_FILE_OWNERS:
        if str(path or "").startswith(prefix):
            return owner
    return ""


# The kinds of change the Changes tab lists for the host's own rules
# (`diff_digests`): a rule file's date moved, or a table's rule count did.
RULE_CHANGE_LAYER = "host firewall"
RULE_CHANGE_KINDS = ("file changed", "rule added", "rule removed")
_NFT_TABLE_NAMED = re.compile(r"^(nftables \S+ \S+?)(?::| appeared| disappeared)")


def _rule_change_owner(change):
    """Whose rules a change of the Changes tab was about: the firewall that
    owns the file, or the kernel table whose count moved."""
    if change.kind == "file changed":
        return rule_file_owner(change.detail)
    named = _NFT_TABLE_NAMED.match(change.detail or "")
    return named.group(1) if named else ""


# The firewalls a rule file can belong to, which is every owner in
# RULE_FILE_OWNERS. A file of one of these is named only while that firewall
# is in effect on the server.
RULE_FILE_FIREWALLS = ("ufw", "firewalld", "nftables", "iptables")


def rules_last_changed(doc, changes=(), in_effect=None):
    """When this host's rules last changed, as far as the page knows, and
    whose they were.

    Two things say so and the newer one is said: the newest date on a rule
    file, and the newest rule change between two reports, which is what the
    Changes tab lists (`changes`, the lines of `host_log`). Until 2026-10-06 only
    the files were asked, so a kernel ruleset that moved was on the Changes
    tab and the Rules tab beside it said "never" (docs/RECORD.md 4.393).

    With neither, the page says no change was seen. It does not say never.

    The provider's snapshot has a time it was read and no time it changed, so
    it is not in this: the fact is about the host.

    **A file's date is named only for a firewall that is in effect.**
    `in_effect` is the names of those, as `rules_tab_body` counts them. A
    server with ufw installed and never enabled read the date of ufw's files
    here, and one with ufw alone could read the date of the image's
    /etc/nftables.conf (docs/RECORD.md 4.220, 4.454). The same holds for a
    file's date that moved between two reports. A rule added to or removed
    from a kernel table was read in the kernel, and always counts. Asked
    without the list, every file counts, as it did.
    """
    def named(file_owner):
        return (in_effect is None or file_owner not in RULE_FILE_FIREWALLS
                or file_owner in in_effect)

    newest, owner = None, ""
    for entry in pp._dicts(pp._mapping(doc.get("rule_files")).get("files")):
        when = utc_from_unix(entry.get("mtime_unix", 0))
        if when is None or not named(rule_file_owner(entry.get("path"))):
            continue
        if newest is None or when > newest:
            newest, owner = when, rule_file_owner(entry.get("path"))
    for change in changes or ():
        if change.layer != RULE_CHANGE_LAYER or change.kind not in RULE_CHANGE_KINDS:
            continue
        if change.when is None:
            continue
        if change.kind == "file changed" and not named(rule_file_owner(change.detail)):
            continue
        if newest is None or change.when > newest:
            newest, owner = change.when, _rule_change_owner(change)
    if newest is None:
        return tpl.NO_RULE_CHANGE_SEEN, ""
    return newest.strftime("%-d %b"), owner


def rules_tab_body(doc, host_name="", provider=None, reported="", read_words="",
                   changes=()):
    """Every firewall on this host, in the order a packet from outside meets
    them: the provider's, the host's own, what a container runtime publishes,
    then whatever else is in the kernel that none of those wrote.

    `reported` is how long ago the agent reported, in words, for the cards.
    `read_words` is the same for the provider's snapshot.

    A layer the agent could not read, or one this page could not read, is
    named at the bottom rather than left out, because an absent layer reads as
    a host that does not have one.
    """
    parts, rule_count, firewall_count = [], 0, 0
    provider_html, provider_rules, provider_firewalls = provider_blocks(
        host_name, provider or {}, host_name, read_words)
    if provider_html:
        parts.append(provider_html)
        rule_count += provider_rules
        firewall_count += provider_firewalls
    else:
        parts.append(tpl.firewall_line_html(provider_empty_words(provider, host_name)))
    host_own, state_not_known = [], False
    # The firewalls counted in a block of their own, by the name
    # `kernel_chain_author` gives them. The kernel's list leaves out their
    # way in and nobody else's.
    counted = []
    ufw = pp._mapping(doc.get("ufw"))
    if ufw.get("status") == "collected":
        html, count = ufw_block(host_name, ufw, reported)
        host_own.append(html)
        # A ufw that is not enabled keeps its row and its rules are listed,
        # and neither it nor they are counted: the strip counts what is in
        # effect, as it does for firewalld's zones (docs/RECORD.md 4.220).
        if ufw_enabled(ufw):
            rule_count += count
            firewall_count += 1
            counted.append("ufw")
        elif ufw_enabled_word(ufw) != "no":
            state_not_known = True
    fwd = pp._mapping(doc.get("firewalld"))
    if fwd.get("status") == "collected":
        html, count = firewalld_block(host_name, fwd, reported,
                                      firewalld_zones_in_effect(doc),
                                      firewalld_forward_policies(doc),
                                      firewalld_zone_entries(doc))
        host_own.append(html)
        rule_count += count
        firewall_count += 1
        counted.append("firewalld")
    # A container runtime's block is read here and placed further down, so
    # the kernel's list knows whether the runtime is counted.
    containers = pp._mapping(doc.get("containers"))
    runtime_blocks = []
    for key, name in CONTAINER_RUNTIMES:
        html, count = container_block(host_name, containers, key, name, reported)
        if html:
            runtime_blocks.append(html)
            rule_count += count
            firewall_count += 1
            counted.append(key)
    # The kernel's own list is read before the host's place is filled: rules
    # nobody named are a firewall in effect, and "No firewall active" stood
    # above twelve of them beside a strip that said one (docs/RECORD.md 4.220).
    kernel_html, kernel_rules = kernel_leftovers_block(host_name, doc, reported, counted)
    # Zero layers is the one depth that is called out (docs/PRODUCT.md
    # section 2), above the row of a firewall that is there and switched off.
    # It is not said over a ufw whose file did not say whether it is on.
    # Zero is the strip's own count: the provider's firewall and a container
    # runtime are counted there, and the card stood beside a strip that said
    # one on a server with either and nothing of its own (docs/RECORD.md
    # 4.454). The kernel's list is counted further down, so it is asked here.
    if not firewall_count and not state_not_known and not kernel_html:
        parts.append(tpl.no_firewall_html())
    parts.extend(host_own)
    parts.extend(runtime_blocks)
    if kernel_html:
        parts.append(kernel_html)
        rule_count += kernel_rules
        firewall_count += 1
    else:
        parts.append(tpl.firewall_line_html(tpl.NOTHING_ELSE_IN_KERNEL))
    # Whose rule files may lend their date: the firewalls counted above, and
    # the kernel's own two kinds where the kernel's list holds a rule of
    # that kind.
    in_effect = set(counted)
    for key, _table, _chain, listed, policy in kernel_leftover_chains(doc, counted):
        if listed or policy:
            in_effect.add("nftables" if key == "nftables" else "iptables")
    changed, owner = rules_last_changed(doc, changes, in_effect)
    strip = tpl.three_facts_html([
        ("Firewalls active", firewall_count, "on this server"),
        ("Rules", rule_count, "across them"),
        ("Rules last changed", changed, owner)])
    named = unreadable_layers_panel(not_readable_sections(doc)) + refused_layers_panel(doc)
    return strip + "".join(parts) + named


def ufw_lines(section, key):
    """One of ufw's two rules files as the lines of text it is.

    `rules` and `rules6` are `[]string` in the agent's schema, so the object
    helper is the wrong tool for them and the shape check has already refused
    anything else by the time this runs.
    """
    value = section.get(key)
    return [line for line in value if isinstance(line, str)] if isinstance(value, list) else []


def unreadable_layers_panel(unreadable):
    """The firewall layers on this host whose section the page could not read.

    Named on the Rules tab as well as on Evidence because a layer that is
    simply missing from this tab reads as a layer the host does not have, and
    the two are different facts.
    """
    rows = [(key, label) for key, label in SECTION_LABELS
            if key in unreadable and key in RULE_LAYERS]
    if not rows:
        return ""
    return tpl.sec_panel(
        "Layers this page could not read",
        "".join(tpl.three_cell_row(tpl.esc(label), tpl.esc(SECTION_UNREADABLE),
                                   theme.status("fail", "not readable"))
                for _key, label in rows))


def refused_layers_panel(doc):
    """The firewall layers on this host the agent was refused, named on the
    Rules tab.

    **A layer that is simply missing from this tab reads as a layer the host
    does not have.** That is already why the panel above exists, and until this
    was written a refused layer was missing in exactly the same way: the tab
    quotes a section whose status is collected and quietly draws nothing for
    every other status. On the fleet measured in docs/RECORD.md 4.72 that is
    firewalld's own conf and its admin zones, so the tab said this host has no
    firewalld configuration when what happened is that the read was refused.

    A layer whose section did collect is named too when a source inside it was
    refused, because `aggregateSources` reports the section as collected then,
    and the tab draws the part that did arrive with no sign of the part that
    did not.
    """
    rows = [(key, sources) for key, sources in refused_reads(doc)
            if key in RULE_LAYERS]
    if not rows:
        return ""
    return tpl.sec_panel(
        "Layers the agent could not read",
        "".join(tpl.three_cell_row(tpl.esc(SECTION_LABEL[key]), tpl.esc(", ".join(sources)),
                                   theme.status("warn", "permission denied"))
                for key, sources in rows))


# raw_panel is gone. The whole document as JSON sat behind a disclosure on
# Evidence, and the owner asked for it out twice, the second time on
# 2026-08-16. The document is still stored verbatim and
# still reachable over the API, so nothing about evidence is lost, it is the
# panel that nobody opened.
def family_sockets(doc):
    """How many listening sockets the agent found on each address family, or
    None for a family question the sockets read cannot answer.

    A failed read must never look like an empty result (RECORD 4.17), so an
    unread sockets section returns None and the cell says so. A section that
    said it was collected and did not survive the read carries the marker by
    now, so it is the same answer here: nothing read, no number given.
    """
    section = pp._mapping(doc.get("sockets"))
    if section.get("status") != "collected":
        return None
    counts = {"v4": 0, "v6": 0}
    for s in pp._dicts(section.get("listening")):
        if s.get("family") in counts:
            counts[s["family"]] += 1
    return counts


# What the inside view contributes, in the matrix's own vocabulary. Loopback is
# read from the bind addresses because a socket bound to 127.0.0.1 is a fact
# about the socket and never a conclusion about reachability: the whole product
# exists because a bind address does not decide what answers from outside.
#
# `is_loopback` is the one place that decides. There were two spellings of this
# before, in this file, and they disagreed: this tab called the owner's tcp/53
# `loopback` while the Overview listed the same port under "bound to a network
# address", one click apart on the same document (2026-08-22).


def _agent_token(inside):
    """The agent column for one finding.

    `not read` is its own answer and is never `nothing`. A sockets section that
    did not arrive cannot say a port is unowned, and a failed read that looks
    like an empty result is `docs/RECORD.md` 4.17.
    """
    if getattr(inside, "absent", False):
        return "no agent"
    if inside.sockets_status != "collected":
        return "not read"
    if inside.sockets:
        addresses = [s.bind_address or "" for s in inside.sockets]
        if all(is_loopback(a) for a in addresses):
            return "loopback"
        return "listening"
    if inside.publications:
        return "published"
    if inside.ambiguous_binds:
        # A wildcard v6 bind may be serving v4 and the document cannot say. It
        # is not `nothing`, because `nothing` asserts an absence.
        return "listening"
    return "nothing"


def _provider_token(provider):
    """The provider column for one finding.

    Three different silences, and they are not the same fact. Nobody connected
    a provider, a provider was asked and does not have this host, and a
    provider that has the host and no rule naming this port.
    """
    if not provider.configured:
        return "not connected"
    if not provider.matched:
        return "no match"
    if provider.rules:
        return "permits"
    return "permits some" if getattr(provider, "narrowed", ()) else "no rule"


def finding_socket_name(sock):
    """What a socket in a finding is called, or "" when nothing names it.

    `socket_holder` decides, the one function the Services tab and the
    Overview's Service column already answer this with, so one socket has one
    name on every tab. It takes the document's own entry, and the engine's
    record carries the same four facts (`join.ListeningSocket`), so they are
    handed over under the document's keys.
    """
    name = socket_holder({"process_name": sock.process_name, "unit": sock.unit,
                          "owner_name": sock.owner_name, "owner_uid": sock.owner_uid})
    return "" if name == "unknown process" else name


def evidence_screen_rows(slug, rows, findings, unread=False):
    """The matrix as the tab draws it: one EvidenceRow per finding, in the
    Overview's order (worst first, then the number) with v4 before v6, the
    engine's words in every view cell, and the service on this family.

    "nothing" from the engine is two facts on the screen: nothing bound on
    this family while the port has a socket on the other, or nothing
    listening at all. Both read off the findings, never guessed.

    `unread` is `sockets_not_read` of the document: every agent cell says
    "not read" and no socket names a service, whatever the findings hold."""
    order = {(r.protocol, r.port): i for i, r in enumerate(rows)}
    row_by_port = {(r.protocol, r.port): r for r in rows}
    sockets_on = {(f.protocol, f.port, f.family): bool(f.inside.sockets) for f in findings}
    out = []
    for port, family, agent, prober, provider, state, limited in evidence_matrix_rows(None, findings):
        protocol, number = port.split("/", 1)
        number = int(number)
        finding = next(f for f in findings
                       if f.protocol == protocol and f.port == number and f.family == family)
        if unread:
            agent = "not read"
        elif agent == "nothing":
            other = "v6" if family == "v4" else "v4"
            agent = ("nothing bound" if sockets_on.get((protocol, number, other))
                     else "nothing listening")
        sockets = () if unread else finding.inside.sockets
        # Named the way the Services tab names the same socket, from the
        # same facts. It read `process_name` alone until 2026-09-20, which
        # agent 0.1.10 never sends, so the column was a dash on every row.
        names = list(dict.fromkeys(
            name for name in (finding_socket_name(s) for s in sockets)
            if name))
        # The Overview's row for this port already has a name, decided by
        # `port_naming` from everything that can name a port. Evidence shows
        # that name on the families that hold a socket, so the two tabs
        # cannot disagree. What the kernel said is the fallback.
        row = row_by_port.get((protocol, number))
        row_name = (row.service if row is not None and not row.service_note
                    and sockets else "")
        service = finding.declared_name or row_name or join_and(names)
        out.append(tpl.EvidenceRow(protocol, number, family, service, agent, prober, provider,
                                   state or "", tpl.row_id(slug, protocol, number), limited,
                                   disagree=finding.outside.disagree,
                                   views=vantage_views(finding.outside)))
    out.sort(key=lambda e: (order.get((e.protocol, e.port), len(order)), e.port, e.family))
    return out


def vantage_views(outside):
    """What each vantage said about one port, (name, the engine's word), for
    the lines under a disagreeing prober cell. Measured vantages only: the
    engine leaves a vantage that said nothing out of the comparison, so the
    screen names none (docs/PRODUCT.md 8e)."""
    return tuple((v.vantage, v.word) for v in outside.views if v.measured)


def any_disagree(findings):
    """Whether any port on the server carries the engine's disagree mark,
    for the Reachable cell of its fleet row."""
    return any(f.outside.disagree for f in findings)


def vantages_line(vantages, findings):
    """The prober card's `vantages` line: every enabled vantage by name in
    registry order. A database from before the registry names the vantages
    that measured this host instead, and a host nothing measured gets a
    dash."""
    names = list(vantages)
    if not names:
        seen = {v.vantage for f in findings for v in f.outside.views if v.measured}
        names = sorted(seen)
    return ", ".join(tpl.mono(n) for n in names) if names else "&mdash;"


def evidence_cards(doc, received_at, findings, now, agentless=False, vantages=(),
                   provider_rules=None):
    """The three cards: (title, when, [(label, value html)], off). Every value
    is a fact the document or the stored runs carry; the provider card is
    greyed with "not connected" while no token is set (SPEC.md section 2),
    and so is the agent's on a host that has none. `provider_rules` is
    `provider_rule_count`'s answer for this server."""
    if agentless:
        agent = ("The agent, inside", "no agent", [], True)
        return [agent] + evidence_cards(doc, received_at, findings, now, vantages=vantages,
                                        provider_rules=provider_rules)[1:]
    sockets = family_sockets(doc)
    saw = ("not read" if sockets is None
           else f"{tpl.mono(sockets['v4'])} sockets on v4, {tpl.mono(sockets['v6'])} on v6")
    filtering = firewall_intent(doc)
    default = _ufw_default(doc)
    if default and filtering.startswith("ufw"):
        filtering += f", default incoming {tpl.mono(default)}"
    version = doc.get("agent_version")
    agent = ("The agent, inside",
             f"reported {age_text(received_at, now)} ago" if received_at else "",
             [("reads", f"{tpl.mono('netlink')} and {tpl.mono('/proc')}, no exec"),
              ("saw", saw), ("filtering", filtering),
              ("version", tpl.mono(version) if isinstance(version, str) and version else "&mdash;")],
             False)
    measured = [f for f in findings if f.outside.measured]
    age = probe_age(findings, now)
    tested = {fam: sum(1 for f in measured if f.family == fam) for fam in ("v4", "v6")}
    prober = ("The prober, outside", f"probed {age} ago" if age else "never probed",
              [("reads", "TCP connect, no version detection"),
               ("from", tpl.prober_from_html()),
               ("tested", f"{tpl.mono(tested['v4'])} ports on v4, {tpl.mono(tested['v6'])} on v6"),
               ("vantages", vantages_line(vantages, findings))],
              False)
    matched = next((f.provider for f in findings if f.provider.matched), None)
    configured = any(f.provider.configured for f in findings)
    if matched:
        # The server, and how many rules its firewalls hold: the number the
        # Rules tab lists. It was the count of the rules that matched a port
        # with a finding, called inbound (docs/RECORD.md 4.395). A count the
        # page does not have is left out, never guessed.
        saw = tpl.mono(matched.server_name or "")
        if provider_rules is not None:
            saw += (f" with {tpl.mono(provider_rules)} "
                    f"{'rule' if provider_rules == 1 else 'rules'}")
        provider = ("The provider", "connected",
                    [("reads", "the firewall and the server list, read only"),
                     ("saw", saw),
                     ("account", tpl.mono(matched.provider))], False)
    elif configured:
        provider = ("The provider", "connected", [("saw", "no match")], False)
    else:
        provider = ("The provider", tpl.NOT_CONNECTED, [], True)
    return [agent, prober, provider]


def section_chips(doc):
    """The document's sections for the strip: (label, tone, suffix). A
    refused read is amber and says so, whether the section or one of its
    sources was refused (refused_reads, docs/RECORD.md 4.72)."""
    refused = {key for key, _sources in refused_reads(doc)}
    chips = []
    for key, label in SECTION_LABELS:
        status = pp._mapping(doc.get(key)).get("status")
        tone, word = SECTION_TONES.get(status, ("off", "not collected"))
        if key in refused or status == "permission_denied":
            chips.append((label, "warn", "refused"))
        elif tone == "fail":
            chips.append((label, "fail", word))
        elif tone == "ok":
            chips.append((label, "", ""))
        # A section the agent did not read is left out, as the owner asked on
        # 2026-09-08. Refused stays, because
        # a read that was refused is a fact and not an absence.
    return chips


def evidence_tab_body(slug, doc, rows, findings, received_at, now, agentless=False,
                      vantages=(), provider=None):
    """The tab. An address host has no document, so no section strip. `slug`
    is the server's name, which is what the provider is asked about."""
    return tpl.evidence_tab_html(slug, evidence_screen_rows(slug, rows, findings,
                                                           unread=sockets_not_read(doc)),
                                 evidence_cards(doc, received_at, findings, now, agentless,
                                                vantages=vantages,
                                                provider_rules=provider_rule_count(provider, slug)),
                                 None if agentless else section_chips(doc), True)


def evidence_matrix_rows(doc, findings=()):
    """One row per port and address family, and what each of the three views
    says about it. `findings` is the joined result from
    `controlplane/app/join.py`, through `site/app/joinbridge.py`.

    **A port the prober did not measure says `not tested` and never inherits a
    neighbour's answer** (`docs/PRODUCT.md` 4b and 8b). That is not a rule this
    function applies, it is the engine's own: the outside view carries one state
    per port per family and `not tested` is one of the four. Every UDP port
    reads `not tested` for the same honest reason, because the prober is a TCP
    connect prober.

    The Together column is the finding's state, and an empty one prints
    `no state`. `docs/PRODUCT.md` 8a: a port whose evidence supports none of
    the five has no state, not a sixth word and not a default.

    `doc` is no longer read. It stays in the signature because the caller has
    it and a later column may want it, and because dropping an argument is a
    change to every caller for no gain today.

    This used to walk the document's listening sockets and hardcode the last
    three columns. It also read `sock.get("address")`, and the agent writes
    that field as `bind_address`, so every row on every host said `v4` and no
    row ever said `loopback`. Driving it from findings ends that by
    construction: the family on a finding is the family the engine decided.
    """
    rows = []
    for finding in findings:
        rows.append((
            f"{finding.protocol}/{finding.port}",
            finding.family,
            _agent_token(finding.inside),
            finding.outside.word,
            _provider_token(finding.provider),
            finding.state or "",
            # A flag beside the state, per family, never a sixth state
            # (docs/DESIGN.md section 3, docs/RECORD.md 4.79 and 4.81). The
            # engine has already made this family-correct, so a v4-pinned rule
            # never lights the v6 row.
            finding.rate_limited))
    rows.sort(key=lambda r: (r[0].split("/")[0],
                             int(r[0].split("/")[1]) if r[0].split("/")[1].isdigit() else 0,
                             r[1]))
    return rows


# Units the kernel names that are not the service on the port. docker.service
# holds every Docker-published port, and the container is named from the
# containers section; a .scope is a login session, or the session a rootless
# container runs in; a .slice is a group of units. Each is carried under the
# row as what the kernel said, never as the row's name (docs/PRODUCT.md, the
# sockets section; docs/AGENT-PRIVILEGE.md 4a).
NOT_A_SERVICE_UNIT = ("docker.service",)


def unit_names_the_service(unit):
    """Whether the unit the kernel named is the thing serving the port: a
    .service or a .socket, and not docker's."""
    if not isinstance(unit, str) or not unit or unit in NOT_A_SERVICE_UNIT:
        return False
    return unit.endswith((".service", ".socket"))


def socket_holder(s):
    """Who a socket row names, for the Services tab and the Overview.

    The process name when the agent measured one. Without it, the systemd
    unit the kernel named for the socket, when that unit is the service: the
    name without its suffix, so caddy.service names the row "caddy" the way
    a socket unit's row is named by its service (docs/PRODUCT.md, the
    sockets section, since 2026-09-12). Without either, the owning user as
    the socket's uid names it: the passwd file's word for the uid when the
    document carries one, the bare uid otherwise. Both are labelled "user"
    or "uid" so they never read as a process name, because the uid is who
    owns the socket and not what is serving it. With none of them, what was
    always shown: an unknown process. Nothing is guessed at any step: a
    kernel before 5.8 or a host without cgroup v2 names no unit, and the
    row then says the user, honestly.
    """
    if s.get("process_name"):
        return s["process_name"]
    unit = s.get("unit")
    if unit_names_the_service(unit):
        return unit.rsplit(".", 1)[0]
    if s.get("owner_name"):
        return f'user {s["owner_name"]}'
    if s.get("owner_uid") is not None:
        return f'uid {s["owner_uid"]}'
    return "unknown process"


def socket_fact(s):
    """The mono line under a socket's name on the Services tab: the unit the
    kernel named, as it named it, whether or not it is the service, else the
    pid, else nothing (docs/screens/host-services/SPEC.md, the What runs
    column). docker.service and a .scope sit here and never in the name."""
    unit = s.get("unit")
    if isinstance(unit, str) and unit:
        return unit
    return f'pid {s["pid"]}' if s.get("pid") else ""


def path_cached(doc, protocol, port, family, cache):
    """`pp.path_for`, memoised for the length of one host page.

    The Overview, the Services tab and the Packet path tab all ask the same
    question of the same ports, and a host with seventeen sockets would
    otherwise walk the whole ruleset once per tab per family. One dict shared
    across the page walks it once, which is also what stops the three tabs being
    able to disagree about a port.
    """
    key = (protocol, port, family)
    if key not in cache:
        cache[key] = pp.path_for(doc, protocol, port, family)
    return cache[key]


def path_counts(path):
    """(base chains, rules that name this port, rules not fully readable) for
    one walked path. Counting in one place, because three screens print these
    numbers and two of them printing a different total would be a real bug."""
    chains = named = unreadable = 0
    for stage in path["stages"]:
        for group in stage["groups"]:
            for entry in group["entries"]:
                chains += 1
                named += entry["counts"][pp.NAMES_PORT]
                unreadable += entry["counts"][pp.UNREADABLE]
    return chains, named, unreadable


def family_summary(doc, protocol, port, family, cache):
    """One address family's line: how many base chains evaluate this port and
    how many rules name it. Empty when no base chain was read for it.

    It says nothing about reachability. A chain evaluating a packet is not a
    chain permitting one, and the rules are on the other tab to be read.
    """
    chains, named, _unreadable = path_counts(path_cached(doc, protocol, port, family, cache))
    if not chains:
        return ""
    # **The chain count left on 2026-08-29.** It counted the base chains our
    # own walk crossed, which is our machinery rather than a fact about the
    # port, and on a real host it read the same on every row,
    # so it separated no two rows on the screen it was drawn on.
    #
    # `none` and not `no rule`, deliberately. `packetpath.base_chains` walks
    # nftables only, so a legacy x_tables rule can never be shown as naming a
    # port. The word counts what this column shows and claims nothing about
    # the host beyond it.
    return n_of(named, "rule") if named else "none"


def is_loopback(address):
    """True for an address the kernel serves only on `lo`."""
    text = str(address or "").strip()
    if not text:
        return False
    # A scope suffix is how the kernel writes a zone, `fe80::1%eth0`, and ss
    # prints one for the resolved stub as `127.0.0.53%lo`. It names a device
    # and never changes which address this is.
    text = text.split("%", 1)[0]
    try:
        return ipaddress.ip_address(text).is_loopback
    except ValueError:
        return False

# The provenance every declared name carries on this page, in one spelling so
# the screens cannot drift into several. A declared name is a thing the
# operator typed, so it always prints beside these words and the measured
# process name, when the document has one, stays on the same row. A
# declaration never hides a measurement. The spelling lives in build.py, where
# the Services tab draws it too.
NAMED_BY_YOU = tpl.NAMED_BY_YOU

# The same idea for the other kind of name on these screens: one a *.socket
# file on the host declares. It is read out of a file, so it is a declaration
# and not a measurement, and it prints beside these words for the same reason
# the operator's own name does. The socket unit is named after them, so a
# reader can open the file the name came from.
DECLARED_BY = "declared by"

FAMILIES = ("v4", "v6")


def join_and(items):
    """A list as a person reads it out: "a", "a and b", "a, b and c"."""
    items = list(items)
    if len(items) <= 1:
        return items[0] if items else ""
    return ", ".join(items[:-1]) + " and " + items[-1]


# Which transport each Listen directive carries. systemd.socket(5), quoted in
# the agent's schema: "For IP sockets the first is TCP and the second UDP".
# Every other Listen* directive is a FIFO, a netlink socket or a message queue,
# so none of them is a port this page can match onto a measured socket.
LISTEN_PROTOCOL = {"ListenStream": "tcp", "ListenDatagram": "udp"}

# The listen kinds that carried a TCP or UDP port. The agent's other kinds are
# a unix path, an abstract unix name, a vsock, an unexpanded "%i" and a value
# it did not recognise, and reading a port out of any of those would be
# inventing one.
LISTEN_PORT_KINDS = ("port_only", "ipv4", "ipv6")


def socket_unit_names(doc):
    """The service unit each declared port belongs to: (protocol, port) mapped
    to (service unit, the *.socket file that declared it).

    The agent collects this because a socket-activated port has no useful
    owning process: systemd holds the listening socket, so /proc attributes the
    port to systemd, and an unprivileged agent reads no process name at all
    (agent/internal/collect/socketunits.go). The unit file names the service.

    **This is a declaration and it raises no row on its own.** Every caller
    joins it onto a socket the agent measured, so a unit file naming a port
    nothing is listening on puts nothing on any screen.

    A port two different service units declare is left out. Which of them
    systemd loads follows from the unit load path, and picking one here would
    be a guess printed as a name. The same unit found in two directories claims
    one service, so that common case still gets its name.
    """
    claims = {}
    for unit in pp._dicts(pp._mapping(doc.get("socket_units")).get("units")):
        # A masked unit is not loaded at all, a template is the pattern
        # instances are made from rather than a listener, and an alias is a
        # second name for a unit that is already in this list.
        if unit.get("masked") or unit.get("template") or unit.get("alias_of"):
            continue
        service = str(unit.get("service_unit") or "")
        if not service:
            continue
        for listen in pp._dicts(unit.get("listen")):
            protocol = LISTEN_PROTOCOL.get(listen.get("directive"))
            port = listen.get("port")
            # bool is a subclass of int in Python and is not a port.
            if not protocol or not isinstance(port, int) or isinstance(port, bool):
                continue
            if port <= 0 or listen.get("kind") not in LISTEN_PORT_KINDS:
                continue
            claims.setdefault((protocol, port), {})[service] = str(unit.get("name") or "")
    named = {}
    for key, services in claims.items():
        if len(services) == 1:
            service, unit_file = next(iter(services.items()))
            named[key] = (service, unit_file)
    return named


def enabled_socket_unit_files(doc):
    """The *.socket files something enabled: the agent found a link to each
    in a .wants or .requires directory (`enable_links`), which is how
    systemd records that a unit was asked for (systemd.unit(5))."""
    return {str(unit.get("name") or "")
            for unit in pp._dicts(pp._mapping(doc.get("socket_units")).get("units"))
            if isinstance(unit.get("enable_links"), list) and unit.get("enable_links")}


def socket_is_units_own(s, unit_file, enabled=True):
    """Whether a *.socket file's declaration may name this measured socket.

    The kernel says whose a listening socket is. One systemd holds for a
    socket unit is reported under that socket unit, and one a running service
    opened itself is reported under the service (measured on three
    distributions, docs/RECORD.md 4.326). So a file declaring port 22 names
    nothing while the kernel gives the socket on 22 to sshd.service: that
    socket unit holds no socket. The file was joined on by port alone, and
    sshd read as a socket unit on three distributions (docs/RECORD.md 4.213,
    4.220).

    Where the kernel named no unit, a kernel before 5.8 or a host without
    cgroup v2, the file is all there is. It names the row only when
    something `enabled` it, and the row says which file the name came from.
    A file nothing enabled named 22 "sshd@" on Rocky Linux 8, where
    sshd.socket was disabled and sshd.service held the port (the second big
    test, 2026-10-25, case C8). What the kernel says is not changed by it.
    """
    unit = s.get("unit")
    if not isinstance(unit, str) or not unit:
        return bool(enabled)
    return unit == unit_file


def unit_declared_for(units, key, sockets, enabled=frozenset()):
    """The (service unit, *.socket file) `socket_unit_names` found for this
    port, when the file may name every one of these sockets, else None. One
    question for the Services tab, which asks it a socket at a time, and the
    Overview, which asks it for all of a port's sockets at once. `enabled`
    is `enabled_socket_unit_files` of the same document."""
    unit = units.get(key)
    if unit and all(socket_is_units_own(s, unit[1], unit[1] in enabled) for s in sockets):
        return unit
    return None


def port_naming(sockets, declared=None, unit=None):
    """What one port's row is called, and the provenance line beside it.

    One function, because the Overview and the Services tab answer this same
    question about the same sockets and used to answer it apart: the Overview
    read `process_name` and printed "unknown process" where the Services tab
    printed the socket's owning user for the very same socket.

    `declared` is the operator's own name for the port and `unit` is what
    `socket_unit_names` found for it. Both are declarations, so both print
    their provenance, and the operator's own name wins because it is the one a
    person on this workspace typed about this host.

    The measured process name stays on the row beside either of them. A
    declaration never hides a measurement.
    """
    if declared:
        name, provenance = declared, NAMED_BY_YOU
    elif unit:
        service, unit_file = unit
        name, provenance = service, f"{DECLARED_BY} {unit_file}"
    else:
        # Nothing declared, so the row is what the agent measured: the process
        # name, or the socket's owning user, or that there was neither.
        return join_and(list(dict.fromkeys(socket_holder(s) for s in sockets))), ""
    measured = list(dict.fromkeys(
        s.get("process_name") for s in sockets if s.get("process_name")))
    if measured:
        provenance += f" · process {join_and(measured)}"
    return name, provenance


def bind_line(sockets):
    """The families one service is bound on, and the addresses behind them.

    The family is the socket's own family field, never read off the shape of
    the address, and one family's answer is never taken from the other
    (PRODUCT.md 4b).
    """
    families = [f for f in FAMILIES if any(s.get("family") == f for s in sockets)]
    # A family the agent reported that this page does not know about is named
    # rather than dropped, because a socket vanishing off a row is the one
    # thing this list must never do.
    families += sorted({str(s.get("family")) for s in sockets
                        if s.get("family") and s.get("family") not in FAMILIES})
    addrs = []
    for s in sockets:
        addr = str(s.get("bind_address", ""))
        if addr and addr not in addrs:
            addrs.append(addr)
    line = join_and(families) if families else "family not reported"
    if addrs:
        line += f", bound to {join_and(addrs)}"
        if all(is_loopback(a) for a in addrs):
            line += ", loopback only"
    return line


def _worst_word(words):
    """The worst state among a thing's ports by STATE_SEVERITY, as (tone,
    word), or ("", "") when none of them has a state."""
    present = {w for w in words if w}
    word = next((w for w in STATE_SEVERITY if w in present), "")
    return (tpl.PORT_TONE.get(word, "off"), word) if word else ("", "")


def _addresses(sockets):
    """The distinct bind addresses of some sockets, in the document's order."""
    return ", ".join(dict.fromkeys(str(s.get("bind_address", "")) for s in sockets
                                   if s.get("bind_address")))


def _thing_row(name, slug, name_fact, sockets, states, declared):
    """One ServiceRow for the sockets of one thing that runs. Its ports are
    one chip each, worst state first, the row's state the worst of them."""
    keys = list(dict.fromkeys((s.get("protocol"), s.get("port")) for s in sockets))
    order = {w: i for i, w in enumerate(STATE_SEVERITY)}
    # worst state first, then by number, the Overview's own order
    keys.sort(key=lambda k: (order.get(states.get(k, ""), len(order)), k[1] or 0))
    words = [states.get(k, "") for k in keys]
    chips = [(f"{port}/{protocol}", tpl.PORT_TONE.get(word, "") if word else "",
              tpl.row_id(slug, protocol, port))
             for (protocol, port), word in zip(keys, words)]
    tone, word = _worst_word(words)
    # A name the operator gave one of these ports sits beside the measured
    # name, never in its place (the owner's delegated call, 2026-09-13,
    # docs/RECORD.md 4.174).
    given = join_and(list(dict.fromkeys(declared[k] for k in keys if declared.get(k))))
    return tpl.ServiceRow(tone, word, name, name_fact, tuple(chips), _addresses(sockets),
                          declared=given)


def thing_key(s):
    """What makes two sockets one row on the Services tab: the same name, the
    same fact under it, and for a socket only its owner names, the same port.

    Where the agent read no process name and no pid and the kernel named no
    service unit, a kernel before 5.8 for one, the row's name is the socket's
    owner and there is nothing under it. An owner is not a thing that runs:
    sshd, a second listener and a loopback service were all root's, and read
    as one row bound to every address the three held (docs/RECORD.md 4.220).
    Nothing in such a document says two ports are one program, so those
    sockets are one row a port, which is the Overview's own row. Anything
    that does say it keeps them together: a process name, a pid, a unit.
    """
    holder, fact = socket_holder(s), socket_fact(s)
    named = bool(s.get("process_name")) or unit_names_the_service(s.get("unit"))
    port = None if named or fact else (s.get("protocol"), s.get("port"))
    return holder, fact, port


def service_groups(slug, doc, rows, names=None):
    """The Services tab's groups: [(title, grey word, [ServiceRow], unsure)]
    in the spec's order (docs/screens/host-services/SPEC.md). `rows` is the
    Overview's PortRow list, which is where every port's state comes from,
    so the two tabs cannot disagree about one port."""
    states = {(r.protocol, r.port): r.word for r in rows}
    declared = dict(names or {})
    groups = []
    # Containers: one row per container that publishes a port, its image
    # under the name, the host addresses it is published on. The host
    # sockets the runtime holds for those ports are the container's and are
    # not listed again as processes.
    published = set()
    containers = doc.get("containers") or {}
    for runtime in ("docker", "podman"):
        items = []
        for c in pp._dicts(containers.get(runtime)):
            ports = pp._dicts(c.get("ports"))
            if not ports:
                continue
            name = c.get("name") or str(c.get("id", ""))[:12]
            sockets = [{"protocol": p.get("protocol"), "port": p.get("host_port"),
                        "bind_address": p.get("host_ip")} for p in ports]
            published.update((p.get("protocol"), p.get("host_port")) for p in ports)
            items.append(_thing_row(name, slug, str(c.get("image") or ""), sockets, states, declared))
        if items:
            groups.append(("Containers", runtime, items, ""))
    listening = [s for s in pp._dicts(pp._mapping(doc.get("sockets")).get("listening"))
                 if (s.get("protocol"), s.get("port")) not in published]
    # Socket units: the sockets a unit file declares and the kernel does not
    # give to another unit, one row per service unit, the .socket file under
    # the name.
    units, enabled = socket_unit_names(doc), enabled_socket_unit_files(doc)
    by_unit, rest = {}, []
    for s in listening:
        unit = unit_declared_for(units, (s.get("protocol"), s.get("port")), [s], enabled)
        if unit:
            by_unit.setdefault(unit, []).append(s)
        else:
            rest.append(s)
    unit_rows = [_thing_row(service[:-len(".service")] if service.endswith(".service") else service,
                            slug, unit_file, sockets, states, declared)
                 for (service, unit_file), sockets in by_unit.items()]
    # Processes and loopback only: the rest, one row per thing, keyed by
    # what the agent could attribute the socket to and the fact under it,
    # the unit the kernel named or the pid. Two sockets of one unit are one
    # row, and two root-owned sockets of two units are two, which the pid
    # alone could not tell apart on a host whose agent reads no pids.
    by_thing = {}
    for s in rest:
        by_thing.setdefault(thing_key(s), []).append(s)
    processes, loopback = [], []
    for (holder, fact, _port), sockets in by_thing.items():
        row = _thing_row(holder, slug, fact, sockets, states, declared)
        addrs = [str(s.get("bind_address", "")) for s in sockets]
        (loopback if addrs and all(is_loopback(a) for a in addrs) else processes).append(row)
    groups.append(("Socket units", "systemd", unit_rows, ""))
    groups.append(("Processes", "", processes, ""))
    groups.append(("Loopback only", "", loopback, ""))
    # The overlay interfaces were a fifth group under a marker asking where
    # they belong, since the spec has four. The owner's answer, 2026-09-10: the
    # overlays can go. The Evidence tab still names the section.
    return groups


def services_tab_body(slug, doc, rows, names=None):
    empty = (tpl.SOCKETS_UNREADABLE
             if pp._mapping(doc.get("sockets")).get("status") == NOT_READABLE
             else tpl.NOTHING_LISTENING)
    return tpl.services_table_html(slug, service_groups(slug, doc, rows, names), empty)


# ---------------------------------------------------------------- overview
#
# The tab a host page opens on. Everything on it is the short form of another
# tab and links to that tab rather than repeating it, so the first screen
# answers what is on an interface and which layers evaluate it, and the long
# reading stays one click away.

NO_HOLDER = "nothing on this host is listening"


def document_ports(doc):
    """Every (protocol, port) the document reports a socket or a container
    publication for, loopback included.

    **Loopback included is the point.** The old Overview dropped a port whose
    every bind is loopback, because the Overview is the ports bound to a
    network address and the Services tab holds the rest. So "not in entries"
    is not the same question as "the document says nothing about it", and
    asking the first one put `tcp/53` from a resolver stub back on the network
    panel the moment findings could add rows. The suite caught it.
    """
    # A socket or a publication without an integer port and a protocol is not
    # a port, and it is left out here the way `packetpath.traced_ports` leaves
    # it out. Until 2026-09-14 an empty entry made a row whose port was None,
    # and the sort under `host_port_rows` raised on it, which took the whole
    # host page down (test_malformed_documents.py).
    keys = set()
    for s in pp._dicts(pp._mapping(doc.get("sockets")).get("listening")):
        if isinstance(s.get("port"), int) and isinstance(s.get("protocol"), str) and s["protocol"]:
            keys.add((s["protocol"], s["port"]))
    containers = pp._mapping(doc.get("containers"))
    for runtime in ("docker", "podman"):
        for c in pp._dicts(containers.get(runtime)):
            for p in pp._dicts(c.get("ports")):
                if isinstance(p.get("host_port"), int) and isinstance(p.get("protocol"), str) and p["protocol"]:
                    keys.add((p["protocol"], p["host_port"]))
    return keys


def fact_rows(rows):
    """Left column, sentence, nothing on the right. The plainest shape a panel
    has, and the one the overview is built from."""
    return "".join(tpl.three_cell_row(tpl.esc(left), tpl.esc(right), "",
                                      first_cls="d", middle_cls="", last_cls="")
                   for left, right in rows)


# One sentence for one fact. The Overview and the Packet path tab both report a
# family with nothing to walk, and two phrasings of the same finding is the
# drift that one owner per fact exists to stop.
#
# It used to end ", and nothing here infers one family from the other". That is
# our own reasoning about our own restraint rather than anything measured, and it
# went on 2026-08-16. What is left is the measurement.
NO_FAMILY = "no listening socket was reported for this port in this family"


# The three answers a port row offers, in the order the row offers them. ""
# is no declaration at all, which is what `clear` puts back. The two words are
# `controlplane/app/intent.py`'s and `site/app/build.py` spells them the same
# way on the control itself.
IF_DECLARED = ("open", "closed", "")


def worst_state(states):
    """The one word a row shows for a set of per-family states.

    **The worse of the two families wins**, in `STATE_SEVERITY` order, which is
    the rule the fleet strip uses and the order `docs/DESIGN.md` section 3
    lists. Showing the calmer one would hide a conflict on v6 behind an
    intended on v4. Empty when no family carries a state.
    """
    return next((word for word in STATE_SEVERITY if word in states), "")


# The states that ask the person for something. On a port's row these are
# never hidden behind a calmer family.
ASKING_STATES = ("conflict", "unreviewed", "unexplained")


def port_row_word(states, answered):
    """(the word, the family it comes from) for one port's row.

    `states` is {family: state} for the families that carry one, and
    `answered` is {family: whether the prober connected on it}.

    **The worse family wins while one of them asks for something**, in
    `STATE_SEVERITY` order, exactly as before: a conflict on v6 is never
    hidden behind an intended on v4.

    **Where neither asks, a family that answered from outside leads over one
    that did not** (`docs/RECORD.md` 4.244, a stated exception to the one
    ranking in `docs/DESIGN.md` section 3, for a port's row only). The two
    quiet states, `stale rule` and `not reachable`, rank above `intended` in
    the fleet's order, so a port open to every IPv4 address and silent on
    IPv6 used to read `NOT REACHABLE`, name "nothing bound on v6" as its
    service and say it "became not reachable" (4.237), and a web server with
    a listener on v4 alone read `STALE RULE` (4.203). The other family keeps
    its own mark beside the word.
    """
    word = worst_state({state: True for state in states.values()})
    if word and word not in ASKING_STATES:
        for family in FAMILY_ORDER:
            if family in states and answered.get(family):
                return states[family], family
    lead = next((family for family in FAMILY_ORDER if states.get(family) == word), None)
    return word, lead


def port_state_cells(findings):
    """The joined findings for one host, keyed (protocol, port), as the three
    cells a port row needs: the state word, what each family answered, and
    which layer decided.

    A finding is per address family and the row is per port, so the two have to
    be reconciled. **The worse of the two families wins the word**, in
    `STATE_SEVERITY` order, which is the same rule the fleet strip uses and the
    same order `docs/DESIGN.md` section 3 lists. Showing the calmer one would
    hide a conflict on v6 behind an intended on v4.

    The layer comes from the finding that carries the shown word, so the word
    and the reason on one row are about the same family rather than averaged
    across both.
    """
    join = joinbridge.load()
    cells = {}
    for finding in findings:
        key = (finding.protocol, finding.port)
        cell = cells.setdefault(key,
                                {"states": {}, "v4": None, "v6": None,
                                 "rate_limited": False, "reviewed": {},
                                 "if": {word: {} for word in IF_DECLARED}})
        cell[finding.family] = finding.outside
        # What this port would carry under each of the three answers the row
        # offers, reconciled across the families exactly as the shown word is.
        # The engine answers it (`join.state_if_declared`), because deriving it
        # from the state and the outside word here would be a second copy of
        # rules that live in one place.
        for word in IF_DECLARED:
            would = join.state_if_declared(finding, word or None)
            if would:
                cell["if"][word][would] = True
        if finding.state:
            cell["states"].setdefault(finding.state, finding.cause)
            # Kept per family, because that is how an acknowledgement is
            # stored and how it lapses. Only a family that has a state can
            # carry one, so this map is also the set of families the row's
            # review control acts on.
            cell["reviewed"][finding.family] = bool(finding.acknowledged)
        # The row is per port and the flag is per family, so the port carries it
        # when either family does. A rule pinned to one family is already only
        # on that family's finding (docs/RECORD.md 4.79), so this never invents
        # a rate limit the engine did not measure.
        if finding.rate_limited:
            cell["rate_limited"] = True
    return cells


def port_row_state(cell):
    """(word, tone, layer) for one port's cell, or ("", "", "") where the three
    views support none of the five states.

    `docs/PRODUCT.md` 8a: a port whose evidence supports none of them has no
    state at all, and this returns nothing rather than a sixth word. The layer
    is dropped when the engine did not determine one, because "not determined"
    in a Why column is a cell that costs a line and says nothing.
    """
    states = cell.get("states") or {}
    word = worst_state(states)
    if not word:
        return "", "", ""
    layer = states[word].layer
    # The sentence is drawn when a filter decided, with its rule quoted under
    # it. "the service decided" went on 2026-08-29: it appeared on every
    # reachable row, so it separated no two rows on the screen it was drawn
    # on, which is 4.128's definition of junk. The state word and the bind
    # line already carry what it said.
    return word, tpl.PORT_TONE.get(word, "off"), (
        "" if layer in (LAYER_NOT_DETERMINED, LAYER_SERVICE)
        else f"the {layer} decided")


# How many rules one port row quotes before it stops, and the shape of the
# line that says it stopped. A `stale rule` on a host with a permit in
# firewalld and another in nftables and another at the provider is three
# quotes, and a row that grew to five lines would push the next port off the
# screen. It is capped rather than cut: a row that quietly stops quoting is a
# row that says one rule decided when three did.
PORT_QUOTE_CAP = 2


def port_row_quotes(cell):
    """(the rules this port's state was decided from, how many were left out).

    **The engine has computed these since the join engine landed and no screen
    has ever drawn them** (`docs/RECORD.md` 4.117). `Cause.quotes` is what
    `docs/PRODUCT.md` section 3 means by "name the layer and quote the rule",
    and until now the layer was named on the row and the rule was readable
    only through `python -m app.join_cli findings` on the box.

    Each entry is (text, source), both the engine's own strings. A rule is
    quoted verbatim because the agent already rendered it in the syntax the
    host itself uses (`docs/PRODUCT.md` 4e principle 5), so this may never
    paraphrase one.

    **Quotes from the service layer are left out here and only here.** They
    are the listening sockets, which this row already shows twice: the process
    in the Port cell and the bind address in the line below this one. Printing
    "sshd on 0.0.0.0" a third time would be the row repeating itself rather
    than adding the evidence a reader came for.
    """
    states = cell.get("states") or {}
    word = next((w for w in STATE_SEVERITY if w in states), "")
    if not word:
        return (), 0
    quotes = [q for q in states[word].quotes if q.layer != LAYER_SERVICE]
    shown = [(q.text, q.source) for q in quotes[:PORT_QUOTE_CAP]]
    return tuple(shown), max(0, len(quotes) - PORT_QUOTE_CAP)


def port_row_review(cell):
    """(the families this row can be reviewed on, whether every one of them is).

    The families are the ones carrying a state. `docs/PRODUCT.md` 8a: a port
    whose evidence supports none of the five has no state, so it has no finding
    to acknowledge and the pair comes back empty and False.

    Reviewed is all of them or none of them, because the row shows one word for
    the port. A mark on a row where only v4 was acknowledged would say more
    than was done.
    """
    reviewed = cell.get("reviewed") or {}
    families = sorted(reviewed)
    return families, bool(families) and all(reviewed[f] for f in families)


# The engine's own word for a cause it could not attribute. Read from the
# engine rather than spelled again here, so a rename there cannot leave this
# module quietly printing "the not determined decided" on every row.
LAYER_NOT_DETERMINED = "not determined"

# The layer whose quotes this row leaves out, because it already shows them.
# Spelled here and pinned equal to the engine's own constant by
# `test_the_layer_words_match_the_engine`, which is what stops a rename there
# from leaving this module silently quoting the listening socket twice.
LAYER_SERVICE = "service"


def port_row_if_declared(cell):
    """What this row's State cell would say under each of the three answers.

    Keyed the way the control reads them: `open`, `closed`, and "" for no
    declaration at all. Reconciled across the address families by the same
    rule the shown word uses, so the answer the click paints is the answer the
    next render produces.

    Every value is empty for a port whose evidence supports no state, which is
    `docs/PRODUCT.md` 8a and is most ports today. The row still offers the
    control, because declaring is also what puts a port on the probe plan.
    """
    would = cell.get("if") or {}
    return {word: worst_state(would.get(word) or {}) for word in IF_DECLARED}


# ------------------------------------------------------------ the Host Overview
#
# docs/screens/host-overview/SPEC.md, decided 2026-09-04. Every value here is
# read off the joined findings and the document; nothing is a sentence about
# our own machinery, and a cell the evidence cannot fill holds nothing.

# What the From outside mark of one family reads, from that family's state.
# Green when what the prober found agrees with what you say, red when it
# disagrees, amber when it answers and you have not said, and nothing when
# nobody looked. A measured silence nobody answered for is green: it is never
# drawn like a family nobody probed (docs/DESIGN.md section 3).
MARK_TONE = {"conflict": "fail", "unreviewed": "warn", "unexplained": "warn",
             "intended": "ok", "not reachable": "ok"}

# The states the Needs a decision box counts on a server. A conflict is not
# among them: it colours the box red instead (SPEC.md section 4).
# `stale rule` left on 2026-09-21: shown on its row, owed by nobody
# (docs/RECORD.md 4.198).
DECISION_WORDS = ("unreviewed", "unexplained")

def _permitted(finding):
    """Whether a rule you wrote permits this port in this family: the
    engine's own list, the same one 8d reads."""
    inside = finding.inside
    return bool(finding.provider.rules) or bool(
        inside.permit_rules if inside.nftables_status == "collected" else ())


def _denied(finding):
    """Whether a rule you wrote names this port in this family and turns the
    packet away: the engine's own list (`InsideView.deny_rules`)."""
    inside = finding.inside
    return bool(inside.deny_rules if inside.nftables_status == "collected" else ())


def _sockets_for(doc, protocol, port):
    return [s for s in pp._dicts(pp._mapping(doc.get("sockets")).get("listening"))
            if s.get("protocol") == protocol and s.get("port") == port]


def _ufw_default(doc):
    """ufw's default for incoming in ufw's own word, or "" when the document
    carries none. It was looked for under `conf`, which is ufw.conf and holds
    no policy, so a real server's card never said it (docs/RECORD.md 4.443)."""
    return dict(ufw_defaults(doc.get("ufw"))).get("incoming", "")


def _time_ago(value, now):
    then = received_at_or_none(value)
    return age_text(then, now) if then else ""


def probe_age(findings, now):
    """How long ago the prober last measured this server, or "" when never."""
    measured = [f.outside.measured_at for f in findings
                if f.outside.measured and f.outside.measured_at]
    if not measured:
        return ""
    return _time_ago(max(measured), now)


def _address_and_port(address, port):
    """An address and a port as one string, the IPv6 address in brackets
    (RFC 3986 section 3.2.2), so `::` and port 443 read `[::]:443` and not
    `:::443`, where the reader has to count colons to find the port."""
    if not address:
        return str(port)
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


# What a card and a row say of a port the engine marks
# `answered_outside_the_rules_source`. The lead says the host's rule permits
# less than what answered: a prober outside the rule's source connected.
# Decided by says why nothing decided: the provider's rule permits everyone
# and the host's permits one source. Neither says anything of the path a
# packet took. Picked on sight of both pairs drawn (docs/RECORD.md 4.375).
ANSWERED_OUTSIDE_LEAD = "reachable, your firewall rule permits less"
ANSWERED_OUTSIDE_DECIDED = "your rules differ"

# The words where nothing inside accounts for a port: the Decided by cell of
# an `unexplained` port, the firewall line of a card on a server without an
# agent, and the source under the port's row in the first-look window. One
# constant since 2026-10-11 so the three cannot drift (docs/record 4.451).
# They read "no view from inside", which claimed no view where an agent had
# looked and seen nothing bound.
NOT_SEEN_INSIDE = "not seen inside"


def _only_unreadable_rules(inside, legacy=0):
    """Whether no readable rule names this port and some rule on its path
    could not be fully read, so "no rule" would be a claim nobody read.
    `legacy` is how many legacy iptables rules this family has, which are
    never placed on a port at all (`legacy_rules_of_family`)."""
    return bool(inside.unreadable_rule_count or legacy) and not inside.permit_rules \
        and not inside.narrowed_rules


# Which legacy x_tables section holds each address family's rules.
LEGACY_TABLES_OF_FAMILY = {"v4": "iptables", "v6": "ip6tables"}


def legacy_rules_of_family(doc, family):
    """How many legacy iptables rules stand for one address family:
    iptables' for v4, ip6tables' for v6.

    The agent stores a legacy rule by its match names, so the page counts
    them and never places one on a port (`site/app/packetpath.py`). Any of
    them may name the port. Beside them the card said "no rule names 22"
    on a Debian 12 server whose legacy INPUT chain accepted 22 (the second
    big test, 2026-10-25, case C5).
    """
    section = pp._mapping((doc or {}).get(LEGACY_TABLES_OF_FAMILY.get(family, "")))
    return sum(len(pp._dicts(chain.get("rules")))
               for table in pp._dicts(section.get("tables"))
               for chain in pp._dicts(table.get("chains")))


def _provider_line(view, port):
    """What a card's provider line says, from the engine's view of the
    provider for one port and family."""
    if not view.configured:
        return "not connected"
    if not view.matched:
        return "server not found"
    if view.rules:
        return tpl.mono(view.rules[0].text)
    return f"no rule names {tpl.mono(port)}"


def _measured_word(state):
    """What one measurement found, in the card's words."""
    prober_mod = joinbridge.module("prober")
    if state == prober_mod.STATE_CONNECTED:
        return "connected"
    if state == prober_mod.STATE_REFUSED:
        return "refused"
    return "no answer"


def _prober_line(outside, now):
    """A card's prober line: what was found, from which vantage, how long ago.

    Every vantage that measured the port is named, with its own result and
    its own time (docs/RECORD.md 4.395). The line named the one vantage whose
    measurement the engine's answer was taken from, so beside an Evidence tab
    listing two vantages the other read as one that measured nothing.

    - One time for all where every vantage's time reads the same, and a time
      beside each name where they differ. A time on the line is always that
      vantage's own.
    - One result for all where they found the same, and a result before each
      name where they did not. The state and the card's first line stay the
      engine's: this line says what each vantage found and concludes nothing.

    A vantage with two measurements, a server probed on two addresses of one
    family, keeps the engine's one resolved answer as before: which of the
    two is that vantage's answer is the engine's to say and not this line's.
    """
    if not outside.measured:
        reason = (outside.reason or "").replace("_", " ")
        return "not tested" + (f", {reason}" if reason and reason != "not probed" else "")
    views = [view for view in outside.views if view.measured]
    names = [view.vantage for view in views]
    if len(views) < 2 or len(set(names)) != len(names):
        ago = _time_ago(outside.measured_at, now)
        return (_measured_word(outside.state)
                + (f" from {tpl.mono(outside.vantage)}" if outside.vantage else "")
                + (f", {ago} ago" if ago else ""))
    words = [_measured_word(view.state) for view in views]
    agos = [_time_ago(view.measured_at, now) for view in views]
    one_time = len(set(agos)) == 1
    one_word = len(set(words)) == 1
    parts = []
    for view, word, ago in zip(views, words, agos):
        # "connected from" once where all found the same, before each name
        # where they did not
        part = tpl.mono(view.vantage) if one_word and parts else f"{word} from {tpl.mono(view.vantage)}"
        if not one_time and ago:
            part += f" {ago} ago"
        parts.append(part)
    line = ", ".join(parts)
    if one_time and agos[0]:
        line += f", {agos[0]} ago"
    return line


def _firewall_line(inside, doc, port, family=""):
    """A card's firewall line, from the engine's view of the rules for one
    port on one family: what the rules say of the port and nothing else.

    In order: a rule that permits it, one that permits it for some, one that
    names it and turns the packet away, rules on its path nobody could fully
    read, this family's legacy rules nobody could place, and only then that
    no rule names it.
    """
    if inside.nftables_status != "collected":
        return "firewall not read"
    if inside.permit_rules:
        more = len(inside.permit_rules) - 1
        return tpl.mono(inside.permit_rules[0].text) + (f", {more} more" if more else "")
    if inside.narrowed_rules:
        return tpl.mono(inside.narrowed_rules[0].text) + " (narrowed)"
    if inside.deny_rules:
        # A rule that names the port and turns the packet away is what the
        # rules say of it, quoted as a permit is. The line read "no rule
        # names 5432" on a server whose ufw denies 5432, which meant no rule
        # permits it and said no rule names it (docs/RECORD.md 4.454). The
        # engine gives this family's own rules, so a deny on v4 says nothing
        # on the v6 card.
        more = len(inside.deny_rules) - 1
        return tpl.mono(inside.deny_rules[0].text) + (f", {more} more" if more else "")
    if inside.unreadable_rule_count:
        # A rule the agent could render only in part, `[xt match multiport]`
        # for one, may name this port, and the engine counts those on the path
        # (NOTE_RULES_NOT_FULLY_READABLE). "No rule names 443" beside one is a
        # claim nobody read: ufw's own file had `allow 80,443` (4.199, C7).
        count = inside.unreadable_rule_count
        return f"{count} {'rule' if count == 1 else 'rules'} not fully readable"
    legacy = legacy_rules_of_family(doc, family)
    if legacy:
        # The Packet path's own words for the same rules.
        return f"{n_of(legacy, 'legacy iptables rule')}, not placed on a port"
    default = _ufw_default(doc) if doc else ""
    return f"no rule names {tpl.mono(port)}" + (f", ufw default {tpl.mono(default)}" if default else "")


def _card(family, finding, doc, port, now, agentless, row_name="", other=None):
    """One family's card for an opened row: (family, tone, lead, lines).

    `row_name` is what the row this card opens under is called, so the card
    and its row never give one port two names. Without it a socket is named
    from what the kernel said about it, and failing that it is unnamed.

    `other` is the other family's finding, read when this family has none:
    the engine hangs the provider's view of this family on it
    (`Finding.other_family_provider`), so the provider line says what the
    provider holds rather than "not connected" beside a connected one."""
    prober_mod = joinbridge.module("prober")
    # A sockets section that was not read says nothing about what is bound,
    # so no line below says nothing is (`sockets_not_read`).
    unread = sockets_not_read(doc)
    if finding is None:
        view = getattr(other, "other_family_provider", None)
        if agentless:
            firewall = NOT_SEEN_INSIDE
        elif doc and other is not None:
            # No finding is no view of the rules. This family's rules are
            # asked of the engine, with the function its findings are built
            # with: the line read "no rule names 5432" here without anybody
            # having looked, over a v6 chain that denies 5432
            # (docs/RECORD.md 4.454).
            firewall = _firewall_line(
                joinbridge.load().inside_view(doc, other.protocol, port, family), doc, port,
                family)
        else:
            firewall = "firewall not read"
        lines = [("agent", "no agent" if agentless else
                  SOCKETS_NOT_READ if unread else "nothing bound"),
                 ("prober", "not tested"),
                 ("firewall", firewall),
                 ("provider", _provider_line(view, port) if view is not None else "not connected")]
        return (family, "", "not tested" + ("" if agentless or unread else ", nothing is bound"),
                tuple(lines))
    inside, outside, state = finding.inside, finding.outside, finding.state
    owner = inside.owns_the_port
    tone = MARK_TONE.get(state or "", "")
    # the lead line: what was found and what that means against what you said
    if outside.connected:
        if state == "conflict":
            lead = "reachable, you said no"
        elif state == "intended":
            lead = "reachable, you said yes" if finding.intent else "reachable, your rule permits it"
        elif state == "unexplained":
            lead = (f"reachable, {NOT_SEEN_INSIDE}" if agentless
                    else f"reachable, {SOCKETS_NOT_READ}" if unread
                    else "reachable, nothing on the host owns it")
        elif finding.answered_outside_the_rules_source:
            # The one unreviewed port a rule does permit: the provider's, for
            # everyone, while the host's own rule permits one source and an
            # address outside it got an answer (docs/PRODUCT.md 8d,
            # docs/RECORD.md 4.358). "No rule permits it" would be untrue.
            # The engine says which case this is, nothing here works it out.
            lead = ANSWERED_OUTSIDE_LEAD
        else:
            # A rule nobody could fully read may be the permit (C7, 4.199).
            lead = ("reachable, a rule could not be fully read"
                    if _only_unreadable_rules(inside, legacy_rules_of_family(doc, family))
                    else "reachable, no rule permits it")
    elif outside.measured:
        if state == "conflict":
            lead = "not reachable, you said yes"
        elif state == "intended":
            lead = "not reachable, you said no"
        elif agentless or owner or unread:
            # A refusal is an answer, and the prober line under it says
            # "refused": the two outcomes keep the Packet path's two words.
            lead = ("not reachable, refused" if outside.state == prober_mod.STATE_REFUSED
                    else "not reachable, no answer")
        else:
            lead = "not reachable, nothing is bound"
    elif state == "stale rule":
        lead = "your rule permits it, nothing is behind it"
    else:
        lead = "not tested" + ("" if agentless or owner or unread else ", nothing is bound")
    # agent
    if agentless:
        agent = "no agent"
    elif inside.publications:
        # The container first, for the reason the row gives: the runtime's
        # host socket for this port is not a service of the host's.
        agent = ", ".join(publishes_it(pub) for pub in inside.publications)
    elif unread:
        agent = SOCKETS_NOT_READ
    elif inside.sockets:
        agent = ", ".join(
            f"{tpl.mono(row_name or finding_socket_name(sock) or 'an unnamed process')} listens on "
            f"{tpl.mono(_address_and_port(sock.bind_address, port))}"
            + (f", pid {tpl.mono(sock.pid)}" if sock.pid is not None else "")
            for sock in inside.sockets)
    elif inside.wildcard_sockets:
        # A v4 card whose only socket is on `::`. The socket is the fact,
        # said as it is, with its own address. Whether it takes v4 is what
        # the document cannot say, so the line does not say it either.
        agent = ", ".join(
            f"{tpl.mono(row_name or finding_socket_name(sock) or 'an unnamed process')} listens on "
            f"{tpl.mono(_address_and_port(sock.bind_address, port))}"
            + (f", pid {tpl.mono(sock.pid)}" if sock.pid is not None else "")
            for sock in inside.wildcard_sockets)
    elif inside.sockets_status != "collected":
        agent = SOCKETS_NOT_READ
    else:
        agent = "nothing bound"
    # prober
    prober = _prober_line(outside, now)
    # firewall
    firewall = NOT_SEEN_INSIDE if agentless else _firewall_line(inside, doc, port, family)
    provider = _provider_line(finding.provider, port)
    return (family, tone, lead, (("agent", agent), ("prober", prober),
                                 ("firewall", firewall), ("provider", provider)))


def _would_read(join, fams, declared):
    """The word the row would carry under one answer, reconciled across the
    families the way the shown word is."""
    states = {fam: join.state_if_declared(f, declared) for fam, f in fams.items()}
    word, _lead = port_row_word(
        {fam: state for fam, state in states.items() if state},
        {fam: f.outside.connected for fam, f in fams.items()})
    return word


def cve_cards(doc, db_path, now, reported_at=None):
    """What the CVE check says of each listening port of one report, as
    {(protocol, port): card}, a card being `controlplane/app/cvecard.Card`.
    `reported_at` is when the report arrived: a report older than three days
    says what was installed then, and its ports are not checked.

    **Empty for a report that carries no packages section**, which is every
    report of the published agent (docs/RECORD.md 4.385). The page then draws
    nothing of the check at all: not a card that says unknown on every port.

    The release's extract is read where `cvestore` keeps it, beside this
    database unless the instance names another place. An extract there that
    is not whole is read as none kept, so the card says there is no data for
    the release and the page stands.

    Which ports have a card, and which address family a port is asked about,
    is the control plane's (`cvecard.cards_of`), so the page and a message
    hold one answer for one port.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("packages"), dict):
        return {}
    cvecard, cvestore = joinbridge.module("cvecard"), joinbridge.module("cvestore")
    refused = joinbridge.module("cveextract").ExtractError
    env = dict(os.environ)
    env[joinbridge.module("db").DB_ENV] = str(db_path)
    where = cvestore.directory(env)

    def extract_for(distribution, version_id):
        try:
            return cvestore.read(distribution, version_id, where)
        except refused:
            return None

    return cvecard.cards_of(doc, extract_for, now, reported_at)


def host_port_row(name, key, fams, doc, names, declared, when, silenced, now, agentless,
                  dismissed=frozenset(), cve=None):
    """One PortRow from the findings of one port, `fams` being {family:
    finding}, and what the document, the declarations and the silences say
    about it. `cve` is this server's `cve_cards`, or None."""
    join = joinbridge.load()
    protocol, port = key
    states = {fam: f.state for fam, f in fams.items() if f.state}
    word, lead_family = port_row_word(
        states, {fam: f.outside.connected for fam, f in fams.items()})
    tone = tpl.PORT_TONE.get(word, "off") if word else ""
    lead = fams[lead_family] if lead_family else None
    # the service: the process or the declared name, or a note about what
    # is not there
    sockets = _sockets_for(doc, protocol, port) if doc else []
    publications = [f for f in fams.values() if f.inside.publications]
    service, note, provenance = "", False, ""
    if agentless:
        service, note = "", True
    elif publications:
        # A container's port is named by its container, before any socket:
        # the host socket a runtime holds for it (docker-proxy, or dockerd
        # with its proxy off) belongs to no service of the host's, and its
        # owner read "user root" here while the Services tab named the
        # container (docs/RECORD.md 4.199, 4.210). Both tabs say one name now.
        pub = publications[0].inside.publications[0]
        service = (names or {}).get(key) or pub.container
        if (names or {}).get(key):
            provenance = f"{NAMED_BY_YOU} · published by {pub.runtime} into container {pub.container}"
    elif sockets_not_read(doc):
        # Neither a socket nor "nothing listening": the section that would
        # say which was not read.
        service, note = SOCKETS_NOT_READ, True
    elif sockets:
        service, provenance = port_naming(
            sockets, (names or {}).get(key),
            unit_declared_for(socket_unit_names(doc), key, sockets,
                              enabled_socket_unit_files(doc)))
    else:
        service, note = "nothing listening", True
    # `owns_the_port` is the engine's own answer, and it counts a socket on
    # the IPv6 wildcard for v4: it may be taking v4 connections and the
    # document cannot say (docs/PRODUCT.md 8a). Reading the sockets alone
    # wrote "nothing bound on v4" beside a v4 connect (docs/RECORD.md 4.199).
    binds = {str(s.get("bind_address", "")) for s in sockets}
    loopback_only = bool(binds) and all(is_loopback(b) for b in binds)
    if lead is not None and not note and not lead.inside.owns_the_port:
        # A listener on loopback alone is named and said to be one. "Nothing
        # bound on v6" beside it hid the one socket the port has: 4.210's
        # 3032, a listener on 127.0.0.1 behind a rule for both families.
        service, note = ((f"{service}, loopback only", True) if loopback_only
                         else (f"nothing bound on {lead.family}", True))
    # the family marks
    marks = tuple(MARK_TONE.get(states.get(fam) or "", "") for fam in FAMILY_ORDER)
    # decided by
    decided = ""
    intent = next((f.intent for f in fams.values() if f.intent), None)
    # Who decided and nothing else: the day of an answer is a line in the
    # opened row since 2026-10-09 (the review's point 4, docs/record 4.447).
    said = "you"
    if loopback_only and word in ("", "not reachable"):
        # bound to loopback only: a fact about the socket, and the sketch's
        # word for it, whatever the prober did or did not measure
        decided = "loopback"
    elif not word and intent:
        # Somebody answered for a port nothing has measured yet. The answer
        # is theirs and is said as theirs, and the State cell stays empty
        # (docs/RECORD.md 4.393, C13).
        decided = said
    elif word == "intended":
        decided = said if intent else "your rule"
    elif word == "conflict":
        decided = said
    elif word == "unreviewed" and lead is not None and lead.answered_outside_the_rules_source:
        decided = ANSWERED_OUTSIDE_DECIDED
    elif word == "unreviewed":
        decided = ("rule not readable" if lead is not None and _only_unreadable_rules(
            lead.inside, legacy_rules_of_family(doc, lead.family)) else "no rule")
    elif word == "unexplained":
        decided = NOT_SEEN_INSIDE
    elif word == "stale rule":
        # The state beside it says what is behind the rule.
        decided = "your rule"
    elif word == "not reachable":
        # The sketch says host firewall. The engine names no layer for a
        # measured silence (docs/PRODUCT.md 8b), so the cell says what is true
        # of the rules and nothing more. The owner's delegated call, 2026-09-13,
        # docs/RECORD.md 4.174.
        # A rule that names the port and denies it is a rule of yours as
        # well: "no rule" stood beside a Rules tab listing the deny
        # (docs/RECORD.md 4.454). Still no layer is named as the cause.
        decided = ("your rule" if lead is not None and (_permitted(lead) or _denied(lead))
                   else "no rule")
    # the answers
    acknowledged = bool(states) and all(fams[fam].acknowledged for fam in states)
    answers, lit, settled, quiet, aside = (), "", False, False, ""
    if word in ("unreviewed", "unexplained"):
        answers = tpl.ANSWERS
        if acknowledged:
            lit, settled = "later", True
    elif word in ("intended", "conflict"):
        answers = tpl.ANSWERS
        if intent:
            lit = "yes" if intent == "open" else "no"
        else:
            lit = "yes"
        settled = True
    elif word == "stale rule":
        answers, aside = ("later",), tpl.REMOVE_THE_RULE
        if acknowledged:
            lit = "later"
        else:
            # Nothing on the closed row, like a port that is not reachable:
            # a stale rule asks nobody for anything (docs/RECORD.md 4.198),
            # so its one answer and the way out beside it wait for the row
            # to be opened.
            quiet = True
    elif word == "not reachable":
        answers = tpl.ANSWERS
        if acknowledged:
            lit, settled = "later", True
        else:
            quiet = True
    elif not word and intent:
        # No Later: it puts off an answer to a state, and there is none.
        answers = ("yes", "no")
        lit, settled = ("yes" if intent == "open" else "no"), True
    if_declared = tuple(_would_read(join, fams, d) for d in ("open", "closed", None)) if fams else ("", "", "")
    # The name the row carries, when it is a name and not a note such as
    # "nothing listening", and only when it names a socket.
    row_name = service if sockets and not note else ""
    cards = tuple(_card(fam, fams.get(fam), doc, port, now, agentless, row_name,
                        other=next((f for k, f in fams.items() if k != fam and f), None))
                  for fam in FAMILY_ORDER)
    # The mark, and whether a person dismissed it. `rare_mark` is what the
    # opened row offers: Dismiss while the mark is drawn, Restore once it is
    # dismissed, and nothing on a port the mark would not be drawn on.
    marked = bool(rarely_reachable(fams.values()))
    dismissed_here = f"{protocol}/{port}" in dismissed
    rare_mark = ("dismissed" if dismissed_here else "shown") if marked else ""
    return tpl.PortRow(
        protocol=protocol, port=port, word=word, tone=tone, service=service,
        service_note=note, provenance=provenance, marks=marks, decided=decided,
        answers=answers, lit=lit, settled=settled, quiet=quiet, aside=aside,
        families=FAMILY_ORDER, if_declared=if_declared,
        rate_limited=any(f.rate_limited for f in fams.values()),
        silenced=any((protocol, port, fam) in silenced for fam in FAMILY_ORDER),
        reach_open=any(f.outside.connected for f in fams.values()),
        rarely=marked and not dismissed_here,
        rare_mark=rare_mark,
        state_families=tuple(sorted(states)),
        answered_on=when if (intent and decided == said) else "",
        cards=cards,
        **_cve_fields((cve or {}).get(key)))


def _cve_fields(entry):
    """A port row's fields for the CVE check, from its card and whether its
    mark is dismissed, or from None."""
    if entry is None:
        return {}
    card, dismissed = entry
    return {"cve_lines": tuple((line.label, line.value, line.note, line.ids) for line in card.lines),
            "cve_mark": card.mark, "cve_ids": card.cves, "cve_dismissed": dismissed,
            "cve_links": card.links}


def load_cve_dismissed(db_path, workspace_id=None):
    """Each server's ports whose CVE mark a person dismissed, with the CVEs
    it was dismissed for: {name: {(protocol, port): frozenset of ids}}
    (controlplane/app/cvedismiss.py owns the storage and the rule). A
    database from before dismissals has none."""
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        return joinbridge.module("cvedismiss").dismissed_by_host(con, workspace_id)
    finally:
        con.close()


def host_port_rows(name, doc, findings, names=None, declared=None, when=None,
                   silenced=(), now=None, agentless=False, dismissed=frozenset(), cve=None):
    """Every port of one server as a PortRow, worst first by the fleet's
    bands applied to the port's state and then by number. A port the engine
    has no finding for still gets its row from the document, with nothing in
    the cells the findings would fill."""
    now = now or datetime.now(timezone.utc)
    by_port = {}
    for finding in findings:
        by_port.setdefault((finding.protocol, finding.port), {})[finding.family] = finding
    if doc:
        for key in document_ports(doc):
            by_port.setdefault(key, {})
    rows = [host_port_row(name, key, fams, doc, names, declared, (when or {}).get(key, ""),
                          silenced, now, agentless, dismissed, cve)
            for key, fams in by_port.items()]
    # a port with no state has no band, so it sorts after every port that has one
    last = len(tpl.FLEET_BANDS)
    rows.sort(key=lambda r: (tpl.fleet_band(r.word) if r.word else last, r.port, r.protocol))
    return rows


def changed_ports(name, transitions, changed, since):
    """The ports of one server whose reachability changed since `since`, as
    [(protocol, port, became reachable, the families that did)], newest
    first, from the recorded transitions and the set
    `load_reachability_changes` picked.

    A port is one row and a transition is one family's. The port became
    reachable when either family's newest measurement in the window is a
    connect, which is the family its row leads with (`port_row_word`). Until
    2026-10-02 the newest row alone decided, whichever family it was, so a
    port that began answering on v4 and was measured silent on v6 a few
    seconds later read "became not reachable" (docs/RECORD.md 4.237).
    """
    prober_mod = joinbridge.module("prober")
    newest, order = {}, []
    for row in transitions:
        key = (name, row["protocol"], row["port"])
        when = received_at_or_none(row.get("seen_at"))
        if key not in changed:
            continue
        if when is None or when < since or row["outside"] not in prober_mod.MEASURED_STATES:
            continue
        port_key = (row["protocol"], row["port"])
        if port_key not in newest:
            newest[port_key] = {}
            order.append(port_key)
        # The rows come newest first, so the first one seen for a family is
        # that family's newest.
        newest[port_key].setdefault(row.get("family"), row["outside"])
    out = []
    for protocol, port in order:
        families = newest[(protocol, port)]
        became = prober_mod.STATE_CONNECTED in families.values()
        # The families the line is true of: the ones whose newest measurement
        # is the outcome the line states.
        moved = tuple(sorted(
            family for family, outside in families.items()
            if family and (outside == prober_mod.STATE_CONNECTED) == became))
        out.append((protocol, port, became, moved))
    return out


def host_overview_body(slug, rows, moved, agentless=False, live=True):
    """The Overview tab: the three boxes, review all ports, the port table."""
    def first(match):
        return next((tpl.row_id(slug, r.protocol, r.port) for r in rows if match(r)), "")
    reachable = [r for r in rows if _row_open(r)]
    deciding = [r for r in rows if _needs_decision(r)]
    tone = "fail" if any(r.word == "conflict" for r in rows) else ("warn" if deciding else "")
    moved_keys = {(protocol, port) for protocol, port, _became, _families in moved}
    line = ""
    if moved:
        protocol, port, became, families = moved[0]
        line = f"{port}/{protocol} became {'reachable' if became else 'not reachable'}"
        # The line names the family when it is true of one family and the
        # port has a state on both: a port that answers on v4 as before and
        # went silent on v6 did not become not reachable, v6 did.
        row = next((r for r in rows if (r.protocol, r.port) == (protocol, port)), None)
        if row is not None and families and set(families) < set(row.state_families):
            line += " on " + " and ".join(families)
    strip = tpl.host_strip_html(
        (len(reachable), len(rows), first(_row_open)),
        (len(deciding), tone, first(_needs_decision)),
        (len(moved), line, first(lambda r: (r.protocol, r.port) in moved_keys)))
    # The window the button opens lists the ports that answer from outside
    # (`first_look_rows`). With none it has no row, so there is no button: it
    # opened an empty window on the first outside server, 0 of 20 reachable
    # (the owner, 2026-09-20).
    review = tpl.review_all_html(slug) if reachable else ""
    return (strip + review
            + tpl.host_rows_html(slug, rows, foot=tpl.NO_AGENT_LINE if agentless else "",
                                 live=live))


def _needs_decision(row):
    """Whether this port counts in the page's Needs a decision box.

    **The same set the Fleet counts for this server**, so the two numbers are
    one number: a port in `unreviewed` or `unexplained`, and since 2026-10-02
    a reachable port on the rarely-public list whatever its state, which the
    Fleet draws as a chip (`fleet_facts`, docs/RECORD.md 4.229 and 4.258).
    A `conflict` is counted by neither: the Fleet has its own box for it and
    this page colours the number red.
    """
    return row.word in DECISION_WORDS or (row.rarely and row.word != "conflict")


def _row_open(row):
    """Whether the prober found this port open on either family, which the
    reachable count and the first-look window both read."""
    return row.reach_open


def first_look_rows(rows, moved=()):
    """The rows of the first-look window: every port the prober found open,
    waiting in the first group and answered by a rule or by you in the
    second (SPEC.md section 8).

    **Sorted so the ports most like a forgotten one come first**
    (docs/RECORD.md 4.221), by what is measured and by nothing else:

    1. a port no rule of the operator's answers, before one a rule answers
    2. a port on the list of ports that should rarely face the internet
    3. a port whose answer from outside has not moved since the server's
       first report, `moved` being the ports that did move
    4. the port number

    It is an order and never a score. A fourth sign was named with these,
    a port that is not one of the host's usual system services, and it is
    left out: nothing sourced says what is usual.
    """
    out = []
    for row in rows:
        if not _row_open(row):
            continue
        if row.lit in ("yes", "no"):
            source = row.decided
            group = "rule"
        else:
            # A waiting row says what its row's Decided by says (SPEC.md
            # section 8): "rule not readable" where a rule on the path could
            # not be fully read, and the words of the one waiting port a rule
            # does permit. It said "no rule" over both, beside a row that
            # said otherwise (the second big test, 24 October, case F6).
            source = row.decided or ("no rule" if row.word == "unreviewed" else "")
            group = "waiting"
        order = (0 if group == "waiting" else 1,
                 0 if row.rarely else 1,
                 1 if (row.protocol, row.port) in moved else 0,
                 row.port, row.protocol)
        out.append((order, (group, row.label, row.service if not row.service_note else "",
                            source, row.lit if row.lit in ("yes", "no") else "", row.protocol,
                            row.port, ",".join(row.state_families))))
    out.sort(key=lambda pair: pair[0])
    return [entry for _order, entry in out]


# ---------------------------------------------------------------- packet path
#
# The inside half of PRODUCT.md section 8 item 1. site/app/packetpath.py does
# the walking and holds the sourcing for the order; this only renders it.
#
# Every checkpoint takes the neutral tone, on purpose. ok, warn and fail mean
# one thing each in this product and none of them applies here: there is no
# verdict to encode, because the outside view does not exist yet. Colouring a
# checkpoint would also be colouring depth of filtering, which DESIGN.md
# section 3 forbids outright. So the word in each step carries the whole
# signal, which is the rule that section leads with anyway.

# What the reader is looking at when a hook has no base chain at all.
EMPTY_HOOK = ("Nothing the agent read attaches to the {hook} hook for {family}, so no rule "
              "of this host is evaluated at this point.")

ROUTING_NOTE = ("The kernel decides here whether this packet goes to a socket on this host or "
                "is forwarded onward. What follows depends on that choice, and the agent reads "
                "rules rather than routes, so the choice itself is not measured.")

UNREADABLE_NOTE = (" A rule that is not fully readable may select this port without saying so "
                   "in text, through a set, an x_tables match or a raw header offset this agent "
                   "does not decode.")

# The same limit as one plain sentence, for the reader of one port's path who is
# looking at a number in the dozens and has been given no reason for it. It used
# to sit in the summary line as a bare "56 not fully readable", which reads as an
# alarm and explains nothing (the owner, 2026-08-16).
def unreadable_line(n):
    """The same limit as one plain sentence, with its grammar surviving n=1.
    As a template it printed "1 rules ... match", which is exactly the kind of
    generated-looking line the reader of this page notices."""
    tail = ("It could select this port without naming it in text, and it is in the "
            "walk below." if n == 1 else
            "Any of them could select this port without naming it in text, and every "
            "one of them is in the walk below.")
    return (f'{n_of(n, "rule")} on this path {verb(n, "matches", "match")} on something '
            f'the agent does not decode: a set, an x_tables match or a raw header '
            f'offset. {tail}')

# What a run of chains that decided nothing folds into on the trace, in this
# module's words.
#
# Two sentences rather than one, and chains carrying different sentences are not
# folded together, so the stronger claim is never made on behalf of a chain that
# cannot support it. A chain holding a rule the agent could not decode is not a
# chain with no rule for this port: fail2ban's chain does carry a dport 22 rule,
# behind a set (PRODUCT.md 4g).
FOLD_NONE = "none of them names this port"
FOLD_UNREADABLE = "nothing readable in them names this port"

SHARED_PRIORITY_NOTE = (" Another base chain is registered at this same priority. The kernel "
                        "traverses equal priorities in registration order, which a host document "
                        "does not record, so which of them runs first cannot be read here.")


def n_of(count, singular, plural=None):
    """A count with the right noun. "1 rules" reads as generated, and this page
    is read by people who notice that sort of thing."""
    return f'{count} {singular if count == 1 else (plural or singular + "s")}'


def verb(count, singular, plural):
    return singular if count == 1 else plural


def walk_block(steps):
    """The full walk of one base chain as quotable text, jumps followed, in
    evaluation order. A rule the agent did not fully render keeps its grade, so
    a half-read rule can never sit in this list looking like a quoted one
    (RECORD 4.18)."""
    lines = []
    for chain, text, rendered, comment, verdict, depth in steps:
        indent = "  " * depth
        grade = "" if rendered == "full" else f"   [rendered: {rendered}]"
        note = f"   # {comment}" if comment else ""
        lines.append(f"{indent}{chain}: {text}{grade}{note}")
        lines.append(f"{indent}    -> {verdict}")
    return "\n".join(lines)


def walk_views(path, declared=None):
    """One walked path, read twice out of one loop: the trace steps for
    trace_html, and the rail cells for tpl.gates_walk_html. Both come from the
    same pass so the two readings cannot disagree about what was evaluated.

    `declared` is the operator's declared name for this port, or None, and it
    reaches only the socket gate at the end of the rail.

    The steps: one per base chain the packet is evaluated against, hooks in
    kernel traversal order and base chains by the priority the kernel itself
    reported, plus the empty core hooks and the routing decision.

    The cells: a chain where a rule names this port is a gate, the routing
    decision is the fork, and everything else folds into quiet blocks carrying
    their count. The socket ends the rail, which is also what keeps the rail
    from ever being empty: a traced port always ends at something that holds
    it.

    A chain is not given a gate for holding a jump. Almost every firewalld base
    chain jumps somewhere, so jumps as a signal would put the wall of nodes
    straight back on the screen, and the one jump that changes where this
    packet goes, a dnat of this port, is a rule that names this port and so
    already earns its gate above.
    """
    steps = []
    cells = []
    quiet = 0

    def flush():
        nonlocal quiet
        if quiet:
            cells.append(tpl.quiet_cell(quiet))
            quiet = 0

    for stage in path["stages"]:
        hook = stage["hook"]
        if not stage["groups"]:
            # An empty core hook is a real answer: nothing on this host filters
            # there. An empty ingress is just noise, because almost no host has
            # one at all.
            if hook != "ingress":
                steps.append((f"{hook} hook", "no base chain is registered here", "off", "",
                              EMPTY_HOOK.format(hook=hook, family=path["family"])))
                quiet += 1
        for group in stage["groups"]:
            shared = len(group["entries"]) > 1
            for entry in group["entries"]:
                counts = entry["counts"]
                named = [text for _, text, _, _, verdict, _ in entry["steps"]
                         if verdict == pp.NAMES_PORT]
                priority = ("priority not readable" if group["priority"] is None
                            else f'priority {group["priority"]}')
                every, unread, other = (counts[pp.EVERY_PORT], counts[pp.UNREADABLE],
                                        counts[pp.OTHER_PORT])
                hits = counts[pp.NAMES_PORT]
                # "no rule here names this port" would be read as "this chain
                # has nothing about your port", which is a stronger claim than
                # the document supports when something in the chain could not
                # be decoded. fail2ban's chain is the live example: it does
                # carry a dport 22 rule, behind a set the agent cannot read.
                if named:
                    word = f'{n_of(hits, "rule")} {verb(hits, "names", "name")} this port'
                elif unread:
                    word = "nothing readable here names this port"
                else:
                    word = "no rule here names this port"
                note = (f'{n_of(every, "rule")} {verb(every, "carries", "carry")} no port match '
                        f'and {verb(every, "is", "are")} evaluated for every port. '
                        f'{unread} {verb(unread, "was", "were")} not fully readable. '
                        f'{other} {verb(other, "names", "name")} a different port and '
                        f'{verb(other, "is", "are")} not listed. '
                        f'The chain policy is {entry["policy"] or "none"}.')
                if shared:
                    note += SHARED_PRIORITY_NOTE
                if counts[pp.UNREADABLE]:
                    note += UNREADABLE_NOTE
                extra = ""
                if entry["steps"]:
                    extra = disclosure(f'the whole walk, {n_of(len(entry["steps"]), "rule")}',
                                       "jumps followed, in evaluation order",
                                       walk_block(entry["steps"]))
                # A chain with a rule naming this port is the reason the reader
                # opened the page, so it is never folded away.
                fold = None if named else (FOLD_UNREADABLE if unread else FOLD_NONE)
                steps.append((f'{hook} · {entry["table"]} {entry["chain"]}',
                              f'{priority}, {word}', "off", "\n".join(named), note, extra, fold))
                if named:
                    flush()
                    cells.append(tpl.gate_cell(
                        hook, f'{entry["table"]} {entry["chain"]}',
                        n_of(hits, "rule"), meta=priority, rules=named, note=note,
                        extra=extra, full=f'{hook} · {entry["table"]} {entry["chain"]}'))
                else:
                    quiet += 1
        if hook == "prerouting":
            steps.append(("the routing decision", "local delivery or forwarded", "off", "",
                          ROUTING_NOTE))
            flush()
            cells.append(tpl.fork_cell())
    flush()
    cells.append(socket_cell(path, declared))
    return steps, cells


def publishes_it(pub):
    """A card's agent line for a port a container publishes: the runtime,
    the container, and the host address it publishes on. A runtime that
    holds no host address for it, as rootful Podman does for -p with no
    address, has the line end at the container. It read "publishes it on"
    with nothing after it (the second big test, finding C10)."""
    line = f"{tpl.mono(pub.runtime)} container {tpl.mono(pub.container)} publishes it"
    return f"{line} on {tpl.mono(pub.host_ip)}" if pub.host_ip else line


def socket_cell(path, declared=None):
    """The rail's last gate: what holds this port at the end of the path.

    The far end of the rail is where the port is, never where a packet got to,
    so the gate is labelled with what holds the port and states nothing about
    arrival. "The packet arrives" is a reachability claim and only the prober
    can make it.

    A declared name takes the label, with NAMED_BY_YOU beside it on the rail
    itself, because a name a person typed must not sit unlabelled where every
    other cell is a quoted measurement. The measured holders stay quoted in
    the gate's panel, and the holder count stays theirs.
    """
    quoted = [f'{s.get("process_name") or "an unattributed process"} '
              f'{s.get("bind_address")}' for s in path["sockets"]]
    notes = []
    for runtime, container, published in path["publications"]:
        cname = container.get("name") or container.get("id", "")[:12]
        # A runtime that holds no host address for it, as rootful Podman does
        # for -p with no address, is said to publish the port and no address
        # (the second big test, finding C10).
        where = (f'{published.get("host_ip")}:{published.get("host_port")}' if published.get("host_ip")
                 else f'port {published.get("host_port")}')
        notes.append(f'{runtime} publishes {where} into container {cname} port '
                     f'{published.get("container_port")}, and the runtime did not say '
                     f'which address family that is.')
    count = len(quoted) + len(notes)
    if not count:
        notes.append("Nothing in this document holds this port in this family.")
    name, _note = path_end(path)
    if declared:
        name = f"{declared}, {NAMED_BY_YOU}"
        notes.insert(0, f"You named this port {declared}.")
    return tpl.gate_cell("socket", name, n_of(count, "holder"), rules=quoted,
                         note=" ".join(notes), full="the socket")


def path_end(path):
    """The (name, note) pair the diagram puts at the far end of the rail.

    The far end of the rail is where the port is, never where a packet got to,
    so it is labelled with what holds the port. Short, because the label sits
    under an 8 pixel mark. Every holder is listed in the rows under the diagram,
    which is where a second socket or a second publication shows up.
    """
    for socket in path["sockets"]:
        who = socket.get("process_name") or "an unattributed process"
        return (who, f'holds a socket on {socket.get("bind_address")}')
    for runtime, container, published in path["publications"]:
        name = container.get("name") or container.get("id", "")[:12]
        return (f"container {name}", f'{runtime} publishes {published.get("host_port")} into it')
    return ("this port", "nothing in this document holds it in this family")


def path_left_out(doc):
    """What this host has that the walk could not place, and nothing else.

    There used to be a panel headed "What this view can and cannot see" above
    this, holding three rows of method: where the order comes from, when a rule
    counts as naming a port, that an accept in one base chain is not the end of
    the story. The owner had it taken out on 2026-08-16, and
    he is right that it read as a disclaimer. What survives is the part that is a
    fact about this document rather than a statement about us: rules this host has
    that are not on the path. Dropping those would be hiding them.
    """
    rows = []
    legacy = pp.legacy_rule_count(doc)
    if legacy:
        # The reason stays. Without it, "none of them on this path" reads as
        # "none of them matches this port", which is a stronger claim than the
        # document supports.
        rows.append(("legacy iptables",
                     f'{n_of(legacy, "rule")}, none of them placed on this path, because the '
                     f'agent stores an x_tables match by name only. Quoted in full on the '
                     f'Rules tab.'))
    excluded = pp.excluded_families(doc)
    if excluded:
        rows.append(("not walked",
                     ", ".join(excluded) + ", which do not sit on the path a connection to a "
                     "host port takes."))
    if not rows:
        return ""
    # Both rows are (label, text) fields rather than sentences. Merging two
    # branches here briefly left one row a tuple and the other a string, both
    # passed to esc(), which would have printed a Python tuple repr onto the
    # page. A test caught it, which is the only reason it is not shipped.
    return ('<div class="sec"><div class="panel">'
            + "".join(tpl.three_cell_row(tpl.esc(left), tpl.esc(right), "",
                                         first_cls="d", middle_cls="", last_cls="")
                      for left, right in rows)
            + '</div></div>')


# What the outward half is allowed to put on a screen.
#
# `docs/PRODUCT.md` 4g's last paragraph governs it exactly as it governs the
# inward half: no outcome, not reachable, not allowed, not blocked, not
# accepted. `site/app/packetpath.py` emits keys and quotes and this turns them
# into the only sentences anybody reads, which is why the copy lives here.
#
# The sentences are deliberately about the document rather than about the
# packet. "A rule here names this port and ends its journey" is a reading of a
# ruleset. "This is what stopped it" would be a guess, because nothing came
# back and a packet that is not answered leaves no evidence of where it
# stopped.
OUTWARD_NOTE = {
    pp.ENDS_ON_THIS_PORT: "a rule here names this port and ends its journey",
    pp.POLICY_ENDS: "nothing here names this port, and this chain's policy "
                    "ends a packet that reaches the end of it",
    pp.CANNOT_RULE_OUT: "rules here could not be fully read, so this "
                        "checkpoint can be neither ruled in nor out",
}


def outward_html(path, outside):
    """The outward reading of one rail, or nothing at all.

    Nothing at all is the common case today and it is the correct one: a port
    the prober did not measure gets no outward view, because reasoning about a
    silence nobody observed is the failure `docs/PRODUCT.md` 4b exists to stop.
    """
    if outside is None:
        return ""
    view = pp.outward_path(path, outside.state, measured=outside.measured)
    if view is None:
        return ""

    where = f" from {outside.vantage}" if outside.vantage else ""
    when = f" at {outside.measured_at[11:16]}" if outside.measured_at else ""
    if view["answered"]:
        # Nothing is marked, and the sentence says why rather than leaving an
        # empty panel that reads as a page that failed.
        return tpl.fold_html(
            "what the outside view adds",
            '<div class="agree">The prober connected to this port'
            f'{where}{when}. Something on the path above let it through and the '
            'ruleset does not say which checkpoint, so none of them is marked.'
            '</div>')

    rows = []
    for entry in view["checkpoints"]:
        notes = "".join(
            f'<div class="d">{tpl.esc(OUTWARD_NOTE.get(key, key))}'
            + (f'<div class="mono dim">{tpl.esc(quote)}</div>' if quote else "")
            + '</div>'
            for key, quote in entry["notes"])
        rows.append(
            tpl.three_cell_row(
                f'<b>{tpl.esc(entry["chain"])}</b>'
                f'<span class="dim"> {tpl.esc(entry["hook"])}, {tpl.esc(entry["table"])}</span>',
                notes, "", first_cls="nm"))

    head = (f'<div class="agree">The prober got no answer on this port{where}'
            f'{when}. These are the checkpoints above that the document says '
            'could account for that. Nothing came back, so which one acted is '
            'not something this page can tell you.</div>')
    if not rows:
        head = (f'<div class="agree">The prober got no answer on this port{where}'
                f'{when}, and no checkpoint above holds anything that accounts '
                'for it. Something the agent could not read, something upstream '
                'of this host, or a rule whose window has passed are all still '
                'possible.</div>')
    tail = ""
    if view["legacy_rules"]:
        tail = ('<div class="agree">' + tpl.esc(
            f"{view['legacy_rules']} legacy iptables rules are not on this path "
            "at all, and any of them could name this port. They are on the "
            "Rules tab.") + '</div>')
    return tpl.fold_html("what the outside view adds", head + "".join(rows) + tail)


# ------------------------------------------------------- the Packet path tab
#
# docs/screens/host-packet-path/SPEC.md, approved 2026-09-10 after eight
# rounds. For one port and family: which tools a packet from outside meets, in
# the order it meets them, and what each of them has for this port.
#
# **The one rule this builder obeys above the rest.** A stop is attributed to
# a tool only when the chain that ended the journey maps to a tool already on
# the path. Where it maps to nobody the fate is `lost` instead, because
# nothing came back and any single checkpoint named as the cause would be a
# guess wearing a fact's clothes (`site/app/packetpath.py`'s own words, and
# `controlplane/app/join.py:_decide` reaches the same wall from the other
# side).

# The prober's word for this port, in the packet path's own vocabulary. The
# left half is what `build.OUTSIDE_SHOWN` already shows on the Evidence tab,
# so the two tabs cannot describe one measurement differently.
PATH_MEASURED_WORDS = {"open": "answered", "refused": "refused",
                       "no answer": "no answer", "not tested": "not probed yet"}

# What the detail line says beside each word. The connect time is not here
# because the join engine's views do not carry it: they hold the state, the
# vantage and when. Saying a number nobody handed us is the one thing this
# line may not do.
PATH_DETAILS = {"answered": "connected from", "refused": "refused from",
                "no answer": "nothing came back from"}


def vantage_address(vantage, family):
    """The address a vantage probes from on this family, from the published
    list, or "".

    The left end says where the packet came from, which is the vantage's own
    address on the family being drawn and never the target's. A vantage with
    no published address on this family shows none rather than the other
    family's.
    """
    try:
        import probers
    except ImportError:
        return ""
    want = str(vantage or "")
    for entry in probers.PROBERS:
        if str(entry.rdns).split(".")[0] != want:
            continue
        try:
            version = ipaddress.ip_network(entry.address, strict=False).version
        except ValueError:
            continue
        if (version == 4) == (family == "v4"):
            return entry.address
    return ""


def path_measurement(outside, now):
    """(word, detail) for the measurement line, in the prober's own words."""
    if outside is None or not outside.measured:
        return "not probed yet", ""
    shown = tpl.OUTSIDE_SHOWN.get(outside.word, outside.word)
    word = PATH_MEASURED_WORDS.get(shown, shown)
    lead = PATH_DETAILS.get(word, "")
    vantage = outside.vantage or ""
    if not lead or not vantage:
        return word, ""
    when = received_at_or_none(outside.measured_at)
    ago = f", {age_text(when, now)} ago" if when else ""
    return word, f"{lead} {vantage}{ago}"


def provider_rule_covers(rule, protocol, port, family):
    """Whether this provider rule is about this port on this family.

    Inbound only, the protocol as the provider named it, the port equal or
    inside the range the provider wrote, and an address of this family among
    its sources. A rule with no port at all, which is how Hetzner writes icmp,
    covers no port.
    """
    if str(rule.direction) != "in" or str(rule.protocol) != protocol:
        return False
    text = str(rule.port or "").strip()
    if not text:
        return False
    if "-" in text:
        low, _, high = text.partition("-")
        try:
            if not (int(low) <= int(port) <= int(high)):
                return False
        except ValueError:
            return False
    elif text != str(port):
        return False
    return bool(rule.source_ips.has_v4 if family == "v4" else rule.source_ips.has_v6)


def provider_path_tool(provider, host_name, protocol, port, family):
    """The provider's firewall as a box, or None when this host has none.

    It is drawn first for every provider. DigitalOcean's own page says a cloud
    firewall stops traffic before it reaches the server and AWS's says the
    same of a security group; no Hetzner page found says where theirs sits,
    and the owner took that call on 2026-09-10 (SPEC.md, and it is still worth a
    Hetzner page saying it).
    """
    found = provider_match(provider or {}, host_name)
    if found is None:
        return None
    place, server = found
    inventory = provider_projects(provider)[place]["inventory"]
    for attached, firewall in inventory.firewalls_for_server(server.id):
        if firewall is None or str(attached.status) != "applied":
            continue
        rules, mine = [], None
        for rule in firewall.rules:
            hit = provider_rule_covers(rule, protocol, port, family)
            words, machine, _unread = provider_source_words(rule.source_ips)
            rules.append({"action": "allow" if rule.direction == "in" else "allow out",
                          "port": port_text(rule.port), "protocol": rule.protocol,
                          "families": provider_families(rule.source_ips),
                          "from": words, "hit": hit,
                          "quote": str(rule.description or "")})
            if hit and mine is None:
                mine = (rule, words)
        label = f"{port}/{protocol}"
        if mine is None:
            finding = f"no rule for {port}"
            facts = [(f"for {label}", "no rule", True)]
        else:
            finding = f"allow {port}, {mine[1]}"
            facts = [(f"for {label}",
                      theme.status("off", "allow") + f"<span>{tpl.esc(mine[1])}</span>",
                      False)]
        # Hetzner's own firewall overview: with no matching rule all inbound
        # is blocked and all outbound permitted (read 2026-09-09).
        facts.append(("without a rule", "deny", False))
        return {"kind": "provider", "name": tpl.PROVIDER_NAMES["hetzner"],
                "mark": "hetzner", "where": firewall.name, "finding": finding,
                "facts": facts, "rules": rules}
    return None


# What a runtime is called on the screen, and its mark.
PATH_RUNTIMES = {"docker": ("Docker", "docker"), "podman": ("Podman", "podman")}


def family_publication(doc, protocol, port, family):
    """The publication of this port on this family, as `(runtime, container,
    published)`, or None when no runtime published it there.

    `0.0.0.0` is v4 and `::` is v6. Any other address, and a runtime that
    did not say, count for both, which is the reading the picker makes of
    them. A path of one family drawn from the other family's publication
    said "published on 0.0.0.0" on a v6 path (docs/RECORD.md 4.237).
    """
    for runtime, container, published in pp.publications_on(doc, protocol, port):
        families = PUBLISH_FAMILIES.get(str(published.get("host_ip") or "")) or FAMILIES
        if family in families:
            return runtime, container, published
    return None


def runtime_path_tool(doc, protocol, port, family):
    """The container runtime that published this port on this family, or
    None.

    It sits before the host firewall, because a publish is a DNAT rule in the
    stage before routing (`docs/PRODUCT.md` 4a). Whether Docker wrote that
    rule for this family is `docker_rewrite`'s to say, and the caller asks.
    """
    found = family_publication(doc, protocol, port, family)
    if found is None:
        return None
    runtime, container, published = found
    name, mark = PATH_RUNTIMES.get(runtime, (runtime, "cube"))
    host_ip = str(published.get("host_ip") or "")
    cname = str(container.get("name") or container.get("id") or "")
    label = f"{port}/{protocol}"
    rules = [{"action": "publish", "port": port, "protocol": protocol,
              "families": PUBLISH_FAMILIES.get(host_ip, ()),
              "from": ANYWHERE if host_ip in PUBLISH_FAMILIES else (host_ip or ""),
              "hit": True,
              "quote": f'{host_ip}:{published.get("host_port", "")}->'
                       f'{published.get("container_port", "")}/{protocol}'}]
    return {"kind": "runtime", "name": name, "mark": mark, "where": "",
            "finding": f"publishes {port}",
            "facts": [(f"for {label}",
                       theme.status("off", "publish")
                       + f'<span>to {tpl.esc(cname)}</span>', False),
                      ("published on", tpl.esc(host_ip) if host_ip
                       else "the runtime did not say", not host_ip)],
            "rules": rules, "runtime": runtime, "container": cname,
            "inside": f'{published.get("container_port", "")}/{protocol}'}


# Whether Docker rewrites a published port's destination in the kernel, on
# one address family, as far as the document says.
#
# **Why this is asked per family.** Docker carries a port past the host
# firewall by rewriting its destination in the stage before routing, so the
# packet is forwarded and never meets the host's input rules
# (`docs/PRODUCT.md` 4a, 4d). It writes that rule only where the container
# has an address of the family. A container on a bridge with no IPv6 is still
# published on the host's IPv6 addresses, by Docker's userland proxy. Docker's
# own page on port publishing, read 2026-10-11: "Ports on the host's IPv6
# addresses will map to the container's IPv4 address if no host IP is given in
# a port mapping, the bridge network is IPv4-only, and --userland-proxy=true
# (default)." That proxy is a plain socket on the host, and the host
# firewall's input rules apply to it: such a port answered on v4 and was
# silent on v6, measured three times on two servers (docs/RECORD.md 4.200,
# 4.210 case 1a, 4.237).
# On a network made with IPv6 the port answered past ufw on both families
# (4.210 case 1b). So neither the family nor the publication says which it is,
# and the kernel's rules do: a real server with Docker 29.8.2 and one port
# published on its default bridge held the rule naming that port in `ip nat
# DOCKER` and an empty `ip6 nat DOCKER` (read 2026-10-11).
#
# Three answers, because a rule that was not read is not a rule that is not
# there. "Cannot say" is drawn as Docker's port always was.
DOCKER_REWRITES = "rewrites"
DOCKER_REWRITES_NOTHING = "nothing"
DOCKER_CANNOT_SAY = "cannot say"


def legacy_rules_of(doc, family):
    """How many legacy x_tables rules the host has on this family.

    The agent stores those by match name only (`site/app/packetpath.py`), so
    Docker's rule may be among them and its port cannot be read.
    """
    section = pp._mapping(doc.get("iptables" if family == "v4" else "ip6tables"))
    return sum(len(pp._dicts(chain.get("rules")))
               for table in pp._dicts(section.get("tables"))
               for chain in pp._dicts(table.get("chains")))


def docker_rewrite(doc, path, protocol, port, family):
    """One of the three answers above for this port and family. `path` is the
    walk of this port on this family.

    Read from the chains of Docker's own that the walk reached in the stage
    before routing, which is where a publish is written. A rule there that
    names this port is the rewrite. A rule there whose port cannot be read
    may be it, and so may a rule the walk never got to and a legacy rule, so
    each of those is "cannot say". Only a ruleset that was read to its end
    and holds no such rule is "nothing".

    A chain is Docker's by its name, `DOCKER` and the like, or by standing in
    a table of Docker's: with its nftables backend "Docker creates two tables,
    ip docker-bridges and ip6 docker-bridges" (Docker's page on that backend,
    read 2026-10-11). No document from that backend has been read here, so
    what its rules look like is not assumed: one this cannot read a port from
    is "cannot say" like any other.
    """
    unread = not path.get("walked_all", False)
    for stage in path.get("stages") or []:
        if stage.get("hook") != "prerouting":
            continue
        for group in stage.get("groups") or []:
            for entry in group.get("entries") or []:
                table = str(entry.get("table") or "").split(" ")[-1]
                for step in entry.get("steps") or []:
                    chain, text = step[0], step[1]
                    if not kernel_tool_name(table, chain).startswith("docker"):
                        continue
                    named = pp.named_dport(text)
                    if named is None:
                        unread = True
                    elif named[1] == port and named[0] in ("", protocol):
                        return DOCKER_REWRITES
    if unread or legacy_rules_of(doc, family):
        return DOCKER_CANNOT_SAY
    return DOCKER_REWRITES_NOTHING


def ufw_path_tool(section, protocol, port, family, reported):
    """ufw as a box: what it has for this port, and its own default."""
    label = f"{port}/{protocol}"
    rules, hits = [], []
    for parts, families, lines, _comment in merged_ufw_rules(section):
        if parts is None:
            continue
        words, machine = from_words(parts.source)
        everybody = words == ANYWHERE
        on = ufw_interface_words(parts)
        # The box on the flow holds about twenty characters, and "allow 443,
        # anywhere, on wt0" lost its interface behind the ellipsis. For a
        # rule from anywhere the interface is what narrows it, so the box says
        # that alone. The panel and the list under it say both.
        short = on if on and everybody else words
        if on:
            words = f"{words}, {on}"
            if short != on:
                short = words
        # The path is a packet coming in. A rule for outgoing traffic is not
        # on its way, so it is never the box's rule, and in the list it says
        # which way it faces, the way a provider's outgoing rule does.
        outgoing = ufw_is_outgoing(parts)
        hit = (not outgoing and ufw_port_names(parts.port, port)
               and family in families)
        rules.append({"action": f"{parts.action} out" if outgoing else parts.action,
                      "port": port_text(parts.port),
                      "protocol": parts.protocol if parts.protocol != "any" else "",
                      "families": tuple(families), "from": words, "hit": hit,
                      "quote": lines[0][1] if lines else ""})
        if hit:
            hits.append((parts, words, short, everybody))
    # The rule the box names: one that holds for every source when there is
    # one, else the first that names the port. A rule for one address written
    # above a rule for everybody is not what the port's answer rests on.
    mine = next((h for h in hits if h[3]), hits[0] if hits else None)
    if ufw_rules_refused(section):
        finding, facts = "not readable", [(f"for {label}", "not readable", True)]
    elif mine is None:
        finding, facts = f"no rule for {port}", [(f"for {label}", "no rule", True)]
    else:
        finding = f"{mine[0].action} {port}, {mine[2]}"
        if mine[0].action == "allow" and not mine[3]:
            # An allow for one source lets that source in and nobody else.
            # Written out on the flow it read as the rule that let the
            # prober's packet through, from another address (the sweep of
            # 2026-09-21, C4 in docs/RECORD.md 4.199). The rule keeps its own
            # row in the list below, with its source.
            finding = PERMITS_SOME
        facts = [(f"for {label}",
                  theme.status("off", mine[0].action)
                  + f"<span>{tpl.esc(mine[1])}</span>", False)]
    for word, value in ufw_defaults(section):
        facts.append((f"default {word}", value, False))
    return {"kind": "host", "name": "ufw", "mark": "linux-logo", "where": "",
            "finding": finding, "facts": facts, "rules": rules}


def firewalld_zone_of_chain(chain, zones):
    """Which of `zones` a chain of firewalld's own table belongs to, or "".

    A zone's chain is `filter_IN_<zone>` and its parts carry a suffix, the way
    `filter_IN_public_allow` does. The longest name wins, so a chain of a zone
    named `work_allow` is never taken for one of `work`.
    """
    best = ""
    for zone in zones:
        base = f"filter_IN_{zone}"
        if (chain == base or chain.startswith(base + "_")) and len(zone) > len(best):
            best = zone
    return best


# A rule of a zone's chain that opens one port to whoever the zone takes:
# the protocol, the port, and accept. The second form is how firewalld 0.9.11
# writes every port it opens (docs/RECORD.md 4.244). Anything else on the rule
# is a condition this page does not put into words, and the box then says the
# kernel names the port and quotes the rule.
_FIREWALLD_PLAIN_ACCEPT = re.compile(
    r"^(?:meta l4proto (?:tcp|udp) )?(?:tcp|udp) dport \d+"
    r"(?: ct state \{ new, untracked \})? accept$")


def firewalld_kernel_rule(path, in_effect):
    """The rule of firewalld's own kernel table that names this port on the
    way in: `(zone, rule text)`, or None. The zone is "" for a rule that
    stands in no zone's chain, which is one of firewalld's policies.

    **firewalld's files name a service and the kernel names its port.** A
    zone file says `ssh`, and which port that is stands in firewalld's own
    service files, which the agent does not read. So read from the files
    alone, this box said "no rule for 22" on a server whose only way in was
    firewalld's ssh service, and the same for a port opened at runtime, which
    is in no file at all (a Fedora 44 server's document, docs/RECORD.md
    4.343). The kernel's table holds the port either way, and the walk of this
    port has already been through it.

    With no zone known to be in effect the rule is still found, in no zone:
    firewalld's table naming the port is a fact whichever zone holds it, and
    the caller quotes it without putting it into words.

    **The rule everybody's packet meets answers, not the first one found.**
    A zone entered for a source stands before the interface's zone in the
    kernel's way into the zones. Taking the first rule that names the port,
    this box said firewalld lets 22 in from 192.0.2.0/24 only, on v6 too, on
    a server whose zone public let everyone in on both families (second big
    test, 2026-10-25, case C7). The jumps that lead to a rule count with it
    (docs/PRODUCT.md 8d): a rule behind a narrowing jump is the answer only
    when no rule is reached without one, and a rule behind a jump this
    family never takes is not there at all.
    """
    in_effect = in_effect or {}
    narrowed = None
    for chain, text, claim, jumps in firewalld_steps_on_the_way_in(path):
        if claim != pp.NAMES_PORT:
            continue
        way = firewalld_way_in(path, jumps)
        if way is None:
            continue
        found = firewalld_zone_of_chain(chain, in_effect), text
        if way == "unconditional":
            return found
        if narrowed is None:
            narrowed = found
    return narrowed


def firewalld_steps_on_the_way_in(path):
    """Every step the walk took through firewalld's own table on the way in,
    each with the jumps that led to it: `(chain, text, claim, jumps)`.

    The walk goes depth first and a jump's own step comes just before the
    steps of the chain it enters, so the jumps above a step are the last
    step met at each smaller depth.
    """
    for stage in path.get("stages") or []:
        if stage.get("hook") != "input":
            continue
        for group in stage.get("groups") or []:
            for entry in group.get("entries") or []:
                if str(entry.get("table") or "") != " ".join(FIREWALLD_TABLE):
                    continue
                above = []
                for chain, text, _rendered, _comment, claim, depth in entry.get("steps") or []:
                    del above[depth:]
                    yield str(chain), str(text), claim, list(above)
                    above.append(str(text))


def firewalld_way_in(path, jumps):
    """How a packet of the walk's family meets what stands behind `jumps`:
    `unconditional`, `narrowed`, or None when it never does. The join
    engine's own reading of a jump's condition, so the box and the state
    agree on it."""
    return joinbridge.load()._path_shape(jumps, path.get("protocol"), path.get("port"),
                                         path.get("family"))


def firewalld_zones_this_family_enters(path, names):
    """Which of the zone `names` a packet of the walk's family can be sent
    into. A zone entered only through lines this family never takes, `ip
    saddr 192.0.2.0/24 goto filter_IN_internal` for a v6 packet, is left
    out. A zone the walk shows no line for is kept, because nothing was read
    that says otherwise.
    """
    ways = {}
    for chain, text, _claim, jumps in firewalld_steps_on_the_way_in(path):
        if chain not in FIREWALLD_DISPATCH_CHAINS:
            continue
        found = _FIREWALLD_ENTERS_ZONE.match(text.strip())
        if found:
            ways.setdefault(found.group("zone"), []).append(
                firewalld_way_in(path, jumps + [text]))
    return [name for name in names
            if name not in ways or any(way is not None for way in ways[name])]


def firewalld_path_tool(section, protocol, port, family, in_effect=None, path=None):
    """firewalld as a box: the zones in effect read for this port, and the
    kernel's own rule for it when the files name none.

    `in_effect` is `firewalld_zones_in_effect`'s answer and `path` the walk
    of this port. With `in_effect` None the kernel did not say which zones
    apply, and every zone's file is read as before.
    """
    label = f"{port}/{protocol}"
    zones = firewalld_loaded_zones(pp._dicts(section.get("zones")))
    if in_effect is not None:
        entered = firewalld_zones_this_family_enters(path or {}, list(in_effect))
        zones = [z for z in zones if str(z.get("name") or "") in entered]
    rules, mine, zone = [], None, ""
    for z in zones:
        for action, rport, rproto, _fams, frm, machine, note in firewalld_zone_rules(z):
            hit = (str(rport) == str(port) and (not rproto or rproto == protocol))
            rules.append({"action": action, "port": rport, "protocol": rproto,
                          "families": (), "from": frm, "hit": hit, "quote": note})
            # A zone that takes everybody answers before one that takes some
            # sources, whichever file came first.
            if hit and (mine is None or (mine[1] != ANYWHERE and frm == ANYWHERE)):
                mine, zone = (action, frm), str(z.get("name") or "")
    quoted = None
    if mine is None:
        # No file names the port. The kernel may: a service's port, or a port
        # opened at runtime.
        found = firewalld_kernel_rule(path or {}, in_effect)
        if found is not None:
            zone, text = found
            held = next((z for z in zones if zone and str(z.get("name") or "") == zone), None)
            if held is not None and _FIREWALLD_PLAIN_ACCEPT.match(text):
                # Who the zone takes is in its own file: its sources, or
                # anywhere when it has none.
                sources = [str(a) for a in (held.get("source_addrs") or []) if str(a)]
                frm = ANYWHERE if not sources else (
                    sources[0] if len(sources) == 1 else SOME_ADDRESSES)
                mine = ("allow", frm)
            else:
                quoted = text
    if quoted is not None:
        finding = f"names {port}"
        facts = [(f"for {label}", f'<span class="mono">{tpl.esc(quoted)}</span>', False)]
    elif mine is None:
        finding, facts = f"no rule for {port}", [(f"for {label}", "no rule", True)]
    else:
        finding = f"{mine[0]} {port}, {mine[1]}"
        if mine[0] == "allow" and mine[1] != ANYWHERE:
            # The same reading as ufw's box: an allow for some sources is not
            # the rule that let everybody's packet through.
            finding = PERMITS_SOME
        facts = [(f"for {label}",
                  theme.status("off", mine[0]) + f"<span>{tpl.esc(mine[1])}</span>",
                  False)]
    if not zone and in_effect is not None:
        # No rule to name a zone by, so the zones whose rules were read are
        # named: "no rule" is a statement about them and about no other.
        zone = ", ".join(str(z.get("name") or "") for z in zones
                         if firewalld_zone_rules(z))
    return {"kind": "host", "name": "firewalld", "mark": "linux-logo",
            "where": f"zone {zone}" if zone else "", "finding": finding,
            "facts": facts, "rules": rules}


# Which tool a kernel table belongs to when no named firewall wrote its chain.
# A table with one of these names is that tool's own, and a table with a plain
# kernel name belongs to nobody.
PLAIN_KERNEL_TABLES = ("filter", "nat", "mangle", "raw", "security")


def kernel_tool_name(table_name, chain_name):
    """The tool that owns this table and chain, or "".

    `kernel_chain_author` is the same judgement the Rules tab makes. Where it
    names nobody, a table with a name of its own is that tool: crowdsec and
    fail2ban both write one. A plain kernel table is nobody's.
    """
    named = kernel_chain_author(table_name, chain_name)
    if named:
        return named
    name = str(table_name or "")
    return "" if name in PLAIN_KERNEL_TABLES or not name else name


def other_kernel_tools(path, drawn):
    """Any other tool the walk met, one box each, in the order it met them.

    `drawn` is the tools already on the path, so ufw and docker are not drawn
    twice: their rules are in the kernel and the box above already quoted them.
    """
    out, seen = [], set(drawn)
    for stage in path.get("stages") or []:
        for group in stage.get("groups") or []:
            for entry in group.get("entries") or []:
                table = str(entry.get("table") or "")
                name = table.split(" ")[-1] if table else ""
                tool = kernel_tool_name(name, entry.get("chain"))
                if not tool or tool in seen:
                    continue
                seen.add(tool)
                port = path["port"]
                rules, mine, unread = [], None, []
                for _chain, text, rendered, _comment, _verdict, _depth in entry.get("steps") or []:
                    claim, readable = pp.rule_port_claim(text, rendered)
                    unread.append((text, readable))
                    proto, _, number = claim.partition("/")
                    if not number:
                        proto, number = "", claim
                    hit = number == str(port)
                    rules.append({"action": pp.rule_verdict(text) or "",
                                  "port": port_text(number), "protocol": proto,
                                  "families": (), "from": text, "hit": hit,
                                  "quote": text})
                    if hit and mine is None:
                        mine = text
                label = f'{port}/{path["protocol"]}'
                # A rule this page could not fully read is not a rule saying
                # nothing about this port. Saying "no rule" over one would be
                # a measurement nobody took.
                hazy = any(not readable for _text, readable in unread)
                if mine is not None:
                    finding = f"names {port}"
                    facts = [(f"for {label}",
                              f'<span class="mono">{tpl.esc(mine)}</span>', False)]
                elif hazy:
                    finding = "not fully read"
                    facts = [(f"for {label}", "a rule was not fully read", True)]
                else:
                    finding = f"no rule for {port}"
                    facts = [(f"for {label}", "no rule", True)]
                out.append({"kind": "other", "name": tool, "mark": "hard-drives",
                            "where": f"table {name}" if name else "",
                            "finding": finding,
                            "facts": facts, "rules": rules, "tool": tool})
    return out


def path_stop_tool(path):
    """Which tool the document says ends the journey, or "".

    Read from `packetpath.checkpoint_notes`, which is the module's own answer
    about one base chain, and resolved to a tool by the same judgement the
    Rules tab uses. A note whose chain belongs to nobody resolves to nobody,
    and the caller then draws `lost` rather than blaming a tool.
    """
    for stage in path.get("stages") or []:
        for group in stage.get("groups") or []:
            for entry in group.get("entries") or []:
                notes = pp.checkpoint_notes(entry)
                table = str(entry.get("table") or "")
                name = table.split(" ")[-1] if table else ""
                # A rule that ends it: the note quotes the rule, and the step
                # carries the chain that rule actually sits in, which is the
                # precise answer. ufw's drop lives in `ufw-user-input` and is
                # only reached through the base chain, so attributing it to the
                # base chain would name the kernel where ufw is the author.
                ends = {quote for key, quote in notes
                        if key == pp.ENDS_ON_THIS_PORT and quote}
                for step in entry.get("steps") or []:
                    chain, text = step[0], step[1]
                    if text not in ends:
                        continue
                    tool = _path_tool_of(name, table, chain)
                    if tool:
                        return tool
                # A policy that ends it belongs to the base chain itself.
                if any(key == pp.POLICY_ENDS for key, _quote in notes):
                    tool = _path_tool_of(name, table, entry.get("chain"))
                    if tool:
                        return tool
    return ""


def _path_tool_of(table_name, table_label, chain):
    """Which tool owns this chain, or "" when nobody has said.

    `the host firewall` is the one plain name that maps to a box here, and it
    is a decision somebody wrote down in `build.PLAIN_CHAIN_NAMES` rather than
    a guess from the spelling. The full table label is the key that vocabulary
    is written in, `inet filter input`, not the bare table name.
    """
    tool = kernel_tool_name(table_name, chain)
    if tool:
        return tool
    if tpl.plain_chain_name(f"{table_label} {chain}") == "the host firewall":
        return "host"
    return ""


# The IPv6 wildcard. The same constant the engine holds as `join.V6_WILDCARD`.
V6_WILDCARD = ipaddress.IPv6Address("::")


def wildcard_v6_sockets(by_family):
    """A port's sockets on the IPv6 wildcard, `::`, out of `pp.sockets_on`'s
    answer.

    Such a socket may be taking the port's v4 connections as well. Whether it
    does is `IPV6_V6ONLY`, which the document does not carry, so on v4 it is
    neither an owner nor an absence (docs/PRODUCT.md 8a). The engine answers
    the same question with `join._wildcard_sockets`, and this reads the
    address the same way: the address itself, compared as an address.
    """
    found = []
    for socket in by_family.get("v6") or []:
        try:
            if ipaddress.ip_address(str(socket.get("bind_address") or "")) == V6_WILDCARD:
                found.append(socket)
        except ValueError:
            continue
    return found


def path_sockets(doc, protocol, port, family):
    """The sockets a path of this family ends at. On v4, with no v4 socket,
    that is the port's sockets on the IPv6 wildcard: the prober's v4
    connection to such a port is answered by one of them or by nothing."""
    by_family = pp.sockets_on(doc, protocol, port)
    sockets = by_family[family]
    if not sockets and family == "v4":
        return wildcard_v6_sockets(by_family)
    return sockets


def path_destination(doc, protocol, port, family, connected, declared="",
                     held=None):
    """What is at the right end: a socket, a container, or nothing.

    `declared` is the name somebody gave this port, which the page prefers and
    always says was given rather than measured (docs/PRODUCT.md 8b).

    `held` is Docker's box for this port where it was left off the path,
    because Docker rewrites nothing for the port on this family. The socket
    at the end is then the one Docker holds for the container, and no box
    names that container, so the end's panel does. With no socket either,
    the publication reaches nothing on this family and the end says nothing
    listens.
    """
    sockets = path_sockets(doc, protocol, port, family)
    container_facts = []
    if held:
        container_facts = [("container", held["container"]),
                           ("in the container", held["inside"])]
    if sockets:
        socket = sockets[0]
        process = str(socket.get("process_name") or "")
        if declared:
            facts = [("on", _address_and_port(socket.get("bind_address", ""), port)),
                     ("you named it", declared)]
            if process:
                facts.append(("process", process))
            return {"kind": "socket", "name": declared,
                    "on": _address_and_port(socket.get("bind_address", ""), port),
                    "word": "reaches" if connected else "listening",
                    "facts": facts + container_facts}
        pid = socket.get("pid")
        bind = _address_and_port(socket.get("bind_address", ""), port)
        facts = [("on", bind)]
        if process:
            facts.append(("process", f"{process}, pid {pid}" if pid else process))
        facts.append(("families", " and ".join(
            f for f in FAMILIES if pp.sockets_on(doc, protocol, port)[f]) or family))
        return {"kind": "socket", "name": process or bind, "on": bind,
                "word": "reaches" if connected else "listening",
                "facts": facts + container_facts}
    found = None if held else family_publication(doc, protocol, port, family)
    if found is not None:
        runtime, container, published = found
        cname = str(container.get("name") or container.get("id") or "")
        image = str(container.get("image") or "")
        inside = f'{published.get("container_port", "")}/{protocol}'
        return {"kind": "container", "name": cname,
                "on": f"{runtime}, {inside} in the container",
                "word": "published to",
                "facts": [("on", _address_and_port(published.get("host_ip", ""), port)),
                          ("image", image), ("in the container", inside)]}
    # A firewall permits the port and nothing listens. The end names no
    # service, because there is none to name (SPEC.md leaves this to the
    # builder).
    return {"kind": "socket", "name": f"{port}/{protocol}", "on": "",
            "word": "nothing listens",
            "facts": [("listening", "nothing")]}


def path_tab_body(doc, name="host", cache=None, names=None, findings=(),
                  provider=None, now=None):
    """One box per tool for each port and family, in the order a packet from
    outside meets them (docs/screens/host-packet-path/SPEC.md).

    A port bound only on loopback is not on the picker: no packet from outside
    reaches it at all, so there is no path to draw.
    """
    now = now or datetime.now(timezone.utc)
    cache = {} if cache is None else cache
    outside_by_port = {(f.protocol, f.port, f.family): f.outside for f in findings}
    nft = pp._mapping(doc.get("nftables"))
    if nft.get("status") == NOT_READABLE:
        return ('<div class="sec"><div class="panel"><div class="agree">The nftables '
                "section of this host's document could not be read, so no ruleset was "
                'walked. How each layer read is on the Evidence tab.</div></div></div>')
    if nft.get("status") != "collected":
        status = str(nft.get("status", "not collected")).replace("_", " ")
        return ('<div class="sec"><div class="panel"><div class="agree">The nftables '
                f"ruleset read as {tpl.esc(status)} on this host, so there is no ruleset "
                'to walk. How each layer read is on the Evidence tab.</div></div></div>')
    # A host whose sockets could not be read is not a host with nothing bound,
    # and the difference is the whole point of saying which it is.
    if pp._mapping(doc.get("sockets")).get("status") == NOT_READABLE:
        return ('<div class="sec"><div class="panel"><div class="agree">The listening '
                "sockets on this host could not be read, so which ports have a path "
                'is not known. How each layer read is on the Evidence tab.</div></div></div>')
    ufw = pp._mapping(doc.get("ufw"))
    fwd = pp._mapping(doc.get("firewalld"))
    # ufw stands on a packet's way unless its own file says it is off: then
    # it filters nothing and is no box (docs/RECORD.md 4.454). It stood on
    # every path of a server where it was installed and never enabled, as
    # "no rule for 8410" (docs/RECORD.md 4.220). A file that does not say
    # keeps the box, since only a no takes it away.
    ufw_on_path = ufw.get("status") == "collected" and ufw_enabled_word(ufw) != "no"
    zones_in_effect = firewalld_zones_in_effect(doc)
    reported = ""
    chips, flows = [], []
    for (protocol, port), _reasons in pp.traced_ports(doc):
        by_family = pp.sockets_on(doc, protocol, port)
        published = pp.publications_on(doc, protocol, port)
        # A publication's family is the one the runtime published on:
        # 0.0.0.0 is v4 and :: is v6, which is the same reading
        # `join._publication_family` and the Rules tab already do. A runtime
        # that did not say leaves both, because choosing one would be the
        # inference docs/PRODUCT.md 4b forbids.
        published_families = set()
        for _runtime, _container, entry in published:
            got = PUBLISH_FAMILIES.get(str(entry.get("host_ip") or ""))
            published_families.update(got or FAMILIES)
        for family in FAMILIES:
            # On v4 a socket on `::` counts: it may be what answers there, and
            # until 2026-10-03 a port with no other socket had no v4 path to
            # open at all, beside an Overview that said the prober connected
            # over v4 (docs/RECORD.md 4.347).
            sockets = path_sockets(doc, protocol, port, family)
            if not sockets and family not in published_families:
                continue
            if sockets and all(is_loopback(str(s.get("bind_address", "")))
                               for s in sockets):
                continue
            outside = outside_by_port.get((protocol, port, family))
            word, detail = path_measurement(outside, now)
            path = path_cached(doc, protocol, port, family, cache)
            tools = []
            got = provider_path_tool(provider, name, protocol, port, family)
            if got:
                tools.append(got)
            runtime = runtime_path_tool(doc, protocol, port, family)
            # Docker's box stands on the path of a family only where Docker
            # may be carrying the port there. Where the kernel was read and
            # Docker rewrites nothing for it, the packet goes to the socket
            # Docker holds like any other packet for this machine: no box of
            # Docker's, the host firewall an ordinary box, and the end the
            # socket (docs/RECORD.md 4.237). `held` keeps what the end needs
            # to name the container.
            held = None
            if runtime and runtime.get("runtime") == "docker" and docker_rewrite(
                    doc, path, protocol, port, family) == DOCKER_REWRITES_NOTHING:
                held, runtime = runtime, None
            if runtime:
                tools.append(runtime)
            if ufw_on_path:
                tools.append(ufw_path_tool(ufw, protocol, port, family, reported))
            elif fwd.get("status") == "collected":
                tools.append(firewalld_path_tool(fwd, protocol, port, family,
                                                 zones_in_effect, path))
            drawn = {t.get("runtime") or t.get("tool") or
                     ("ufw" if t["name"] == "ufw" else
                      "firewalld" if t["name"] == "firewalld" else t["name"])
                     for t in tools}
            if held:
                # Left off on purpose, so not to be drawn as "also in the
                # kernel" either.
                drawn.add(held["runtime"])
            tools += other_kernel_tools(path, drawn)
            # A tool the packet never meets. Docker accepts a published port in
            # the kernel's forward chain ahead of ufw's rules and an accept
            # ends the walk there, so on a Docker port ufw is not reached
            # (docs/PRODUCT.md 4d). Rootful Podman is the opposite and ufw
            # decides, so it is not a ghost there. Docker's box is on this
            # path only where Docker rewrites the port on this family or the
            # document cannot say, see `docker_rewrite`.
            if runtime and runtime.get("runtime") == "docker":
                for tool in tools:
                    if tool["kind"] == "host":
                        tool["state"] = "ghost"
                        tool["finding"] = "not reached"
            stop = path_stop_tool(path) if word == "no answer" else ""
            fate = {"answered": "reach", "refused": "refused",
                    "not probed yet": "none"}.get(word, "lost")
            # The provider is drawn first, and with no rule for this port its
            # own default ends the journey there (Hetzner's firewall overview,
            # read 2026-09-09, the box's "without a rule: deny"). A host rule
            # behind it was marked instead, a box the packet never reaches
            # (the sweep of 2026-09-21, C6 in docs/RECORD.md 4.199).
            if word == "no answer" and tools and tools[0]["kind"] == "provider" \
                    and tools[0]["finding"] == f"no rule for {port}":
                stop = "provider"
            if word == "no answer" and stop:
                for i, tool in enumerate(tools):
                    key = (tool.get("runtime") or tool.get("tool")
                           or ("host" if tool["kind"] == "host" else tool["name"]))
                    if key == stop or (stop == "host" and tool["kind"] == "host") \
                            or (stop == "provider" and tool["kind"] == "provider") \
                            or tool["name"].lower() == stop:
                        # A box the packet never meets does not end its
                        # journey. The chain the document marks is this
                        # tool's, and a packet Docker rewrites is forwarded
                        # past it, so nobody is marked and the packets fade.
                        # Until 2026-10-11 the box read "not reached" on the
                        # rail and "ends its journey here" in its panel
                        # (docs/RECORD.md 4.237).
                        if tool.get("state") == "ghost":
                            break
                        tool["state"] = "stop"
                        fate = "stop"
                        # A tool after the one that ends the journey is never
                        # reached either (SPEC.md).
                        for later in tools[i + 1:]:
                            later["state"] = "ghost"
                            later["finding"] = "not reached"
                        break
            # A port with nothing on its way keeps its path: from outside,
            # the line, and where it ends. Until 2026-10-12 it had none, and a
            # server with no firewall read "nothing is bound to a network
            # address" over ports that are bound and answer
            # (docs/RECORD.md 4.454).
            vantage = (outside.vantage if outside is not None else "") or "the prober"
            chips.append(f"{port}/{protocol} {family}")
            flows.append(tpl.path_example_html(
                path_flow_uid(name, len(flows)),
                {"port": port, "protocol": protocol, "families": (family,),
                 "word": word, "detail": detail, "fate": fate, "tools": tools,
                 "vantage": vantage,
                 "address": vantage_address(vantage, family),
                 "dest": path_destination(doc, protocol, port, family,
                                          fate == "reach",
                                          (names or {}).get((protocol, port), ""),
                                          held)}))
    if not chips:
        return ('<div class="sec"><div class="panel"><div class="agree">No port on this '
                'host has a path from outside: nothing is bound to a network address and '
                'no container publishes one.</div></div></div>')
    # The agent stores a legacy iptables rule by match name only, so it can be
    # counted and never placed on a port (`site/app/packetpath.py`). Counted
    # under the flow rather than drawn as a box on it.
    legacy = pp.legacy_rule_count(doc)
    line = ""
    if legacy:
        line = (f'<div class="pt-meas">{tpl.esc(n_of(legacy, "legacy iptables rule"))}'
                ", not placed on a port</div>")
    return tpl.walk_picker_html(path_chips_uid(name), chips, flows) + line


# Every server's page is in one document, so a chip's or a box's id has to be
# unique across all of them, and so does a radio group's name, since checking
# a radio unchecks every other radio of its name in the document. Until
# 2026-10-27 the chips were `pp-<name>-<n>` and the boxes `pp-<name>-<path>-<box>`,
# so the chips of a server named "box-2" had the ids of the boxes of "box"'s
# third path, and a server installed again beside its old row is named just
# that (the -2 suffix in controlplane/app/store.py). Its chips reached the old
# server's boxes and did nothing (second big test, 26 October). A letter now
# says which kind each id is, c for the chips and p for a path.
# test_path_ids_per_server.py holds it, with server names that end the way
# another server's ids end.
def path_chips_uid(name):
    """The chips' radio group, `<uid>`, and their ids, `<uid>-<n>`."""
    return f"pp-{name}-c"


def path_flow_uid(name, index):
    """One path's radio group, `<uid>`, and its boxes' ids, `<uid>-<box>`."""
    return f"pp-{name}-p{index}"


def alert_raised_text(rows):
    """When this host's oldest open alert was raised, or empty.

    One row shows one mark, so the oldest is the one it names: it is the one
    that has been open longest and the newest would keep resetting the time a
    reader is watching. **Where the alert went is not read here.** It is a
    fact per alert and a server can have several open, so it is said on the
    Alerts screen, where each of them has its own row.
    """
    times = [datetime.fromisoformat(r["raised_at"]) for r in rows]
    return min(times).strftime("%d %b %H:%M") if times else ""


def alert_port(subject):
    """The (protocol, port, family) an alert is about, or None.

    A finding alert's subject is what `controlplane/app/finding_alerts.py`
    writes with `subject_for`, which is `tcp/443 v6`. The dead-man switch has
    one stream per host and writes no subject at all, so None is the ordinary
    answer here and not an error.

    **Put through `intent.normalise`, which is the door the route on the other
    end goes through** (`controlplane/app/ingest.py`, `_port_key`). Splitting
    the string here and trusting the halves was the first version and it was
    wrong: `https/443 v6` parses perfectly and is not a protocol the store
    accepts, so the menu would have been drawn and every click on it refused
    with a 400 nobody could act on. Asking the same module the route asks
    means a control is only ever drawn for a port the route will take.

    **A subject this cannot read comes back as None rather than raising.** The
    column is text and an older build or a hand-written row could hold
    anything, and the cost of getting it wrong is one control missing from a
    row rather than a screen that will not draw at all.
    """
    if not subject:
        return None
    where, _, family = subject.partition(" ")
    protocol, _, port = where.partition("/")
    if not port.isdigit():
        return None
    intent = joinbridge.module("intent")
    try:
        return intent.normalise(protocol, int(port), family)
    except intent.IntentError:
        return None


# The channel type, as the icon map spells it. A label is the operator's own
# word and has no glyph, so the type is what the glyph is looked up under.
#
# A type missing from here falls back to the default glyph rather than raising,
# which is `named_rows_html`'s rule and the reason it has one (docs/RECORD.md
# 4.89). All five that can be stored are listed anyway, because a real mark is
# most of what makes a row scannable.
CHANNEL_TYPE_ICON = {"webhook": "Webhook", "email": "Email", "slack": "Slack",
                     "telegram": "Telegram", "discord": "Discord"}

# What a person calls the channel, as against what the database stores. Only
# one of the five differs and it is worth the map anyway: "Microsoft Teams" is
# coming and will differ too.
CHANNEL_TYPE_WORD = {"webhook": "Webhook", "email": "Email", "slack": "Slack",
                     "telegram": "Telegram", "discord": "Discord"}

def channel_word(key):
    """What a channel is called on screen, from what the delivery row stored.

    A stored key is `type:ENVVAR` and may carry a third part, so the type is the
    prefix. The variable and anything after it never reach a screen
    (docs/RECORD.md 4.87). Mail is not in that table at all and arrives here as
    the bare type. A type this map has never heard of is printed as it was
    stored rather than raising, the same fallback the icon map takes.
    """
    kind = key.split(":", 1)[0]
    return CHANNEL_TYPE_WORD.get(kind, kind)

# ------------------------------------------------ the Alerts screen's lines
# docs/screens/alerts/SPEC.md: a state word on the tag, a few grey words of
# why, and never the sweep's sentence. The sentence is what the alert stores
# (`controlplane/app/finding_alerts.py` `_detail`, `controlplane/app/alerts.py`
# for the silent kind), so it is read back here into the words the screen
# shows. A detail this cannot read falls back to the stored kind, so an older
# row draws a line rather than breaking the page.

# "tcp/443 on v6 was closed, now open" or "tcp/443 on v6 had no state, now open"
DETAIL_RE = re.compile(r"^(\w+)/(\d+) on (v4|v6) (?:was (.+?)|had no state), now (.+)$")
# A different program answering a port that already has an answer, told once
# and never open (`controlplane/app/finding_alerts.py`, `_one_program`). The
# state did not move and it is `intended`, so the tag says reachable like any
# answered port, and the why is the two programs.
PROGRAM_RE = re.compile(r"^(\w+)/(\d+) on (v4|v6) program was (.+?), now (.+)$")

# The word the tag carries, and its tone on Open now, by the state the port
# went to. `unreviewed`, `unexplained` and `intended` all mean the port answers
# from outside, which is what the reader wants to know before the why says
# which of the three it is.
ALERT_WORDS = {
    "conflict": ("conflict", "fail"),
    "unreviewed": ("reachable", "warn"),
    "unexplained": ("reachable", "warn"),
    "intended": ("reachable", "warn"),
    "not reachable": ("unreachable", "off"),
    "stale rule": ("unreachable", "off"),
    "": ("reachable", "warn"),
}
KIND_WORDS = {
    "silent": ("silent", "warn"),
    "outside view stale": ("stale", "off"),
    # Drawn on Sent only, where a tag carries no tone: a CVE message is sent
    # from a batch and is never an open alert.
    "cve": ("cve", "off"),
}
# The why for a conflict is what the operator declared, since a conflict is
# the measurement disagreeing with that word.
# The Why column's words for a port somebody answered for. The verb is the
# alert message's own label, `you said`, and the values are the message's
# own, so a row here and a message about the same port say one thing in the
# same words (docs/screens/alerts/SPEC-layout-b.md).
DECLARED_WHY = {"closed": "you said closed", "open": "you said reachable"}
STATE_WHY = {"unreviewed": "nobody has said whether it should be",
             "unexplained": "not explained",
             "intended": "reviewed", "stale rule": "rule stale"}
# How the Why column opens for an agent that stopped reporting. The stored
# sentence opens "no report for".
SILENT_STORED = "no report for "
SILENT_WHY = "nothing from the agent for "
# How the sent log's line opens for the message that an agent reports again
# (`controlplane/app/reportingagain.py`, `detail`). The tag says these two
# words, and the Why column the clause after them, which is the silence's
# own: how long nothing came.
AGAIN_STORED = "reporting again"
# How the stored sentence opens for an outside view that went stale
# (`controlplane/app/finding_alerts.py`, `_stale_detail`). The sent log keeps
# the sentence and not the kind, so a Sent line is known to be this kind by
# these words, and its tag says `stale` as the row on Open now does.
STALE_STORED = "no probing pass has finished for "


def parse_detail(detail):
    """(protocol, port, family, before, after) from a finding alert's stored
    sentence, or None for the kinds that have none."""
    m = DETAIL_RE.match(detail or "")
    if m:
        protocol, port, family, before, after = m.groups()
        return protocol, int(port), family, before or "", after
    m = PROGRAM_RE.match(detail or "")
    if m:
        protocol, port, family, _was, _now = m.groups()
        return protocol, int(port), family, "intended", "intended"
    return None


def alert_why(kind, detail, parsed, declared):
    """The few grey words in the Why column. `declared` is what the operator
    said this port and family should be, or empty."""
    if kind == "silent":
        # "no report for 180 minutes, past the 35 minute threshold": the first
        # clause, in the sketch's short unit.
        return _silence_in_short((detail or "").split(",", 1)[0].strip())
    if kind == AGAIN_STORED:
        # "reporting again, no report for 72 minutes": the tag has the first
        # clause, so this is the second, and nothing when there is none.
        return _silence_in_short((detail or "").partition(",")[2].strip())
    program = PROGRAM_RE.match(detail or "")
    if program:
        return f"{program.group(5)}, was {program.group(4)}"
    if parsed is None:
        return (detail or "").split(",", 1)[0].strip()
    _p, _n, _f, before, after = parsed
    if after == "conflict":
        return DECLARED_WHY.get(declared, "not as declared")
    if after in STATE_WHY:
        return STATE_WHY[after]
    return f"was {before}" if before else "had no state"


def _silence_in_short(clause):
    """How long nothing came from an agent, as a Why column says it."""
    clause = clause.replace(" minutes", " min").replace(" minute", " min")
    if clause.startswith(SILENT_STORED):
        clause = SILENT_WHY + clause[len(SILENT_STORED):]
    return clause


def alert_words(kind, parsed):
    """(word, tone) for the tag."""
    if kind in KIND_WORDS:
        return KIND_WORDS[kind]
    if parsed is None:
        return (kind, "warn")
    return ALERT_WORDS.get(parsed[4], (parsed[4], "warn"))


def open_alert_lines(rows, now, silences=None, declarations=None, paused=()):
    """Open alerts as `build.AlertLine`s, newest first.

    A line about a port offers Silence, a silent agent's line offers Pause,
    and a port that went away offers nothing (docs/screens/alerts/SPEC.md).
    A silence stops the mail and the alert stays open (docs/PRODUCT.md 4c).
    `silences` is `load_port_silences`'s answer by host name, `declarations`
    is `load_declarations`'s, and `paused` the names of servers whose
    monitoring is paused.
    """
    silences = silences or {}
    declarations = declarations or {}
    out = []
    for row in rows:
        host = row["host_name"]
        parsed = parse_detail(row.get("detail"))
        port = alert_port(row.get("subject"))
        declared = ""
        protocol, number, families, action = "", "", (), ()
        if parsed is not None:
            protocol, number, family = parsed[0], parsed[1], parsed[2]
            families = (family,)
            declared = declarations.get(host, {}).get((protocol, number), {}).get(family, "")
        word, tone = alert_words(row["kind"], parsed)
        if port is not None and word not in ("unreachable",):
            quiet = port in silences.get(host, set())
            action = ("silence", *port, quiet)
        elif row["kind"] == "silent":
            action = ("pause", host in paused)
        out.append(tpl.AlertLine(
            datetime.fromisoformat(row["raised_at"]), host, word, tone,
            protocol, number, families,
            alert_why(row["kind"], row.get("detail"), parsed, declared), action))
    return out


def channel_destinations(channels):
    """What each delivery key's row shows as its destination, so a Sent line
    can say where it went under the channel's word. Mail is configured on
    the box and has no address this process can read, so it stays bare."""
    out = {}
    for channel, _last, _used, key in channels:
        out[key] = channel.destination_env or channel.destination_hint
    return out


def sent_kind(detail, parsed):
    """The kind of alert a Sent line is about, read from how its stored
    sentence opens, since the sent log keeps the words and not the kind. A
    sentence of no kind known here is its own first clause, so the line is
    still drawn."""
    if detail.startswith("no report"):
        return "silent"
    if detail.startswith(STALE_STORED):
        return "outside view stale"
    # A CVE message's line is its title, which opens with one of two
    # beginnings, read from the module that writes them.
    cvewords = joinbridge.module("cvewords")
    if detail.startswith((cvewords.UPDATE_FIXES + " ", cvewords.NEWER_FIXES + " ")):
        return "cve"
    if parsed is not None:
        return "finding changed"
    return detail.split(",", 1)[0]


def sent_alert_lines(rows, channels=(), declarations=None):
    """The delivery rows as `build.AlertLine`s, in `load_sent`'s order, which
    is newest first. The tag is neutral on Sent, so no tone is set."""
    destinations = channel_destinations(channels)
    declarations = declarations or {}
    out = []
    for row in rows:
        parsed = parse_detail(row["detail"])
        kind = sent_kind(row["detail"] or "", parsed)
        word, _tone = alert_words(kind, parsed)
        protocol, number, families, declared = "", "", (), ""
        if parsed is not None:
            protocol, number, families = parsed[0], parsed[1], (parsed[2],)
            declared = (declarations.get(row["host_name"], {})
                        .get((protocol, number), {}).get(parsed[2], ""))
        out.append(tpl.AlertLine(
            datetime.fromisoformat(row["sent_at"]), row["host_name"], word, "",
            protocol, number, families,
            alert_why(kind, row["detail"], parsed, declared),
            channel=channel_word(row["channel"]),
            destination=destinations.get(row["channel"], ""),
            off=word in ("unreachable",)))
    return out


def alerts_channels_html(channels=(), counts=None):
    """Where alerts go, one row per stored channel, mail included.

    **There was a fixed Email row here until 2026-09-20**, reading "set on the
    server" in every workspace with no menu to remove it, from when mail was
    configured by environment alone (`docs/RECORD.md` 4.86). An account is
    given a stored email row for its own address now, so mail is a row like
    any other (`docs/RECORD.md` 4.186). `counts` is each channel key's
    deliveries of the past 7 days, from `load_sent_counts`.
    """
    counts = counts or {}
    rows = []
    for channel, _last, _used, key in channels:
        # `on` and `off` are the row's own enabled flag, a fact it holds. This
        # runs in the render unit, which has no alerts.env, so it cannot say
        # whether a variable is set and does not pretend to.
        state = theme.status("ok", "on") if channel.enabled else theme.status("off", "off")
        rows.append((CHANNEL_TYPE_WORD.get(channel.type, channel.type),
                     CHANNEL_TYPE_ICON.get(channel.type, channel.type),
                     # Where the alert goes, which is what the column is
                     # headed. `channels.Channel.hint` decides how much shows.
                     (channel.destination_env or channel.destination_hint),
                     "", state, str(counts.get(key, 0)),
                     tpl.row_menu_html(channel.label, enabled=channel.enabled,
                                       channel_type=channel.type,
                                       events=channel.subscriptions)))
    return tpl.channel_rows_html(rows, tpl.NO_DESTINATION_ADDED)


def channel_row_templates_html():
    """A hidden, empty row per channel type, for the browser to clone.

    **Adding a channel used to change nothing on screen until the page was
    reloaded**, which is the one thing a click may not do. The
    browser has to put the new row up itself, and a row it writes from scratch
    is a second copy of this page's markup that drifts from the first one the
    day either is touched.

    So the row is not written twice. Every type gets one `<template>` here,
    drawn by `build.channel_row_html`, which is the same call every visible row
    is drawn by. The browser clones the one whose type the control plane
    answered with and fills in the values. A `<template>` is not rendered and
    its content is not in the document, so this costs the page nothing but its
    bytes.

    **They sit outside every view**, in `build.page`'s own slot, and not in the
    panel that lists channels. A hidden Slack-shaped row inside a panel headed
    "where it goes" reads as a Slack row to anything looking at the markup, and
    several tests here look at exactly that.

    What is in a template is exactly what a channel that was just added looks
    like: it is on, it has delivered nothing, and its destination and its label
    are the two things only the answer knows.
    """
    out = []
    # The types the control plane can store, read from the module that stores
    # them, so a sixth type gets a template the day it is added and never the
    # day somebody remembers. Reached through joinbridge like everything else
    # here, and unguarded for the same reason `load_channels` is: a render that
    # cannot reach the control plane has already failed further up.
    for kind in joinbridge.module("channels").TYPES:
        row = (CHANNEL_TYPE_WORD.get(kind, kind),
               CHANNEL_TYPE_ICON.get(kind, kind),
               "", "", theme.status("ok", "on"), "0",
               # An empty label, because the label is the control plane's to
               # give: the window stopped asking for one and a free label is
               # made from the type (`controlplane/app/ingest.py`). The browser
               # writes it in from the answer.
               tpl.row_menu_html("", enabled=True, channel_type=kind))
        out.append(f'<template class="crow-tpl" data-type="{tpl.esc(kind)}">'
                   f'{tpl.channel_row_html(row)}</template>')
    return "".join(out)


def probed_line(findings, now):
    """The probed cell of the header: how long ago, or the word never."""
    age = probe_age(findings, now)
    return f'<span class="num">{age}</span> ago' if age else "never"


def is_first_look(rows, declared, findings, seen=False):
    """Whether this page is the look the window opens on its own: a port
    waiting for an answer, nothing answered by a person yet, and nobody in
    the account has seen it (the owner, 2026-09-06: once per account). The
    window's title reads from this too, since 2026-10-11, so "First look"
    is said only when the page knows it is one (docs/record 4.451).

    **Only when a port is waiting, since 2026-09-21.** It opened for any
    reachable port, so on a server whose every open port a rule had already
    answered it listed them prefilled YES and asked for a Confirm: nothing in
    it needed anybody, once per server, on every server of a fleet. The owner's
    rule is that nothing here feels like homework (docs/RECORD.md 4.197). The
    window is
    still there under Answer reachable ports.
    """
    waiting = any(group == "waiting" for group, *_rest in first_look_rows(rows))
    return bool(not seen and waiting and not declared
                and not any(f.acknowledged for f in findings))


def first_look_attr(rows, declared, findings, seen=False):
    """The marker the page script reads to open the first-look window on its
    own, from `is_first_look`."""
    return ' data-first="1"' if is_first_look(rows, declared, findings, seen) else ""


def load_first_looks(con, hosts):
    """The names of the hosts whose first look somebody in the account has
    seen. A database the route has never written has no table: nobody has
    seen anything."""
    try:
        seen = {row[0] for row in con.execute("SELECT host_id FROM first_looks")}
    except sqlite3.OperationalError:
        return set()
    return {h["name"] for h in hosts if h["id"] in seen}


def server_fix(cve, silenced=()):
    """The words of the CVE check's own mark for a whole server, from its
    ports' cards, or empty. A port whose mark was dismissed is not in it.

    Neither is a port a silence covers on either family, `silenced` being
    this server's (protocol, port, family) triples. It keeps its own mark
    on its row and leaves the server's count, as an alert a person silenced
    leaves the count beside Alerts (docs/PRODUCT.md 4c). A CVE message
    counts what this mark stands for and asks the same of a silence
    (controlplane/app/cvetell.py), so the two say one number: the second
    big test's G9 had the message count a silenced port's CVEs."""
    if not cve:
        return ""
    return joinbridge.module("cvecard").server_mark(
        card for (protocol, port), (card, dismissed) in cve.items()
        if not dismissed and not any((protocol, port, family) in silenced for family in FAMILY_ORDER))


def host_view(h, newest, story, now, window, names=None, findings=(),
              muted=False, declared=None, transitions=(), silenced=(),
              when=None, changed=(), proof=None, first_seen=False,
              provider=None, vantages=(), raised="", probing=False, tags=(),
              display="", moved_ever=(), dismissed=frozenset(), cve=None):
    """One host's page. The id is host-<name>, which is why a host name is
    restricted to url-safe characters at creation time.

    `names` is this host's declared service names, keyed (protocol, port),
    from load_names. Absent means none are declared, which is also what a
    database from before the port_names table answers.

    `findings` is this host's joined findings from `load_findings`. Empty means
    the engine had nothing to say about this host, and the Evidence matrix then
    shows no rows rather than inventing any.

    `declared` is this host's live port declarations from `load_declarations`,
    keyed (protocol, port). The Overview's rows show them and change them,
    because a declaration is what moves a port off `unreviewed`.

    `muted` is whether a live mute covers this server, from `load_mutes`. It
    decides what the Mute control says, whether its menu offers a way back,
    and whether the mark beside the state word is filled.

    `provider` is the stored provider snapshot from `load_provider`, which is
    fleet-wide. The Rules tab takes this server's own firewalls out of it,
    matched by name the way the join engine matches them.
    """
    name = h["name"]
    live = tone, word = freshness(h, now)
    # Read before the unreadable branch below rewrites the state word. How a
    # server is watched and how its newest document read are two facts, and
    # this one must not be taken from the other.
    mode = monitoring_mode(h, newest)
    facts, first_look, first_attr = "", "", ""
    # The port rows, for the server that has a document to draw them from. A
    # server that never reported, or whose document would not read, has none,
    # and so no port that could carry the rarely-public mark in its header.
    rows = []
    # Scan now is host page only and secondary weight (the owner, docs/PRODUCT.md
    # 5f). It carries the host name so the one dialog on the page knows which
    # host to re-probe. Mark reviewed is gone from this header for good: an
    # acknowledgement is about one finding and never about a whole server
    # (the owner, 2026-08-24), so reviewing lives on the port row and a header
    # button here would be the wrong claim again.
    acts = (tpl.mute_menu_html(name, muted=muted)
            + tpl.scan_button(name))
    hsub = "no document yet"
    if isinstance(newest, Unreadable):
        # The document arrived and would not read, which is not "no document
        # yet" and must never be shown as it. One panel and no tabs, because
        # every tab renders the newest document and none of it can be read.
        live = tone, word = "fail", "not readable"
        hsub = ""
        arrived = (f'<span class="num">{age_text(newest.received_at, now)}</span> ago'
                   if newest.received_at else "&mdash;")
        facts = tpl.host_facts_html(tpl.AGENT_WORD[mode], [
            ("hostname", "&mdash;"), ("agent reported", arrived),
            ("probed", probed_line(findings, now)), ("ports", "&mdash;")], host=name, probing=probing)
        body = ('<div class="sec"><div class="panel"><div class="agree">'
                f'{tpl.esc(DOCUMENT_UNREADABLE)}</div></div></div>')
    elif not newest:
        # No tabs at all rather than seven empty ones. There is one thing to
        # say and the page says it.
        #
        # **Once.** The header's state tag already reads `not watched` and
        # the panel says the same thing in a sentence, so a sub-line reading
        # "no document yet" was a third wording of one fact four lines apart.
        #
        # And the two acts that exist for such a server, since 2026-08-29:
        # a fresh install command, because the add-server window shows the
        # command once and a window closed too early left this page a dead
        # end with no way back to it (the 2026-08-23 audit, control 3), and
        # Remove, which was otherwise unreachable too, because both lived on
        # a Settings tab this page has never had.
        hsub = ""
        facts = tpl.host_facts_html(tpl.AGENT_WORD[mode], [
            ("hostname", "&mdash;"), ("agent reported", "never"),
            ("probed", probed_line(findings, now)), ("ports", "&mdash;")], host=name, probing=probing)
        safe = tpl.esc(name)
        acts_rows = tpl.setting_row(
            "Install command",
            f'<div class="code m-copy js-recred-out" id="rc-{safe}" hidden></div>',
            f'{tpl.button("New install command", "js-recred", data_host=safe)}')
        acts_rows += tpl.setting_row(
            "Remove this server", "",
            f'{tpl.button("Remove", "danger js-remove", data_host=safe, data_name=safe, data_kind="agent")}')
        body = ('<div class="sec"><div class="panel"><div class="agree">No document received from '
                'this host yet.</div></div></div>'
                f'<div class="sec"><div class="panel">{acts_rows}</div></div>')
    else:
        received_at, doc = newest
        listening, _containers, _sections = doc_counts(doc)
        hostname = doc.get("hostname", "")
        unreadable = not_readable_sections(doc)
        # Which agent produced this document, when the document says so. An
        # agent old enough not to carry the field leaves it out rather than
        # reading as unknown, because absent and unknown are different facts
        # and only one of them is measured.
        #
        # It is here because the fleet was upgraded 0.1.5 to 0.1.6 and nothing
        # in the product could confirm it: every host had to be reached over
        # ssh to answer a question about the hosts (docs/RECORD.md 4.89).
        #
        # The section count and the schema version left this line on
        # 2026-08-24 (machinery): a reader needed neither, and
        # an unreadable section is still named in full just below.
        # The five facts under the name (docs/screens/host-overview/SPEC.md
        # section 2). The section count, the agent version and the unreadable
        # sections left this line with the sketch: the Evidence tab names an
        # unreadable section and the rest was machinery.
        rows = host_port_rows(name, doc, findings, names, declared, when,
                              silenced, now, dismissed=dismissed, cve=cve)
        moved_24h = changed_ports(name, transitions, changed, now - timedelta(hours=24))
        hsub = ""
        facts = tpl.host_facts_html(tpl.AGENT_WORD[mode], [
            ("hostname", tpl.esc(hostname) if hostname else "&mdash;"),
            ("agent reported", f'<span class="num">{age_text(received_at, now)}</span> ago'),
            ("probed", probed_line(findings, now)),
            ("ports", f'<span class="num">{len(rows)}</span>')], host=name, probing=probing)
        first = is_first_look(rows, declared, findings, seen=first_seen)
        first_look = tpl.first_look_modal(name, name, first_look_rows(rows, moved_ever),
                                          sum(1 for r in rows if _row_open(r)), first=first)
        first_attr = ' data-first="1"' if first else ""
        changes_tab = changes_tab_body(name, transitions, story, window, now)
        # One cache for the whole host page. The Overview and the Services tab
        # ask the same question of the same ports, so the ruleset is walked once
        # per port and family rather than once per tab.
        walk_cache = {}
        # Three headings left on 2026-08-24, the owner's second declutter round:
        # each one restated the label of the tab it sat under. The sample
        # shell dropped the same three.
        tabs = [
            ("overview", "Overview", host_overview_body(name, rows, moved_24h)),
            ("services", "Services", services_tab_body(name, doc, rows, names)),
            # A planned tab's body is not built - the tuple is the one
            # switch, which is also what lets the tests render the full page
            # with it emptied and keep proving these two renderers work.
            ("rules", "Rules",
             "" if "rules" in tpl.HOST_TABS_PLANNED
             else rules_tab_body(doc, name, provider,
                                 f"{age_text(received_at, now)} ago",
                                 provider_read_words(provider, name, now),
                                 # the same lines the Changes tab lists
                                 changes=host_log(transitions, story))),
            ("evidence", "Evidence",
             evidence_tab_body(name, doc, rows, findings, received_at, now,
                               vantages=vantages, provider=provider)),
            ("path", "Packet path",
             "" if "path" in tpl.HOST_TABS_PLANNED
             else path_tab_body(doc, name, walk_cache, names, findings,
                                provider, now)),
            ("changes", "Changes", changes_tab),
            ("settings", "Settings",
             settings_tab_body(h, doc, mode, declared, proof, silenced, now, tags=tags,
                               display=display)),
        ]
        body = tpl.host_tabs_html(name, tabs)
    # Exactly the word the fleet row shows for this server (SPEC.md section
    # 1), decided by the same function, so the header a reader lands on cannot
    # disagree with the row they clicked. A host whose newest document would
    # not read has no port answer to show, whatever the engine kept from an
    # older document.
    tone_word = fleet_row_word(
        None if isinstance(newest, Unreadable) else worst_port_state(findings), live,
        alert_open=bool(raised))
    return f"""<div class="wrap view" id="host-{name}"{first_attr}>
  <button class="back" data-v="fleet">&larr; Fleet</button>
  <div class="hh">
    {tpl.host_head(f'<span class="hname">{tpl.esc(display or name)}</span>',
                   tpl.state_set_html(name, tone_word, muted, raised,
                                      rarely=any(r.rarely for r in rows),
                                      paused=is_paused(h), fix=server_fix(cve, silenced)),
                   hsub, facts)}
    <div class="acts">{acts}</div>
  </div>
{body}
{first_look}
</div>"""


# ------------------------------------------------------ a host with no agent
#
# The third tier of the 2026-08-24 decision, drawn against the data an address
# host really has (docs/RECORD.md 4.104): no document, so no Services and no
# inside view, and the state words are about its proof and its probes rather
# than about an agent that is not there. Everything below is values, statuses
# and empty-state lines.

def fleet_row_word(port, live, alert_open=False):
    """The one word a fleet row's State cell shows, as (tone, word).

    `fleet_state` decides between the port axis and the liveness axis. The
    Fleet then has one word for a fine server, `watched`, on an agent host and
    an address host alike (SPEC.md section 5), so the engine's own quiet words
    for a port, `intended` and `not reachable`, become that word here. Nothing
    else is renamed: a problem keeps the engine's word.
    """
    primary, _secondary = fleet_state(port, live)
    if primary[1] in tpl.QUIET_PORT_WORDS or primary == tpl.WATCHED:
        # Fine on both axes. It is `watched` only when nothing is open on it:
        # an alert still open is the worse thing to say, and green beside it
        # reads as all clear (the owner, 2026-09-20).
        return tpl.ALERT_OPEN if alert_open else tpl.WATCHED
    return primary


def address_fleet_row(h, findings, proof, now, muted=False, raised="", tags=(),
                      display="", dismissed=frozenset()):
    tone, word, _last = address_freshness(h, proof, findings, now)
    # The same two axes an agent row carries, decided the same way. A host
    # with no agent has fewer facts on the second one, `watched` rather than
    # `reporting`, and none on the inside view at all, but what is reachable
    # on it is measured exactly as it is anywhere else and belongs in the same
    # cell.
    tone, word = fleet_row_word(worst_port_state(findings), (tone, word),
                                alert_open=bool(raised))
    reach, chips = fleet_facts({}, findings, dismissed)
    return tpl.FleetRow(tone, word, h["name"],
                        reach=reach, chips=chips, muted=muted, alert=raised,
                        disagree=any_disagree(findings), tags=tuple(tags),
                        display=display, rarely=bool(rarely_reachable(findings, dismissed)),
                        pending=host_kind(h) != "address" and not h["last_report_at"],
                        paused=is_paused(h))


def answered_ports(doc, declared):
    """The ports somebody answered for, as the Probing list draws them:
    [(protocol, port, sub)], escaped, in port order. The line under each is
    the service the agent reports on it and what was declared. The sample
    draws its list with this too (sample_story.py)."""
    services = {}
    if isinstance(doc, dict):
        for s in pp._dicts(pp._mapping(doc.get("sockets")).get("listening")):
            key = (s.get("protocol"), s.get("port"))
            if s.get("process_name") and key not in services:
                services[key] = s["process_name"]
    ports = []
    for (protocol, port) in sorted(declared or {}, key=lambda key: (key[1], key[0])):
        word = declared_word(declared[(protocol, port)])
        service = services.get((protocol, port), "")
        sub = f"{tpl.esc(service)}, declared {tpl.esc(word)}" if service else f"declared {tpl.esc(word)}"
        ports.append((tpl.esc(protocol), int(port), sub))
    return ports


def settings_tab_body(h, doc, mode, declared, proof, silences, now, agentless=False,
                      tags=(), display=""):
    """The Settings tab of one server: the five categories of
    docs/screens/host-settings/SPEC.md, each from what the control plane
    stores. `doc` is the read view or None, `declared` the port
    declarations keyed (protocol, port), `proof` this host's proofs of
    control, `silences` {(protocol, port, family): until}, `tags` the words
    a person put on this server, `display` its display name or empty."""
    name = h["name"]
    safe = tpl.esc(name)
    paused = ("paused" in h.keys()) and bool(h["paused"])
    # What the remove window says about the machine: how long ago the agent
    # last reported, and whether it still does, in which case the line is a
    # warning. An address-only server has no agent and gets neither.
    last = "" if agentless else last_report_text(h, now)
    reporting = not agentless and freshness(h, now)[1] == "reporting"
    server = tpl.server_panel(safe, safe, paused, kind="address" if agentless else "agent",
                              last=last, reporting=reporting, tags=tags,
                              display=display)
    # the agent: the read mode, the enrolment date, the version the newest
    # document names
    mode_word = {"full read": "Full read", "partial read": "Limited read",
                 "no agent": "No agent", "agent": "Agent"}.get(mode, mode)
    enrolled = short_date(h["created_at"]) if "created_at" in h.keys() else ""
    version = doc.get("agent_version") if isinstance(doc, dict) else ""
    agent = tpl.agent_panel(safe, tpl.esc(mode_word), tpl.esc(enrolled),
                            tpl.esc(version) if isinstance(version, str) else "")
    probing = tpl.probing_panel(safe, answered_ports(doc, declared), agent=not agentless)
    # the addresses: every proof with its method and its status
    addresses = []
    ours_missing = (proof or {}).get("ours_missing", set())
    for row, live in proofs_to_draw(proof):
        method = tpl.PROOF_METHOD_WORD.get(row["method"] if "method" in row.keys() else "", "")
        status = proof_status(row, live, row["id"] in ours_missing)
        sub = f"{method}, {status}" if method else status
        addresses.append((tpl.esc(row["target"]), tpl.esc(sub), live))
    address_rows = tpl.addresses_panel(safe, addresses)
    # the alerts: the quiet threshold the sweep uses, and the silences
    quiet = joinbridge.module("alerts").SILENT_AFTER_SECONDS // 60
    ends = []
    for (protocol, port, family), until in sorted((silences or {}).items(),
                                                   key=lambda kv: (kv[0][1], kv[0][0], kv[0][2])):
        when = received_at_or_none(until) if until else None
        sub = f"until {when.strftime('%-d %b %H:%M')}" if when else tpl.SILENCE_NO_END
        ends.append((tpl.esc(protocol), int(port), tpl.esc(family), sub))
    alerts = tpl.alerts_panel(safe, quiet, ends, agent=not agentless)
    return tpl.hset_view(safe, [("server", server), ("agent", agent), ("probing", probing),
                                ("addresses", address_rows), ("alerts", alerts)],
                         head={"addresses": tpl.add_address_button(safe)})


def proof_day(value):
    """The day a proof was revoked, ran out or runs to, as its row writes it:
    "3 Sep", with no zero in front, the way the Changes tab writes a day. It
    read "03 Sep" until 2026-10-06 (docs/RECORD.md 4.379)."""
    try:
        when = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return ""
    return f"{when.day} {when.strftime('%b')}"


def proof_yes_words(row):
    """What the window says the moment an address is proved: the address, the
    way and the day, in the two words its row carries, `PROOF_METHOD_WORD`
    and `proof_day`. The registry's own sentence names the way by its code
    word, which is for a command line and not for a screen (docs/RECORD.md
    4.379). Asked for by the verify route, through the bridge that draws the
    page, so the row's words have one owner."""
    way = tpl.PROOF_METHOD_WORD.get(row["method"], "")
    return f"{row['target']} proved by {way} until {proof_day(row['expires_at'])}"


def proofs_to_draw(proof):
    """The proofs a server's Addresses draws, as (row, whether that row is
    live): one for each address. Its live proof where it has one, and
    otherwise the newest proof it had.

    Every proof the registry ever recorded was its own row, and a row was
    called live when its address was. So an address proved again after its
    proof ran out stood twice, "proved until" and "expired", and both rows
    offered Revoke (measured 2026-10-06, docs/RECORD.md 4.393). A row is live
    here only when the registry's own reader of live proofs returned that
    very row. The registry keeps every row. This is which of them is drawn.
    """
    proof = proof or {}
    live_ids = proof.get("live_ids", set())
    chosen = {}
    # Newest first, so the first row seen for an address is its newest, and
    # only a live one takes its place.
    for row in proof.get("rows", ()):
        key = (row["target"], row["family"])
        live = row["id"] in live_ids
        if key not in chosen or (live and not chosen[key][1]):
            chosen[key] = (row, live)
    return list(chosen.values())


def proof_status(row, live, ours_missing=False):
    """What one proof row says about itself, as a value. `ours_missing` is a
    live row on an instance whose address our side does not hold: it says
    the words the address window says for that, and never proved."""
    day = proof_day
    if row["revoked_at"]:
        return f"revoked {day(row['revoked_at'])}"
    if row["expired_at"]:
        return f"expired {day(row['expired_at'])}"
    failure = row["renewal_failure"] if "renewal_failure" in row.keys() else None
    if live and ours_missing:
        return joinbridge.module("proberproofs").NOT_PROVED_WITH_THE_PROBERS
    if live:
        if failure:
            return f"proved until {day(row['expires_at'])} · not renewed: {failure}"
        return f"proved until {day(row['expires_at'])}"
    return f"expired {day(row['expires_at'])}"


def declared_word(families):
    """What one port's declarations say, as a value.

    Both address families carrying the same word is that word, because that
    is what was declared. Anything else names the family beside each word:
    one family declared and the other not, or the two declared differently,
    are both real and a single word for them would be a claim nobody made.
    """
    words = set(families.values())
    if len(families) == len(FAMILY_ORDER) and len(words) == 1:
        return words.pop()
    return " · ".join(f"{family} {families[family]}"
                      for family in FAMILY_ORDER if family in families)


# The two address families, in the order every screen here prints them. A
# declared port carries one row per family in the store and one row on the
# screen, so this is also what the Remove button clears.
FAMILY_ORDER = ("v4", "v6")


def address_host_view(h, now, names, findings, proof, muted=False,
                      declared=None, silenced=(), when=None, changed=(),
                      transitions=(), first_seen=False, vantages=(), raised="",
                      probing=False, tags=(), display="", moved_ever=(),
                      dismissed=frozenset(), provider=None):
    """The page of a host with no agent. Same frame as `host_view`, four
    tabs: what was measured, the evidence behind it, the changes, and the
    settings. No Services, because nothing on the host was read, and no
    packet path, because there is no ruleset to walk."""
    name = h["name"]
    tone, word, _last = address_freshness(h, proof, findings, now)
    tone_word = fleet_row_word(worst_port_state(findings), (tone, word),
                               alert_open=bool(raised))
    mode = monitoring_mode(h, None)
    acts = (tpl.mute_menu_html(name, muted=muted)
            + tpl.scan_button(name))
    proved = len(proof.get("proved", proof.get("live", ())))
    rows = host_port_rows(name, None, findings, names, declared, when, silenced, now,
                          agentless=True, dismissed=dismissed)
    moved = changed_ports(name, transitions, changed, now - timedelta(hours=24))
    # The address host's four facts (SPEC.md section 2): addresses proved in
    # place of the hostname and the agent's report.
    facts = tpl.host_facts_html(tpl.AGENT_WORD[mode], [
        ("addresses proved", f'<span class="num">{proved}</span>'),
        ("probed", probed_line(findings, now)),
        ("ports", f'<span class="num">{len(rows)}</span>')], host=name, probing=probing)
    first = is_first_look(rows, declared, findings, seen=first_seen)
    first_look = tpl.first_look_modal(name, name, first_look_rows(rows, moved_ever),
                                      sum(1 for r in rows if _row_open(r)), first=first)
    first_attr = ' data-first="1"' if first else ""
    tabs = [
        ("overview", "Overview", host_overview_body(name, rows, moved, agentless=True)),
        ("evidence", "Evidence",
         evidence_tab_body(name, {}, rows, findings, None, now, agentless=True,
                           vantages=vantages, provider=provider)),
        ("changes", "Changes", changes_tab_body(name, transitions, None, Window(), now)),
        ("settings", "Settings",
         settings_tab_body(h, None, mode, declared, proof, silenced, now, agentless=True,
                           tags=tags, display=display)),
    ]
    body = tpl.host_tabs_html(name, tabs)
    return f"""<div class="wrap view" id="host-{name}"{first_attr}>
  <button class="back" data-v="fleet">&larr; Fleet</button>
  <div class="hh">
    {tpl.host_head(f'<span class="hname">{tpl.esc(display or name)}</span>',
                   tpl.state_set_html(name, tone_word, muted, raised,
                                      rarely=any(r.rarely for r in rows),
                                      paused=is_paused(h)),
                   "", facts)}
    <div class="acts">{acts}</div>
  </div>
{body}
{first_look}
</div>"""


# ---------------------------------------------------------------- the page

# Where the control plane deploy leaves the commit it shipped, for the footer
# to name. `ops/deploy-controlplane.sh` writes it and `ops/RUNBOOK.md` lists it
# among the files on the box.
BUILD_FILE_ENV = "WHICHPORTS_BUILD_FILE"
DEFAULT_BUILD_FILE = "/srv/controlplane/DEPLOYED_COMMIT"

# A commit is hex, short or full, and the deploy may append " +local changes"
# when it shipped a dirty tree. Anything else in that file is not a commit and
# is not put on a page: it is read at render time from a path on disk, so the
# footer must not become somewhere arbitrary text can be printed.
BUILD_STAMP_RE = re.compile(r"^[0-9a-f]{7,40}( \+local changes)?$")


def deployed_commit(path=None) -> str:
    """The commit the control plane deploy shipped, or "" if it cannot be read.

    **"" is the honest answer and never a guess.** A missing file is the
    ordinary case in a test and on a machine nobody has deployed to, and a
    footer that invented a commit would be worse than one that omits it.
    """
    where = pathlib.Path(path or os.environ.get(BUILD_FILE_ENV)
                         or DEFAULT_BUILD_FILE)
    try:
        text = where.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""
    return text if BUILD_STAMP_RE.match(text) else ""


def render_stamp(now, path=None) -> str:
    """The footer of every rendered dashboard.

    The commit comes first because it is the question. The owner, 2026-08-23,
    after a deploy he could not confirm: he could never tell a rendering
    fault from a deploy that had not gone out or a wait that was too short,
    and one refresh after a deploy has to show it.

    A render time alone cannot answer that. It moves on every request whether
    or not anybody deployed, so a page rendered faithfully from month-old code
    looks exactly like a page rendered from the commit you just shipped. The
    commit is the fact that separates them, and it is the same fact the public
    pages already carry in their own footer (`ops/deploy-site.sh`).

    The time stays, because it is the other half: it is when this page was
    asked for, which since the request-time render is also when it was built.
    """
    when = f"rendered {now.strftime('%Y-%m-%d %H:%M:%S')} UTC"
    commit = deployed_commit(path)
    return f"built {commit}, {when}" if commit else when


# The nav entries a live page does not draw. Nothing, since 2026-08-30.
#
# This tuple held `settings` and `auth` from 2026-08-28 and `integrations`
# from 2026-08-29, on a reading of the rule for customer screens as "leave an unbuilt
# control out". The owner asked for all three back in as many words (RECORD
# 4.139 and 4.140), and 5a now says what he said: an unbuilt thing is shown
# with the `planned` tag, and the tag is all that may be said beside it. The
# greyed Authorisation entry is NAV's own third-element form and never
# carried a view.
EMPTY_ON_A_LIVE_PAGE = ()


def draw_host_view(h, newest, *args, **kwargs):
    """One host's page, and never anybody else's problem.

    `load` proves the newest document walks the packet path before any HTML
    exists (`walks`), and `read_view` replaces a section of the wrong shape
    with `not_readable`. This is the backstop behind both: a builder on any
    tab that still raises on some shape neither anticipated ends this host's
    page and not the render. The host is drawn as a document that could not
    be read, which is the honest state and the same one a document that
    would not walk gets, and the failure is named on stderr with its type
    so the journal says which host and which shape, never a blank page and
    never a silent drop.

    Returns (html, drawn) where drawn is False when the fallback was used, so
    the fleet row can say the same thing the page does.
    """
    try:
        return host_view(h, newest, *args, **kwargs), True
    except Exception as exc:  # noqa: BLE001, the whole point is that nothing escapes
        received_at = newest[0] if isinstance(newest, tuple) else None
        print(f"host {h['id']}: its page could not be drawn from the newest"
              f" document ({type(exc).__name__}), so it is shown as not readable",
              file=sys.stderr)
        return host_view(h, Unreadable(received_at), *args, **kwargs), False


def when_text(value):
    """A stored ISO stamp as the day and the minute somebody reads, or empty
    when there is nothing stored, as `short_date` does it."""
    if not value:
        return ""
    try:
        return datetime.fromisoformat(str(value)).strftime("%d %b %Y %H:%M")
    except ValueError:
        return str(value)


def render(db_path, now=None, window=None, workspace_id=None, admin=None,
           viewing=None, csrf="", feedback_to="", commit_file=None,
           with_prober_api=False):
    """One workspace's page.

    `feedback_to` is the host a Feedback message goes to, the host of the
    prober API an instance in the beta talks to, and empty when the message
    stays on this instance, where the window names the page's own host
    (docs/screens/feedback/BRIEF.md). `commit_file` is where the deployed
    commit is read from, for the footer and the window's Version line, and
    None reads it where `deployed_commit` says.

    `admin` is the service-wide numbers from
    `controlplane/app/adminstats.py`, or None. **None is what every caller
    passes unless the session behind the request carries the admin flag**, and
    when it is None neither the nav entry nor the screen is in the HTML at all,
    so there is nothing for a browser to reveal by editing an address bar. The
    gate is `controlplane/app/web_auth.py`, which is the only place that knows
    who is signed in.

    `viewing` is `(workspace_id, name)` when this render is an admin looking
    into somebody else's workspace, and None otherwise. It draws the banner and
    puts the marker on the body that turns every write control off.
    **It changes nothing about what the page reads**: `workspace_id` decides
    that, and the caller has already decided both together.
    """
    now = now or datetime.now(timezone.utc)
    window = window or Window()
    (hosts, documents, history, alerts, names, findings, channels, mailed,
     sent, mutes, proofs, declarations, transitions, silenced, changed,
     when_declared, first_seen, ever_alerted, provider,
     removed, refusals, vantages, probing, tags, display_names, moved_ports,
     dismissed_marks) = load(
         db_path, now=now, window=window, workspace_id=workspace_id,
         with_prober_api=with_prober_api)
    sent_rows, sent_total, sent_per_channel = sent

    # Every host's page is drawn before any row, so a host whose page could
    # not be drawn is a not-readable row as well as a not-readable page
    # (draw_host_view). The rows and the views then agree by construction.
    # What the CVE check says of each server's ports, worked out once a
    # render from the report and the release's data, and kept nowhere.
    # Each port's card goes on with whether a person dismissed its mark.
    cve = {}
    cve_off = load_cve_dismissed(db_path, workspace_id)
    is_dismissed = joinbridge.module("cvedismiss").is_dismissed
    for h in hosts:
        report = documents.get(h["name"])
        if report and not isinstance(report, Unreadable):
            off = cve_off.get(h["name"], {})
            cve[h["name"]] = {
                key: (card, is_dismissed(card, off.get(key)))
                for key, card in cve_cards(report[1], db_path, now, reported_at=report[0]).items()}
    host_pages = {}
    undrawable = set()
    for h in hosts:
        if host_kind(h) == "address":
            continue
        html, drawn = draw_host_view(
            h, documents.get(h["name"]), history[h["name"]], now,
            window, names.get(h["name"]),
            findings.get(h["name"], ()),
            muted=h["name"] in mutes,
            declared=declarations.get(h["name"], {}),
            transitions=transitions.get(h["name"], ()),
            silenced=silenced.get(h["name"], {}),
            when=when_declared.get(h["name"], {}),
            changed=changed, proof=proofs.get(h["name"], {}),
            first_seen=h["name"] in first_seen,
            provider=provider, vantages=vantages,
            raised=alert_raised_text(alerts.get(h["name"], ())),
            probing=h["name"] in probing,
            tags=tags.get(h["name"], ()),
            display=display_names.get(h["name"], ""),
            moved_ever=moved_ports.get(h["name"], ()),
            dismissed=dismissed_marks.get(h["name"], frozenset()),
            cve=cve.get(h["name"]))
        host_pages[h["name"]] = html
        if not drawn:
            undrawable.add(h["name"])

    fleet_rows = []
    for h in hosts:
        if host_kind(h) == "address":
            fleet_rows.append(address_fleet_row(
                h, findings.get(h["name"], ()), proofs.get(h["name"], {}), now,
                muted=h["name"] in mutes,
                raised=alert_raised_text(alerts.get(h["name"], ())),
                tags=tags.get(h["name"], ()),
                display=display_names.get(h["name"], ""),
                dismissed=dismissed_marks.get(h["name"], frozenset())))
            continue
        live = freshness(h, now)
        report = documents.get(h["name"])
        # A document that arrived and would not read is a different fact from
        # no document. The row takes the fail tone and its state word says
        # why: a host nothing can be read about is not a healthy row, and it
        # must not read as one that never reported (DESIGN.md section 3, the
        # broken row owns the screen). It replaces the liveness fact rather
        # than sitting beside it, because it IS the liveness fact.
        broken = isinstance(report, Unreadable) or h["name"] in undrawable
        if broken:
            live = ("fail", "not readable")
            report = None
        # The hostname the document reports, under the name, only where it
        # says something the name does not (SPEC.md section 5).
        hostname = ""
        doc = {}
        if report:
            _received_at, doc = report
            hostname = doc.get("hostname", "") or ""
        # A document that would not read has no port answer to offer,
        # whatever the engine kept from an older one, so the row says that
        # and nothing else.
        host_findings = () if broken else findings.get(h["name"], ())
        tone, word = fleet_row_word(worst_port_state(host_findings), live,
                                    alert_open=bool(alerts.get(h["name"])))
        dismissed = dismissed_marks.get(h["name"], frozenset())
        reach, chips = fleet_facts(doc, host_findings, dismissed)
        fleet_rows.append(tpl.FleetRow(
            tone, word, h["name"], hostname=hostname,
            reach=reach, chips=chips, muted=h["name"] in mutes,
            alert=alert_raised_text(alerts.get(h["name"], ())),
            disagree=any_disagree(host_findings),
            tags=tuple(tags.get(h["name"], ())),
            display=display_names.get(h["name"], ""),
            rarely=bool(rarely_reachable(host_findings, dismissed)),
            # a server that never sent a document: inside the `not watched`
            # band it sorts after one that reports (docs/record 4.447)
            pending=host_kind(h) != "address" and not h["last_report_at"],
            paused=is_paused(h),
            fix="" if broken else server_fix(cve.get(h["name"]), silenced.get(h["name"], {})),
            unread=broken))

    # Worst first, then by host name. The database hands the hosts over in name
    # order, which is fine for building the rows and wrong for reading them:
    # the row that needs somebody has to be at the top. The band order and why
    # it is stable are in build.py above FLEET_BANDS.
    fleet_rows = tpl.sort_fleet_rows(fleet_rows)
    # **Scan a server left this page on 2026-08-23.** The owner asked why the
    # fleet had a button that only led to a server's own scan button.
    # Scanning is per host and the button that scans is on the host page.
    acts = f'{tpl.button("Add server", "pri js-add")}'
    # The banner's one source today is an email destination the relay is
    # refusing, which the sweep keeps since the second big test's finding
    # E22. Billing has no table, so it draws nothing (the owner, 2026-09-05,
    # answer 2). An empty Fleet is one box and no banner (SPEC.md, When
    # there is no server).
    notes = relay_refusal_notes(channels, refusals) if hosts else []
    gone = tpl.removed_list_html(tuple(
        (tpl.esc(r["name"]), tpl.esc(f"removed {short_date(r['revoked_at'])}"))
        for r in removed))
    views = tpl.fleet_view(tpl.fleet_notes_html(notes),
                           tpl.fleet_strip_html(tpl.fleet_totals(fleet_rows, len(changed))),
                           tpl.fleet_rows_html(fleet_rows), acts, gone)
    for h in hosts:
        if host_kind(h) == "address":
            views += address_host_view(h, now, names.get(h["name"]),
                                       findings.get(h["name"], ()),
                                       proofs.get(h["name"], {}),
                                       muted=h["name"] in mutes,
                                       declared=declarations.get(h["name"], {}),
                                       silenced=silenced.get(h["name"], {}),
                                       when=when_declared.get(h["name"], {}),
                                       changed=changed,
                                       raised=alert_raised_text(alerts.get(h["name"], ())),
                                       probing=h["name"] in probing,
                                       transitions=transitions.get(h["name"], ()),
                                       first_seen=h["name"] in first_seen,
                                       vantages=vantages,
                                       tags=tags.get(h["name"], ()),
                                       display=display_names.get(h["name"], ""),
                                       moved_ever=moved_ports.get(h["name"], ()),
                                       dismissed=dismissed_marks.get(h["name"], frozenset()),
                                       provider=provider)
            continue
        views += host_pages[h["name"]]

    # No fleet-wide Changes view and no Authorisation view. A transition
    # belongs to the server it happened on, so it is a tab there, and
    # authorisation is not built, so the nav says planned instead of opening a
    # screen with one sentence on it (the owner, 2026-08-15).
    open_alerts = [row for rows in alerts.values() for row in rows]
    paused_hosts = {h["name"] for h in hosts
                    if ("paused" in h.keys()) and h["paused"]}
    # Nothing here yet is no alert ever and nothing ever sent, whatever is
    # connected: an alert is recorded and shown here either way
    # (docs/screens/alerts/SPEC-layout-b.md). Both are asked, because a
    # deleted server takes its alerts with it and leaves what was sent about
    # it in the Sent list, which a box saying nothing ever happened would hide.
    open_lines = open_alert_lines(open_alerts, now, silenced, declarations,
                                  paused_hosts)
    views += tpl.alerts_view(
        open_lines,
        sent_alert_lines(sent_rows, channels, declarations), now,
        nothing_yet=not ever_alerted and not sent_rows)
    # **Integrations and Settings are real destinations again since
    # 2026-08-30** (RECORD 4.139). They were pulled because each was a wall of
    # planned rows, and the owner asked where they went. Integrations is its
    # honest empty state over the Add window, which is a room
    # waiting to be furnished rather than a room of "not built yet" signs.
    # Settings is the working account controls, the same ones the avatar menu
    # holds, laid out as the page every product also has.
    # Where alerts go stands here since layout B, under Alert destinations:
    # the rows the Alerts screen listed as Channels, from the same call.
    views += tpl.integrations_view(
        provider_lines(provider, [h["name"] for h in hosts], now),
        alerts_channels_html(channels, sent_per_channel),
        has_destinations=bool(channels))
    # The account's own facts arrive after the page loads: the script asks
    # whoami and fills the marked fields, the way the avatar chip is filled.
    views += tpl.account_settings_view(live=True)
    # Only Authorisation stays out: it has never had a view, so a nav item can
    # never point at a screen that is not on the page.
    nav = [item for item in tpl.NAV if item[0] not in EMPTY_ON_A_LIVE_PAGE]
    admin_count = 0
    if admin is not None:
        nav.append(tpl.ADMIN_NAV)
        views += tpl.admin_view(admin_sections(admin, now, csrf),
                                tpl.admin_strip_html(admin_strip(admin, now)),
                                feedback_open=int(admin.get("feedback_open") or 0))
        admin_count = admin_badge_count(admin, now)
    # Three windows on the page, one mechanism. add_server_modal keeps its own
    # script, the two new ones use the generic block in tpl.page().
    banner = ""
    if viewing is not None:
        banner = tpl.viewing_banner(viewing[1], viewing[0])
    # The Feedback button and its window are absent while an admin views
    # another workspace: every write is off there, and the window is one.
    feedback_html = ""
    feedback_modal = ""
    if viewing is None:
        feedback_html = tpl.feedback_button_html()
        feedback_modal = tpl.feedback_modal(
            feedback_to, tpl.feedback_version(deployed_commit(commit_file)))
    return tpl.page(nav, views,
                    viewing_html=banner,
                    open_count=tpl.alerts_needing_you(open_lines),
                    admin_count=admin_count,
                    feedback_html=feedback_html,
                    # `now` is the render's own clock, so a stamp that stops
                    # moving means the timer stopped or the render is failing.
                    # That is the one thing a stale page could never say
                    # before (the owner, 2026-08-23).
                    stamp=render_stamp(now, commit_file),
                    modal_html=tpl.add_server_modal() + tpl.remove_modal()
                    + tpl.delete_modal()
                    + tpl.add_modal(live=True)
                    + tpl.provider_token_modal()
                    + tpl.password_modal(live=True) + tpl.two_factor_modal(live=True)
                    + tpl.address_modal() + feedback_modal,
                    templates_html=(channel_row_templates_html()
                                    + tpl.port_row_template_html()))


# The directory name under `--out-dir` that holds the per-workspace pages, and
# the file inside each one. Only the CLI writes them now, for development and
# the tests: on the box the control plane calls `render()` per request and no
# file is read back.
WORKSPACE_DIRNAME = "w"
INDEX_FILENAME = "index.html"


def workspace_ids(db_path):
    """Every workspace to render, in id order.

    A database from before workspaces has no table, and rendering workspace 1
    alone is the right answer there: it is where the migration puts every
    existing host, so the page holds exactly what it held before. That case is
    reachable during a deploy, when this may run against a database no init has
    touched yet.
    """
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT id FROM workspaces ORDER BY id").fetchall()
    except sqlite3.OperationalError:
        print("no workspaces table yet, rendering workspace 1 only",
              file=sys.stderr)
        return [1]
    finally:
        con.close()
    return [row[0] for row in rows] or [1]


def write_page(out_dir, workspace_id, html):
    """One workspace's page, written atomically into its own directory.

    Nothing on the box reads these files any more, the control plane renders
    per request. The atomic write stays because it costs one rename and keeps
    the CLI honest for anything watching a file in development: the rename is
    within one directory, so it is a rename on the same filesystem, which is
    what makes it atomic at all.
    """
    directory = pathlib.Path(out_dir) / WORKSPACE_DIRNAME / str(int(workspace_id))
    directory.mkdir(parents=True, exist_ok=True)
    out = directory / INDEX_FILENAME
    tmp = out.with_suffix(".tmp")
    tmp.write_text(html)
    tmp.replace(out)
    return out


def main():
    # allow_abbrev=False, and it is load bearing. argparse accepts any
    # unambiguous prefix by default, so a unit file still passing the old
    # `--out /srv/whichports/app/index.html` would be read as `--out-dir` and
    # would quietly write `index.html/w/1/index.html`, a directory named after
    # the file it replaced. Off, the stale flag is an error and somebody reads
    # it. Nothing here is invoked with an abbreviation on purpose.
    ap = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    ap.add_argument("--db", required=True)
    # `--out-dir` rather than the `--out` file path this took until workspaces
    # existed. The name changed on purpose: a unit file still passing `--out`
    # fails loudly here instead of writing one workspace's page over the
    # directory every workspace's page lives in.
    ap.add_argument("--out-dir", required=True,
                    help="the directory holding w/<workspace_id>/index.html")
    # Widening this costs render time roughly in proportion, see HISTORY_DAYS.
    # Whatever it is set to, the page says it.
    ap.add_argument("--history-days", type=int, default=HISTORY_DAYS,
                    help="how far back the Changes view and each host's History read "
                         f"(default {HISTORY_DAYS})")
    args = ap.parse_args()
    if args.history_days < 1:
        ap.error("--history-days must be at least 1")
    window = Window(days=args.history_days)
    for workspace_id in workspace_ids(args.db):
        html = render(args.db, window=window, workspace_id=workspace_id)
        out = write_page(args.out_dir, workspace_id, html)
        print(f"wrote {out} {len(html)} bytes")


if __name__ == "__main__":
    main()
