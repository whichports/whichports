"""The Prometheus endpoint.

RECORD.md 4.1 records the only conditional yes this project has had, and the
condition was this: feed the central view someone already runs, do not be
another dashboard. So the metrics are written to be joined with everything
else on that wallboard, and they are deliberately modest about what they
know.

What is here is what the agent reported: how long ago it reported, how many
sockets listen, how many container publications exist, how many sections read
cleanly, and whether a host is paused or revoked. Plus, since 2026-08-16, what
the prober actually measured.

**That last part was the condition this docstring set and it has now been
met.** It used to say nothing here may be called reachable, because the prober
did not exist and reachable was its word alone (PRODUCT.md 4b). The first
outside measurement was taken on 2026-08-16 (RECORD 4.53), so the results are
published, and the way they are published is the whole point: they carry the
prober's own four state words as a label, `connect_succeeded`,
`connect_refused`, `no_response` and `not_tested`. **There is still no metric
called reachable**, because whether a completed connect means reachable is the
reader's conclusion and a metric named for it would be us drawing it for them.
A host nobody has probed gets no series at all rather than a zero, because zero
measured results and a measurement of zero are different facts.

Format is the Prometheus text exposition format, written by hand: one
counter of a dependency is not worth adding for six metric families.
"""

import sqlite3
from datetime import datetime, timezone

from . import vantages

# Metric names are stable API the moment someone builds a dashboard on them.
# Adding is free, renaming is not.
HELP = [
    ("whichports_up", "gauge", "1 when the control plane answered this scrape."),
    ("whichports_hosts", "gauge", "Hosts on the fleet, by state."),
    ("whichports_host_last_report_age_seconds", "gauge",
     "Seconds since this host's most recent document. Absent if it never reported."),
    ("whichports_host_listening_sockets", "gauge",
     "Listening sockets in this host's most recent document."),
    ("whichports_host_published_ports", "gauge",
     "Container port publications in this host's most recent document."),
    ("whichports_host_sections_collected", "gauge",
     "Document sections that read cleanly, out of whichports_host_sections_total."),
    ("whichports_host_sections_total", "gauge", "Document sections the agent attempts."),
    ("whichports_host_paused", "gauge", "1 when monitoring for this host is paused."),
    ("whichports_host_documents_total", "counter",
     "Documents received from this host since it was added."),
    ("whichports_alerts_open", "gauge", "Alerts raised and not yet resolved, by kind."),
    ("whichports_alerts_undelivered", "gauge",
     "Open alerts that have not been delivered to anyone."),
    ("whichports_probe_results", "gauge",
     "Results of this host's most recent probe run, by address family and by the"
     " prober's own state word. Absent for a host that has never been probed."),
    ("whichports_probe_last_run_age_seconds", "gauge",
     "Seconds since this host's most recent probe run started. Absent if it has"
     " never been probed."),
    ("whichports_vantage_enabled", "gauge",
     "1 when this vantage in the registry is driven on every pass, 0 when it is"
     " switched off."),
    ("whichports_vantage_last_run_age_seconds", "gauge",
     "Seconds since this vantage's most recent finished probe run, across every"
     " host. Absent if it has never finished one."),
]

# Alert kinds this build can raise. Emitted at zero when there are none, because
# a gauge that disappears at zero cannot be alerted on: the query returns no data
# rather than returning 0, and "no data" is indistinguishable from a scrape that
# is not running. A kind written by a newer build is emitted alongside these
# rather than dropped, so the scrape cannot quietly disagree with the database.
KNOWN_ALERT_KINDS = ("silent", "finding changed")

SECTIONS = ("sockets", "nftables", "iptables", "ip6tables", "ufw",
            "firewalld", "containers", "overlays", "rule_files")


def escape_label(value: str) -> str:
    """Prometheus label values escape backslash, quote and newline. Host
    names are already restricted at creation, but the hostname inside a
    document is the host's own text and gets the same treatment as anywhere
    else it crosses a boundary."""
    return (str(value).replace("\\", "\\\\").replace('"', '\\"')
            .replace("\n", " ").replace("\r", " "))


def render(con: sqlite3.Connection, now: datetime | None = None) -> str:
    now = now or datetime.now(timezone.utc)
    lines = []
    for name, kind, help_text in HELP:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")

    lines.append("whichports_up 1")

    hosts = con.execute("SELECT * FROM hosts ORDER BY name").fetchall()
    # "address" is a host watched from outside only, with no agent to report
    # (docs/PRODUCT.md 3a). It never reports by design, so counting it as
    # never_reported would read as an agent that failed to start.
    states = {"reporting": 0, "silent": 0, "never_reported": 0,
              "paused": 0, "revoked": 0, "address": 0}

    for host in hosts:
        name = escape_label(host["name"])
        label = f'host="{name}"'
        paused = bool(host["paused"]) if "paused" in host.keys() else False
        kind = host["kind"] if "kind" in host.keys() else "agent"

        if host["revoked_at"]:
            states["revoked"] += 1
        elif paused:
            states["paused"] += 1
        elif kind == "address":
            states["address"] += 1
        elif not host["last_report_at"]:
            states["never_reported"] += 1

        lines.append(f"whichports_host_paused{{{label}}} {1 if paused else 0}")

        count = con.execute(
            "SELECT COUNT(*) AS c FROM reports WHERE host_id = ?", (host["id"],)
        ).fetchone()["c"]
        lines.append(f"whichports_host_documents_total{{{label}}} {count}")

        if not host["last_report_at"]:
            continue
        age = max(0, int((now - datetime.fromisoformat(host["last_report_at"])).total_seconds()))
        lines.append(f"whichports_host_last_report_age_seconds{{{label}}} {age}")
        if not host["revoked_at"] and not paused:
            # Two ticks of the packaged fifteen minute timer, the same window
            # the fleet view calls silent.
            states["silent" if age > 35 * 60 else "reporting"] += 1

        latest = con.execute(
            "SELECT document FROM reports WHERE host_id = ?"
            " ORDER BY received_at DESC, id DESC LIMIT 1", (host["id"],)
        ).fetchone()
        if latest is None:
            continue
        import json
        try:
            doc = json.loads(latest["document"])
        except (json.JSONDecodeError, TypeError):
            continue
        listening = len(((doc.get("sockets") or {}).get("listening")) or [])
        cont = doc.get("containers") or {}
        published = sum(len(c.get("ports") or [])
                        for runtime in ("docker", "podman")
                        for c in (cont.get(runtime) or []))
        collected = sum(1 for key in SECTIONS
                        if (doc.get(key) or {}).get("status") == "collected")
        lines.append(f"whichports_host_listening_sockets{{{label}}} {listening}")
        lines.append(f"whichports_host_published_ports{{{label}}} {published}")
        lines.append(f"whichports_host_sections_collected{{{label}}} {collected}")
        lines.append(f"whichports_host_sections_total{{{label}}} {len(SECTIONS)}")

    for state, value in states.items():
        lines.append(f'whichports_hosts{{state="{state}"}} {value}')

    lines.extend(alert_lines(con))
    lines.extend(probe_lines(con, hosts, now))
    lines.extend(vantage_lines(con, now))
    return "\n".join(lines) + "\n"


def vantage_lines(con: sqlite3.Connection, now: datetime) -> list[str]:
    """Each vantage in the registry: whether it is driven, and how long ago it
    last finished a pass anywhere.

    **Per vantage, across every host**, which is the question a dead box
    raises: not "is this host's outside view fresh", which the host series
    answer and which stays fresh while any vantage runs, but "is probe2 still
    measuring anything". A registry that does not exist yet, which is every
    database from before 2026-09-08, publishes nothing here and the scrape
    still answers.
    """
    if not vantages.table_exists(con):
        return []
    lines = []
    for vantage in vantages.list_all(con):
        name = escape_label(vantage.name)
        lines.append(f'whichports_vantage_enabled{{vantage="{name}"}}'
                     f' {1 if vantage.enabled else 0}')
        try:
            run = con.execute(
                "SELECT finished_at FROM probe_runs WHERE vantage = ?"
                " AND finished_at IS NOT NULL"
                " ORDER BY finished_at DESC, id DESC LIMIT 1",
                (vantage.name,)).fetchone()
        except sqlite3.OperationalError:
            continue
        if run is None:
            continue
        finished = _parse_stamp(run["finished_at"])
        if finished is None:
            continue
        age = max(0, int((now - finished).total_seconds()))
        lines.append(
            f'whichports_vantage_last_run_age_seconds{{vantage="{name}"}} {age}')
    return lines


def probe_lines(con: sqlite3.Connection, hosts, now: datetime) -> list[str]:
    """What the prober measured, per host, from its most recent run only.

    **The newest run only, never a sum.** Any cadence produces many runs per
    host, and adding them would count one port once per run and make a fleet
    look busier the longer it has been watched.

    A state this build does not know is published under its own name rather
    than dropped, the same rule the alert kinds follow, so a scrape can never
    quietly disagree with the database.

    Probe tables that do not exist yet read as no runs, not as a failed scrape.
    On 2026-08-16 the production database had no prober tables at all and the
    endpoint still had to answer, or the one metric that reports we are up goes
    down with everything else.
    """
    lines = []
    for host in hosts:
        run = None
        try:
            run = con.execute(
                "SELECT id, started_at FROM probe_runs WHERE host_id = ?"
                " ORDER BY started_at DESC, id DESC LIMIT 1", (host["id"],)).fetchone()
        except sqlite3.OperationalError:
            return []
        if run is None:
            continue
        name = escape_label(host["name"])
        started = _parse_stamp(run["started_at"])
        if started is not None:
            age = max(0, int((now - started).total_seconds()))
            lines.append(
                f'whichports_probe_last_run_age_seconds{{host="{name}"}} {age}')
        counted = {}
        for row in con.execute(
                "SELECT family, state, COUNT(*) AS c FROM probe_results"
                " WHERE run_id = ? GROUP BY family, state", (run["id"],)):
            counted[(str(row["family"]), str(row["state"]))] = row["c"]
        for (family, state), value in sorted(counted.items()):
            lines.append(f'whichports_probe_results{{host="{name}",'
                         f'family="{escape_label(family)}",'
                         f'state="{escape_label(state)}"}} {value}')
    return lines


def _parse_stamp(value):
    """A stamp written by an older build, or by hand, must not take the scrape
    down. An unreadable one publishes no age rather than a wrong one."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def alert_lines(con: sqlite3.Connection) -> list[str]:
    """The dead-man switch's own output, so a wallboard can see it.

    It had none, and the cost of that was measured: two silence alerts sat
    open on production for a day, both against hosts that had never reported,
    and nothing outside the box could see them. A monitoring tool that dies
    quietly is worse than none (PRODUCT.md 4c), and the part built to make a
    quiet failure loud was itself the quiet one.

    `whichports_alerts_undelivered` is the second half and is the metric that
    would have shown the SMTP outage: while the relay was refusing the sender,
    every alert was recorded and none was delivered, and the only way to know
    was to read the journal on the box.

    An alerts table that does not exist yet reads as no alerts, not as a
    failed scrape. A fresh database has nothing to be wrong about, and taking
    the endpoint down over it would break the metric that reports we are up.
    """
    counts = {kind: 0 for kind in KNOWN_ALERT_KINDS}
    undelivered = 0
    try:
        rows = con.execute(
            "SELECT kind, COUNT(*) AS c, SUM(notified_at IS NULL) AS undelivered"
            " FROM alerts WHERE resolved_at IS NULL GROUP BY kind").fetchall()
    except sqlite3.OperationalError:
        rows = []
    for row in rows:
        counts[str(row["kind"])] = counts.get(str(row["kind"]), 0) + row["c"]
        undelivered += row["undelivered"] or 0

    lines = [f'whichports_alerts_open{{kind="{escape_label(kind)}"}} {value}'
             for kind, value in sorted(counts.items())]
    lines.append(f"whichports_alerts_undelivered {undelivered}")
    return lines
