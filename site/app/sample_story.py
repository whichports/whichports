"""The sample page's one server, as one description (docs/RECORD.md 4.443).

The sample page drew each tab of its server from rows written by hand, and
the tabs told two stories: the Overview said no ufw rule names 8410 and the
default is allow, the Rules tab listed a rule for 8410 and a default of deny,
Evidence said the provider permits it while the Overview said no provider is
connected. An outside reader found it on the first walk.

Here the server is described once, as the things a real one is made of: what
its agent reports, what the probers measured, what somebody answered. That
is put into a database of the control plane's own making, the engine joins
it as it joins a real server, and every tab is drawn by the function the
live page draws it with. A tab cannot say something the others do not,
because none of them is written down any more.

The story is the Overview's, the one the approved sketch opens on: no ufw
rule names 8410, ufw's default for incoming is allow, no provider is
connected, so 8410 answers from outside and nobody said it should.

Everything here is invented: the ports, the rules, the times. The probers'
addresses are the two on our own published list (site/probers.py).
"""
import dataclasses
import functools
import json
import pathlib
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import render_live as rl

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import probers  # noqa: E402

tpl = rl.tpl

# The id the sample page gives its one server. Its shown name is the
# header's, in build.py.
SERVER = "host"
HOSTNAME = "ubuntu-app-01"
NOW = tpl.SAMPLE_NOW
REPORTED = NOW - timedelta(minutes=4)
PROBED = NOW - timedelta(minutes=12)
# Three hours earlier 8410 did not answer yet. The two passes are what makes
# the change the Overview's third box and the Changes tab show.
PROBED_BEFORE = NOW - timedelta(hours=3)
ANSWERED_443 = datetime(2026, 8, 13, 9, 30, tzinfo=timezone.utc)
# The two addresses the sample's Settings tab lists as proved for this
# server, from the ranges kept for documentation.
ADDRESS = {"v4": "203.0.113.198", "v6": "2001:db8:c17:2b::1"}

YES, SHUT, REFUSED = "connect_succeeded", "no_response", "connect_refused"
# The row the sample opens on, as the approved sketch does: its two cards are
# the first thing a reader meets. Which row is open is the drawing's choice
# and the one thing here that is not a fact about the server.
OPEN_ROW = ("tcp", 8410)
ALLOWED = (22, 80, 443, 8096)
DENIED = (5432,)


def _socket(protocol, port, name, pid, address, family):
    return {"protocol": protocol, "family": family, "port": port, "pid": pid,
            "bind_address": address, "process_name": name}


SOCKETS = [
    _socket("tcp", 443, "caddy", 3, "0.0.0.0", "v4"), _socket("tcp", 443, "caddy", 3, "::", "v6"),
    _socket("tcp", 80, "caddy", 3, "0.0.0.0", "v4"), _socket("tcp", 80, "caddy", 3, "::", "v6"),
    _socket("tcp", 8410, "uvicorn", 4, "0.0.0.0", "v4"),
    _socket("tcp", 22, "sshd", 1, "0.0.0.0", "v4"),
    _socket("tcp", 5432, "postgres", 5, "0.0.0.0", "v4"),
    _socket("tcp", 5432, "postgres", 5, "::", "v6"),
    _socket("udp", 323, "chronyd", 6, "127.0.0.1", "v4"),
]

# What each prober found on each port, v4 then v6, in the newest pass. 8096
# is allowed by a rule with nothing listening behind it, so the server itself
# refuses the connection. 5432 is dropped by its deny rule, so nothing comes
# back at all.
MEASURED = {443: (YES, YES), 80: (YES, YES), 8410: (YES, SHUT), 22: (YES, YES),
            8096: (REFUSED, REFUSED), 5432: (SHUT, SHUT)}


def _ufw_table(family):
    """The kernel's side of ufw with its default for incoming set to allow:
    the base chain lets through what no rule names."""
    rules = [f"meta l4proto tcp tcp dport {port} counter accept" for port in ALLOWED]
    rules += [f"meta l4proto tcp tcp dport {port} counter drop" for port in DENIED]
    return {"family": family, "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter", "policy": "accept",
         "rules": [{"text": "counter jump ufw-user-input", "rendered": "full"}]},
        {"name": "ufw-user-input", "rules": [{"text": text, "rendered": "full"} for text in rules]}]}


def document():
    """What the server's agent reports: one document, in the agent's shape."""
    def lines(anywhere):
        return ([f"allow tcp {port} {anywhere} any {anywhere} in" for port in ALLOWED]
                + [f"deny tcp {port} {anywhere} any {anywhere} in" for port in DENIED])
    return {
        "schema_version": 1,
        "hostname": HOSTNAME,
        "agent_version": tpl.SAMPLE_AGENT_VERSION,
        "collected_at_unix": int(REPORTED.timestamp()),
        "sockets": {"status": "collected", "listening": SOCKETS},
        "nftables": {"status": "collected", "tables": [_ufw_table("ip"), _ufw_table("ip6")]},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "collected", "conf": {"ENABLED": "yes", "LOGLEVEL": "low"},
                "defaults": {"DEFAULT_INPUT_POLICY": "ACCEPT", "DEFAULT_OUTPUT_POLICY": "ACCEPT",
                             "DEFAULT_FORWARD_POLICY": "DROP"},
                "rules": lines("0.0.0.0/0"), "rules6": lines("::/0"),
                "sources": {"ufw.conf": {"status": "collected"},
                            "user.rules": {"status": "collected"},
                            "user6.rules": {"status": "collected"}}},
        "firewalld": {"status": "not_present"},
        "containers": {"status": "collected"},
        "overlays": {"status": "collected"},
        "rule_files": {"status": "collected", "files": []},
    }


def _stamp(moment):
    return moment.isoformat()


def _pass(con, host_id, moment, found):
    """One pass of each prober over the server's ports, stored the way a
    measurement that arrives from a prober is stored."""
    prober = rl.joinbridge.module("prober")
    for name in ("probe1", "probe2"):
        results = []
        for port, by_family in sorted(found.items()):
            for family, state in zip(("v4", "v6"), by_family):
                results.append(prober.Result(family=family, target=ADDRESS[family], port=port,
                                             state=state, connect_ms=14.0 if state == YES else None,
                                             measured_at=_stamp(moment)))
        prober.store_measurement(con, host_id, prober.Run(
            id=None, vantage=name, started_at=_stamp(moment), finished_at=_stamp(moment),
            results=tuple(results)))


def _database(path):
    """The description as rows, through the control plane's own functions
    wherever one takes a time. Two tables stamp the clock by themselves, the
    report and the answer, and those two rows are set to the sample's times
    after they are written."""
    module = rl.joinbridge.module
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    for name in ("db", "prober", "intent", "vantages", "alerts", "finding_alerts"):
        module(name).init(con)
    host_id, _credential = module("store").add_host(con, SERVER)
    doc = document()
    module("store").insert_report(con, host_id, doc["collected_at_unix"], 1, json.dumps(doc))
    con.execute("UPDATE reports SET received_at = ?", (_stamp(REPORTED),))
    con.execute("UPDATE hosts SET last_report_at = ?, created_at = ?",
                (_stamp(REPORTED), _stamp(ANSWERED_443 - timedelta(hours=1))))
    con.commit()
    by_name = {}
    for listed in probers.PROBERS:
        by_name.setdefault(listed.rdns.split(".")[0], []).append(listed.address)
    for name, addresses in sorted(by_name.items()):
        module("vantages").add(con, name, f"root@{name}", addresses, now=PROBED_BEFORE)
    for family in ("v4", "v6"):
        module("intent").declare(con, SERVER, "tcp", 443, family, "closed")
    con.execute("UPDATE port_intents SET declared_at = ?", (_stamp(ANSWERED_443),))
    con.commit()
    # The pass of three hours ago, when 8410 did not answer, and what the
    # control plane's own pass over the findings made of it. Then the newest
    # pass, and the same again: that is where the change comes from.
    before = dict(MEASURED)
    before[8410] = (SHUT, SHUT)
    _pass(con, host_id, PROBED_BEFORE, before)
    module("finding_alerts").evaluate(con, now=PROBED_BEFORE)
    _pass(con, host_id, PROBED, MEASURED)
    module("finding_alerts").evaluate(con, now=PROBED)
    module("finding_alerts").evaluate(con, now=NOW)
    con.close()


@dataclasses.dataclass(frozen=True)
class Parts:
    """The sample server's page, piece by piece, each drawn by the live
    page's own function from the one result."""
    word: tuple            # (tone, word) of the server's state tag
    facts: list            # the header's facts, label and value
    overview: str
    services: str
    rules: str
    evidence: str
    path: str
    first_look: tuple      # (rows, how many ports answer) for the first-look window
    fleet: tuple           # (reach, chips): the server's two cells on the Fleet
    rows: tuple            # the Overview's rows, for whoever needs a port's own facts
    probing: tuple         # the answers the Settings tab lists under Probing


@functools.lru_cache(maxsize=1)
def parts():
    with tempfile.TemporaryDirectory() as folder:
        path = str(pathlib.Path(folder) / "sample.db")
        _database(path)
        (hosts, documents, history, alerts, names, findings, _channels, _mailed, _sent,
         _mutes, _proofs, declarations, transitions, silenced, changed, when_declared,
         _first_seen, _ever, provider, _removed, _refusals, vantages, _probing, _tags, _display,
         moved_ports, dismissed) = rl.load(path, now=NOW)
    host = next(h for h in hosts if h["name"] == SERVER)
    received_at, doc = documents[SERVER]
    found = findings.get(SERVER, ())
    moves = transitions.get(SERVER, ())
    story = history[SERVER]
    rows = rl.host_port_rows(SERVER, doc, found, names.get(SERVER), declarations.get(SERVER, {}),
                             when_declared.get(SERVER, {}), silenced.get(SERVER, {}), NOW,
                             dismissed=dismissed.get(SERVER, frozenset()))
    rows = [dataclasses.replace(row, open=(row.protocol, row.port) == OPEN_ROW) for row in rows]
    moved = rl.changed_ports(SERVER, moves, changed, NOW - timedelta(hours=24))
    reported = f"{rl.age_text(received_at, NOW)} ago"
    facts = [("hostname", tpl.esc(doc["hostname"])),
             ("agent reported", f'<span class="num">{rl.age_text(received_at, NOW)}</span> ago'),
             ("probed", rl.probed_line(found, NOW)),
             ("ports", f'<span class="num">{len(rows)}</span>')]
    word = rl.fleet_row_word(rl.worst_port_state(found), rl.freshness(host, NOW),
                             alert_open=bool(alerts.get(SERVER)))
    return Parts(
        word=word,
        facts=facts,
        overview=rl.host_overview_body(SERVER, rows, moved, live=False),
        services=rl.services_tab_body(SERVER, doc, rows, names.get(SERVER)),
        rules=rl.rules_tab_body(doc, SERVER, provider, reported,
                                rl.provider_read_words(provider, SERVER, NOW),
                                changes=rl.host_log(moves, story)),
        evidence=rl.evidence_tab_body(SERVER, doc, rows, found, received_at, NOW,
                                      vantages=vantages, provider=provider),
        path=rl.path_tab_body(doc, SERVER, {}, names.get(SERVER), found, provider, NOW),
        first_look=(rl.first_look_rows(rows, moved_ports.get(SERVER, ())),
                    sum(1 for row in rows if rl._row_open(row))),
        fleet=rl.fleet_facts(doc, found, dismissed.get(SERVER, frozenset())),
        rows=tuple(rows),
        probing=tuple(rl.answered_ports(doc, declarations.get(SERVER, {}))))
