"""One answer per port, three words: yes, no, later, on the Host Overview.

    Run from site/app: python3 -m pytest test_host_answers.py

The owner, 2026-09-04, decision 2 of docs/screens/host-overview/SPEC.md: yes
declares the port open, no declares it closed, later hides the question until
the port's state changes. "Mark read" and the separate acknowledgement went,
and the acknowledgement store is what later writes to. This file covers the
screen half: which rows offer which answers, which one is lit and why, what a
click posts, and the first-look window that asks once for the whole server.

Its own file on purpose, the same reason test_scan_button.py is: a screen that
adds a control adds its tests here rather than growing test_render_live.py.
"""
import json
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import pytest  # noqa: E402

import build  # noqa: E402
import render_live as rl  # noqa: E402
import theme  # noqa: E402


# ------------------------------------------------------------ the fragments

def row(**kw):
    base = dict(protocol="tcp", port=22, word="unreviewed", tone="warn", service="sshd",
                marks=("warn", ""), decided="no rule", answers=build.ANSWERS,
                state_families=("v4",), if_declared=("intended", "conflict", "unreviewed"))
    base.update(kw)
    return build.PortRow(**base)


def test_a_question_offers_the_three_answers_and_lights_none():
    html = build.port_row_html("box", row())
    buttons = re.findall(r'<button class="ans ([a-z]+)" data-answer="([a-z]+)">', html)
    assert buttons == [("yes", "yes"), ("no", "no"), ("later", "later")]
    assert "pick" not in html
    assert '<span class="pra " ' in html


def test_a_settled_row_lights_its_answer_and_carries_the_class_that_hides_the_rest():
    html = build.port_row_html("box", row(word="intended", tone="ok", lit="yes", settled=True))
    assert '<button class="ans yes pick" data-answer="yes">yes</button>' in html
    assert '<span class="pra settled" ' in html
    # the rest is hidden by the stylesheet until the row opens, not left out
    assert 'data-answer="no"' in html and 'data-answer="later"' in html
    assert ".pra.settled .ans:not(.pick){display:none}" in build.CSS
    assert ".prsel:checked+.pr .pra.settled .ans{display:inline-block}" in build.CSS


def test_a_picked_no_is_neutral_and_never_red():
    """The owner, 2026-09-20: answering no is not wrong, and red says wrong.
    No is an answer, not a fault. It takes the neutral
    fill a picked LATER has, and red stays with the state beside it, which is
    where a conflict is said (docs/RECORD.md 4.189)."""
    html = build.port_row_html("box", row(word="conflict", tone="fail", lit="no", settled=True))
    assert '<button class="ans no pick" data-answer="no">' in html
    assert "unsure" not in html
    assert (".ans.no.pick,.ans.later.pick{background:var(--panel2);color:var(--ink);"
            "border-color:var(--line2)}") in build.CSS
    rule = build.CSS[build.CSS.index(".ans.no.pick"):]
    rule = rule[:rule.index("}")]
    assert "fail" not in rule


def test_a_stale_rule_offers_later_only_beside_the_other_way_out():
    html = build.port_row_html("box", row(word="stale rule", answers=("later",),
                                          aside=build.REMOVE_THE_RULE))
    assert html.count("data-answer=") == 1 and 'data-answer="later"' in html
    assert f'<span class="or">{build.REMOVE_THE_RULE}</span>' in html


def test_a_quiet_row_hides_its_answers_until_it_opens():
    html = build.port_row_html("box", row(word="not reachable", tone="off", quiet=True))
    assert '<span class="pra quiet" ' in html
    # The answers, and since 2026-09-21 the aside beside them, which a quiet
    # stale rule carries ("or remove the rule", test_stale_rule_is_quiet.py).
    assert ".pra.quiet .ans,.pra.quiet .or{visibility:hidden}" in build.CSS
    assert (".prsel:checked+.pr .pra.quiet .ans,"
            ".prsel:checked+.pr .pra.quiet .or{visibility:visible}") in build.CSS


def test_a_row_with_no_finding_offers_nothing():
    html = build.port_row_html("box", row(word="", tone="", answers=(), if_declared=("", "", "")))
    assert "data-answer=" not in html
    assert 'class="st ' not in html


def test_the_answer_box_names_the_port_and_what_each_answer_makes_it():
    html = build.port_row_html("box", row(port=443, state_families=("v4", "v6"),
                                          if_declared=("intended", "conflict", "unreviewed")))
    assert ('<span class="pra " data-host="box" data-protocol="tcp" data-port="443"'
            ' data-fams="v4,v6" data-stfams="v4,v6" data-st-open="intended"'
            ' data-st-closed="conflict" data-st-none="unreviewed">') in html


def test_the_row_escapes_what_could_carry_document_text():
    html = build.port_row_html("box", row(service="<b>x</b>", provenance="<i>y</i>",
                                          decided="<u>z</u>"))
    for raw in ("<b>x</b>", "<i>y</i>", "<u>z</u>"):
        assert raw not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html and "&lt;u&gt;z&lt;/u&gt;" in html


def test_the_row_opens_on_a_checkbox_and_the_cards_are_under_it():
    cards = (("v4", "warn", "reachable, no rule permits it",
              (("agent", f"{build.mono('sshd')} listens on {build.mono('0.0.0.0:22')}"),
               ("prober", "connected"), ("firewall", "no rule"), ("provider", "not connected"))),
             ("v6", "", "not tested, nothing is bound",
              (("agent", "nothing bound"), ("prober", "not tested"),
               ("firewall", "no rule"), ("provider", "not connected"))))
    html = build.port_row_html("box", row(cards=cards))
    assert html.startswith('<input type="checkbox" class="prsel" id="pr-box-tcp-22">'
                           '<label class="pr" for="pr-box-tcp-22" data-port="22/tcp">')
    assert html.count('<div class="prec">') == 2
    assert '<span class="lead">reachable, no rule permits it</span>' in html
    assert '<b class="mono">0.0.0.0:22</b>' in html
    assert ".prsel:checked+.pr+.pre{display:grid}" in build.CSS
    # the sample opens one row
    assert 'class="prsel" id="pr-host-tcp-8410" checked>' in build.build_sample()


def test_the_page_carries_the_click_handler_and_no_browser_dialog():
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    assert "var postAnswer=" in script
    assert "'acknowledge'" in script and "'declare'" in script
    assert "answerIntent={yes:'open',no:'closed'}" in script
    assert "wireAnswers" in script
    for bad in ("alert(", "confirm(", "prompt("):
        assert bad not in script.replace("confirm.onclick", "").replace("confirm.disabled", "") \
            .replace("var confirm=", "").replace("if(!confirm)", "")


def test_the_first_look_window_is_two_groups_later_and_confirm():
    rows = [("rule", "443/tcp", "caddy", "your rule", "yes", "tcp", 443, "v4,v6"),
            ("waiting", "8410/tcp", "uvicorn", "no rule", "", "tcp", 8410, "v4")]
    html = build.first_look_modal("box", "box", rows, 2)
    assert '<div class="ovl js-modal fv" id="fv-box" data-host="box">' in html
    assert "<h2>First look at box</h2>" in html
    # on every later look the title is the column's own words (the outside
    # review's point 6, docs/record 4.451)
    assert "<h2>Your answers for box</h2>" in build.first_look_modal("box", "box", rows, 2, first=False)
    assert "2 ports answer from outside. Say for each whether it should." in html
    # the ports waiting for an answer lead since 2026-10-02 (record 4.221)
    assert html.index("waiting for you") < html.index("answered already")
    assert ('<div class="fv-r" data-protocol="tcp" data-port="443" data-stfams="v4,v6">'
            in html)
    assert '<button class="ans yes pick" data-answer="yes">yes</button>' in html
    assert 'class="btn js-fv-later" data-close="fv-box">Later</button>' in html
    assert 'class="btn pri js-fv-confirm">Confirm</button>' in html
    assert "once per browser" not in html
    # one port reads in the singular
    assert "1 port answers from outside" in build.first_look_modal("b", "b", rows[:1], 1)


# ------------------------------------------------------------- the live feed
#
# The schema, the document shape and the helpers take the same form
# test_render_live.py uses, copied rather than imported so this file stands
# alone (the posture test_scan_button.py states and guards).

SCHEMA = """
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0,
    workspace_id INTEGER NOT NULL DEFAULT 1);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
INSERT INTO workspaces (id, name, created_at) VALUES (1, 'default', '2026-08-14T12:00:00+00:00');
"""

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

SSHD = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
        "process_name": "sshd", "pid": 1}
SSHD6 = {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 22,
         "process_name": "sshd", "pid": 1}


def document(listening):
    return {
        "schema_version": 1,
        "hostname": "Almabox",
        "collected_at_unix": int(NOW.timestamp()),
        "sockets": {"status": "collected", "listening": listening},
        "nftables": {"status": "collected", "tables": []},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "not_present"},
        "firewalld": {"status": "not_present"},
        "containers": {"status": "collected", "podman": []},
        "overlays": {"status": "collected"},
        "rule_files": {"status": "collected", "files": []},
    }


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return str(path)


def add_host(db, name, listening):
    con = sqlite3.connect(db)
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, created_at, last_report_at)"
        " VALUES (?, ?, ?, ?)",
        (name, "hash-" + name, NOW.isoformat(),
         (NOW - timedelta(minutes=2)).isoformat()))
    doc = document(listening)
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix,"
        " schema_version, document) VALUES (?, ?, ?, 1, ?)",
        (cur.lastrowid, (NOW - timedelta(minutes=2)).isoformat(),
         doc["collected_at_unix"], json.dumps(doc)))
    con.commit()
    con.close()


def probe_result(db, host_name, port, family, state):
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS probe_runs (
        id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
        vantage TEXT NOT NULL, started_at TEXT NOT NULL, finished_at TEXT);
    CREATE TABLE IF NOT EXISTS probe_results (
        id INTEGER PRIMARY KEY, run_id INTEGER NOT NULL REFERENCES probe_runs(id),
        family TEXT NOT NULL, target TEXT, port INTEGER, state TEXT NOT NULL,
        reason TEXT, connect_ms REAL, os_errno INTEGER, measured_at TEXT NOT NULL);
    """)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?",
                          (host_name,)).fetchone()[0]
    run = con.execute("SELECT id FROM probe_runs WHERE host_id = ?",
                      (host_id,)).fetchone()
    if run is None:
        run_id = con.execute(
            "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
            " VALUES (?, ?, ?, ?)",
            (host_id, "probe1", NOW.isoformat(), NOW.isoformat())).lastrowid
    else:
        run_id = run[0]
    con.execute(
        "INSERT INTO probe_results (run_id, family, target, port, state,"
        " reason, connect_ms, os_errno, measured_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, family, "185.199.108.153", port, state, None, 1.0, None,
         NOW.isoformat()))
    con.commit()
    con.close()


def acknowledge(db, host_name, protocol, port, family, state):
    """One stored acknowledgement, written the way `app/intent.py` writes one.
    The table is created here so every other test still runs against a database
    where nobody has ever acknowledged anything."""
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS port_acknowledgements (
        id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
        protocol TEXT NOT NULL, port INTEGER NOT NULL, family TEXT NOT NULL,
        state TEXT NOT NULL, account TEXT NOT NULL DEFAULT 'default',
        acknowledged_at TEXT NOT NULL, cleared_at TEXT);
    """)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?",
                          (host_name,)).fetchone()[0]
    con.execute(
        "INSERT INTO port_acknowledgements (host_id, protocol, port, family,"
        " state, acknowledged_at) VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, protocol, port, family, state, NOW.isoformat()))
    con.commit()
    con.close()


def declare_intent(db, host_name, protocol, port, family, value):
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS port_intents (
        id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
        protocol TEXT NOT NULL, port INTEGER NOT NULL, family TEXT NOT NULL,
        intent TEXT NOT NULL, account TEXT NOT NULL DEFAULT 'default',
        declared_at TEXT NOT NULL, cleared_at TEXT);
    """)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?",
                          (host_name,)).fetchone()[0]
    con.execute(
        "INSERT INTO port_intents (host_id, protocol, port, family, intent,"
        " declared_at) VALUES (?, ?, ?, ?, ?, ?)",
        (host_id, protocol, port, family, value, NOW.isoformat()))
    con.commit()
    con.close()

# ------------------------------------------------------------- what lights up

def add_doc(db, name, doc):
    """A host with one stored document of the caller's own shape."""
    con = sqlite3.connect(db)
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, created_at, last_report_at)"
        " VALUES (?, ?, ?, ?)",
        (name, "hash-" + name, NOW.isoformat(), (NOW - timedelta(minutes=2)).isoformat()))
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix,"
        " schema_version, document) VALUES (?, ?, ?, 1, ?)",
        (cur.lastrowid, (NOW - timedelta(minutes=2)).isoformat(),
         doc["collected_at_unix"], json.dumps(doc)))
    con.commit()
    con.close()


UFW_ALLOW_22 = {"family": "ip", "name": "filter", "chains": [
    {"name": "ufw-user-input", "hook": "input", "priority": 0, "type": "filter",
     "rules": [{"text": "ip protocol tcp tcp dport 22 counter accept", "rendered": "full"}]}]}


def answers_of(html, name, port="22/tcp"):
    """(the answer box's class, the lit answer or "", the decided-by words)
    for one port row on one host's page."""
    section = html.split(f'id="host-{name}"', 1)[1].split('<div class="wrap view"', 1)[0]
    row_html = section.split(f'data-port="{port}"', 1)[1].split("</label>", 1)[0]
    kind = re.search(r'<span class="pra ([a-z]*)"', row_html).group(1)
    lit = re.search(r'class="ans ([a-z]+) pick', row_html)
    decided = re.search(r'<span class="prw[^"]*"[^>]*>([^<]*)</span>', row_html).group(1)
    offered = re.findall(r'data-answer="([a-z]+)"', row_html)
    return kind, (lit.group(1) if lit else ""), decided, offered


def test_unexplained_reads_not_seen_inside_in_the_cell_and_under_the_window_row(db):
    """`no view from inside` said there was no view where the agent had looked
    and seen nothing bound. Since 2026-10-11 the words are `not seen inside`,
    one constant for the Decided by cell, the source under the port's row in
    the window, and the firewall line of a card on a server without an agent,
    so the three cannot drift (docs/record 4.451)."""
    doc = document([SSHD])  # sshd on v4 only, so v6 has nothing bound
    doc["nftables"] = {"status": "collected", "tables": [UFW_ALLOW_22]}
    add_doc(db, "almabox", doc)
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    probe_result(db, "almabox", 22, "v6", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert rl.NOT_SEEN_INSIDE == "not seen inside"
    cell = html.split('data-port="22/tcp"', 1)[1].split('<span class="prst">', 1)[1].split("</span>", 1)[0]
    assert "unexplained" in cell
    _kind, lit, decided, _offered = answers_of(html, "almabox")
    assert (lit, decided) == ("", rl.NOT_SEEN_INSIDE)
    window = first_look(html, "almabox")
    assert f"<small>{rl.NOT_SEEN_INSIDE}</small>" in window
    assert "no view from inside" not in html


def test_a_reachable_undeclared_port_is_a_question(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    kind, lit, decided, offered = answers_of(rl.render(db, now=NOW), "almabox")
    assert (kind, lit, decided) == ("", "", "no rule")
    assert offered == ["yes", "no", "later"]


def test_yes_is_lit_by_a_declaration_and_says_who_and_when(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    html = rl.render(db, now=NOW)
    assert answers_of(html, "almabox")[:3] == ("settled", "yes", "you")
    assert theme.status("ok", "intended") in html
    assert answered_on(html, "almabox") == "14 Aug"


def test_no_is_lit_by_a_declaration_of_closed_and_the_row_is_a_conflict(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    declare_intent(db, "almabox", "tcp", 22, "v4", "closed")
    html = rl.render(db, now=NOW)
    assert answers_of(html, "almabox")[:3] == ("settled", "no", "you")
    assert theme.status("fail", "conflict") in html
    assert answered_on(html, "almabox") == "14 Aug"


def test_yes_is_lit_by_a_rule_you_wrote(db):
    """docs/PRODUCT.md 8d on the screen: nobody clicked, the rule answered."""
    doc = document([SSHD])
    doc["nftables"] = {"status": "collected", "tables": [UFW_ALLOW_22]}
    add_doc(db, "almabox", doc)
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert answers_of(html, "almabox")[:3] == ("settled", "yes", "your rule")
    # and the opened row quotes the rule and says so in its lead line
    assert '<b class="mono">ip protocol tcp tcp dport 22 counter accept</b>' in html
    assert "reachable, your rule permits it" in html


def test_later_is_lit_by_an_acknowledgement_and_settles_the_row(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    acknowledge(db, "almabox", "tcp", 22, "v4", "unreviewed")
    kind, lit, decided, _offered = answers_of(rl.render(db, now=NOW), "almabox")
    assert (kind, lit, decided) == ("settled", "later", "no rule")


def test_a_lapsed_acknowledgement_lights_nothing(db):
    """Filed against `unreviewed`, and the declaration made the finding a
    `conflict`, which is a different finding: the answer is the declaration's."""
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    acknowledge(db, "almabox", "tcp", 22, "v4", "unreviewed")
    declare_intent(db, "almabox", "tcp", 22, "v4", "closed")
    assert answers_of(rl.render(db, now=NOW), "almabox")[:2] == ("settled", "no")


def test_half_an_acknowledged_port_is_not_lit(db):
    """The row shows one word for the port and the store is keyed per family,
    so the answer is lit only when every family with a state carries it."""
    add_host(db, "almabox", [SSHD, SSHD6])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    probe_result(db, "almabox", 22, "v6", "connect_succeeded")
    acknowledge(db, "almabox", "tcp", 22, "v4", "unreviewed")
    kind, lit, _decided, _offered = answers_of(rl.render(db, now=NOW), "almabox")
    assert (kind, lit) == ("", "")


def test_a_measured_silence_offers_its_answers_under_the_hand(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "no_response")
    kind, lit, decided, offered = answers_of(rl.render(db, now=NOW), "almabox")
    assert (kind, lit) == ("quiet", "")
    assert offered == ["yes", "no", "later"]
    # the engine attributes the silence to no layer, so the cell says what is
    # true of the rules and nothing more, and is not a marker (docs/RECORD.md
    # 4.174)
    assert decided == "no rule"
    assert 'class="prw unsure"' not in rl.render(db, now=NOW)


def test_a_port_nobody_measured_offers_no_answer(db):
    add_host(db, "almabox", [SSHD])
    kind, lit, decided, offered = answers_of(rl.render(db, now=NOW), "almabox")
    assert (kind, lit, decided, offered) == ("", "", "", [])


def test_the_state_cell_holds_the_state_alone(db):
    """The rule of docs/DESIGN.md section 3: an acknowledgement is not in the
    cell that answers State. Later lives in the answer column, so the cell
    cannot read as a state and its opposite at once."""
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    acknowledge(db, "almabox", "tcp", 22, "v4", "unreviewed")
    html = rl.render(db, now=NOW)
    cell = html.split('data-port="22/tcp"', 1)[1].split('<span class="prst">', 1)[1].split("</span>", 1)[0]
    assert cell.count('class="st ') == 1
    rows = html.split('<div class="panel ptbl">', 1)[1].split("</div>\n", 1)[0]
    assert "tag-rvw" not in rows


# ------------------------------------------------------------ the first look

def first_look(html, name):
    return html.split(f'id="fv-{name}"', 1)[1].split("</div>\n</div>", 1)[0]


def test_the_window_opens_on_its_own_only_before_anyone_answered(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    assert 'id="host-almabox" data-first="1"' in rl.render(db, now=NOW)
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    assert 'data-first="1"' not in rl.render(db, now=NOW)


def test_a_server_whose_every_open_port_a_rule_answered_never_asks(db):
    """The owner, 2026-09-21: it must not feel like homework. Somebody who adds
    twenty servers and has to go over every port of each is given a long job.

    Read from production that day: on app-01 the window would have
    opened on a first visit to list five ports his own rules had already
    answered, every one prefilled YES, and ask for a Confirm. A window with
    nothing in it that needs anybody, once per server. It opens on its own
    only when a port is waiting for an answer."""
    doc = document([SSHD])
    doc["nftables"] = {"status": "collected", "tables": [UFW_ALLOW_22]}
    add_doc(db, "almabox", doc)
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert "answered already" in first_look(html, "almabox")
    assert 'data-first="1"' not in html
    # and it is still there to be opened by hand
    assert "js-review-all" in html


def test_one_port_waiting_beside_ports_a_rule_answered_does_ask(db):
    doc = document([SSHD, {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                           "port": 8410, "process_name": "uvicorn", "pid": 4}])
    doc["nftables"] = {"status": "collected", "tables": [UFW_ALLOW_22]}
    add_doc(db, "almabox", doc)
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    probe_result(db, "almabox", 8410, "v4", "connect_succeeded")
    assert 'id="host-almabox" data-first="1"' in rl.render(db, now=NOW)


def test_a_server_with_nothing_reachable_never_asks(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "no_response")
    html = rl.render(db, now=NOW)
    assert 'data-first="1"' not in html
    assert "0 ports answer from outside" in first_look(html, "almabox")


def test_the_window_lists_the_reachable_ports_in_their_two_groups(db):
    doc = document([SSHD, {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                           "port": 8410, "process_name": "uvicorn", "pid": 4}])
    doc["nftables"] = {"status": "collected", "tables": [UFW_ALLOW_22]}
    add_doc(db, "almabox", doc)
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    probe_result(db, "almabox", 8410, "v4", "connect_succeeded")
    window = first_look(rl.render(db, now=NOW), "almabox")
    assert "2 ports answer from outside" in window
    waiting = window.split("waiting for you")[1].split("answered already")[0]
    rule = window.split("answered already")[1]
    assert 'data-port="22"' in rule and '<button class="ans yes pick"' in rule
    assert "sshd<small>your rule</small>" in rule
    assert 'data-port="8410"' in waiting and "pick" not in waiting
    assert "uvicorn<small>no rule</small>" in waiting


def mark_seen(db, name):
    """Somebody in the account saw this server's first look: the row the
    page script's post leaves (`controlplane/app/intent.py`, first_looks)."""
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE IF NOT EXISTS first_looks (host_id INTEGER PRIMARY KEY,"
                " account TEXT NOT NULL, seen_at TEXT NOT NULL)")
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.execute("INSERT OR IGNORE INTO first_looks VALUES (?, 'default', ?)",
                (host_id, NOW.isoformat()))
    con.commit()
    con.close()


def test_the_window_is_a_first_look_once_and_your_answers_after(db):
    """The outside review's point 6 (REVIEW-2026-10-06): the button said
    "review all ports" and nothing said what it did. It reads what a person
    does there, over the column YOUR ANSWER, and the window's title follows
    it: `First look at <server>` only on the look the page opens on its own,
    which is what the page already knows (`first_look_attr`), and `Your
    answers for <server>` on every later one (docs/record 4.451)."""
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    # a first look: a port waiting, nothing answered, nobody has seen it
    html = rl.render(db, now=NOW)
    assert 'id="host-almabox" data-first="1"' in html
    assert "<h2>First look at almabox</h2>" in first_look(html, "almabox")
    assert "Your answers for almabox" not in html
    # a second look: somebody saw it, nothing answered yet
    mark_seen(db, "almabox")
    html = rl.render(db, now=NOW)
    assert 'data-first="1"' not in html
    assert "<h2>Your answers for almabox</h2>" in first_look(html, "almabox")
    assert "First look at almabox" not in html
    # a look after every port was answered: the window still opens from the
    # button, with the answer lit, under the later title
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    html = rl.render(db, now=NOW)
    assert 'data-first="1"' not in html
    window = first_look(html, "almabox")
    assert "<h2>Your answers for almabox</h2>" in window
    assert '<button class="ans yes pick"' in window
    assert "js-review-all" in html


def test_the_button_says_what_a_person_does_there(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    overview = html[html.index('id="t-almabox-overview"'):
                    html.index('id="t-almabox-services"')]
    assert ('<button class="btn rv js-review-all" data-host="almabox">'
            'Answer reachable ports</button>') in overview
    # no redo arrow: nothing runs again, a window opens
    assert "&#8635;" not in overview and "review all ports" not in overview


def test_a_server_where_nothing_answers_has_no_review_button(db):
    """The owner, 2026-09-20, on the first outside server, 0 of 20 reachable:
    the button opened a window with nothing in it to edit. The
    window lists the ports that answer from outside (SPEC.md section 8), so
    with none it has no row, and a button that opens an empty window is a
    button to nothing. It is drawn when the window has a row."""
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "no_response")
    html = rl.render(db, now=NOW)
    overview = html[html.index('id="t-almabox-overview"'):
                    html.index('id="t-almabox-services"')]
    assert "js-review-all" not in overview
    assert "Answer reachable ports" not in overview
    # The table is still there, and so is every answer on its rows.
    assert 'data-port="22"' in overview


def test_a_server_never_probed_has_no_review_button_either(db):
    add_host(db, "almabox", [SSHD])
    html = rl.render(db, now=NOW)
    overview = html[html.index('id="t-almabox-overview"'):
                    html.index('id="t-almabox-services"')]
    assert "js-review-all" not in overview


def test_the_window_is_reached_from_review_all_ports(db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert '<button class="btn rv js-review-all" data-host="almabox">' in html
    script = html[html.rindex("<script>"):]
    assert "openFirstLook(b.dataset.host)" in script
    # once per account (the owner, 2026-09-06): the opening is recorded on the
    # server, and nothing is remembered in the browser
    assert "'/first-look'" in script and "wp-first-look" not in script


def answered_on(html, host):
    """The day of the answer, where it moved to on 2026-10-09: the opened
    row's own line, never the Decided by cell (docs/record 4.447)."""
    row = html[html.index(f'id="pr-{host}-tcp-22"'):]
    row = row[:row.index('<input type="checkbox" class="prsel"', 10) if '<input type="checkbox" class="prsel"' in row[10:] else len(row)]
    found = re.search(r'<div class="prwhen"><span class="k">answered</span> ?<span class="v">([^<]+)</span></div>', row)
    return found.group(1) if found else ""


def test_decided_by_says_who_and_the_day_is_in_the_opened_row(db):
    """Decided by says who decided and nothing else; the day sits in the
    opened row as a label and a value, and a port nobody answered has no
    such line (the review's point 4, docs/record 4.447)."""
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert answered_on(html, "almabox") == ""
    assert "you, " not in html
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    html = rl.render(db, now=NOW)
    assert '<span class="prw">you</span>' in html
    assert answered_on(html, "almabox") == "14 Aug"
    assert not re.search(r'class="prw">you, \d', html)


def test_a_persons_own_answers_are_not_filed_under_a_rule(db):
    """Found on the test fleet on 2026-09-30 (docs/RECORD.md 4.220): a server
    with no firewall, port 22 answered Yes and port 3100 answered No by a
    person, and the window listed both under "answered by a rule you wrote".
    The group holds every port that has an answer, so its heading says that,
    and each row says whose answer it is (docs/RECORD.md 4.453)."""
    listener = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                "port": 3100, "process_name": "node", "pid": 9}
    add_host(db, "almabox", [SSHD, listener])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    probe_result(db, "almabox", 3100, "v4", "connect_succeeded")
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    declare_intent(db, "almabox", "tcp", 3100, "v4", "closed")
    window = first_look(rl.render(db, now=NOW), "almabox")
    assert "a rule you wrote" not in window
    assert "waiting for you" not in window
    answered = window.split(build.FIRST_LOOK_ANSWERED, 1)[1]
    for port, service, lit in ((22, "sshd", "yes"), (3100, "node", "no")):
        row = answered.split(f'data-port="{port}"', 1)[1].split('<div class="fv-r"', 1)[0]
        assert f"{service}<small>you</small>" in row
        assert f'<button class="ans {lit} pick"' in row


def test_the_windows_second_heading_names_no_rule():
    assert build.FIRST_LOOK_GROUPS[1] == ("rule", "answered already")
    assert "rule" not in build.FIRST_LOOK_ANSWERED
