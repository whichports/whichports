"""The live renderer, tested against a real SQLite file.

Run from site/app: python3 -m pytest test_render_live.py

The schema below mirrors controlplane/app/db.py, which owns it. If that
schema changes shape these tests break loudly, which is the point: the
renderer reads production's tables and must move with them.
"""
import json
import re
import importlib
import importlib.util
import pathlib
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

import render_live as rl
# render_live puts site/ on the path when it is imported, which is what makes
# the design system importable by name here rather than through rl.
import theme  # noqa: E402

# The control plane owns this schema, in controlplane/app/db.py. This is a copy
# and a copy drifts, which it had: `hosts` gained `paused` and `auto_named` and
# this string did not, so the day the renderer started asking the join engine
# for findings, every test that renders a page failed with `IndexError: No item
# with that key` from deep inside the engine.
#
# It stays a copy, because building the fixture through the control plane's own
# `db.init` would put a second import path into every test in this file for one
# statement. **`test_the_fixture_schema_has_not_drifted` is what makes that
# safe**: it reads the real schema and fails here if a column appears there and
# not here, so the next drift is a named failure in this file instead of a
# stack trace in somebody else's.
SCHEMA = """
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT UNIQUE,
    kind TEXT NOT NULL DEFAULT 'agent',
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0,
    workspace_id INTEGER NOT NULL DEFAULT 1);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
CREATE TABLE report_digests (
    report_id INTEGER PRIMARY KEY REFERENCES reports(id),
    version TEXT NOT NULL, digest TEXT NOT NULL);
INSERT INTO workspaces (id, name, created_at) VALUES (1, 'default', '2026-08-14T12:00:00+00:00');
"""

NOW = datetime(2026, 8, 14, 12, 0, 0, tzinfo=timezone.utc)

def probed_cell(value):
    """The header's Probed fact as it is drawn: the turning mark, written
    always and shown only while probing (test_probing_mark.py), then the
    value."""
    import theme
    return ('<div class="k">probed</div><div class="v"><span class="pspin" title="probing">'
            + theme.icon("circle-notch", 13) + '</span>' + value + '</div>')


# The owner, 2026-08-24, moved Rules and Packet path past v1 and had them shown
# as planned. Neither tab is rendered, so the
# tests that read one have nothing to read.
#
# **They keep running, against a page with the tuple emptied.** They are the
# only page-level proof that the walk and the rule quoting work, and the gate
# allows no skips, so instead of skipping for a whole release each one renders
# with `HOST_TABS_PLANNED` emptied through the fixture below. The shipped page
# keeps the tabs planned, these tests keep proving the hidden renderers work,
# and the day the tabs come back the fixture is deleted and nothing else moves.
# What covers the renderers without the fixture is app/test_packetpath.py (the
# walker on its own) and app/test_screens.py (the fragments directly).
@pytest.fixture()
def v2_tabs(monkeypatch):
    """A page as it will render after v1: no tab is planned."""
    monkeypatch.setattr(rl.tpl, "HOST_TABS_PLANNED", ())


def document(listening=None, podman=None, rule_files=None, nft_rules=2,
             socket_units=None):
    """`socket_units` is left out entirely unless a test passes one, because an
    agent older than that collector sends no such section and every other test
    here is then also the older-agent case."""
    doc = {
        "schema_version": 1,
        "hostname": "Almabox",
        "collected_at_unix": int(NOW.timestamp()),
        "sockets": {"status": "collected", "listening": listening or []},
        "nftables": {"status": "collected", "tables": [{
            "family": "inet", "name": "firewalld",
            "chains": [{"name": "input", "rules": [{"text": "x", "rendered": "full"}] * nft_rules}],
        }]},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "not_present"},
        "firewalld": {"status": "collected", "conf": {"DefaultZone": "public"}},
        "containers": {"status": "collected", "podman": podman or []},
        "overlays": {"status": "collected"},
        "rule_files": {"status": "collected", "files": rule_files or []},
    }
    if socket_units is not None:
        doc["socket_units"] = socket_units
    return doc


SSHD = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
        "process_name": "sshd", "pid": 1}
LOOP = {"protocol": "udp", "family": "v4", "bind_address": "127.0.0.1", "port": 323,
        "process_name": "chronyd", "pid": 2}
JELLYFIN = {"id": "abc123", "name": "jellyfin", "image": "jellyfin",
            "ports": [{"host_ip": "0.0.0.0", "host_port": 8096,
                       "container_port": 8096, "protocol": "tcp"}]}


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    return str(path)


def add_host(db, name, reports, last_report_at=None, revoked=False,
             workspace_id=1):
    con = sqlite3.connect(db)
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, created_at, revoked_at,"
        " last_report_at, workspace_id) VALUES (?, ?, ?, ?, ?, ?)",
        (name, "hash-" + name, NOW.isoformat(),
         NOW.isoformat() if revoked else None, last_report_at, workspace_id))
    for received_at, doc in reports:
        con.execute(
            "INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version,"
            " document) VALUES (?, ?, ?, ?, ?)",
            (cur.lastrowid, received_at.isoformat(), doc["collected_at_unix"], 1,
             json.dumps(doc)))
    con.commit()
    con.close()


def test_fleet_shows_real_hosts_and_no_sample_data(db):
    add_host(db, "almabox", [(NOW - timedelta(minutes=4), document(listening=[SSHD, LOOP]))],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    html = rl.render(db, now=NOW)
    assert "almabox" in html
    assert "reporting" in html
    # not one string from the sample shell may survive into a live page
    for sample in ("dataproc-01", "mqtt-01", "edge-cache-02", "sysadmin@example.org",
                   "wp_9f2c41ae7b3d0000"):
        assert sample not in html, f"sample data leaked into the live page: {sample}"


def test_freshness_words(db):
    add_host(db, "fresh", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_host(db, "newbox", [])
    add_host(db, "oldbox", [], revoked=True)
    html = rl.render(db, now=NOW)
    assert "silent 3h 0m" in html
    assert "not watched" in html
    assert "revoked" in html
    # the state tag says it, and no sentence beside it repeats it
    assert "no document for" not in html


def test_services_group_facts_only(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[SSHD, LOOP], podman=[JELLYFIN]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "jellyfin" in html
    # The Overview has a row for the published port, and its opened row says
    # who publishes it and where, in the card's agent line.
    assert 'data-port="8096/tcp"' in html
    assert 'publishes it on <b class="mono">0.0.0.0</b>' in html
    # the live page never claims reachability in any direction
    assert "reachable," not in html
    assert "not reachable" not in html


def test_a_socket_without_a_process_names_its_owner_as_the_user(db):
    """The non-root agent reads no process names, and the owning uid is the
    attribution that remains (docs/RECORD.md 4.64). The label says user, or
    uid, never implying the owner is the process. A socket carrying neither
    keeps the words shown today."""
    caddy = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
             "port": 443, "owner_uid": 991, "owner_name": "caddy"}
    podman = {"protocol": "tcp", "family": "v6", "bind_address": "::",
              "port": 18080, "owner_uid": 1003}
    bare = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
            "port": 9999}
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[caddy, podman, bare]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "user caddy" in html
    assert "uid 1003" in html
    assert "unknown process" in html  # the bare socket keeps today's words


def test_a_measured_process_name_is_never_relabelled_as_the_user(db):
    """When the agent measured a process name the owner label steps back: the
    process is the answer the reader wants, and the uid stays raw evidence."""
    sshd = dict(SSHD, owner_uid=0, owner_name="root")
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[sshd]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "sshd" in html
    assert "user root" not in html


def path_document():
    """A host whose ufw-shaped ruleset only reaches its real rules through
    jumps, plus a base chain at a lower priority the way fail2ban registers
    one. The two together are the shape the packet path exists to show."""
    d = document(listening=[SSHD], podman=[JELLYFIN])
    d["nftables"] = {"status": "collected", "tables": [
        {"family": "inet", "name": "f2b-table", "chains": [
            {"name": "f2b-chain", "hook": "input", "priority": -1, "policy": "accept",
             "rules": [{"text": "meta l4proto tcp tcp dport 22 [lookup @addr-set-sshd] [reject]",
                        "rendered": "partial"}]}]},
        {"family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "policy": "drop",
             "rules": [{"text": "counter jump ufw-user-input", "rendered": "full"}]},
            {"name": "ufw-user-input", "rules": [
                {"text": "ip protocol tcp tcp dport 22 counter accept", "rendered": "full"},
                {"text": "ip protocol tcp tcp dport 3306 counter accept", "rendered": "full"}]}]},
    ]}
    return d


def test_packet_path_makes_no_claim_the_prober_would_have_to_make(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), path_document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    # the sample shell's arrival language must never reach a live page
    for claim in ("the packet arrives", "nothing in front of it said no", "let it past",
                  "never met it"):
        assert claim not in html, f"a reachability claim reached the live page: {claim}"
    # How the outside view read is stated once, as a field on the Evidence tab,
    # where it is a fact about our own machinery. This used to assert the
    # sentence "the prober is not built" and that stopped being true on
    # 2026-08-21, so it asserts the sentence that replaced it. The rule it holds
    # is unchanged: said once, on Evidence, never on the packet path.
    assert "TCP connect, no version detection" in html
    assert html.count("TCP connect, no version detection") == 1
    # And this host was never probed, so both families say so rather than
    # borrowing a word from a measurement nobody took.
    assert "not tested" in html
    # It used to be a sentence under the Overview's first panel and under every
    # packet path block as well: "This is the inside view. The view from outside
    # needs the prober, which is not built." the owner had it removed on 2026-08-16.
    # Repeated on every port it told the reader nothing about their own server,
    # which is what makes it a disclaimer rather than a finding (the
    # absence is the statement).
    assert "This is the inside view" not in html
    assert "The view from outside" not in html
    assert "you draw the conclusion" not in html


# ------------------------------------------------------- the path, as gates
#
# The rail (tpl.gates_walk_html) is the same walk as the trace fold under it:
# walk_views builds both out of one loop. What these check is that it stays the
# same walk: a rail for every family that was measured and none for a family
# that was not, no tone or outcome the inside view cannot support, and the
# quiet count agreeing with the checkpoints the trace lists.

def test_the_rail_and_the_trace_are_one_walk_read_twice(db):
    """walk_views builds both out of one loop, and this is what proves they
    stay in step: every gate is a checkpoint the trace names, and the quiet
    blocks account for every checkpoint that is not a gate or the fork."""
    path = rl.pp.path_for(path_document(), "tcp", 22, "v4")
    steps, cells = rl.walk_views(path)
    assert steps, "the fixture stopped producing checkpoints"
    gates = [c for c in cells if c["kind"] == "gate"]
    step_names = [step[0] for step in steps]
    # the socket gate is the path's end, not a chain step, so it is excluded
    for gate in gates[:-1]:
        assert gate["full"] in step_names, f'{gate["full"]} is on the rail, not the trace'
    assert gates[-1]["full"] == "the socket"
    quiet = sum(c["n"] for c in cells if c["kind"] == "quiet")
    forks = sum(1 for c in cells if c["kind"] == "fork")
    assert forks == 1 and "the routing decision" in step_names
    assert quiet == len(steps) - (len(gates) - 1) - forks, \
        "the quiet blocks do not account for every checkpoint the trace lists"


def test_the_overview_is_the_port_table_and_it_invents_nothing(db):
    """Direction A on a live host. The prober has never run against this
    fixture, so the three views support none of the five states and the row
    says so by having none (docs/PRODUCT.md 8a), with both families reading
    not tested rather than borrowing an answer."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), path_document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    overview = tab_body(host_section(html, "box"), "box", "overview")
    assert 'data-port="22/tcp"' in overview
    assert 'data-port="8096/tcp"' in overview
    # both families boxed and empty: nobody looked, and the row says so by
    # having no tone rather than by borrowing an answer
    assert overview.count('<i class="">v4</i><i class="">v6</i>') >= 2
    assert 'class="st ' not in overview.split('class="panel ptbl"')[1], \
        "a live row wears a state tag the prober has not earned"
    # and the Decided by cell holds nothing for a port nobody measured
    assert '<span class="prw"></span>' in overview
    # The way from a row into the packet path went with that tab (the
    # planned tuple). A label pointing at a radio that is not on the page
    # does nothing when it is clicked, so the row carries none.
    assert 'for="tb-box-path"' not in overview
    # the firewall intent sentence left on 2026-08-24 with the port count:
    # both said what the table under them shows
    assert "Firewall intent" not in overview


def test_no_tick_glyph_reaches_the_live_page(db):
    """docs/DESIGN.md section 3, and healthchecks.io's own diagram is built out
    of checkmark circles, so this is the rule most at risk here."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), path_document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    for glyph in "✓✔✅☑☒✘✗❌✖":
        assert glyph not in html, f"a verdict glyph reached the page: {glyph!r}"


def test_the_ruleset_is_walked_once_per_port_and_family_for_the_whole_page(db):
    """Three tabs ask the same question of the same ports. The cache is what
    stops them walking the ruleset separately, and what stops them being able to
    disagree."""
    doc = path_document()
    cache = {}
    first = rl.path_cached(doc, "tcp", 22, "v4", cache)
    second = rl.path_cached(doc, "tcp", 22, "v4", cache)
    assert first is second
    assert list(cache) == [("tcp", 22, "v4")]


def crowded_document():
    """The shape the owner's own host produced, which the invented sample hid.

    Ten base chains on the prerouting hook, none of them carrying a rule that
    names the traced port, and every one of them holding a rule the agent could
    not fully render, so each reads "nothing readable here names this port". No
    base chain on input at all. Nothing here is a claim about what firewalld or
    netavark write: it is a document of the shape a firewalld plus netavark host
    sent, kept as a fixture because the sample data is what let ten identical
    nodes reach the screen.
    """
    d = document(listening=[SSHD])
    chains = []
    for i in range(10):
        chains.append({
            "name": f"pre_{i}", "hook": "prerouting", "priority": -300 + i * 10,
            "policy": "accept",
            # a set lookup is the commonest thing the agent cannot decode, and
            # it is why these chains cannot be called portless
            "rules": [{"text": "ip saddr [lookup @allowed] counter accept",
                       "rendered": "partial"},
                      {"text": "counter jump pre_zones", "rendered": "full"}],
        })
    d["nftables"] = {"status": "collected", "tables": [
        {"family": "inet", "name": "firewalld", "chains": chains[:6]},
        {"family": "inet", "name": "netavark", "chains": chains[6:]},
    ]}
    return d


def svg_for(html, stem):
    """The one drawn path whose ids start with `stem`, as markup."""
    start = html.index(f'aria-labelledby="{stem}-t')
    start = html.rindex("<svg", 0, start)
    return html[start:html.index("</svg>", start)]


def test_changes_between_documents(db):
    older = document(listening=[LOOP], rule_files=[{"path": "/etc/ufw/user.rules",
                                                    "mtime_unix": 100}])
    newer = document(listening=[LOOP, SSHD], podman=[JELLYFIN],
                     rule_files=[{"path": "/etc/ufw/user.rules", "mtime_unix": 200}],
                     nft_rules=5)
    add_host(db, "box", [(NOW - timedelta(minutes=2), newer),
                         (NOW - timedelta(minutes=17), older)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    changes = tab_body(host_section(html, "box"), "box", "changes")
    assert '<span class="st nt">started</span>' in changes and "sshd on 0.0.0.0:22" in changes
    assert '<span class="st nt">published</span>' in changes
    assert "podman jellyfin, host port 8096 on 0.0.0.0" in changes
    assert "/etc/ufw/user.rules" in changes
    assert "nftables inet firewalld: 2 to 5 rules" in changes


def test_no_documents_yet_is_stated(db):
    add_host(db, "empty-host", [])
    html = rl.render(db, now=NOW)
    assert "No document received from this host yet" in html


def test_the_install_command_comes_from_the_add_server_flow(db):
    """Settings used to paste an install snippet. It moved into the add-server
    flow, which mints a real command against /api/admin/hosts, so the page no
    longer carries a pasted one at all (the owner, 2026-08-15)."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert 'id="add-cmd"' in html                 # the box the minted command lands in
    assert "/api/admin/hosts" in html             # and where it is minted
    # The **enrolling** commands are minted and never pasted. The one pasted
    # command on the page is "Try it, send nothing" (`docs/RECORD.md` 4.124),
    # which enrols nothing and needs no credential, so there is nothing for
    # the server to mint.
    assert "--credential=" not in html
    assert html.count("get.whichports.com/install.sh") == 1
    assert "--mode=stdout" in html
    assert "enrol --token" not in html  # the sample shell's invented syntax


def test_the_linux_flow_offers_one_agent(db):
    """The Linux method stage holds one clickable agent card, unmarked (the
    recommended tag left on 2026-09-08 at the owner's word), plus the try-locally
    and agentless cards. The second agent card went on 2026-09-13 with option D
    (`docs/RECORD.md` 4.169 and 4.172): one agent, and the installer takes no
    flag. The suite cannot click, so it reads the emitted script.

    The absences are asserted, not just the presences. The control plane's own
    tests assert `install_command_full_visibility` is not in the body, and a
    card asking for a key the API stopped sending is the failure this pair
    exists to catch."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    # one real agent card, and the label closes it at once so nothing rides along
    assert 'id="add-agent"' in html
    # one agent since 2026-09-12, so the card is called what it is. The owner
    # said yes to the recommendation on 2026-09-18 (docs/RECORD.md 4.184).
    assert "Limited agent" not in html
    assert html.count('<div class="m-card-t">Agent</div>') == 1
    assert "recommended" not in html
    # the full-visibility card and every trace of it are gone
    assert 'id="add-agent-full"' not in html
    assert "Full visibility" not in html
    assert "install_command_full_visibility" not in html
    assert "getElementById('add-agent-full')" not in html
    # the one card picks the one key from the minted response
    assert "pickAgent(this,'install_command')" in html
    # one mint, kept, so re-picking never mints again
    assert "addCmds=r.body" in html
    assert "if(addCmds){cmdBox.textContent=shownCmd();return}" in html
    # reopening or re-picking clears the cards' selection. reset, pickAgent and
    # pickAddr each cleared the agent card one line apiece until 4.124 made it a
    # list they share. Asserting the behaviour rather than the line count,
    # because the count was only ever a proxy for it.
    assert "var linuxCards=['add-try','add-agent','add-addr']" in html
    assert html.count("clearLinux()") >= 3


def test_the_settings_page_is_the_accounts_in_the_server_tabs_shape(db):
    """The page that was pulled on 2026-08-28 (RECORD 4.123) and put back on
    the owner's word (RECORD 4.140) is the account's Settings from its spec
    since 2026-09-07 (docs/screens/account-settings): six categories on the
    rail, the working rows real, and every unbuilt one tagged."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    nav = html.split('<nav class="nav">')[1].split("</nav>")[0]
    assert ">Settings</a>" in nav
    assert 'id="settings"' in html
    after = html.split('id="settings"')[1]
    ends = [i for i in (after.find('<div class="wrap view"'),
                        after.find('<div class="ovl"')) if i != -1]
    settings = after[:min(ends)] if ends else after
    for label in ("Profile", "Security", "Workspace", "Members", "Billing", "API"):
        assert label in settings, f"a rail category is missing: {label}"
    # the working rows, filled by the script from whoami
    assert 'class="in js-who-name"' in settings
    assert 'class="kv js-who-email"' in settings
    for k in ("dark", "light", "system"):
        assert f"js-mode-{k}" in settings
    assert "js-signout" in settings
    assert 'data-open="pw-ovl"' in settings and html.count('id="pw-ovl"') == 1
    assert 'class="in js-wsname"' in settings
    # the script fills them and posts the two names to their routes
    assert "fetch('/api/admin/account/name'" in html or "'/api/admin/account/name'" in html
    assert "'/api/admin/workspace/name'" in html
    assert "fetch('/api/admin/account/password'" in html
    for gone in ("Not in v1", "Kubernetes", "read only token"):
        assert gone not in html, f"{gone} is still on the page"
    assert "Limited agent" not in html
    # The second agent card went with option D on 2026-09-13 (`docs/RECORD.md`
    # 4.169 and 4.172). Asserting its absence rather than dropping the line,
    # because the API stopped sending the key it asked for.
    assert "Full visibility" not in html
    # the sample account never reaches a live page
    for gone in ("sysadmin@example.org", "Robin Sample", "13 Aug 2026", 'value="whichports"'):
        assert gone not in html, f"sample settings data leaked: {gone}"
    assert html.count(">Paused</b>") == 1


# ------------------------------------------------- the hex-encoded ufw comment
#
# The shape is real: on 2026-08-16 the dashboard printed a hex string where
# the operator's own rule note should have been. The words and the hex below
# are made up for the sample person. ufw writes a rule comment into the tuple
# line hex-encoded and decodes it again when it prints status, so the hex is
# the file format and not a corruption (git.launchpad.net/ufw/plain/src/util.py,
# hex_encode and hex_decode).
UFW_HEX = "726f62696e206d61632c206168656164206f66207468652072617465206c696d6974"
UFW_NOTE = "robin mac, ahead of the rate limit"


def strip_facts(html):
    """The three facts at the top of a tab, as (label, value)."""
    return [(label, value) for label, value in re.findall(
        r'<div class="l">([^<]*)</div><div class="n">([^<]*)</div>', html)]


def ufw_host(db, *tuples):
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"}, "defaults": {},
                  "rules": list(tuples), "rules6": []}
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    return rl.render(db, now=NOW)


@pytest.mark.usefixtures("v2_tabs")
def test_a_hex_encoded_ufw_comment_is_shown_as_the_operators_own_words(db):
    """The bug this decode exists for. The note is the most useful thing on the
    row and the page printed 70 hex digits instead of it."""
    html = ufw_host(
        db, f"limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment={UFW_HEX}")
    rules = tab_body(host_section(html, "box"), "box", "rules")
    assert UFW_NOTE in rules, "the operator's comment is still not readable"
    assert UFW_HEX not in rules, "the hex is still on the rule row"
    # Scoped to the rules tab on purpose. The whole document is also on the page,
    # behind a disclosure on Evidence, and it keeps the raw hex because it is the
    # evidence and evidence is not rewritten. Asserting over the whole page would
    # have forced the document to be edited to satisfy a test about a rule row.
    assert UFW_HEX not in html, "the hex is still somewhere on the page"
    # and the rule itself is still quoted exactly as it arrived
    assert "limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in" in html


def test_the_comment_decodes_to_its_note():
    assert rl.decoded_hex_comment(UFW_HEX) == UFW_NOTE


@pytest.mark.parametrize("raw, why", [
    ("6a65726f6", "odd length, so it is not a whole hex string"),
    ("not a hex comment", "not hex at all"),
    ("ff", "even and hex, and not valid UTF-8"),
    ("6107", "decodes to a\\x07, and a control character is not text"),
    ("0a", "a newline is not a comment"),
    ("", "nothing to decode"),
])
def test_a_comment_that_is_not_unambiguous_hex_is_shown_as_it_arrived(raw, why):
    """Untrusted text out of a file on somebody else's host. Anything we cannot
    decode cleanly is shown as it arrived, because mojibake would be worse than
    the hex."""
    assert rl.decoded_hex_comment(raw) == raw, why


@pytest.mark.usefixtures("v2_tabs")
def test_a_decoded_comment_is_escaped_before_it_reaches_the_page(db):
    """The comment is operator-controlled and could be markup. Same rule as the
    raw document: host text renders as text, never as markup."""
    hexed = "<script>alert(1)</script>".encode().hex()
    html = ufw_host(db, f"allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment={hexed}")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


@pytest.mark.usefixtures("v2_tabs")
def test_a_tuple_with_no_comment_is_untouched(db):
    html = ufw_host(db, "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in")
    assert "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in" in html
    # no empty comment row invented for a rule that has none
    assert "comment" not in tab_body(host_section(html, "box"), "box", "rules")


@pytest.mark.usefixtures("v2_tabs")
def test_rules_tab_lists_one_firewall_at_a_time(db):
    """The tab's shape since 2026-09-10 (docs/screens/host-rules/SPEC.md):
    one bordered list per firewall in the order a packet meets them, its own
    defaults on its row, and every rule numbered.

    ufw and the kernel are not shown twice. ufw writes its rules into the
    kernel, so a kernel chain ufw wrote is not in the kernel's own list.
    """
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP",
                               "DEFAULT_OUTPUT_POLICY": "ACCEPT"},
                  "rules": ["limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"],
                  "rules6": []}
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "inet", "name": "netavark",
        "chains": [{"name": "FORWARD", "hook": "forward", "policy": "accept",
                    "rules": [{"text": "ct state invalid drop", "rendered": "full"},
                              {"text": "meta l4proto tcp [unmodelled]", "rendered": "partial"}]},
                   {"name": "ufw-user-input", "rules": [
                       {"text": "tcp dport 22 accept", "rendered": "full"}]}],
    }]}
    doc["rule_files"] = {"status": "collected",
                         "files": [{"path": "/etc/ufw/user.rules",
                                    "mtime_unix": int((NOW - timedelta(days=1)).timestamp())}]}
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    rules = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "rules")
    # ufw's own block: its state, its two defaults in its own words, its rule
    assert "ufw" in rules and "active" in rules
    # The file says DROP and ACCEPT. ufw says them as deny and allow, and so
    # does the page since 2026-10-09 (docs/RECORD.md 4.443).
    assert "incoming <b>deny</b>" in rules and "outgoing <b>allow</b>" in rules
    assert ">limit</span>" in rules and ">22<" in rules
    # the kernel keeps what nobody named and drops what ufw wrote
    assert "ct state invalid drop" in rules
    assert "tcp dport 22 accept" not in rules
    # a rule read in part says so and is never left out
    assert "meta l4proto tcp [unmodelled]" in rules
    assert "not fully readable" in rules
    # the strip counts the blocks and the rows under them: ufw, firewalld and
    # the kernel, with ufw's one rule and the kernel's two
    assert strip_facts(rules) == [("Firewalls active", "3"), ("Rules", "3"),
                                  ("Rules last changed", "13 Aug")]


@pytest.mark.usefixtures("v2_tabs")
def test_a_ufw_line_that_is_not_a_tuple_is_shown_and_never_read_as_one(db):
    """A field count alone would read an iptables line as a tuple and print
    `-A` as an action. ufw's own four actions are the guard, and a line that
    is not one of them keeps its text and says it could not be read."""
    html = ufw_host(db, "-A ufw-user-input -p tcp --dport 22 -j ACCEPT")
    rules = tab_body(host_section(html, "box"), "box", "rules")
    assert "-A ufw-user-input -p tcp --dport 22 -j ACCEPT" in rules
    assert "not fully readable" in rules
    assert ">-A</span>" not in rules


def test_evidence_names_the_partial_read(db):
    doc = document(listening=[SSHD])
    doc["sockets"]["sources"] = {"tcp": {"status": "collected"},
                                 "tcp6": {"status": "permission_denied"}}
    doc["rule_files"] = {"status": "permission_denied", "cause": "permission"}
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    # the strip on the Evidence tab: a refused source refuses the section
    assert theme.status("warn", "listening sockets · refused") in html
    assert theme.status("warn", "rule file mtimes · refused") in html




def test_raw_document_is_present_and_escaped(db):
    doc = document(listening=[dict(SSHD, process_name='<script>alert(1)</script>')])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    # host text renders as text, never as markup: the terminal rule, HTML edition
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    # The whole-document panel is gone entirely, not just its heading. The owner
    # asked twice for it to be removed, the second time on 2026-08-16.
    # The document is still stored verbatim and still reachable over the API, so
    # no evidence is lost, only a panel nobody opened.
    assert "the whole document, as JSON" not in html
    assert "The document, verbatim" not in html
    # The escaping guarantee above never depended on that panel and is the half
    # of this test that matters: a host's own text renders as text.


def overlay_doc(**overlays):
    doc = document(listening=[SSHD])
    doc["overlays"] = {"status": "collected", **overlays}
    return doc


def services_of(db, name="box"):
    return tab_body(host_section(rl.render(db, now=NOW), name), name, "services")


OVERLAY_HEAD = '<span class="svcg-t">overlay</span>'


















# ------------------------------------------------- the columns of a live row
#
# The five columns the owner named on 2026-08-16. build.py owns them and
# test_fleet.py pins them on the sample shell; these are the live feed's half,
# because what fills the Problem column here is a real silent host, a real
# paused host and a real open alert.


def live_thead(html):
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    head = re.search(r'<div class="thead[^"]*"[^>]*>(.*?)</div>', fleet, re.S).group(1)
    return [label.strip() for label in re.findall(r"<span[^>]*>([^<]+)</span>", head)]


def test_the_live_fleet_header_is_the_four_columns_of_the_spec(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    labels = live_thead(rl.render(db, now=NOW))
    assert labels == ["State", "Server", "Reachable", "Needs a decision"]
    assert labels == list(rl.tpl.FLEET_COLUMNS)


def test_a_host_nobody_probed_leaves_its_cells_empty_rather_than_claiming(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    row = _fleet_row(rl.render(db, now=NOW), "box")
    # Nothing joins an outside measurement onto a port yet, so the row says
    # `not watched` and its Reachable and Needs a decision cells hold
    # nothing (docs/screens/fleet/SPEC.md section 5). A number here would be
    # a measurement nobody took, PRODUCT.md 4b.
    assert 'data-state="not watched"' in row
    assert '<div class="frc"></div>' in row
    assert '<div class="fchips"></div>' in row


def test_a_host_nothing_has_been_read_on_does_not_claim_nothing_is_wrong(db):
    """A host whose agent has never spoken has had nothing measured, so the
    column says that rather than none."""
    add_host(db, "newbox", [])
    html = rl.render(db, now=NOW)
    row = _fleet_row(html, "newbox")
    assert 'data-state="not watched"' in row
    assert '<div class="frc"></div>' in row and '<div class="fchips"></div>' in row
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    assert "nothing read yet" not in fleet, "a sentence came back into an empty cell"


def test_a_silent_host_shows_its_last_document_and_no_sentence(db):
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    html = rl.render(db, now=NOW)
    row = _fleet_row(html, "quiet")
    assert 'data-state="silent 3h 0m"' in row
    # the Reachable cell reads from the last document: one port observed,
    # nothing measured open (SPEC.md section 5, the silent row)
    assert '<div class="frc"><b>0</b> of 1 port</div>' in row
    # the hostname sits under the name because it differs from it
    assert '<div class="fsrv"><div class="hn">quiet</div><small class="fhost">Almabox</small></div>' in row
    # and no sentence anywhere on the row
    assert "prob-note" not in html and "no document for" not in html
    assert 'class="rnote"' not in html


def _fleet_row(html, host):
    """One fleet row's markup, for a test that reads what a cell holds."""
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    return re.search(rf'<a class="row" href="[^"]*" data-host="{host}".*?</a>',
                     fleet, re.S).group(0)


def rl_host(db, name):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    row = con.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
    con.close()
    return row


def doc_of(db, name):
    con = sqlite3.connect(db)
    row = con.execute("SELECT document FROM reports WHERE host_id ="
                      " (SELECT id FROM hosts WHERE name = ?) ORDER BY id DESC LIMIT 1",
                      (name,)).fetchone()
    con.close()
    return json.loads(row[0])


def add_address_host_row(db, name):
    con = sqlite3.connect(db)
    con.execute("INSERT INTO hosts (name, token_hash, kind, created_at, revoked_at, paused,"
                " workspace_id) VALUES (?, NULL, 'address', ?, NULL, 0, 1)",
                (name, NOW.isoformat()))
    con.commit()
    con.close()


def test_a_fleet_row_has_no_agent_cell(db):
    """The owner had the Agent column removed on 2026-10-02. How a server is
    watched stays among the facts on its own page (`header_agent`)."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    row = _fleet_row(html, "box")
    assert "fag" not in row and "binoculars" not in row
    assert row.count("<div") == row.count("</div>")
    assert header_agent(html) == ["agent"]


def test_an_open_alert_is_a_magenta_marker_beside_the_state(db):
    """The owner's own example: the open alert goes in that column and not in
    the server's cell."""
    """The approved sketch has no place for the open-alert mark, and on
    2026-09-06 the owner decided: an "alert open" badge, without the date for
    now, beside the state."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    row = _fleet_row(rl.render(db, now=NOW), "quiet")
    marker = '<span class="tag-alert" title="alert open">alert open</span>'
    assert marker in row and "14 Aug 10:00" not in row
    # in the State cell, beside the state, and nowhere else on the row
    state_cell = row.split('<div class="fsrv">')[0]
    assert marker in state_cell
    assert row.count("tag-alert") == 1


def test_an_open_alert_is_a_mark_and_a_time_and_never_a_sentence(db):
    """The owner, 2026-08-29, wanted it shown as what it is, an open alert. It
    was one grey line in the same ink and at
    the same size as "2 more ports not shown", so the loudest fact on the row
    read as a footnote about folded ports.

    It takes the neutral flag shape beside a value (`docs/DESIGN.md` section
    3) and never a status tone: this row's State cell already carries the
    row's tone (`docs/RECORD.md` 4.115), so a second one here would compete
    with it.
    """
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    row = _fleet_row(rl.render(db, now=NOW), "quiet")
    assert '<span class="tag-alert" title="alert open">alert open</span>' in row
    assert '<span class="num">14 Aug 10:00</span>' not in row
    # no status tone rides on the mark
    for tone in ("ok", "warn", "fail", "off"):
        assert f'tag-alert {tone}' not in row
        assert f'{tone} tag-alert' not in row
    # and the old sentence is gone from every screen
    assert "alert open since" not in rl.render(db, now=NOW)


def test_where_an_alert_went_is_said_once_and_on_the_alerts_screen(db):
    """The fleet row showed one alert's delivery for a server that can have
    several open, so it said nothing about the second. Every open alert has
    its own row on the Alerts screen, so the fact is said there."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    html = rl.render(db, now=NOW)
    assert "Email" in sent_section(html), "the Alerts screen says where it went"
    row = _fleet_row(html, "quiet")
    assert "mail" not in row


def test_two_open_alerts_are_one_badge(db):
    """One row shows one badge however many alerts are open; the Alerts
    screen has a row per alert."""
    add_host(db, "quiet", [(NOW - timedelta(hours=9), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(hours=9)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    add_alert(db, "quiet", "tcp/22 became reachable", NOW - timedelta(hours=8))
    row = _fleet_row(rl.render(db, now=NOW), "quiet")
    assert row.count("tag-alert") == 1


def test_the_fleet_has_a_search_box_and_no_filter_buttons(db):
    """The row of filter buttons left with the Fleet of 2026-09-03
    (docs/screens/fleet/SPEC.md section 4): the state column and the sort
    carry that. The search box stays and acts on the rows' text."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_host(db, "quiet", [(NOW - timedelta(hours=9), document())],
             last_report_at=(NOW - timedelta(hours=9)).isoformat())
    html = rl.render(db, now=NOW)
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    assert 'data-f="' not in fleet
    assert 'class="seg"' not in fleet and 'class="cnt"' not in fleet
    assert '<input class="srch" placeholder="Search">' in fleet
    assert "srch.addEventListener('input',applyFleet)" in html
    # rows still carry the word, which is what the sort and the tests read
    assert 'data-state="not watched"' in fleet
    assert 'data-state="silent 9h 0m"' in fleet


def test_diff_reports_stopped_listening():
    older = document(listening=[SSHD, LOOP])
    newer = document(listening=[LOOP])
    events = rl.diff_documents(older, newer)
    assert any(e.kind == "stopped" and (e.protocol, e.port) == ("tcp", 22) for e in events)


def test_diff_is_quiet_when_nothing_moved():
    doc = document(listening=[SSHD], podman=[JELLYFIN])
    assert rl.diff_documents(doc, doc) == []


def test_paused_host_shows_paused_never_healthy(db):
    add_host(db, "sleeper", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET paused = 1 WHERE name = 'sleeper'")
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    row = _fleet_row(html, "sleeper")
    assert 'data-state="paused"' in row
    # paused wins over reporting: the row must not claim health, and its two
    # cells are empty by the spec's table
    assert 'data-state="reporting"' not in html
    assert '<div class="frc"></div>' in row and '<div class="fchips"></div>' in row
    assert "monitoring paused" not in html


def test_renderer_survives_a_database_without_the_paused_column(db):
    add_host(db, "oldschema", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)  # schema fixture has no paused column
    assert "oldschema" in html and "reporting" in html


def test_admin_controls_are_wired_into_the_page(db):
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)
    assert 'id="add-ovl"' in html          # the add-server modal rides along
    assert 'class="btn pri js-add"' in html
    assert 'id="add-linux"' in html and "Other devices" in html
    # Windows is a real pick since 2026-08-27: outside only, no agent, the same
    # answer PRODUCT.md section 7 already gives for appliances.
    assert 'id="add-windows"' in html and "Windows" in html
    # the agentless tier is real since 2026-08-26: a pick card, not a planned one
    assert "Addresses, no agent" in html and 'id="add-addr"' in html
    assert "Range, no agent" not in html
    assert 'id="add-name"' not in html     # no name field: the hostname names it
    assert 'class="code m-copy"' in html   # the command box copies itself
    # nothing is preselected: the first click on a platform is a real choice
    assert 'class="m-card pick sel"' not in html
    # the method and command stages start hidden
    for stage in ("add-method-linux", "add-method-other", "add-cmd-stage"):
        assert f'class="m-stage" id="{stage}"' in html
    assert 'js-pause' in html and 'data-host="box"' in html
    assert 'js-remove' in html
    assert 'js-rename' not in html and 'id="id-box"' in html
    # appearance moved under the profile menu, beside who is signed in
    assert 'id="pm-menu"' in html and 'id="pm-user"' in html
    assert 'id="mode-light"' in html and 'id="mode-dark"' in html
    assert 'id="pm-signout"' in html
    assert "wp-mode" in html               # applied before first paint
    # the modal closes with a glyph, not the word
    assert 'id="add-close" aria-label="Close"' in html
    assert ">close</button>" not in html


def test_the_pause_switch_posts_to_the_server(db):
    """Pause used to be caught only by the generic visual toggle, which flips
    pixels and posts nothing, so pausing a server did nothing (the owner,
    2026-08-24). The suite cannot click, so it reads the emitted script: the
    dedicated handler is there, it posts the flipped state, a refusal flips
    the switch back, and the generic toggle no longer also fires, which would
    flip the switch twice per click and land it where it started."""
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)
    assert "querySelectorAll('.js-pause')" in html
    assert "'/api/admin/hosts/'+b.dataset.host+'/pause'" in html
    assert "JSON.stringify({paused:paused})" in html
    # flip first, and flip back when the server answers anything but 204
    assert "if(r.status!==204){b.classList.toggle('off');" in html
    # a switch that names no host is left alone rather than posting to nowhere
    assert "if(!b.dataset.host)return" in html
    # the generic toggle excludes js-pause, and the old catch-all is gone
    assert "querySelectorAll('.sw:not(:disabled):not(.js-pause)')" in html
    assert "querySelectorAll('.sw:not(:disabled)')" not in html


def test_the_account_menu_asks_who_and_signs_out_with_a_post(db):
    """The menu asks the control plane who is signed in and signs out with a
    POST to the app's session sign-out, landing on /login. The old script did
    a GET, which the route now refuses, and wrote 'unknown' into the menu
    where an empty answer means nobody the app can name."""
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)
    assert "fetch('/api/admin/whoami',{cache:'no-store'})" in html
    assert "fetch('/api/admin/signout',{method:'POST',cache:'no-store'})" in html
    assert "location.href='/login'" in html
    # an empty answer stays quiet rather than guessing at a name
    assert "textContent='Signed in'" in html
    assert "textContent='unknown'" not in html


def test_the_avatar_chip_starts_neutral_and_derives_real_initials(db):
    """The chip was hardcoded RS and the menu's first open rewrote it with the
    first two letters of the signed-in email, so it read jb and turned into je
    on a click (the owner, 2026-08-24). It starts as a neutral glyph, is filled
    from whoami when the page loads, and the letters are derived initials, the
    name's first two words or the email's local part, never a slice of the
    address."""
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)
    chip = re.search(r'id="pm-btn"[^>]*>(.*?)</button>', html, re.S).group(1)
    assert "<svg" in chip
    assert "RS" not in chip
    assert "chipInitials" in html
    assert "u.slice(0,2)" not in html
    # Asked once, when the page loads: the call sits in the load handler and
    # the dataset.asked guard keeps the menu click from asking a second time.
    assert "fillWho();" in html
    assert html.count("fetch('/api/admin/whoami'") == 1


def test_page_script_is_valid_javascript(db, tmp_path):
    """The frame script is assembled inside a Python f-string, where an
    unescaped newline once broke every control on the page at once. When
    node is available, let a real parser be the judge."""
    import re
    import shutil
    import subprocess
    if not shutil.which("node"):
        pytest.skip("node not available")
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)
    js = re.findall(r"<script>(.*?)</script>", html, re.S)[-1]
    script = tmp_path / "page.js"
    script.write_text(js)
    proc = subprocess.run(["node", "--check", str(script)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr






def test_a_placeholder_host_is_not_drawn_and_no_sentence_says_why(db):
    """It was a `never reported` row until 2026-09-20. A server the window
    made is shown once it has reported (test_pending_servers.py), and nothing
    on the page explains the absence."""
    add_host(db, "new-abc123", [])
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET auto_named = 1")
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert "new-abc123" not in html
    assert "waiting for its first report" not in html


def test_copy_box_uses_a_plain_pointer(db):
    """macOS renders cursor:copy as the drag-and-drop green plus, which reads
    as "something is being added" rather than "click copies". An earlier
    project of the author's shipped that bug first (the owner, 2026-07-22). It
    does not ship twice."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert ".m-copy{cursor:pointer" in html
    # the declaration itself, not the comment that explains why it is gone
    assert "cursor:copy;" not in html and "cursor:copy}" not in html


def test_platform_cards_carry_phosphor_glyphs(db):
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert html.count('class="ic"') >= 5      # three platforms plus two methods
    assert 'viewBox="0 0 256 256"' in html    # the Phosphor grid
    assert "currentColor" in html             # glyphs follow the palette
    # no icon may claim a verdict (DESIGN.md section 3)
    for forbidden in ("check", "shield", "seal", "lock"):
        assert forbidden not in html.lower().split("<script>")[0][:20000]


def test_explanatory_clutter_is_gone(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert 'class="fn"' not in html      # the footnote essays
    # `class="hint"` is deliberately NOT banned outright. It now carries measured
    # counts, for instance how many ufw rules are on v4 and v6, which is a fact
    # rather than an aside. Banning the mechanism would have forced a real number
    # out of the page to satisfy a test about prose.
    assert "deliberately absent" not in html
    assert "on purpose" not in html


def test_the_round_two_copy_stays_gone(db):
    """The owner, 2026-08-24, the second declutter round: the screens say less.
    Every string here left this feed in that round and must not come back.
    The sample shell's half of this guard is in test_build_sample.py."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    for gone in ("Ports, and what answered from outside",
                 "listening sockets across the fleet",
                 "Firewall intent",
                 "bound to a network address",
                 "bound to loopback only",
                 "What is running",
                 "Every port, and what each view says",
                 "What has changed on this server",
                 "nothing open",
                 "None of these is built yet",
                 # the span forms are the host header's. The fleet row's meta
                 # still carries the plain section count on purpose.
                 "sections read",
                 "schema <span"):
        assert gone not in html, f"removed copy came back: {gone}"
    # an empty subtitle renders no div at all, not a blank strip
    assert '<div class="psub"></div>' not in html
    # the Add window carries no footer note: the planned tag on each card is
    # the whole of what may be said
    for live in (True, False):
        assert "m-note" not in rl.tpl.add_modal(live=live)


def test_primary_button_keeps_its_fill_on_hover(db):
    """.btn:hover:not(:disabled) scores (0,3,0) and outranks .btn.pri at
    (0,2,0), so hover repainted the primary fill with --hover: near-white in
    light mode, under white text. The fill is restated at a specificity that
    wins."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert ".btn.pri:hover:not(:disabled){background:var(--acc-fill)" in html


# ------------------------------------------------------ the dead-man display

# `subject` carries which thing inside a kind the alert is about, and it is
# here because a finding alert names a port in it while the dead-man switch
# writes none (controlplane/app/alerts.py). A renderer that meets the column
# missing is its own case and `test_an_alert_row_without_a_subject_has_no_menu`
# is the one that covers it, by using the older schema on purpose.
ALERTS_SCHEMA = """
CREATE TABLE alerts (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL, detail TEXT NOT NULL, raised_at TEXT NOT NULL,
    resolved_at TEXT, notified_at TEXT, subject TEXT);
"""

SILENCES_SCHEMA = """
CREATE TABLE alert_silences (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL, protocol TEXT, port INTEGER, family TEXT,
    until TEXT, created_at TEXT NOT NULL, cleared_at TEXT);
"""


# The log of what went out, as the control plane makes it
# (`controlplane/app/alerts.py`, `sent_log`). The Sent list and each channel's
# number read this table and nothing else. Beside it the table the same
# function writes for a silence's message, who was told an agent stopped
# reporting (`silence_told`), which no page reads.
SENT_LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS sent_log (
    id INTEGER PRIMARY KEY, workspace_id INTEGER NOT NULL, host_name TEXT NOT NULL,
    detail TEXT NOT NULL, channel TEXT NOT NULL, sent_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS silence_told (
    alert_id INTEGER NOT NULL, channel TEXT NOT NULL, told_at TEXT NOT NULL,
    again_at TEXT, PRIMARY KEY (alert_id, channel));
"""


def log_sent(db, alert_id, channel, when):
    """The line the sweep writes beside every send that succeeded, written by
    the control plane's own function, so these tests cannot drift from it."""
    con = sqlite3.connect(db)
    con.executescript(SENT_LOG_SCHEMA)
    rl.joinbridge.module("alerts").log_sent(con, alert_id, channel, when)
    con.close()


def add_alert(db, host_name, detail, raised_at, resolved=False, notified=False,
              kind="silent", subject=None, logged=True):
    """One alert. `notified` is a mail the relay accepted, and it is logged as
    sent the way the sweep logs a mail to the environment's recipient.
    `logged=False` is a mail a stored email channel sent: the sweep logs that
    one under the channel's key, which `add_delivery` does."""
    con = sqlite3.connect(db)
    try:
        con.executescript(ALERTS_SCHEMA)
    except sqlite3.OperationalError:
        pass
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (host_name,)).fetchone()[0]
    alert_id = con.execute(
        "INSERT INTO alerts (host_id, kind, detail, raised_at, resolved_at,"
        " notified_at, subject) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (host_id, kind, detail, raised_at.isoformat(),
         raised_at.isoformat() if resolved else None,
         raised_at.isoformat() if notified else None, subject)).lastrowid
    con.commit()
    con.close()
    if notified and logged:
        log_sent(db, alert_id, "email", raised_at)
    return alert_id


def silence_port(db, host_name, protocol, port, family):
    """A live per-port silence, written the way `app/silence_cli.py` writes
    one: no expiry, which is what permanent means."""
    con = sqlite3.connect(db)
    try:
        con.executescript(SILENCES_SCHEMA)
    except sqlite3.OperationalError:
        pass
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (host_name,)).fetchone()[0]
    con.execute("INSERT INTO alert_silences (host_id, kind, protocol, port,"
                " family, until, created_at) VALUES (?, 'silence', ?, ?, ?, NULL, ?)",
                (host_id, protocol, port, family, NOW.isoformat()))
    con.commit()
    con.close()


def test_a_database_without_an_alerts_table_still_renders(db):
    """The sweep runs on its own timer and creates the table. A dashboard that
    500s because a feature is not switched on yet is worse than one that shows
    nothing."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    # no alert ever is the one box (docs/screens/alerts/SPEC-layout-b.md)
    assert rl.tpl.NOTHING_YET in html


def test_an_open_alert_reaches_the_alerts_view_and_the_fleet_row(db):
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes, past the 35 minute threshold",
              NOW - timedelta(hours=2))
    html = rl.render(db, now=NOW)
    assert "nothing from the agent for 180 min" in _open_section(html)
    # the fleet row carries the mark
    assert '<span class="tag-alert" title="alert open">alert open</span>' in _fleet_row(html, "quiet")
    # nothing was delivered on this database, and Sent lists nothing
    assert "data-host" not in sent_section(html)


def test_a_delivered_alert_says_so(db):
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    html = rl.render(db, now=NOW)
    assert "Email" in sent_section(html)


# ------------------------------------- an open alert is something you can act on
#
# The owner, 2026-08-29: the page said four open alerts and offered nothing to
# do with them. The rows were inert markup: they named an unreviewed port and offered
# no way to reach it and no way to switch it off. These are what stops that
# coming back.
#
# The mutations they are built to catch:
#
#   1. **A row that goes nowhere.** The click is the whole of the fix, so the
#      host it carries has to be the host the row is about, and the view it
#      names has to be one this page really drew.
#   2. **A control offered where it does not work.** The dead-man switch has no
#      port, so a silence item on its row would post a path with no port in it.
#   3. **A menu that opens on the wrong half.** A port already silenced must
#      offer to be let back on, not to be silenced a second time, or the one
#      click that lifts it is unreachable from the screen.
#   4. **A silence read wider than it is.** It is keyed per protocol, per port
#      and per family, so a silence on one must not open the menu of another.


def _open_section(html):
    """The Open now table, and only it. Sent below it lists the same hosts
    and words, so a bare `in html` would pass on the wrong section."""
    after = html.split('<h2 class="alh2">Open now', 1)[1]
    return after.split('<h2 class="alh2">Sent', 1)[0]


def add_finding_alert(db, host_name, port=443, family="v6", **kw):
    """One finding alert about one port, subject and all, the way
    `controlplane/app/finding_alerts.py` raises one."""
    add_alert(db, host_name,
              f"tcp/{port} on {family} had no state, now unreviewed",
              NOW - timedelta(hours=2), kind="finding changed",
              subject=f"tcp/{port} {family}", **kw)


def test_an_open_alert_row_goes_to_the_server_it_names(db):
    add_host(db, "web", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_finding_alert(db, "web")
    html = rl.render(db, now=NOW)
    row = _open_section(html)
    assert 'class="al" data-host="web"' in row
    # and the view that click asks for is one this page really drew, or the
    # row lands on the fleet and the alert is no closer to being dealt with
    assert 'id="host-web"' in html


def test_an_open_alert_about_a_port_offers_to_silence_it(db):
    add_host(db, "web", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_finding_alert(db, "web", port=443, family="v6")
    row = _open_section(rl.render(db, now=NOW))
    assert ">Silence<" in row
    assert "js-al-silence" in row
    assert 'data-protocol="tcp"' in row
    assert 'data-port="443"' in row
    assert 'data-family="v6"' in row


def test_a_silenced_port_offers_to_be_let_back_on(db):
    """The half that is shown is the half that applies. A port already quiet
    that still offered `Silence` would leave the one click that lifts it
    unreachable from this screen."""
    add_host(db, "web", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_finding_alert(db, "web", port=443, family="v6")
    silence_port(db, "web", "tcp", 443, "v6")
    row = _open_section(rl.render(db, now=NOW))
    # the row says it, rather than looking exactly like one that alerts
    # (docs/RECORD.md 4.119), and offers nothing a second click could do
    assert ">Silenced<" in row
    assert "js-al-silence" not in row


def test_a_silence_on_another_family_does_not_open_the_menu(db):
    """v4 and v6 are separate silences, so v4 being quiet says nothing about
    the v6 alert on the same port number."""
    add_host(db, "web", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_finding_alert(db, "web", port=443, family="v6")
    silence_port(db, "web", "tcp", 443, "v4")
    row = _open_section(rl.render(db, now=NOW))
    assert ">Silence<" in row
    assert ">Silenced<" not in row


def test_a_dead_man_alert_carries_no_silence_control(db):
    """It has one stream per host and no port, so a silence item on it would
    post a path with nothing in the port segment. It still goes to the server,
    which is where the control that quiets it lives."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    row = _open_section(rl.render(db, now=NOW))
    assert 'class="al" data-host="quiet"' in row
    assert "js-al-silence" not in row
    # what it offers instead is the pause, which is what quiets it
    assert ">Pause<" in row


def test_an_alert_row_without_a_subject_column_still_renders(db):
    """A database from before the column was added has no subject at all, and
    a dashboard that will not draw because of it is worse than one row without
    its menu."""
    add_host(db, "old", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    # Written by hand rather than through `add_alert`, because the point is the
    # older table and that helper creates today's.
    con = sqlite3.connect(db)
    con.executescript(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY,"
        " host_id INTEGER NOT NULL REFERENCES hosts(id), kind TEXT NOT NULL,"
        " detail TEXT NOT NULL, raised_at TEXT NOT NULL, resolved_at TEXT,"
        " notified_at TEXT);")
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'old'").fetchone()[0]
    con.execute("INSERT INTO alerts (host_id, kind, detail, raised_at)"
                " VALUES (?, 'silent', 'no report for 180 minutes', ?)",
                (host_id, (NOW - timedelta(hours=2)).isoformat()))
    con.commit()
    con.close()
    row = _open_section(rl.render(db, now=NOW))
    assert "nothing from the agent for 180 min" in row
    assert "js-al-silence" not in row


@pytest.mark.parametrize("subject", ["", "tcp/443", "https/443 v6", "nonsense",
                                     "tcp/ v6", "tcp/443 "])
def test_a_subject_that_cannot_be_read_costs_the_menu_and_not_the_page(db, subject):
    """The column is text and an older build or a hand-written row could hold
    anything. The cost of getting it wrong is one missing control, never a
    screen that will not draw."""
    add_host(db, "web", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_alert(db, "web", "something moved", NOW - timedelta(hours=2),
              kind="finding changed", subject=subject)
    row = _open_section(rl.render(db, now=NOW))
    assert "something moved" in row
    assert "js-al-silence" not in row


def test_silencing_is_not_offered_as_a_way_to_close_an_alert(db):
    """A silence stops the mail and the alert stays open, which is what
    `docs/PRODUCT.md` 4c says and what the route does. Nothing on this screen
    may offer to close one by hand, because a monitoring tool that hides a live
    finding on a click is the failure this product exists to avoid."""
    add_host(db, "web", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_finding_alert(db, "web")
    silence_port(db, "web", "tcp", 443, "v6")
    html = rl.render(db, now=NOW)
    # The row is still there, which is the property: nothing on this screen
    # closes a live finding. The count is what changed on 2026-09-10, and it
    # is a number of things to do rather than a number of open alerts, so a
    # port somebody silenced leaves it (docs/PRODUCT.md 4c).
    assert "nobody has said whether it should be" in _open_section(html)
    assert '<span class="nb">' not in html
    assert "Silenced" in _open_section(html)


@pytest.mark.usefixtures("v2_tabs")
def test_the_count_beside_alerts_leaves_out_the_one_you_silenced(db):
    """The owner, 2026-09-10, having asked twice. Two open alerts, one silenced,
    so the count says one and both lines stay on the screen."""
    for name in ("web", "db"):
        add_host(db, name, [(NOW - timedelta(minutes=2), document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
        add_finding_alert(db, name)
    silence_port(db, "web", "tcp", 443, "v6")
    html = rl.render(db, now=NOW)
    assert '<span class="nb">1</span>' in html
    assert _open_section(html).count('class="al"') == 2


def test_a_webhook_delivered_alert_is_not_read_as_unsent(db):
    """docs/RECORD.md 4.89: with a webhook delivered and mail not, the open
    alert used to read a bare "not mailed", which reads as nobody was told. It
    now names the channel that took it and still says mail did not go."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL")  # links to alert id 1
    html = rl.render(db, now=NOW)
    # the webhook took it, and mail is not listed as having gone
    section = sent_section(html)
    assert "Webhook" in section
    assert "Email" not in section
    # it is said once, on the Alerts screen, and the fleet row carries the
    # mark rather than a second copy of the delivery fact
    assert "ebhook" not in _fleet_row(html, "quiet")


def test_a_mailed_alert_with_no_other_channel_reads_as_before(db):
    """Mail only, no delivery row, so the wording is exactly what it was and no
    channel clause is invented (docs/RECORD.md 4.83, notified_at stays mail)."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    section = sent_section(rl.render(db, now=NOW))
    assert "Email" in section           # the Alerts screen says it
    # no delivery the table lacks is invented
    assert "Webhook" not in section


def test_an_alert_taken_by_mail_and_webhook_names_both(db):
    """Both channels took it, so both are named and mail is not undercut."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL")  # links to alert id 1
    html = rl.render(db, now=NOW)
    section = sent_section(html)
    assert "Email" in section and "Webhook" in section   # Sent names both
    assert section.count('class="al" data-host') == 2
    # and the fleet row does not say it a second time in its own voice
    assert "ebhook" not in _fleet_row(html, "quiet")


def test_an_alert_nothing_took_still_says_not_mailed(db):
    """Neither channel delivered, so the honest reading is unchanged and no
    channel is claimed. This is the state 4.89 left in place, not the bug."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    html = rl.render(db, now=NOW)
    assert "data-host" not in sent_section(html)  # nothing went, nothing listed
    assert "nothing from the agent for 180 min" in _open_section(html)


def test_a_delivery_on_a_resolved_alert_is_not_shown(db):
    """load_deliveries joins open alerts only, so a channel that took an alert
    that has since resolved never reappears as an open delivery."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              resolved=True)
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL")  # links to the resolved alert
    html = rl.render(db, now=NOW)
    assert "No open alerts" in html
    assert "webhook sent" not in html


def test_a_resolved_alert_is_not_shown_as_open(db):
    add_host(db, "back", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_alert(db, "back", "no report for 180 minutes", NOW - timedelta(hours=2), resolved=True)
    html = rl.render(db, now=NOW)
    assert "No open alerts" in html
    assert "alert open since" not in html


def test_the_alerts_view_does_not_claim_channels_it_does_not_have(db):
    """The owner had the planned Webhook, Slack and Teams rows removed on
    2026-08-16, and on 2026-09-20 the fixed Email row went the same way
    (`docs/RECORD.md` 4.186): an account's mail is a stored row now, so with
    no row stored the panel claims no channel at all, mail included.

    The panel stands on Integrations since layout B
    (docs/screens/alerts/SPEC-layout-b.md), and the Alerts view holds none.
    With nothing connected Integrations is its one box, so both states are
    read: the box, then the panel's one line once a provider is connected."""
    add_host(db, "box", [])
    seen_an_alert(db, "box")
    html = rl.render(db, now=NOW)
    assert rl.tpl.NOTHING_CONNECTED in integrations_view_of(html)
    for view in (alerts_view_of(html), integrations_view_of(html)):
        assert "Email" not in view
        assert "Webhook" not in view and "Slack" not in view
    connect_a_provider(db)
    section = destinations_section(rl.render(db, now=NOW))
    assert rl.tpl.NO_DESTINATION_ADDED in section
    assert "Email" not in section
    assert "Webhook" not in section and "Slack" not in section


# ----------------------------------------------------------- what went out
#
# The delivery list, built on 2026-08-24. The section carried the planned tag
# over an empty panel, on the grounds that the sweep records that it mailed and
# never why it did not. That is true of the suppression half only. What went out
# was always recorded, in `alerts.notified_at` and in `alert_deliveries`, and
# these tests are what says the list holds every one of them and invents none.


def sent_section(html):
    """The "What went out" panel of the Alerts view, and nothing after it.
    Since Integrations left the live page it can be the last view before the
    modals, so this stops at the next view OR the first overlay, whichever
    comes first, the same two bounds the integrations view test uses."""
    start = html.index('<h2 class="alh2">Sent')
    view = html[start:]
    ends = [i for i in (view.find('<div class="wrap view"'),
                        view.find('<div class="ovl"')) if i != -1]
    return view[:min(ends)] if ends else view


def test_what_went_out_lists_a_mailed_alert(db):
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    section = sent_section(rl.render(db, now=NOW))
    assert "quiet" in section                        # which host
    assert "nothing from the agent for 180 min" in section        # which alert
    assert "Email" in section                        # which channel
    assert "<b>14 Aug</b> 10:00" in section          # when
    # the section exists now, so nothing on it may still be marked planned
    assert "tag-planned" not in section


def test_what_went_out_includes_an_alert_that_has_since_resolved(db):
    """A log of what went out, not a second list of what is open. The mail was
    sent, so it is listed, whatever the alert did afterwards."""
    add_host(db, "back", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_alert(db, "back", "no report for 180 minutes", NOW - timedelta(hours=2),
              resolved=True, notified=True)
    html = rl.render(db, now=NOW)
    assert "No open alerts" in html                    # it really is resolved
    assert "nothing from the agent for 180 min" in sent_section(html)


def test_what_went_out_names_the_channel_and_never_the_variable(db):
    """A stored channel key is `type:ENVVAR`. The type is what a reader is told
    and the variable never reaches a screen (docs/RECORD.md 4.87)."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL",
                 when=NOW - timedelta(hours=2))
    section = sent_section(rl.render(db, now=NOW))
    assert "Webhook" in section
    assert "WHICHPORTS_WEBHOOK_URL" not in section


def test_a_mail_and_a_webhook_on_one_alert_are_two_lines(db):
    """Two tables, two facts, two deliveries. Neither is a copy of the other
    (controlplane/app/alerts.py), so neither is dropped."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL",
                 when=NOW - timedelta(hours=2))
    section = sent_section(rl.render(db, now=NOW))
    assert section.count('class="al" data-host') == 2
    assert "Email" in section and "Webhook" in section
    assert '<span class="cnt c7">2</span>' in section


def test_what_went_out_is_newest_first(db):
    add_host(db, "early", [(NOW - timedelta(hours=9), document())],
             last_report_at=(NOW - timedelta(hours=9)).isoformat())
    add_host(db, "late", [(NOW - timedelta(hours=9), document())],
             last_report_at=(NOW - timedelta(hours=9)).isoformat())
    add_alert(db, "early", "the older one", NOW - timedelta(hours=8), notified=True)
    add_alert(db, "late", "the newer one", NOW - timedelta(hours=1), notified=True)
    section = sent_section(rl.render(db, now=NOW))
    assert section.index("the newer one") < section.index("the older one")


def test_a_webhook_and_a_mail_from_different_hours_interleave(db):
    """The two tables are merged and then ordered, rather than one printed after
    the other. A webhook that went after a mail is above it."""
    add_host(db, "quiet", [(NOW - timedelta(hours=9), document())],
             last_report_at=(NOW - timedelta(hours=9)).isoformat())
    add_alert(db, "quiet", "the mailed one", NOW - timedelta(hours=8), notified=True)
    add_alert(db, "quiet", "the posted one", NOW - timedelta(hours=6))
    add_delivery(db, "slack:WHICHPORTS_SLACK_URL", when=NOW - timedelta(hours=6),
                 alert_id=2)
    section = sent_section(rl.render(db, now=NOW))
    assert section.index("the posted one") < section.index("the mailed one")
    assert "Slack" in section


def test_nothing_sent_is_a_line_and_the_period_stays_on_the_heading(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    seen_an_alert(db, "box")
    section = sent_section(rl.render(db, now=NOW))
    assert rl.tpl.NOTHING_SENT in section
    assert ">7d<" in section
    assert "data-host" not in section


def test_a_delivery_older_than_the_window_is_not_listed(db):
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "the old one", NOW - timedelta(days=rl.tpl.SENT_READ_DAYS + 1),
              notified=True)
    add_alert(db, "quiet", "the recent one", NOW - timedelta(days=6), notified=True)
    section = sent_section(rl.render(db, now=NOW))
    assert "the recent one" in section
    assert "the old one" not in section
    assert '<span class="cnt c7">1</span>' in section
    # the recent one is past 24 hours, so the 24h pill would hide it
    assert 'data-r="7"' in section


def test_a_cut_list_says_how_many_there_were(db, monkeypatch):
    """A list showing part of a longer one must not read as the whole of it."""
    monkeypatch.setattr(rl, "SENT_LIMIT", 2)
    add_host(db, "quiet", [(NOW - timedelta(hours=9), document())],
             last_report_at=(NOW - timedelta(hours=9)).isoformat())
    for hours in (8, 7, 6, 5):
        add_alert(db, "quiet", f"alert from {hours} hours back",
                  NOW - timedelta(hours=hours), notified=True)
    section = sent_section(rl.render(db, now=NOW))
    assert section.count('class="al" data-host') == 2
    # the two kept are the newest two
    assert "alert from 5 hours back" in section
    assert "alert from 8 hours back" not in section


def test_a_database_with_no_deliveries_table_still_lists_the_mail(db):
    """A box the sweep has mailed from but that has never had a webhook. The
    alerts table is there, the delivery table is not, and the mail is listed."""
    add_host(db, "quiet", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2),
              notified=True)
    section = sent_section(rl.render(db, now=NOW))
    assert "Email" in section
    assert '<span class="cnt c7">1</span>' in section


def test_a_database_with_no_alerts_table_says_nothing_was_sent(db):
    """The sweep has never run here, so neither table exists and the page still
    renders with the empty line."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    seen_an_alert(db, "box")
    assert rl.tpl.NOTHING_SENT in sent_section(rl.render(db, now=NOW))


# ------------------------------------------- the history window and its edges
#
# The owner reported firewall changes he made on 2026-08-14 showing in Changes
# and being gone the next day. The renderer read the newest twelve documents
# per host, which on the packaged fifteen minute timer is a window of about
# two and three quarter hours. The store held the full history, only the read
# was capped, and nothing on the screen said so.
#
# These tests hold both halves of the fix: the window is materially wider, and
# whatever bound ends it is stated on the screen instead of being silent.


def test_a_change_older_than_the_old_twelve_document_window_still_appears(db):
    reports = []
    for i in range(20):
        # i counts backwards from the newest document. sshd starts listening
        # and the ufw rule file moves between the fifteenth and the fourteenth
        # document, 3h30m before NOW, well outside the old twelve document
        # window of about 2h45m.
        listening = [LOOP] if i >= 15 else [LOOP, SSHD]
        mtime = 100 if i >= 15 else 200
        reports.append((NOW - timedelta(minutes=15 * i),
                        document(listening=listening,
                                 rule_files=[{"path": "/etc/ufw/user.rules",
                                              "mtime_unix": mtime}])))
    add_host(db, "box", reports, last_report_at=reports[0][0].isoformat())

    hosts, documents, history, alerts, port_names, _findings, _channels, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    assert len(history["box"].digests) == 20   # every document in the window, not twelve

    html = rl.render(db, now=NOW)
    changes = tab_body(host_section(html, "box"), "box", "changes")
    assert '<span class="st nt">started</span>' in changes
    assert "/etc/ufw/user.rules" in changes
    # Still dated, for the reason this assertion was written: over a window of
    # days a bare "08:30" is ambiguous. The date is on every line, in ink, and
    # the header names the zone, because the clocks are UTC and a bare clock
    # was read as local time (the owner, 2026-08-24).
    when = NOW - timedelta(minutes=15 * 14)
    assert f'<b>{when.strftime("%-d %b")}</b> {when.strftime("%H:%M")}' in changes
    assert "<span>When · UTC</span>" in changes


def test_the_changes_view_states_the_period_it_covers(db):
    """As a field on the heading line, the way the Alerts screen already says
    the same thing. It used to be two sentences under the list, and both of
    them explained how a change is worked out and what is not read, which is
    machinery on a customer screen (the owner 2026-08-29)."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "changes in the last 7 days" in html
    assert "Documents older than that are not read here." not in html
    assert "Differences between one document and the next" not in html
    assert "The oldest document read here" not in html


def test_a_change_outside_the_window_is_absent_and_the_screen_says_the_period(db):
    """The window is a bound, so something has to fall out of it. What must
    never happen is falling out quietly."""
    add_host(db, "box", [
        (NOW - timedelta(minutes=2), document(listening=[LOOP])),
        (NOW - timedelta(minutes=17), document(listening=[LOOP])),
        (NOW - timedelta(days=8), document(listening=[LOOP])),
        (NOW - timedelta(days=8, minutes=15), document(listening=[LOOP, SSHD])),
    ], last_report_at=(NOW - timedelta(minutes=2)).isoformat())

    html = rl.render(db, now=NOW)
    assert '<span class="st nt">stopped</span>' not in html
    assert "<b>0</b> changes in the last 7 days" in html
    assert rl.tpl.NO_CHANGES in html

    # and it is the window that hides it, not a lost document
    wide = rl.render(db, now=NOW, window=rl.Window(days=30))
    assert '<span class="st nt">stopped</span>' in wide


def test_a_host_silent_past_the_window_still_shows_its_last_document(db):
    """The history read is time bounded and the newest document read is not,
    on purpose. A host that went quiet ten days ago still shows what it last
    said rather than reading as a host that never reported."""
    add_host(db, "gone", [(NOW - timedelta(days=10), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(days=10)).isoformat())
    html = rl.render(db, now=NOW)
    assert "No document received from this host yet" not in html
    assert 'data-port="22/tcp"' in html
    assert "silent 10d" in html
    # its History tab has nothing in the window and says that, rather than
    # rendering an empty panel
    assert rl.tpl.NO_CHANGES in html


def test_a_capped_read_says_the_span_it_covered_and_not_the_one_it_asked_for(db):
    """A host that sends more documents than the read takes stops short of the
    window, so naming the window would claim ground the read never covered.
    The heading says the oldest document it did reach instead.

    The sentence this replaced named our read limit and the host in one
    breath, which is machinery. Saying nothing at all was not
    open: a truncation is never downgraded to make the
    output cleaner, and a partial list that reads as complete is exactly that.
    """
    reports = [(NOW - timedelta(minutes=15 * i), document(listening=[LOOP]))
               for i in range(6)]
    add_host(db, "chatty", reports, last_report_at=reports[0][0].isoformat())
    html = rl.render(db, now=NOW, window=rl.Window(max_docs=3))
    # Scoped to this host's page. The Alerts screen carries a `last 7 days`
    # hint of its own over the deliveries, and it is about a different period
    # of a different thing.
    page = _overview_of(html, "chatty")
    oldest = (NOW - timedelta(minutes=30)).strftime("%d %b %H:%M")
    assert f"changes since {oldest}</span>" in page
    # the nominal window is not claimed, because it was not covered
    assert "last 7 days" not in page
    # and our own read limit is not named on any screen
    assert "sent more than 3 documents" not in html


def test_the_row_cap_says_how_many_changes_it_did_not_show(db):
    def sock(port):
        return {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                "port": port, "process_name": f"p{port}", "pid": port}

    grew = [[], [sock(22)], [sock(22), sock(23)], [sock(22), sock(23), sock(24)]]
    reports = [(NOW - timedelta(minutes=15 * (3 - i)), document(listening=listening))
               for i, listening in enumerate(grew)]
    add_host(db, "box", reports, last_report_at=NOW.isoformat())
    html = rl.render(db, now=NOW, window=rl.Window(limit=1))
    # a cut list says how many there were, so it can never read as complete
    changes = tab_body(host_section(html, "box"), "box", "changes")
    assert "<b>3</b> changes in the last 7 days" in changes
    assert changes.count('class="cr"') == 1
    assert "p24 on 0.0.0.0:24" in changes and "p22 on" not in changes


def test_every_host_changes_tab_states_the_period_itself(db):
    reports = [(NOW - timedelta(minutes=15 * i), document(listening=[LOOP]))
               for i in range(4)]
    add_host(db, "box", reports, last_report_at=reports[0][0].isoformat())
    add_host(db, "other", reports, last_report_at=reports[0][0].isoformat())
    html = rl.render(db, now=NOW)
    # every host's Changes tab says the period itself, because a tab is read on
    # its own and there is no fleet-wide Changes view carrying it any more
    for name in ("box", "other"):
        page = _overview_of(html, name)
        assert page.count("changes in the last 7 days") == 1
    # and when the read reached the whole window it does not say where it
    # started, which was a fact about our ingest and not about the server
    assert "The oldest document read here" not in html


def test_the_history_window_keeps_digests_and_not_whole_documents(db):
    """A week of whole documents for every host costs hundreds of megabytes on
    a box that also runs Caddy and the ingest, measured at about 150 kB per
    parsed document. Only the slice the diff reads is kept, and this test is
    what stops that regressing quietly."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    hosts, documents, history, alerts, port_names, _findings, _channels, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    _when, entry = history["box"].digests[0]
    # "unreadable" joined the four on 2026-08-16. It is a tuple of section
    # names and it is what stops a section nobody could read being diffed as
    # everything in it having disappeared, so it has to survive with the
    # digest rather than be recomputed from a document that is gone by then.
    assert set(entry) == {"listeners", "publications", "mtimes", "nft_counts", "unreadable"}
    assert "nftables" not in entry and "hostname" not in entry
    # the newest document is still whole, because every tab renders it
    assert documents["box"][1]["hostname"] == "Almabox"


def test_a_document_that_will_not_parse_does_not_take_the_history_down(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[LOOP, SSHD])),
                         (NOW - timedelta(minutes=17), document(listening=[LOOP]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    con = sqlite3.connect(db)
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix,"
                " schema_version, document) VALUES (1, ?, 0, 1, '{not json')",
                ((NOW - timedelta(minutes=32)).isoformat(),))
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert '<span class="st nt">started</span>' in html




def test_the_services_list_still_claims_nothing_about_reachability(db):
    """A chain evaluating a packet is not a chain permitting one, and the
    prober does not exist. The counts must not drift into a verdict."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), path_document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    # The stylesheet legitimately contains cursor:not-allowed, so the check
    # runs on the markup rather than the whole document. A crude version of
    # this test failed on exactly that and the scoping is the fix.
    body = re.sub(r"<style>.*?</style>", "", html, flags=re.S)
    for claim in ("allowed", "blocked", "permitted", "open to the internet"):
        assert claim not in body, f"the services list drew a conclusion: {claim}"


# ------------------------------------------------------- the Add window
#
# The owner asked for these two flows to be a button that opens a window, the way
# add-server already is. Both feeds get the same window from the same builder,
# so every test here reads the live page and the sample shell.
#
# They were two windows, Add channel and Add integration, until layout B made
# them one, opened by one button (docs/screens/alerts/SPEC-layout-b.md). Its
# first cards pick a kind, and each kind's own cards stand in a step of their
# own, so a test about one kind reads that step through `kind_cards`.
#
# The failure being guarded against is one thing: shipping a card that looks
# like a choice, does nothing when clicked, and leaves the reader thinking the
# product is broken rather than unfinished. So a planned card has to be visibly
# planned and genuinely unclickable, which is three facts at once. The word
# planned is on it, the disabled attribute is on it, and it carries no
# data-fields for the page script to bind a reveal to.

# The class list is captured whole rather than as one optional word, because a
# picker card now carries two modifiers and a regex that only allowed one
# silently matched nothing at all.
MODAL_CARD = re.compile(r'<button type="button" class="m-card((?: [a-z]+)*)"(.*?)</button>', re.S)


def kind_cards(window, kind):
    """The step of the Add window that holds one kind's cards, and nothing
    after it: "dest", "prov" or "mon" (`build.ADD_KINDS`)."""
    start = window.index(f'<div class="m-stage m-kind" id="conn-{kind}">')
    return window[start:window.index('<div class="m-stage', start + 1)]


def catalogue():
    """Every card of the Add window that is not a built channel's: the
    providers, the monitoring cards and Syslog. They were one list of
    providers and one of feeds until layout B split the feeds
    (docs/screens/alerts/SPEC-layout-b.md)."""
    return rl.tpl.PROVIDERS + rl.tpl.MONITORING + [rl.tpl.SYSLOG_CARD]


def modal_markup(html, mid):
    """The markup of one modal window, by its overlay id.

    Matched without the closing bracket, because the overlay carries attributes
    after its id: `data-title` holds the heading it opened with, so a window
    that renamed itself to edit a row can put the original word back.
    """
    start = html.index(f'<div class="ovl js-modal" id="{mid}"')
    return html[start:html.index("</div>\n</div>", start)]


def sample():
    """The sample shell, built from the same template module."""
    return rl.tpl.build_sample()


def test_the_add_channel_button_opens_a_window_wired_through_page(db):
    """A channel is added through the one Add window since layout B
    (docs/screens/alerts/SPEC-layout-b.md). Its trigger left the Alerts
    header for Integrations, and the Add channel window left the page."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        assert 'id="conn-ovl"' in html, feed
        # the trigger is the one Add button, and the Alerts view holds none
        assert '<button class="btn pri" data-open="conn-ovl">Add</button>' in html, feed
        assert "data-open=" not in alerts_view_of(html), feed
        # the close glyph and the footer button name the same overlay
        assert html.count('data-close="conn-ovl"') >= 2, feed
        # one window on the page, not one per view
        assert html.count('id="conn-ovl"') == 1, feed
        assert 'id="chan-ovl"' not in html and 'data-open="chan-ovl"' not in html, feed


def test_the_add_integration_button_opens_a_window_wired_through_page(db):
    """On both feeds again since 2026-08-30 (RECORD 4.139): Integrations came
    back to the live page as its honest empty state over this window, which
    the owner asked for.

    The button reads Add and the window is the one Add window since layout B
    (docs/screens/alerts/SPEC-layout-b.md). The Integrations view holds the
    button once: in its box on this live page, where nothing is connected,
    and in its header on the sample shell."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        assert 'id="conn-ovl"' in html, feed
        view = integrations_view_of(html)
        trigger = '<button class="btn pri" data-open="conn-ovl">Add</button>'
        assert trigger in view, feed
        # Once in the view and once on the page, so no other view holds one.
        # Counted as an attribute, with the space before it, because the
        # page script names the same words inside a selector.
        assert view.count('data-open="conn-ovl"') == 1, feed
        assert html.count(' data-open="conn-ovl"') == 1, feed
        assert html.count('id="conn-ovl"') == 1, feed
        assert 'id="intg-ovl"' not in html and 'data-open="intg-ovl"' not in html, feed
    # which of the two places holds it, on each feed
    assert '<div class="acts">' not in integrations_view_of(rl.render(db, now=NOW))
    assert '<div class="acts"><button class="btn pri" data-open="conn-ovl">' in \
        integrations_view_of(sample())


def test_every_trigger_names_a_window_that_is_on_the_page(db):
    """A trigger naming an overlay the page does not carry is a button that
    does nothing at all, which is the whole failure mode here."""
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        named = set(re.findall(r'data-(?:open|close)="([^"]+)"', html))
        assert named, feed
        for mid in named:
            assert f'id="{mid}"' in html, f"{feed}: nothing on the page is {mid}"


def test_the_built_channels_can_be_picked_and_the_rest_cannot(db):
    """Five are built since 2026-08-22 (docs/RECORD.md #259) and the window
    shows all five. Only Email could be picked from 2026-09-20 (`untilalpha.md`,
    docs/RECORD.md 4.189), and all five again since 2026-10-01
    (docs/RECORD.md 4.224)."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        chan = modal_markup(html, "conn-ovl")
        for channel in ("Email", "Slack", "Discord", "Telegram", "Webhook"):
            assert f">{channel}" in chan, f"{feed}: {channel} is missing from the window"
        for channel in UNBUILT_CHANNELS:
            assert channel not in chan, f"{feed}: {channel} is offered"
        # A card of this window names its step in data-fields. data-stage is
        # the shared picker's, which shows one step at a time, and no card
        # here may carry it (`build.add_card_html`).
        assert "data-stage" not in chan, feed
        picks = re.findall(r'class="m-card pick[^"]*" data-fields="([^"]+)"',
                           kind_cards(chan, "dest"))
        assert picks == ["chan-email", "chan-slack", "chan-webhook", "chan-telegram",
                         "chan-discord"], f"{feed}: {picks}"
        # and picking one reveals its own step, every one of which starts hidden
        for stage in picks:
            assert f'id="{stage}"' in chan, feed
        assert not re.search(r'class="m-stage[^"]* on"', chan), \
            f"{feed}: a step is open before anything is picked"


def test_the_window_no_longer_offers_the_environment_route(db):
    """The owner had the "or read it from the server's environment" option
    deleted on 2026-08-23.

    **The route is gone from the screen and not from the product.**
    `controlplane/app/channels.py` still stores `destination_env`, the CLI still
    writes one, and every row on the box is configured that way and keeps
    working. This asserts only that no window offers it, because a second way to
    answer one question is the clutter he removed.
    """
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    assert "read it from the server" not in chan
    assert "js-env" not in chan
    assert "/etc/whichports/alerts.env" not in chan
    assert "WHICHPORTS_SLACK_URL" not in chan


def test_only_telegram_asks_for_a_second_field(db):
    """It is the one channel whose credential and destination are two different
    things, so it is the one row with a chat id."""
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    assert chan.count('class="m-input js-chat"') == 1
    assert 'id="chan-telegram-chat"' in chan
    # The sentence naming which of the two is the credential went with the rest
    # of the window's prose on 2026-08-23. The two field labels say it.
    assert "Not the bot token" not in chan
    assert "Chat id" in chan


def test_the_advanced_step_is_real_except_for_the_timing(db):
    """The event choice is stored. The timing is not: channels.py holds no
    schedule, and the environment policy is the last of docs/PRODUCT.md 4c
    still to be built, so that one control alone is shown and marked planned.

    **The Label field left on 2026-08-23**, on the owner's word. Rows are still
    keyed by label, so the control plane names one
    itself when a request carries none.
    """
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    assert "Advanced settings" in chan
    assert "js-label" not in chan, "the label field is gone from the window"
    assert "chan-label" not in chan
    # One planned control in the Advanced step, and it is the timing. It is
    # the only planned control a destination's own steps hold since the
    # channel cards are real again (2026-10-01).
    assert "Notification timing" in chan
    advanced = chan[chan.index('id="chan-adv"'):]
    assert advanced.count('class="tag-planned"') == 1, \
        "the timing, and nothing else in Advanced marked planned"
    steps = chan[chan.index('<div class="m-stage" id='):chan.index('id="chan-adv"')]
    assert steps.count('<div class="m-stage" id="chan-') == len(rl.tpl.CHANNEL_FIELDS)
    assert "tag-planned" not in steps, "a field step is marked planned"
    # The window is every kind's since layout B
    # (docs/screens/alerts/SPEC-layout-b.md), so its other planned tags are
    # counted out one by one: Docs in its head, and each card that cannot be
    # picked yet.
    unbuilt = [name for _k, name, _g, built in catalogue() if not built]
    assert len(unbuilt) == 11
    assert chan.count('class="tag-planned"') == 1 + 1 + len(unbuilt)
    assert kind_cards(chan, "dest").count('class="tag-planned"') == 1, \
        "Syslog, and no channel that is built"
    # and Advanced is open when the window opens (docs/screens/alerts/SPEC.md)
    assert '<details class="m-adv" open>' in chan
    # One switch per kind the sweep can raise, and a switch rather than a
    # checkbox, which is what the owner asked for.
    assert chan.count('class="sw js-event"') == len(rl.tpl.EVENT_KINDS) == 4
    assert 'type="checkbox"' not in chan
    # Every one starts on, because a channel nobody asked takes every kind
    # (controlplane/app/channels.py), and a row of off switches would say the
    # opposite of what saving it does.
    assert 'class="sw js-event off"' not in chan
    assert "Tick nothing" not in chan


def test_the_screen_and_the_engine_name_the_same_kinds(db):
    """The site cannot import the control plane except through joinbridge, so
    the kind vocabulary is spelled twice. Spelled twice and never compared is
    the drift that produced 4.82 and 4.85, so it is compared here."""
    engine = rl.joinbridge.module("channels")
    assert [kind for kind, _ in rl.tpl.EVENT_KINDS] == list(engine.KIND_NAMES)


def test_a_planned_channel_cannot_be_clicked(db):
    """The important one. A planned card is disabled, so the browser refuses
    the click, and it names no step, so no handler in the page script matches
    it either. Both, because either alone is one edit away from a card that
    looks live and does nothing. No channel is planned since the Alerts
    screen's spec. The one planned card among the destinations is Syslog,
    since layout B (docs/screens/alerts/SPEC-layout-b.md), and the rule is
    held over it."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        chan = modal_markup(html, "conn-ovl")
        cards = MODAL_CARD.findall(kind_cards(chan, "dest"))
        assert len(cards) == len(rl.tpl.ADD_CHANNELS) + 1 == 6, f"{feed}: {len(cards)} cards"
        planned = [body for kind, body in cards if "planned" in kind.split()]
        unbuilt = [n for n, stage in rl.tpl.ADD_CHANNELS if stage is None]
        assert len(unbuilt) == 0, f"{feed}: {unbuilt}"
        assert len(planned) == len(unbuilt) + 1, f"{feed}: {len(planned)} planned"
        assert f">{rl.tpl.SYSLOG_CARD[1]}<" in planned[0], feed
        for body in planned:
            assert "disabled" in body, f"{feed}: a planned channel is not disabled"
            assert 'aria-disabled="true"' in body, feed
            assert "data-stage" not in body, f"{feed}: a planned channel names a stage"
            assert "data-fields" not in body, f"{feed}: a planned channel names its fields"
            assert '<span class="tag-planned">planned</span>' in body, \
                f"{feed}: a planned channel does not say planned"



def test_only_a_built_integration_can_be_clicked(db):
    """Every unbuilt one is a planned card, disabled and without a step, so
    the browser refuses the click and no handler matches it. The one built
    provider is a real pick with its own fields (docs/screens/integrations).

    The window is the one Add window since layout B
    (docs/screens/alerts/SPEC-layout-b.md), so the five channels' cards are
    in it too and are held to the same rule."""
    add_host(db, "box", [])
    channels = [name for name, stage in rl.tpl.ADD_CHANNELS if stage]
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        intg = modal_markup(html, "conn-ovl")
        cards = MODAL_CARD.findall(intg)
        assert len(cards) == len(rl.tpl.ADD_CHANNELS) + len(catalogue()), \
            f"{feed}: {len(cards)} cards"
        built = channels + [n for _k, n, _g, b in catalogue() if b]
        for kind, body in cards:
            name = re.search(r'<div class="m-card-t">([^<]+)', body).group(1)
            if name in built:
                assert "pick" in kind.split() and "data-fields" in body, f"{feed}: {name}"
                assert "disabled" not in body, f"{feed}: {name}"
            else:
                assert "planned" in kind.split(), f"{feed}: {name} is not planned"
                assert "disabled" in body, feed
                assert "data-stage" not in body and "data-fields" not in body, feed
                assert '<span class="tag-planned">planned</span>' in body, feed
        for _k, name, _g, _b in catalogue():
            assert f">{name}<" in intg or f">{name}" in intg, f"{feed}: {name} is missing"
        # each built one's own fields, and no step for one that is not built
        steps = re.findall(r'<div class="m-stage" id="intg-([a-z]+)"', intg)
        assert steps == [k for k, _n, _g, b in catalogue() if b], feed


def test_mail_is_an_ordinary_channel_now(db):
    """**This test used to assert the opposite.** It was
    `test_the_live_window_does_not_offer_a_field_it_cannot_store` and it
    asserted the recipient field was disabled and the window said setting one
    "arrives with the alert engine (M3)". The owner asked on 2026-08-23 why it
    still said that. A recipient is not a credential, so mail takes the same
    step every other channel takes."""
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    assert "arrives with the alert engine (M3)" not in chan
    # The action reads Save since layout B, where it read Save channel.
    assert "disabled>Save" not in chan
    assert '<div class="m-stage" id="chan-email"' in chan
    assert 'id="chan-email-dest"' in chan


def test_the_mail_step_asks_for_an_address(db):
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    # The field label as it is drawn. The lower-case spelling this used to look
    # for lived only in the environment-variable text, which left the window on
    # 2026-08-23, so matching it would now pass on nothing.
    assert "Recipient address" in chan
    # **And it does not offer mail a URL placeholder**, which the owner caught on
    # 2026-08-23: a recipient address is not a URL. The
    # placeholder is per type now, and mail's is empty.
    # This step alone, sliced to where the next one starts, because every other
    # channel here legitimately has https:// in its own field.
    step = chan.split('id="chan-email"')[1].split('<div class="m-stage"')[0]
    assert 'placeholder=""' in step
    assert "https://" not in step


def test_the_sample_window_still_raises_a_toast(db):
    """The sample shell is the clickable demo, so its action raises the toast
    every other control there raises rather than posting anywhere.

    The Add window's action is the page script's on both feeds since layout B
    (docs/screens/alerts/SPEC-layout-b.md), so the shell's is marked
    data-sample, and the script reads the mark and says its toast before
    anything that leaves the page."""
    page = sample()
    chan = modal_markup(page, "conn-ovl")
    assert ('<button class="btn pri" id="conn-go" hidden data-dest="Save"'
            ' data-prov="Connect" data-sample="1">Save</button>') in chan
    add_host(db, "box", [])
    assert "data-sample" not in modal_markup(rl.render(db, now=NOW), "conn-ovl")
    click = page[page.index("connGo.onclick=function(){"):]
    click = click[:click.index("\n    };")]
    marked = click.index("if(connGo.dataset.sample){")
    said = click.index("toast(kind==='prov'?'The provider would be connected here'"
                       ":'The destination would be saved here');\n        return;")
    assert marked < said
    for leaves in ("location.href=", "connectProvider(stage)", "saveDestination(stage)"):
        assert said < click.index(leaves), f"{leaves} comes before the shell's toast"


def integrations_view_of(html):
    """The Integrations view, and nothing after it."""
    start = html.index('<div class="wrap view" id="integrations">')
    return html[start:html.index("\n</div>", start)]


def alerts_view_of(html):
    """The Alerts view, and nothing after it."""
    start = html.index('<div class="wrap view" id="alerts">')
    return html[start:html.index("\n</div>", start)]


def destinations_section(html):
    """The Alert destinations table of the Integrations view, and nothing
    after it. It stood on the Alerts view as Channels until layout B
    (docs/screens/alerts/SPEC-layout-b.md)."""
    view = integrations_view_of(html)
    return view[view.index('<h2 class="alh2">Alert destinations'):]


def seen_an_alert(db, host_name):
    """One resolved alert, so the Alerts screen is past its nothing-yet state
    and draws its tables (docs/screens/alerts/SPEC-layout-b.md: no alert ever
    is the one box)."""
    add_alert(db, host_name, "no report for 40 minutes, past the 35 minute threshold",
              NOW - timedelta(days=3), resolved=True)


def connect_a_provider(db, workspace_id=1):
    """One provider token, so the Integrations screen is past its
    nothing-connected box and draws both headings with no destination stored
    (docs/screens/alerts/SPEC-layout-b.md: no provider and no destination is
    the one box)."""
    hetzner = rl.joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hetzner.init(con)
    hetzner.add_token(con, "hzread" + "k" * 58, workspace_id,
                      now=NOW - timedelta(minutes=30))
    con.close()


# What still cannot deliver, so what still may not appear in a list of where
# alerts go. This was six until 2026-08-22, when the senders landed and Slack,
# Telegram, Discord and the webhook stopped being claims (docs/RECORD.md #259).
# The rule is the owner's of 2026-08-16 and it has not moved: a row for something
# with nothing behind it claims a delivery. Only the list of what has nothing
# behind it got shorter.
UNBUILT_CHANNELS = ("Ntfy", "Teams")


def test_the_configured_channels_list_holds_no_unbuilt_channel(db):
    """The list says what is configured, so a channel with nothing behind it
    has no row in it. A configured list that shows an unbuilt channel is
    claiming it delivers, which is the accuracy rule applied to the product
    rather than to prose (the owner 2026-08-16)."""
    add_host(db, "box", [])
    seen_an_alert(db, "box")
    # Mail is a stored row since 2026-09-20, the one an account is given.
    add_channel_holding_its_destination(db, "email", "ops@example.org",
                                        channel_type="email")
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        section = destinations_section(html)
        assert "Email" in section, f"{feed}: email is configured and is not listed"
        for name in UNBUILT_CHANNELS:
            assert name not in section, \
                f"{feed}: {name} is not built and is in the configured list"
        # and nothing in that panel is marked planned, because a planned row is
        # exactly the thing being removed
        assert "tag-planned" not in section, f"{feed}: a planned row is still listed"


def test_every_built_channel_is_offered_inside_the_add_window(db):
    """Removing the rows must not hide what can be added. Every built channel
    is in the Add window."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        chan = modal_markup(html, "conn-ovl")
        for name in ("Webhook", "Slack", "Discord", "Telegram", "Email"):
            assert f">{name}" in chan, f"{feed}: {name} is missing from the window"


def test_the_configured_channels_list_holds_only_what_is_set_up(db):
    """One row per configured channel, built from the shared fragment so the
    sample shell and the live page cannot drift apart."""
    rows = rl.tpl.sample_channel_rows_html()
    assert rows.count('<div class="crow">') == len(rl.tpl.SAMPLE_CHANNEL_ROWS)
    assert "Email" in rows
    assert rows in destinations_section(sample())
    add_host(db, "box", [])
    # A provider, so the list is drawn with nothing in it. With nothing
    # connected at all Integrations is its one box and draws no list.
    connect_a_provider(db)
    assert rl.alerts_channels_html() in destinations_section(rl.render(db, now=NOW))


def test_only_mail_has_no_menu_on_the_artboard(db):
    """Mail is configured by environment alone and has no row behind it, so
    there is nothing for a menu to act on. Every stored channel has one."""
    rows = rl.tpl.sample_channel_rows_html()
    assert rows.count('class="rm-t"') == len(rl.tpl.SAMPLE_CHANNEL_ROWS) - 1
    assert 'aria-label="Manage Email"' not in rows


def test_no_row_says_mail_is_set_on_the_server(db):
    """The fixed row said "set on the server" in every workspace, could not be
    removed, and was true of none but the operator's. The owner asked on
    2026-09-20 for it to be removed (docs/RECORD.md 4.186)."""
    add_host(db, "box", [])
    seen_an_alert(db, "box")
    # A provider, so the list this row stood in is drawn. It is on
    # Integrations since layout B and is not drawn with nothing connected.
    connect_a_provider(db)
    html = rl.render(db, now=NOW)
    assert rl.tpl.NO_DESTINATION_ADDED in destinations_section(html)
    assert "set on the server" not in html


def test_an_empty_channel_list_says_nothing_is_mailed():
    """Nothing configured is a real state and it has to read as one, rather
    than as a panel that failed to render."""
    empty = rl.tpl.channels_html([])
    assert "No channel is set up" in empty
    assert '<div class="ch2">' not in empty


def test_the_integrations_view_is_the_button_and_the_tables_only(db):
    """The owner, 2026-08-16: everything else comes out. The catalogue of what is
    planned lives inside the Add window instead. The view holds what is
    connected (docs/screens/integrations/SPEC.md): the providers, and since
    layout B the alert destinations (docs/screens/alerts/SPEC-layout-b.md)."""
    add_host(db, "box", [])
    for feed, html in (("sample", sample()),):
        view = html[html.index('<div class="wrap view" id="integrations">'):]
        # Integrations is the last view on a live page since Settings went
        # (`docs/RECORD.md` 4.123), so this stops at the next view OR at the
        # modals, whichever comes first. Without the second bound the slice
        # ran to the end of the document and swallowed the Add window, whose
        # catalogue is exactly what this test says is not in the view.
        ends = [i for i in (view.find('<div class="wrap view"', 10),
                            view.find('<div class="ovl"')) if i != -1]
        view = view[:min(ends)] if ends else view
        assert ('<button class="btn pri" data-open="conn-ovl">Add</button>'
                in view), feed
        # the connected provider, then the destinations, and no Feeds heading
        assert "Hetzner Cloud" in view, feed
        headings = re.findall(r'<h2 class="alh2">([^<]+)', view)
        assert headings == ["Providers", "Alert destinations"], f"{feed}: {headings}"
        assert rl.tpl.sample_channel_rows_html() in view, feed
        assert "No feed connected yet" not in html, feed
        # and not one line of the catalogue that used to fill the view
        for _k, name, _g, built in catalogue():
            if not built:
                assert name not in view, f"{feed}: the catalogue still lists {name}"
        # the only planned tags are in the row's menu, on the three actions
        # nothing behind them yet
        outside = re.sub(r'<div class="rm-p">.*?</div></div>', "", view, flags=re.S)
        assert "tag-planned" not in outside, f"{feed}: a planned row is still in the view"


def test_the_catalogue_moved_into_the_add_integration_window(db):
    """The list the owner removed from the view is not gone from the product, it
    is inside the window, where each unbuilt choice is marked planned."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        intg = modal_markup(html, "conn-ovl")
        for _k, name, _g, _b in catalogue():
            assert name in intg, f"{feed}: {name} is missing from the window"
        # each under its own kind: the providers, the monitoring cards, and
        # Syslog among the destinations (docs/screens/alerts/SPEC-layout-b.md)
        for kind, listed in (("prov", rl.tpl.PROVIDERS), ("mon", rl.tpl.MONITORING),
                             ("dest", [rl.tpl.SYSLOG_CARD])):
            for _k, name, _g, _b in listed:
                assert f">{name}<" in kind_cards(intg, kind), f"{feed}: {name} is not under {kind}"


# ------------------------------------------- the marks on the two pickers
#
# The owner asked for a vector on every channel and every integration on
# 2026-08-16, and then for real logos where they exist: the icon set the
# product already uses wherever it has one, which is nearly every alert
# channel, and a logo fetched from elsewhere for the integrations it lacks.
#
# So a channel with a mark we may reproduce in one colour carries it, and
# everything else keeps a neutral Phosphor glyph. theme.BRAND_MARKS is the list
# of the three and site/THIRD_PARTY_NOTICES.md is why the rest are not.

def test_every_channel_choice_carries_an_icon(db):
    """A picker where some rows have a shape and some do not looks broken. The
    count has to match the number of cards exactly."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        # the destinations' own cards: the five channels, and Syslog after them
        chan = kind_cards(modal_markup(html, "conn-ovl"), "dest")
        # per card, not per window: the window's own close glyph is an icon too
        cards = MODAL_CARD.findall(chan)
        assert len(cards) == len(rl.tpl.ADD_CHANNELS) + 1, feed
        for _kind, body in cards:
            assert body.count('<svg class="ic"') == 1, f"{feed}: a card has no glyph"
        for name, _stage in rl.tpl.ADD_CHANNELS:
            glyph = rl.tpl.CHANNEL_ICONS[name]
            assert theme.ICONS[glyph] in chan, f"{feed}: {name} has no {glyph}"


def test_every_integration_choice_carries_an_icon(db):
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        intg = modal_markup(html, "conn-ovl")
        # every card of the window that is not a channel's
        cards = MODAL_CARD.findall(intg)[len(rl.tpl.ADD_CHANNELS):]
        assert len(cards) == len(catalogue()), feed
        for _kind, body in cards:
            assert body.count('<svg class="ic"') == 1, f"{feed}: a card has no glyph"
        for _k, name, glyph, _b in catalogue():
            assert theme.icon(glyph, 20) in intg, f"{feed}: {name} has no {glyph}"


def test_a_choice_card_is_a_mark_and_a_name_and_nothing_else(db):
    """The owner, 2026-08-16: the name and the logo, no other text. Every card
    used to carry a sentence under the name, six of them in all, the mail
    card's among them. The class that drew them is gone from both pickers, so
    a session that adds one back fails here rather than in review.

    The two pickers are one window since layout B
    (docs/screens/alerts/SPEC-layout-b.md), on both feeds, and every card of
    it is read."""
    add_host(db, "box", [])
    gone = ("A message to an address you own", "A post to a channel or a person",
            "A push to an ntfy topic", "A scrapeable endpoint")
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        window = modal_markup(html, "conn-ovl")
        assert "m-card-d" not in window, f"{feed}: a card still has a sentence"
        found = MODAL_CARD.findall(window)
        assert len(found) == len(rl.tpl.ADD_CHANNELS) + len(catalogue()), feed
        for cards in found:
            body = cards[1]
            assert body.count("<div") == 1, f"{feed}: a card holds two blocks"
        for sentence in gone:
            assert sentence not in html, f"{feed}: {sentence!r} is still on the page"


def test_nothing_the_page_draws_is_fetched_from_anywhere(db):
    """The whole-page half of the same rule test_theme.py checks per glyph. Two
    icon sets are inlined now and the tempting shortcut for the next one is a
    CDN link, which would be a third-party request on a page whose entire
    argument is that it makes none.

    The fonts are self hosted and the favicons sit beside the page, so the only
    thing here that may name a host is a link a reader clicks.
    """
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        for smell in ("<img", "<use", "<image", "xlink:href", "@import",
                      "url(http", "src=\"http", "src=\"//"):
            assert smell not in html, f"{feed}: the page fetches something, {smell!r}"
        # Every reference the browser *fetches* is a relative path of ours, so
        # the page carries its own assets wherever it is served from.
        #
        # **A link a reader clicks is a different thing and is exempt**, which
        # the docstring above already said and the assertion did not. It has to
        # be: since 2026-08-23 the dashboard is served by the app at /, /alerts
        # and /host/<name>, so a relative action link would resolve against the
        # current path and `api/admin/...` clicked from /host/box would ask for
        # /host/api/admin/... A navigation link is absolute on purpose.
        fetched = re.findall(r'(?:\bsrc|<link[^>]*\bhref)="([^"]+)"', html)
        for ref in fetched:
            if ref.startswith(("http", "//", "mailto:", "#")):
                continue
            assert not ref.startswith("/"), f"{feed}: {ref} is an absolute path"


def test_an_action_link_is_absolute_because_a_deep_link_would_break_it(db):
    """The other half of the rule above, asserted rather than left implied.
    The dashboard answers at /host/<name>, so a relative action link would be
    resolved against that path and 404."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    # Both shapes, because the Slack connect stopped being an <a> on
    # 2026-08-23 and became the footer button's own navigation. A rule that
    # only looked at href attributes would have passed by finding nothing.
    paths = (re.findall(r'<a[^>]*href="([^"]*api/admin[^"]*)"', html)
             + re.findall(r"location\.href='([^']*api/admin[^']*)'", html)
             + re.findall(r"fetch\('([^']*api/admin[^']*)'", html))
    assert paths, "no admin action path on the page, so this tests nothing"
    for path in paths:
        assert path.startswith("/"), f"{path} would break from /host/<name>"


def test_a_configured_row_carries_the_same_icon_as_its_card(db):
    """One glyph per channel, named once, so the list and the window cannot draw
    different pictures of the same destination."""
    add_host(db, "box", [])
    seen_an_alert(db, "box")
    add_channel_holding_its_destination(db, "email", "ops@example.org",
                                        channel_type="email")
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        section = destinations_section(html)
        assert theme.ICONS[rl.tpl.CHANNEL_ICONS["Email"]] in section, feed
        # One glyph per row. The artboard draws three rows and this live page
        # holds the one stored mail row, so the count is per feed rather than
        # a single number that would have to be wrong for one of them.
        expected = len(rl.tpl.SAMPLE_CHANNEL_ROWS) if feed == "sample" else 1
        assert section.count('<div class="nm"><svg class="ic"') == expected, feed


def test_every_choice_has_an_icon_name_the_theme_carries():
    """A name theme.ICONS does not hold used to be a KeyError deep in a dict
    lookup. Both maps are checked here so a channel added without a glyph fails
    the suite rather than the build on the owner's machine."""
    for name, _stage in rl.tpl.ADD_CHANNELS:
        assert name in rl.tpl.CHANNEL_ICONS, f"{name} has no glyph"
    for _k, name, glyph, _b in catalogue():
        assert glyph in theme.ICONS or glyph in theme.MARKS, f"{name} has no glyph"
    # the Add window's first cards are choices too
    for _key, name, glyph in rl.tpl.ADD_KINDS:
        assert glyph in theme.ICONS, f"{name} has no glyph"
    for glyph in rl.tpl.CHANNEL_ICONS.values():
        assert glyph in theme.ICONS, f"theme.ICONS has no {glyph}"


def test_the_five_channels_the_owner_named_carry_their_own_logo():
    """The owner picked these by name on 2026-08-16, and Phosphor draws all five, so
    the pairing is asserted both ways: a logo cannot drift onto the wrong product
    and a sixth cannot appear without this failing."""
    want = {"Slack": "slack-logo", "Discord": "discord-logo",
            "Telegram": "telegram-logo", "Webhook": "webhooks-logo",
            "Microsoft Teams": "microsoft-teams-logo"}
    for product, glyph in want.items():
        assert rl.tpl.CHANNEL_ICONS[product] == glyph, \
            f"{product} is drawn with {rl.tpl.CHANNEL_ICONS[product]}"
    logos = {p for p, g in rl.tpl.CHANNEL_ICONS.items() if g.endswith("-logo")}
    assert logos == set(want), f"a channel gained or lost a logo: {logos ^ set(want)}"


def test_ntfy_and_email_keep_a_neutral_glyph():
    """Neither has a Phosphor logo. ntfy is niche enough that Phosphor draws
    none, and email is a protocol rather than a product, so a mark would be
    naming a vendor that is not involved."""
    for product in ("Ntfy", "Email"):
        assert not rl.tpl.CHANNEL_ICONS[product].endswith("-logo"), \
            f"{product} gained a logo, which nothing asked for"


def test_the_integration_marks_reach_both_feeds(db):
    """The owner, 2026-09-07, having read what each owner's terms say, chose
    logos over names, everywhere, as in the drawings. Every mark the sketch
    draws is on the page, from theme.MARKS
    (record 4.152)."""
    marks = sorted(g for _k, _n, g, _b in catalogue() if g in theme.MARKS)
    assert len(marks) == 11, marks
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        intg = modal_markup(html, "conn-ovl")
        for mark in marks:
            assert theme.icon(mark, 20) in intg, f"{feed}: {mark}"


def test_no_verdict_glyph_reaches_either_page(db):
    """docs/DESIGN.md section 3: no tick or checkmark glyphs anywhere. Neither
    as a character nor as an icon that claims one."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        for tick in ("✓", "✔", "✅", "☑", "☐", "√"):
            assert tick not in html, f"{feed}: a tick glyph reached the page"
    for name in theme.ICONS:
        for claim in ("check", "shield", "seal", "lock", "badge", "medal"):
            assert claim not in name, f"theme.ICONS carries a verdict glyph: {name}"


def test_alerts_and_integrations_are_both_views_again(db):
    """Integrations came back to the live nav on 2026-08-30 (RECORD 4.139).
    Both are views on the live page and both in the sample shell."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        assert '<div class="wrap view" id="alerts">' in html, feed
        assert 'data-v="alerts"' in html, feed
        assert '<div class="wrap view" id="integrations">' in html, feed
        assert 'data-v="integrations"' in html, feed
# ---------------------------------------------------------------- fleet order
# The list is sorted by how much a row needs a person, then by host name. The
# band order itself lives in a comment above FLEET_BANDS in build.py. These
# tests pin it, because a sort that silently loses a row, or that comes out in
# a different order on the next render, is worse than no sort at all.


def fleet_order(html):
    """The host names in the fleet list, in the order the page shows them.

    Scoped to the fleet view on purpose. A host's Settings tab also carries
    data-host attributes, so a search of the whole document would read those
    too and the order would mean nothing.
    """
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    return re.findall(r'<a class="row" href="[^"]*" data-host="([^"]+)"', fleet)


def test_the_live_fleet_puts_the_rows_that_need_a_person_first(db):
    """The owner, 2026-08-15: what matters rises to the top.

    The four hosts are named so that alphabetical order is the exact reverse
    of the order they should come out in. Sorting by name alone passes nothing
    here, and neither does the database's own ORDER BY name.
    """
    add_host(db, "a-reporting", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    add_host(db, "b-revoked", [], revoked=True)
    add_host(db, "c-silent", [(NOW - timedelta(hours=3), document())],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_host(db, "d-never", [])
    order = fleet_order(rl.render(db, now=NOW))
    # b-revoked is absent: the fleet is the working fleet and a revoked row has
    # been taken out of it deliberately. d-never is last, because a pending
    # enrolment is not a finding. Both changed on 2026-08-16 after nine
    # placeholder rows buried three real servers on the live page.
    assert order == ["c-silent", "a-reporting", "d-never"]
    assert "b-revoked" not in order


def test_a_revoked_host_is_not_in_the_fleet_but_is_not_destroyed(db):
    """Revoking says this row is not a server of mine. It leaves the list, and
    the row stays in the database so nothing is lost and a later screen can show
    revoked hosts on purpose."""
    add_host(db, "gone", [], revoked=True)
    add_host(db, "here", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert fleet_order(html) == ["here"]


def test_a_pending_enrolment_never_outranks_a_working_server(db):
    """The bug the owner hit: nine `new-xxxxxx` rows that had never been a server
    sat above his three real ones, because the sort ranked never-reported with
    the findings. One that never started has not stopped."""
    for i in range(4):
        add_host(db, f"a-pending-{i}", [])
    add_host(db, "z-works", [(NOW - timedelta(minutes=2), document())],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    order = fleet_order(rl.render(db, now=NOW))
    assert order[0] == "z-works", f"a pending row outranked a working server: {order}"


def fleet_row(word, name):
    """A fleet row with only the two fields the sort reads filled in."""
    return rl.tpl.FleetRow("warn", word, name)


# One host in every band, handed to the sort in the wrong order on purpose.
# The names are chosen so that alphabetical order is the exact reverse of the
# band order, so neither the input order nor a plain sort by name can pass.
EVERY_BAND = [
    ("reporting", "aa-reporting"),
    ("intended", "ab-intended"),
    ("paused", "ba-paused"),
    ("revoked", "bb-revoked"),
    ("silent 12m", "ca-silent"),
    ("not watched", "da-never"),
    ("unexplained", "ea-unexplained"),
    ("stale rule", "fa-stale"),
    ("unreviewed", "ga-unreviewed"),
    ("conflict", "ha-conflict"),
]


def test_one_host_in_every_band_comes_out_in_the_documented_band_order():
    """The band order in build.py above FLEET_BANDS, asserted as a list.

    If this test and that comment ever disagree, one of them is a lie and the
    comment is the one a reader trusts, so fix the code or change both.
    """
    rows = [fleet_row(word, name) for word, name in EVERY_BAND]
    order = [row.name for row in rl.tpl.sort_fleet_rows(rows)]
    assert order == [
        "ha-conflict",       # reachable and you marked it closed
        "ga-unreviewed",     # reachable, nobody has said whether that is intended
        "ea-unexplained",    # the probe sees it, no agent can attribute it
        "ca-silent",         # it reported before and has stopped, a real problem
        "ba-paused",         # deliberately not watched
        "bb-revoked",        # unranked now: the fleet filters revoked rows out,
                             # so this word should never reach the sort at all
        "aa-reporting",      # the quiet majority
        "ab-intended",
        "fa-stale",          # a rule allows it, nothing listens behind it. With
                             # the quiet ones since 2026-09-21: worth seeing,
                             # owed by nobody (docs/RECORD.md 4.198)
        # Last, and this is the change of 2026-08-16. A pending enrolment is not
        # a finding, and ranking it with the problems buried the working fleet.
        "da-never",
    ]


def test_the_retired_words_sort_into_the_same_bands_as_the_words_that_replaced_them():
    """`you said no` became `conflict` and `never reviewed` became
    `unreviewed`. The rename and this sort are separate branches, so the sort
    reads both sets of words rather than dropping a row into the unknown band
    depending on which one landed first."""
    for retired, current in rl.tpl.RETIRED_STATE_WORDS.items():
        assert rl.tpl.fleet_band(retired) == rl.tpl.fleet_band(current)


def test_two_hosts_in_one_band_come_out_alphabetically_whatever_their_case():
    rows = [fleet_row("unreviewed", name) for name in ("Zeta", "alpha", "Beta", "aardvark")]
    order = [row.name for row in rl.tpl.sort_fleet_rows(rows)]
    assert order == ["aardvark", "alpha", "Beta", "Zeta"]


def test_the_order_does_not_jitter_between_renders():
    """The reason the name is the tiebreaker at all. A list that reorders for
    no visible reason is worse than one that is merely alphabetical, and the
    same fleet must render the same way on every request."""
    rows = [fleet_row(word, name) for word, name in EVERY_BAND]
    once = rl.tpl.sort_fleet_rows(rows)
    twice = rl.tpl.sort_fleet_rows(rows)
    assert once == twice
    # Sorting the result again changes nothing, and shuffling the input does
    # not change the output either. Two names that differ only in case are in
    # here because they are the one case where a stable sort would otherwise
    # let the input order decide.
    assert rl.tpl.sort_fleet_rows(once) == once
    mixed_case = [fleet_row("unreviewed", n) for n in ("web-01", "WEB-01", "web-02")]
    assert (rl.tpl.sort_fleet_rows(mixed_case)
            == rl.tpl.sort_fleet_rows(list(reversed(mixed_case))))


def test_a_state_the_sort_does_not_recognise_still_gets_its_row():
    """The worst possible bug in a list like this is a row that is not there.

    A word nobody has taught the sort about must never cost a server its line.
    It sorts above the quiet majority so somebody sees it, and below every
    state we do recognise so it cannot push a real finding off the top.
    """
    rows = [fleet_row("conflict", "known-bad"),
            fleet_row("quarantined", "strange-01"),
            fleet_row("", "no-word-at-all"),
            fleet_row("reporting", "quiet-01")]
    out = rl.tpl.sort_fleet_rows(rows)
    assert len(out) == len(rows)
    by_name = lambda row: row.name  # noqa: E731
    assert sorted(out, key=by_name) == sorted(rows, key=by_name), \
        "the sort changed a row rather than moving it"
    assert [row.name for row in out] == ["known-bad", "no-word-at-all", "strange-01", "quiet-01"]


def test_the_sample_shell_is_sorted_by_the_same_bands():
    """One template, two feeds. The demo and the live page must agree about
    what order a fleet comes in, so this reads the order off the sample page
    and checks it against the bands rather than against a fixed list of hosts.
    """
    word_of = {row.name: row.word for row in rl.tpl.FLEET_SAMPLE}
    order = fleet_order(rl.tpl.build_sample())
    assert len(order) == len(rl.tpl.FLEET_SAMPLE), "the sample shell lost a row"
    bands = [rl.tpl.fleet_band(word_of[name]) for name in order]
    assert bands == sorted(bands), f"the sample fleet is out of band order: {order}"
    for band in set(bands):
        names = [n for n in order if rl.tpl.fleet_band(word_of[n]) == band]
        assert names == sorted(names, key=str.casefold), f"band {band} is not alphabetical"
# ------------------------------------------- the host detail's own sub tabs
#
# The owner, on the live host page: the server view is split into its tabs again,
# as it was before, and is not one long page to scroll.
# Two more of his notes ride along: per server settings belong in the host, and
# fleet-wide Changes folds into the host that changed.

SSHD6 = {"protocol": "tcp", "family": "v6", "bind_address": "::", "port": 22,
         "process_name": "sshd", "pid": 1}

HOST_TABS = [("overview", "Overview"), ("services", "Services"), ("path", "Packet path"),
             ("evidence", "Evidence"), ("changes", "Changes"), ("rules", "Rules"),
             ("settings", "Settings")]


def host_section(html, name):
    """One host's slice of the page, so a claim about the host detail cannot be
    satisfied by markup somewhere else on it."""
    start = html.index(f'id="host-{name}"')
    rest = html[start:]
    end = rest.find('class="wrap view"')
    return rest[:end] if end > 0 else rest


def tab_body(section, name, key):
    """One tab panel out of a host's slice. A panel ends at the next panel or
    at the first-look window, which sits after the last panel."""
    rest = section.split(f'id="t-{name}-{key}"')[1]
    return re.split(r'<div class="tab|<div class="ovl', rest)[0]


def header_agent(html):
    """The word in the agent fact of every host header on a page."""
    return re.findall(r'<div class="k">agent</div><div class="v">(?:<svg.*?</svg>)?(\w+)</div>',
                      html, re.S)


# --------------------------------------------- which agent produced this
#
# The fleet was upgraded 0.1.5 to 0.1.6 and nothing in the product could
# confirm it: every host had to be reached over ssh to answer a question about
# the hosts (RECORD 4.89). The document carries the version now, so the page
# can say it.

def test_the_host_header_is_the_five_facts_and_names_no_agent_version(db):
    """The header of 2026-09-04 (docs/screens/host-overview/SPEC.md section
    2): agent, hostname, agent reported, probed, ports. The agent version
    that RECORD 4.89 put on the old line is off the header; where it lives
    next is a question put to the owner on 2026-09-05."""
    doc = dict(document(listening=[SSHD]), agent_version="0.1.6")
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    head = host_section(rl.render(db, now=NOW), "box").split('<div class="acts">')[0]
    assert re.findall(r'<div class="k">([^<]+)</div>', head) == [
        "agent", "hostname", "agent reported", "probed", "ports"]
    assert '<div class="k">hostname</div><div class="v">Almabox</div>' in head
    assert '<div class="k">agent reported</div><div class="v"><span class="num">2m</span> ago</div>' in head
    assert probed_cell('never') in head
    assert '<div class="k">ports</div><div class="v"><span class="num">1</span></div>' in head
    assert "0.1.6" not in head
    assert "schema <span" not in head and "sections read" not in head


def test_a_version_out_of_a_document_is_escaped_like_any_other_text(db):
    """It is stamped by our own build, and it still arrives over the wire in
    a document, so it is treated as text a host sent."""
    doc = dict(document(listening=[SSHD]), agent_version="<script>x</script>")
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "<script>x</script>" not in html


@pytest.mark.usefixtures("v2_tabs")
def test_the_host_detail_carries_one_tab_per_subject(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[SSHD, LOOP], podman=[JELLYFIN]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    section = host_section(rl.render(db, now=NOW), "box")
    for key, label in HOST_TABS:
        assert f'for="tb-box-{key}">{label}</label>' in section, f"no {label} tab"
        assert f'id="t-box-{key}"' in section, f"no {label} panel"
    # and each panel carries its own content rather than being an empty shell.
    #
    # The Overview and Services headings left on 2026-08-24, the owner's second
    # declutter round: each restated the label of the tab it sat under. So the
    # markers are the tabs' own content, which is the stronger check anyway: a
    # heading over an empty panel would have passed the old one.
    for key, marker in (("overview", 'class="hstrip"'),
                        ("services", 'class="srow"'),
                        # one box per tool since 2026-09-10
                        ("path", 'class="pt-flow'),
                        ("evidence", 'class="mr"'),
                        ("changes", 'class="panel ctbl"'),
                        # one bordered list per firewall since 2026-09-10
                        ("rules", 'class="fw"'),
                        ("settings", 'class="hset"')):
        assert marker in tab_body(section, "box", key), \
            f"the {key} tab does not carry {marker!r}"


@pytest.mark.usefixtures("v2_tabs")
def test_the_tabs_switch_without_javascript(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    section = host_section(html, "box")
    # a radio group per host, the first one checked, and CSS does the switching
    assert 'type="radio" class="tabsel k-overview" name="tabs-box"' in section
    assert section.count('name="tabs-box"') == len(HOST_TABS)
    # one tab open, the first. Counted on the tab radios rather than on every
    # " checked>" in the slice, because this host's Settings tab is a rail of
    # radios of its own now and one of those is checked too.
    assert len(re.findall(r'class="tabsel k-\w+" name="tabs-box" id="[^"]+" checked>',
                          section)) == 1
    assert ".tabsel.k-overview:checked~.tab.k-overview{display:block}" in html
    # the old script-driven tabs are gone, so a blocked script cannot hide them
    assert "function setT(" not in html
    assert "data-t=" not in html








def test_changes_moved_into_the_host_and_left_the_top_nav(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[LOOP, SSHD])),
                         (NOW - timedelta(minutes=17), document(listening=[LOOP]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert '<span class="st nt">started</span>' in tab_body(host_section(html, "box"), "box", "changes")
    # no top level Changes: not in the nav, and not as a view of its own
    assert 'data-v="changes"' not in html
    assert 'id="changes"' not in html
    assert ">Changes</a>" not in html


def test_authorisation_is_the_greyed_planned_entry_again(db):
    """It was removed on 2026-08-28 with the Settings page, and the owner asked
    for both back in as many words on 2026-08-30 (RECORD 4.140). It has never
    had a view, so it is the unclickable form nav_html draws for a planned
    item: no data-v, the tag beside the word, and nothing behind it."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    nav = html.split('<nav class="nav">')[1].split("</nav>")[0]
    assert 'class="planned">Authorisation<span class="tag-planned">planned</span>' in nav
    assert 'data-v="auth"' not in html
    assert 'id="auth"' not in html
    for label in ("Fleet", "Alerts", "Integrations", "Settings"):
        assert f">{label}</a>" in nav


def test_the_sample_shell_still_shows_what_is_coming(db):
    """The two feeds are for two readers. A live page is what a customer sees
    and the sample is where the owner looks at what is planned, so the entries a
    live page drops stay in the drawing."""
    sample = rl.tpl.build_sample()
    nav = sample.split('<nav class="nav">')[1].split("</nav>")[0]
    assert "Authorisation" in nav
    assert ">Settings</a>" in nav


def test_per_server_settings_are_in_the_host_and_the_account_is_not(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    section = host_section(html, "box")
    settings = tab_body(section, "box", "settings")
    for wanted in ("js-pause", "js-remove"):
        assert wanted in settings, f"per server setting missing: {wanted}"
    # The planned rows of the spec (Timezone, Labels, Provider, the mail
    # switches) carry the tag and nothing beside it; the old sweep rows and
    # Authorised addresses are gone.
    for gone in ("production", "development", "Authorised addresses"):
        assert gone not in settings, f"a dead control is back: {gone}"
    # Renaming is a settings row (the owner, 2026-08-24): the field with the id
    # the page script reads, and the button wired to the rename endpoint.
    assert '<span class="idv" id="id-box">box</span>' in settings and "js-rename" not in settings
    # Muting is not a row (2026-08-16): the header already carries the button,
    # and one setting in two places is how two places start disagreeing.
    assert "Mute" not in settings
    # The header keeps the name and the mute button, and renames nothing.
    header = section.split('<div class="hh">')[1].split("</div>\n  </div>")[0]
    # The mute is a button that opens a menu of lengths since 2026-08-24,
    # and renaming lives in settings since the same day, so the header
    # carries the menu trigger and no rename control.
    assert ">Mute<" in header and "Mute 2h" not in header
    for gone in ("pencil", "rnsel", "rnbox", "js-rename", 'id="rn-box"'):
        assert gone not in header, f"the header still renames: {gone}"
    # The account level settings stay on the top level Settings view and never
    # leak into a host page. The page itself is back since 2026-08-30, on
    # the owner's word (RECORD 4.140), so the page-wide ban this used to carry
    # is gone with it and only the host-section half still holds.
    for account in ("Appearance", "Authenticator app", "Billing"):
        assert account not in section, f"account setting leaked into the host: {account}"
    # And the three things the owner had removed from settings are gone from the
    # whole page rather than relocated: the provider connection, the install
    # command and the not-in-v1 list (2026-08-15). This half of the test used to
    # assert they were still present at the top level, which stopped being true.
    # "Hetzner Robot" is deliberately NOT checked here: it is a legitimate
    # provider name on a host row in the fleet table. What was removed is the
    # provider CONNECTION block, whose Connect buttons are the unambiguous mark.
    # `get.whichports.com/install.sh` is no longer in this list. It came back
    # deliberately on 2026-08-28 in the add-server flow's "Try it, send
    # nothing" card, which is not a settings page and mints nothing
    # (`docs/RECORD.md` 4.124). What must stay gone is the settings page
    # pasting one, and the settings page is gone entirely.
    assert "Not in v1" not in html, "removed from settings but still on the page"
    # The provider connects on the Integrations screen since 2026-09-06
    # (docs/screens/integrations/SPEC.md), never on a server's settings.
    assert ">Connect</button>" not in section


def test_environment_is_planned_on_both_feeds_and_tags_takes_one_more(db):
    """The owner asked for labels on 2026-08-24 (RECORD 4.102) and placed them
    under Server on 2026-09-04 (docs/screens/host-settings/SPEC.md). Since
    2026-10-02 they are the Tags row (test_tags_screen.py), and Environment
    stays planned, a disabled field with the tag, on the live page too."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    settings = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "settings")
    assert "<h3>Labels" not in settings
    assert 'class="in mono tagin js-tag-add"' in settings
    assert ('<input class="in" value="" placeholder="" disabled>'
            '<span class="tag-planned">planned</span>') in settings
    assert settings.count('<input class="in" value="" placeholder="" disabled>') == 1


# ----------------------------------- one bad document must not freeze the fleet

def test_one_hosts_malformed_document_does_not_take_the_whole_render_down(db):
    """Measured on 2026-08-16 against a copy of the production database. One
    stored document with a valid envelope and `"listening": [null]` raised
    AttributeError out of `digest`, so `render_live.py` exited before writing
    anything and the dashboard froze for every host, showing stale data with
    nothing saying so.

    The ingest stores a document verbatim on purpose (PRODUCT.md 4e) and
    validates only the envelope, so any enrolled host can post this. Three
    separate guards claimed to prevent it: `parse_report`'s docstring says a
    single malformed document must not take the page down, the packet path's
    own malformed-document test says the same, and neither covered a wrong
    type because both were written against None.
    """
    add_host(db, "good", [(NOW, document())], last_report_at=NOW.isoformat())
    add_host(db, "bad", [(NOW, {"schema_version": 1, "collected_at_unix": 1,
                                "hostname": "bad", "sockets": {"listening": [None]}})],
             last_report_at=NOW.isoformat())
    hosts, newest, history, alerts, port_names, _findings, _channels, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    names = [h["name"] for h in hosts]
    assert "good" in names and "bad" in names
    assert newest["good"] is not None, "the healthy host lost its document"


def test_a_section_of_the_wrong_type_is_named_rather_than_read_as_empty(db):
    """The gap this used to record, closed.

    A section holding the wrong type used to read as an empty section, so "the
    agent reported no sockets" and "the agent reported something we could not
    make sense of" were the same on screen. That is the conflation
    docs/RECORD.md 4.46 records, where a firewall the agent was not allowed to
    read looked identical to a firewall with nothing in it.

    The hard case is the one below: the section says it was collected, and what
    it holds is not the shape this page reads. Nothing may claim the read
    succeeded, and nothing may claim the host has no sockets.
    """
    doc = document(listening=[SSHD])
    doc["sockets"] = {"status": "collected", "listening": "not a list"}
    add_host(db, "wrongtype", [(NOW, doc)], last_report_at=NOW.isoformat())
    hosts, newest, history, alerts, port_names, _findings, _channels, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    assert newest["wrongtype"] is not None, "the document still loads"
    assert rl.unreadable_sections(doc) == ("sockets",)

    html = rl.render(db, now=NOW)
    section = host_section(html, "wrongtype")
    # the Evidence strip names it, in the vocabulary the other tags use
    assert theme.status("fail", "listening sockets · not readable") in section
    # and it is not counted as one of the nine reads. The count reaches no
    # screen since 2026-08-24 (machinery), so what gets asserted
    # is the counter over the view every screen actually reads, where the
    # wrong-type section carries the marker rather than its own claim.
    assert rl.doc_counts(rl.read_view(doc))[2] == 5
    assert rl.doc_counts(doc)[2] == 6, "the stored document is left as it came"
    assert "sections read" not in html


def test_a_document_that_would_still_end_the_render_is_named_not_blanked(db):
    """The backstop, for anything the type sweep does not cover. `walks` runs
    the packet path over the newest document before any HTML exists, so a
    document that would raise later is caught at load time and its host is
    named instead of ending the render for everyone."""
    good_doc = document()
    bad_doc = document()
    bad_doc["marker"] = "explode"      # document() gives both the same hostname
    add_host(db, "good", [(NOW, good_doc)], last_report_at=NOW.isoformat())
    add_host(db, "bad", [(NOW, bad_doc)], last_report_at=NOW.isoformat())
    original = rl.pp.traced_ports

    def explode(doc):
        if doc.get("marker") == "explode":
            raise RuntimeError("a shape the sweep did not anticipate")
        return original(doc)

    rl.pp.traced_ports = explode
    try:
        hosts, newest, history, alerts, port_names, _findings, _channels, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    finally:
        rl.pp.traced_ports = original
    assert newest["good"] is not None, "the healthy host lost its document"
    assert "bad" in rl.unreadable_documents(history)


def test_the_whole_page_still_renders_with_a_malformed_document_present(db):
    """The end to end version, because the crash was in load and the page is
    what the timer writes."""
    add_host(db, "good", [(NOW, document())], last_report_at=NOW.isoformat())
    add_host(db, "bad", [(NOW, {"schema_version": 1, "collected_at_unix": 1,
                                "hostname": "bad", "nftables": {"tables": "oops"}})],
             last_report_at=NOW.isoformat())
    html = rl.render(db, now=NOW)
    assert "good" in html and len(html) > 1000


# ------------------------------ a section nobody could read is not an empty one
#
# docs/RECORD.md 4.46 in the renderer. The type-safe sweep of #127 stopped a
# wrong-typed section from raising, and what it left behind was a section that
# reads as empty, so "the agent found nothing" and "the agent sent something we
# could not make sense of" looked identical. These are the tests for telling
# them apart, and for the crash half that the sweep did not reach: every one of
# the cases below was measured against a copy of production first.

def full_document():
    """One document carrying every field this page reads, in the shapes
    `agent/internal/hostdoc/hostdoc.go` gives them.

    It exists to catch the opposite failure from the rest of this section: a
    shape check strict enough to call a healthy host unreadable would be the
    same false claim pointed the other way.
    """
    return {
        "schema_version": 1, "hostname": "full", "collected_at_unix": int(NOW.timestamp()),
        "sockets": {"status": "collected",
                    "sources": {"tcp": {"status": "collected"},
                                "tcp6": {"status": "permission_denied", "cause": "permission"}},
                    "listening": [SSHD, LOOP]},
        "nftables": {"status": "collected", "sources": {"netlink": {"status": "collected"}},
                     "tables": [{"family": "inet", "name": "filter", "chains": [
                         {"name": "input", "type": "filter", "hook": "input", "priority": 0,
                          "policy": "drop", "builtin": True,
                          "rules": [{"text": "tcp dport 22 accept", "rendered": "full",
                                     "comment": "ssh"}]}]}]},
        "iptables": {"status": "collected", "tables": [{"name": "filter", "chains": [
            {"name": "INPUT", "builtin": True, "policy": "ACCEPT",
             "rules": [{"text": "-A INPUT -j ACCEPT", "rendered": "full"}]}]}]},
        "ip6tables": {"status": "not_present", "cause": "not_installed"},
        "ufw": {"status": "collected", "conf": {"ENABLED": "yes"},
                "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                "rules": ["allow any 22 0.0.0.0/0 any 0.0.0.0/0 in"],
                "rules6": ["allow any 22 ::/0 any ::/0 in"]},
        "firewalld": {"status": "collected", "conf": {"DefaultZone": "public"},
                      "zones": [{"name": "public", "origin": "etc", "parsed": True,
                                 "target": "default", "services": ["ssh"],
                                 "ports": [{"port": "8096", "protocol": "tcp"}],
                                 "interfaces": ["eth0"], "source_addrs": ["10.0.0.0/8"],
                                 "forward_ports": [{"port": "80", "protocol": "tcp",
                                                    "to_port": "8080"}],
                                 "masquerade": False, "forward": True}]},
        "containers": {"status": "collected", "podman": [JELLYFIN],
                       "docker": [{"id": "d1", "name": "nginx", "image": "nginx",
                                   "ports": [{"host_ip": "0.0.0.0", "host_port": 80,
                                              "container_port": 80, "protocol": "tcp"}]}]},
        "overlays": {"status": "collected",
                     "interfaces": [{"name": "wg0", "type": "65534", "devtype": "wireguard"},
                                    {"name": "ts0", "type": "65534", "tun": True}],
                     "tailscale": {"socket": True, "state_dir": True},
                     "netbird": {"socket": False}},
        "rule_files": {"status": "collected",
                       "files": [{"path": "/etc/ufw/user.rules", "mtime_unix": 1786887003}]},
    }


def test_a_document_in_the_shape_the_agent_sends_has_no_unreadable_section(db):
    """The guard against over-strictness. A false "not readable" is the same
    kind of claim as a false empty, so every fixture this suite renders, and a
    document carrying every field the page reads, must come back clean."""
    for doc in (document(), document(listening=[SSHD, LOOP], podman=[JELLYFIN]),
                path_document(), full_document()):
        assert rl.unreadable_sections(doc) == (), doc.get("hostname")


def test_a_null_where_a_list_belongs_is_absence_and_not_an_unreadable_section():
    """Go marshals a nil slice as null, and `Listening []ListeningSocket` in
    hostdoc.go carries no omitempty, so a host with nothing listening sends
    `"listening": null`. Calling that unreadable would put a fault on every
    quiet host in the fleet."""
    doc = document()
    doc["sockets"] = {"status": "collected", "listening": None}
    doc["containers"] = {"status": "collected", "docker": None, "podman": None}
    assert rl.unreadable_sections(doc) == ()


WRONG_TYPES = [
    ("sockets", {"status": "collected", "listening": "not a list"}, "listening sockets"),
    ("sockets", {"status": "collected", "listening": [None, 7]}, "listening sockets"),
    ("sockets", "not an object", "listening sockets"),
    ("nftables", {"status": "collected", "tables": {"family": "inet"}}, "nftables"),
    ("nftables", {"status": "collected", "tables": [{"chains": "oops"}]}, "nftables"),
    ("nftables", {"status": "collected", "tables": [{"chains": [{"rules": [7]}]}]}, "nftables"),
    ("iptables", {"status": "collected", "tables": True}, "iptables (legacy)"),
    ("ip6tables", {"status": "collected", "tables": ["a string"]}, "ip6tables (legacy)"),
    ("ufw", {"status": "collected", "conf": ["ENABLED"]}, "ufw"),
    ("ufw", {"status": "collected", "rules": [None]}, "ufw"),
    ("ufw", {"status": "collected", "defaults": "DROP"}, "ufw"),
    ("firewalld", {"status": "collected", "zones": "public"}, "firewalld"),
    ("firewalld", {"status": "collected", "zones": [{"services": [7]}]}, "firewalld"),
    ("containers", {"status": "collected", "podman": {"name": "jellyfin"}}, "containers"),
    ("containers", {"status": "collected", "docker": [{"ports": "8096"}]}, "containers"),
    ("overlays", {"status": "collected", "interfaces": ["wg0"]}, "overlay interfaces"),
    ("overlays", {"status": "collected", "tailscale": "present"}, "overlay interfaces"),
    ("rule_files", {"status": "collected", "files": [{"mtime_unix": "yesterday"}]},
     "rule file mtimes"),
    ("rule_files", {"status": "collected", "files": 4}, "rule file mtimes"),
    ("sockets", {"status": ["collected"], "listening": []}, "listening sockets"),
    ("sockets", {"status": "collected", "sources": {"tcp": "collected"}}, "listening sockets"),
    ("sockets", {"status": "collected", "listening": [dict(SSHD, port=["22"])]},
     "listening sockets"),
    # True is an int in Python and is not a port. Without this the shape check
    # would accept it and the page would print tcp/True.
    ("sockets", {"status": "collected", "listening": [dict(SSHD, port=True)]},
     "listening sockets"),
]


@pytest.mark.parametrize("key,value,label", WRONG_TYPES,
                         ids=[f"{k}-{i}" for i, (k, _v, _l) in enumerate(WRONG_TYPES)])
def test_no_wrong_typed_section_ends_the_render_and_every_one_is_named(db, key, value, label):
    """Both halves of this card in one test, over every section.

    The render must survive, which is #127's guarantee and is measured here
    against sections that reach call sites #127 never touched. And the section
    must be named, because a section quietly dropped is the empty-looking
    section this card is about.
    """
    doc = document(listening=[SSHD], podman=[JELLYFIN])
    doc[key] = value
    add_host(db, "good", [(NOW, document(listening=[SSHD]))], last_report_at=NOW.isoformat())
    add_host(db, "bad", [(NOW, doc)], last_report_at=NOW.isoformat())
    html = rl.render(db, now=NOW)

    assert rl.unreadable_sections(doc) == (key,)
    good = host_section(html, "good")
    assert theme.status("fail", "not readable") not in good, "the healthy host took the fault"
    bad = host_section(html, "bad")
    evidence = tab_body(bad, "bad", "evidence")
    assert theme.status("fail", f"{label} · not readable") in evidence
    # one bad section is not an unreadable document: the row keeps its own
    # state and carries no sentence about the section, which the Evidence tab
    # names (docs/screens/fleet/SPEC.md section 5, no sentence in a cell)
    row = _fleet_row(html, "bad")
    assert theme.status("fail", "not readable") not in row
    assert "could not be read" not in row


@pytest.mark.usefixtures("v2_tabs")
def test_a_number_that_is_not_a_date_does_not_end_the_render(db):
    """The one fault the shape check cannot catch, because the type is right.
    10**30 is a number and `datetime.fromtimestamp` raises on it, which ended
    the render for the fleet until this. Found by mutating a copy of a
    production document rather than by reading the code."""
    doc = document(rule_files=[{"path": "/etc/ufw/user.rules", "mtime_unix": 10 ** 30}])
    add_host(db, "box", [(NOW, doc)], last_report_at=NOW.isoformat())
    rules = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "rules")
    # The strip's third fact is the only place a rule file's time reaches the
    # screen now. A number outside every date is not a time, so the fact says
    # no change was seen rather than a date nobody measured. It said "never"
    # until 2026-10-06 (docs/RECORD.md 4.395, test_rules_last_changed.py).
    assert ("Rules last changed", rl.tpl.NO_RULE_CHANGE_SEEN) in strip_facts(rules)
    assert "1970" not in rules


def test_comparing_two_documents_by_hand_does_not_invent_a_transition_either():
    """`diff_documents` takes documents from its caller rather than from the
    store, so it is the other way an unchecked one could get in. The render
    path is covered above, this is the helper on its own."""
    older = document(listening=[SSHD, LOOP])
    newer = document(listening=[SSHD, LOOP])
    newer["sockets"] = {"status": "collected", "listening": "not a list"}
    events = rl.diff_documents(older, newer)
    assert not any(e.kind == "stopped" for e in events)
    assert any(e.kind == "not readable" and e.detail == "listening sockets" for e in events)


def test_the_host_page_names_the_sections_it_could_not_read_on_every_tab(db):
    """Said once at the top rather than on each of the seven tabs, because a
    reader who opens the Services tab and finds three rows has to know whether
    three is what the host has or what survived the read."""
    doc = document(listening=[SSHD], podman=[JELLYFIN])
    doc["sockets"] = {"status": "collected", "listening": "not a list"}
    doc["overlays"] = {"status": "collected", "interfaces": "wg0"}
    add_host(db, "box", [(NOW, doc)], last_report_at=NOW.isoformat())
    section = host_section(rl.render(db, now=NOW), "box")
    # the header is the five facts and names them nowhere; the Evidence tab
    # names every section and wears the fault on each one
    head = section.split('<div class="acts">')[0]
    assert "not readable" not in head
    evidence = tab_body(section, "box", "evidence")
    assert evidence.count("· not readable</span>") >= 2




def test_the_filtering_row_says_the_layer_was_not_read_rather_than_none_found(db):
    """The Evidence tab's filtering row is one line and it is the one a reader
    trusts. "none found" over a ufw section nobody could read is a finding
    nobody measured."""
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": "ENABLED=yes"}
    doc["firewalld"] = {"status": "not_present"}
    add_host(db, "box", [(NOW, doc)], last_report_at=NOW.isoformat())
    evidence = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "evidence")
    assert "the ufw section could not be read" in evidence
    assert "none found" not in evidence


def test_an_unreadable_sockets_section_is_not_zero_sockets_bound(db):
    """RECORD 4.17's rule, which `family_sockets` already keeps for a failed
    read, extended to a read that says it worked and did not survive the trip.
    """
    doc = document(listening=[SSHD])
    doc["sockets"] = {"status": "collected", "listening": {"port": 22}}
    add_host(db, "box", [(NOW, doc)], last_report_at=NOW.isoformat())
    evidence = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "evidence")
    assert "not read" in evidence
    assert "0 sockets bound" not in evidence


def test_an_unreadable_section_does_not_invent_a_transition(db):
    """The change view is where an empty-looking section states a finding
    rather than only failing to state one: every socket in the last document
    reads as a socket that stopped listening, which nobody measured."""
    older = document(listening=[SSHD, LOOP])
    newer = document(listening=[SSHD, LOOP])
    newer["sockets"] = {"status": "collected", "listening": "not a list"}
    add_host(db, "box", [(NOW - timedelta(minutes=2), newer),
                         (NOW - timedelta(minutes=17), older)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    changes = tab_body(host_section(html, "box"), "box", "changes")
    assert '<span class="st nt">stopped</span>' not in changes
    assert '<span class="st nt">not readable</span>' in changes
    assert '<span class="cdet">listening sockets</span>' in changes


@pytest.mark.usefixtures("v2_tabs")
def test_an_unreadable_ruleset_is_not_a_host_with_no_rules(db):
    """The packet path says what it walked. A ruleset it could not read is not
    a ruleset with nothing in it, and the tab has to say which one this is."""
    doc = document(listening=[SSHD])
    doc["nftables"] = {"status": "collected", "tables": "oops"}
    add_host(db, "box", [(NOW, doc)], last_report_at=NOW.isoformat())
    html = rl.render(db, now=NOW)
    path = tab_body(host_section(html, "box"), "box", "path")
    assert "could not be read" in path
    rules = tab_body(host_section(html, "box"), "box", "rules")
    assert "could not be read" in rules
    assert "No firewall layer was readable on this host" not in rules


@pytest.mark.usefixtures("v2_tabs")
def test_the_ufw_rule_count_is_the_rules_the_page_lists(db):
    """The strip counts what the lists under it draw. Found while writing the
    card this replaced, live on both hosts that run ufw: the old hint counted
    `_dicts(section["rules"])` and ufw's rules are a list of strings, so it
    said 0 rules over a list of three of them.

    A rule somebody wrote once is written into both files, so those two lines
    are one row carrying both families and the count says two, not three.
    """
    doc = document()
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "rules": ["allow any 22 0.0.0.0/0 any 0.0.0.0/0 in",
                            "allow any 80 0.0.0.0/0 any 0.0.0.0/0 in"],
                  "rules6": ["allow any 22 ::/0 any ::/0 in"]}
    add_host(db, "box", [(NOW, doc)], last_report_at=NOW.isoformat())
    rules = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "rules")
    # two rows for three lines, and the strip counts the same two
    assert rules.count('for="rr-box-ufw-') == 2
    assert ("Rules", "2") in strip_facts(rules)
    # 22 is in both files and says so, 80 is in one and says that
    assert '<i class="v4">v4</i>+<i class="v6">v6</i>' in rules
    assert rules.count('<i class="v4">v4</i></small>') == 1


# ------------------------------------------------------------- declared names
#
# The operator can name the service on a port once, in the control plane
# (controlplane/app/intent.py owns the storage, docs/RECORD.md 4.64 the
# suggestion). The page prefers the name and always says it was named by the
# operator, and the measured process name never leaves the screen because of
# one. The schema below mirrors controlplane/app/intent.py, which owns it, the
# same arrangement as SCHEMA at the top of this file.

NAMES_SCHEMA = """
CREATE TABLE IF NOT EXISTS port_names (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    protocol TEXT NOT NULL, port INTEGER NOT NULL, name TEXT NOT NULL,
    account TEXT NOT NULL, declared_at TEXT NOT NULL, cleared_at TEXT);
"""


def declare_name(db, host, protocol, port, name, cleared_at=None):
    con = sqlite3.connect(db)
    con.executescript(NAMES_SCHEMA)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?",
                          (host,)).fetchone()[0]
    con.execute(
        "INSERT INTO port_names (host_id, protocol, port, name, account,"
        " declared_at, cleared_at) VALUES (?, ?, ?, ?, 'default', ?, ?)",
        (host_id, protocol, port, name, NOW.isoformat(), cleared_at))
    con.commit()
    con.close()


# --------------------------------------- a stored document that will not read
#
# The level above the wrong-typed section: the stored document itself. The
# ingest stores what a host sends verbatim and validates only the envelope
# (PRODUCT.md 4e), so the store can hold a document that is empty, truncated,
# not JSON at all, valid JSON that is not an object, or JSON nested too deep
# to parse. Two guarantees, and every test here is about one of them:
#
#   1. One such document never ends the render for the other hosts. Before
#      this card a document nested too deep raised RecursionError out of
#      json.loads, which parse_report did not catch, and the timer's render
#      died for the whole fleet.
#   2. It never reads as a document that never arrived. "No document received
#      from this host yet" over a document that arrived and would not read is
#      docs/RECORD.md 4.46 one level up: the absence of a thing and a thing
#      nobody could read are different facts.

# json.loads parses nesting recursively, so this raises RecursionError rather
# than JSONDecodeError. It is one string a host could post today.
TOO_DEEP = "[" * 200000 + "]" * 200000

# Every way a stored document can be broken at the document level. The pair is
# (test id, exactly what the document column holds).
BROKEN_DOCUMENTS = [
    ("empty", ""),
    ("truncated", json.dumps(document())[:200]),
    ("not-json", "this is not json {{{"),
    ("a-list", "[1, 2, 3]"),
    ("a-string", json.dumps("hello")),
    ("null", "null"),
    ("a-number", "42"),
    ("too-deep", TOO_DEEP),
]


def add_raw_report(db, name, raw, received=None, received_text=None):
    """A host whose stored document is exactly `raw`, no json.dumps in the way.
    `received_text` overrides the report's received_at column verbatim, for
    the one test about that column itself. The hosts row stays well formed
    either way, because the ingest writes it and this card is about the
    stored document."""
    when = (received or (NOW - timedelta(minutes=4))).isoformat()
    con = sqlite3.connect(db)
    cur = con.execute(
        "INSERT INTO hosts (name, token_hash, created_at, last_report_at)"
        " VALUES (?, ?, ?, ?)", (name, "hash-" + name, NOW.isoformat(), when))
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version,"
        " document) VALUES (?, ?, ?, 1, ?)",
        (cur.lastrowid, received_text or when, int(NOW.timestamp()), raw))

    con.commit()
    con.close()


def test_a_declared_name_leads_and_the_measurement_stays_beside_it(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 22, "ssh for the admins")
    section = host_section(rl.render(db, now=NOW), "box")
    # the overview holder cell: the name first, its provenance, the process
    overview = tab_body(section, "box", "overview")
    assert ('ssh for the admins<small class="by">named by you · process sshd</small>'
            in overview)
    # the services row keeps the measured name, test_host_services.py says
    # how it wears the declared one


# The same two cases on the packet path, split off rather than skipped whole, so
# the two tabs that still ship keep their coverage while these wait for the tab
# (AFTER_V1). Every assertion is the one it was before the split.
def test_a_declared_name_stands_alone_when_no_process_name_was_read(db):
    """The case the name exists for (docs/RECORD.md 4.64): the non-root agent
    reads no process name at all. The name answers, the provenance stays, and
    no invented process is printed beside it."""
    unattributed = dict(SSHD, process_name="")
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[unattributed]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 22, "ssh")
    section = host_section(rl.render(db, now=NOW), "box")
    assert 'ssh<small class="by">named by you</small>' in section
    assert "named by you · process" not in section


def test_a_declared_name_reaches_a_container_published_port(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(podman=[JELLYFIN]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 8096, "jellyfin for the family")
    overview = tab_body(host_section(rl.render(db, now=NOW), "box"),
                        "box", "overview")
    assert ('jellyfin for the family<small class="by">named by you · published by podman '
            'into container jellyfin</small>') in overview


def test_a_database_without_the_names_table_renders_the_measured_names(db):
    """Production ran before the port_names table existed. No migration step:
    the page renders, with the measured names alone."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "sshd" in html
    assert "named by you" not in html


def test_a_name_for_a_port_nothing_reported_puts_nothing_on_the_screen(db):
    """A declaration is a thing a person typed and it raises no row. The port
    is on no screen, so neither is its name (docs/PRODUCT.md 8b)."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 8080, "the staging app")
    assert "the staging app" not in rl.render(db, now=NOW)


def test_a_cleared_name_is_not_shown(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 22, "the old name",
                 cleared_at=NOW.isoformat())
    html = rl.render(db, now=NOW)
    assert "the old name" not in html
    assert "named by you" not in html


def test_one_hosts_name_does_not_reach_another_host(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_host(db, "other", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 22, "ssh on box")
    html = rl.render(db, now=NOW)
    assert "ssh on box" in host_section(html, "box")
    assert "ssh on box" not in host_section(html, "other")


def test_a_declared_name_is_escaped_on_the_page(db):
    """The name is operator text and the store bounds it, and the page still
    escapes it like every other value it prints."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 22, 'grafana <b onload="x">')
    html = rl.render(db, now=NOW)
    assert '<b onload="x">' not in html
    assert "grafana &lt;b" in html


# -------------------------------------------------- names out of a socket unit
#
# The other kind of name on these screens, and the one the agent already
# collects. A socket-activated port has no useful owning process: systemd holds
# the listening socket, and under an unprivileged agent there is no process name
# in the document at all, so every row on almabox read "user root" on
# 2026-08-24. The *.socket file names the service, the agent has carried it
# since docs/RECORD.md 4.76, and the renderer never read it.
#
# It stays a declaration. It is only ever joined onto a socket the agent
# measured, it says on screen which file it came from, and a measured process
# name is never replaced by one.

# cockpit.socket as almabox has it: one bare port, so the file declares no
# address and no family, and the service name follows systemd's own default
# rule rather than a Service= line. Enabled, with the link `systemctl enable`
# makes: where the kernel names no unit for a socket, only a file something
# enabled names it (the second big test, 2026-10-25, case C8). This fixture
# carried no enable_links until that rule read them.
COCKPIT_UNIT = {
    "name": "cockpit.socket", "file": "/usr/lib/systemd/system/cockpit.socket",
    "origin": "vendor", "source": "usr_lib_systemd_system", "parsed": True,
    "socket_section": True, "service_unit": "cockpit.service",
    "service_source": "implied",
    "listen": [{"directive": "ListenStream", "value": "9090", "kind": "port_only",
                "address_specified": False, "port": 9090}],
    "enable_links": ["/etc/systemd/system/sockets.target.wants/cockpit.socket"],
}

# The measured half, as an unprivileged agent reports it: no process name, and
# the owning uid is the attribution that remains (docs/RECORD.md 4.72).
COCKPIT_SOCKET = {"protocol": "tcp", "family": "v6", "bind_address": "::",
                  "port": 9090, "owner_uid": 0, "owner_name": "root"}

# A second listener on the same host that no unit file declares, so it keeps
# the measured fallback and both tabs have something to agree about.
ROOT_SOCKET = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
               "port": 8080, "owner_uid": 0, "owner_name": "root"}


def unit_section(units, status="collected", **extra):
    """A socket_units section the shape the agent sends one."""
    return {"status": status, "units": units, **extra}


def socket_unit_host(db, units, listening=(COCKPIT_SOCKET,), host="box"):
    add_host(db, host, [(NOW - timedelta(minutes=2),
                         document(listening=list(listening),
                                  socket_units=unit_section(list(units))))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    return host_section(rl.render(db, now=NOW), host)


def test_a_socket_activated_port_is_named_by_its_service_unit(db):
    section = socket_unit_host(db, [COCKPIT_UNIT])
    overview = tab_body(section, "box", "overview")
    assert 'cockpit.service<small class="by">declared by cockpit.socket</small>' in overview
    # and the row is no longer the uid
    assert "user root" not in overview


def test_the_overview_and_the_services_tab_name_one_socket_the_same_way(db):
    """The second defect behind the same report: the Overview read
    `process_name` on its own, so it printed "unknown process" for a socket the
    Services tab printed "user root" for. One namer now, so one document cannot
    give a reader two answers."""
    section = socket_unit_host(db, [COCKPIT_UNIT],
                               listening=(COCKPIT_SOCKET, ROOT_SOCKET))
    overview = tab_body(section, "box", "overview")
    services = tab_body(section, "box", "services")
    assert "cockpit.service" in overview and "<b>cockpit</b>" in services
    for tab in (overview, services):
        assert "user root" in tab          # the undeclared port, on both tabs
    assert "unknown process" not in section


def test_a_document_without_the_socket_units_section_keeps_the_measured_name(db):
    """Every agent older than that collector sends no such section."""
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[COCKPIT_SOCKET]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    section = host_section(rl.render(db, now=NOW), "box")
    assert "user root" in section
    assert "declared by" not in section
    # a section the agent did not read is not on the strip (2026-09-08)
    assert "socket units" not in section


def test_a_socket_units_section_of_the_wrong_type_is_named_rather_than_read(db):
    """A host document is stored verbatim, so the section can hold anything.
    Nothing may be named out of it and the trust view says why."""
    doc = document(listening=[COCKPIT_SOCKET],
                   socket_units={"status": "collected", "units": "not a list"})
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    assert rl.unreadable_sections(doc) == ("socket_units",)
    section = host_section(rl.render(db, now=NOW), "box")
    assert theme.status("fail", "socket units · not readable") in section
    assert "cockpit.service" not in section
    assert "user root" in section


def test_a_socket_units_section_the_agent_could_not_read_names_nothing(db):
    """The agent's own failure, which is not the same fact as an empty one. It
    carries no units, so nothing is named, and the trust view says what
    happened rather than the section reading as collected and empty."""
    denied = unit_section([], status="permission_denied", cause="permission")
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[COCKPIT_SOCKET], socket_units=denied))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    section = host_section(rl.render(db, now=NOW), "box")
    assert "declared by" not in section
    assert "user root" in section
    assert theme.status("warn", "socket units · refused") in section


def test_a_declared_port_nothing_is_listening_on_puts_nothing_on_a_screen(db):
    """A unit file is a declaration. It never raises a row of its own, exactly
    as an operator's declared name for an absent port does not."""
    absent = dict(COCKPIT_UNIT, name="jetty.socket", service_unit="jetty.service",
                  listen=[{"directive": "ListenStream", "value": "18080",
                           "kind": "port_only", "address_specified": False,
                           "port": 18080}])
    section = socket_unit_host(db, [absent])
    assert "jetty" not in section
    assert "18080" not in section


def test_the_operators_own_name_wins_over_the_unit_file(db):
    """Both are declarations and the operator's is the one a person on this
    workspace typed about this host."""
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[COCKPIT_SOCKET],
                                   socket_units=unit_section([COCKPIT_UNIT])))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    declare_name(db, "box", "tcp", 9090, "the web console")
    section = host_section(rl.render(db, now=NOW), "box")
    overview = tab_body(section, "box", "overview")
    assert 'the web console<small class="by">named by you' in overview
    assert "cockpit.service" not in overview
    assert "declared by cockpit.socket" not in section


def test_a_measured_process_name_stays_beside_the_unit_name(db):
    """A root agent does read a process name for a socket-activated port, and
    what it reads is systemd. The unit names the row, the measurement stays."""
    measured = dict(COCKPIT_SOCKET, process_name="systemd", pid=1)
    section = socket_unit_host(db, [COCKPIT_UNIT], listening=(measured,))
    assert "declared by cockpit.socket · process systemd" in section


def test_a_port_two_units_declare_is_named_by_neither(db):
    """Which unit systemd loads follows from the load path, and picking one
    here would be a guess printed as a name."""
    other = dict(COCKPIT_UNIT, name="console.socket", service_unit="console.service")
    section = socket_unit_host(db, [COCKPIT_UNIT, other])
    assert "cockpit.service" not in section
    assert "console.service" not in section
    assert "user root" in section


def test_one_unit_found_in_two_directories_still_names_its_port(db):
    """The agent reports a unit once per directory it was found in, on purpose.
    Two copies of one unit name one service, so this is not the ambiguous case
    above."""
    override = dict(COCKPIT_UNIT, file="/etc/systemd/system/cockpit.socket",
                    origin="admin", source="etc_systemd_system")
    section = socket_unit_host(db, [override, COCKPIT_UNIT])
    assert "cockpit.service" in section


@pytest.mark.parametrize("field", ["masked", "template", "alias_of"])
def test_a_unit_that_is_not_a_listener_names_nothing(db, field):
    """A masked unit is not loaded, a template is the pattern instances are
    made from, and an alias is a second name for a unit already in the list."""
    value = "cockpit-real.socket" if field == "alias_of" else True
    section = socket_unit_host(db, [dict(COCKPIT_UNIT, **{field: value})])
    assert "cockpit.service" not in section
    assert "user root" in section


@pytest.mark.parametrize("kind,value", [
    ("unix_path", "/run/cockpit.sock"),
    ("unix_abstract", "@cockpit"),
    ("vsock", "vsock::9090"),
    ("specifier", "%i"),
    ("not_an_internet_socket", "/run/fifo"),
    ("unknown", "something the agent did not recognise"),
])
def test_a_listener_that_is_not_a_tcp_or_udp_port_names_nothing(db, kind, value):
    """The port on those entries is 0 or absent, and reading one out of them
    would be inventing it."""
    unit = dict(COCKPIT_UNIT, listen=[{"directive": "ListenStream", "value": value,
                                       "kind": kind, "address_specified": False}])
    section = socket_unit_host(db, [unit])
    assert "cockpit.service" not in section
    assert "user root" in section


def test_a_datagram_declaration_does_not_name_a_tcp_port(db):
    """ListenStream is TCP and ListenDatagram is UDP (systemd.socket(5)), so a
    udp declaration says nothing about the tcp port of the same number."""
    udp = dict(COCKPIT_UNIT, listen=[{"directive": "ListenDatagram", "value": "9090",
                                      "kind": "port_only", "address_specified": False,
                                      "port": 9090}])
    section = socket_unit_host(db, [udp])
    assert "cockpit.service" not in section
    assert "user root" in section


def test_a_unit_declaring_an_address_names_the_port_it_carries(db):
    """The file may name an address, and the socket the agent measured is
    still the authority on where the port is bound."""
    pinned = dict(COCKPIT_UNIT, listen=[{"directive": "ListenStream",
                                         "value": "[::]:9090", "kind": "ipv6",
                                         "address_specified": True, "address": "::",
                                         "address_family": "v6", "port": 9090}])
    section = socket_unit_host(db, [pinned])
    assert "cockpit.service" in section


def test_a_unit_name_out_of_a_document_is_escaped_on_the_page(db):
    """Both strings come off a host's own file system, so they are printed the
    way every other document value is."""
    hostile = dict(COCKPIT_UNIT, name='<img src=x onerror="go()">.socket',
                   service_unit='<b onload="x">.service')
    section = socket_unit_host(db, [hostile])
    assert "<img src=x" not in section
    assert '<b onload="x">' not in section
    assert "&lt;b onload" in section


@pytest.mark.parametrize("section", [
    "not a section",
    {},
    {"units": "not a list"},
    {"units": [None, 5, "unit"]},
    {"units": [{"service_unit": "a.service"}]},
    {"units": [{"service_unit": "", "listen": [
        {"directive": "ListenStream", "kind": "port_only", "port": 9090}]}]},
    {"units": [{"service_unit": "a.service", "listen": "not a list"}]},
    {"units": [{"service_unit": "a.service", "listen": [
        {"directive": "ListenStream", "kind": "port_only", "port": True}]}]},
    {"units": [{"service_unit": "a.service", "listen": [
        {"directive": "ListenStream", "kind": "port_only", "port": "9090"}]}]},
    {"units": [{"service_unit": "a.service", "listen": [
        {"directive": "ListenStream", "kind": "port_only", "port": 0}]}]},
    {"units": [{"service_unit": "a.service", "listen": [
        {"directive": "ListenFIFO", "kind": "port_only", "port": 9090}]}]},
])
def test_nothing_is_named_out_of_a_malformed_socket_units_section(section):
    """The shape check refuses most of these before a screen sees them, and
    this function is called with the document a host sent, so it answers for
    itself as well."""
    assert rl.socket_unit_names({"socket_units": section}) == {}


def test_a_document_with_no_sections_at_all_names_nothing():
    assert rl.socket_unit_names({}) == {}


def test_a_document_too_deep_to_parse_does_not_end_the_render(db):
    """The card itself. One host posts a nesting bomb, and before the fix the
    whole render died with RecursionError, so the page went stale for every
    host and the fault was visible nowhere on it."""
    add_host(db, "goodbox", [(NOW - timedelta(minutes=4), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    add_raw_report(db, "badbox", TOO_DEEP)
    html = rl.render(db, now=NOW)
    # the good host renders fully
    assert "goodbox" in html and 'data-port="22/tcp"' in html
    # and the bad one is a loud fact on the page, not a log line
    bad = host_section(html, "badbox")
    assert theme.status("fail", "not readable") in bad


@pytest.mark.parametrize("raw", [raw for _id, raw in BROKEN_DOCUMENTS],
                         ids=[i for i, _raw in BROKEN_DOCUMENTS])
def test_an_unreadable_document_is_not_a_document_that_never_arrived(db, raw):
    """Every document-level break, same two assertions each: the other host is
    untouched, and the broken host says its document could not be read rather
    than pretending nothing ever arrived."""
    add_host(db, "goodbox", [(NOW - timedelta(minutes=4), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    add_raw_report(db, "badbox", raw)
    html = rl.render(db, now=NOW)

    good = host_section(html, "goodbox")
    assert 'data-port="22/tcp"' in good
    assert theme.status("fail", "not readable") not in good, "the healthy host took the fault"

    bad = host_section(html, "badbox")
    assert theme.status("fail", "not readable") in bad
    assert "could not be read" in bad
    # the lie this card removes
    assert "No document received from this host yet" not in bad

    # the fleet row says it without the host being opened, and wears the fail
    # tone rather than a healthy reporting tag
    row = _fleet_row(html, "badbox")
    assert theme.status("fail", "not readable") in row
    # the tag is the whole statement: the cells the spec empties hold nothing
    assert '<div class="frc"></div>' in row and '<div class="fchips"></div>' in row


def test_a_huge_but_valid_document_renders_and_takes_no_fault(db):
    """The guard is about shape, never size. A document with megabytes of
    fields this page does not read is still a readable document."""
    doc = document(listening=[SSHD])
    doc["padding"] = "x" * 2_000_000
    add_host(db, "bigbox", [(NOW - timedelta(minutes=4), doc)],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    html = rl.render(db, now=NOW)
    big = host_section(html, "bigbox")
    assert 'data-port="22/tcp"' in big
    assert theme.status("fail", "not readable") not in big


def test_one_bad_document_among_three_good_hosts_costs_only_its_own_row(db):
    for name in ("alpha", "bravo", "charlie"):
        add_host(db, name, [(NOW - timedelta(minutes=4), document(listening=[SSHD]))],
                 last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    add_raw_report(db, "badbox", "not json")
    html = rl.render(db, now=NOW)
    for name in ("alpha", "bravo", "charlie"):
        section = host_section(html, name)
        assert 'data-port="22/tcp"' in section, f"{name} lost its document"
        assert theme.status("fail", "not readable") not in section
    assert theme.status("fail", "not readable") in host_section(html, "badbox")


def test_every_document_unreadable_still_renders_a_page(db):
    """The worst store there is: nothing in it can be read. The page still
    renders, and every row says what is wrong instead of the fleet being one
    traceback in the journal."""
    for i, (case, raw) in enumerate(BROKEN_DOCUMENTS):
        add_raw_report(db, f"host-{i}", raw)
    html = rl.render(db, now=NOW)
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    for i in range(len(BROKEN_DOCUMENTS)):
        row = re.search(rf'<a class="row" href="[^"]*" data-host="host-{i}".*?</a>',
                        fleet, re.S).group(0)
        assert theme.status("fail", "not readable") in row


def test_a_store_with_no_hosts_still_renders_a_page(db):
    html = rl.render(db, now=NOW)
    assert 'id="fleet"' in html
    # no table: the box with the slashed drives and Add server stands where
    # it would (docs/screens/alerts/SPEC.md, the empty Fleet)
    assert '<div class="thead' not in html
    assert rl.tpl.NO_SERVERS in html
    assert 'class="btn pri js-add">Add server</button>' in html
    # No boxes with zeros (docs/screens/fleet/SPEC.md, When there is no
    # server). This test held four boxes reading zero of no ports until the
    # second big test found them on an empty Fleet against the spec (F3).
    assert "of 0 ports" not in html
    assert 'class="fstrip"' not in html


def test_a_received_at_that_is_not_a_date_is_unreadable_not_fatal(db):
    """The other column of a reports row. The ingest writes it, so a broken one
    means the store itself was interfered with, and the render still has to
    survive it and say so."""
    add_raw_report(db, "badbox", json.dumps(document()), received_text="not a date")
    html = rl.render(db, now=NOW)
    assert theme.status("fail", "not readable") in host_section(html, "badbox")


def test_an_unreadable_document_in_the_history_is_counted_and_said_out_loud(db, capsys):
    """A broken older document, behind a readable newest one. Before this card
    it fell out of the history with no count and no line on stderr, which is
    the quiet skip this project does not allow. The host's own page still
    renders from the newest document."""
    add_host(db, "box", [(NOW - timedelta(minutes=4), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    con = sqlite3.connect(db)
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version,"
        " document) VALUES (1, ?, ?, 1, ?)",
        ((NOW - timedelta(minutes=19)).isoformat(), int(NOW.timestamp()), "not json"))
    con.commit()
    con.close()
    hosts, newest, history, alerts, _names, _findings, _channels, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    assert isinstance(newest["box"], tuple), "the readable newest document still loads"
    assert history["box"].unreadable == 1
    assert "could not be read" in capsys.readouterr().err
    html = rl.render(db, now=NOW)
    assert 'data-port="22/tcp"' in host_section(html, "box")


def test_the_render_command_exits_cleanly_with_a_broken_document_in_the_store(
        db, tmp_path, monkeypatch, capsys):
    """What the timer actually runs is main(). A broken stored document must
    leave it writing the page and returning, because a timer whose unit fails
    stops updating the page for every host."""
    add_host(db, "goodbox", [(NOW - timedelta(minutes=4), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    add_raw_report(db, "badbox", TOO_DEEP)
    out_dir = tmp_path / "app"
    monkeypatch.setattr(rl.sys, "argv",
                        ["render_live.py", "--db", db, "--out-dir", str(out_dir)])
    rl.main()   # any exception, SystemExit included, fails this test
    assert "wrote" in capsys.readouterr().out
    html = (out_dir / rl.WORKSPACE_DIRNAME / "1" / rl.INDEX_FILENAME).read_text()
    assert "goodbox" in html
    assert theme.status("fail", "not readable") in html



# ==================================== the join engine, and findings on a screen
#
# `docs/RECORD.md` 4.80. Until this landed every port on every host read
# `not tested` and the five states appeared nowhere a person could see them.
# `site/app/joinbridge.py` owns why the engine cannot simply be imported.

import app.joinbridge as jb  # noqa: E402


def probe_result(db, host_name, port, family, state, vantage="probe1",
                 measured_at=None):
    """One stored probe result, written the way the prober writes one.

    The tables are created here rather than in the fixture, so every other test
    in this file still runs against a database where the prober has never run.
    That is the state of a real box before the first pass and it has to stay
    renderable.
    """
    measured_at = (measured_at or NOW).isoformat()
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
    # One run per vantage: a second vantage's results go in a run of their
    # own, the way the prober stores them, so two vantages can disagree.
    run = con.execute("SELECT id FROM probe_runs WHERE host_id = ? AND vantage = ?",
                      (host_id, vantage)).fetchone()
    if run is None:
        run_id = con.execute(
            "INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
            " VALUES (?, ?, ?, ?)",
            (host_id, vantage, measured_at, measured_at)).lastrowid
    else:
        run_id = run[0]
    con.execute(
        "INSERT INTO probe_results (run_id, family, target, port, state,"
        " reason, connect_ms, os_errno, measured_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (run_id, family, "185.199.108.153", port, state, None, 1.0, None,
         measured_at))
    con.commit()
    con.close()


# ------------------------------------------------------------------ the bridge

def test_the_bridge_loads_the_engine_without_replacing_the_site_package():
    """The whole reason this module exists. `controlplane/app` is a regular
    package and `site/app` is a namespace one, so putting the control plane on
    sys.path replaces `app` rather than adding to it, and `app.build` then
    stops existing."""
    join = jb.load()
    assert join.STATES == ("conflict", "unreviewed", "intended", "stale rule",
                           "unexplained", "not reachable")
    import app.build
    assert app.build.__name__ == "app.build"


def test_every_state_the_engine_can_produce_is_drawable():
    """**The guard the sixth state needed and did not have.**

    `not reachable` was in `PORT_TONE` and `CHIP_CLASS` for months as a word
    the sample shell used, while `controlplane/app/join.py` could not produce
    it. When it started producing it on 2026-08-28 the two maps were already
    right by luck, and `STATE_SEVERITY` and `FLEET_BANDS` were not: a port
    whose only state was the new word would have rendered as `listening` with
    no tone at all, and its row would have sorted into the unknown band above
    every working server.

    So the engine's own tuple is the list, read through the bridge rather than
    spelled again here, and a seventh word fails this the day it is added
    instead of rendering as nothing.
    """
    for state in jb.load().STATES:
        assert state in rl.tpl.PORT_TONE, f"{state!r} has no tone"
        assert state in rl.tpl.CHIP_CLASS, f"{state!r} has no chip class"
        assert state in rl.STATE_SEVERITY, f"{state!r} has no severity rank"
        assert rl.tpl.fleet_band(state) != rl.tpl.UNRANKED_BAND, (
            f"{state!r} sorts into the band for words the table does not know")


def test_a_port_that_is_shut_and_undeclared_draws_quiet():
    """`not reachable` is the most common row on a well run server, so it may
    never take a tone that asks for attention. `docs/DESIGN.md` section 3:
    healthy stays quiet, and without that rule a status treatment becomes a
    way of shouting on every row at once."""
    assert rl.tpl.PORT_TONE["not reachable"] == "off"
    assert rl.tpl.CHIP_CLASS["not reachable"] == "quiet"
    # Below `unreviewed`, which is the same port answering the internet.
    order = rl.STATE_SEVERITY
    assert order.index("unreviewed") < order.index("not reachable")
    assert order.index("not reachable") < order.index("intended")


def test_the_bridge_hands_back_the_same_module_twice():
    """Called once per host per render, on every dashboard request.
    Re-executing a 1,700 line module each time would be a cost for nothing."""
    assert jb.load() is jb.load()


def test_the_bridge_finds_the_layout_the_box_actually_has(tmp_path):
    """`ops/deploy-controlplane.sh` copies both trees into one directory, so on
    the box the engine is at ../../app and in a checkout it is at
    ../../controlplane/app. Both are real and both are tried."""
    box = tmp_path / "srv" / "controlplane"
    (box / "app").mkdir(parents=True)
    (box / "site" / "app").mkdir(parents=True)
    (box / "app" / "__init__.py").write_text("")
    (box / "app" / "join.py").write_text("")
    here = box / "site" / "app" / "render_live.py"
    assert jb.candidate_directories(here)[0] == box / "app"


def test_the_bridge_refuses_rather_than_pretending(tmp_path):
    """A renderer that quietly falls back to `not tested` when it cannot load
    the engine is a monitoring tool failing silently, which is the thing
    docs/PRODUCT.md 4c exists to prevent."""
    empty = tmp_path / "a" / "b" / "c.py"
    empty.parent.mkdir(parents=True)
    with pytest.raises(jb.JoinEngineMissing) as raised:
        jb.load(here=empty)
    assert "not beside this renderer" in str(raised.value)


# ------------------------------------------------------- the fixture's schema

def test_the_fixture_schema_has_not_drifted():
    """SCHEMA at the top of this file is a copy of the control plane's, and a
    copy drifts. It had: `hosts` gained `paused` and `auto_named` and this copy
    did not, so the day the renderer started asking the engine for findings,
    every test that renders a page failed with an IndexError from inside it.

    This reads the real one and fails here, by name, the next time it happens.

    **It loads the module rather than reading its text.** It used to find the
    schema by splitting the file on the exact characters that opened that
    string, which stopped finding anything the day the string was composed
    from a table body defined above it. A scrape that matches nothing raises
    where it stands instead of reporting drift, so it fails loudly, but it
    fails for the wrong reason and says nothing about the schema.

    **It loads it as a package under its own name**, which is the shape
    `site/app/joinbridge.py` already uses and for the same two reasons. A bare
    `spec_from_file_location` on one file cannot resolve that file's own
    relative imports, and `db.py` gained one on 2026-08-28; and registering
    the control plane's package as `app` would shadow the site's own, which is
    the hazard joinbridge's docstring is about. A private alias does neither.
    """
    app_dir = (pathlib.Path(__file__).resolve().parent.parent.parent
               / "controlplane" / "app")
    alias = "controlplane_for_drift_check"
    spec = importlib.util.spec_from_file_location(
        alias, app_dir / "__init__.py",
        submodule_search_locations=[str(app_dir)])
    package = importlib.util.module_from_spec(spec)
    # Registered before it is executed, so `db.py`'s `from .workspace import`
    # resolves through sys.modules the way a real package import would.
    sys.modules[alias] = package
    spec.loader.exec_module(package)
    try:
        real_db = importlib.import_module(alias + ".db")
    finally:
        for name in [n for n in sys.modules if n == alias or n.startswith(alias + ".")]:
            del sys.modules[name]
    real = sqlite3.connect(":memory:")
    real.executescript(real_db.SCHEMA)
    copy = sqlite3.connect(":memory:")
    copy.executescript(SCHEMA)

    def columns(con, table):
        return {row[1] for row in con.execute(f"PRAGMA table_info({table})")}

    def tables(con):
        return {row[0] for row in con.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table'"
            " AND name NOT LIKE 'sqlite_%'")}

    # The list of tables is read from the real schema rather than written out
    # here, so a table added there is checked from the day it is added.
    absent = tables(real) - tables(copy)
    assert not absent, (
        f"the control plane's schema has tables {sorted(absent)} and the copy "
        f"in this file does not. Add them to SCHEMA above")
    for tbl in sorted(tables(real)):
        missing = columns(real, tbl) - columns(copy, tbl)
        assert not missing, (
            f"the real {tbl} table has {sorted(missing)} and the copy in this "
            f"file does not. Add them to SCHEMA above")
    real.close()
    copy.close()


# ------------------------------------------------------------- the port matrix

def test_a_port_nobody_probed_still_reads_not_tested(db):
    """docs/PRODUCT.md 4b, the rule that outranks the rest here. No probe row
    means no reachability answer, and the cell says so rather than guessing."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    rows = rl.load(db, now=NOW)[5]["box"]
    matrix = rl.evidence_matrix_rows(None, rows)
    assert matrix
    assert all(row[3] == "not tested" for row in matrix)


def test_a_measured_port_says_what_was_measured(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    by_family = {(row[0], row[1]): row for row in matrix}
    assert by_family[("tcp/22", "v4")][3] == "connect succeeded"


def test_the_other_family_does_not_inherit_the_answer(db):
    """docs/PRODUCT.md 4b in one assertion. v4 was measured, v6 was not, and the
    v6 cell says not tested rather than borrowing its neighbour's word."""
    doc = document(listening=[SSHD, dict(SSHD, family="v6",
                                         bind_address="2001:db8::1", pid=9)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    by_family = {(row[0], row[1]): row for row in matrix}
    assert by_family[("tcp/22", "v4")][3] == "connect succeeded"
    assert by_family[("tcp/22", "v6")][3] == "not tested"


def test_refused_and_no_response_are_kept_apart(db):
    """ops/RUNBOOK.md: a refusal means nothing was listening, a timeout means
    something dropped it silently, and telling those two apart is the product.
    One word for both would throw that away on the screen built to show it."""
    doc = document(listening=[SSHD, dict(SSHD, port=443, pid=3)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_refused")
    probe_result(db, "box", 443, "v4", "no_response")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    words = {row[0]: row[3] for row in matrix if row[1] == "v4"}
    assert words["tcp/22"] == "connect refused"
    assert words["tcp/443"] == "no response"


def test_a_udp_port_reads_not_tested_and_that_is_correct(db):
    """This is a TCP connect prober. A UDP row that borrowed a TCP answer would
    be reporting a measurement of a different protocol."""
    add_host(db, "box", [(NOW - timedelta(minutes=2),
                          document(listening=[SSHD, LOOP]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    udp = [row for row in matrix if row[0].startswith("udp/")]
    assert udp
    assert all(row[3] == "not tested" for row in udp)


def test_the_family_column_is_the_family_and_not_always_v4(db):
    """The bug this replaced. The old row builder read `sock.get("address")`
    and the agent writes that field as `bind_address`, so every row on every
    host said v4 and no row ever said loopback."""
    doc = document(listening=[SSHD, dict(SSHD, family="v6",
                                         bind_address="2001:db8::1", pid=9)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    assert {row[1] for row in matrix} == {"v4", "v6"}


# ------------------------------------------------------ what loopback means
#
# Measured on the prod box on 2026-08-22: the kernel's own local routing table
# reads `local 127.0.0.0/8 dev lo proto kernel scope host src 127.0.0.1`, so
# the whole range is served on lo and nothing arriving on a public address
# reaches any of it. Two spellings of this used to live in render_live.py and
# they disagreed, which put tcp/53 on the "bound to a network address" panel
# while the Evidence tab called the same port loopback.

RESOLVED_STUB = {"protocol": "tcp", "family": "v4", "bind_address": "127.0.0.53",
                 "port": 53, "process_name": "systemd-resolve", "pid": 7}
RESOLVED_STUB_2 = dict(RESOLVED_STUB, bind_address="127.0.0.54", pid=8)


def test_the_whole_127_range_is_loopback():
    """systemd-resolved binds its stub on 127.0.0.53 and 127.0.0.54 and is on
    essentially every modern Ubuntu and Debian box, so the narrow test was
    wrong on two of the three hosts in the fleet."""
    for address in ("127.0.0.1", "127.0.0.53", "127.0.0.54", "127.255.255.254",
                    "::1", "::ffff:127.0.0.1"):
        assert rl.is_loopback(address), address


def test_a_wildcard_or_a_public_address_is_not_loopback():
    for address in ("0.0.0.0", "::", "203.0.113.198", "2001:db8::1",
                    "128.0.0.1", "126.255.255.255", "::ffff:8.8.8.8"):
        assert not rl.is_loopback(address), address


def test_a_scope_suffix_names_a_device_and_changes_nothing():
    """`ss` prints the resolved stub as `127.0.0.53%lo`, and a link-local
    address always carries one. The zone names an interface, not an address."""
    assert rl.is_loopback("127.0.0.53%lo")
    assert not rl.is_loopback("fe80::1%eth0")


def test_an_address_this_cannot_parse_is_not_called_loopback():
    """The safe direction, and the one the old comment was reaching for:
    leaving a port on the list shows the reader something real, and hiding one
    that might answer from outside is the failure that matters."""
    for junk in ("", None, "not an address", "127.0.0.999", "0x7f000001"):
        assert not rl.is_loopback(junk), junk


def test_the_resolved_stub_is_a_row_that_says_loopback(db):
    """tcp/53 was once listed under "Ports bound to a network address", which
    the owner found on his own fleet. The Overview of 2026-09-04 is every port
    in the joined set, one row each, and a loopback-only port says so in its
    Decided by cell (the sketch's 323/udp chronyd row)."""
    doc = document(listening=[SSHD, RESOLVED_STUB, RESOLVED_STUB_2])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    overview = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "overview")
    assert 'data-port="22/tcp"' in overview
    row = overview.split('data-port="53/tcp"')[1].split("</label>")[0]
    assert '<span class="prw">loopback</span>' in row


def test_the_overview_and_the_evidence_tab_agree_about_a_loopback_port(db):
    """They did not, one click apart, on the same document. One predicate now
    decides for both."""
    doc = document(listening=[SSHD, RESOLVED_STUB])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    assert [r[2] for r in matrix if r[0] == "tcp/53"] == ["loopback"]
    overview = rl.render(db, now=NOW).split('id="t-box-overview"')[1].split('<div class="tab')[0]
    assert '"pnum">tcp/53<' not in overview


def test_a_port_on_both_loopback_and_a_real_address_still_counts_as_bound(db):
    """Only a port whose every bind is loopback is loopback-only. One socket
    on the wildcard is enough to keep it on the panel."""
    both = dict(RESOLVED_STUB, bind_address="0.0.0.0", pid=9)
    doc = document(listening=[RESOLVED_STUB, both])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    overview = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "overview")
    row = overview.split('data-port="53/tcp"')[1].split("</label>")[0]
    assert '<span class="prw">loopback</span>' not in row


def test_a_loopback_bind_is_labelled_loopback(db):
    loop = {"protocol": "tcp", "family": "v4", "bind_address": "127.0.0.1",
            "port": 5432, "process_name": "postgres", "pid": 4}
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[loop]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    assert [row[2] for row in matrix if row[0] == "tcp/5432"] == ["loopback"]


def test_a_state_reaches_the_matrix(db):
    """A port that answers from outside, with a listener behind it and nobody
    having said whether that is intended, is `unreviewed`. That word had never
    appeared on a live page."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    assert [row[5] for row in matrix if row[1] == "v4"] == ["unreviewed"]


def test_a_port_with_no_state_stays_empty_rather_than_taking_one(db):
    """docs/PRODUCT.md 8a. A port whose evidence supports none of the five has
    no state, not a sixth word and not a default."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    assert all(row[5] == "" for row in matrix)






def test_unexplained_is_a_finding_and_reads_like_one(db):
    """It wore the off tone and the quiet chip, which the evidence key says
    mean a view that cannot know, while FLEET_BANDS sorts it with the
    problems. The one state whose colour disagreed with its own rank
    (2026-08-29)."""
    assert rl.tpl.PORT_TONE["unexplained"] == "warn"
    assert rl.tpl.CHIP_CLASS["unexplained"] == "new"
    # And the matrix Together cell reads the same map rather than a local
    # copy, which is how this state fell to off there in the first place.
    row = rl.tpl.evidence_row_html("box", rl.tpl.EvidenceRow(
        "tcp", 22, "v6", "", "nothing bound", "connect succeeded", "not connected",
        "unexplained", "pr-box-tcp-22"))
    assert 'st warn">unexplained' in row


def test_the_port_ranking_and_the_fleet_ranking_are_one_ranking(db):
    """STATE_SEVERITY has always claimed to be the order FLEET_BANDS sorts
    by, and until 2026-08-29 it held `unexplained` and `unreviewed` the other
    way round. The port states must keep the relative order of the bands, so
    a server's State cell cannot pick a word its own row would sort lower
    under."""
    bands = [rl.tpl.fleet_band(w) for w in rl.STATE_SEVERITY]
    assert bands == sorted(bands), list(zip(rl.STATE_SEVERITY, bands))


def test_an_alert_about_a_port_leads_with_the_port(db):
    """It led with the stored kind, and "finding changed" is our machinery's
    word (the 2026-08-29 audit round). The reader's question is which port,
    and the detail sentence under it already says what changed. A port is
    mono like every port in the product."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_alert(db, "box", "tcp/443 on v4 was intended, now conflict",
              NOW - timedelta(hours=2), kind="finding changed",
              subject="tcp/443 v4")
    row = _open_section(rl.render(db, now=NOW))
    assert '<span class="cpn">443<small>TCP/<i class="v4">v4</i></small></span>' in row
    assert "finding changed" not in row
    assert ">conflict<" in row


def test_a_silent_alert_keeps_its_own_word(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_alert(db, "box", "no report for 47 minutes",
              NOW - timedelta(hours=2), kind="silent")
    assert ">silent<" in _open_section(rl.render(db, now=NOW))

def test_the_matrix_reaches_the_rendered_page(db):
    """End to end. Not the row builder in isolation, the page a person opens."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert '<span class="st nt">open</span>' in html
    assert "unreviewed" in html


# --------------------------------------------- the rate-limit flag on a screen
#
# docs/DESIGN.md section 3 and docs/RECORD.md 4.81: a rate limit is a flag beside
# the state, never a second state, drawn neutral and never `warn`. The engine
# already produces Finding.rate_limited; these prove it reaches a screen and
# does so honestly.


def limited_table(port=22):
    """A ufw-shaped v4 ruleset whose only rule is a rate limit on this port.

    The same shape the join engine's own tests use
    (controlplane/tests/test_finding_alerts.py): ufw's `limit` compiles to a
    `[xt match recent]` rule that jumps into a limit-accept chain, and that
    token is what the engine reads as a rate limit (join.py LIMIT_MODULE_TOKENS).
    It is a v4 `ip` table on purpose, so only the v4 finding may carry the flag.
    """
    text = (f"ip protocol tcp tcp dport {port} [xt match conntrack]"
            " [xt match recent] counter jump ufw-user-limit-accept")
    return {"family": "ip", "name": "filter", "chains": [
        {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
         "policy": "drop",
         "rules": [{"text": "counter jump ufw-user-input", "rendered": "full"}]},
        {"name": "ufw-user-input",
         "rules": [{"text": text, "rendered": "partial"}]},
        {"name": "ufw-user-limit-accept",
         "rules": [{"text": "counter accept", "rendered": "full"}]},
    ]}


def limited_doc(listening, port=22):
    """A document whose only firewall rule is a rate limit on `port`."""
    doc = document(listening=listening)
    doc["nftables"] = {"status": "collected", "tables": [limited_table(port)]}
    return doc


def test_a_rate_limited_port_flags_the_matrix_row(db):
    """The flag rides the v4 finding the engine set from the rule."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), limited_doc([SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    by_family = {(r[0], r[1]): r for r in matrix}
    assert by_family[("tcp/22", "v4")][6] is True


def test_a_plain_port_carries_no_flag(db):
    """A port with no such rule gets no flag, in the data and on the page."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    assert all(r[6] is False for r in matrix)
    # the flag markup is absent. Not the bare string "tag-rate", which the
    # stylesheet carries on every page as a selector.
    assert rl.tpl.rate_flag(True) not in rl.render(db, now=NOW)


def test_the_flag_never_lands_on_the_family_its_rule_excludes(db):
    """docs/RECORD.md 4.79. The limit is a v4 `ip` table, so the v6 row must not
    borrow it. Both halves are measured, never guessed."""
    doc = limited_doc([SSHD, dict(SSHD, family="v6",
                                  bind_address="2001:db8::1", pid=9)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    matrix = rl.evidence_matrix_rows(None, rl.load(db, now=NOW)[5]["box"])
    by_family = {(r[0], r[1]): r for r in matrix}
    assert by_family[("tcp/22", "v4")][6] is True
    assert by_family[("tcp/22", "v6")][6] is False


def test_the_flag_reaches_the_page_neutral_and_beside_the_state(db):
    """docs/DESIGN.md section 3. The exact word, the neutral `.tag-rate` shape,
    the state word still present and still owning its own tag, and no status
    tone anywhere near the flag."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), limited_doc([SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert '<span class="tag-rate" title="rate limited">rate limited</span>' in html
    assert rl.tpl.rate_flag(True) == '<span class="tag-rate" title="rate limited">rate limited</span>'
    # the state is still shown and is not replaced by the flag
    assert "unreviewed" in html
    # the flag never wears a status tone (never `warn`, DESIGN section 3)
    for tone in ("warn", "fail", "ok"):
        assert f'class="st {tone}">rate limited' not in html


def test_the_overview_flags_a_rate_limited_port(db):
    """The host Overview shows a per-port state too, so it shows the flag too."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), limited_doc([SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    overview = (rl.render(db, now=NOW)
                .split('id="t-box-overview"')[1].split('<div class="tab')[0])
    assert '<span class="tag-rate" title="rate limited">rate limited</span>' in overview
    assert "unreviewed" in overview


def test_a_database_the_prober_has_never_touched_still_renders(db):
    """A box before the first pass has no probe tables at all. The page has to
    render, with every port reading not tested."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "not tested" in html


def test_one_host_that_cannot_be_joined_does_not_take_the_page_down(db, capsys):
    """The engine parses the stored document itself and its own guard catches
    less than this renderer's. One host must never end the render."""
    add_host(db, "good", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_host(db, "bad", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())

    engine = jb.load()
    real = engine.host_findings

    def explode(con, host_id, **kwargs):
        row = con.execute("SELECT name FROM hosts WHERE id = ?",
                          (host_id,)).fetchone()
        if row[0] == "bad":
            raise RecursionError("too deep")
        return real(con, host_id, **kwargs)

    engine.host_findings = explode
    try:
        html = rl.render(db, now=NOW)
    finally:
        engine.host_findings = real
    assert "good" in html and "bad" in html
    # the type and the message: a journal line naming only the type sat
    # unread from 2026-08-29 to 2026-09-15
    err = capsys.readouterr().err
    assert "the three views could not be joined (RecursionError: too deep)" in err


def declare_intent(db, host_name, protocol, port, family, value):
    """One declaration, written the way `python -m app.intent_cli declare`
    writes one. The table is created here so every other test still runs
    against a database where nobody has ever declared anything."""
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

# ------------------------------------------------------------ the fleet strip

def test_a_measured_silence_is_not_drawn_as_never_tested(db):
    """The difference this column exists for. A flat bar was measured and did
    not answer. A hollow bar is a family nobody probed. Drawing the first as
    the second throws away a measurement that was taken."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "no_response")
    _h, docs, _hi, _a, _n, findings, *_ = rl.load(db, now=NOW)
    reach, chips = rl.fleet_facts(docs["box"][1], findings["box"])
    # measured and shut: the port is observed and not open
    assert reach == (0, 1)
    assert chips == ()


def test_an_answered_port_fills_only_the_family_that_answered(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    _h, docs, _hi, _a, _n, findings, *_ = rl.load(db, now=NOW)
    reach, chips = rl.fleet_facts(docs["box"][1], findings["box"])
    # one family answered, so the port counts as open once (answer 4), and
    # nobody has said whether that is intended, so it is a chip
    assert reach == (1, 1)
    assert chips == (("tcp/22", "warn"),)


def test_the_worse_of_two_families_is_the_word_the_row_shows(db):
    """A row shows one word for a port that has two families. Showing the
    calmer of the two would hide a conflict on v6 behind an intended on v4."""
    doc = document(listening=[SSHD, dict(SSHD, family="v6",
                                         bind_address="2001:db8::1", pid=9)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    probe_result(db, "box", 22, "v6", "connect_succeeded")
    declare_intent(db, "box", "tcp", 22, "v6", "closed")
    _h, docs, _hi, _a, _n, findings, *_ = rl.load(db, now=NOW)
    reach, chips = rl.fleet_facts(docs["box"][1], findings["box"])
    # v6 is a conflict and v4 unreviewed: both need somebody, so the chip
    # names the whole port and takes the worse tone (answer 7)
    assert chips == (("tcp/22", "fail"),)
    assert reach == (1, 1)


def test_a_chip_names_the_family_when_only_one_family_needs_a_decision(db):
    """Answer 7: the suffix says which side of the port to look at, and only
    when the other side has a finding that needs nothing."""
    doc = document(listening=[SSHD, dict(SSHD, family="v6",
                                         bind_address="2001:db8::1", pid=9)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    probe_result(db, "box", 22, "v6", "connect_succeeded")
    declare_intent(db, "box", "tcp", 22, "v4", "open")
    _h, docs, _hi, _a, _n, findings, *_ = rl.load(db, now=NOW)
    reach, chips = rl.fleet_facts(docs["box"][1], findings["box"])
    assert chips == (("tcp/22 v6", "warn"),)
    # and a port with a finding in one family only never carries a suffix
    add_host(db, "one", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "one", 22, "v4", "connect_succeeded")
    _h, docs, _hi, _a, _n, findings, *_ = rl.load(db, now=NOW)
    assert rl.fleet_facts(docs["one"][1], findings["one"])[1] == (("tcp/22", "warn"),)


def test_a_listening_port_the_engine_says_nothing_about_still_shows(db):
    """The document's ports are the floor. A fleet row losing a port is exactly
    the fault this column exists to make visible."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    _h, docs, *_ = rl.load(db, now=NOW)
    reach, chips = rl.fleet_facts(docs["box"][1], ())
    assert reach == (0, 1) and chips == ()
    # and a host with no document and no findings observes nothing at all
    assert rl.fleet_facts({}, ()) == (None, ())


# ------------------------------------------- the state on the host page itself
#
# The fleet row carried the joined state from the day the engine landed and the
# host page for the same port did not, which is a page contradicting itself one
# click apart (the owner saw the state missing from the server's own overview on
# 2026-08-21).

def test_a_state_reaches_the_port_table_on_the_host_page(db):
    """The regression this section exists for. A port that answers from
    outside with a listener behind it and nobody having said whether that is
    intended is `unreviewed`, on the host page as well as on the fleet row."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    overview = tab_body(host_section(html, "box"), "box", "overview")
    assert theme.status("warn", "unreviewed") in overview
    assert '<i class="warn">v4</i><i class="">v6</i>' in overview, "v6 borrowed the v4 answer"


def test_the_host_page_and_the_fleet_row_agree_about_a_port(db):
    """One ranking on the page rather than two. Both read the same findings
    through the same severity order, so the word cannot differ by one click."""
    doc = document(listening=[SSHD, dict(SSHD, family="v6",
                                         bind_address="2001:db8::1", pid=9)])
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    probe_result(db, "box", 22, "v6", "connect_succeeded")
    declare_intent(db, "box", "tcp", 22, "v6", "closed")
    _h, docs, _hi, _a, _n, findings, *_ = rl.load(db, now=NOW)
    _reach, chips = rl.fleet_facts(docs["box"][1], findings["box"])
    word, _tone, _why = rl.port_row_state(
        rl.port_state_cells(findings["box"])[("tcp", 22)])
    assert word == "conflict"
    assert chips == (("tcp/22", rl.tpl.PORT_TONE[word]),)


def test_the_why_column_names_a_filter_and_never_the_service(db):
    """The sentence is drawn when a filtering layer decided, with its rule
    quoted under it. "the service decided" went on 2026-08-29: it appeared on
    every reachable row, so it separated no two rows on the screen it was
    drawn on, which is 4.128's definition of junk. The state word and the
    bind line already carry what it said."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    _h, _d, _hi, _a, _n, findings, _ch, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    cells = rl.port_state_cells(findings["box"])
    word, _tone, why = rl.port_row_state(cells[("tcp", 22)])
    assert word == "unreviewed"
    assert why == "", why
    assert "not determined" not in why, "a cell that costs a line and says nothing"


def test_a_stale_rule_still_names_the_firewall_and_quotes_it(db):
    """The information-bearing case keeps its sentence and its evidence: the
    rule that outlived its service, quoted verbatim under the layer that
    holds it (docs/DESIGN.md section 3)."""
    doc = document(listening=[SSHD], nft_rules=1)
    doc["nftables"]["tables"][0]["chains"][0] = {
        "name": "input", "type": "filter", "hook": "input", "priority": 0,
        "policy": "drop",
        "rules": [{"text": "tcp dport 3000 accept", "rendered": "full"}]}
    add_host(db, "box", [(NOW - timedelta(minutes=2), doc)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    # Measured, like the real case this mirrors: the probe got nothing back
    # on the permitted port, and the rule is what is left holding it open.
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    probe_result(db, "box", 3000, "v4", "no_response")
    _h, _d, _hi, _a, _n, findings, _ch, _mailed, _sent, _mutes, _proofs, *_ = rl.load(db, now=NOW)
    cells = rl.port_state_cells(findings["box"])
    word, _tone, why = rl.port_row_state(cells[("tcp", 3000)])
    assert word == "stale rule"
    assert why == "the host firewall decided", why
    quotes, _more = rl.port_row_quotes(cells[("tcp", 3000)])
    assert any("tcp dport 3000 accept" in text for text, _src in quotes)


def test_the_engines_undetermined_layer_is_read_from_the_engine(db):
    """It is spelled once, in the engine. A rename there that left this module
    holding the old spelling would print "the not determined decided" on every
    row, quietly, on the one screen that exists to name a layer."""
    assert rl.LAYER_NOT_DETERMINED == jb.load().LAYER_NOT_DETERMINED


def test_a_port_the_engine_says_nothing_about_keeps_its_row_and_no_state(db):
    """The document's ports are the floor here too, and a port with no finding
    is not a port with a blank row: it still names both families as untested,
    and it still carries no control that leads nowhere."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    overview = tab_body(host_section(html, "box"), "box", "overview")
    assert 'data-port="22/tcp"' in overview
    assert 'class="st ' not in overview.split('class="panel ptbl"')[1]
    assert '<i class="">v4</i><i class="">v6</i>' in overview
    # and it offers no answer: there is no finding to answer for
    assert '<span class="pra "' in overview and 'data-answer=' not in overview
    assert 'for="tb-box-path"' not in overview


def test_the_fleet_legend_no_longer_says_every_bar_is_hollow(db):
    """It said so, and it was true until the prober ran on a schedule."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "Every bar on this page is hollow" not in html
    assert "The prober does not run on a schedule" not in html







# ============================== the Integrations screen lists every channel
#
# The Alerts screen did until layout B (docs/screens/alerts/SPEC-layout-b.md).
#
# `docs/RECORD.md` 4.86. The channels panel is a list of what is configured
# (the owner, 2026-08-16), so a webhook that delivers has to appear on it. The row
# holds no destination, which is what lets this renderer read it at all.


def add_channel(db, label="ops", channel_type="webhook",
                env_name="WHICHPORTS_WEBHOOK_URL", enabled=True):
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS notification_channels (
        id INTEGER PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
        destination_env TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, removed_at TEXT);
    """)
    con.execute(
        "INSERT INTO notification_channels (type, label, destination_env,"
        " enabled, created_at) VALUES (?, ?, ?, ?, ?)",
        (channel_type, label, env_name, 1 if enabled else 0, NOW.isoformat()))
    con.commit()
    con.close()


def add_delivery(db, channel_key, when=None, alert_id=1):
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS alert_deliveries (
        id INTEGER PRIMARY KEY, alert_id INTEGER NOT NULL,
        channel TEXT NOT NULL, delivered_at TEXT NOT NULL);
    """)
    con.execute("INSERT INTO alert_deliveries (alert_id, channel, delivered_at)"
                " VALUES (?, ?, ?)",
                (alert_id, channel_key, (when or NOW).isoformat()))
    con.commit()
    con.close()
    # A delivery is a send that succeeded, and the sweep logs it as one.
    log_sent(db, alert_id, channel_key, when or NOW)


def test_a_database_with_no_channel_table_still_renders(db):
    """A box the sweep has not touched since this landed."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "Email" in html


def test_a_configured_webhook_appears_on_the_alerts_screen(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops slack")
    html = rl.render(db, now=NOW)
    assert "ops slack" in html
    assert "WHICHPORTS_WEBHOOK_URL" in html


def add_channel_holding_its_destination(db, label, destination,
                                        subscriptions="", workspace_id=1,
                                        channel_type="slack"):
    """A row configured the ordinary way, holding its own value.

    `subscriptions` is comma separated and empty means every kind, which is
    what the column means (`controlplane/app/channels.py`).
    """
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS notification_channels (
        id INTEGER PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
        destination_env TEXT NOT NULL, destination TEXT NOT NULL DEFAULT '',
        destination_extra TEXT NOT NULL DEFAULT '',
        subscriptions TEXT NOT NULL DEFAULT '',
        workspace_id INTEGER NOT NULL DEFAULT 1,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, removed_at TEXT);
    """)
    con.execute(
        "INSERT INTO notification_channels (type, label, destination_env,"
        " destination, subscriptions, workspace_id, enabled, created_at)"
        " VALUES (?, ?, '', ?, ?, ?, 1, ?)",
        (channel_type, label, destination, subscriptions, workspace_id,
         NOW.isoformat()))
    con.commit()
    con.close()


def test_the_secret_segment_of_a_destination_never_reaches_the_page(db):
    """The Destination column shows where an alert goes since 2026-08-23, so
    what must not reach the page narrowed from the whole destination to the part
    that is the credential: a webhook URL's last path segment, which is what
    lets anybody post. `channels.Channel.hint` decides that and says why.

    **This is the second layer and not the guard itself, and the difference is
    worth being exact about.** Measured: with `for_display` edited to stop
    clearing the destination, this test still passes, because the template does
    not render that field either way. So what it really covers is a template
    that starts rendering it, or a key or a detail line that carries it in.

    The guard on `for_display` itself is
    `controlplane/tests/test_channels.py::test_what_a_renderer_gets_has_no_destination_on_it`,
    which does fail on that edit. Both are worth having. Only one of them is
    the guard.
    """
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops slack", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    html = rl.render(db, now=NOW)
    assert "SUPERSECRETVALUE" not in html
    panel = channels_panel(html)
    # The row now names which webhook it is, up to the segment that is the
    # secret, which is the whole point of the column.
    assert "hooks.slack.com/services/T00/B00/" in panel
    assert "hooks.slack.com/services/T00/B00/SUPERSECRETVALUE" not in panel


def test_the_screen_says_which_service_without_saying_the_secret(db):
    """The host is all it may show, and it is all a person needs to tell one
    channel from another. The secret in every one of these is the path."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops slack", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    panel = channels_panel(rl.render(db, now=NOW))
    assert "hooks.slack.com" in panel
    assert "SUPERSECRETVALUE" not in panel


def test_the_delivery_key_on_the_page_is_not_the_destination(db):
    """The key reaches the page through `took_by` and through the times-used
    count, so a key that was the URL would leak it by another route."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops slack", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    html = rl.render(db, now=NOW)
    assert "SUPERSECRETVALUE" not in html


def test_the_screen_never_shows_a_destination(db):
    """A row configured by variable names the variable, and the renderer must
    not find the value anywhere else."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    html = rl.render(db, now=NOW)
    assert "hooks.example.com" not in html
    assert "SUPERSECRET" not in html


def channels_panel(html):
    """Just the "Where it goes" panel, so an assertion about a channel cannot
    be satisfied by something else on a page this size.

    **This exists because one was.** The test below asserted the words
    "switched off" appeared somewhere in the rendered page, and they did: in a
    CSS comment about the account rail, which ships in the stylesheet. So it
    passed whatever the channel row said, including when the row stopped saying
    it at all. Scope every channel assertion to this.
    """
    return destinations_section(html)


def test_a_channel_switched_off_still_appears_and_says_off(db):
    """Off is not removed. A list of where alerts go has to show one that is
    switched off, or the list is not what it says it is."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="quiet one", enabled=False)
    panel = channels_panel(rl.render(db, now=NOW))
    assert "quiet one" in panel
    # The Tag treatment, one hairline box holding the word (docs/DESIGN.md
    # section 3), and the word is the signal rather than the tone.
    assert '<span class="st off">off</span>' in panel


def test_a_channel_that_is_on_says_on(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    assert '<span class="st ok">on</span>' in channels_panel(rl.render(db, now=NOW))


def test_the_row_shows_the_variable_name_as_the_destination(db):
    """The column is headed Destination and a row holds no destination, so what
    it can honestly show is the name of the variable the sweep reads
    (docs/RECORD.md 4.87)."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops", env_name="WHICHPORTS_SLACK_URL", channel_type="slack")
    panel = channels_panel(rl.render(db, now=NOW))
    assert "WHICHPORTS_SLACK_URL" in panel
    assert "Slack" in panel


def test_the_row_carries_the_five_columns_the_design_asked_for(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    panel = channels_panel(rl.render(db, now=NOW))
    for column in ("Channel", "Destination", "Status"):
        assert f">{column}<" in panel, column
    assert ">Sent<small>past 7 days</small><" in panel


def test_times_used_counts_what_that_channel_actually_took(db):
    """From alert_deliveries, which is a fact about our own machinery rather
    than about the operator's configuration."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    # a delivery hangs off an alert, so one is raised first
    add_alert(db, "box", "no report for 40 minutes", NOW - timedelta(hours=1))
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL")
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL")
    add_delivery(db, "webhook:WHICHPORTS_SOMETHING_ELSE")
    panel = channels_panel(rl.render(db, now=NOW))
    assert '<div class="crow-u">2</div>' in panel, "the count picked up another channel's"


def test_every_row_carries_its_own_menu(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops one")
    add_channel(db, label="ops two")
    panel = channels_panel(rl.render(db, now=NOW))
    assert panel.count('class="rm-t"') == 2
    # The four the owner asked for on 2026-08-23: edit, send a test
    # notification, enable or disable, and delete. Showing what was
    # sent was the fifth on the reference screen and is not in his list.
    for item in ("Edit", "Send test", "Turn off", "Delete"):
        assert f">{item}<" in panel, item
    assert ">Show sent<" not in panel
    # Delete sits apart, under a line, in the fail tone
    assert '<hr class="rm-hr"><button type="button" class="rm-i rm-post rm-del"' in panel
    # Each item says which channel it acts on, or a menu acts on the wrong row.
    # The trigger names its row in data-menu instead, so this is the item count.
    assert panel.count('data-label="ops one"') == 4
    assert panel.count('data-label="ops two"') == 4
    assert panel.count('data-menu="ops one"') == 1


def test_the_toggle_item_names_the_action_and_not_the_state(db):
    """An enabled channel offers Turn off and a disabled one offers Turn on,
    because a menu item is a thing you are about to do. The Status cell is
    where the row's own state is read (docs/DESIGN.md section 3)."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="on air")
    add_channel(db, label="switched off", enabled=False)
    panel = channels_panel(rl.render(db, now=NOW))
    # Each row offers exactly one of the two, and it is the right one. Asserted
    # per row rather than over the panel, because both words appear on a page
    # holding one enabled and one disabled channel whatever either row says.
    assert 'data-act="disable" data-label="on air"' in panel
    assert 'data-act="enable" data-label="on air"' not in panel
    assert 'data-act="enable" data-label="switched off"' in panel
    assert 'data-act="disable" data-label="switched off"' not in panel


def test_the_menu_calls_the_route_names_the_control_plane_actually_serves(db):
    """**The bug this exists to stop, because it nearly shipped.** This screen
    was written against an `/edit` route and the control plane shipped
    `/destination` in `#296`, so Edit would have posted to a 404 while the
    feature looked finished. Every path this page posts to is asserted by name
    here, and `controlplane/tests/test_channels_endpoint.py` asserts the other
    end of each one.
    """
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    # One of each state, because an enabled row offers only Disable and a
    # disabled row only Enable, so one channel can never show both routes.
    add_channel(db, label="ops")
    add_channel(db, label="night rota", enabled=False)
    html = rl.render(db, now=NOW)
    # The three the script spells out in full, which are the ones at risk of
    # disagreeing with the control plane. `/events` joined them on 2026-08-24,
    # when editing a Slack row became a change to its switches alone.
    for path in ("/destination", "/test", "/events"):
        assert "encodeURIComponent" in html and path in html, path
    # The rest are built from the menu item's own data-act, so the value in the
    # attribute is the last path segment and that is what to assert.
    for act in ("remove", "enable", "disable"):
        assert f'data-act="{act}"' in html, act
    # and the name that was wrong is not there under any spelling
    assert "/edit'" not in html
    assert "'/edit'" not in html


# ------------------------------- editing a row that has no destination field
#
# Slack stopped offering one on 2026-08-24, so Edit on a Slack row had to mean
# something that cannot break the row. It means the switches: the stored
# webhook is never posted from this page, so a connected channel stays
# connected whatever is done in the window.


def test_editing_a_row_with_no_field_writes_only_which_kinds_it_takes(db):
    """A Slack row's destination is not on this page, so posting it back would
    send an empty string and the control plane would refuse it. The page reads
    the field's absence and posts the switches to /events instead."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    html = rl.render(db, now=NOW)
    # the branch, and the fact it is keyed off the field and not off the type
    assert "var kindsOnly=!!editing&&!destField;" in html
    assert "(kindsOnly?'/events':'/destination')" in html
    # a step with no field never reaches the refusal meant for an empty one.
    # Until docs/RECORD.md 4.228 that was one test on the destination field's
    # presence, `if(destField&&!dest)`, and this line held it. A refusal is
    # of a field the step holds now, each with its own check, and the Slack
    # step holds none. What a click on Save does there is held in a real
    # browser (test_layout_b_browser.py, the edit of a Slack row).
    assert "var refused=checkFields(stage);" in html
    assert "data-pattern" not in rl.tpl.channel_stage("chan-slack")


def test_an_edit_never_leaves_for_slack(db):
    """The connect writes a row of its own, so a connect from a window opened
    on an existing row would leave two rows behind."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    html = rl.render(db, now=NOW)
    assert ("return !!stage&&stage.dataset.type==='slack'&&!connOvl.dataset.editing;"
            in html)
    # and the footer goes back to the saving word when the window opens on a
    # row: Edit marks the window as editing, then paints the foot from that
    assert "connGo.textContent=slackConnect()?'Connect to Slack':connGo.dataset[kind];" in html
    edit = html[html.index("var bindEdit=function(b){"):]
    edit = edit[:edit.index("onWire(")]
    assert edit.index("connOvl.dataset.editing=label;") < edit.index("connFoot();")
    assert 'data-dest="Save"' in modal_markup(html, "conn-ovl")


def test_a_slack_row_keeps_every_way_of_managing_it(db):
    """A row whose destination cannot be edited must still be one a person can
    switch off, test and delete. Losing the menu would be a row nobody can get
    rid of."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    panel = channels_panel(rl.render(db, now=NOW))
    for item in ("Edit", "Send test", "Turn off", "Delete"):
        assert f">{item}<" in panel, item
    assert 'data-act="remove" data-label="ops"' in panel
    assert 'data-type="slack"' in panel


def test_the_menu_carries_the_kinds_the_row_already_takes(db):
    """The switches in the window start from the row rather than from every
    kind, or saving an edit would quietly subscribe the row to kinds nobody
    picked."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE",
        subscriptions="silent")
    html = rl.render(db, now=NOW)
    assert 'data-events="silent"' in channels_panel(html)
    assert "takes.indexOf(sw.dataset.kind)<0" in html


def test_a_row_that_takes_every_kind_says_so_with_an_empty_list(db):
    """Empty is every kind, which is what the column means, so the window shows
    every switch on rather than every switch off."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    html = rl.render(db, now=NOW)
    assert 'data-events=""' in channels_panel(html)
    assert "takes.length>0&&" in html


def test_the_kinds_on_the_menu_are_never_the_destination(db):
    """The menu gained an attribute out of the row, so the rule the whole panel
    follows is asserted on it too."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(
        db, "ops", "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE",
        subscriptions="silent,finding changed")
    panel = channels_panel(rl.render(db, now=NOW))
    assert "SUPERSECRETVALUE" not in panel
    assert 'data-events="silent,finding changed"' in panel


def test_the_test_answer_shows_the_command_when_one_comes_back(db):
    """A row whose secret this process does not hold answers with a `command`
    beside the reason. Showing only the reason would say it could not be done
    here without saying what to do instead."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    html = rl.render(db, now=NOW)
    assert "j.command" in html
    # detail is the empty string on a success, so the words there are ours
    assert "Test sent to " in html


def test_send_test_asks_the_control_plane_and_repeats_what_it_answered(db):
    """The owner, 2026-08-23: the test is per channel and the big Send test
    button goes. So the row asks the control plane to send, and the
    control plane is what decides whether it can: a row holding its own
    destination is sent to, and a row naming a variable this process never
    reads answers with the line to run on the box (docs/RECORD.md 4.87).

    **The page repeats that answer rather than claiming a send**, which is why
    the toast is the response body and not a sentence written here.
    """
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    html = rl.render(db, now=NOW)
    assert 'class="rm-i rm-test" data-act="test"' in html
    assert "/test'" in html and "rm-test" in html
    assert "toast(j.detail" in html, "the answer is shown, not a claim of ours"
    # and the page-level button it replaces is gone
    assert 'data-msg="A test alert' not in html


def test_a_label_that_looks_like_markup_cannot_escape_the_row_or_the_menu(db):
    """A label is the operator's own text and reaches an attribute the script
    reads, so it is escaped in both places or it is a hole."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label='x"><script>alert(1)</script>')
    panel = channels_panel(rl.render(db, now=NOW))
    assert "<script>alert(1)</script>" not in panel
    assert "&lt;script&gt;" in panel


def test_a_channel_type_nobody_predicted_still_renders(db):
    """The 4.89 trap. A map keyed by a word that stopped being drawn from a
    fixed set took the whole render down once, and PORT_TONE did it before
    that. The type falls back rather than raising."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="future", channel_type="carrier pigeon")
    panel = channels_panel(rl.render(db, now=NOW))
    assert "future" in panel


def test_a_stored_email_row_is_an_ordinary_row_with_its_menu(db):
    """The row an account is given (`controlplane/app/accounts.py`). It shows
    its address, and it has the menu every stored row has, so it can be
    switched off or deleted."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(db, "email", "tester@example.org",
                                        channel_type="email")
    panel = channels_panel(rl.render(db, now=NOW))
    assert "tester@example.org" in panel
    assert 'aria-label="Manage email"' in panel
    assert "set on the server" not in panel


def test_a_channel_that_has_never_delivered_says_so(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    assert '<div class="crow-u z">0</div>' in channels_panel(rl.render(db, now=NOW))


def test_a_channel_that_has_delivered_says_how_often(db):
    """Scoped to the panel, which is what `channels_panel` exists to make
    everything here do. The page also carries the hidden row the browser clones
    when a channel is added, and that one counts zero because a channel that
    was just added has sent nothing."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    # a delivery hangs off an alert, so one is raised first
    add_alert(db, "box", "no report for 40 minutes", NOW - timedelta(hours=1))
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL")
    panel = channels_panel(rl.render(db, now=NOW))
    assert '<div class="crow-u">1</div>' in panel


def test_delivery_is_matched_to_the_right_channel(db):
    """Two channels, one delivery. The key is the variable a destination is
    read from, so the wrong row must not claim it."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops", env_name="WHICHPORTS_WEBHOOK_URL")
    add_channel(db, label="security", env_name="WHICHPORTS_WEBHOOK_URL_SEC")
    # a delivery hangs off an alert, so one is raised first
    add_alert(db, "box", "no report for 40 minutes", NOW - timedelta(hours=1))
    add_delivery(db, "webhook:WHICHPORTS_WEBHOOK_URL_SEC")
    panel = channels_panel(rl.render(db, now=NOW))
    assert '<div class="crow-u">1</div>' in panel
    assert panel.count('<div class="crow-u z">0</div>') == 1, \
        "the other channel should still have sent nothing"


def test_an_operators_own_label_does_not_take_the_render_down(db):
    """The trap this guards. `icons[name]` on a label nobody predicted is a
    KeyError, and the channels list is the first place a name stopped being one
    of a fixed set of words."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="pagerduty-ish thing")
    assert "pagerduty-ish thing" in rl.render(db, now=NOW)


def test_a_label_is_escaped(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="a b")
    con = sqlite3.connect(db)
    con.execute("UPDATE notification_channels SET label = ?",
                ("<script>alert(1)</script>",))
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ===================================== the packet path's outward half
#
# `docs/RECORD.md` 4.91. The rail is read against a measurement the prober
# took, and never against an absence.

DROP_443 = "ip protocol tcp tcp dport 443 counter drop"


def ufw_doc(port=443, policy="drop", rules=None):
    rules = rules if rules is not None else [
        {"text": DROP_443, "rendered": "full", "comment": ""}]
    return {
        "schema_version": 1, "hostname": "box", "collected_at_unix": 0,
        "sockets": {"status": "collected", "listening": [
            {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
             "port": port, "process_name": "caddy", "pid": 1}]},
        "nftables": {"status": "collected", "tables": [
            {"family": "ip", "name": "filter", "chains": [
                {"name": "INPUT", "hook": "input", "priority": 0,
                 "type": "filter", "policy": policy, "rules": rules}]}]},
    }


def a_walked_host(db, port=443, policy="drop", rules=None):
    add_host(db, "box", [(NOW - timedelta(minutes=2), ufw_doc(port, policy, rules))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())


def test_an_unprobed_port_gets_no_outward_view(db):
    """docs/PRODUCT.md 4b, on the screen this time."""
    a_walked_host(db)
    html = rl.render(db, now=NOW)
    assert "what the outside view adds" not in html


def test_the_vantage_is_named(db):
    """docs/PRODUCT.md 5e. The same port answers from one network and not from
    another, so a measurement without a vantage cannot be read."""
    a_walked_host(db)
    probe_result(db, "box", 443, "v4", "no_response", vantage="probe1")
    assert f"from {rl.tpl.mono('probe1')}" in rl.render(db, now=NOW)


# ================================================================ workspaces
#
# The page is rendered per workspace, so the thing to prove is that a host in
# somebody else's workspace reaches none of it: not the fleet table, not the
# alerts, not the declared names, not the mail count, and not the host section
# that would carry its ports and its rules.
#
# `workspace_id=None` is the whole fleet. Nothing serves that to a browser, and
# the tests that use it are the ones that are not about workspaces at all.


@pytest.fixture()
def two_workspaces(db):
    """One host in workspace 1, one in workspace 2, each with a document, an
    open alert and a declared name."""
    con = sqlite3.connect(db)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'second', ?)",
                (NOW.isoformat(),))
    con.commit()
    con.close()
    for name, workspace in (("mybox", 1), ("theirbox", 2)):
        add_host(db, name, [(NOW - timedelta(minutes=4), document(listening=[SSHD]))],
                 last_report_at=(NOW - timedelta(minutes=4)).isoformat(),
                 workspace_id=workspace)
        add_alert(db, name, f"{name} went quiet", NOW - timedelta(minutes=1),
                  notified=True)
        declare_name(db, name, "tcp", 22, f"{name}-ssh")
    return db


def test_a_host_in_another_workspace_is_not_on_the_page(two_workspaces):
    html = rl.render(two_workspaces, now=NOW, workspace_id=1)
    assert "mybox" in html
    assert "theirbox" not in html


def test_each_workspace_sees_only_its_own_host(two_workspaces):
    theirs = rl.render(two_workspaces, now=NOW, workspace_id=2)
    assert "theirbox" in theirs
    assert "mybox" not in theirs


def test_an_alert_against_another_workspaces_host_is_not_shown(two_workspaces):
    html = rl.render(two_workspaces, now=NOW, workspace_id=1)
    assert "mybox went quiet" in html
    assert "theirbox went quiet" not in html


def test_a_declared_name_from_another_workspace_is_not_shown(two_workspaces):
    html = rl.render(two_workspaces, now=NOW, workspace_id=1)
    assert "mybox-ssh" in html
    assert "theirbox-ssh" not in html


def test_the_mail_count_is_this_workspaces_alerts_only(two_workspaces):
    con = sqlite3.connect(two_workspaces)
    con.row_factory = sqlite3.Row
    assert rl.mail_count(con, 1) == 1
    assert rl.mail_count(con, 2) == 1
    assert rl.mail_count(con) == 2
    con.close()


def test_the_loads_reach_nothing_outside_the_workspace(two_workspaces):
    """The four reads under render(), asked directly, so a failure names which
    one leaked rather than only saying a string was on the page."""
    con = sqlite3.connect(two_workspaces)
    con.row_factory = sqlite3.Row
    assert list(rl.load_alerts(con, 1)) == ["mybox"]
    assert list(rl.load_names(con, 1)) == ["mybox"]
    hosts, *_ = rl.load(two_workspaces, now=NOW, workspace_id=1)
    assert [row["name"] for row in hosts] == ["mybox"]
    con.close()


def test_a_channel_in_another_workspace_is_not_on_the_page(two_workspaces):
    """The tenant leak from the 2026-08-23 audit, closed: the Alerts page
    listed every workspace's channel labels, because `load_channels` took no
    workspace at all."""
    add_channel_holding_its_destination(
        two_workspaces, "ours slack", "https://hooks.slack.com/services/T1/B1/x",
        workspace_id=1)
    add_channel_holding_its_destination(
        two_workspaces, "theirs slack", "https://hooks.slack.com/services/T2/B2/x",
        workspace_id=2)
    html = rl.render(two_workspaces, now=NOW, workspace_id=1)
    assert "ours slack" in html
    assert "theirs slack" not in html
    theirs = rl.render(two_workspaces, now=NOW, workspace_id=2)
    assert "theirs slack" in theirs
    assert "ours slack" not in theirs


def test_load_sent_reaches_nothing_outside_the_workspace(two_workspaces):
    """The delivery list is read through the same host join every other read
    uses, so a delivery to somebody else's server cannot reach this page. Both
    tables are checked, because either one on its own would be a leak."""
    add_delivery(two_workspaces, "webhook:WHICHPORTS_WEBHOOK_URL", alert_id=2)
    con = sqlite3.connect(two_workspaces)
    con.row_factory = sqlite3.Row
    since = NOW - timedelta(days=7)
    mine, mine_total = rl.load_sent(con, since, 50, 1)
    assert [row["host_name"] for row in mine] == ["mybox"]
    assert mine_total == 1
    theirs, theirs_total = rl.load_sent(con, since, 50, 2)
    # the mail on their alert and the webhook that took it, and nothing of ours
    assert {row["host_name"] for row in theirs} == {"theirbox"}
    assert theirs_total == 2
    _all_rows, all_total = rl.load_sent(con, since, 50)
    assert all_total == 3
    con.close()


def test_another_workspaces_delivery_is_not_in_what_went_out(two_workspaces):
    add_delivery(two_workspaces, "webhook:WHICHPORTS_WEBHOOK_URL", alert_id=2)
    section = sent_section(rl.render(two_workspaces, now=NOW, workspace_id=1))
    assert "mybox" in section
    assert "theirbox" not in section
    assert "Webhook" not in section        # that row hangs off their alert
    assert '<span class="cnt c7">1</span>' in section


def test_no_workspace_at_all_is_still_the_whole_fleet(two_workspaces):
    """The deploy check renders this, and the tests that are not about
    workspaces render it too. It must keep showing everything."""
    html = rl.render(two_workspaces, now=NOW)
    assert "mybox" in html
    assert "theirbox" in html


def test_a_workspace_with_no_hosts_still_renders_a_page(two_workspaces):
    """A new account has no servers yet and must see an empty dashboard rather
    than an error."""
    con = sqlite3.connect(two_workspaces)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (3, 'empty', ?)",
                (NOW.isoformat(),))
    con.commit()
    con.close()
    html = rl.render(two_workspaces, now=NOW, workspace_id=3)
    assert "mybox" not in html
    assert "theirbox" not in html
    assert "<html" in html


# --- what the timer writes ---

def test_the_command_writes_one_page_per_workspace(two_workspaces, tmp_path,
                                                   monkeypatch, capsys):
    out_dir = tmp_path / "app"
    monkeypatch.setattr(rl.sys, "argv",
                        ["render_live.py", "--db", two_workspaces,
                         "--out-dir", str(out_dir)])
    rl.main()
    capsys.readouterr()
    first = (out_dir / rl.WORKSPACE_DIRNAME / "1" / rl.INDEX_FILENAME).read_text()
    second = (out_dir / rl.WORKSPACE_DIRNAME / "2" / rl.INDEX_FILENAME).read_text()
    assert "mybox" in first and "theirbox" not in first
    assert "theirbox" in second and "mybox" not in second


def test_the_command_refuses_the_old_out_flag(db, tmp_path, monkeypatch):
    """A unit file still passing `--out` has to fail loudly. Silently writing
    one workspace's page over the directory every page lives in would be a
    dashboard that stops updating without saying so."""
    monkeypatch.setattr(rl.sys, "argv",
                        ["render_live.py", "--db", db, "--out",
                         str(tmp_path / "index.html")])
    with pytest.raises(SystemExit):
        rl.main()


def test_workspace_ids_reads_them_in_order(two_workspaces):
    assert rl.workspace_ids(two_workspaces) == [1, 2]


def test_workspace_ids_answers_one_when_the_table_is_missing(tmp_path, capsys):
    """Reachable during a deploy, against a database no init has touched yet.
    Workspace 1 is where the migration puts every existing host, so its page
    holds exactly what the page held before."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.executescript(
        "CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE,"
        " token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL,"
        " revoked_at TEXT, last_report_at TEXT);")
    con.commit()
    con.close()
    assert rl.workspace_ids(str(path)) == [1]
    assert "no workspaces table" in capsys.readouterr().err


def test_write_page_replaces_the_file_rather_than_leaving_a_half_written_one(tmp_path):
    """The control plane serves this file on request, so it must never read one
    that is half written. The rename is inside one directory, which is what
    makes it atomic."""
    first = rl.write_page(tmp_path, 1, "<html>one</html>")
    second = rl.write_page(tmp_path, 1, "<html>two</html>")
    assert first == second
    assert second.read_text() == "<html>two</html>"
    assert not list(second.parent.glob("*.tmp"))


# ------------------------------------------------- you can tell what is live

def test_the_dashboard_says_when_it_was_rendered(db):
    """The owner, 2026-08-23, could not tell a change that did not work from one
    that had not arrived. The dashboard is rendered on the box per request rather
    than deployed, so this is the fact that answers it."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert 'class="pgstamp"' in html
    assert f"rendered {NOW.strftime('%Y-%m-%d %H:%M:%S')} UTC" in html


def test_the_stamp_moves_with_the_render(db):
    """A stamp that does not move is a render that is failing, which is exactly
    the case that used to be invisible."""
    add_host(db, "box", [])
    first = rl.render(db, now=NOW)
    later = rl.render(db, now=NOW + timedelta(minutes=7))
    assert first != later
    assert (NOW + timedelta(minutes=7)).strftime("%H:%M:%S") in later


def test_the_sample_shell_carries_no_render_stamp():
    """It is a drawing with no render behind it, so a time on it would be a
    claim about machinery that did not run."""
    assert 'class="pgstamp"' not in sample()


# ------------------------------- the window offers the ordinary way first

def test_the_window_asks_for_the_destination_itself(db):
    """The owner, 2026-08-22: the way every other product does it. Pasting
    the value is the first field now, and naming a variable is folded away
    underneath it."""
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    assert 'class="m-input js-dest"' in chan
    # The paragraph under the field went on 2026-08-23 with the rest of the
    # window's prose. The label above it says what the field is for.
    assert "Paste it here" not in chan
    # One destination field per step that asks for one. Slack asks for nothing
    # since 2026-08-24, so it is the one built channel with no field.
    asking = [name for name, field in rl.tpl.CHANNEL_FIELDS.items() if field[1]]
    assert "chan-slack" not in asking
    assert len(asking) == len(rl.tpl.CHANNEL_FIELDS) - 1 == 4
    assert chan.count('class="m-input js-dest"') == len(asking)


def test_no_placeholder_invites_pasting_a_secret_nowhere_useful(db):
    """The destination field's placeholder is the scheme and nothing else. An
    example webhook URL would be a thing people copy."""
    add_host(db, "box", [])
    chan = modal_markup(rl.render(db, now=NOW), "conn-ovl")
    assert 'placeholder="https://"' in chan


def test_the_slack_step_is_the_connect_button_and_nothing_else(db):
    """The owner, 2026-08-22: Slack is one button that says Connect to Slack. On
    2026-08-24 he had the webhook URL field removed and gave the button those
    words. So the step holds nothing at all
    and the footer button is the whole of it."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    chan = modal_markup(html, "conn-ovl")
    slack = chan.split('id="chan-slack"')[1].split('id="chan-discord"')[0]
    # **No second button inside the step** (the owner, 2026-08-23: it replaces
    # the Save channel button and is not a button of its own). The window's
    # one primary button becomes it. That button reads Save since layout B.
    assert "Connect to Slack" not in slack
    assert 'class="btn pri m-connect"' not in chan
    assert "connGo.textContent=slackConnect()?'Connect to Slack'" in html
    assert "location.href='/api/admin/channels/slack/connect'" in html
    # The Slack card names its step again since 2026-10-01
    # (docs/RECORD.md 4.224), after being planned for the closed alpha from
    # 2026-09-20.
    assert 'data-fields="chan-slack"' in chan
    assert 'id="chan-slack"' in chan


def test_the_words_on_the_button_are_the_ones_he_asked_for(db):
    """The owner, 2026-08-24, renamed the button to Connect to Slack. The old
    words are gone from both feeds."""
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        assert "Add to Slack" not in html, feed


def test_only_slack_gets_a_connect_button(db):
    """It is the one channel that can hand itself over. A button on the others
    would be a control with nothing behind it."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    chan = modal_markup(html, "conn-ovl")
    # Nothing in the window itself connects any more, and the one script that
    # does names slack and only slack.
    assert chan.count("Connect to Slack") == 0
    assert chan.count('class="btn pri m-connect"') == 0
    assert html.count("channels/slack/connect") == 1
    assert "stage.dataset.type==='slack'" in html
    # and the script asks that of no other type
    assert re.findall(r"stage\.dataset\.type===?'([a-z]+)'", html) == ["slack"]


def test_no_window_offers_a_slack_destination_field(db):
    """The owner had the Slack webhook URL field removed on 2026-08-24.

    **The field is gone from the screen and not from the product**, the same
    split the environment route took. `controlplane/app/channels.py` still
    stores a Slack destination, the connect writes one, the CLI writes one and
    every row on the box keeps working. This asserts only that no window asks a
    person to type one.
    """
    add_host(db, "box", [])
    for feed, html in (("live", rl.render(db, now=NOW)), ("sample", sample())):
        chan = modal_markup(html, "conn-ovl")
        slack = chan.split('id="chan-slack"')[1].split('id="chan-discord"')[0]
        assert "js-dest" not in slack, feed
        assert "m-input" not in slack, feed
        assert "webhook" not in slack.lower(), feed
        # and the words that framed the field went with it
        assert "or paste a webhook URL" not in chan, feed
        assert "You never see or paste it" not in chan, feed
        assert "Slack incoming webhook URL" not in html, feed


# ------------------------- the footer answers "is my change live"
#
# The owner, 2026-08-23, after a deploy he could not confirm: he could never
# tell a rendering fault from a deploy that had not gone out or a wait that
# was too short, and one refresh after a deploy has to show it.
#
# He had said a version of it that morning and the answer then was a render
# time. This is why that was not enough.


def test_the_footer_names_the_commit_the_deploy_left(db, tmp_path):
    build = tmp_path / "DEPLOYED_COMMIT"
    build.write_text("87d4bb2\n")
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    # The render reads the path from the environment, so the assertion goes
    # through the same function the page does rather than around it.
    assert rl.render_stamp(NOW, build).startswith("built 87d4bb2, rendered")
    assert 'class="pgstamp"' in html


def test_a_render_time_alone_cannot_answer_whether_a_deploy_landed(db, tmp_path):
    """**The reason the commit had to be added.** Two renders from two
    different commits, at two different times, are indistinguishable if the
    footer carries only the time: both look current, because the time moves on
    its own with every request whether or not anybody deployed."""
    old = tmp_path / "old"
    old.write_text("aaaaaaa\n")
    new = tmp_path / "new"
    new.write_text("bbbbbbb\n")
    later = NOW + timedelta(minutes=1)
    # Same clock, different code: the time says nothing, the commit says it all.
    assert "aaaaaaa" in rl.render_stamp(later, old)
    assert "bbbbbbb" in rl.render_stamp(later, new)
    assert rl.render_stamp(later, old) != rl.render_stamp(later, new)


def test_the_time_stays_because_it_answers_the_other_half(tmp_path):
    """A right commit with a time that stopped moving is a render that died
    after the deploy, which is a different fault and has to stay visible."""
    build = tmp_path / "DEPLOYED_COMMIT"
    build.write_text("87d4bb2\n")
    assert "rendered" in rl.render_stamp(NOW, build)
    assert rl.render_stamp(NOW, build) != rl.render_stamp(
        NOW + timedelta(minutes=3), build)


def test_no_commit_file_omits_the_commit_rather_than_inventing_one(tmp_path):
    """The ordinary case in a test and on a machine nobody has deployed to. A
    footer that guessed would be worse than one that says less."""
    assert rl.render_stamp(NOW, tmp_path / "absent") == (
        f"rendered {NOW.strftime('%Y-%m-%d %H:%M:%S')} UTC")


def test_a_dirty_deploy_says_so_on_the_page(tmp_path):
    """ops/deploy-controlplane.sh appends this when it ships an uncommitted
    tree, the same wording ops/deploy-site.sh uses. A commit that does not
    describe what shipped is worse than no commit."""
    build = tmp_path / "DEPLOYED_COMMIT"
    build.write_text("87d4bb2 +local changes\n")
    assert rl.render_stamp(NOW, build).startswith(
        "built 87d4bb2 +local changes, rendered")


@pytest.mark.parametrize("junk", [
    "not-a-commit", "<script>alert(1)</script>", "87d4bb2; rm -rf /",
    "../../etc/passwd", "87d4bb2 and some prose", "", "   ", "zzzzzzz",
    "87d4bb2\nsecond line", "87d4bb2 +local changes but also this",
])
def test_the_footer_refuses_anything_that_is_not_a_commit(tmp_path, junk):
    """**This file is read at render time from a path on disk**, so the footer
    must not become somewhere arbitrary text can be printed onto every
    workspace's dashboard. Only hex, with the one suffix the deploy writes."""
    build = tmp_path / "DEPLOYED_COMMIT"
    build.write_text(junk)
    assert rl.render_stamp(NOW, build) == (
        f"rendered {NOW.strftime('%Y-%m-%d %H:%M:%S')} UTC")


def test_a_directory_where_the_file_should_be_is_not_a_crash(tmp_path):
    """The render runs on every dashboard request and must not start failing
    because something on the box is the wrong shape."""
    (tmp_path / "DEPLOYED_COMMIT").mkdir()
    assert rl.deployed_commit(tmp_path / "DEPLOYED_COMMIT") == ""


def test_the_environment_names_the_file_so_the_unit_and_this_agree(db, monkeypatch, tmp_path):
    build = tmp_path / "elsewhere"
    build.write_text("cafe123\n")
    monkeypatch.setenv(rl.BUILD_FILE_ENV, str(build))
    add_host(db, "box", [])
    assert "built cafe123" in rl.render(db, now=NOW)


def test_a_mail_row_shows_the_whole_address(db):
    """The owner, 2026-08-23, on a mail row that read as set on this screen and
    showed no address: the destination is to be shown. A recipient is not a
    credential."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS notification_channels (
        id INTEGER PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
        destination_env TEXT NOT NULL, destination TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL,
        removed_at TEXT);
    """)
    con.execute(
        "INSERT INTO notification_channels (type, label, destination_env,"
        " destination, enabled, created_at) VALUES ('email', 'ops inbox', '',"
        " 'ops@example.com', 1, ?)", (NOW.isoformat(),))
    con.commit()
    con.close()
    panel = channels_panel(rl.render(db, now=NOW))
    assert "ops@example.com" in panel
    # and the placeholder that sent the owner looking is gone for good
    assert "set on this screen" not in panel


def test_no_row_says_set_on_this_screen(db):
    """The words that made the column useless. A Destination column answering
    with anything other than a destination is the column failing at its job."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel_holding_its_destination(db, "ops", "https://example.com/a/b/c")
    assert "set on this screen" not in rl.render(db, now=NOW)


# ---------------- the dashboard behaves like a product, not like a form
#
# The owner, 2026-08-23, went through the screens and named five small things
# that had been added and kept for no reason he could see. Each is pinned
# here so a later change cannot put it back.


def without_comments(html):
    """The page with its own comments dropped, script and stylesheet both.

    **Why this exists, and it is the same fault twice.** The page ships its
    comments inside itself, and several of them quote the very wording they
    were written to remove, so a test looking for that wording in the raw HTML
    fails on the explanation rather than on anything a person sees.
    `docs/RECORD.md` #266 records the mirror image of this, a test that passed
    because the words it wanted were sitting in a CSS comment.

    Whole-line `//` first, so a `https://` inside a string survives, then
    `/* ... */` blocks, which is where the stylesheet keeps its reasoning.
    """
    kept = [line for line in html.splitlines()
            if not line.lstrip().startswith("//")]
    return re.sub(r"/\*.*?\*/", "", "\n".join(kept), flags=re.S)


def test_the_page_applies_its_own_address_on_load(db):
    """**The bug, and it was one missing line.** `applyPath` existed, was
    correct, and was wired only to `popstate`, so a reload or a pasted link
    landed on the fleet whatever the address said: "if i reload /alerts i get
    sent to fleet, if i open the link
    https://app.whichports.com/integrations i get sent to fleet".

    Driven for real over HTTP in the pull request. Asserted here because a test
    that reads the script is what stops the line being dropped again.
    """
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert "applyPath(location.pathname,'replace')" in html
    # and it stays wired to the back button, which is a different event
    assert "popstate" in html


def test_a_row_action_never_talks_about_the_render(db):
    """A row action once answered that the control plane "catches up within
    the minute", and the owner had it out. A customer cannot act on our timer
    and should not be told about it."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    html = without_comments(rl.render(db, now=NOW))
    for ours in ("catches up", "within the minute", "control plane", "next sweep"):
        assert ours not in html, ours


def test_a_row_action_paints_its_own_result(db):
    """The row changes on the click. The request goes out behind it and only a
    refusal is ever mentioned."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    html = rl.render(db, now=NOW)
    # the status cell and the menu item are both repainted, and undone on a
    # refusal, which is the pair that keeps the screen honest
    assert "setRow" in html and "undo" in html
    assert "That did not save, so nothing changed." in html


def test_no_browser_dialog_is_ever_used(db):
    """The owner wanted our own window for "are you sure", in the product's
    look, and never the browser's. Browser dialogs cannot
    be styled and they differ on every engine."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    add_channel(db, label="ops")
    html = without_comments(rl.render(db, now=NOW))
    for native in ("window.confirm", "window.prompt", "window.alert",
                   "confirm(", "prompt(", "alert("):
        assert native not in html, native
    # ours instead, and it is in the page rather than built per call
    assert 'id="ask"' in html
    assert "askConfirm(" in html


def test_the_confirm_dialog_can_be_refused_three_ways(db):
    """A dialog asking about a delete has to be as easy to refuse as to accept:
    the Cancel button, the backdrop, and Escape."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert "ask-no" in html
    assert "e.target===ovl" in html
    assert "e.key==='Escape'" in html


def test_the_fleet_has_no_button_that_only_points_elsewhere(db):
    """The owner asked why the fleet had a button that only led to a server's
    own scan button. Its whole effect was a message
    telling you to go and use the real one."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    html = rl.render(db, now=NOW)
    assert "Scan a server" not in html
    assert "Open a server to scan it" not in html
    # the one that really scans is on the host page and stays
    assert "Scan now" in html


def test_windows_is_offered_and_leads_to_the_agentless_route(db):
    """A Windows box is watched from outside, so the card is a real pick.

    It was greyed and tagged planned until 2026-08-27, which told anybody with
    a Windows estate that there was nothing here for them, while the whole
    agentless tier was there for them. Tier 1 installs nothing and does not
    know what a machine runs.
    """
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)

    card = html.split('id="add-windows"', 1)[1].split("</div>", 2)[1]
    assert "planned" not in card, "the platform card itself is a real pick"
    assert 'class="m-card pick" id="add-windows"' in html

    # Its own stage since 2026-08-30 (RECORD 4.140): the same outside-only
    # card an appliance gets, plus the planned Windows agent card the owner
    # asked for. The planned card is not a pick and carries the tag alone.
    handler = html.split("getElementById('add-windows').onclick", 1)[1][:200]
    assert "add-method-windows" in handler
    stage = html.split('id="add-method-windows"', 1)[1].split('id="add-addr-stage"')[0]
    assert 'id="add-addr-windows"' in stage
    assert 'Windows agent<span class="tag-planned">planned</span>' in stage
    assert 'aria-disabled="true"' in stage
    assert "pick" not in stage.split('aria-disabled')[1].split('</div>')[0]


def test_the_windows_card_is_cleared_like_every_other_platform(db):
    """reset() clears each platform card. A card added to the row and left out
    of reset stays selected after the window is reopened, which is the bug the
    other two cards already have a line each to prevent."""
    add_host(db, "box", [(NOW - timedelta(minutes=3), document())],
             last_report_at=(NOW - timedelta(minutes=3)).isoformat())
    html = rl.render(db, now=NOW)
    for card in ("add-linux", "add-windows", "add-other"):
        assert f"getElementById('{card}').classList.remove('sel')" in html
# ------------------------------------------------ the stored digest is a cache
#
# It feeds the change detection, so a wrong digest silently changes what the
# product reports happened. These are the tests that say it cannot.

def _cache_rows(db):
    con = sqlite3.connect(db)
    rows = con.execute("SELECT report_id, version, digest FROM report_digests"
                       " ORDER BY report_id").fetchall()
    con.close()
    return rows


def _two_documents(db, name="box"):
    """One host with two documents that differ, so the history has a change in
    it and the digest is what decides that."""
    first = document(listening=[SSHD])
    second = document(listening=[SSHD, dict(SSHD, port=443)])
    add_host(db, name, [(NOW - timedelta(minutes=2), second),
                        (NOW - timedelta(minutes=20), first)],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())


def test_a_page_off_a_warm_cache_is_the_page_off_a_cold_one(db):
    """The whole property. If these two ever differ, the cache has changed
    what the product says happened."""
    _two_documents(db)
    cold = rl.render(db, now=NOW)
    assert _cache_rows(db), "the first render filled the cache"
    warm = rl.render(db, now=NOW)
    assert warm == cold


def test_wiping_the_cache_changes_nothing(db):
    """It holds no fact of its own. Every row can be deleted and the next
    render rebuilds it from the documents, which is what makes it safe to
    throw away in an incident."""
    _two_documents(db)
    warm = rl.render(db, now=NOW)
    con = sqlite3.connect(db)
    con.execute("DELETE FROM report_digests")
    con.commit()
    con.close()
    assert _cache_rows(db) == []
    assert rl.render(db, now=NOW) == warm


def test_a_row_from_another_version_is_ignored_rather_than_served(db):
    """A cache handing back an old format is worse than no cache. The rows are
    left alone and simply not read, then replaced on the way out."""
    _two_documents(db)
    right = rl.render(db, now=NOW)
    con = sqlite3.connect(db)
    con.execute("UPDATE report_digests SET version = 'not-this-version',"
                " digest = '{\"listeners\": [], \"publications\": [],"
                " \"mtimes\": [], \"nft_counts\": [], \"unreadable\": []}'")
    con.commit()
    con.close()
    assert rl.render(db, now=NOW) == right


def test_a_digest_that_will_not_decode_is_recomputed(db):
    """Truncated, not JSON, or JSON of the wrong shape. Each is a row that
    cannot be trusted and each has to fall back to the document rather than
    reaching the page."""
    for broken in ("", "not json", "[]", '{"listeners": "not a list"}', "{"):
        con = sqlite3.connect(db)
        con.execute("DELETE FROM hosts")
        con.execute("DELETE FROM reports")
        con.execute("DELETE FROM report_digests")
        con.commit()
        con.close()
        _two_documents(db)
        right = rl.render(db, now=NOW)
        con = sqlite3.connect(db)
        con.execute("UPDATE report_digests SET digest = ?", (broken,))
        con.commit()
        con.close()
        assert rl.render(db, now=NOW) == right, f"broke on {broken!r}"


def test_a_database_with_no_cache_table_still_renders(db):
    """Every database written before this table existed. It renders, at the
    old speed, and says nothing about it."""
    _two_documents(db)
    right = rl.render(db, now=NOW)
    con = sqlite3.connect(db)
    con.execute("DROP TABLE report_digests")
    con.commit()
    con.close()
    assert rl.render(db, now=NOW) == right


def test_a_cached_digest_belongs_to_its_own_report(db):
    """Two reports, two digests, and the wrong one on the wrong report would
    make the change feed describe a change that never happened. Keyed by
    report id, so this is really asking whether the key is right."""
    _two_documents(db)
    rl.render(db, now=NOW)
    rows = _cache_rows(db)
    assert len(rows) == 2
    assert len({r[0] for r in rows}) == 2, "one row per report"
    assert rows[0][2] != rows[1][2], "two different documents, two digests"


def test_the_version_is_stable_across_calls(db):
    """It is what decides whether a stored row is readable. If it moved on
    every call, nothing would ever be served from the cache and the whole
    thing would be a write-only table."""
    assert rl.DIGEST_VERSION == rl.digest_version()
    assert rl.DIGEST_VERSION is None or rl.DIGEST_VERSION


def test_a_stored_digest_decodes_to_what_digest_computes(db):
    """The round trip at its narrowest: what goes in the table is what the
    walker produced, not a lossy version of it."""
    doc = document(listening=[SSHD])
    entry = rl.digest(doc)
    text = rl.encode_digest(entry)
    assert text is not None
    assert rl.decode_digest(text) == entry


# --------------------------------------------- how a server is watched
#
# The owner asked for the way a server is monitored to be visible per server. The
# words and what each is measured from are `monitoring_mode` in render_live.py,
# and the header there says why none of them names an install.

def mode_marks(html):
    """Every mode mark on a page, in the order they were written."""
    return re.findall(r'<span class="tag-mode">([^<]*)</span>', html)


def refused():
    """A section or a source the agent was refused, in the shape it arrives
    in: hostdoc.go's StatusPermissionDenied with CausePermission beside it."""
    return {"status": "permission_denied", "cause": "permission"}


def reporting(db, name, doc, minutes=2):
    add_host(db, name, [(NOW - timedelta(minutes=minutes), doc)],
             last_report_at=(NOW - timedelta(minutes=minutes)).isoformat())


def test_a_document_with_nothing_refused_says_full_read(db):
    reporting(db, "box", document(listening=[SSHD]))
    html = rl.render(db, now=NOW)
    # The host page's agent fact and the fleet row's Agent word must not
    # disagree.
    # one agent since 2026-09-12: the word is "agent" whatever was read,
    # the read mode itself stays with monitoring_mode for the Rules tab
    assert rl.monitoring_mode(rl_host(db, "box"), (NOW, doc_of(db, "box"))) == "full read"
    assert header_agent(html) == ["agent"]


def test_a_refused_section_says_partial_read(db):
    doc = document(listening=[SSHD])
    doc["firewalld"] = refused()
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert rl.monitoring_mode(rl_host(db, "box"), (NOW, doc)) == "partial read"
    assert header_agent(html) == ["agent"]


def test_a_refused_source_under_a_collected_section_says_partial_read(db):
    """docs/RECORD.md 4.72, and this is the case the whole function exists for.
    `aggregateSources` reports a section as collected when any one source
    collected, so on a non-root Ubuntu host ufw says collected while both of
    its rules files were refused. Reading the section status alone calls that
    host a full read, which is the green headline that was wrong twice."""
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "rules": [], "rules6": [],
                  "sources": {"conf": {"status": "collected"},
                              "rules": refused(), "rules6": refused()}}
    reporting(db, "box", doc)
    assert rl.refused_reads(doc) == (("ufw", ("rules", "rules6")),)
    assert rl.monitoring_mode(rl_host(db, "box"), (NOW, doc)) == "partial read"
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_a_host_with_no_document_says_agent_and_claims_nothing_more(db):
    """There is an agent, and nothing has arrived to say how its reads went.
    Saying full read here would be a claim about a document nobody has."""
    add_host(db, "newbox", [])
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_a_document_that_will_not_read_says_agent(db):
    add_host(db, "broken", [])
    con = sqlite3.connect(db)
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix,"
                " schema_version, document) VALUES (1, ?, 0, 1, ?)",
                ((NOW - timedelta(minutes=2)).isoformat(), "not json at all"))
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_a_section_this_page_could_not_read_is_not_a_full_read(db):
    """The shape check replaces such a section with a marker, so no refusal is
    found in it. That must not read as nothing having been refused: what is
    true is that we do not know, and `agent` is the word for that."""
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "rules": [{"not": "a line of text"}]}
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_a_section_that_says_read_error_is_not_a_full_read(db):
    doc = document(listening=[SSHD])
    doc["nftables"] = {"status": "read_error", "cause": "parse_failed"}
    assert rl.unfinished_reads(doc) == ("nftables",)
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_a_document_that_collected_nothing_is_not_a_full_read(db):
    """An envelope with no sections in it. Nothing was refused, because
    nothing was read, and a fleet where that outranks a working host would be
    the emptiest document reading as the best answer."""
    doc = {"schema_version": 1, "hostname": "Almabox",
           "collected_at_unix": int(NOW.timestamp())}
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_a_section_an_older_agent_does_not_send_is_not_held_against_it(db):
    """The fleet runs more than one agent version and `document()` sends no
    socket_units, which is the older agent. Absent is that agent not producing
    the section, not this run failing to read it."""
    doc = document(listening=[SSHD])
    assert "socket_units" not in doc
    reporting(db, "box", doc)
    assert rl.monitoring_mode(rl_host(db, "box"), (NOW, doc)) == "full read"
    html = rl.render(db, now=NOW)
    assert header_agent(html) == ["agent"]


def test_the_mode_never_takes_a_status_tone(db):
    """docs/DESIGN.md section 3: a second fact beside a state, never a state.
    A tone here would paint a limited agent as a problem, which is a verdict
    on somebody's install and not a measurement."""
    doc = document(listening=[SSHD])
    doc["firewalld"] = refused()
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    for tone in ("ok", "warn", "fail", "off"):
        assert f'<span class="tag-mode {tone}">' not in html
        assert f'<span class="st {tone}">partial read</span>' not in html


def test_every_servers_page_says_how_it_is_watched(db):
    """The whole of what the owner asked for: not one server without the answer.
    On its own page since 2026-10-02, when the Fleet's Agent column left."""
    reporting(db, "full", document(listening=[SSHD]))
    part = document(listening=[SSHD])
    part["firewalld"] = refused()
    reporting(db, "part", part)
    add_host(db, "pending", [])
    add_address_host_row(db, "outside")
    html = rl.render(db, now=NOW)
    # two kinds and nothing else, whatever each agent could read
    assert sorted(header_agent(html)) == ["agent", "agent", "agent", "none"]


def test_the_mode_is_read_before_an_unreadable_document_rewrites_the_state(db):
    """A host whose newest document will not read takes the fail tone and the
    state word `not readable`. Its mode is a different fact and must not be
    taken from that word."""
    add_host(db, "broken", [])
    con = sqlite3.connect(db)
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix,"
                " schema_version, document) VALUES (1, ?, 0, 1, ?)",
                ((NOW - timedelta(minutes=2)).isoformat(), "[]"))
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert "not readable" in html
    assert header_agent(html) == ["agent"]


def test_a_not_readable_section_is_not_counted_as_a_refusal(db):
    """`not_readable` is ours and `permission_denied` is the agent's. Reading
    one as the other would say the host refused us something it never did."""
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "rules": [{"not": "a line"}]}
    view = rl.read_view(doc)
    assert rl.not_readable_sections(view) == ("ufw",)
    assert rl.refused_reads(view) == ()


# ------------------------------------- a refused layer on the Rules tab

def test_a_refused_layer_is_named_on_the_rules_tab(v2_tabs, db):
    """A layer missing from that tab reads as a layer the host does not have,
    which is already why the unreadable panel exists. A refused one was
    missing in exactly the same way."""
    doc = document(listening=[SSHD])
    doc["firewalld"] = refused()
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert "Layers the agent could not read" in html
    assert '<span class="st warn">permission denied</span>' in html


def test_a_refused_source_names_the_layer_and_the_sources(v2_tabs, db):
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "rules": [], "rules6": [],
                  "sources": {"conf": {"status": "collected"},
                              "rules": refused(), "rules6": refused()}}
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert "Layers the agent could not read" in html
    assert "rules, rules6" in html


def test_a_refused_ufw_rules_file_is_not_printed_as_a_firewall_with_no_rules(v2_tabs, db):
    """docs/RECORD.md 4.72: root reads three rules on each family and non-root
    reads none, while the section still says collected because `ufw.conf` is
    world readable. An empty list drawn from that says ufw has no rules, which
    is a measurement nobody took.

    So the block says not readable instead, and the panel at the bottom names
    the two files. The source names are the agent's own, from
    `hostdoc.UfwSources`.
    """
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "rules": [], "rules6": [],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": refused(), "user6.rules": refused()}}
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    rules = tab_body(host_section(html, "box"), "box", "rules")
    assert '<span class="st fail">not readable</span>' in rules
    assert '<span class="st ok">active</span>' not in rules
    assert rules.count('for="rr-box-ufw-') == 0
    assert "Layers the agent could not read" in html
    assert "user.rules, user6.rules" in html


def test_a_ufw_rules_file_that_was_read_lists_what_was_in_it(v2_tabs, db):
    """The other half. A file that was read draws its rules and the block says
    ufw is active, so the two cases cannot be confused for each other."""
    doc = document(listening=[SSHD])
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "rules": ["allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in"],
                  "rules6": [],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    reporting(db, "box", doc)
    rules = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "rules")
    assert rules.count('for="rr-box-ufw-') == 1
    assert "not readable" not in rules


def test_a_refused_layer_that_is_not_a_firewall_layer_stays_off_the_rules_tab(v2_tabs, db):
    """The panel is the Rules tab's, so it names filtering layers. Sockets are
    named on their own screens and the Evidence tab names every section."""
    doc = document(listening=[SSHD])
    doc["containers"] = refused()
    reporting(db, "box", doc)
    html = rl.render(db, now=NOW)
    assert "Layers the agent could not read" not in html
    assert header_agent(html) == ["agent"]


def test_a_refusal_the_mark_counts_is_one_the_evidence_tab_names(db):
    """The mark is a summary and the Evidence tab is where a reader checks it.
    The two walk the same list, so a reader following the mark finds the
    section it was counting."""
    doc = document(listening=[SSHD])
    doc["firewalld"] = refused()
    doc["rule_files"] = refused()
    reporting(db, "box", doc)
    assert [key for key, _sources in rl.refused_reads(doc)] == ["firewalld", "rule_files"]
    html = rl.render(db, now=NOW)
    evidence = tab_body(host_section(html, "box"), "box", "evidence")
    for label in ("firewalld", "rule file mtimes"):
        assert theme.status("warn", f"{label} · refused") in evidence
    assert evidence.count("· refused</span>") == 2


# ------------------------------------------- the State cell is the port answer
#
# `docs/RECORD.md` 4.115. Until 2026-08-28 an agent host's State cell came from
# `freshness()` and nothing else, so a server with a port in `conflict`
# rendered green reading `REPORTING` and the finding was a coloured chip two
# columns to the right. These pin the rule that replaced it: the worse of the
# two axes takes the cell, the other sits beside it, and neither is ever lost.

def _sock_on(port):
    return {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
            "port": port, "process_name": f"svc{port}", "pid": port}


def _row_state(html, name):
    row = [r for r in re.findall(r'<a class="row" .*?</a>', html, re.S)
           if f'data-host="{name}"' in r][0]
    return re.findall(r'<span class="st [a-z]+">([^<]+)</span>', row)


def _header_state(html, name):
    """The state words in a host page's own heading, and nothing below it."""
    head = html.split(f'id="host-{name}"', 1)[1].split("</h1>", 1)[0]
    return re.findall(r'<span class="st [a-z]+">([^<]+)</span>', head)


def test_a_reporting_server_with_a_conflict_says_conflict(db):
    """**The defect this change exists to fix.** The agent is fine, so the old
    cell said `reporting` in the ok tone, and the one thing wrong with this
    server was a chip in another column. The agent being fine is not news."""
    reporting(db, "box", document(listening=[SSHD]))
    declare_intent(db, "box", "tcp", 22, "v4", "closed")
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)

    assert _row_state(html, "box") == ["conflict"]
    # `reporting` is the ordinary case, so it is not drawn at all rather than
    # drawn as a second tag on every healthy row on the page.
    assert "reporting" not in _row_state(html, "box")
    # and the header a reader lands on says the same thing as the row
    assert _header_state(html, "box")[0] == "conflict"


def test_a_silent_server_with_a_conflict_leads_with_the_conflict(db):
    """Two facts, both true. The conflict is worse on the one ranking, so it
    takes the row's one tag (docs/screens/fleet/SPEC.md section 5, answer
    11: the second tag is dropped on the Fleet), and the host page header
    still shows both."""
    reporting(db, "box", document(listening=[SSHD]), minutes=200)
    declare_intent(db, "box", "tcp", 22, "v4", "closed")
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)

    assert _row_state(html, "box") == ["conflict"]
    # the header says exactly the word the fleet row shows (SPEC.md section 1)
    assert _header_state(html, "box") == ["conflict"]


def test_a_silent_server_whose_ports_are_calm_leads_with_the_silence(db):
    """The other way round, and it is why one ranking decides rather than a
    rule saying the port always wins. Nothing is reachable that should not be,
    and the thing worth knowing is that these ports were last measured three
    hours ago."""
    reporting(db, "box", document(listening=[SSHD]), minutes=200)
    probe_result(db, "box", 22, "v4", "no_response")
    html = rl.render(db, now=NOW)

    words = _row_state(html, "box")
    assert len(words) == 1 and words[0].startswith("silent")
    # and the Reachable cell reads from the last document: nothing open of one
    assert '<div class="frc"><b>0</b> of 1 port</div>' in _fleet_row(html, "box")


def test_a_shut_undeclared_fleet_reads_as_watched_rather_than_reporting(db):
    """What a well run fleet looks like. The column stops answering "is the
    agent talking to us", which is a question about us. The engine's word
    for the port is `not reachable`, and the Fleet has one word for a fine
    server, `watched` (SPEC.md section 5), with the Reachable cell saying
    what was measured."""
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "no_response")
    html = rl.render(db, now=NOW)

    assert _row_state(html, "box") == ["watched"]
    assert 'data-state="watched"' in html
    assert "not reachable" not in _fleet_row(html, "box")
    assert '<div class="frc"><b>0</b> of 1 port</div>' in _fleet_row(html, "box")
    # and the host page keeps the engine's own word for the port
    assert "not reachable" in host_section(html, "box")


def test_a_host_nobody_probed_says_so_rather_than_reporting(db):
    """**Found by looking at the render, not by a test.** A fleet screenshot
    on 2026-08-28 had a row reading REPORTING in green directly under two red
    ones, and it was the row nothing was known about.

    With no measurement there is no state (`docs/PRODUCT.md` 8a) and the cell
    must still say something, because a blank cell reads as one that failed to
    render. What it may not say is a green word: this column answers what is
    reachable, and the honest answer here is that nobody has looked. It is the
    word an address host in the same position already used.
    """
    reporting(db, "box", document(listening=[SSHD]))
    html = rl.render(db, now=NOW)
    assert _row_state(html, "box") == ["not watched"]
    assert "reporting" not in html.split('id="fleet"', 1)[1].split(
        '<div class="wrap view"', 1)[0]


def test_the_ok_tone_is_never_spent_on_a_server_nobody_measured(db):
    """The rule behind the test above, said as the rule. `ok` is the one green
    in the system and `docs/DESIGN.md` section 3 spends it on `intended`,
    which means measured and matching what somebody declared. Nothing else may
    take it."""
    assert rl.NOT_PROBED[0] == "off"
    assert rl.fleet_state(None, ("ok", "reporting")) == (rl.NOT_PROBED, None)
    assert rl.fleet_state(None, ("ok", "watched")) == (rl.NOT_PROBED, None)
    # A liveness word that is NOT ordinary is still the honest answer and is
    # kept, and since 2026-10-09 it is the same word a server nobody probed
    # carries: nothing is known of either yet (docs/record 4.447).
    never = ("off", "not watched")
    assert rl.fleet_state(None, never) == (never, None)
    assert rl.NOT_PROBED == never


def test_a_document_that_would_not_read_shows_no_port_answer(db):
    """An older probe can outlive the document that explained it. The row must
    not present a finding from one document as the state of a host whose
    newest document could not be read: `not readable` is what this row can
    honestly say about itself and it says only that."""
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    con = sqlite3.connect(db)
    con.execute("UPDATE reports SET document = ?", ("[]",))
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)

    assert _row_state(html, "box") == ["not readable"]
    assert _header_state(html, "box")[0] == "not readable"


def test_the_worse_of_the_two_takes_the_cell_by_one_ranking(db):
    """`fleet_state` reads `build.FLEET_BANDS` and never a second ordering
    written beside it. A rule saying "the port always wins" would bury a host
    that stopped reporting under a calm port state, and a rule saying "the
    agent always wins" is the defect this replaced."""
    conflict = (rl.tpl.PORT_TONE["conflict"], "conflict")
    calm = (rl.tpl.PORT_TONE["not reachable"], "not reachable")
    silent = ("warn", "silent 3h 0m")

    assert rl.fleet_state(conflict, silent) == (conflict, silent)
    assert rl.fleet_state(calm, silent) == (silent, calm)
    # An ordinary liveness word is dropped rather than drawn.
    assert rl.fleet_state(calm, ("ok", "reporting")) == (calm, None)
    assert rl.fleet_state(calm, ("ok", "watched")) == (calm, None)
    # With no port state the liveness word is the cell, and repeating it
    # beside itself would be one row saying one fact twice.
    assert rl.fleet_state(None, silent) == (silent, None)


def test_the_worst_port_is_the_one_the_row_names(db):
    """One server, several ports, one cell. `STATE_SEVERITY` decides, which is
    the order the port strip and the port row already use, so a reader meets
    one ranking on the page rather than three."""
    reporting(db, "box", document(listening=[SSHD, _sock_on(443), _sock_on(9100)]))
    declare_intent(db, "box", "tcp", 443, "v4", "closed")
    probe_result(db, "box", 22, "v4", "no_response")
    probe_result(db, "box", 443, "v4", "connect_succeeded")
    probe_result(db, "box", 9100, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)

    # not reachable, conflict and unreviewed are all present on this host.
    assert _row_state(html, "box") == ["conflict"]


def test_a_finding_with_no_state_is_not_read_as_a_calm_one(db):
    """`docs/PRODUCT.md` 8a: a port whose evidence supports none of the six
    has no state. Counting that as calm would let a server with one such port
    and nothing else claim an answer it does not have."""
    assert rl.worst_port_state(()) is None


# ------------------------------------------------------- the rule that decided
#
# `docs/RECORD.md` 4.117. The join engine has filled `Cause.quotes` since it
# landed and no screen ever drew them, so a row named a layer and the rule
# behind it was readable only through `python -m app.join_cli findings` on the
# box. `docs/PRODUCT.md` section 3's promise is "name the layer and quote the
# rule", and only the first half was on any screen.

def _overview_of(html, name):
    """The host page. The Overview is the first tab body on it, and the test
    only needs to know the rows are somewhere on this host's page rather than
    on another host's."""
    return html.split(f'id="host-{name}"', 1)[1].split('<div class="wrap view"', 1)[0]


def _nft_rule(text):
    return {"text": text, "rendered": "full", "comment": ""}


def stale_rule_document(ports=(9200,)):
    """A ufw-shaped permit for a port nothing listens on, which is what
    `stale rule` is. Shaped after the firewalld permits the engine finds on
    almabox, and ufw-shaped because the base chain holds nothing but jumps
    on the commonest firewall there is (`docs/RECORD.md` 4.42)."""
    doc = document(listening=[SSHD])
    doc["nftables"] = {"status": "collected", "tables": [{
        "family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop",
             "rules": [_nft_rule("counter jump ufw-before-input")]},
            {"name": "ufw-before-input",
             "rules": [_nft_rule("counter jump ufw-user-input")]},
            {"name": "ufw-user-input",
             "rules": [_nft_rule(f"ip protocol tcp tcp dport {p} counter accept")
                       for p in ports]},
        ]}]}
    return doc


def test_the_row_quotes_the_rule_that_decided(db):
    """The half of the promise no screen kept. The row already said which
    layer, and this is the rule it read, verbatim and with where it came
    from."""
    reporting(db, "box", stale_rule_document())
    html = rl.render(db, now=NOW)
    overview = _overview_of(html, "box")
    # verbatim, mono, in the opened row's firewall line
    assert '<b class="mono">ip protocol tcp tcp dport 9200 counter accept</b>' in overview


def test_a_stale_rule_gets_a_row_at_all(db):
    """**The Overview could not show a `stale rule` before this**
    (`docs/RECORD.md` 4.117). Its table was built from the document's listening
    sockets, and a permit for a port nothing listens on has a rule and no
    socket, so the one state most likely to carry a rule quote had no row for
    the quote to sit on."""
    reporting(db, "box", stale_rule_document())
    overview = _overview_of(rl.render(db, now=NOW), "box")
    assert 'data-port="9200/tcp"' in overview
    assert "stale rule" in overview
    # it says what is holding the port, which is nothing, and offers later
    # with the one other way out
    row = overview.split('data-port="9200/tcp"')[1].split("</label>")[0]
    assert '<span class="prs note">nothing listening</span>' in row
    assert '<span class="prw">your rule</span>' in row
    assert f'<span class="or">{rl.tpl.REMOVE_THE_RULE}</span>' in row
    assert row.count('data-answer=') == 1 and 'data-answer="later"' in row


def test_a_port_with_a_socket_and_no_finding_keeps_its_row(db):
    """The floor, and why the findings add to the document rather than
    replacing it. A port the engine could not digest must not vanish from the
    table because of that."""
    reporting(db, "box", document(listening=[SSHD]))
    overview = _overview_of(rl.render(db, now=NOW), "box")
    assert 'data-port="22/tcp"' in overview


def test_a_row_with_nothing_to_quote_prints_no_empty_box(db):
    """The common row. The service answered, so the layer that decided is the
    service and the evidence is the bind line the row already carries. An
    empty quote block would put a gap under every healthy port."""
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert '<div class="pq">' not in _overview_of(html, "box")




def test_a_row_says_how_many_rules_it_did_not_quote(db):
    """A row that quietly stops quoting says one rule decided when three did.
    Capped rather than cut, and the cap says so."""
    reporting(db, "box", stale_rule_document())
    overview = _overview_of(rl.render(db, now=NOW), "box")
    # Three permits on 9200, 9300 and 9400, but each is its own port, so each
    # row quotes its own one rule. The cap is asserted on the function, where
    # a row with several rules on one port can be built directly.
    cell = {"states": {"stale rule": _cause([("a", "s"), ("b", "s"),
                                             ("c", "s"), ("d", "s")])}}
    quotes, more = rl.port_row_quotes(cell)
    assert len(quotes) == rl.PORT_QUOTE_CAP
    assert more == 4 - rl.PORT_QUOTE_CAP
    assert "9200" in overview


class _cause:
    """A stand-in for join.Cause carrying only what this module reads."""
    def __init__(self, pairs, layer="host firewall"):
        self.layer = layer
        self.quotes = tuple(
            type("Q", (), {"text": t, "source": s, "layer": layer})()
            for t, s in pairs)


def test_the_layer_words_match_the_engine():
    """`LAYER_SERVICE` and `LAYER_NOT_DETERMINED` are spelled in the renderer
    and mean nothing unless they are the engine's own words. Pinned here so a
    rename in `join.py` fails rather than leaving this module quietly quoting
    the listening socket twice, or printing "the not determined decided"."""
    join = jb.load()
    assert rl.LAYER_SERVICE == join.LAYER_SERVICE
    assert rl.LAYER_NOT_DETERMINED == join.LAYER_NOT_DETERMINED


def test_a_loopback_only_port_stays_off_the_network_panel(db):
    """The bug the suite caught while this change was being written. A
    resolver stub on 127.0.0.53 has a finding, so asking "is this port in
    entries" put it back on the panel that exists to hold the ports bound to a
    network address. The question is whether the DOCUMENT says anything about
    the port, not whether the Overview already listed it."""
    doc = document(listening=[SSHD, {"protocol": "tcp", "family": "v4",
                                     "bind_address": "127.0.0.53", "port": 53,
                                     "process_name": "systemd-resolve", "pid": 3}])
    reporting(db, "box", doc)
    probe_result(db, "box", 53, "v4", "no_response")
    overview = _overview_of(rl.render(db, now=NOW), "box")
    assert 'data-port="22/tcp"' in overview
    # the stub has its row, measured silent and bound to loopback
    row = overview.split('data-port="53/tcp"')[1].split("</label>")[0]
    assert 'data-state=' not in row
    assert theme.status("off", "not reachable") in row
    assert '<span class="prw">loopback</span>' in row
    assert ("tcp", 53) in rl.document_ports(doc)


# ------------------------------- what the finding sweep knows, on the screen
#
# `docs/RECORD.md` 4.119. `finding_changes` has recorded every reachability
# transition since finding alerts landed, and `alert_silences` has recorded
# which ports will never alert. Both drive the mail. Neither had ever been
# read by a renderer.

def transition(db, host_name, protocol, port, family, frm, to, outcome,
               seen_at=None, description="a change"):
    """One row the way `finding_alerts._open_change` and `_settle` leave it."""
    seen_at = (seen_at or NOW).isoformat()
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS finding_changes (
        id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
        protocol TEXT NOT NULL, port INTEGER NOT NULL, family TEXT NOT NULL,
        from_state TEXT NOT NULL, to_state TEXT NOT NULL, outside TEXT NOT NULL,
        vantage TEXT, measured_at TEXT, description TEXT NOT NULL,
        outcome TEXT NOT NULL, alert_id INTEGER, seen_at TEXT NOT NULL,
        settled_at TEXT);
    """)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?",
                          (host_name,)).fetchone()[0]
    con.execute(
        "INSERT INTO finding_changes (host_id, protocol, port, family,"
        " from_state, to_state, outside, vantage, measured_at, description,"
        " outcome, seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (host_id, protocol, port, family, frm, to, "connect_succeeded",
         "probe1", seen_at, description, outcome, seen_at))
    con.commit()
    con.close()


def silence_port(db, host_name, protocol, port, family):
    """One live per-port silence, the way `app.silence_cli` writes one."""
    con = sqlite3.connect(db)
    con.executescript("""
    CREATE TABLE IF NOT EXISTS alert_silences (
        id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
        kind TEXT NOT NULL, protocol TEXT, port INTEGER, family TEXT,
        until TEXT, created_at TEXT NOT NULL, cleared_at TEXT);
    """)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?",
                          (host_name,)).fetchone()[0]
    con.execute(
        "INSERT INTO alert_silences (host_id, kind, protocol, port, family,"
        " created_at) VALUES (?, 'silence', ?, ?, ?, ?)",
        (host_id, protocol, port, family, NOW.isoformat()))
    con.commit()
    con.close()


def test_a_reachability_transition_reaches_the_changes_tab(db):
    """**The one history a customer wants and the only one that was missing.**
    The tab showed differences between one stored document and the next, so
    "the rule file's mtime moved" was on it and "tcp/5432 became reachable
    from the internet" was in a table nothing read."""
    reporting(db, "box", document(listening=[SSHD]))
    transition(db, "box", "tcp", 5432, "v4", "not reachable", "unreviewed",
               "raised", seen_at=NOW - timedelta(hours=2))
    changes = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "changes")
    assert '<span class="st nt">reachable</span>' in changes
    assert '<span class="cpn">5432<small>TCP/<i class="v4">v4</i></small></span>' in changes
    assert "connect succeeded from probe1" in changes
    # what was done about it is not a line here (docs/screens/host-changes/SPEC.md)
    assert "an alert was raised" not in changes


def test_a_silenced_port_says_so_on_its_row(db):
    """**A silenced port never alerts and looked exactly like one that
    would.** `load_mutes` asked about whole-server mutes and nothing ever
    asked about the per-port kind, which `app.silence_cli` writes."""
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    before = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "overview")
    assert rl.tpl.SILENCED_WORD not in before

    silence_port(db, "box", "tcp", 22, "v4")
    after = tab_body(host_section(rl.render(db, now=NOW), "box"), "box", "overview")
    assert rl.tpl.SILENCED_WORD in after


def test_the_silence_mark_is_neutral_and_never_a_state(db):
    """Somebody asking not to be told is not a verdict about the port
    (docs/DESIGN.md section 3, the rate flag's rule)."""
    assert rl.tpl.silenced_flag(True) == (
        '<span class="tag-rate" data-mark="silenced" title="silenced">'
        f'{rl.tpl.SILENCED_WORD}</span>')
    assert rl.tpl.silenced_flag(False) == ""
    assert rl.tpl.SILENCED_WORD not in rl.tpl.CHIP_CLASS


# ---------------------------------------- the screens stop explaining themselves
#
# `docs/RECORD.md` 4.120. The rule for customer screens lists what a screen may carry: labels,
# values, names, numbers, statuses, findings, error messages, refusals, and a
# line when a section is empty or unreadable. Three things on these screens
# were none of those, and 5a exists because sessions put them back for weeks.

# The words a screen may never use about our own machinery. Not a complete
# list of English, a list of the concepts that had actually leaked: the
# sweep's window, the enrolment lifecycle, and the shape of the alert policy.
# "35 minutes" left this list on 2026-09-05: the Settings tab's Alerts
# category shows the quiet delay under its row, on the spec's word
# (docs/screens/host-settings/SPEC.md), as a value and not a sentence.
MACHINERY = ("enrolled host", "paused or revoked",
             "filtered into a folder", "is not a sixth word",
             "until a provider token is held")


def test_no_screen_names_our_machinery(db):
    """Read against both feeds, because the sample shell is a screen too and
    two of the three lines this catches were only ever on it."""
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    for html in (rl.render(db, now=NOW), rl.tpl.build_sample()):
        for phrase in MACHINERY:
            assert phrase not in html, f"a screen says {phrase!r}"


def test_the_empty_alerts_line_is_the_empty_state_and_nothing_more(db):
    """5a allows "a line when a section is empty". It does not allow that line
    to go on and name four of our own concepts."""
    reporting(db, "box", document(listening=[SSHD]))
    seen_an_alert(db, "box")
    html = rl.render(db, now=NOW)
    assert rl.tpl.nothing_open_html() in html


def test_the_evidence_matrix_carries_no_legend(db):
    """`docs/DESIGN.md` section 3 requires every word in this vocabulary to be
    readable by somebody who has never been told what it means, and says a
    word that needs the manual is the wrong word. A legend under the matrix
    was that manual, on a customer screen."""
    assert not hasattr(rl.tpl, "evidence_key_html")
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    html = rl.render(db, now=NOW)
    assert "A dashed token is a view that cannot know" not in html
    # and the words the legend was spelling out are still on the row, because
    # they are what a reader actually reads
    assert "not tested" in html


# --------------------------- a count and the table under it add up
#
# `docs/RECORD.md` 4.121.

def test_the_ports_fact_and_the_overview_rows_add_up(db):
    """The header's ports fact counts the joined set and the table lists
    every port in it, loopback ones included, so the two agree by
    construction."""
    reporting(db, "box", document(listening=[SSHD, LOOP]))
    page = _overview_of(rl.render(db, now=NOW), "box")
    assert '<div class="k">ports</div><div class="v"><span class="num">2</span></div>' in page
    assert page.count('<label class="pr" ') == 2
    assert "loopback port not listed" not in page


def test_a_host_with_nothing_on_loopback_says_no_line_at_all(db):
    """Zero draws nothing. There is no number to reconcile, so the sentence
    that was left taught how the two tabs divide the ports up, which is what
    the rule for customer screens keeps off a customer surface (the owner, 2026-08-29). And it
    is not printed as a number either: "0 more" is a count nobody needs."""
    reporting(db, "box", document(listening=[SSHD]))
    page = _overview_of(rl.render(db, now=NOW), "box")
    assert "Loopback included" not in page
    assert "loopback" not in page
    # and no empty panel line is left behind where the sentence used to sit
    assert '<div class="agree"></div>' not in page


def test_the_loopback_line_counts_ports_and_not_sockets(db):
    """Two sockets on one loopback port is one port not listed, because the
    table this line is about is a table of ports."""
    second = {"protocol": "udp", "family": "v6", "bind_address": "::1",
              "port": 323, "process_name": "chronyd", "pid": 2}
    reporting(db, "box", document(listening=[SSHD, LOOP, second]))
    page = _overview_of(rl.render(db, now=NOW), "box")
    # two sockets on one loopback port are one row, and the fact says two ports
    assert page.count('data-port="323/udp"') == 1
    assert '<div class="k">ports</div><div class="v"><span class="num">2</span></div>' in page


def test_a_fleet_row_holds_no_sentence_and_the_host_page_holds_the_facts(db):
    """Four kinds of fact used to share this row as grey lines: how long the
    host has been silent, how much of its document would not read, that an
    alert is open and whether it was mailed. Since the Fleet of 2026-09-03 the
    row holds a state tag, values and chips, and no sentence at all
    (docs/screens/fleet/SPEC.md section 5). The silence is the tag, the
    unreadable section is named on the Evidence tab, the alert is a marker
    beside the tag until item 12 is decided, and where it went is said on the
    Alerts screen."""
    doc = document(listening=[SSHD])
    # A section that arrived in a shape the page does not read, which is what
    # `not_readable_sections` looks for once `read_view` has marked it.
    doc["firewalld"] = ["not an object"]
    add_host(db, "quiet", [(NOW - timedelta(hours=3), doc)],
             last_report_at=(NOW - timedelta(hours=3)).isoformat())
    add_alert(db, "quiet", "no report for 180 minutes", NOW - timedelta(hours=2))
    html = rl.render(db, now=NOW)
    row = _fleet_row(html, "quiet")
    assert "prob-note" not in row and "no document for" not in row
    assert "could not be read" not in row
    assert 'data-state="silent 3h 0m"' in row
    assert '<span class="tag-alert" title="alert open">alert open</span>' in row
    assert "could not be read" in host_section(html, "quiet")


# ------------------------------------------ green means measured and matching
#
# `docs/RECORD.md` 4.122. `docs/DESIGN.md` section 3 spends the ok tone on
# `intended`, which means measured and matching what somebody declared. The
# Services tab spent it on every row of a long list, so green came to mean "we
# read this successfully" and there was nothing left to say "this is correct".



def test_green_survives_where_it_is_earned(db):
    """The rule is about spending it, not about removing it. A port measured
    reachable that somebody declared open is exactly what `ok` is for."""
    reporting(db, "box", document(listening=[SSHD]))
    probe_result(db, "box", 22, "v4", "connect_succeeded")
    declare_intent(db, "box", "tcp", 22, "v4", "open")
    declare_intent(db, "box", "tcp", 22, "v6", "open")
    overview = _overview_of(rl.render(db, now=NOW), "box")
    assert '<span class="st ok">intended</span>' in overview


# ---------------------------------------- trying the agent without trusting it
#
# `docs/RECORD.md` 4.124. The agent has had `--mode=stdout` since it was
# written. Its own header calls it "the way to evaluate the agent without
# trusting anything", it is the default mode, and it reads no config and opens
# no connection. The product never offered it, so the least committing thing
# the add-server flow could do was install an agent and enrol it in one paste.

def test_the_linux_flow_offers_a_way_to_read_it_first(db):
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    assert 'id="add-try"' in html
    # "Try it, send nothing" until 2026-08-30, which the owner read cold and
    # could not parse (RECORD 4.140). What it does is unchanged: stdout mode,
    # nothing leaves the machine, and the command below the card is the proof.
    assert '<div class="m-card-t">Try it locally</div>' in html
    assert "--mode=stdout" in html


def test_the_try_command_enrols_nothing_and_starts_nothing(db):
    """The point of the card. It installs and reads, and there is nothing to
    revoke afterwards: the packaged unit delivers only when the host is
    enrolled, and the timer is not enabled here either."""
    cmd = rl.tpl.TRY_COMMAND
    assert "--mode=stdout" in cmd
    assert "enroll" not in cmd
    assert "--credential" not in cmd
    assert "systemctl enable" not in cmd


def test_the_try_card_mints_no_credential(db):
    """Every other agent card asks the server for a host and a credential.
    This one creates nothing, so it must not go near that endpoint: a card
    that quietly made a host would be the opposite of what it says."""
    add_host(db, "box", [])
    html = rl.render(db, now=NOW)
    handler = html.split("document.getElementById('add-try').onclick", 1)[1]
    # Up to the next card's code. The mark used to be the comment above it,
    # and no comment is sent to a browser since 2026-10-02.
    handler = handler.split("var addGo=document.getElementById('add-addr-go')", 1)[0]
    assert "/api/admin/hosts" not in handler
    assert "mint()" not in handler
    assert "addPick=null" in handler


def test_the_try_command_is_the_one_installer_and_not_a_second_one(db):
    """Naming a second download path would be a second thing to keep signed
    and a second thing to trust. It is the same installer the other two cards
    use, without the enrol and without the timer."""
    assert rl.tpl.TRY_COMMAND.startswith(
        "curl -fsSL https://get.whichports.com/install.sh | sudo sh")


# ------------------ the declared ports of a server that has an agent
#
# `docs/RECORD.md` 4.125. The row control files one declaration and shows what
# that one port was told. What it cannot do is show a server's declarations in
# total, or withdraw one for a port the document has stopped reporting, since
# a row only exists while the port does. That is this panel, and it was on the
# address host's Settings tab alone.

def _settings_of(html, name):
    section = html.split(f'id="host-{name}"', 1)[1]
    return section.split('<div class="wrap view"', 1)[0]


def test_an_agent_host_lists_the_ports_it_has_declared(db):
    reporting(db, "box", document(listening=[SSHD]))
    declare_intent(db, "box", "tcp", 22, "v4", "open")
    settings = _settings_of(rl.render(db, now=NOW), "box")
    assert "22/tcp" in settings
    assert 'class="btn js-port-rm" data-host="box"' in settings


def test_an_agent_host_can_declare_a_port_the_document_never_reported(db):
    """The gap the row control cannot close. A row exists while the port does,
    so a port whose listener went away has no row to press and its declaration
    no way back."""
    reporting(db, "box", document(listening=[SSHD]))
    settings = _settings_of(rl.render(db, now=NOW), "box")
    assert 'class="btn js-port-add" data-host="box"' in settings


def test_the_panel_is_the_same_one_a_host_without_an_agent_has(db):
    """One function, two kinds of host. Two panels would be two places to fix
    the next time the declare endpoint changes shape."""
    assert rl.settings_tab_body.__name__ == "settings_tab_body"
    for gone in ("address_port_rows", "address_probing_rows", "declared_port_rows",
                 "hsettings_panel"):
        assert not hasattr(rl, gone), gone


# ---------------------------------- the install command can be handed out again

def test_a_never_reported_server_offers_its_command_and_its_removal(db):
    """The add-server window shows the command once, so closing it too early
    left this page a dead end: no tabs, no settings, no way back to the
    command and no way to remove the row (the 2026-08-23 audit, control 3).
    The page keeps its one sentence and carries the two acts that exist for
    such a server."""
    add_host(db, "quietbox", [])
    html = rl.render(db, now=NOW)
    section = host_section(html, "quietbox")
    assert "No document received from this host yet." in section
    assert 'class="btn js-recred" data-host="quietbox"' in section
    assert 'id="rc-quietbox"' in section
    assert 'class="btn danger js-remove" data-host="quietbox"' in section
    # and the shared script carries the handler that fills the box
    script = html[html.rindex("<script>"):]
    assert "js-recred" in script and "/credential'" in script


def test_a_reporting_server_offers_no_credential_row(db):
    """Its agent holds the working credential and the route refuses a new
    one, so the Agent category has no Credential row (the owner, 2026-09-06)."""
    reporting(db, "talkingbox", document(listening=[SSHD]))
    section = host_section(rl.render(db, now=NOW), "talkingbox")
    assert "js-recred" not in section
    assert "Remove this server" in section