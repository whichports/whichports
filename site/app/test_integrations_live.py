"""The provider token per workspace, as the live page shows it.

Three properties the whole change rests on (record 4.178). The token is never
on a page: the renderer reads the hint the row stored beside it and never the
value, held by a source scan and by a rendered page. A workspace sees only its
own provider. And the row's acts and the window's Connect are live on the
live page and toasts on the sample shell.
"""
import pathlib
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

import build
import render_live as rl
import test_render_live as trl

NOW = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)
TOKEN = "hzread" + "k" * 58


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.executescript("INSERT OR IGNORE INTO workspaces (id, name, created_at)"
                      " VALUES (2, 'two', '2026-09-14T00:00:00+00:00');")
    con.commit()
    con.close()
    return str(path)


def connect(db, workspace_id, token=TOKEN, with_snapshot=True):
    hz = rl.joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hz.init(con)
    hz.add_token(con, token, workspace_id, now=NOW - timedelta(minutes=30))
    if with_snapshot:
        hz.store_snapshot(con, hz.Snapshot(
            fetched_at=(NOW - timedelta(minutes=12)).isoformat(),
            servers=({"id": 1, "name": f"server-of-{workspace_id}", "status": "running",
                      "public_net": {"ipv4": {"ip": "203.0.113.5"}, "ipv6": None,
                                     "firewalls": []}},),
            firewalls=()), workspace_id=workspace_id)
        hz.record_fetch(con, NOW - timedelta(minutes=12), workspace_id=workspace_id)
    con.close()


def integrations_view(html):
    view = html[html.index('<div class="wrap view" id="integrations">'):]
    ends = [i for i in (view.find('<div class="wrap view"', 10), view.find('<div class="ovl'))
            if i != -1]
    return view[:min(ends)] if ends else view


def test_the_token_is_never_on_the_page_and_the_renderer_never_reads_it(db):
    trl.add_host(db, "box", [])
    connect(db, 1)
    html = rl.render(db, now=NOW, workspace_id=1)
    assert TOKEN not in html
    assert TOKEN[:20] not in html
    view = integrations_view(html)
    assert '<b class="pvtok">…' + TOKEN[-4:] + "</b>" in view
    source = pathlib.Path(rl.__file__).read_text()
    assert "token_for" not in source, "the renderer names the one function that returns the token"


def test_a_workspace_sees_only_its_own_provider(db):
    trl.add_host(db, "box", [])
    connect(db, 1)
    one = integrations_view(rl.render(db, now=NOW, workspace_id=1))
    two = integrations_view(rl.render(db, now=NOW, workspace_id=2))
    assert "Hetzner Cloud" in one and "1<small>" in one
    assert build.NOTHING_CONNECTED in two
    assert "Hetzner Cloud" not in two and "server-of-1" not in two


def test_two_workspaces_each_see_their_own_and_not_the_others(db):
    trl.add_host(db, "box", [])
    connect(db, 1, token="one-" + "a" * 60)
    connect(db, 2, token="two-" + "b" * 60)
    one = integrations_view(rl.render(db, now=NOW, workspace_id=1))
    two = integrations_view(rl.render(db, now=NOW, workspace_id=2))
    assert "…aaaa" in one and "…bbbb" not in one
    assert "…bbbb" in two and "…aaaa" not in two


def test_a_token_that_has_not_been_read_yet_is_already_a_row(db):
    trl.add_host(db, "box", [])
    connect(db, 1, with_snapshot=False)
    view = integrations_view(rl.render(db, now=NOW, workspace_id=1))
    assert "Hetzner Cloud" in view and "…" + TOKEN[-4:] in view
    assert build.NOTHING_CONNECTED not in view


def test_a_refused_token_shows_the_status_the_provider_answered(db):
    hz = rl.joinbridge.module("hetzner")
    trl.add_host(db, "box", [])
    connect(db, 1, with_snapshot=False)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hz.record_fetch(con, NOW - timedelta(minutes=3),
                    hz.ProviderError(hz.ERROR_UNAUTHORIZED, status=401), workspace_id=1)
    con.close()
    view = integrations_view(rl.render(db, now=NOW, workspace_id=1))
    assert '<span class="st fail">refused</span>' in view
    assert '<span class="pvread warn">3 min ago, 401</span>' in view


def test_the_live_page_carries_the_acts_and_the_sample_carries_toasts(db):
    trl.add_host(db, "box", [])
    connect(db, 1)
    live = rl.render(db, now=NOW, workspace_id=1)
    view = integrations_view(live)
    for cls in ("js-prov-read", "js-prov-token", "js-prov-off"):
        assert cls in view, cls
    assert "tag-planned" not in view
    # The window's Connect is the one Add window's action since layout B
    # (docs/screens/alerts/SPEC-layout-b.md): the script writes the word on
    # it, and on the sample shell it is marked, so a click there is a toast.
    action = '<button class="btn pri" id="conn-go" hidden data-dest="Save" data-prov="Connect"'
    assert action + ">Save</button>" in live
    assert 'id="ptok-ovl"' in live and live.count('id="ptok-ovl"') == 1
    sample = build.build_sample()
    sample_view = integrations_view(sample)
    assert "js-prov-read" not in sample_view and "js-act" in sample_view
    assert action + ' data-sample="1">Save</button>' in sample
    assert "The provider would be connected here" in sample


def test_the_page_script_binds_every_act_it_draws():
    script = pathlib.Path(build.__file__).with_name("page.js").read_text()
    for needle in ("js-prov-read", "js-prov-token", "js-prov-off", "conn-go", "ptok-go",
                   "/api/admin/integrations/", "view:integrations"):
        assert needle in script, needle
    # the Add window's action reaches the provider's own request
    assert "if(kind==='prov')connectProvider(stage);" in script
    assert "var connectProvider=function(stage){" in script
    assert "'disconnect'" in script and "/token" in script and "'read'" in script


# ------------------------------------------- "in your fleet", by proved address
#
# The owner, 2026-09-20: the screen said 6 servers, 0 in your fleet, while one
# of them was in the fleet. The count matched by name alone. Its spec said
# "matched by address" all along. controlplane/tests/test_provider_match.py
# holds the rule, and these hold that the screens reach it.
#
# The proof is made through the registry's own calls, never by writing its
# tables: only `app/authz.py` may touch those, and a test in its suite fails
# any file that does.

import test_address_hosts_screen as tahs  # noqa: E402


def connect_listing(db, server_name, ipv4):
    """A connected provider whose one server has this name and this address."""
    hz = rl.joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hz.init(con)
    hz.add_token(con, TOKEN, 1, now=NOW - timedelta(minutes=30))
    hz.store_snapshot(con, hz.Snapshot(
        fetched_at=(NOW - timedelta(minutes=12)).isoformat(),
        servers=({"id": 1, "name": server_name, "status": "running",
                  "public_net": {"ipv4": {"ip": ipv4}, "ipv6": None,
                                 "firewalls": []}},),
        firewalls=()), workspace_id=1)
    hz.record_fetch(con, NOW - timedelta(minutes=12), workspace_id=1)
    con.close()


def host_id_of(db, name):
    """The host's id, with the registry's own tables made first, the way the
    ingest makes them, so `tahs.prove` has somewhere to record a proof."""
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        tahs.registry().init(con)
        return con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    finally:
        con.close()


# `tahs.prove` makes a proof with twenty days left on its own clock, so the
# page is rendered on that clock. On this file's later one the proof has
# lapsed, and a lapsed proof rightly names no server.
PROVED_AT = tahs.NOW


def test_a_server_named_differently_is_in_the_fleet_by_its_proved_address(db):
    trl.add_host(db, "student-net", [])
    connect_listing(db, "ubuntu-4gb-nbg1-2", tahs.V4)
    assert "0 in your fleet" in integrations_view(rl.render(db, now=PROVED_AT, workspace_id=1))
    tahs.prove(db, host_id_of(db, "student-net"), tahs.V4)
    assert "1 in your fleet" in integrations_view(rl.render(db, now=PROVED_AT, workspace_id=1))


def test_two_hosts_cannot_count_one_server_twice(db):
    trl.add_host(db, "student-net", [])
    trl.add_host(db, "ubuntu-4gb-nbg1-2", [])     # this one matches by its name
    connect_listing(db, "ubuntu-4gb-nbg1-2", tahs.V4)
    tahs.prove(db, host_id_of(db, "student-net"), tahs.V4)
    assert "1 in your fleet" in integrations_view(rl.render(db, now=PROVED_AT, workspace_id=1))


def test_the_rules_tab_finds_the_server_by_the_proved_address(db):
    trl.reporting(db, "student-net", trl.document(listening=[trl.SSHD]))
    connect_listing(db, "ubuntu-4gb-nbg1-2", tahs.V4)
    html = rl.render(db, now=PROVED_AT, workspace_id=1)
    assert rl.tpl.PROVIDER_SERVER_NOT_FOUND in html
    tahs.prove(db, host_id_of(db, "student-net"), tahs.V4)
    html = rl.render(db, now=PROVED_AT, workspace_id=1)
    assert rl.tpl.PROVIDER_SERVER_NOT_FOUND not in html
    # Listed, and with no firewall attached in this snapshot, which is the
    # state the owner's server was in before he attached one.
    assert rl.tpl.NO_FIREWALL_AT_PROVIDER in html


# ------------------------------- one token per project (docs/RECORD.md 4.206)

def connect_project(db, token, *, server_id, server_name, ipv4, minutes_ago,
                    firewalls=(), attached=()):
    """One more Hetzner project for workspace 1: the token that reads it and
    what that token read, since a workspace holds one token per project."""
    hz = rl.joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hz.init(con)
    token_id, _hint = hz.add_token(con, token, 1, now=NOW - timedelta(hours=1))
    read_at = NOW - timedelta(minutes=minutes_ago)
    hz.store_snapshot(con, hz.Snapshot(
        fetched_at=read_at.isoformat(),
        servers=({"id": server_id, "name": server_name, "status": "running",
                  "public_net": {"ipv4": {"ip": ipv4}, "ipv6": None,
                                 "firewalls": [{"id": f, "status": "applied"}
                                               for f in attached]}},),
        firewalls=tuple(firewalls)), workspace_id=1, token_id=token_id)
    hz.record_fetch(con, read_at, workspace_id=1, token_id=token_id)
    con.close()
    return token_id


def firewall(fid, name, server_id):
    return {"id": fid, "name": name, "applied_to": [{"type": "server", "server": {"id": server_id}}],
            "rules": [{"direction": "in", "protocol": "tcp", "port": "443", "description": "",
                       "source_ips": ["0.0.0.0/0"], "destination_ips": []}]}


def rows_of(view):
    return [part for part in view.split('<div class="al pv"')[1:]]


def two_projects(db):
    trl.add_host(db, "student-net", [])
    trl.add_host(db, "mattermost", [])
    first = connect_project(db, "first-project-" + "a" * 50, server_id=1,
                            server_name="student-net", ipv4="203.0.113.10", minutes_ago=12,
                            firewalls=[firewall(3, "fw-acme", 1)], attached=[3])
    second = connect_project(db, "second-project-" + "b" * 49, server_id=9,
                             server_name="mattermost", ipv4="203.0.113.20", minutes_ago=40,
                             firewalls=[firewall(3, "fw-mattermost", 9)], attached=[3])
    return first, second


def test_two_tokens_are_two_rows_each_with_its_own_project(db):
    first, second = two_projects(db)
    view = integrations_view(rl.render(db, now=NOW, workspace_id=1))
    rows = rows_of(view)
    assert len(rows) == 2
    one, two = rows
    assert f'data-token="{first}"' in one and "…aaaa" in one and "12 min ago" in one
    assert f'data-token="{second}"' in two and "…bbbb" in two and "40 min ago" in two
    # Each project's server is in the fleet on its own row, never both on one.
    assert "1 in your fleet" in one and "1 in your fleet" in two
    assert f'data-menu="intg-hetzner-{first}"' in one
    assert f'data-menu="intg-hetzner-{second}"' in two


def test_a_host_in_the_second_project_draws_that_projects_firewall(db):
    """Both projects have a firewall 3, because ids are the provider's per
    project. The host's own project's firewall 3 is the one drawn."""
    two_projects(db)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    provider = rl.load_provider(con, 1)
    con.close()
    provider["addresses"] = {}
    html, rules, firewalls = rl.provider_blocks("mattermost", provider, "mattermost", "")
    assert "fw-mattermost" in html and "fw-acme" not in html
    assert (rules, firewalls) == (1, 1)
    assert rl.provider_read_words(provider, "mattermost", NOW) == "snapshot taken 40 min ago"
    assert rl.provider_read_words(provider, "student-net", NOW) == "snapshot taken 12 min ago"
    assert rl.provider_empty_words(provider, "nowhere") == build.PROVIDER_SERVER_NOT_FOUND
