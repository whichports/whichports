"""The Integrations screen, built from docs/screens/integrations/SPEC.md and
its sketch.

    Run from site/app: python3 -m pytest test_integrations_screen.py

The Providers table from the stored snapshot and the last read's outcome,
the Alert destinations under it, the empty states, the Add window's provider
and monitoring cards, and the words the live page makes of what the control
plane stores. The Feeds line and the Add integration window went with layout
B (docs/screens/alerts/SPEC-layout-b.md).
"""
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
import theme  # noqa: E402

NOW = datetime(2026, 9, 7, 12, 0, tzinfo=timezone.utc)


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def line(**kw):
    base = dict(key="hetzner", name="Hetzner Cloud", token="set on the server",
                word="connected", tone="ok", servers=4, in_fleet=3, firewalls=2,
                without=1, read="12 min ago")
    base.update(kw)
    return build.ProviderLine(**base)


# --------------------------------------------------------------- the table

def test_a_provider_line_carries_the_seven_columns_in_order():
    html = build.provider_line_html(line())
    order = [html.index(s) for s in ('class="pvn"', 'class="pvtok"', 'class="altag"',
                                     "3 in your fleet", "1 server without",
                                     'class="pvread"', 'class="rmenu"')]
    assert order == sorted(order)
    assert build.alerts_thead_html(build.PROVIDER_COLUMNS) in build.providers_table_html([line()])


def test_the_counts_sit_over_their_second_line():
    html = build.provider_line_html(line())
    assert '<span class="pvn2">4<small>3 in your fleet</small></span>' in html
    assert '<span class="pvn2">2<small>1 server without</small></span>' in html
    assert "2 servers without" in build.provider_line_html(line(without=2))
    assert "0 servers without" in build.provider_line_html(line(without=0))


def test_a_line_with_no_snapshot_has_empty_counts():
    html = build.provider_line_html(line(servers="", in_fleet="", firewalls="", without=""))
    assert html.count('<span class="pvn2"></span>') == 2


def test_the_status_and_the_read_column():
    ok = build.provider_line_html(line())
    assert '<span class="st ok">connected</span>' in ok
    assert '<span class="pvread">12 min ago</span>' in ok
    bad = build.provider_line_html(line(word="refused", tone="fail", read="3 h ago, 401",
                                        read_warn=True))
    assert '<span class="st fail">refused</span>' in bad
    assert '<span class="pvread warn">3 h ago, 401</span>' in bad


def test_a_provider_line_is_not_a_way_to_a_server():
    """It carries no data-host, so the row click that opens a server never
    binds to it."""
    html = build.provider_line_html(line())
    assert "data-host" not in html
    assert 'data-provider="hetzner"' in html


def test_every_field_is_escaped():
    html = build.provider_line_html(line(name="<b>x", token='"><i>', read="<u>"))
    for raw in ("<b>x", '"><i>', "<u>"):
        assert raw not in html
    assert "&lt;b&gt;x" in html


def test_the_row_menu_is_read_now_replace_token_and_disconnect_apart_and_live():
    """Live since the credential store exists (record 4.178): each item
    carries the class the page script binds and the provider it acts on,
    and nothing is planned or disabled any more."""
    menu = build.provider_menu_html("hetzner")
    order = [menu.index(s) for s in (">Read now<", ">Replace token<", '<hr class="rm-hr">',
                                     ">Disconnect<")]
    assert order == sorted(order)
    assert "disabled" not in menu and build.PLANNED_TAG not in menu
    for cls in ("js-prov-read", "js-prov-token", "js-prov-off"):
        assert f'class="rm-i {cls}' in menu, cls
    assert ('class="rm-i js-prov-off rm-del" data-provider="hetzner" data-token="">Disconnect<'
            in menu)
    assert menu.count('data-provider="hetzner"') == 3
    assert 'data-menu="intg-hetzner"' in menu


def test_two_tokens_of_one_provider_are_two_menus_each_naming_its_own():
    """One token per project since 2026-09-27 (docs/RECORD.md 4.206). Two
    Hetzner rows sharing a menu id would open each other's menu, and an item
    that did not name its token would act on whichever the server picked."""
    first = build.provider_menu_html("hetzner", ref=4)
    second = build.provider_menu_html("hetzner", ref=7)
    assert 'data-menu="intg-hetzner-4"' in first and 'data-menu="intg-hetzner-7"' in second
    assert first.count('data-token="4"') == 3 and 'data-token="7"' not in first
    assert second.count('data-token="7"') == 3 and 'data-token="4"' not in second


def test_a_row_carries_its_token_and_hands_it_to_its_menu():
    row = build.provider_line_html(line(ref=9))
    assert 'class="al pv" data-provider="hetzner" data-token="9"' in row
    assert 'data-menu="intg-hetzner-9"' in row and row.count('data-token="9"') == 4


def test_the_sample_shells_row_menu_raises_a_toast_instead():
    """The shell has no server behind it, so its items say what would
    happen, the way every other menu on the shell does."""
    menu = build.provider_menu_html("hetzner", live=False)
    assert menu.count('class="rm-i js-act') == 3
    assert menu.count("data-msg=") == 3
    assert "js-prov" not in menu and build.PLANNED_TAG not in menu
    assert 'class="rm-i js-act rm-del"' in menu


# ---------------------------------------------------------------- the view

def no_destination():
    """What the view is handed for a workspace with no alert destination,
    as `render_live.alerts_channels_html` makes it."""
    return build.channel_rows_html([], build.NO_DESTINATION_ADDED)


def test_the_page_is_providers_then_alert_destinations_with_the_button_in_the_header():
    """Alert destinations stands where Feeds stood, and the one button reads
    Add (docs/screens/alerts/SPEC-layout-b.md)."""
    html = build.integrations_view([line()], no_destination(), False)
    assert re.findall(r'<h2 class="alh2">([^<]+)', html) == ["Providers", "Alert destinations"]
    assert html.count('data-open="conn-ovl"') == 1
    assert '<div class="acts"><button class="btn pri" data-open="conn-ovl">Add</button></div>' in html
    # a provider and no destination: the one line under its heading
    assert ('<div class="panel altbl chan chanp"><div class="al alempty">'
            f'{build.NO_DESTINATION_ADDED}</div></div>') in html
    assert "No feed connected yet" not in html and not hasattr(build, "NO_FEED")
    # nothing on the connected page is planned any more: the row's three
    # acts are live (record 4.178)
    assert "tag-planned" not in html


def test_nothing_connected_is_the_box_and_no_header_button():
    html = build.integrations_view([], no_destination(), False)
    assert build.NOTHING_CONNECTED in html
    assert theme.ICONS["plugs"] in html
    assert html.count('data-open="conn-ovl"') == 1
    # the one button, the last thing in the box
    assert (f'<div class="w">{build.NOTHING_CONNECTED}</div>'
            '<button class="btn pri" data-open="conn-ovl">Add</button></div>') in html
    assert '<div class="acts">' not in html
    # The box and nothing under it. It stood over the Feeds line until
    # layout B. Now no heading stands over nothing, and neither empty line
    # is said.
    assert "alh2" not in html
    assert build.NO_DESTINATION_ADDED not in html and build.NO_PROVIDER_FIREWALL not in html


def test_the_lists_are_alphabetical_and_hold_what_the_spec_lists():
    names = [n for _k, n, _g, _b in build.PROVIDERS]
    assert names == sorted(names, key=str.lower)
    assert names == ["AWS", "Azure", "DigitalOcean", "Hetzner Cloud", "Linode",
                     "OVHcloud", "Scaleway", "Vultr"]
    # The four feeds are two lists since layout B
    # (docs/screens/alerts/SPEC-layout-b.md): three monitoring cards, and
    # Syslog, which is offered among the alert destinations.
    assert not hasattr(build, "FEEDS")
    monitoring = [n for _k, n, _g, _b in build.MONITORING]
    assert monitoring == ["Grafana", "Prometheus", "Zabbix"]
    assert build.SYSLOG_CARD[:2] == ("syslog", "Syslog")
    assert [k for k, _n, _g, built in build.PROVIDERS if built] == ["hetzner"]
    assert not any(built for _k, _n, _g, built in build.MONITORING + [build.SYSLOG_CARD])
    for key, *_rest in trl.catalogue():
        assert key in build.INTEGRATION_FIELDS, key


def test_the_marks_are_the_sketches_and_the_rest_are_neutral():
    """The owner's decision of 2026-09-07 (record 4.152): the marks as the
    sketch draws them, taken down the day an owner asks."""
    marks = {k: g for k, _n, g, _b in trl.catalogue() if g in theme.MARKS}
    assert marks == {"aws": "amazonwebservices", "azure": "microsoftazure",
                     "digitalocean": "digitalocean", "hetzner": "hetzner", "linode": "akamai",
                     "ovh": "ovh", "scaleway": "scaleway", "vultr": "vultr",
                     "grafana": "grafana", "prometheus": "prometheus", "zabbix": "zabbix"}
    rest = {k: g for k, _n, g, _b in trl.catalogue() if g not in theme.MARKS}
    assert rest == {"syslog": "broadcast"}
    for glyph in rest.values():
        assert glyph in theme.ICONS
    assert 'viewBox="0 0 24 24"' in theme.icon("hetzner")


# -------------------------------------------------------------- the window

def test_the_window_has_a_step_per_kind_one_pickable_provider_and_its_fields():
    """The two groups under one heading each, Providers and Feeds, are steps
    of the one Add window since layout B, one per first card
    (docs/screens/alerts/SPEC-layout-b.md). The cards are the twelve they
    were: eight providers, three monitoring cards, and Syslog, which stands
    among the alert destinations."""
    html = build.add_modal(live=True)
    assert re.findall(r'<div class="m-card pick" data-kind="([a-z]+)">', html) == [
        "dest", "prov", "mon"]
    assert re.findall(r'<div class="m-stage m-kind" id="conn-([a-z]+)">', html) == [
        "dest", "prov", "mon"]
    assert "m-grp" not in html, "a group heading, where the first cards name the kinds"
    providers, monitoring = trl.kind_cards(html, "prov"), trl.kind_cards(html, "mon")
    assert providers.count('class="m-cards m4"') == 1
    assert monitoring.count('class="m-cards m4 w3"') == 1
    picks = re.findall(r'class="m-card pick nmo" data-fields="([^"]+)"', providers + monitoring)
    assert picks == ["intg-hetzner"]
    assert "data-stage" not in html
    planned = 'class="m-card planned nmo" disabled aria-disabled="true"'
    assert (providers.count(planned), monitoring.count(planned)) == (7, 3)
    assert trl.kind_cards(html, "dest").count(planned) == 1
    assert html.count(planned) == 11
    assert '<div class="m-stage" id="intg-hetzner" data-type="hetzner">' in html
    assert html.count('<div class="m-stage" id="intg-') == 1
    assert 'placeholder="" type="password"' in html, "no invented token shape"


def test_the_live_window_footer_is_cancel_then_a_connect_that_acts_and_docs_is_planned():
    html = build.add_modal(live=True)
    foot = html.split('<div class="m-foot">')[1]
    assert foot.index(">Cancel<") < foot.index('id="conn-go"')
    # One action for every kind since layout B. It is hidden until a built
    # card's fields show, and the page script writes its word on it: Connect
    # for a provider, and then it connects.
    assert ('<button class="btn pri" id="conn-go" hidden data-dest="Save"'
            ' data-prov="Connect">Save</button>') in foot
    script = pathlib.Path(build.__file__).with_name("page.js").read_text()
    assert "connGo.textContent=slackConnect()?'Connect to Slack':connGo.dataset[kind];" in script
    assert "if(kind==='prov')connectProvider(stage);" in script
    assert build.PLANNED_TAG not in foot and "disabled" not in foot
    assert "data-sample" not in foot
    assert '<div class="m-err m-quiet" id="conn-err"></div>' in html
    head = html.split('<div class="m-h">')[1].split("</div>")[0]
    assert build.PLANNED_TAG in head and "Docs" in head
    assert 'class="btn out" disabled>Docs' in head
    assert theme.ICONS["arrow-square-out"] in head


def test_the_sample_windows_connect_says_what_it_would_do():
    """It was a disabled button tagged planned in the Add integration window.
    The one Add window has one action for every kind, so on the sample shell
    it is marked, and the page script says what a click would do and sends
    nothing, as the shell's other controls do
    (docs/screens/alerts/SPEC-layout-b.md says nothing of the shell)."""
    html = build.add_modal(live=False)
    foot = html.split('<div class="m-foot">')[1]
    assert foot.index(">Cancel<") < foot.index('id="conn-go"')
    assert ('<button class="btn pri" id="conn-go" hidden data-dest="Save"'
            ' data-prov="Connect" data-sample="1">Save</button>') in foot
    assert build.PLANNED_TAG not in foot and "disabled" not in foot
    script = pathlib.Path(build.__file__).with_name("page.js").read_text()
    click = script[script.index("connGo.onclick=function(){"):]
    click = click[:click.index("\n    };")]
    said = click.index("toast(kind==='prov'?'The provider would be connected here'")
    assert click.index("if(connGo.dataset.sample){") < said
    assert said < click.index("connectProvider(stage)")


def test_the_replace_token_window_is_one_secret_field_and_save():
    html = build.provider_token_modal()
    assert 'id="ptok-ovl"' in html and "Replace token" in html
    assert 'id="ptok-input" type="password"' in html
    assert 'class="btn pri" id="ptok-go">Save</button>' in html
    assert 'id="ptok-err"' in html
    foot = html.split('<div class="m-foot">')[1]
    assert foot.index(">Cancel<") < foot.index(">Save<")


def test_no_marker_is_left_in_the_window():
    for live in (True, False):
        assert "unsure" not in build.add_modal(live=live)


def test_an_odd_last_field_spans_the_width_by_css():
    assert ".m-two>div:nth-child(odd):last-child{grid-column:1/-1}" in build.CSS


# ------------------------------------------------- the live page's words

def snapshot(servers=(), firewalls=(), when=None):
    hz = rl.joinbridge.module("hetzner")
    return hz.Snapshot(fetched_at=(when or NOW - timedelta(minutes=12)).isoformat(),
                       servers=tuple(servers), firewalls=tuple(firewalls))


def server(i, name, firewall_ids):
    return {"id": i, "name": name, "status": "running",
            "public_net": {"ipv4": {"ip": f"203.0.113.{i}"}, "ipv6": None,
                           "firewalls": [{"id": f, "status": "applied"} for f in firewall_ids]}}


def provider(snap=None, fetch=None, token=None):
    hz = rl.joinbridge.module("hetzner")
    # One project, the shape `load_provider` hands over per token.
    return {"projects": [{"snapshot": snap, "inventory": hz.parse_snapshot(snap) if snap else None,
                          "fetch": fetch, "token": token}]}


def test_nothing_connected_is_no_snapshot_and_no_read():
    assert rl.provider_lines(provider(), ["box"], NOW) == []
    unset = {"tried_at": NOW.isoformat(), "error_kind": "not_configured", "error_status": None}
    assert rl.provider_lines(provider(fetch=unset), ["box"], NOW) == []


def test_the_counts_come_from_the_snapshot_and_the_fleet_match_is_by_name():
    snap = snapshot([server(1, "Box", [1]), server(2, "other", [1, 2]), server(3, "lone", [])],
                    [{"id": 1, "name": "a", "rules": [], "applied_to": []},
                     {"id": 2, "name": "b", "rules": [], "applied_to": []}])
    got = rl.provider_lines(provider(snap), ["box", "media-01"], NOW)[0]
    assert (got.servers, got.in_fleet, got.firewalls, got.without) == (3, 1, 2, 1)
    assert (got.word, got.tone, got.read, got.read_warn) == ("connected", "ok", "12 min ago", False)
    assert got.token == "", "a snapshot with no token behind it claims no token"
    assert got.name == "Hetzner Cloud"


def test_the_token_column_is_the_hint_the_row_stored_and_never_the_token():
    snap = snapshot([server(1, "box", [1])], [{"id": 1, "name": "a", "rules": [], "applied_to": []}])
    got = rl.provider_lines(provider(snap, token={"hint": "…c3f1", "set_at": NOW.isoformat()}),
                            ["box"], NOW)[0]
    assert got.token == "…c3f1"
    html = build.provider_line_html(got)
    assert '<b class="pvtok">…c3f1</b>' in html


def test_a_token_with_no_read_yet_is_a_connected_line_with_empty_counts():
    """The moment after Connect, before the first read is stored: the row is
    there, with the hint, and every count empty rather than zero."""
    got = rl.provider_lines(provider(token={"hint": "…c3f1", "set_at": NOW.isoformat()}),
                            ["box"], NOW)
    assert len(got) == 1
    assert got[0].token == "…c3f1"
    assert (got[0].servers, got[0].in_fleet, got[0].firewalls, got[0].without) == ("", "", "", "")
    assert got[0].word == "connected"


def test_a_refused_read_newer_than_the_snapshot_turns_the_status():
    snap = snapshot(when=NOW - timedelta(hours=5))
    fetch = {"tried_at": (NOW - timedelta(hours=3)).isoformat(),
             "error_kind": "unauthorized", "error_status": 401}
    got = rl.provider_lines(provider(snap, fetch), [], NOW)[0]
    assert (got.word, got.tone, got.read, got.read_warn) == ("refused", "fail", "3 h ago, 401", True)
    assert got.servers == 0


def test_a_refused_read_older_than_the_snapshot_is_history():
    snap = snapshot(when=NOW - timedelta(minutes=12))
    fetch = {"tried_at": (NOW - timedelta(hours=3)).isoformat(),
             "error_kind": "forbidden", "error_status": 403}
    got = rl.provider_lines(provider(snap, fetch), [], NOW)[0]
    assert (got.word, got.read, got.read_warn) == ("connected", "12 min ago", False)


def test_a_read_that_did_not_happen_keeps_the_status_and_says_why_in_amber():
    snap = snapshot(when=NOW - timedelta(hours=5))
    fetch = {"tried_at": (NOW - timedelta(hours=1)).isoformat(),
             "error_kind": "network", "error_status": None}
    got = rl.provider_lines(provider(snap, fetch), [], NOW)[0]
    assert (got.word, got.tone, got.read, got.read_warn) == ("connected", "ok", "1 h ago, no answer", True)


def test_a_refused_read_with_no_snapshot_at_all_is_a_line_with_empty_counts():
    fetch = {"tried_at": (NOW - timedelta(minutes=2)).isoformat(),
             "error_kind": "unauthorized", "error_status": 401}
    got = rl.provider_lines(provider(None, fetch), [], NOW)[0]
    assert got.word == "refused" and got.servers == ""
    assert got.read == "2 min ago, 401"


def test_a_snapshot_that_will_not_parse_keeps_the_line_without_counts():
    hz = rl.joinbridge.module("hetzner")
    snap = hz.Snapshot(fetched_at=(NOW - timedelta(minutes=1)).isoformat(), servers=("junk",))
    got = rl.provider_lines({"projects": [{"snapshot": snap, "inventory": None, "fetch": None}]},
                            [], NOW)[0]
    assert got.servers == "" and got.word == "connected"


@pytest.mark.parametrize("delta,words", [
    (timedelta(seconds=30), "just now"), (timedelta(minutes=12), "12 min ago"),
    (timedelta(hours=3, minutes=20), "3 h ago"), (timedelta(days=2), "2 d ago")])
def test_the_read_column_speaks_in_one_unit(delta, words):
    assert rl.read_age(NOW - delta, NOW) == words


# ---------------------------------------------------------- end to end

def store(db, snap, fetch_error=None, tried=None):
    hz = rl.joinbridge.module("hetzner")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    hz.init(con)
    if snap is not None:
        hz.store_snapshot(con, snap)
    if tried is not None:
        hz.record_fetch(con, tried, fetch_error)
    con.commit()
    con.close()


def integrations_view(html):
    start = html.index('<div class="wrap view" id="integrations">')
    view = html[start:]
    ends = [i for i in (view.find('<div class="wrap view"', 10), view.find('<div class="ovl'))
            if i != -1]
    return view[:min(ends)] if ends else view


def test_a_database_without_the_provider_tables_renders_nothing_connected(db):
    trl.add_host(db, "box", [])
    view = integrations_view(rl.render(db, now=NOW))
    assert build.NOTHING_CONNECTED in view
    assert "Hetzner" not in view


def test_a_stored_snapshot_is_a_connected_line(db):
    trl.add_host(db, "box", [])
    store(db, snapshot([server(1, "box", [1]), server(2, "other", [])],
                       [{"id": 1, "name": "a", "rules": [], "applied_to": []}]),
          tried=NOW - timedelta(minutes=12))
    view = integrations_view(rl.render(db, now=NOW))
    assert "Hetzner Cloud" in view
    assert '<span class="st ok">connected</span>' in view
    assert "2<small>1 in your fleet</small>" in view
    assert "1<small>1 server without</small>" in view
    assert '<span class="pvread">12 min ago</span>' in view
    assert build.NOTHING_CONNECTED not in view
    assert 'data-open="conn-ovl">Add</button>' in view
    # and with no destination stored, the one line under Alert destinations
    assert build.NO_DESTINATION_ADDED in view.split('<h2 class="alh2">Alert destinations')[1]


def test_a_refused_token_reaches_the_page(db):
    hz = rl.joinbridge.module("hetzner")
    trl.add_host(db, "box", [])
    store(db, snapshot(when=NOW - timedelta(hours=5)),
          fetch_error=hz.ProviderError(hz.ERROR_UNAUTHORIZED, status=401),
          tried=NOW - timedelta(hours=3))
    view = integrations_view(rl.render(db, now=NOW))
    assert '<span class="st fail">refused</span>' in view
    assert '<span class="pvread warn">3 h ago, 401</span>' in view


def test_the_window_is_on_both_feeds_once():
    html = build.build_sample()
    assert html.count('id="conn-ovl"') == 1
    assert 'id="intg-ovl"' not in html
    assert build.SAMPLE_PROVIDERS[0].name in html


def test_the_page_script_sends_the_rows_token_with_every_act():
    """Read now, Replace token and Disconnect each post the row's token id,
    and the Disconnect window names the token, since the provider's name
    alone does not say which of two rows it is."""
    script = pathlib.Path(build.__file__).with_name("page.js").read_text()
    assert "body.token_id=Number(token)" in script
    for act in ("providerAct(b.dataset.provider,b.dataset.token,'read'",
                "providerAct(b.dataset.provider,b.dataset.token,'disconnect'",
                "ptokToken=b.dataset.token",
                "tokenBody(ptokToken,{token:token})"):
        assert act in script, act
    assert "querySelector('.pvtok')" in script
