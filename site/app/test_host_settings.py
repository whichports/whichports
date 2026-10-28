"""The Settings tab: the rail and the content side by side, every setting a
row in a bordered list with its control at the right, per
docs/screens/host-settings/SPEC.md. Nothing has a Save for the tab: a
switch and a button act at once, a typed value has its own.

    Run from site/app: python3 -m pytest test_host_settings.py

Its own file, the way test_host_changes.py is. The rename handler's
repointing is still test_rename_button.py's, the port row clone
test_rows.py's; this file covers the rows the categories are made of, what
the live page fills them with, and the browser half of the name field, the
remove window and the unsilence row.
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sqlite3
import sys
import threading
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import (  # noqa: E402
    NOW, SSHD, add_host, db, declare_intent, document, host_section, silence_port, tab_body)
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

__all__ = ["db"]


# ------------------------------------------------------------ the fragments

def test_a_row_is_the_icon_the_name_a_line_under_it_and_the_control():
    html = build.hset_row("plug", "22/tcp", "sshd", "<i>c</i>", mono=True)
    assert html.startswith('<div class="li"><svg class="ic" width="18"')
    assert ('<span class="t"><b class="mono num">22/tcp</b><small class="dim">sshd</small></span>'
            '<span class="c"><i>c</i></span></div>') in html
    # no line, no small; no control, no cell; fixed keeps the width
    assert '<b>Name</b></span><span class="c fix">x</span>' in build.hset_row("tag", "Name", "", "x", fixed=True)
    assert build.hset_row("tag", "Labels").endswith('<span class="t"><b>Labels</b></span></div>')


def test_the_rail_is_the_five_entries_the_planned_one_and_the_notifications_group():
    rail = build.hset_rail("box")
    labels = re.findall(r'<label class="hitem h-(\w+)" for="hs-box-\1">', rail)
    assert labels == ["server", "agent", "probing", "addresses", "alerts"]
    assert '<span class="hitem hplanned">' in rail and "Provider" in rail
    assert rail.index("Provider") < rail.index("<hr>") < rail.index('<div class="g">Notifications</div>')
    assert rail.count('<span class="tag-planned">planned</span>') == 1


def test_the_open_entry_is_the_panel_surface_with_the_accent_bar():
    """The one place in the product a chosen item draws a bar, on the
    approved sketch's word (GitHub's settings pages, the owner 2026-09-04)."""
    css = build.hset_css()
    assert ".hsel.h-server:checked~.hbody .hstage.h-server{display:block}" in css
    assert ".hsel.h-server:checked~.hrail .hitem.h-server{background:var(--panel2);font-weight:600}" in css
    assert "::before{content:'';position:absolute;left:-8px" in css


def test_the_view_opens_on_the_first_panel_with_its_title():
    html = build.hset_view("box", [("server", "S"), ("agent", "A")])
    assert html.startswith('<div class="hset"><input type="radio" class="hsel h-server" name="hs-box" id="hs-box-server" checked>')
    assert '<div class="hstage h-server"><h2>Server</h2>S</div><div class="hstage h-agent"><h2>Agent</h2>A</div>' in html


def test_the_id_row_is_text_with_no_field_and_no_save():
    html = build.name_row("box", "box")
    assert '<span class="idv" id="id-box">box</span>' in html
    assert "<input" not in html and "<button" not in html
    assert 'class="c fix"' in html
    assert "Rename" not in html


def test_the_server_panel_is_two_lists_and_the_red_one_last():
    html = build.server_panel("box", "box", True)
    assert html.count('<div class="list') == 2
    assert html.endswith('</div>')
    assert '<div class="list danger">' in html and html.index("danger") > html.index("Paused")
    assert '<button type="button" class="sw js-pause" data-host="box"></button>' in html
    assert ('<button class="btn danger js-remove" data-host="box" data-name="box"'
            ' data-kind="agent">Remove</button>') in html
    # timezone and environment are planned, with the tag and nothing beside it
    assert build.hset_choice("UTC", disabled=True) + build.PLANNED_TAG in html
    assert ('<input class="in" value="" placeholder="" disabled>'
            + build.PLANNED_TAG) in html
    assert html.count('<input class="in" value="" placeholder="" disabled>') == 1
    assert "<h3>Labels" not in html


def test_the_probing_panel_is_the_cadence_row_then_the_ports_then_the_add_row():
    html = build.probing_panel("box", [("tcp", 22, "sshd, declared open")])
    assert "<b>From outside</b>" in html
    # On a server with an agent the list is the answers, on one without it
    # is what the probers look at (docs/RECORD.md 4.460).
    assert f"<h3>{build.PROBING_LIST_AGENT}</h3>" in html
    no_agent = build.probing_panel("box", [("tcp", 22, "declared open")], agent=False)
    assert f"<h3>{build.PROBING_LIST_ADDRESS}</h3>" in no_agent
    assert build.port_row("box", "tcp", 22, "sshd, declared open") in html
    add = html[html.index("Add a port"):]
    assert 'class="in mono short pd-port"' in add
    assert '<span class="seg"><button type="button" data-intent="open">open</button>' in add
    assert '<button class="btn js-port-add" data-host="box">Add</button>' in add
    assert html.index("22/tcp") < html.index("Add a port")


def test_the_addresses_panel_lists_the_proved_addresses_and_nothing_else():
    """The row that added an address is gone since 2026-10-06 (docs/RECORD.md
    4.379): the section's heading carries a button and a window does the
    rest, held in test_address_window.py."""
    html = build.addresses_panel("box", [("1.2.3.4", "token file, proved until 2 Dec", True),
                                         ("203.0.113.8", "expired 14 Aug", False)])
    assert html.count('class="btn js-addr-revoke"') == 1
    assert html.count('class="li"') == 2
    assert html.index("1.2.3.4") < html.index("203.0.113.8")
    for gone in ("ar-box", "js-addr-start", "js-addr-verify", "Add an address", "<input"):
        assert gone not in html, gone
    assert build.addresses_panel("box", []).count(build.NO_ADDRESS_LINE) == 1


def test_the_alerts_panel_is_two_mail_rows_and_the_silences():
    """The mail rows are facts with nothing at their right since 2026-10-14
    (docs/RECORD.md 4.460): they were two disabled switches, each tagged
    planned. A server with no agent has no quiet row."""
    html = build.alerts_panel("box", 35, [("tcp", 9100, "v4", "no end")])
    mail = html.split("<h3>Silenced ports</h3>")[0]
    assert mail.count('class="li"') == 2
    assert 'class="sw' not in mail and build.PLANNED_TAG not in mail
    assert "after 35 minutes" in html
    no_agent = build.alerts_panel("box", 35, [], agent=False).split("<h3>Silenced ports</h3>")[0]
    assert no_agent.count('class="li"') == 1 and "goes quiet" not in no_agent
    assert ('<button class="btn js-unsilence" data-host="box" data-protocol="tcp"'
            ' data-port="9100" data-family="v4">Unsilence</button>') in html
    assert f'<div class="li lempty">{build.NO_SILENCES}</div>' in build.alerts_panel("box", 35, [])


def test_the_agent_panel_is_the_read_mode_and_the_version_and_no_credential():
    """The owner, 2026-09-06: is there any need to change the credential here?
    There is not: a credential is reissued only for a server whose agent
    never spoke, which has its own page. Two rows."""
    html = build.agent_panel("box", "Full read", "13 Aug 2026", "0.1.8")
    assert "<b>Full read</b><small class=\"dim\">enrolled 13 Aug 2026</small>" in html
    assert "<b>Version 0.1.8</b>" in html
    assert html.count('<div class="li">') == 2
    assert "Credential" not in html and "js-recred" not in html
    assert "Version &mdash;" in build.agent_panel("box", "Agent", "", "")


def test_the_remove_window_asks_for_the_name_and_starts_disabled():
    html = build.remove_modal()
    assert 'id="rm-ovl"' in html and '<h2>Remove <span id="rm-name"></span></h2>' in html
    # the name in a chip that copies it on a click
    assert ('<button type="button" class="cfchip" id="rm-chip" title="Copy">'
            '<b class="mono" id="rm-name2"></b>') in html
    assert "to confirm." in html
    # the way out first and the action last, as every other window here
    assert html.index('>Cancel</button>') < html.index('id="rm-go"')
    assert '<input class="in mono" id="rm-input"' in html
    assert '<button class="btn danger" id="rm-go" disabled>Remove</button>' in html
    assert '<button class="btn" data-close="rm-ovl">Cancel</button>' in html


def test_the_sample_carries_the_tab_and_no_data_host():
    page = build.build_sample()
    section = page[page.index('id="host"'):]
    settings = re.split(r'<div class="tab|<div class="ovl', section.split('id="t-host-settings"')[1])[0]
    assert 'class="hset"' in settings and "data-host" not in settings
    assert 'id="rm-ovl"' in page
    # `addr-ovl` left this list on 2026-10-06: the address window is back, by
    # the drawing of docs/RECORD.md 4.379.
    for old in ("choice_row", "Authorised addresses", "as-rail\" aria-label=\"Settings for this server", "js-addr-add"):
        assert old not in page, old
    assert page.count('id="addr-ovl"') == 1


# ------------------------------------------------------------- the live tab

def reporting(db, name, doc, minutes=2):
    add_host(db, name, [(NOW - timedelta(minutes=minutes), doc)],
             last_report_at=(NOW - timedelta(minutes=minutes)).isoformat())


def settings_of(db, name="box"):
    return tab_body(host_section(rl.render(db, now=NOW), name), name, "settings")


def panel(html, key):
    return html.split(f'<div class="hstage h-{key}">')[1].split('<div class="hstage')[0]


def test_the_server_panel_fills_from_the_host_row(db):
    reporting(db, "box", document(listening=[SSHD]))
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET paused = 1 WHERE name = 'box'")
    con.commit()
    con.close()
    server = panel(settings_of(db), "server")
    assert '<span class="idv" id="id-box">box</span>' in server
    assert '<button type="button" class="sw js-pause" data-host="box"></button>' in server
    assert 'class="btn danger js-remove" data-host="box" data-name="box"' in server


def test_the_agent_panel_fills_from_the_document_and_the_enrolment(db):
    doc = document(listening=[SSHD])
    doc["agent_version"] = "0.1.8"
    reporting(db, "box", doc)
    agent = panel(settings_of(db), "agent")
    assert "<b>Full read</b>" in agent
    assert "enrolled 14 Aug 2026" in agent
    assert "<b>Version 0.1.8</b>" in agent
    assert "js-recred" not in agent


def test_the_probing_panel_lists_the_declared_ports_with_their_service(db):
    reporting(db, "box", document(listening=[SSHD]))
    declare_intent(db, "box", "tcp", 22, "v4", "open")
    declare_intent(db, "box", "tcp", 22, "v6", "open")
    declare_intent(db, "box", "tcp", 8096, "v4", "closed")
    probing = panel(settings_of(db), "probing")
    assert build.port_row("box", "tcp", 22, "sshd, declared open") in probing
    assert build.port_row("box", "tcp", 8096, "declared v4 closed") in probing
    assert probing.index("22/tcp") < probing.index("8096/tcp") < probing.index("Add a port")


def test_the_alerts_panel_lists_the_live_silences(db):
    reporting(db, "box", document(listening=[SSHD]))
    silence_port(db, "box", "tcp", 22, "v4")
    alerts = panel(settings_of(db), "alerts")
    assert "after 35 minutes" in alerts
    assert ('<button class="btn js-unsilence" data-host="box" data-protocol="tcp"'
            ' data-port="22" data-family="v4">Unsilence</button>') in alerts
    assert f'<small class="dim">{build.SILENCE_NO_END}</small>' in alerts


def test_an_address_host_has_the_same_five_categories(db):
    from test_address_hosts_screen import add_address_host, prove, registry
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    registry().init(con)
    con.close()
    host_id = add_address_host(db, "outside-only")
    prove(db, host_id)
    settings = settings_of(db, "outside-only")
    for key in ("server", "agent", "probing", "addresses", "alerts"):
        assert f'<div class="hstage h-{key}">' in settings, key
    assert "<b>No agent</b>" in panel(settings, "agent")
    assert "js-addr-revoke" in panel(settings, "addresses")


def test_the_never_reported_page_keeps_its_two_acts_through_the_window(db):
    add_host(db, "quiet", [])
    section = host_section(rl.render(db, now=NOW), "quiet")
    assert 'class="btn js-recred" data-host="quiet"' in section
    assert 'class="btn danger js-remove" data-host="quiet" data-name="quiet"' in section


# ---------------------------------------------------------- in the browser

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>settings drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var result={errs:[],posts:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    w.fetch=function(url,opts){
      opts=opts||{};
      if((opts.method||'GET')==='POST'){
        result.posts.push({url:String(url),body:opts.body||null});
        return Promise.resolve({ok:true,redirected:false,status:204,
          json:function(){return Promise.resolve({})},text:function(){return Promise.resolve('')}});
      }
      return Promise.resolve({ok:true,redirected:false,status:200,text:function(){return Promise.resolve('')}});
    };
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick();
    d.getElementById('tb-box-settings').click(); await tick();
    var id=d.getElementById('id-box');
    result.idRow={text:id.textContent,
      controls:id.closest('.li').querySelectorAll('input,button').length};
    // the remove window
    d.querySelector('#host-box .hsel.h-server').click();
    d.querySelector('#host-box .js-remove').click(); await tick();
    var ovl=d.getElementById('rm-ovl'), go=d.getElementById('rm-go'), rin=d.getElementById('rm-input');
    result.window={open:ovl.classList.contains('on'),name:d.getElementById('rm-name').textContent,
      disabled:go.disabled};
    rin.value='wrong';rin.dispatchEvent(new w.Event('input'));
    result.wrongName=go.disabled;
    rin.value='box';rin.dispatchEvent(new w.Event('input'));
    result.rightName=go.disabled;
    go.click(); await tick();
    result.afterRemove={closed:!ovl.classList.contains('on'),view:(d.querySelector('.view.on')||{}).id};
    out.textContent=JSON.stringify(result);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def drive(tmp_path, page, harness):
    site = tmp_path / "www"
    site.mkdir()
    (site / "live.html").write_text(page, encoding="utf-8")
    (site / "harness.html").write_text(harness, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=8000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert result.get("errs") == [], result
    return result


def test_the_id_is_text_in_the_browser_and_the_window_removes(tmp_path, db):
    reporting(db, "box", document(listening=[SSHD]))
    r = drive(tmp_path, rl.render(db, now=NOW), HARNESS)
    assert r["idRow"] == {"text": "box", "controls": 0}
    assert r["window"] == {"open": True, "name": "box", "disabled": True}
    assert r["wrongName"] is True and r["rightName"] is False
    assert r["posts"][-1] == {"url": "/api/admin/hosts/box/revoke", "body": None}
    assert not [p for p in r["posts"] if "/rename" in p["url"]]
    # The window stays open after Remove, with the command to copy
    # (docs/screens/host-settings/BRIEF-remove-command.md); test_delete_server.py
    # drives the rest of that window.
    assert r["afterRemove"] == {"closed": False, "view": "fleet"}


UNSILENCE = """<!doctype html>
<meta charset="utf-8">
<title>unsilence drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var result={errs:[],posts:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    w.fetch=function(url,opts){
      opts=opts||{};
      if((opts.method||'GET')==='POST'){result.posts.push(String(url));
        return Promise.resolve({ok:true,status:204,redirected:false,json:function(){return Promise.resolve({})}})}
      return Promise.resolve({ok:true,redirected:false,status:200,text:function(){return Promise.resolve('')}});
    };
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick();
    d.getElementById('tb-box-settings').click();
    d.getElementById('hs-box-alerts').click(); await tick();
    result.before=d.querySelectorAll('#host-box .js-unsilence').length;
    d.querySelector('#host-box .js-unsilence').click(); await tick();
    result.after=d.querySelectorAll('#host-box .js-unsilence').length;
    out.textContent=JSON.stringify(result);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def test_unsilence_posts_and_the_row_goes_at_once(tmp_path, db):
    reporting(db, "box", document(listening=[SSHD]))
    silence_port(db, "box", "tcp", 22, "v4")
    r = drive(tmp_path, rl.render(db, now=NOW), UNSILENCE)
    assert (r["before"], r["after"]) == (1, 0)
    assert r["posts"] == ["/api/admin/hosts/box/ports/tcp/22/v4/unsilence"]
