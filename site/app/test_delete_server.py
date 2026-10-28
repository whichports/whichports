"""Delete for a removed server, and the Remove window that hands over the
machine: the list under the fleet table, the delete window, the two rows
about the machine, and the window that stays open after Remove
(docs/PRODUCT.md 4f, docs/screens/host-settings/BRIEF-remove-command.md).

    Run from site/app: python3 -m pytest test_delete_server.py

The browser half also proves the one defect the owner hit on 2026-09-13: after
the page had refreshed itself once, the typed name no longer enabled Remove,
because the window's setup ran again on every wire() (docs/RECORD.md 4.175).
The harness lets the page refresh once, then types the name.
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
from test_address_hosts_screen import add_address_host  # noqa: E402
from test_fleet import fleet_rows, fleet_section  # noqa: E402
from test_host_settings import reporting, settings_of  # noqa: E402
from test_render_live import NOW, SSHD, add_host, db, document, host_section, tab_body  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

__all__ = ["db"]

REMOVE_BUTTON = '<button class="btn danger js-remove" data-host="{n}" data-name="{n}"{about}>Remove</button>'


# ------------------------------------------------------------ the fragments

def test_no_removed_server_is_an_empty_hidden_block_the_refresh_can_swap():
    assert build.removed_list_html(()) == '<div class="fgone" hidden></div>'


def test_the_removed_list_is_a_heading_and_one_row_per_server_with_delete():
    html = build.removed_list_html((("box", "removed 14 Sep 2026"),
                                    ("older", "removed 02 Sep 2026")))
    assert html.startswith('<div class="fgone"><h2 class="alh2">Removed</h2><div class="list">')
    assert html.endswith('</div></div>')
    delete = build.button("Delete", "danger js-delete", data_host="box", data_name="box")
    assert delete == '<button class="btn danger js-delete" data-host="box" data-name="box">Delete</button>'
    assert build.hset_row("hard-drives", "box", "removed 14 Sep 2026", delete) in html
    assert html.index('data-host="box"') < html.index('data-host="older"')
    assert html.count('<div class="li">') == 2


def test_the_delete_window_is_the_remove_windows_shape_with_its_own_ids():
    html = build.delete_modal()
    assert 'id="del-ovl"' in html and '<div class="modal panel rmw">' in html
    assert '<h2>Delete <span id="del-name"></span></h2>' in html
    assert ('<button type="button" class="cfchip" id="del-chip" title="Copy">'
            '<b class="mono" id="del-name2"></b>') in html
    assert '<input class="in mono" id="del-input"' in html
    assert '<button class="btn" data-close="del-ovl">Cancel</button>' in html
    assert '<button class="btn danger" id="del-go" disabled>Delete</button>' in html
    assert html.index('>Cancel</button>') < html.index('id="del-go"')
    # nothing about the machine: a removed server's agent is already refused
    assert "rmrow" not in html and "uninstall" not in html


def test_the_remove_window_carries_the_two_rows_about_the_machine_hidden():
    html = build.remove_modal()
    last = ('<div class="rmrow" id="rm-last" hidden><span class="l">Last report</span>'
            '<span class="v" id="rm-last-v"></span></div>')
    cmd = ('<div class="rmrow" id="rm-cmd" hidden><span class="l">On the server</span>'
           '<div class="code m-copy" id="rm-cmd-v">sudo whichports-uninstall</div></div>')
    assert last in html and cmd in html
    assert build.UNINSTALL_COMMAND == "sudo whichports-uninstall"
    # between the field and the buttons, the last report first
    assert html.index('id="rm-input"') < html.index(last) < html.index(cmd) < html.index('class="m-foot"')
    # a label and a value, never a sentence
    rows = re.findall(r'<span class="l">([^<]+)</span>', html)
    assert rows == ["Last report", "On the server"]


def test_the_remove_button_says_what_the_window_needs_about_the_machine():
    panel = build.server_panel("box", "box", False)
    assert REMOVE_BUTTON.format(n="box", about=' data-kind="agent"') in panel
    panel = build.server_panel("box", "box", False, kind="agent", last="2m ago", reporting=True)
    assert REMOVE_BUTTON.format(n="box", about=' data-kind="agent" data-last="2m ago" data-live="1"') in panel
    panel = build.server_panel("box", "box", False, kind="agent", last="3d ago", reporting=False)
    assert REMOVE_BUTTON.format(n="box", about=' data-kind="agent" data-last="3d ago"') in panel
    panel = build.server_panel("addr", "addr", False, kind="address")
    assert REMOVE_BUTTON.format(n="addr", about=' data-kind="address"') in panel
    # the sample shell's button is the sample's, untouched
    assert 'data-msg="The remove window would open here"' in build.server_panel("box", "box", False, live=False)


def test_the_page_script_knows_the_list_and_both_windows():
    script = build.build_sample()
    script = script[script.rindex("<script>"):]
    assert "push('gone:page',root.querySelector('#fleet .fgone'))" in script
    assert "if(kind==='gone') return document.querySelector('#fleet .fgone')" in script
    assert "'/delete'" in script and "'/revoke'" in script
    # the remove window is set up once, before the delete window, and neither
    # inside a pass that runs again after every refresh, which is what stacked
    # its listeners
    at = script.index("var rmOvl=")
    assert script.rfind("\n  });", 0, at) > script.rfind("onWire(function(){", 0, at)
    assert at < script.index("var delOvl=")
    assert "new MutationObserver" in script


def test_the_sample_shell_holds_both_windows_and_an_empty_removed_block():
    html = build.build_sample()
    assert 'id="rm-ovl"' in html and 'id="del-ovl"' in html
    assert '<div class="fgone" hidden></div>' in fleet_section(html)


# ------------------------------------------------------------- the live page

def removed_names(html):
    return re.findall(r'class="btn danger js-delete" data-host="([^"]+)"', fleet_section(html))


def test_a_removed_server_leaves_the_table_for_the_list_under_it(db):
    reporting(db, "box", document(listening=[SSHD]))
    add_host(db, "old", [], revoked=True)
    html = rl.render(db, now=NOW)
    assert [re.search(r'data-host="([^"]+)"', r).group(1) for r in fleet_rows(html)] == ["box"]
    assert removed_names(html) == ["old"]
    fleet = fleet_section(html)
    assert fleet.index('class="panel ftbl"') < fleet.index('<div class="fgone"><h2 class="alh2">Removed</h2>')
    assert build.hset_row("hard-drives", "old", "removed 14 Aug 2026",
                          build.button("Delete", "danger js-delete", data_host="old", data_name="old")) in fleet
    # no page for a removed server, exactly as before
    assert 'id="host-old"' not in html
    assert 'id="del-ovl"' in html


def test_with_nothing_removed_the_block_is_there_empty_and_hidden(db):
    reporting(db, "box", document(listening=[SSHD]))
    assert '<div class="fgone" hidden></div>' in fleet_section(rl.render(db, now=NOW))


def test_the_newest_removal_is_first(db):
    add_host(db, "first-out", [], revoked=True)
    add_host(db, "last-out", [], revoked=True)
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET revoked_at = ? WHERE name = 'first-out'",
                ((NOW - timedelta(days=3)).isoformat(),))
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert removed_names(html) == ["last-out", "first-out"]
    assert "removed 11 Aug 2026" in fleet_section(html)


def test_another_workspaces_removed_server_is_not_listed(db):
    add_host(db, "mine", [], revoked=True, workspace_id=1)
    add_host(db, "theirs", [], revoked=True, workspace_id=2)
    assert removed_names(rl.render(db, now=NOW, workspace_id=1)) == ["mine"]
    assert removed_names(rl.render(db, now=NOW, workspace_id=2)) == ["theirs"]


def test_a_removed_servers_name_is_escaped_in_the_list(db):
    add_host(db, "a<b", [], revoked=True)
    fleet = fleet_section(rl.render(db, now=NOW))
    assert 'data-host="a&lt;b" data-name="a&lt;b"' in fleet
    assert "<b>a&lt;b</b>" in fleet and "a<b" not in fleet


def test_the_live_remove_button_carries_the_last_report_and_whether_it_still_reports(db):
    reporting(db, "box", document(listening=[SSHD]))
    assert REMOVE_BUTTON.format(n="box", about=' data-kind="agent" data-last="2m ago" data-live="1"') in settings_of(db)


def test_a_silent_agent_carries_its_last_report_without_the_warning(db):
    reporting(db, "quiet", document(listening=[SSHD]), minutes=120)
    assert REMOVE_BUTTON.format(n="quiet", about=' data-kind="agent" data-last="2h 0m ago"') in settings_of(db, "quiet")


def test_a_never_reported_server_carries_no_last_report(db):
    add_host(db, "fresh", [])
    section = host_section(rl.render(db, now=NOW), "fresh")
    assert REMOVE_BUTTON.format(n="fresh", about=' data-kind="agent"') in section


def test_an_address_only_server_is_marked_so_the_window_shows_no_command(db):
    add_address_host(db, "addr")
    section = tab_body(host_section(rl.render(db, now=NOW), "addr"), "addr", "settings")
    assert REMOVE_BUTTON.format(n="addr", about=' data-kind="address"') in section


# ----------------------------------------------------------- in the browser

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>delete drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
var PAGE='';
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    // Wait for what the act should show rather than one fixed tick after it:
    // the page paints after a promise chain, and under load one tick lost the
    // race once (d7, 2026-09-14). Gives up after two seconds, so a real
    // failure still fails on the assertion.
    var until=async function(cond){var t0=Date.now();
      while(!cond()&&Date.now()-t0<2000)await tick();};
    var result={errs:[],posts:[],gets:0};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    // A refresh is answered with this same page rendered a moment later, so
    // its stamp differs, the refresh swaps that piece and wires the page
    // again, which is the state the Remove window failed in on 2026-09-13.
    w.fetch=function(url,opts){
      opts=opts||{};
      if((opts.method||'GET')==='POST'){
        result.posts.push({url:String(url),body:opts.body||null});
        return Promise.resolve({ok:true,redirected:false,status:204,
          json:function(){return Promise.resolve({})},text:function(){return Promise.resolve('')}});
      }
      result.gets+=1;
      return Promise.resolve({ok:true,redirected:false,status:200,
        text:function(){return Promise.resolve(PAGE.replace('rendered ','rendered again '))}});
    };
    var gone=function(){return d.querySelector('#fleet .fgone')};
    var names=function(){return Array.prototype.map.call(
      d.querySelectorAll('#fleet .js-delete'),function(b){return b.dataset.host})};
    var last=function(){return result.posts[result.posts.length-1]};
    // the removed list and the delete window
    result.atStart={hidden:gone().hidden,rows:names(),
      table:Array.prototype.map.call(d.querySelectorAll('#fleet .row[data-host]'),
        function(r){return r.dataset.host})};
    var dovl=d.getElementById('del-ovl'), dgo=d.getElementById('del-go'), din=d.getElementById('del-input');
    d.querySelector('#fleet .js-delete[data-host="old"]').click();
    await until(function(){return dovl.classList.contains('on')});
    result.delWindow={open:dovl.classList.contains('on'),name:d.getElementById('del-name').textContent,
      chip:d.getElementById('del-name2').textContent,disabled:dgo.disabled};
    din.value='wrong';din.dispatchEvent(new w.Event('input'));
    result.delWrong=dgo.disabled;
    din.value='old';din.dispatchEvent(new w.Event('input'));
    result.delRight=dgo.disabled;
    dgo.click();
    await until(function(){return !dovl.classList.contains('on')&&gone().hidden});
    result.afterDelete={closed:!dovl.classList.contains('on'),hidden:gone().hidden,rows:names(),post:last()};
    // one refresh on the clock, which swaps the stamp and wires the page again
    var gets=result.gets;
    await tick(61000);
    await until(function(){return result.gets>gets});
    result.refreshed=result.gets>gets;
    // the remove window on an agent host still reporting
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick();
    d.getElementById('tb-box-settings').click(); await tick();
    d.querySelector('#host-box .hsel.h-server').click();
    var ovl=d.getElementById('rm-ovl'), go=d.getElementById('rm-go'), rin=d.getElementById('rm-input');
    d.querySelector('#host-box .js-remove').click();
    await until(function(){return ovl.classList.contains('on')});
    var lastRow=d.getElementById('rm-last'), cmd=d.getElementById('rm-cmd');
    var cancel=ovl.querySelector('.acts [data-close]');
    result.rmWindow={open:ovl.classList.contains('on'),name:d.getElementById('rm-name').textContent,
      lastHidden:lastRow.hidden,last:d.getElementById('rm-last-v').textContent,
      warn:lastRow.classList.contains('warn'),cmdHidden:cmd.hidden,
      cmd:d.getElementById('rm-cmd-v').textContent,cancel:cancel.textContent,disabled:go.disabled};
    rin.value='wrong';rin.dispatchEvent(new w.Event('input'));
    result.rmWrong=go.disabled;
    rin.value='box';rin.dispatchEvent(new w.Event('input'));
    result.rmRight=go.disabled;
    go.click();
    await until(function(){return cancel.textContent==='Close'});
    result.afterRemove={open:ovl.classList.contains('on'),cancel:cancel.textContent,
      inputDisabled:rin.disabled,goDisabled:go.disabled,view:(d.querySelector('.view.on')||{}).id,
      rowHidden:d.querySelector('#fleet .row[data-host="box"]').style.display==='none',post:last()};
    gets=result.gets;
    cancel.click();
    await until(function(){return result.gets>gets});
    result.afterClose={open:ovl.classList.contains('on'),refreshed:result.gets>gets};
    // an address-only server: no agent, so neither row
    d.querySelector('#fleet .row[data-host="addr"]').click(); await tick();
    d.getElementById('tb-addr-settings').click(); await tick();
    d.querySelector('#host-addr .hsel.h-server').click();
    d.querySelector('#host-addr .js-remove').click();
    await until(function(){return ovl.classList.contains('on')});
    result.addrWindow={open:ovl.classList.contains('on'),lastHidden:lastRow.hidden,
      cmdHidden:cmd.hidden,cancel:cancel.textContent,disabled:go.disabled};
    out.textContent=JSON.stringify(result);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
fetch('live.html').then(function(r){return r.text()}).then(function(t){PAGE=t;f.src='live.html'});
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
             "--virtual-time-budget=90000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert result.get("errs") == [], result
    return result


def test_delete_and_remove_in_the_browser(tmp_path, db):
    reporting(db, "box", document(listening=[SSHD]))
    add_host(db, "old", [], revoked=True)
    add_address_host(db, "addr")
    r = drive(tmp_path, rl.render(db, now=NOW), HARNESS)

    # the removed server is in the list and not in the table
    assert r["atStart"] == {"hidden": False, "rows": ["old"], "table": ["addr", "box"]}
    # Delete: the window, the typed name, the request, the row gone at once
    assert r["delWindow"] == {"open": True, "name": "old", "chip": "old", "disabled": True}
    assert r["delWrong"] is True and r["delRight"] is False
    assert r["afterDelete"] == {"closed": True, "hidden": True, "rows": [],
                                "post": {"url": "/api/admin/hosts/old/delete", "body": None}}
    # the page refreshed itself once in between, and Remove still enables
    assert r["refreshed"] is True
    assert r["rmWindow"] == {"open": True, "name": "box", "lastHidden": False, "last": "2m ago",
                             "warn": True, "cmdHidden": False, "cmd": "sudo whichports-uninstall",
                             "cancel": "Cancel", "disabled": True}
    assert r["rmWrong"] is True and r["rmRight"] is False
    # Remove: the row goes and the fleet is shown, the window stays with the
    # command, Cancel reads Close, and closing it asks for the page
    assert r["afterRemove"] == {"open": True, "cancel": "Close", "inputDisabled": True,
                                "goDisabled": True, "view": "fleet", "rowHidden": True,
                                "post": {"url": "/api/admin/hosts/box/revoke", "body": None}}
    assert r["afterClose"] == {"open": False, "refreshed": True}
    # an address-only server: the window without either row
    assert r["addrWindow"] == {"open": True, "lastHidden": True, "cmdHidden": True,
                               "cancel": "Cancel", "disabled": True}
