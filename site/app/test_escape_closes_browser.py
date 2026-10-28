"""Escape closes the window that is open, every one of them, in a real
browser (docs/RECORD.md 4.362, 4.371).

Measured on 2026-10-04: nine windows, each opened by its own control, and
Escape closed none. Only the small confirm dialog answered the key. A window
is closed by Escape through its own cross, so whatever a window does when it
is closed on a click, it does on the key too: the Add server window asks for
the page when it made a server.

They are eight since layout B: the Add channel and the Add integration
windows are one, opened by the one Add button on Integrations
(docs/screens/alerts/SPEC-layout-b.md).

    Run from site/: python3 -m pytest app/test_escape_closes_browser.py
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

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
import test_integrations_live as til  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
UVICORN = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
           "process_name": "uvicorn", "pid": 7}

STUB = """<script>
window.__posts=[];window.__gets=0;window.__page=%(page)s;
window.fetch=function(url,opts){
  var u=String(url);
  var answer=function(status,body){
    return Promise.resolve({ok:status>=200&&status<300,status:status,redirected:false,
      json:function(){return Promise.resolve(body||{})},
      text:function(){return Promise.resolve(window.__page)}})};
  if(opts&&opts.method==='POST'){
    window.__posts.push(u);
    if(u==='/api/admin/hosts') return answer(200,{id:7,name:'new-1',install_command:'curl install'});
    return answer(204);
  }
  if(u.indexOf('/api/admin/')===0) return answer(200,{name:'new-1',reported_at:null,probed_at:null});
  window.__gets++;
  return answer(200);
};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>escape closes the window</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={windows:{}};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var on=function(id){var o=d.getElementById(id);return !!(o&&o.classList.contains('on'))};
    var escape=function(target){
      (target||d.activeElement||d.body).dispatchEvent(
        new w.KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}))};
    var tryWindow=async function(name,id,opener){
      var r={found:!!opener};
      if(opener){
        opener.click(); await tick(150);
        r.opened=on(id);
        escape(); await tick(150);
        r.openAfterEscape=on(id);
        var o=d.getElementById(id); if(o)o.classList.remove('on');
        await tick(50);
      }
      seen.windows[name]=r;
    };
    // Nothing open: the key does nothing at all.
    escape(d.body); await tick(100);
    seen.nothingOpen={posts:w.__posts.length,gets:w.__gets,
                      open:d.querySelectorAll('.ovl.on').length};
    // Alerts held the Add channel button. It opens no window now, so what
    // would open one there is counted, and so are the Add window's controls.
    d.querySelector('[data-v="alerts"]').click(); await tick();
    seen.alertsOpeners=d.querySelectorAll('#alerts [data-open]').length;
    d.querySelector('[data-v="integrations"]').click(); await tick();
    seen.addOpeners=d.querySelectorAll('[data-open="conn-ovl"]').length;
    await tryWindow('add','conn-ovl',d.querySelector('#integrations [data-open="conn-ovl"]'));
    await tryWindow('provider token','ptok-ovl',d.querySelector('.js-prov-token'));
    d.querySelector('[data-v="settings"]').click(); await tick();
    await tryWindow('password','pw-ovl',d.querySelector('[data-open="pw-ovl"]'));
    await tryWindow('two factor','tfa-ovl',d.querySelector('[data-open="tfa-ovl"]'));
    d.querySelector('[data-v="fleet"]').click(); await tick();
    await tryWindow('add server','add-ovl',d.querySelector('.js-add'));
    await tryWindow('delete server','del-ovl',d.querySelector('.js-delete'));
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(150);
    seen.windows['first look']={found:true,opened:on('fv-box')};
    escape(); await tick(150);
    seen.windows['first look'].openAfterEscape=on('fv-box');
    await tryWindow('remove server','rm-ovl',d.querySelector('#host-box .js-remove'));
    // The key pressed in a field of a window closes that window.
    d.querySelector('[data-v="settings"]').click(); await tick();
    d.querySelector('[data-open="pw-ovl"]').click(); await tick(150);
    var current=d.getElementById('pw-current'); current.focus(); current.value='typed';
    escape(current); await tick(150);
    seen.fromAField={open:on('pw-ovl')};
    // A field on the page keeps its own meaning for the key, with no window open.
    d.querySelector('[data-v="fleet"]').click(); await tick();
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(150);
    Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
    d.querySelector('label[for="tb-box-settings"]').click(); await tick();
    var name=d.querySelector('#host-box .js-display');
    name.focus(); name.value='half typed'; name.dispatchEvent(new w.Event('input',{bubbles:true}));
    escape(name); await tick(150);
    seen.pageField={value:name.value,open:d.querySelectorAll('.ovl.on').length};
    // The Add server window, closed by the key after it made a server: it
    // asks for the page, as it does when closed on a click.
    d.querySelector('[data-v="fleet"]').click(); await tick();
    d.querySelector('.js-add').click(); await tick(150);
    d.getElementById('add-linux').click(); await tick();
    d.getElementById('add-agent').click(); await tick(300);
    var gets=w.__gets;
    escape(); await tick(500);
    seen.afterMaking={open:on('add-ovl'),asked:w.__gets-gets};
    // The confirm dialog still answers the key itself, once.
    w.askConfirm('Sure','Really','Yes',function(){seen.confirmed=true});
    await tick(100);
    seen.confirm={opened:on('ask')};
    escape(); await tick(150);
    seen.confirm.openAfterEscape=on('ask');
    seen.confirm.saidYes=!!seen.confirmed;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""

WINDOWS = ["add", "provider token", "password", "two factor",
           "add server", "delete server", "first look", "remove server"]


def drive(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD, UVICORN]))
    trl.add_channel(path)
    trl.add_host(path, "oldbox", [], revoked=True)
    til.connect(path, 1)
    then = NOW - timedelta(minutes=20)
    trl.probe_result(path, "box", 22, "v4", "connect_succeeded", measured_at=then)
    trl.probe_result(path, "box", 8410, "v4", "connect_succeeded", measured_at=then)
    page = rl.render(path, now=NOW)
    site = tmp_path / "www"
    site.mkdir()
    assert page.count("<head>") == 1
    embedded = json.dumps(page).replace("</", "<\\/")
    (site / "live.html").write_text(
        page.replace("<head>", "<head>" + STUB % {"page": embedded}, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=20000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def seen(tmp_path_factory):
    return drive(tmp_path_factory.mktemp("escape"))


def test_every_window_was_found_and_opened_by_its_own_control(seen):
    """What the rest of this file rests on."""
    assert sorted(seen["windows"]) == sorted(WINDOWS)
    for name, got in seen["windows"].items():
        assert got["found"] and got["opened"], name
    # The Add window has the one control, on Integrations, and Alerts has none.
    assert (seen["addOpeners"], seen["alertsOpeners"]) == (1, 0)


@pytest.mark.parametrize("name", WINDOWS)
def test_escape_closes_the_window(seen, name):
    assert seen["windows"][name]["openAfterEscape"] is False


def test_escape_with_nothing_open_does_nothing(seen):
    assert seen["nothingOpen"] == {"posts": 0, "gets": 0, "open": 0}


def test_escape_in_a_field_of_a_window_closes_that_window(seen):
    assert seen["fromAField"] == {"open": False}


def test_a_field_on_the_page_keeps_its_own_escape(seen):
    """The display name's field puts back what it held, as before."""
    assert seen["pageField"] == {"value": "", "open": 0}


def test_a_window_closed_by_the_key_does_what_it_does_on_a_click(seen):
    assert seen["afterMaking"] == {"open": False, "asked": 1}


def test_the_confirm_dialog_still_cancels_on_the_key(seen):
    assert seen["confirm"] == {"opened": True, "openAfterEscape": False, "saidYes": False}
