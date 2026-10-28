"""Adding a server by its address makes the server once, and only when there
is an address to prove, in a real browser (docs/RECORD.md 4.362, 4.363).

The window made the server first and looked at the address afterwards. So
Create with no address typed left a server behind and said "An address is
needed", and the next click on Create asked for the same server again, which
the control plane refuses because the name is taken (measured 2026-10-04).

What holds now: the name, the address and the way to prove it are looked at
before anything is made, and a server this window already made is not made a
second time when the control plane refuses its address.

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch.

    Run from site/: python3 -m pytest app/test_add_by_address_browser.py
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

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
REFUSAL = "That address cannot be probed."
YES = "192.0.2.10 proved by token file until 13 Sep"

# Every POST is written down. Making a server answers with the name it was
# asked for. An address is refused while window.__refuse is set, and takes a
# challenge otherwise.
STUB = """<script>
window.__posts=[];window.__refuse=false;
window.fetch=function(url,opts){
  var u=String(url);
  var answer=function(status,body){
    return Promise.resolve({ok:status>=200&&status<300,status:status,redirected:false,
      json:function(){return Promise.resolve(body||{})},
      text:function(){return Promise.resolve('')}})};
  if(opts&&opts.method==='POST'){
    window.__posts.push(u+(opts.body?' '+opts.body:''));
    if(u==='/api/admin/hosts')
      return answer(200,{id:9,name:JSON.parse(opts.body).name});
    if(/\\/addresses$/.test(u))
      return window.__refuse?answer(400,{detail:%(refusal)s})
        :answer(200,{id:7,token:'tok-1',publish_at:'http://192.0.2.9/.well-known/proof'});
    if(/\\/verify$/.test(u))
      return answer(200,{ok:true,code:'proved',detail:%(yes)s});
    return answer(204);
  }
  return answer(200);
};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>add a server by its address</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var type=function(id,text){var el=d.getElementById(id);el.value=text;
      el.dispatchEvent(new w.Event('input',{bubbles:true}))};
    var made=function(){return w.__posts.filter(function(u){
      return u.indexOf('/api/admin/hosts ')===0})};
    var started=function(){return w.__posts.filter(function(u){
      return /\\/addresses /.test(u)})};
    var go=d.getElementById('add-addr-go');
    var shown=function(el){return !!el&&!el.hidden&&!el.closest('[hidden]')};
    var win=d.getElementById('add-ovl');
    var look=function(){return {made:made(),started:started(),
      says:d.getElementById('add-addr-err').textContent,button:go.textContent,
      token:d.getElementById('add-addr-token').textContent,
      goShown:shown(go),
      foot:Array.prototype.filter.call(win.querySelectorAll('.m-foot button'),shown)
        .map(function(b){return b.textContent.trim()+(b.classList.contains('pri')?' (primary)':'')}),
      fixed:d.getElementById('add-addr-address').disabled,
      ways:Array.prototype.map.call(win.querySelectorAll('#add-addr-stage .m-card'),function(c){
        return c.getAttribute('aria-disabled')==='true'}),
      result:d.getElementById('add-addr-result').textContent,
      scrolls:win.querySelector('.modal').scrollHeight>win.querySelector('.modal').clientHeight,
      footInView:(function(){
        var box=win.querySelector('.modal').getBoundingClientRect();
        return Array.prototype.filter.call(win.querySelectorAll('.m-foot button'),shown)
          .every(function(b){var r=b.getBoundingClientRect();
            return r.top>=box.top&&r.bottom<=box.bottom})})()}};
    var open=async function(){
      d.querySelector('.js-add').click(); await tick(100);
      d.getElementById('add-linux').click(); await tick();
      d.getElementById('add-addr').click(); await tick()};
    await open();
    seen.picked=look();
    // 1. A name and nothing else.
    type('add-addr-name','edge');
    go.click(); await tick(200);
    seen.noAddress=look();
    // 2. An address, and no way to prove it chosen.
    type('add-addr-address','192.0.2.9');
    go.click(); await tick(200);
    seen.noMethod=look();
    // 3. All three, and the control plane refuses the address.
    d.getElementById('add-addr-http').click(); await tick();
    w.__refuse=true;
    go.click(); await tick(200);
    seen.refused=look();
    // 4. The address put right, on the same window.
    w.__refuse=false;
    type('add-addr-address','192.0.2.10');
    go.click(); await tick(200);
    seen.putRight=look();
    // 4b. Verify, and the control plane says yes.
    go.click(); await tick(200);
    seen.verified=look();
    // 5. The window closed and opened again, for another server.
    d.getElementById('add-close').click(); await tick(300);
    await open();
    type('add-addr-name','edge-two');
    type('add-addr-address','192.0.2.11');
    d.getElementById('add-addr-http').click(); await tick();
    go.click(); await tick(200);
    seen.secondServer=look();
    // 6. A refusal, and then another name typed over the first.
    d.getElementById('add-close').click(); await tick(300);
    w.__posts.length=0;
    await open();
    type('add-addr-name','north');
    type('add-addr-address','192.0.2.12');
    d.getElementById('add-addr-http').click(); await tick();
    w.__refuse=true;
    go.click(); await tick(200);
    w.__refuse=false;
    type('add-addr-name','south');
    go.click(); await tick(200);
    seen.renamed=look();
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def a_page(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
    return rl.render(path, now=NOW)


def drive(tmp_path, page):
    site = tmp_path / "www"
    site.mkdir()
    assert page.count("<head>") == 1
    (site / "live.html").write_text(
        page.replace("<head>", "<head>" + STUB % {"refusal": json.dumps(REFUSAL),
                                                    "yes": json.dumps(YES)}, 1),
        encoding="utf-8")
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
    tmp_path = tmp_path_factory.mktemp("add-by-address")
    return drive(tmp_path, a_page(tmp_path))


def made(name):
    return '/api/admin/hosts {"name":"%s","kind":"address"}' % name


def test_no_server_is_made_while_no_address_is_typed(seen):
    got = seen["noAddress"]
    assert got["made"] == []
    assert got["says"] == "An address is needed"
    assert got["button"] == "Create"


def test_no_server_is_made_while_no_way_to_prove_it_is_chosen(seen):
    got = seen["noMethod"]
    assert got["made"] == []
    assert got["says"] == "Choose how to prove it"
    assert got["button"] == "Create"


def test_with_all_three_the_server_is_made_and_its_address_is_asked_for(seen):
    got = seen["refused"]
    assert got["made"] == [made("edge")]
    assert got["started"] == [
        '/api/admin/hosts/edge/addresses {"address":"192.0.2.9","method":"http-token"}']


def test_a_refused_address_says_the_control_planes_own_words(seen):
    got = seen["refused"]
    assert got["says"] == REFUSAL
    assert got["button"] == "Create"


def test_a_server_this_window_made_is_not_made_again(seen):
    """The address is put right and Create is clicked again. The server is
    there already, so only its address is asked for, on that server."""
    got = seen["putRight"]
    assert got["made"] == [made("edge")]
    assert got["started"][-1] == (
        '/api/admin/hosts/edge/addresses {"address":"192.0.2.10","method":"http-token"}')
    assert len(got["started"]) == 2
    assert got["says"] == ""
    assert got["button"] == "Verify"
    assert got["token"] == "tok-1"


def test_a_window_opened_again_makes_the_next_server(seen):
    got = seen["secondServer"]
    assert got["made"] == [made("edge"), made("edge-two")]
    assert got["started"][-1].startswith("/api/admin/hosts/edge-two/addresses ")


def test_another_name_typed_after_a_refusal_is_another_server(seen):
    """The first server was made under the first name and stays as it is. A
    different name is a different server, and it is never proved under the
    first one's name."""
    got = seen["renamed"]
    assert got["made"] == [made("north"), made("south")]
    assert got["started"][-1].startswith("/api/admin/hosts/south/addresses ")


# The same form as the address window's (test_address_window_browser.py), in
# this window's foot: one primary button at every step (docs/RECORD.md 4.379).

def test_create_is_absent_until_a_way_is_picked(seen):
    assert seen["picked"]["goShown"] is False
    assert seen["picked"]["foot"] == ["Cancel"]
    assert seen["noMethod"]["goShown"] is False
    assert seen["refused"]["goShown"] is True


def test_the_fields_are_fixed_once_a_token_is_out(seen):
    assert seen["refused"]["fixed"] is False and seen["refused"]["ways"] == [False, False]
    assert seen["putRight"]["fixed"] is True and seen["putRight"]["ways"] == [True, True]


def test_after_the_yes_done_stands_alone(seen):
    got = seen["verified"]
    assert got["result"] == YES
    assert got["foot"] == ["Done (primary)"]


def test_the_foot_holds_one_primary_button_at_every_step(seen):
    feet = [look["foot"] for look in seen.values() if isinstance(look, dict) and "foot" in look]
    assert len(feet) >= 8
    for foot in feet:
        assert sum(word.endswith("(primary)") for word in foot) <= 1, foot
    assert seen["putRight"]["foot"] == ["Done", "Verify (primary)"]


def test_the_foot_stays_in_view_while_the_form_scrolls(seen):
    """With a token out the form is taller than the window, so it scrolls in
    its box. The button that acts stays where it can be seen: it used to be
    under the fold (measured 2026-10-06, docs/RECORD.md 4.379)."""
    got = seen["putRight"]
    assert got["scrolls"] is True
    assert got["footInView"] is True
    assert all(look["footInView"] for look in seen.values()
               if isinstance(look, dict) and "footInView" in look)
