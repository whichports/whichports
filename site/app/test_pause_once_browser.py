"""A second click on Pause while the first is still on its way is not sent,
in a real browser (docs/RECORD.md 4.362, 4.371).

The switch flips on the click and posts behind it. Nothing held it while the
answer was out, so a double click posted paused and then not paused, and the
server ended as it began with the person thinking they had paused it
(measured 2026-10-04: two posts).

    Run from site/: python3 -m pytest app/test_pause_once_browser.py
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

# A pause is answered only when the test lets it, so the time between the
# click and the answer can be looked at. window.__refuse makes it a refusal.
STUB = """<script>
window.__posts=[];window.__waiting=[];window.__refuse=false;window.__page=%(page)s;
window.fetch=function(url,opts){
  var u=String(url);
  if(opts&&opts.method==='POST'){
    window.__posts.push(u+' '+(opts.body||''));
    return new Promise(function(resolve){window.__waiting.push(function(){
      var status=window.__refuse?409:204;
      resolve({ok:status===204,status:status,redirected:false,
        json:function(){return Promise.resolve({detail:'Not now.'})}})})});
  }
  return Promise.resolve({ok:true,status:200,redirected:false,
    text:function(){return Promise.resolve(window.__page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>pause once</title>
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
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
    d.querySelector('label[for="tb-box-settings"]').click(); await tick();
    var sw=function(){return d.querySelector('#host-box .js-pause')};
    var look=function(){return {posts:w.__posts.slice(),paused:!sw().classList.contains('off'),
      looksOff:sw().disabled}};
    var answer=async function(){w.__waiting.splice(0).forEach(function(go){go()}); await tick(200)};
    seen.asSent=look();
    // Two clicks before any answer.
    sw().click(); sw().click(); await tick(100);
    seen.twoClicks=look();
    await answer();
    seen.answered=look();
    // Once it is answered, a click is a click again.
    sw().click(); await tick(100); await answer();
    seen.clickedAgain=look();
    // A refusal puts the switch back, and it can be tried again.
    w.__refuse=true;
    sw().click(); sw().click(); await tick(100);
    seen.refusedWaiting=look();
    await answer();
    seen.refused=look();
    w.__refuse=false;
    sw().click(); await tick(100); await answer();
    seen.afterRefusal=look();
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""

PAUSE = '/api/admin/hosts/box/pause {"paused":true}'
UNPAUSE = '/api/admin/hosts/box/pause {"paused":false}'


def drive(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
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
             "--virtual-time-budget=10000", "--dump-dom",
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
    return drive(tmp_path_factory.mktemp("pause"))


def test_the_server_is_sent_not_paused(seen):
    assert seen["asSent"] == {"posts": [], "paused": False, "looksOff": False}


def test_two_clicks_before_an_answer_post_once(seen):
    assert seen["twoClicks"]["posts"] == [PAUSE]


def test_the_switch_shows_paused_at_once_and_stays_so(seen):
    assert seen["twoClicks"]["paused"] is True
    assert seen["answered"]["paused"] is True
    assert seen["answered"]["posts"] == [PAUSE]


def test_the_switch_never_looks_switched_off_while_it_waits(seen):
    """It is held by a mark the eye cannot see. A disabled switch is drawn
    grey, which is how a planned one is drawn."""
    assert seen["twoClicks"]["looksOff"] is False
    assert seen["refusedWaiting"]["looksOff"] is False


def test_after_the_answer_a_click_is_a_click_again(seen):
    assert seen["clickedAgain"]["posts"] == [PAUSE, UNPAUSE]
    assert seen["clickedAgain"]["paused"] is False


def test_a_refusal_puts_the_switch_back_and_it_can_be_tried_again(seen):
    assert seen["refusedWaiting"]["posts"] == [PAUSE, UNPAUSE, PAUSE]
    assert seen["refused"]["paused"] is False
    assert seen["afterRefusal"]["posts"] == [PAUSE, UNPAUSE, PAUSE, PAUSE]
    assert seen["afterRefusal"]["paused"] is True
