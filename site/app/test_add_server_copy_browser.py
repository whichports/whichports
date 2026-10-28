"""A click on the command in the Add server window copies the command that
is shown, in a real browser (docs/RECORD.md 4.362, 4.371).

The box copied the command the control plane handed out for the agent's
card. The try-it card asks the control plane for nothing, so on that card a
click copied nothing and nothing flashed, under a label that says click to
copy (measured 2026-10-04).

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch. The
clipboard is a stand-in too, since a headless browser has none to give.

    Run from site/: python3 -m pytest app/test_add_server_copy_browser.py
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
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
INSTALL = "curl -fsSL https://get.whichports.com/install.sh | sudo sh -s -- enroll"

# The creation of an agent's server is answered only when the test lets it,
# so the moment before the answer can be looked at.
STUB = """<script>
window.__copied=[];window.__release=null;
Object.defineProperty(navigator,'clipboard',{configurable:true,value:{
  writeText:function(t){window.__copied.push(String(t));return Promise.resolve()}}});
window.fetch=function(url,opts){
  var u=String(url);
  var answer=function(status,body){
    return {ok:status>=200&&status<300,status:status,redirected:false,
      json:function(){return Promise.resolve(body||{})},
      text:function(){return Promise.resolve('')}}};
  if(opts&&opts.method==='POST'&&u==='/api/admin/hosts')
    return new Promise(function(resolve){window.__release=function(){
      resolve(answer(200,{id:7,name:'new-1',install_command:%(install)s}))}});
  return Promise.resolve(answer(opts&&opts.method==='POST'?204:200,
                                {name:'new-1',reported_at:null,probed_at:null}));
};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the command copies</title>
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
    var box=d.getElementById('add-cmd');
    var click=async function(){
      var before=w.__copied.length;
      box.click(); await tick(100);
      return {shown:box.textContent,copied:w.__copied.slice(before),
              flashed:box.classList.contains('copied')}};
    d.querySelector('.js-add').click(); await tick(100);
    d.getElementById('add-linux').click(); await tick();
    // The try-it card.
    d.getElementById('add-try').click(); await tick();
    seen.tryIt=await click();
    await tick(1600);
    seen.flashOverAfter=box.classList.contains('copied');
    // The agent's card, before the control plane has answered.
    d.getElementById('add-agent').click(); await tick();
    seen.waiting=await click();
    w.__release(); await tick(100);
    seen.agent=await click();
    // And back to the try-it card.
    d.getElementById('add-try').click(); await tick();
    seen.tryItAgain=await click();
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


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
    (site / "live.html").write_text(
        page.replace("<head>", "<head>" + STUB % {"install": json.dumps(INSTALL)}, 1),
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
             "--virtual-time-budget=15000", "--dump-dom",
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
    return drive(tmp_path_factory.mktemp("copy"))


def test_a_click_on_the_try_it_command_copies_it(seen):
    got = seen["tryIt"]
    assert got["shown"] == build.TRY_COMMAND
    assert got["copied"] == [build.TRY_COMMAND]


def test_the_box_flashes_as_every_copied_box_does_and_stops(seen):
    assert seen["tryIt"]["flashed"] is True
    assert seen["flashOverAfter"] is False


def test_nothing_is_copied_while_the_command_is_still_being_made(seen):
    """The box says the credential is being created. That is not a command."""
    got = seen["waiting"]
    assert got["shown"] != INSTALL and got["shown"] != build.TRY_COMMAND
    assert got["copied"] == []


def test_the_agents_command_is_copied_as_before(seen):
    got = seen["agent"]
    assert got["shown"] == INSTALL
    assert got["copied"] == [INSTALL]


def test_each_card_copies_its_own_command(seen):
    """Back on the try-it card after the agent's: never the agent's command,
    which carries a credential."""
    assert seen["tryItAgain"]["copied"] == [build.TRY_COMMAND]
