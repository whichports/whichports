"""Three controls that must still work after the page has refreshed itself,
and one click that must not stop it from refreshing, in a real browser.

Found by the review of 2026-09-21 and each measured before it was fixed
(docs/RECORD.md 4.199):

- a click on a tab left a hidden radio focused, and `busy()` took any focused
  INPUT for somebody typing, so the quiet refresh stopped;
- Dark, Light and System on the Settings screen were bound once, and the
  generic segmented-control pass that runs on every refresh replaced them;
- the server name field added its key listener on every refresh, so Enter
  posted the rename once per refresh the page had lived through.

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch. Every GET
answers the same page with a new render stamp, so every refresh finds a
change and re-runs every wire pass, which is what production does.

    Run from site/: python3 -m pytest app/test_refresh_survivors_browser.py
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW

STUB = """<script>
window.__posts=[];window.__gets=0;
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push(String(url));
    return Promise.resolve({ok:true,status:204,
      json:function(){return Promise.resolve({})}});
  }
  window.__gets++;
  var page=%(page)s.replace('class="pgstamp">','class="pgstamp">refresh '+window.__gets+' ');
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>refresh survivors</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var seen={};
    // The server's page first, as a person gets there, or its tabs sit in a
    // view that is not drawn and nothing in it can take focus.
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick();
    // 1. A click on a tab, then nothing: the minute refresh must still come.
    d.querySelector('label[for="tb-box-services"]').click();
    d.getElementById('tb-box-services').focus();   // what Chrome does on a real click
    seen.focused=d.activeElement&&d.activeElement.id;
    await tick(61000); await tick(200);
    seen.getsAfterTabClick=w.__gets;
    await tick(61000); await tick(200);
    seen.getsAfterTwoMinutes=w.__gets;
    // 2. Appearance, after those refreshes.
    d.activeElement&&d.activeElement.blur();
    d.querySelector('.js-mode-light').click(); await tick();
    seen.modeAfterLight=d.documentElement.dataset.mode||'';
    d.querySelector('.js-mode-dark').click(); await tick();
    seen.modeAfterDark=d.documentElement.dataset.mode||'';
    // 3. A display name saved with Enter, after those refreshes: one POST.
    var field=d.querySelector('#host-box .js-display');
    field.focus(); field.value='Box two';
    field.dispatchEvent(new w.Event('input',{bubbles:true}));
    field.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Enter',bubbles:true}));
    await tick(300);
    seen.namePosts=w.__posts.filter(function(u){return u.indexOf('/display-name')>=0}).length;
    out.textContent=JSON.stringify(seen);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
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
    embedded = json.dumps(page).replace("</", "<\\/")
    assert page.count("<head>") == 1
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
             "--virtual-time-budget=140000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


def test_the_page_keeps_refreshing_and_its_controls_keep_working(tmp_path):
    got = drive(tmp_path, a_page(tmp_path))
    # The tab's hidden radio really was focused, as after a real click.
    assert got["focused"] == "tb-box-services"
    assert got["getsAfterTabClick"] >= 1, "a click on a tab stopped the quiet refresh"
    assert got["getsAfterTwoMinutes"] > got["getsAfterTabClick"]
    # Appearance still does something after the page has refreshed twice.
    assert got["modeAfterLight"] == "light"
    assert got["modeAfterDark"] == ""
    # And Enter in the Name field saves once, however long the page lived.
    assert got["namePosts"] == 1
