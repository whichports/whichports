"""A kind switched off in a destination's Edit is said saved only when the
server's answer holds it, in a real browser.

The second big test, finding E20 (25 October 2026): on a Webhook row, Edit,
the address typed again, one kind switched off, Save. The page posted the
kinds to /destination, the route wrote the address alone, answered 200, and
the window said "Saved." over a row that kept every kind. The route writes
the kinds now (controlplane/app/channels.py, set_destination) and answers
the kinds the row takes as stored. The window holds that answer to what it
sent: the same kinds, "Saved." and the row takes them. Anything else, and
the window stays open and says so at its foot.

The stand-in server is a script put in the page's own head, before the
page's script, so the page's wrapper of fetch wraps it.

    Run from site/: python3 -m pytest app/test_edit_kinds_kept_browser.py
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
EVERY_KIND = ["finding changed", "silent", "outside view stale", "cve"]

# Answers the POST with whatever the harness put in window.__answer, and
# keeps each POST's address and body on window.__posts.
STUB = """<script>
window.__posts=[];
window.__answer={status:200,body:{}};
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST')window.__posts.push({url:String(url),body:String(opts.body||'')});
  var a=window.__answer;
  return Promise.resolve({ok:a.status>=200&&a.status<300,status:a.status,redirected:false,
    json:function(){return Promise.resolve(a.body)},text:function(){return Promise.resolve('')}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>edit keeps its kinds</title>
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
    var list=function(sel){return Array.prototype.slice.call(d.querySelectorAll(sel))};
    var ovl=d.getElementById('conn-ovl');
    var rowKinds=function(){var b=list('.chanp .crow .rm-edit').filter(function(b){
      return b.dataset.label==='ops'})[0]; return b?b.dataset.events:null};
    var look=function(){var t=d.getElementById('toast');
      return {open:ovl.classList.contains('on'),
        toast:t.classList.contains('on')?t.textContent:'',
        foot:d.getElementById('conn-err').textContent,
        row:rowKinds()}};
    // Edit on the row, the address typed again, the first kind switched
    // off, and Save, with the stand-in answering `answer`.
    var edit=async function(answer){
      d.getElementById('toast').classList.remove('on');
      w.__answer=answer;
      list('.rm-edit').filter(function(b){return b.dataset.label==='ops'})[0].click(); await tick(100);
      var field=d.querySelector('#chan-webhook .js-dest');
      field.value='https://hooks.example.invalid/x';
      field.dispatchEvent(new Event('input',{bubbles:true}));
      var sw=list('#conn-ovl .js-event').filter(function(s){
        return s.dataset.kind==='finding changed'})[0];
      if(!sw.classList.contains('off')){sw.click(); await tick()}
      d.getElementById('conn-go').click(); await tick(300);
      return look()};
    var close=async function(){
      if(ovl.classList.contains('on')){ovl.querySelector('[data-close="conn-ovl"]').click(); await tick(100)}};
    d.querySelector('[data-v="integrations"]').click(); await tick();
    seen.before=look();
    // The old server's answer: 200, and every kind still on the row.
    seen.kept=await edit({status:200,body:{destination:'hooks.example.invalid/…',
      events:['finding changed','silent','outside view stale','cve']}});
    await close();
    // An answer that names no kinds at all.
    seen.silent=await edit({status:200,body:{destination:'hooks.example.invalid/…'}});
    await close();
    // The server's answer now: the kinds sent, as stored.
    seen.saved=await edit({status:200,body:{destination:'hooks.example.invalid/…',
      events:['silent','outside view stale','cve']}});
    seen.posts=w.__posts;
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
    # A Webhook row that takes every kind, as the test's own did.
    trl.add_channel_holding_its_destination(
        path, "ops", "https://hooks.example.invalid/x", channel_type="webhook")
    page = rl.render(path, now=NOW)
    site = tmp_path / "www"
    site.mkdir()
    assert page.count("<head>") == 1
    (site / "live.html").write_text(page.replace("<head>", "<head>" + STUB, 1), encoding="utf-8")
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
    return drive(tmp_path_factory.mktemp("edit-kinds"))


def test_the_row_starts_with_every_kind(seen):
    assert seen["before"]["row"] == ""


def test_each_save_posts_the_kinds_with_the_address_to_the_rows_destination(seen):
    assert len(seen["posts"]) == 3
    for post in seen["posts"]:
        assert post["url"] == "/api/admin/channels/ops/destination"
        body = json.loads(post["body"])
        assert body["destination"] == "https://hooks.example.invalid/x"
        assert sorted(body["events"]) == sorted(["silent", "outside view stale", "cve"])


def test_an_answer_that_kept_every_kind_is_not_called_saved(seen):
    kept = seen["kept"]
    assert kept["toast"] == "" and kept["open"] is True
    assert kept["foot"] == "The kinds did not save. Try again."
    assert kept["row"] == ""


def test_an_answer_that_names_no_kinds_is_not_called_saved(seen):
    assert seen["silent"]["toast"] == "" and seen["silent"]["open"] is True
    assert seen["silent"]["foot"] == "The kinds did not save. Try again."


def test_an_answer_that_holds_the_kinds_sent_is_saved_and_the_row_takes_them(seen):
    saved = seen["saved"]
    assert saved["toast"] == "Saved." and saved["open"] is False
    assert sorted(saved["row"].split(",")) == sorted(["silent", "outside view stale", "cve"])
