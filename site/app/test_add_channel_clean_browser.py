"""The Add channel window opens with every kind switched on, whatever window
was open before it, in a real browser (docs/RECORD.md 4.362, 4.371).

Edit on a channel opens the same window with the switches set to the kinds
that channel takes. The window was then closed and the switches stayed as
they were, so Add channel opened afterwards showed another channel's choice
under its own heading (measured 2026-10-04: two of three still off). A new
channel made there would have taken fewer kinds than anybody chose.

That window is the one Add window on Integrations since layout B
(docs/screens/alerts/SPEC-layout-b.md). So adding is three clicks here: the
Add button, the Alert destination card, then a channel's card, which is when
the switches show. Edit on a row opens the same window on that row.

    Run from site/: python3 -m pytest app/test_add_channel_clean_browser.py
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

STUB = """<script>
window.__posts=[];
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST')window.__posts.push(String(url));
  return Promise.resolve({ok:true,status:204,redirected:false,
    json:function(){return Promise.resolve({})},text:function(){return Promise.resolve('')}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>add channel opens clean</title>
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
    // `shown` is the steps that are showing, so a look says whether the
    // switches it read were on the screen.
    var look=function(){return {open:ovl.classList.contains('on'),
      heading:ovl.querySelector('.m-h h2').textContent.trim(),
      off:list('#conn-ovl .js-event.off').map(function(s){return s.dataset.kind}),
      switches:list('#conn-ovl .js-event').length,
      shown:list('#conn-ovl .m-stage.on').map(function(s){return s.id})}};
    var close=async function(){ovl.querySelector('[data-close="conn-ovl"]').click(); await tick(100)};
    var add=async function(){
      d.querySelector('#integrations [data-open="conn-ovl"]').click(); await tick(100);
      seen.opened=seen.opened||look();
      ovl.querySelector('.m-card[data-kind="dest"]').click(); await tick(100);
      ovl.querySelector('.m-card.pick[data-fields="chan-webhook"]').click(); await tick(100)};
    var edit=async function(){list('.rm-edit').filter(function(b){
      return b.dataset.label==='ops'})[0].click(); await tick(100)};
    d.querySelector('[data-v="integrations"]').click(); await tick();
    await add(); seen.addFirst=look(); await close();
    await edit(); seen.editing=look(); await close();
    await add(); seen.addAfterEdit=look();
    // A kind switched off by hand in Add, and the window closed without saving.
    list('#conn-ovl .js-event')[0].click(); await tick();
    seen.switchedOff=look(); await close();
    await add(); seen.addAgain=look(); await close();
    await edit(); seen.editingAgain=look(); await close();
    seen.posts=w.__posts.length;
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
    # A channel that takes one kind of three.
    trl.add_channel_holding_its_destination(
        path, "ops", "https://hooks.example.invalid/x", subscriptions="silent",
        channel_type="webhook")
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
    return drive(tmp_path_factory.mktemp("add-channel"))


SHOWN = ["conn-dest", "chan-webhook", "chan-adv"]


def test_the_window_is_sent_with_every_kind_on(seen):
    # as the server sent it, before a card is picked: no step showing
    assert seen["opened"]["heading"] == "Add" and seen["opened"]["shown"] == []
    # Four since the CVE check's kind has its switch (controlplane/app/channels.py).
    assert seen["opened"]["switches"] == 4 and seen["opened"]["off"] == []
    # and with the webhook's fields and the switches on the screen
    assert seen["addFirst"]["heading"] == "Add"
    assert seen["addFirst"]["shown"] == SHOWN
    assert seen["addFirst"]["switches"] == 4 and seen["addFirst"]["off"] == []


def test_edit_shows_the_kinds_that_channel_takes(seen):
    """What the rest of this file rests on: the channel takes one kind, so
    the other three switches are off while it is being edited."""
    assert seen["editing"]["heading"] == "Edit ops"
    assert seen["editing"]["shown"] == SHOWN
    assert len(seen["editing"]["off"]) == 3 and "silent" not in seen["editing"]["off"]


def test_add_channel_after_an_edit_has_every_kind_on(seen):
    assert seen["addAfterEdit"]["heading"] == "Add"
    assert seen["addAfterEdit"]["shown"] == SHOWN
    assert seen["addAfterEdit"]["off"] == []


def test_a_kind_switched_off_and_not_saved_is_on_again_next_time(seen):
    assert len(seen["switchedOff"]["off"]) == 1
    assert seen["addAgain"]["off"] == []


def test_edit_still_shows_the_stored_kinds_afterwards(seen):
    assert seen["editingAgain"]["off"] == seen["editing"]["off"]


def test_opening_and_closing_posts_nothing(seen):
    assert seen["posts"] == 0
