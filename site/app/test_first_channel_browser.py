"""The first channel of a workspace shows up at once, driven in a real browser.

The owner, 2026-09-20, on the first outside workspace: the page said no channel
had been added, and the channel he then added showed only after a refresh.
A workspace with no channel and no alert ever draws the one "Nothing
here yet" box, and that page has no Channels panel, so the script that paints
a new row had nowhere to put it and quietly did nothing. Every test of the add
started from a workspace that had already alerted, so none of them met it.

Here the page is rendered for exactly that workspace, the add is clicked
through in Chrome, and the server the page talks to is the harness: the POST
answers the stored row, and the page's own background fetch answers the
render of the same workspace with the row in it.

The list of where alerts go is on Integrations since layout B, under Alert
destinations (docs/screens/alerts/SPEC-layout-b.md). A workspace with
nothing connected draws the one "Nothing connected yet" box there, which has
no list either, so the same first add is driven on that screen: the Add
button in the box, the Alert destination card, the Email card, Save.

    Run from site/: python3 -m pytest app/test_first_channel_browser.py
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
ADDRESS = "tester@example.org"

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>first channel drive</title>
<pre id="out"></pre>
<iframe id="f" width="1200" height="800"></iframe>
<script>
var NEXT=%(next)s;
var ROW=%(row)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    // The stub was put in the page's own head (see `with_stubbed_server`), so
    // the page's fetch wrapper wraps it exactly as it wraps the real fetch.
    // Replacing `w.fetch` from out here would bypass that wrapper, and with it
    // the bookkeeping that decides whether a refresh's answer is used, which
    // is where the fault of 2026-09-21 lived (docs/RECORD.md 4.199).
    var posts=w.__posts, gets=w.__gets;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    d.querySelector('.nav [data-v="integrations"]').click();
    await tick();
    // The view is asked for by its id each time, because the page swaps it
    // for the one the server sent.
    var nothing=function(){
      return d.getElementById('integrations').textContent.indexOf('Nothing connected yet')>=0};
    var before={panel:!!d.querySelector('#integrations .chanp'),nothing:nothing()};
    d.querySelector('#integrations [data-open="conn-ovl"]').click();
    await tick();
    d.querySelector('#conn-ovl .m-card[data-kind="dest"]').click();
    await tick();
    d.querySelector('#conn-ovl .m-card.pick[data-fields="chan-email"]').click();
    await tick();
    var field=d.querySelector('#conn-ovl .m-stage.on .js-dest');
    field.value='%(address)s';
    field.dispatchEvent(new w.Event('input'));
    d.getElementById('conn-go').click();
    // Well under the minute the background refresh waits, so a row that is
    // there now was put there by the click and not by the timer.
    await tick(2000);
    var panel=d.querySelector('#integrations .chanp');
    out.textContent=JSON.stringify({before:before,posts:posts,gets:gets,
      view:(d.querySelector('.view.on')||{}).id,
      windowOpen:d.getElementById('conn-ovl').classList.contains('on'),
      panel:!!panel,
      rows:panel?panel.querySelectorAll('.crow').length:0,
      address:panel?panel.textContent.indexOf('%(address)s')>=0:false,
      nothing:nothing()});
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def empty_workspace(path):
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


STUB = """<script>
window.__posts=[];window.__gets=[];
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push({url:String(url),body:JSON.parse(opts.body)});
    return Promise.resolve({ok:true,status:201,
      json:function(){return Promise.resolve(%(row)s)}});
  }
  window.__gets.push(String(url));
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(%(next)s)}})};
</script>"""


def with_stubbed_server(page, second, row):
    """The page with a stand-in for the server put ahead of its own script."""
    embedded = json.dumps(second).replace("</", "<\\/")
    stub = STUB % {"row": json.dumps(row), "next": embedded}
    assert page.count("<head>") == 1
    return page.replace("<head>", "<head>" + stub, 1)


def drive(tmp_path, first, second, row):
    site = tmp_path / "www"
    site.mkdir()
    (site / "live.html").write_text(with_stubbed_server(first, second, row),
                                    encoding="utf-8")
    (site / "harness.html").write_text(
        HARNESS % {"next": "null", "row": "null", "address": ADDRESS},
        encoding="utf-8")
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
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


def test_the_first_channel_of_a_workspace_is_on_the_page_without_a_reload(tmp_path):
    first = rl.render(empty_workspace(tmp_path / "a.db"), now=NOW)
    second_db = empty_workspace(tmp_path / "b.db")
    trl.add_channel_holding_its_destination(second_db, "email", ADDRESS,
                                            channel_type="email")
    second = rl.render(second_db, now=NOW)
    row = {"label": "email", "type": "email", "enabled": True,
           "destination_hint": ADDRESS, "events": []}

    got = drive(tmp_path, first, second, row)

    # The page it started from is as the one he was on: the one box, and no
    # panel to paint into.
    assert got["before"] == {"panel": False, "nothing": True}
    assert [p["url"] for p in got["posts"]] == ["/api/admin/channels"]
    assert got["posts"][0]["body"]["destination"] == ADDRESS
    assert not got["windowOpen"]
    # And after the click, with no reload and inside two seconds:
    assert "/integrations" in got["gets"], "the page never asked for itself after the add"
    assert got["panel"] and got["rows"] == 1 and got["address"]
    assert not got["nothing"]
    # still on the screen the add was made on
    assert got["view"] == "integrations"
