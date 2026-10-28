"""The paused mark arrives with the click that pauses, in a real browser.

    Run from site/: python3 -m pytest app/test_paused_mark_browser.py

A server with a port nobody has answered for reads `unreviewed`. Pausing it
does not change that word, so until now nothing on its header or its Fleet
row moved (docs/RECORD.md 4.453). The Pause switch asks the server and then
brings the page over. This drives that: the switch is clicked on the
server's Settings tab, the stand-in server answers 204 and serves the paused
page from then on, and the header and the row are read. Then the switch is
clicked again and the mark has to go.

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch.
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
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
UVICORN = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
           "process_name": "uvicorn", "pid": 7}

# A POST to the pause route flips which page the stand-in serves, the way
# the real server's next page knows about the pause.
STUB = """<script>
window.__posts=[];window.__serve='open';window.__pages=%(pages)s;
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push(String(url)+' '+String(opts.body||''));
    if(/\\/pause$/.test(String(url))){
      window.__serve=JSON.parse(opts.body).paused?'paused':'open';
    }
    return Promise.resolve({ok:true,status:204,
      json:function(){return Promise.resolve({})}});
  }
  var page=window.__pages[window.__serve];
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the paused mark arrives with the click</title>
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
    var list=function(root,sel){return Array.prototype.slice.call(root.querySelectorAll(sel))};
    // The state and the paused mark of one place: the words, and whether
    // the mark stands on the state's own line.
    var read=function(root){
      var state=root.querySelector('.st');
      var marks=list(root,'[data-mark="paused"]');
      var s=state.getBoundingClientRect();
      return {state:state.textContent,
        marks:marks.map(function(m){return m.textContent}),
        titles:marks.map(function(m){return m.title}),
        drawn:marks.map(function(m){var b=m.getBoundingClientRect();return b.width>0&&b.height>0}),
        onTheStatesLine:marks.map(function(m){var b=m.getBoundingClientRect();
          return b.top<s.bottom&&b.bottom>s.top&&b.left>=s.right}),
        muteMarks:list(root,'[data-mute-tag]').map(function(m){return m.textContent})}};
    var look=function(){
      var fleetWas=d.getElementById('fleet').classList.contains('on');
      return {header:read(d.querySelector('#host-box .hh')),
        switchOn:!d.querySelector('#host-box .js-pause').classList.contains('off'),
        serving:w.__serve}};
    var row=function(){
      d.querySelector('nav.nav a[data-v="fleet"]').click();
      return read(d.querySelector('#fleet .row[data-host="box"] > div'))};
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    // The first-look window opens on a server's first visit, and a refresh
    // waits while a window is open.
    list(d,'.ovl.on').forEach(function(o){o.classList.remove('on')});
    d.querySelector('#host-box label[for="tb-box-settings"]').click(); await tick(100);
    seen.before=look();
    d.querySelector('#host-box .js-pause').click(); await tick(400);
    seen.paused=look();
    seen.pausedRow=row(); await tick(100);
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    d.querySelector('#host-box .js-pause').click(); await tick(400);
    seen.resumed=look();
    seen.resumedRow=row();
    seen.posts=w.__posts;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def a_page(tmp_path, name, paused):
    """One server whose port 8410 answers from outside and no rule names."""
    path = str(tmp_path / f"{name}.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD, UVICORN]))
    trl.probe_result(path, "box", 8410, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=5))
    if paused:
        con = sqlite3.connect(path)
        con.execute("UPDATE hosts SET paused = 1 WHERE name = 'box'")
        con.commit()
        con.close()
    return rl.render(path, now=NOW)


def drive(tmp_path):
    pages = {"open": a_page(tmp_path, "open", False), "paused": a_page(tmp_path, "paused", True)}
    site = tmp_path / "www"
    site.mkdir()
    embedded = json.dumps(pages).replace("</", "<\\/")
    first = pages["open"]
    assert first.count("<head>") == 1
    (site / "live.html").write_text(
        first.replace("<head>", "<head>" + STUB % {"pages": embedded}, 1), encoding="utf-8")
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
    return drive(tmp_path_factory.mktemp("paused-mark"))


def pause_posts(seen):
    """What the page sent to the pause route, in order. The page also tells
    the server that the first look was seen, which is not this file's."""
    return [post for post in seen["posts"] if "/pause " in post]


def test_before_the_click_the_server_reads_unreviewed_and_no_mark(seen):
    """What the rest of this file rests on."""
    got = seen["before"]
    assert got["header"]["state"] == "unreviewed"
    assert got["header"]["marks"] == []
    assert got["switchOn"] is False and got["serving"] == "open"


def test_the_click_asks_the_server_to_pause(seen):
    assert pause_posts(seen)[0] == '/api/admin/hosts/box/pause {"paused":true}'


def test_after_the_click_the_header_says_paused_beside_unreviewed(seen):
    got = seen["paused"]
    assert got["switchOn"] is True and got["serving"] == "paused"
    assert got["header"]["state"] == "unreviewed"
    assert got["header"]["marks"] == ["paused"]
    assert got["header"]["titles"] == ["paused"]


def test_the_mark_is_drawn_on_the_states_own_line(seen):
    for place in (seen["paused"]["header"], seen["pausedRow"]):
        assert place["drawn"] == [True], place
        assert place["onTheStatesLine"] == [True], place


def test_after_the_click_the_fleet_row_says_paused_beside_unreviewed(seen):
    got = seen["pausedRow"]
    assert got["state"] == "unreviewed"
    assert got["marks"] == ["paused"]


def test_the_mute_mark_is_left_empty_by_a_pause(seen):
    """A pause is not a mute, and the mute's own mark stays as it was."""
    assert seen["paused"]["header"]["muteMarks"] == [""]
    assert seen["pausedRow"]["muteMarks"] == [""]


def test_the_second_click_takes_the_mark_away_again(seen):
    assert pause_posts(seen) == ['/api/admin/hosts/box/pause {"paused":true}',
                                 '/api/admin/hosts/box/pause {"paused":false}']
    got = seen["resumed"]
    assert got["switchOn"] is False and got["serving"] == "open"
    assert got["header"]["marks"] == []
    assert seen["resumedRow"]["marks"] == []
