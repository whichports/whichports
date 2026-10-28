"""The count beside Alerts and a server's first-look window follow the server
without a reload, in a real browser (docs/RECORD.md 4.362, 4.364).

Neither was among the pieces the quiet refresh brings over. Measured on
2026-10-04: the server's page carried 1 beside Alerts and the screen showed
none, and a first-look window still listed the ports of an older page.

The top bar is not a piece, because which of its entries is lit is the page's
own doing. Only the count is brought over, and only when the server's own
count moved: a count the page took down on a click is not put back up by an
answer that is older than the click.

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch.

    Run from site/: python3 -m pytest app/test_refresh_reaches_browser.py
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

STUB = """<script>
window.__posts=[];window.__gets=0;window.__serve='two';window.__pages=%(pages)s;
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push(String(url));
    return Promise.resolve({ok:true,status:204,
      json:function(){return Promise.resolve({})}});
  }
  window.__gets++;
  var page=window.__pages[window.__serve];
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the refresh reaches the count and the first-look window</title>
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
    var rowsIn=function(name){
      var fresh=new w.DOMParser().parseFromString(w.__pages[name],'text/html');
      return fresh.querySelectorAll('#fv-box .fv-r').length};
    var look=function(){
      var badges=list('nav.nav .nb');
      return {gets:w.__gets,
        count:badges.map(function(b){return b.textContent}),
        countSitsIn:badges.map(function(b){return b.parentNode.dataset.v}),
        lit:list('nav.nav a.on').map(function(a){return a.dataset.v}),
        firstLookRows:d.querySelectorAll('#fv-box .fv-r').length,
        firstLookOpen:d.getElementById('fv-box').classList.contains('on')}};
    var go=async function(name,as){
      w.__serve=name;
      await tick(61000); await tick(300);
      seen[as||name]=look()};
    seen.firstLookRowsThe={two:rowsIn('two'),three:rowsIn('three'),none:rowsIn('none')};
    // On the Alerts screen, as somebody who came to look at them.
    d.querySelector('nav.nav a[data-v="alerts"]').click(); await tick(100);
    seen.asSent=look();
    // One alert is paused here. The count goes down on the click.
    d.querySelector('#alerts .js-al-pause').click(); await tick(300);
    d.activeElement&&d.activeElement.blur();
    seen.paused=look();
    // The refresh brings a page from before that click: still two.
    await go('two','olderAnswer');
    // Then the server's count moves, up, away, and back.
    await go('three'); await go('none'); await go('three','threeAgain');
    // The first-look window, opened from the server's page after all that.
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    list('.ovl.on').forEach(function(o){o.classList.remove('on')});
    d.querySelector('#host-box .js-review-all').click(); await tick(100);
    var answers=list('#fv-box .fv-r .ans');
    answers[0].click(); await tick();
    seen.opened={open:d.getElementById('fv-box').classList.contains('on'),
                 rows:d.querySelectorAll('#fv-box .fv-r').length,
                 picked:d.querySelectorAll('#fv-box .ans.pick').length};
    seen.posts=w.__posts;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def a_page(tmp_path, name, quiet, answering):
    """One server with the ports given answering from outside, and `quiet`
    more servers whose agents went silent, each with its open alert."""
    path = str(tmp_path / f"{name}.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD, UVICORN]))
    for port in (22, 8410):
        state = "connect_succeeded" if port in answering else "no_response"
        trl.probe_result(path, "box", port, "v4", state,
                         measured_at=NOW - timedelta(minutes=5))
    for n in range(quiet):
        host = f"quiet-{n + 1}"
        trl.reporting(path, host, trl.document(listening=[trl.SSHD]), minutes=90)
        trl.add_alert(path, host, "no report for 42 min", NOW - timedelta(hours=1),
                      kind="silent")
    return rl.render(path, now=NOW)


def three_pages(tmp_path):
    """`two` and `three` are named for the count beside Alerts, and `none`
    has no open alert. On `two` both of the server's ports answer, on the
    others one does, so the first-look window lists a different number of
    ports."""
    return {"two": a_page(tmp_path, "two", 2, answering=(22, 8410)),
            "three": a_page(tmp_path, "three", 3, answering=(22,)),
            "none": a_page(tmp_path, "none", 0, answering=(22,))}


def drive(tmp_path, pages):
    site = tmp_path / "www"
    site.mkdir()
    embedded = json.dumps(pages).replace("</", "<\\/")
    first = pages["two"]
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
             "--virtual-time-budget=270000", "--dump-dom",
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
    tmp_path = tmp_path_factory.mktemp("reaches")
    return drive(tmp_path, three_pages(tmp_path))


def test_the_three_pages_are_what_their_names_say(seen):
    """What the rest of this file rests on."""
    assert seen["asSent"]["count"] == ["2"]
    assert seen["asSent"]["lit"] == ["alerts"]
    rows = seen["firstLookRowsThe"]
    assert rows["two"] != rows["three"], rows


def test_a_pause_takes_the_count_down_on_the_click(seen):
    assert seen["paused"]["count"] == ["1"]
    assert any(url.endswith("/pause") for url in seen["posts"])


def test_an_answer_older_than_the_click_does_not_put_the_count_back_up(seen):
    got = seen["olderAnswer"]
    assert got["gets"] > seen["paused"]["gets"]
    assert got["count"] == ["1"]


def test_the_count_follows_the_server_when_the_servers_count_moves(seen):
    assert seen["three"]["count"] == ["3"]


def test_the_count_goes_away_when_no_alert_is_open(seen):
    assert seen["none"]["count"] == []


def test_the_count_comes_back_beside_alerts(seen):
    got = seen["threeAgain"]
    assert got["count"] == ["3"]
    assert got["countSitsIn"] == ["alerts"]


def test_the_lit_entry_of_the_top_bar_is_left_alone(seen):
    """The server always sends the bar with Fleet lit. Somebody on Alerts
    stays on Alerts."""
    for name in ("olderAnswer", "three", "none", "threeAgain"):
        assert seen[name]["lit"] == ["alerts"], name


def test_the_first_look_window_lists_what_the_servers_newest_page_lists(seen):
    assert seen["three"]["firstLookRows"] == seen["firstLookRowsThe"]["three"]
    assert seen["opened"]["rows"] == seen["firstLookRowsThe"]["three"]


def test_a_refresh_never_opens_the_window(seen):
    for name in ("olderAnswer", "three", "none", "threeAgain"):
        assert seen[name]["firstLookOpen"] is False, name


def test_the_window_that_came_in_still_opens_and_takes_an_answer(seen):
    assert seen["opened"]["open"] is True
    assert seen["opened"]["picked"] == 1
