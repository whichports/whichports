"""An answer on a port repaints its whole row at once, in a real browser.

    Run from site/: python3 -m pytest app/test_answers_repaint_browser.py

Found on the test fleet on 2026-09-30 (docs/RECORD.md 4.220): after Yes the
state and the lit answer changed at the click and Decided by still read
`no rule` until a reload, and after Later nothing on the row changed at all.
docs/screens/host-overview/SPEC.md says every answer posts and the row
repaints at once.

One server whose port 8410 answers from outside and no rule names. For each
of the three answers, with the row closed and with it opened, the answer is
clicked on a fresh copy of the page. The stand-in server takes the post and
from then on serves the page a real server would render after that answer.
What the row reads a moment after the click is held to what that page says.

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
import test_host_answers as tha  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
UVICORN = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
           "process_name": "uvicorn", "pid": 7}
ANSWERS = ("yes", "no", "later")
CASES = [f"{word}-{how}" for word in ANSWERS for how in ("closed", "opened")]

# A post of an answer moves which page the stand-in serves, the way the real
# server's next page knows the answer.
STUB = """<script>
window.__posts=[];window.__serve='open';window.__pages=%(pages)s;
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    var u=String(url);
    window.__posts.push(u+' '+String(opts.body||''));
    if(/\\/acknowledge$/.test(u))window.__serve='later';
    if(/\\/declare$/.test(u))window.__serve=JSON.parse(opts.body).intent==='open'?'yes':'no';
    return Promise.resolve({ok:true,status:204,
      json:function(){return Promise.resolve({})}});
  }
  var page=window.__pages[window.__serve];
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>an answer repaints its row</title>
<pre id="out"></pre>
<div id="frames"></div>
<script>
var out=document.getElementById('out');
var CASES=%(cases)s;
var seen={};
var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
var list=function(root,sel){return Array.prototype.slice.call(root.querySelectorAll(sel))};
var flat=function(s){return String(s||'').replace(/\\s+/g,' ').trim()};
// The row of port 8410 on the server's Overview, as a reader meets it.
var read=function(doc){
  var label=doc.querySelector('#host-box label.pr[for$="-tcp-8410"]');
  var st=label.querySelector('.prst .st');
  return {state:st?st.textContent:'',
    decided:flat(label.querySelector('.prw').textContent),
    lit:list(label,'.ans.pick').map(function(b){return b.dataset.answer}),
    answers:list(label,'.ans').map(function(b){return b.dataset.answer}),
    opened:flat(label.nextElementSibling.textContent),
    header:flat(doc.querySelector('#host-box .hh .st').textContent),
    boxes:flat(doc.querySelector('#host-box .hstrip').textContent)}};
var one=function(name){
  return new Promise(function(done){
    var parts=name.split('-'), word=parts[0], how=parts[1];
    var f=document.createElement('iframe');
    f.width=1300;f.height=800;
    f.onload=async function(){
      var got={};
      try{
        var w=f.contentWindow, d=f.contentDocument;
        d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
        // The first-look window opens on a first visit, and a refresh
        // waits while a window is open.
        list(d,'.ovl.on').forEach(function(o){o.classList.remove('on')});
        var label=d.querySelector('#host-box label.pr[for$="-tcp-8410"]');
        var box=d.getElementById(label.htmlFor);
        if(how==='opened'){box.checked=true}
        got.before=read(d);
        label.querySelector('.ans[data-answer="'+word+'"]').click(); await tick(600);
        got.after=read(d);
        got.rowStillOpen=d.getElementById(label.htmlFor).checked;
        got.serving=w.__serve;
        got.posts=w.__posts.filter(function(p){return p.indexOf('/first-look')<0});
        got.says=read(new w.DOMParser().parseFromString(w.__pages[w.__serve],'text/html'));
      }catch(e){got.error=String(e&&e.stack||e)}
      seen[name]=got;
      done();
    };
    // The address first: a frame put on the page without one loads an
    // empty page and says so through the same onload.
    f.src='live.html';
    document.getElementById('frames').appendChild(f);
  });
};
(async function(){
  for(var i=0;i<CASES.length;i++){await one(CASES[i])}
  out.textContent=JSON.stringify(seen);
})();
</script>
"""


def a_page(tmp_path, name):
    """The server as its page reads after the answer `name`, or before any."""
    path = str(tmp_path / f"{name}.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD, UVICORN]))
    trl.probe_result(path, "box", 8410, "v4", "connect_succeeded",
                     measured_at=NOW - timedelta(minutes=5))
    if name in ("yes", "no"):
        for family in ("v4", "v6"):
            tha.declare_intent(path, "box", "tcp", 8410, family,
                               "open" if name == "yes" else "closed")
    if name == "later":
        tha.acknowledge(path, "box", "tcp", 8410, "v4", "unreviewed")
    return rl.render(path, now=NOW)


def drive(tmp_path):
    pages = {name: a_page(tmp_path, name) for name in ("open",) + ANSWERS}
    site = tmp_path / "www"
    site.mkdir()
    embedded = json.dumps(pages).replace("</", "<\\/")
    first = pages["open"]
    assert first.count("<head>") == 1
    (site / "live.html").write_text(
        first.replace("<head>", "<head>" + STUB % {"pages": embedded}, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS % {"cases": json.dumps(CASES)}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=60000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    return json.loads(html_mod.unescape(got.group(1)))


@pytest.fixture(scope="module")
def seen(tmp_path_factory):
    return drive(tmp_path_factory.mktemp("answers-repaint"))


def test_every_case_ran_and_none_threw(seen):
    assert sorted(seen) == sorted(CASES)
    assert [name for name in CASES if "error" in seen[name]] == []


def test_before_any_answer_the_row_is_unreviewed_and_nobody_decided(seen):
    """What the rest of this file rests on."""
    for name in CASES:
        before = seen[name]["before"]
        assert before["state"] == "unreviewed", name
        assert before["decided"] == "no rule", name
        assert before["lit"] == [] and before["answers"] == list(ANSWERS), name


def test_the_three_pages_differ_from_the_one_before_an_answer(seen):
    """An answer that changed nothing on the server's own page would let
    every test under this one pass by standing still."""
    for name in CASES:
        got = seen[name]
        assert got["serving"] == name.split("-")[0], name
        assert got["says"] != got["before"], name


@pytest.mark.parametrize("name", CASES)
def test_the_click_posts_the_answer(seen, name):
    word = name.split("-")[0]
    posts = seen[name]["posts"]
    if word == "later":
        assert posts == ["/api/admin/hosts/box/ports/tcp/8410/v4/acknowledge "]
    else:
        intent = "open" if word == "yes" else "closed"
        assert posts == [f'/api/admin/hosts/box/ports/tcp/8410/{family}/declare {{"intent":"{intent}"}}'
                         for family in ("v4", "v6")]


@pytest.mark.parametrize("name", CASES)
def test_the_lit_answer_is_the_one_clicked(seen, name):
    assert seen[name]["after"]["lit"] == [name.split("-")[0]]


@pytest.mark.parametrize("name", CASES)
def test_decided_by_reads_what_the_server_says_at_once(seen, name):
    got = seen[name]
    assert got["after"]["decided"] == got["says"]["decided"]


@pytest.mark.parametrize("name", CASES)
def test_the_whole_row_reads_what_the_server_says_at_once(seen, name):
    """The state, who decided, the lit answer, the opened row's lines, the
    header's word and the three boxes."""
    got = seen[name]
    assert got["after"] == got["says"]


@pytest.mark.parametrize("name", [n for n in CASES if n.endswith("-opened")])
def test_an_opened_row_stays_open_through_its_answer(seen, name):
    assert seen[name]["rowStillOpen"] is True
