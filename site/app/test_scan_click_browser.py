"""Scan now, clicked in a real browser: the Probed fact turns at once, no
window opens, and a refusal is said as a toast and turns nothing.

docs/screens/host-overview/SPEC.md: "Scan now shows its result in the header
and in the marks, with no dialog." test_probing_mark.py holds what the server
draws. This holds what the click does before the server has said anything.

    Run from site/: python3 -m pytest app/test_scan_click_browser.py
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

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>scan click</title>
<pre id="out"></pre>
<iframe id="f" width="1200" height="700"></iframe>
<script>
var ANSWER=%(answer)s;
var PAGE=%(page)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var posts=[], pages=0;
    w.fetch=function(url,opts){
      if(opts&&opts.method==='POST'){posts.push(String(url));
        return Promise.resolve({ok:true,status:200,
          json:function(){return Promise.resolve(ANSWER)}})}
      pages++;
      return Promise.resolve({ok:true,redirected:false,status:200,
        text:function(){return Promise.resolve(PAGE)}})};
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var fact=function(name){return d.querySelector('[data-probed="'+name+'"]')};
    var spin=function(name){return w.getComputedStyle(
      fact(name).querySelector('.pspin')).display!=='none'};
    var before={box:spin('box'),other:spin('other')};
    d.querySelector('#host-box .js-scan').click();
    await tick(200);
    var toastEl=d.querySelector('.toast.on,.toast.show,#toast');
    out.textContent=JSON.stringify({before:before,
      after:{box:spin('box'),other:spin('other')},
      posts:posts,windows:d.querySelectorAll('.ovl.on').length,
      toast:toastEl?toastEl.textContent:'',
      button:d.querySelector('#host-box .js-scan').disabled,
      path:w.location.pathname});
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
    for name in ("box", "other"):
        trl.reporting(path, name, trl.document(listening=[trl.SSHD]))
    return rl.render(path, now=NOW)


def drive(tmp_path, page, answer):
    site = tmp_path / "www"
    site.mkdir()
    (site / "live.html").write_text(page, encoding="utf-8")
    embedded = json.dumps(page).replace("</", "<\\/")
    (site / "harness.html").write_text(
        HARNESS % {"answer": json.dumps(answer), "page": embedded}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=3000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


def test_an_accepted_scan_turns_that_servers_fact_at_once_and_opens_nothing(tmp_path):
    got = drive(tmp_path, a_page(tmp_path),
                {"accepted": True, "sentence": "Scanning now from outside.",
                 "retry_after_seconds": 0,
                 "oneshot_command": "sudo whichports-agent --mode=oneshot"})
    assert got["before"] == {"box": False, "other": False}
    assert got["after"] == {"box": True, "other": False}
    assert got["posts"] == ["/api/admin/hosts/box/scan"]
    assert got["windows"] == 0
    assert got["button"] is False
    assert "oneshot" not in got["toast"]


def test_a_refused_scan_says_the_control_planes_sentence_and_turns_nothing(tmp_path):
    sentence = "Just scanned. Try again in about 90 seconds."
    got = drive(tmp_path, a_page(tmp_path),
                {"accepted": False, "sentence": sentence, "retry_after_seconds": 90,
                 "oneshot_command": "sudo whichports-agent --mode=oneshot"})
    assert got["after"] == {"box": False, "other": False}
    assert got["windows"] == 0
    assert sentence in got["toast"]
