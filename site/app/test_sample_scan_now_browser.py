"""Scan now on the sample page, clicked in a real browser (docs/RECORD.md
4.443).

The sample page has nothing behind it. Its Scan now was the live button, so
the click asked a server that is not there and the page answered "That did
not work, HTTP 501". It now says what it would do, as the sample's other
controls do, and asks nobody for anything.

    Run from site/: python3 -m pytest app/test_sample_scan_now_browser.py
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sys
import threading

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

# Ahead of the page's own script, so the page's wrapper around fetch wraps
# it. It writes down everything the page asks for and answers the way a
# server that is not there does.
WATCH = """<script>
window.__asked=[];
window.fetch=function(url,opts){
  window.__asked.push(((opts&&opts.method)||'GET')+' '+String(url));
  return Promise.resolve({ok:false,redirected:false,status:501,
    json:function(){return Promise.resolve({})},text:function(){return Promise.resolve('')}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>scan now on the sample</title>
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
    d.querySelector('#fleet a.row').click(); await tick(100);
    Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
    var button=Array.prototype.filter.call(d.querySelectorAll('.view.on button'),function(b){
      return b.offsetParent!==null&&b.textContent.trim()==='Scan now'})[0];
    seen.found=!!button;
    seen.askedBefore=w.__asked.slice();
    seen.probedBefore=d.querySelector('.view.on [data-probed]').className;
    button.click(); await tick(300);
    seen.asked=w.__asked.slice(seen.askedBefore.length);
    seen.toast=d.getElementById('toast').textContent;
    seen.toastShown=d.getElementById('toast').classList.contains('on');
    seen.probedAfter=d.querySelector('.view.on [data-probed]').className;
    seen.buttonReads=button.textContent.trim();
    seen.buttonOff=button.disabled;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


@pytest.fixture(scope="module")
def seen(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("sample-scan")
    site = tmp_path / "www"
    site.mkdir()
    page = build.build_sample()
    assert page.count("<head>") == 1
    (site / "live.html").write_text(page.replace("<head>", "<head>" + WATCH, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=8000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


def test_the_button_is_on_the_samples_server_page(seen):
    assert seen["found"] is True


def test_the_click_asks_no_server_for_anything(seen):
    assert seen["asked"] == []


def test_the_click_says_what_it_would_do(seen):
    assert seen["toastShown"] is True
    assert seen["toast"] == "The server would be scanned here"


def test_the_click_claims_no_probing_and_leaves_the_button_as_it_was(seen):
    """Nothing is being probed, so the Probed fact does not start to turn."""
    assert "probing" not in seen["probedAfter"].split()
    assert seen["probedAfter"] == seen["probedBefore"]
    assert seen["buttonReads"] == "Scan now" and seen["buttonOff"] is False
