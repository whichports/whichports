"""Dismiss and Restore on the CVE check's mark, clicked in a real browser.

    Run from site/: python3 -m pytest app/test_cve_dismiss_browser.py

What is drawn on the server's answer is in test_cve_card.py. This holds what
a click does at once, before any refresh: one request that names one port of
one server and no CVE, the mark gone from the row, the line saying
dismissed with Restore, and the mark beside the server's name staying while
another port still carries one. The harness is test_rarely_dismiss.py's,
whose control this one stands beside, and the page is the live render's own.
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
import test_cve_card as tc  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rarely_dismiss import STUB  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>cve mark drive</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var view=function(){return d.getElementById('host-web-07')};
    var labelOf=function(port){return view().querySelector('label.pr[data-port="'+port+'/tcp"]')};
    var lineOf=function(port){return labelOf(port).nextElementSibling.querySelector('.prmk.fix')};
    var state=function(port){var l=lineOf(port), m=labelOf(port).querySelector('.prst .tag-fix');
      return {marked:!!m,title:m?m.title:'',
        off:l.classList.contains('off'),word:(l.querySelector('.st')||{}).textContent||'',
        button:l.querySelector('.js-fix').textContent,
        dismiss:l.querySelector('.js-fix').dataset.dismiss,
        strip:!!labelOf(port).nextElementSibling.querySelector('.prpk')}};
    var count=function(){return view().querySelector('.hstrip>div:nth-child(2) .n').textContent};
    var headMarked=function(){return !!view().querySelector('.hh .stset .tag-fix')};
    var toast=function(){return d.getElementById('toast').textContent};
    var click=async function(port){lineOf(port).querySelector('.js-fix').click();await tick()};
    var seen={errs:[]};
    w.addEventListener('error',function(e){seen.errs.push(String(e.message))});

    seen.start={p22:state(22),p80:state(80),count:count(),head:headMarked()};

    w.__next={status:200,body:{dismissed:true}};
    await click(22);
    seen.dismissed22={p22:state(22),p80:state(80),count:count(),head:headMarked(),
      toast:toast(),post:w.__posts[w.__posts.length-1]};

    w.__next={status:200,body:{dismissed:true}};
    await click(80);
    seen.dismissedBoth={p80:state(80),count:count(),head:headMarked()};

    w.__next={status:200,body:{dismissed:false}};
    await click(22);
    seen.restored22={p22:state(22),count:count(),head:headMarked(),toast:toast(),
      post:w.__posts[w.__posts.length-1]};

    w.__next={status:400,body:{detail:'this port carries no mark to dismiss'}};
    await click(22);
    seen.refused={p22:state(22),head:headMarked(),toast:toast()};
    seen.posts=w.__posts.length;
    out.textContent=JSON.stringify(seen);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def drive(tmp_path, page):
    site = tmp_path / "www"
    site.mkdir()
    assert page.count("<head>") == 1
    (site / "live.html").write_text(page.replace("<head>", "<head>" + STUB, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=20000", "--dump-dom",
             f"http://127.0.0.1:{httpd.server_address[1]}/harness.html"])
    finally:
        httpd.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def drove(tmp_path_factory):
    """One Chrome run for every assertion below."""
    tmp_path = tmp_path_factory.mktemp("cvemark")
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    tc.server(path)
    tc.extract(path)
    return drive(tmp_path, rl.render(path, now=trl.NOW))


SHOWN = {"marked": True, "off": False, "word": "", "button": "Dismiss", "dismiss": "1", "strip": True}
GONE = {"marked": False, "title": "", "off": True, "word": "dismissed", "button": "Restore", "dismiss": "0",
        "strip": True}


def test_the_page_script_raised_nothing(drove):
    assert drove["errs"] == []


def test_both_marked_ports_start_with_dismiss(drove):
    assert drove["start"]["p22"] == {**SHOWN, "title": "an update fixes 2 CVEs"}
    assert drove["start"]["p80"] == {**SHOWN, "title": "a newer version fixes 1 CVE"}
    assert drove["start"]["head"] is True


def test_dismiss_posts_one_port_of_one_server_and_no_cve_and_paints_at_once(drove):
    seen = drove["dismissed22"]
    assert seen["post"] == '/api/admin/hosts/web-07/cve-mark/tcp/22 {"dismissed":true}'
    assert "CVE" not in seen["post"]
    assert seen["p22"] == GONE, "the mark is gone, the line says dismissed, and the strip stays"
    assert seen["p80"] == drove["start"]["p80"], "the other port was touched"
    assert seen["toast"] == "Dismissed"


def test_the_mark_beside_the_name_stays_while_another_port_carries_one(drove):
    assert drove["dismissed22"]["head"] is True
    assert drove["dismissedBoth"]["p80"] == GONE
    assert drove["dismissedBoth"]["head"] is False


def test_the_count_under_needs_a_decision_never_moves(drove):
    """The check's mark was never counted there, so dismissing it takes
    nothing off and restoring it puts nothing on."""
    counts = {drove[step]["count"] for step in ("start", "dismissed22", "dismissedBoth", "restored22")}
    assert counts == {"0"}


def test_restore_brings_the_mark_back_with_its_words(drove):
    seen = drove["restored22"]
    assert seen["post"] == '/api/admin/hosts/web-07/cve-mark/tcp/22 {"dismissed":false}'
    assert seen["p22"] == {**SHOWN, "title": "an update fixes 2 CVEs"}
    assert seen["head"] is True and seen["toast"] == "Restored"


def test_a_refusal_is_its_words_in_a_toast_and_nothing_is_painted(drove):
    seen = drove["refused"]
    assert seen["toast"] == "this port carries no mark to dismiss"
    assert seen["p22"] == drove["restored22"]["p22"]
    assert drove["posts"] == 4
