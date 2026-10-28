"""The gaps in the proof form once a token is out (docs/RECORD.md 4.379).

On the live window of 2026-10-06 there was about 60 px of nothing between
the two ways and "Publish this token", and "Read from" stood directly under
the token box. One gap now stands above each of the two labels. The form is
one function drawn in two windows, so both are measured, in a real browser,
in the product's own fonts, at 1440 and 1024.

    Run from site/: python3 -m pytest app/test_proof_form_gaps_browser.py
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

# Each window is opened by hand and its form put in the two steps by the one
# thing the stylesheet reads, the proof block's `hidden`. No click and no
# request: this measures the drawing, the flow has its own tests.
HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the proof form's gaps</title>
<pre id="out"></pre>
<iframe id="f" width="%(width)d" height="900" style="border:0"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    await d.fonts.ready;
    seen.window=w.innerWidth;
    var box=function(el){return el.getBoundingClientRect()};
    var measure=function(ovl,prefix,reveal){
      Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
      d.getElementById(ovl).classList.add('on');
      reveal();
      // This browser draws no frame, so a window that opens with a motion
      // would stand at the motion's first frame, a hair small. The motion is
      // ended the browser's own way and the window is measured at rest.
      d.getAnimations().forEach(function(a){
        if(['v-in','o-in','m-in'].indexOf(a.animationName)>=0)a.finish()});
      var id=function(part){return d.getElementById(prefix+'-'+part)};
      var proof=id('proof'), err=id('err');
      var labels=proof.querySelectorAll('.m-label');
      var got={};
      proof.hidden=true;
      got.errRoomAtStart=box(err).height;
      proof.hidden=false;
      id('token').textContent='wp-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      id('where').textContent='http://185.199.108.154:80/.well-known/whichports-authorization';
      got.shown=box(proof).height>0;
      got.aboveToken=Math.round((box(labels[0]).top-box(id('http')).bottom)*10)/10;
      got.aboveWhere=Math.round((box(labels[1]).top-box(id('token')).bottom)*10)/10;
      err.textContent='the address answered 404';
      got.aboveTokenWithALine=Math.round((box(labels[0]).top-box(id('http')).bottom)*10)/10;
      got.lineHeight=box(err).height;
      err.textContent='';
      return got};
    seen.address=measure('addr-ovl','ad',function(){});
    seen.server=measure('add-ovl','add-addr',function(){
      d.getElementById('add-method-linux').classList.add('on');
      d.getElementById('add-addr-stage').classList.add('on')});
    var address=d.querySelector('#add-addr-stage .m-input+.m-label');
    seen.server.aboveAddress=Math.round((box(address).top-box(d.getElementById('add-addr-name')).bottom)*10)/10;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""

FONTS = pathlib.Path(__file__).resolve().parent.parent / "fonts"
WIDTHS = [1024, 1440]
WINDOWS = ["address", "server"]


class PageAndFonts(QuietHandler):
    def translate_path(self, path):
        clean = path.split("?", 1)[0]
        if "/fonts/" in clean:
            return str(FONTS / clean.rsplit("/", 1)[1])
        return super().translate_path(path)


def measure(tmp_path, width, page):
    site = tmp_path / f"www-{width}"
    site.mkdir()
    (site / "live.html").write_text(page, encoding="utf-8")
    (site / "harness.html").write_text(HARNESS % {"width": width}, encoding="utf-8")
    handler = functools.partial(PageAndFonts, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / f'chrome-{width}'}",
             f"--window-size={width + 40},1100",
             "--virtual-time-budget=8000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def at(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("gaps")
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    page = rl.render(db, now=trl.NOW)
    return {width: measure(tmp_path, width, page) for width in WIDTHS}


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("window", WINDOWS)
def test_the_form_was_drawn_and_measured(at, width, window):
    assert at[width]["window"] == width
    assert at[width][window]["shown"] is True


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("window", WINDOWS)
def test_one_gap_stands_above_each_of_the_two_labels(at, width, window):
    got = at[width][window]
    assert got["aboveToken"] == got["aboveWhere"], got


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("window", WINDOWS)
def test_the_gap_is_a_gap_and_not_a_hole(at, width, window):
    """Wider than a label sits over its own field, and nowhere near the
    60 px that stood above the token."""
    got = at[width][window]
    assert 12 <= got["aboveToken"] <= 24, got


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("window", WINDOWS)
def test_a_refusal_line_with_a_token_out_still_has_its_room(at, width, window):
    """A line under the two ways pushes the token down by its own height
    and its margin, it is never drawn over anything."""
    got = at[width][window]
    assert got["lineHeight"] >= 16, got
    assert got["aboveTokenWithALine"] >= got["aboveToken"] + got["lineHeight"], got


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("window", WINDOWS)
def test_before_a_token_the_refusal_line_keeps_its_reserved_room(at, width, window):
    """So a refusal at Start does not move the foot."""
    assert at[width][window]["errRoomAtStart"] >= 18, at[width][window]


@pytest.mark.parametrize("width", WIDTHS)
def test_the_add_server_windows_name_field_has_the_same_gap_under_it(at, width):
    """That window draws a Name field over the form, and the form's Address
    label touched it."""
    got = at[width]["server"]
    assert got["aboveAddress"] == got["aboveWhere"], got
    assert 12 <= got["aboveAddress"] <= 24, got
