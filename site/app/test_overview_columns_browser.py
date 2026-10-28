"""The Overview's port table gives every column room at 1024 as at 1440, in
a real browser (docs/RECORD.md 4.373).

The table's columns were fixed widths with Decided by taking what was left.
Below about 1220 nothing was left: measured on 2026-10-06 at 1024, that
column was 0 wide, so its heading stood on two lines and "your rule" on two
in every row. A drawn page hides this, since the words still show.

What is held here, at both widths, on the sample server whose rows carry the
longest words the table has: the heading on one line, the short answers on
one line, the longest on two at most, and nothing wider than its column.

    Run from site/: python3 -m pytest app/test_overview_columns_browser.py
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
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the overview's columns</title>
<pre id="out"></pre>
<iframe id="f" width="%(width)d" height="900" style="border:0"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    await d.fonts.ready;
    d.querySelector('#fleet .row[data-host]').click(); await tick(200);
    Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
    var view=d.querySelector('.view.on');
    var head=view.querySelector('.prh');
    var lines=function(el){
      var style=w.getComputedStyle(el);
      var line=parseFloat(style.lineHeight)||parseFloat(style.fontSize)*1.5;
      return Math.round(el.getBoundingClientRect().height/line)};
    seen.window=w.innerWidth;
    seen.tracks=w.getComputedStyle(head).gridTemplateColumns.split(' ').map(parseFloat);
    seen.headings=Array.prototype.map.call(head.children,function(c){
      return [c.textContent.trim(),lines(c)]}).filter(function(h){return h[0]});
    seen.decided=[];seen.wider=[];
    Array.prototype.forEach.call(view.querySelectorAll('label.pr'),function(row){
      var cell=row.querySelector('.prw');
      if(cell.textContent.trim())seen.decided.push([cell.textContent.trim(),lines(cell)]);
      Array.prototype.forEach.call(row.children,function(c){
        if(c.scrollWidth>c.clientWidth+1)
          seen.wider.push(c.className+': '+c.textContent.trim().slice(0,30))});
      var answers=row.querySelector('.pra');
      // On one line: no piece starts below where another one ends.
      var boxes=Array.prototype.map.call(answers.children,function(b){
        return b.getBoundingClientRect()}).filter(function(r){return r.width});
      var lowestTop=Math.max.apply(null,boxes.map(function(r){return r.top}).concat([0]));
      var highestBottom=Math.min.apply(null,boxes.map(function(r){return r.bottom}).concat([1e9]));
      if(boxes.length&&lowestTop>=highestBottom)
        seen.wider.push('answers on two lines: '+answers.textContent.trim());
    });
    var table=view.querySelector('.ptbl').getBoundingClientRect();
    var last=head.lastElementChild.getBoundingClientRect();
    seen.lastColumnEndsInside=last.right<=table.right+0.5;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""

FONTS = pathlib.Path(__file__).resolve().parent.parent / "fonts"


class PageAndFonts(QuietHandler):
    """The page and, under any path that ends in /fonts/<file>, the product's
    own fonts: a column is measured in the face it is drawn in."""

    def translate_path(self, path):
        clean = path.split("?", 1)[0]
        if "/fonts/" in clean:
            return str(FONTS / clean.rsplit("/", 1)[1])
        return super().translate_path(path)


def widest_server(tmp_path):
    """A server drawn by the renderer whose one row asks the most of the
    narrow columns: a port of five digits and a long service name."""
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[
        {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 65535,
         "process_name": "whichports-test-dual", "pid": 9}]))
    trl.probe_result(path, "box", 65535, "v4", "connect_succeeded")
    return rl.render(path, now=trl.NOW)


def measure(tmp_path, width, page=None, name="sample"):
    site = tmp_path / f"www-{name}-{width}"
    site.mkdir()
    (site / "live.html").write_text(page or build.build_sample(), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS % {"width": width}, encoding="utf-8")
    handler = functools.partial(PageAndFonts, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / f'chrome-{name}-{width}'}",
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
    tmp_path = tmp_path_factory.mktemp("columns")
    return {width: measure(tmp_path, width) for width in (1024, 1440)}


@pytest.fixture(scope="module")
def widest_at(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("widest")
    page = widest_server(tmp_path)
    return {width: measure(tmp_path, width, page, "widest") for width in (1024, 1440)}


WIDTHS = [1024, 1440]


@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_was_measured_at_the_width_asked_for(at, width):
    assert at[width]["window"] == width
    assert len(at[width]["tracks"]) == 7
    assert len(at[width]["decided"]) >= 5


@pytest.mark.parametrize("width", WIDTHS)
def test_every_column_heading_is_on_one_line(at, width):
    assert at[width]["headings"] == [
        ["State", 1], ["Port", 1], ["Service", 1], ["From outside", 1],
        ["Decided by", 1], ["Your answer", 1]]


@pytest.mark.parametrize("width", WIDTHS)
def test_the_decided_by_column_has_room_for_a_short_answer_on_one_line(at, width):
    short = [(words, lines) for words, lines in at[width]["decided"]
             if words in ("your rule", "no rule", "loopback")]
    assert short, at[width]["decided"]
    assert all(lines == 1 for _words, lines in short), short
    # Wide enough for the widest of those and for the two new answers a rule
    # can give (docs/RECORD.md 4.358), measured at 103 in this face.
    assert at[width]["tracks"][4] >= 110


@pytest.mark.parametrize("width", WIDTHS)
def test_the_longest_answer_takes_two_lines_at_most(at, width):
    assert max(lines for _words, lines in at[width]["decided"]) <= 2, at[width]["decided"]
    assert "your rule" in [words for words, _ in at[width]["decided"]]


@pytest.mark.parametrize("width", WIDTHS)
def test_nothing_is_wider_than_its_column(at, width):
    assert at[width]["wider"] == []
    assert at[width]["lastColumnEndsInside"] is True


def test_at_1440_the_columns_are_the_ones_they_were(at):
    """The wide layout is not touched."""
    assert at[1440]["tracks"][:4] == [184, 100, 170, 110]
    assert at[1440]["tracks"][5:] == [270, 22]


@pytest.mark.parametrize("width", WIDTHS)
def test_a_five_digit_port_and_a_long_name_stay_inside_their_columns(widest_at, width):
    got = widest_at[width]
    assert got["wider"] == []
    assert got["lastColumnEndsInside"] is True
    assert [lines for _heading, lines in got["headings"]] == [1, 1, 1, 1, 1, 1]
