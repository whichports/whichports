"""The count beside Sent is the count of the range that is chosen, in a real
browser (docs/RECORD.md 4.393, 4.395).

The count was every line the page had read, thirty days of them, whatever
range was chosen. Measured on 2026-10-06: "Sent 3" beside the 7d range, above
"Nothing sent in the last 7 days". The three were ten days old.

    Run from site/: python3 -m pytest app/test_alerts_sent_count_browser.py
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

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the sent count</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var visible=function(el){return !!el&&el.getClientRects().length>0};
    var look=function(){
      var heading=Array.prototype.filter.call(d.querySelectorAll('#alerts h2.alh2'),function(h){
        return h.firstChild.textContent.trim()==='Sent'})[0];
      var counts=Array.prototype.filter.call(heading.querySelectorAll('.cnt'),visible);
      return {count:counts.map(function(c){return c.textContent}),
        lines:Array.prototype.filter.call(d.querySelectorAll('#alerts .alsent .al[data-r]'),visible).length,
        empty:Array.prototype.filter.call(d.querySelectorAll('#alerts .alsent .alempty'),visible)
          .map(function(e){return e.textContent})}};
    d.querySelector('nav.nav a[data-v="alerts"]').click(); await tick(100);
    seen.opensOn=look();
    for (var name of ['24h','7d','30d']) {
      d.querySelector('label[for="sg-alerts-'+name+'"]').click(); await tick(100);
      seen[name]=look();
    }
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def page(tmp_path, name, ages):
    """One server and one alert that was sent for each age given."""
    path = str(tmp_path / f"{name}.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
    trl.add_channel(path)
    for age in ages:
        trl.add_alert(path, "box", "no report for 40 minutes, past the 35 minute threshold",
                      NOW - age, resolved=True, notified=True)
    return rl.render(path, now=NOW)


def drive(tmp_path, name, ages):
    site = tmp_path / f"www-{name}"
    site.mkdir()
    (site / "live.html").write_text(page(tmp_path, name, ages), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / f'chrome-{name}'}",
             "--virtual-time-budget=5000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def spread(tmp_path_factory):
    """One sent two hours ago, one three days ago, two ten days ago."""
    return drive(tmp_path_factory.mktemp("sent"), "spread",
                 [timedelta(hours=2), timedelta(days=3), timedelta(days=10), timedelta(days=11)])


@pytest.fixture(scope="module")
def old(tmp_path_factory):
    """The measured case: three, all of them ten days old or more."""
    return drive(tmp_path_factory.mktemp("sent-old"), "old",
                 [timedelta(days=10), timedelta(days=11), timedelta(days=12)])


@pytest.mark.parametrize("name, count", [("24h", 1), ("7d", 2), ("30d", 4)])
def test_the_count_is_the_count_of_the_chosen_range(spread, name, count):
    got = spread[name]
    assert got["lines"] == count
    assert got["count"] == [str(count)]
    assert got["empty"] == []


def test_the_page_opens_on_seven_days_with_that_ranges_count(spread):
    assert spread["opensOn"] == spread["7d"]


def test_a_range_with_nothing_sent_shows_no_count_above_its_empty_line(old):
    for name, words in (("24h", "Nothing sent in the last 24 hours"),
                        ("7d", "Nothing sent in the last 7 days")):
        assert old[name] == {"count": [], "lines": 0, "empty": [words]}, name


def test_the_older_ones_are_counted_where_they_are_listed(old):
    assert old["30d"] == {"count": ["3"], "lines": 3, "empty": []}


@pytest.mark.parametrize("name", ["24h", "7d", "30d"])
def test_never_more_than_one_count_is_shown(spread, old, name):
    assert len(spread[name]["count"]) <= 1 and len(old[name]["count"]) <= 1
