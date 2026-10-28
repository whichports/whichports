"""A mark never wraps under its state on the Fleet, measured in a real
browser at 1440 and at 1024.

    Run from site/app: python3 -m pytest test_fleet_marks_browser.py

`docs/DESIGN.md` section 3: the facts beside a state are slim marks in the
same line, and a mark never wraps under its state. Measured on 2026-10-11
(`docs/RECORD.md` 4.445): the State column was 150 px wide, 130 px at 1024,
and a slim mark takes 29 px with its gap. So a muted server that also
carried the rarely-public mark wrapped at 1024 on `watched`, 131 px in 130,
one mark alone wrapped on the longest word of that day, which has since
become `not watched`, and three wrapped on every word at both widths.

The CVE check's own mark is the fourth a row can carry (`docs/RECORD.md`
4.446), and the paused mark beside a worse word the fifth (4.453). So the
most a State cell holds is five, and that row is here too.

The rows here are drawn by the page's own builder and put into the sample
shell's table, so the stylesheet under test is the one that ships.
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

# (state tone, state word, name, muted, an open alert, rarely public, the
# words of the CVE check's mark)
ROWS = [
    ("ok", "watched", "two-marks", True, "", True, ""),
    ("ok", "reporting", "three-marks", True, "2026-10-11 09:00 UTC", True, ""),
    ("warn", "unreviewed", "three-on-a-finding", True, "2026-10-11 09:00 UTC", True, ""),
    ("fail", "not readable", "a-long-word", True, "", False, ""),
    ("off", "not watched", "not-watched", True, "", False, ""),
    ("ok", "watched", "no-mark", False, "", False, ""),
    ("ok", "watched", "the-checks-mark", False, "", False, "a newer version fixes 1 CVE"),
    ("ok", "reporting", "four-marks", True, "2026-10-11 09:00 UTC", True, "an update fixes 2 CVEs"),
    ("warn", "unreviewed", "four-on-a-finding", True, "2026-10-11 09:00 UTC", True, "an update fixes 12 CVEs"),
]
MARKS = [2, 3, 3, 1, 1, 0, 1, 4, 4]
# Every mark a row can carry at once: paused under a worse word, muted, an
# open alert, rarely public, and the check's.
FIVE = ("warn", "unreviewed", "five-marks", "an update fixes 3 CVEs")

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>fleet marks</title>
<pre id="out"></pre>
<iframe id="f" width="%(width)d" height="%(height)d" style="border:0"></iframe>
<script>
var out=document.getElementById('out'), f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||80)})};
    var table=d.querySelector('#fleet .ftbl');
    Array.prototype.forEach.call(table.querySelectorAll('a.row'),function(r){r.remove()});
    table.insertAdjacentHTML('beforeend',%(rows)s);
    await tick();
    var mid=function(el){var b=el.getBoundingClientRect();return (b.top+b.bottom)/2};
    var rows=Array.prototype.map.call(table.querySelectorAll('a.row'),function(r){
      var cell=r.children[0], state=cell.querySelector('.st');
      var marks=Array.prototype.filter.call(cell.children,function(el){
        return el!==state&&el.getClientRects().length>0});
      var fix=cell.querySelector('.tag-fix'), rare=cell.querySelector('.tag-rare');
      var box=function(el){var b=el.getBoundingClientRect();return [Math.round(b.width),Math.round(b.height)]};
      return {name:r.dataset.host, marks:marks.length,
        fix:fix?{title:fix.title,box:box(fix),shown:marks.indexOf(fix)>=0}:null,
        rare:rare?box(rare):null,
        under:marks.filter(function(m){return Math.abs(mid(m)-mid(state))>2}).length,
        cut:marks.filter(function(m){
          return m.getBoundingClientRect().right>cell.getBoundingClientRect().right+0.5}).length,
        cell:Math.round(cell.getBoundingClientRect().width),
        serverLeft:Math.round(r.children[1].getBoundingClientRect().left),
        lastWidth:Math.round(r.children[3].getBoundingClientRect().width)}});
    var head=table.querySelector('.thead');
    out.textContent=JSON.stringify({rows:rows,
      headServerLeft:Math.round(head.children[1].getBoundingClientRect().left),
      wide:d.documentElement.scrollWidth-d.documentElement.clientWidth});
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='page.html';
</script>
"""


def fleet_rows():
    tone, word, name, fix = FIVE
    return build.fleet_rows_html([
        build.FleetRow(tone, word, name, muted=muted, alert=alert, rarely=rarely, fix=fix)
        for tone, word, name, muted, alert, rarely, fix in ROWS] + [
        build.FleetRow(tone, word, name, muted=True, alert="2026-10-11 09:00 UTC", rarely=True,
                       paused=True, fix=fix)])


def measure(tmp_path, width, height):
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    (site / "page.html").write_text(build.build_sample(), encoding="utf-8")
    (site / "harness.html").write_text(
        HARNESS % {"width": width, "height": height, "rows": json.dumps(fleet_rows())}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox", "--no-first-run",
             f"--user-data-dir={tmp_path / 'chrome-profile'}", f"--window-size={width + 40},{height + 200}",
             "--virtual-time-budget=8000", "--dump-dom",
             f"http://127.0.0.1:{server.server_address[1]}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    seen = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in seen, seen
    return seen


@pytest.mark.parametrize("width,height", [(1440, 900), (1024, 768)])
def test_no_mark_wraps_under_its_state_on_the_fleet(tmp_path, width, height):
    seen = measure(tmp_path, width, height)
    by_name = {row["name"]: row for row in seen["rows"]}
    # The rows were drawn with the marks this test is about.
    assert [by_name[name]["marks"] for _t, _w, name, *_ in ROWS] == MARKS, seen["rows"]
    assert by_name[FIVE[2]]["marks"] == 5, by_name[FIVE[2]]
    for row in seen["rows"]:
        assert row["under"] == 0, f"{row['name']} at {width}: {row['under']} of its marks stand under its state"
        assert row["cut"] == 0, f"{row['name']} at {width}: a mark runs out of its cell"
    # One column for every row and for the header: a row with three marks
    # does not push its own name aside and leave the others where they were.
    lefts = {row["serverLeft"] for row in seen["rows"]} | {seen["headServerLeft"]}
    assert len(lefts) == 1, f"the Server column starts at {sorted(lefts)} at {width}"
    assert seen["wide"] <= 0, f"the page runs {seen['wide']} px wide at {width}"
    assert all(row["lastWidth"] > 100 for row in seen["rows"]), seen["rows"]


@pytest.mark.parametrize("width,height", [(1440, 900), (1024, 768)])
def test_the_checks_mark_is_drawn_on_its_rows_in_the_slim_marks_own_box(tmp_path, width, height):
    """The check's mark has a rule of its own beside the other marks' rule,
    so nothing but this holds the two boxes to one size. Its words are its
    title, as the page says them, and a row the check says nothing of
    carries no such mark."""
    seen = measure(tmp_path, width, height)
    by_name = {row["name"]: row for row in seen["rows"]}
    for _tone, _word, name, _muted, _alert, _rarely, fix in ROWS:
        got = by_name[name]["fix"]
        if not fix:
            assert got is None, f"{name} carries the check's mark and was given none"
            continue
        assert got["title"] == fix and got["shown"], got
    for name in ("four-marks", "four-on-a-finding", FIVE[2]):
        assert by_name[name]["fix"]["box"] == by_name[name]["rare"], by_name[name]
    assert by_name[FIVE[2]]["fix"]["title"] == FIVE[3]


def test_a_fleet_without_marks_keeps_the_width_its_state_column_had(tmp_path):
    """The column grows for the row that needs it and for nothing else."""
    plain = build.fleet_rows_html([build.FleetRow("ok", "watched", "no-mark"),
                                   build.FleetRow("ok", "reporting", "nor-this")])
    kept = fleet_rows.__globals__["fleet_rows"]
    fleet_rows.__globals__["fleet_rows"] = lambda: plain
    try:
        wide = measure(tmp_path, 1440, 900)
        narrow = measure(tmp_path, 1024, 768)
    finally:
        fleet_rows.__globals__["fleet_rows"] = kept
    assert {row["cell"] for row in wide["rows"]} == {150}, wide["rows"]
    assert {row["cell"] for row in narrow["rows"]} == {130}, narrow["rows"]
