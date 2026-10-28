"""Two vantages that disagree: the mark on the Evidence tab's prober cell,
the lines under it, the mark after "n of m" on the fleet row, and the prober
card's `vantages` line (docs/screens/host-evidence/SPEC.md and
docs/screens/fleet/SPEC.md, the paragraphs decided 2026-09-08,
docs/PRODUCT.md 8e).

    Run from site/app: python3 -m pytest test_disagree_mark.py

The engine puts the mark on OutsideView.disagree and what each vantage said
on OutsideView.views (record 4.157). This file proves the screen draws
exactly that and nothing more: no colour, no sentence, no vantage named
when they agree, no vantage named that measured nothing.
"""
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_fleet import fleet_rows, row_cells  # noqa: E402
from test_host_evidence import cards_of, lines_of, row  # noqa: E402
from test_render_live import (  # noqa: E402
    NOW, SSHD, SSHD6, db, document, host_section, probe_result, reporting, tab_body)

__all__ = ["db"]

MARK = '<span class="tag-disagree">disagree</span>'


# ------------------------------------------------------------ the fragments

def test_the_mark_is_the_rate_flags_shape_and_nothing_when_they_agree():
    assert build.disagree_flag(True) == MARK
    assert build.disagree_flag(False) == ""
    assert build.DISAGREE_WORD == "disagree"


def test_the_theme_gives_the_mark_the_rate_flags_rule():
    css = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", build.build_sample(), re.S))
    base = re.search(r"\.tag-planned,\.tag-rate,[^{]*\{", css).group(0)
    assert ".tag-disagree" in base
    tight = re.search(r"\.tag-rate,\.tag-rvw,[^{]*\{", css).group(0)
    assert ".tag-disagree" in tight


def test_the_prober_cell_carries_the_mark_and_one_line_per_vantage():
    html = build.evidence_row_html("box", row(
        disagree=True, views=(("probe1", "no response"), ("probe2", "connect succeeded"))))
    assert ('<span class="mv"><span class="mvw"><span class="st nt">open</span>' + MARK
            + '</span><span class="mvv">probe1 no answer</span>'
            '<span class="mvv">probe2 open</span></span>') in html
    # the State column is untouched: the mark is a fact about the measurement
    assert '<span class="mst"><span class="st fail">conflict</span></span>' in html


def test_when_the_vantages_agree_the_cell_is_the_word_alone():
    html = build.evidence_row_html("box", row(
        disagree=False, views=(("probe1", "connect succeeded"), ("probe2", "connect succeeded"))))
    assert MARK not in html and "mvv" not in html and "probe1" not in html
    assert '<span class="st nt">open</span>' in html


def test_the_reach_cell_takes_the_mark_after_n_of_m():
    assert build.reach_cell_html((3, 8), True) == "<b>3</b> of 8 ports" + MARK
    assert build.reach_cell_html((3, 8)) == "<b>3</b> of 8 ports"
    assert build.reach_cell_html(None, True) == ""


def test_a_fleet_row_draws_its_mark_in_the_reachable_cell():
    marked = build.FleetRow("ok", "watched", "box", reach=(1, 2), disagree=True)
    assert row_cells(build.fleet_row_html(marked))[2] == "<b>1</b> of 2 ports" + MARK
    plain = build.FleetRow("ok", "watched", "box", reach=(1, 2))
    assert row_cells(build.fleet_row_html(plain))[2] == "<b>1</b> of 2 ports"


def test_the_sample_card_line_is_vantages():
    """The line's word, and since 2026-10-07 both of the sample's probers
    where it named one (docs/RECORD.md 4.443)."""
    assert ('<span class="evk">vantages</span><span>' + build.mono("probe1") + ", "
            + build.mono("probe2") + "</span>" in build.build_sample())


# ------------------------------------------------------------- the live page

def two_vantages(db, agree=False):
    """One host, port 22 measured from two vantages: probe2 saw it open,
    probe1 saw nothing, unless they agree."""
    reporting(db, "box", document(listening=[SSHD, SSHD6]))
    probe_result(db, "box", 22, "v4", "connect_succeeded", vantage="probe2",
                 measured_at=NOW - timedelta(minutes=9))
    probe_result(db, "box", 22, "v4", "connect_succeeded" if agree else "no_response",
                 vantage="probe1", measured_at=NOW - timedelta(minutes=4))


def evidence_rows(db, name="box"):
    html = tab_body(host_section(rl.render(db, now=NOW), name), name, "evidence")
    return re.findall(r'<div class="mr" .*?</div>', html.split('<div class="evcs">')[0], re.S)


def registry(db, *names, off=()):
    module = rl.joinbridge.module("vantages")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    module.init(con)
    for n, name in enumerate(names):
        module.add(con, name, f"root@{name}", [f"185.199.110.{n + 1}"])
    for name in off:
        module.set_enabled(con, name, False)
    con.commit()
    con.close()


def test_a_disagreement_is_drawn_on_the_evidence_row_and_the_fleet_row(db):
    two_vantages(db)
    rows = evidence_rows(db)
    v4 = next(r for r in rows if '<i class="v4">' in r)
    # open from probe2, the mark, then what each said by name
    assert ('<span class="mv"><span class="mvw"><span class="st nt">open</span>' + MARK
            + '</span><span class="mvv">probe1 no answer</span>'
            '<span class="mvv">probe2 open</span></span>') in v4
    v6 = next(r for r in rows if '<i class="v6">' in r)
    assert MARK not in v6 and "mvv" not in v6
    # port 22 on two families is one observed port, and it is open from probe2
    fleet = fleet_rows(rl.render(db, now=NOW))
    assert row_cells(fleet[0])[2] == "<b>1</b> of 1 port" + MARK


def test_agreement_draws_nothing_and_names_no_vantage_on_the_row(db):
    two_vantages(db, agree=True)
    html = rl.render(db, now=NOW)
    assert MARK not in html
    v4 = next(r for r in evidence_rows(db) if '<i class="v4">' in r)
    assert "probe1" not in v4 and "probe2" not in v4
    assert row_cells(fleet_rows(html)[0])[2] == "<b>1</b> of 1 port"


def test_a_vantage_that_measured_nothing_is_not_named_under_the_word(db):
    """A stored not_tested row is a vantage that did not measure: the engine
    leaves it out of the comparison and the screen leaves it out of the
    lines (docs/PRODUCT.md 8e)."""
    two_vantages(db)
    probe_result(db, "box", 22, "v4", "not_tested", vantage="probe3",
                 measured_at=NOW - timedelta(minutes=1))
    v4 = next(r for r in evidence_rows(db) if '<i class="v4">' in r)
    assert "probe3" not in v4
    assert v4.count('<span class="mvv">') == 2


def test_the_prober_card_lists_every_enabled_vantage_in_registry_order(db):
    two_vantages(db)
    registry(db, "probe2", "probe1", "probe3", off=("probe3",))
    lines = lines_of(cards_of(db)[1][3])
    assert lines["vantages"] == f'{build.mono("probe1")}, {build.mono("probe2")}'
    assert "vantage" not in lines


def test_without_a_registry_the_card_names_the_vantages_that_measured(db):
    two_vantages(db)
    lines = lines_of(cards_of(db)[1][3])
    assert lines["vantages"] == f'{build.mono("probe1")}, {build.mono("probe2")}'


def test_the_mark_never_takes_a_tone_and_never_reaches_the_boxes(db):
    """The mark is per port on Evidence and per server on the Fleet, never a
    fleet number: the Reachable box counts the port as reachable and shows
    no mark (docs/screens/fleet/SPEC.md)."""
    two_vantages(db)
    html = rl.render(db, now=NOW)
    strip = re.search(r'<div class="fstrip">(.*?)</div>\s*<input class="srch"', html, re.S).group(1)
    assert MARK not in strip
    assert re.search(r'<span class="tag-disagree" [^>]*class="(fail|warn|ok)"', html) is None


# ------------------------------------------------------------ in the browser
#
# The prober and provider tags sit 8px in from their column on every row,
# from the theme's .st+.st spacing. A row with the mark wraps its prober tag,
# so without a rule of its own it lost those 8px and its tags started left of
# the rows above and below it, read off the shot by the spec session on
# 2026-09-14 and measured at 700 against 708. Real pixels from Chrome, because
# "not in line" is a number and a screenshot hides it.

import functools  # noqa: E402
import html as html_mod  # noqa: E402
import http.server  # noqa: E402
import json  # noqa: E402
import threading  # noqa: E402

from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

MEASURE = """<script>window.addEventListener('load',function(){setTimeout(function(){
 var rows=[];document.querySelectorAll('#host-box .mr').forEach(function(r){
   var cells=[];r.querySelectorAll(':scope > *').forEach(function(c){
     cells.push(Math.round(c.getBoundingClientRect().left))});
   rows.push(cells)});
 var pre=document.createElement('pre');pre.id='measure';
 pre.textContent=JSON.stringify(rows);document.body.appendChild(pre)},300)})</script>"""


def measure(tmp_path, page):
    site = tmp_path / "www"
    site.mkdir()
    (site / "index.html").write_text(page.replace("</body>", MEASURE + "</body>", 1),
                                     encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--window-size=1440,900", "--virtual-time-budget=4000", "--dump-dom",
             f"http://127.0.0.1:{port}/index.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="measure">(.*?)</pre>', dom, re.S)
    assert got, f"nothing measured, the dumped page was:\n{dom[:2000]}"
    return json.loads(html_mod.unescape(got.group(1)))


def test_a_row_with_the_mark_keeps_its_cells_in_line_with_the_rows_without(tmp_path, db):
    two_vantages(db)
    # the Evidence tab open: the view on, and its radio checked, as the page
    # script does from the path
    page = rl.render(db, now=NOW)
    page = page.replace('<div class="wrap view on" id="fleet">', '<div class="wrap view" id="fleet">', 1)
    page = page.replace('<div class="wrap view" id="host-box"', '<div class="wrap view on" id="host-box"', 1)
    page = page.replace('id="tb-box-overview" checked', 'id="tb-box-overview"', 1)
    page = page.replace('id="tb-box-evidence"', 'id="tb-box-evidence" checked', 1)
    rows = measure(tmp_path, page)
    assert len(rows) == 2 and len(rows[0]) == 6, rows
    # 22/v4 carries the mark, 22/v6 does not: every cell starts on the same x
    assert rows[0] == rows[1], rows
