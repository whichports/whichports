"""The two motions of the dashboard, a view arriving and a window opening
(docs/RECORD.md 4.416, 4.419, docs/DESIGN.md section 5).

Each is an animation on a class the page's script already sets, `.view.on`
and `.ovl.on`, so the script is untouched. What is held here, in a real
browser:

- the durations and the curve are the design's two and one, and no other,
- with reduced motion asked for nothing moves: the view and the window are
  simply there,
- once a motion has ended nothing keeps a transform, so the top bar stays
  pinned to the browser window and a window's foot stays at its bottom,
- the quiet refresh that swaps a piece of a view plays nothing.

    Run from site/: python3 -m pytest app/test_motion_browser.py
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
import theme  # noqa: E402
import test_refresh_reaches_browser as pages_of  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

QUICK, MOVE = 0.12, 0.18
EASE = "cubic-bezier(0.2, 0, 0.2, 1)"

# The frame is short so the page scrolls and the Add server window's form
# scrolls inside it: both pinned things have something to hold against.
HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the two motions</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="420"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    // This browser is run on a clock of its own and draws no frame, so an
    // animation stands at its first frame until it is ended. `ours` reads
    // which of the three are in play, `end` ends them the browser's own way.
    var OURS=['v-in','o-in','m-in'];
    var mine=function(){return d.getAnimations().filter(function(a){
      return OURS.indexOf(a.animationName)>=0})};
    var ours=function(){return mine().map(function(a){
      return a.animationName+' on '+(a.effect.target.id||a.effect.target.className)}).sort()};
    var end=async function(){
      var all=mine();
      all.forEach(function(a){a.finish()});
      await Promise.all(all.map(function(a){return a.finished}));
      await tick(20)};
    var playing=function(el){
      var s=w.getComputedStyle(el);
      return {name:s.animationName,seconds:parseFloat(s.animationDuration),
              curve:s.animationTimingFunction,fill:s.animationFillMode,
              running:el.getAnimations().length}};
    var rest=function(el){
      var s=w.getComputedStyle(el);
      return {transform:s.transform,opacity:s.opacity,running:el.getAnimations().length}};
    var shown=function(){return d.querySelector('.view.on')};
    await d.fonts.ready;
    seen.reduced=w.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // The first paint: the Fleet is the view that is on.
    seen.first=playing(shown());
    seen.firstInPlay=ours();
    await end();
    seen.firstRest=rest(shown());

    // A view switched to.
    d.querySelector('nav.nav a[data-v="alerts"]').click();
    seen.view=playing(shown());
    seen.viewIs=shown().id;
    seen.viewInPlay=ours();
    await end();
    seen.viewRest=rest(shown());

    // The top bar, with the page scrolled, after a view has arrived.
    d.querySelector('nav.nav a[data-v="fleet"]').click(); await end();
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
    await end();
    w.scrollTo(0,200); await tick(50);
    seen.scrolledBy=w.scrollY;
    seen.topBarAt=d.querySelector('.top').getBoundingClientRect().top;
    w.scrollTo(0,0);
    d.querySelector('nav.nav a[data-v="fleet"]').click(); await end();

    // A window opened.
    d.querySelector('#fleet .js-add').click();
    var ovl=d.getElementById('add-ovl'), modal=ovl.querySelector('.modal');
    seen.overlay=playing(ovl);
    seen.modal=playing(modal);
    seen.windowInPlay=ours();
    await end();
    seen.overlayRest=rest(ovl);
    seen.modalRest=rest(modal);

    // Its foot, with the form long enough to scroll under it.
    d.getElementById('add-linux').click(); await tick(50);
    d.getElementById('add-addr').click(); await tick(50);
    d.getElementById('add-addr-http').click(); await tick(50);
    var foot=modal.querySelector('.m-foot');
    var footAt=function(){
      var m=modal.getBoundingClientRect(), b=foot.getBoundingClientRect();
      return {below:Math.round((m.bottom-b.bottom)*10)/10,inside:b.top>=m.top&&b.bottom<=m.bottom+0.5}};
    seen.formScrolls=modal.scrollHeight>modal.clientHeight+1;
    modal.scrollTop=0; await tick(50);
    seen.footAtTop=footAt();
    modal.scrollTop=modal.scrollHeight; await tick(50);
    seen.footAtEnd=footAt();
    d.getElementById('add-close').click(); await tick(100);
    await end();

    // The quiet refresh, with a page whose Fleet and count changed.
    var gets=w.__gets;
    seen.inPlayBeforeTheRefresh=ours();
    w.__serve='three';
    await tick(61000); await tick(300);
    seen.refresh={asked:w.__gets-gets,
                  rowsNow:d.querySelectorAll('#fleet .row[data-host]').length,
                  inPlay:ours()};
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def drive(tmp_path, pages, reduced):
    site = tmp_path / ("www-reduced" if reduced else "www")
    site.mkdir()
    embedded = json.dumps(pages).replace("</", "<\\/")
    first = pages["two"]
    assert first.count("<head>") == 1
    (site / "live.html").write_text(
        first.replace("<head>", "<head>" + pages_of.STUB % {"pages": embedded}, 1),
        encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={site / 'chrome-profile'}"]
            + (["--force-prefers-reduced-motion"] if reduced else [])
            + ["--virtual-time-budget=90000", "--dump-dom",
               f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("motion")
    pages = pages_of.three_pages(tmp_path)
    return {"moving": drive(tmp_path, pages, reduced=False),
            "reduced": drive(tmp_path, pages, reduced=True)}


@pytest.fixture(scope="module")
def moving(runs):
    return runs["moving"]


@pytest.fixture(scope="module")
def reduced(runs):
    return runs["reduced"]


# ------------------------------------------------------------- the two runs

def test_the_two_runs_are_what_their_names_say(moving, reduced):
    assert moving["reduced"] is False
    assert reduced["reduced"] is True
    assert moving["viewIs"] == reduced["viewIs"] == "alerts"


# ---------------------------------------------- the design's two and one

def test_the_tokens_are_the_designs_two_durations_and_one_curve():
    assert "--quick:120ms;--move:180ms;--ease:cubic-bezier(.2,0,.2,1)" in theme.TOKENS


def test_a_view_arrives_in_move_on_the_one_curve(moving):
    for when in ("first", "view"):
        assert moving[when]["name"] == "v-in", moving[when]
        assert moving[when]["seconds"] == MOVE
        assert moving[when]["curve"] == EASE


def test_a_window_opens_in_quick_and_move_on_the_one_curve(moving):
    assert (moving["overlay"]["name"], moving["overlay"]["seconds"]) == ("o-in", QUICK)
    assert (moving["modal"]["name"], moving["modal"]["seconds"]) == ("m-in", MOVE)
    assert moving["overlay"]["curve"] == moving["modal"]["curve"] == EASE


def test_the_motions_are_written_with_the_tokens_and_no_number_of_their_own():
    rules = re.findall(r"(\.(?:view|ovl)\.on[^{]*)\{animation:([^}]*)\}", build.CSS)
    assert sorted(rules) == [(".ovl.on", "o-in var(--quick) var(--ease)"),
                             (".ovl.on .modal", "m-in var(--move) var(--ease)"),
                             (".view.on", "v-in var(--move) var(--ease)")]


def test_no_motion_keeps_its_last_frame_by_a_fill_word(moving):
    """A fill word leaves a transform on the element for good."""
    for when in ("first", "view", "overlay", "modal"):
        assert moving[when]["fill"] == "none", (when, moving[when])


def test_it_is_in_play_at_the_click_and_only_what_was_asked_for(moving):
    """A view switched to plays the view alone, and a window opened plays
    the window and the dimming behind it and not the view again."""
    assert moving["firstInPlay"] == ["v-in on fleet"]
    assert moving["viewInPlay"] == ["v-in on alerts"]
    assert moving["windowInPlay"] == ["m-in on modal panel", "o-in on add-ovl"]


# -------------------------------------------------- once it has ended

@pytest.mark.parametrize("run", ["moving", "reduced"])
@pytest.mark.parametrize("when", ["firstRest", "viewRest", "overlayRest", "modalRest"])
def test_once_ended_nothing_keeps_a_transform_or_is_see_through(runs, run, when):
    """Ended here by the browser's own `finish`, since this browser draws no
    frame. That a motion ends by itself in its own time is measured in a
    browser at real speed, and the record says what that read."""
    assert runs[run][when] == {"transform": "none", "opacity": "1", "running": 0}


@pytest.mark.parametrize("run", ["moving", "reduced"])
def test_the_top_bar_stays_pinned_with_the_page_scrolled(runs, run):
    assert runs[run]["scrolledBy"] == 200
    assert runs[run]["topBarAt"] == 0


@pytest.mark.parametrize("run", ["moving", "reduced"])
def test_a_windows_foot_stays_at_its_bottom_while_the_form_scrolls(runs, run):
    got = runs[run]
    assert got["formScrolls"] is True
    assert got["footAtTop"]["inside"] and got["footAtEnd"]["inside"], got
    assert got["footAtTop"]["below"] <= 1, got["footAtTop"]


def test_the_foot_is_where_it_is_without_any_motion(moving, reduced):
    assert moving["footAtTop"] == reduced["footAtTop"]
    assert moving["footAtEnd"] == reduced["footAtEnd"]


# ------------------------------------------------------ reduced motion

@pytest.mark.parametrize("when", ["first", "view", "overlay", "modal"])
def test_with_reduced_motion_a_motion_lasts_no_time(reduced, when):
    """The blanket rule's 0.01ms, so an end still fires and nothing is seen."""
    assert reduced[when]["seconds"] <= 0.00002, reduced[when]


# ------------------------------------------------------ the quiet refresh

@pytest.mark.parametrize("run", ["moving", "reduced"])
def test_a_quiet_refresh_that_swaps_a_piece_plays_nothing(runs, run):
    assert runs[run]["inPlayBeforeTheRefresh"] == []
    got = runs[run]["refresh"]
    assert got["asked"] >= 1 and got["rowsNow"] == 4, got
    assert got["inPlay"] == [], got
