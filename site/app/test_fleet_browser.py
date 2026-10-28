"""What the Fleet does, driven in a real browser: the search filters the rows
as you type, a dismissed banner stays dismissed on this browser until the
fact changes, and a row opens the server's page in place.

    Run from site/app: python3 -m pytest test_fleet_browser.py

The page is the sample shell, served over http so localStorage works, and
Chrome's virtual time runs the script. The quiet refresh has its own file,
test_quiet_refresh.py.
"""
import functools
import html as html_mod
import http.server
import json
import pathlib
import re
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

# A second render of the sample, with the banner's fact changed: the same
# shape with a new value is a new fact, so a dismissal must not hide it.
OTHER_FACT = [("fail", "channel:other@example.com",
               "Alert mail to <b>other@example.com</b> was refused by the relay.",
               "Open channel", "alerts")]

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>fleet drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
// The pages and the step to run on each, in order. One Chrome process for the
// whole plan, so what the page keeps in localStorage survives from one page to
// the next the way it does for a reader, without waiting on Chrome to flush it
// to disk before it is killed.
var PLAN=%(plan)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
var results=[], at=0;
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument, step=PLAN[at].step;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var shown=function(){return Array.prototype.filter.call(
      d.querySelectorAll('#fleet .row'),function(r){return r.style.display!=='none'})
      .map(function(r){return r.dataset.host})};
    var notes=function(){return Array.prototype.map.call(
      d.querySelectorAll('#fleet .fnote'),function(n){
        return {key:n.dataset.note,hidden:n.hidden,
                visible:w.getComputedStyle(n).display!=='none'}})};
    var result={step:step,errs:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    if(step==='search'){
      var srch=d.querySelector('#fleet .srch');
      result.all=shown();
      srch.value='media-01'; srch.dispatchEvent(new w.Event('input')); await tick();
      result.found=shown();
      srch.value='ubuntu-app'; srch.dispatchEvent(new w.Event('input')); await tick();
      result.hostname=shown();
      srch.value='WATCHED'; srch.dispatchEvent(new w.Event('input')); await tick();
      result.state=shown();
      srch.value=''; srch.dispatchEvent(new w.Event('input')); await tick();
      result.cleared=shown();
    }
    if(step==='dismiss'){
      result.before=notes();
      d.querySelector('#fleet .fnote .x').click(); await tick();
      result.after=notes();
      result.stored=w.localStorage.getItem('wp-notes-dismissed');
    }
    if(step==='again'){
      // the browser remembers: the same fact stays hidden, the new fact shows
      result.notes=notes();
      result.stored=w.localStorage.getItem('wp-notes-dismissed');
    }
    if(step==='open'){
      d.querySelector('#fleet .row[data-host="media-01"]').click(); await tick();
      result.opened=d.querySelector('.view.on').id;
      result.href=d.querySelector('#fleet .row[data-host="media-01"]').getAttribute('href');
      result.path=w.location.pathname;
    }
    results.push(result);
    at+=1;
    if(at<PLAN.length){f.src=PLAN[at].page}
    else{out.textContent=JSON.stringify(results)}
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src=PLAN[0].page;
</script>
"""


def drive(tmp_path, steps):
    """Serve the pages and run the harness over them in one Chrome run.
    `steps` is [(step name, page html)]. Returns one result per step."""
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    plan = []
    for i, (step, page) in enumerate(steps):
        (site / f"page{i}.html").write_text(page, encoding="utf-8")
        plan.append({"page": f"page{i}.html", "step": step})
    (site / "harness.html").write_text(HARNESS % {"plan": json.dumps(plan)}, encoding="utf-8")
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
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    results = json.loads(html_mod.unescape(got.group(1)))
    assert isinstance(results, list), results
    assert len(results) == len(steps), results
    return results


def sample_with_notes(notes):
    """The sample shell with the banner list swapped."""
    kept = build.FLEET_SAMPLE_NOTES
    build.FLEET_SAMPLE_NOTES = notes
    try:
        return build.build_sample()
    finally:
        build.FLEET_SAMPLE_NOTES = kept


def test_the_search_filters_the_rows_live_on_name_hostname_and_row_text(tmp_path):
    (result,) = drive(tmp_path, [("search", build.build_sample())])
    assert len(result["all"]) == 12
    assert result["found"] == ["media-01"]
    # the hostname under the name is searched too
    assert result["hostname"] == ["app-01"]
    # and the state word, case does not matter
    # the word `watched` is in `not watched` too since 2026-10-09 (docs/record
    # 4.447), so a search for it finds the two it names and the two it is
    # part of, in the page's own order
    assert result["state"] == ["office-06", "store-07", "edge-05", "new-a1b2c3"]
    assert result["cleared"] == result["all"]


def test_a_dismissed_banner_stays_dismissed_until_the_fact_changes(tmp_path):
    first, second, third = drive(tmp_path, [
        ("dismiss", build.build_sample()),
        ("again", build.build_sample()),
        ("again", sample_with_notes(OTHER_FACT)),
    ])
    # shown, then hidden by the click, and the fact's id is what the browser keeps
    assert first["before"] == [{"key": "channel:sysadmin@example.org", "hidden": False,
                                "visible": True}]
    assert first["after"] == [{"key": "channel:sysadmin@example.org", "hidden": True,
                               "visible": False}]
    assert json.loads(first["stored"]) == ["channel:sysadmin@example.org"]
    # a fresh load of the same page: still hidden, nothing asked of the server
    assert second["notes"] == [{"key": "channel:sysadmin@example.org", "hidden": True,
                                "visible": False}]
    # the fact changed: the new banner shows, and the old id is forgotten
    assert third["notes"] == [{"key": "channel:other@example.com", "hidden": False,
                               "visible": True}]
    assert json.loads(third["stored"]) == []


def test_two_banners_show_one_at_a_time_worst_first(tmp_path):
    both = [("warn", "billing:trial", "Trial ends <b>Friday</b>.", "Billing", "settings")] + OTHER_FACT
    first, second = drive(tmp_path, [("dismiss", sample_with_notes(both)),
                                     ("again", sample_with_notes(both))])
    # fail first and the warn behind it, off the screen
    assert [n["key"] for n in first["before"]] == ["channel:other@example.com", "billing:trial"]
    assert [n["visible"] for n in first["before"]] == [True, False]
    # dismissing the first reveals the second, at once and after a reload
    assert [n["visible"] for n in first["after"]] == [False, True]
    assert [n["visible"] for n in second["notes"]] == [False, True]


def test_a_row_opens_the_servers_page_in_place_and_is_a_real_link(tmp_path):
    (result,) = drive(tmp_path, [("open", build.build_sample())])
    assert result["href"] == "/host/media-01"
    # the sample has one demo host page, which every row leads to
    assert result["opened"] == "host"
    assert result["path"] == "/host/demo"
