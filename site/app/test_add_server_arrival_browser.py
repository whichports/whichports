"""The Add server window shows the server arriving, driven in a real browser.

docs/screens/add-server/BRIEF-arrival.md, the owner's yes of 2026-09-20. He
installed the first outside server, nothing on screen said it had worked, and he
ran enable, start and oneshot by hand. The window now shows two rows under the
install command: First report, then First measurement.

The page is a live render of an empty workspace and the server it talks to is
the harness: the create answers an id and a command, the arrival route answers
"nothing yet", then a report, then a finished pass, and the page's own fetch
of itself answers the render of the workspace with that server measured.

    Run from site/: python3 -m pytest app/test_add_server_arrival_browser.py
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

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>arrival drive</title>
<pre id="out"></pre>
<iframe id="f" width="1200" height="900"></iframe>
<script>
var NEXT=%(next)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  if(f.contentWindow.location.pathname.indexOf('/host/')===0)return;
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var asks=0, pages=0, posts=0;
    // What the arrival route answers on its 1st, 2nd, 3rd... call.
    var ANSWERS=[
      {name:'new-abc123',reported_at:null,probed_at:null},
      {name:'web-01',reported_at:new Date().toISOString(),probed_at:null},
      {name:'web-01',reported_at:new Date().toISOString(),
       probed_at:new Date().toISOString()}];
    var answer=function(body,status){return Promise.resolve({ok:true,
      redirected:false,status:status||200,
      json:function(){return Promise.resolve(body)},
      text:function(){return Promise.resolve(NEXT)}})};
    w.fetch=function(url,opts){
      url=String(url);
      if(opts&&opts.method==='POST'){posts++;
        return answer({id:7,name:'new-abc123',kind:'agent',
          install_command:'curl -fsSL https://get.whichports.com/install.sh | sudo sh'},201)}
      if(url.indexOf('/api/admin/hosts/arrival/7')===0){
        var a=ANSWERS[Math.min(asks,ANSWERS.length-1)];asks++;return answer(a)}
      pages++;return answer({});
    };
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var rows=function(){return Array.prototype.map.call(
      d.querySelectorAll('#add-arr .arr-row'),function(r){
        var mark=r.querySelector('.arr-m .ic');
        return {step:r.dataset.step,label:r.querySelector('.arr-l').textContent,
          value:r.querySelector('.arr-v').textContent,
          spinner:!!mark&&w.getComputedStyle(mark).display!=='none'}})};
    // What is painted, not only the attribute: a class that sets display
    // would keep a hidden element on the screen.
    var snap=function(){return {hidden:w.getComputedStyle(
        d.getElementById('add-arr')).display==='none',
      rows:rows(),button:d.getElementById('add-done').textContent,
      asks:asks,pages:pages}};
    var seen={};
    d.querySelector('.js-add').click(); await tick();
    seen.opened=snap();
    d.getElementById('add-linux').click(); await tick();
    d.getElementById('add-agent').click(); await tick(200);
    seen.command=snap();
    seen.commandText=d.getElementById('add-cmd').textContent;
    await tick(3100); seen.first=snap();      // answered: nothing yet
    await tick(3000); seen.reported=snap();   // answered: a report
    await tick(3000); await tick(300); seen.measured=snap();
    await tick(9500); seen.later=snap();      // and it has stopped asking
    seen.posts=posts;
    seen.path=w.location.pathname;
    // Closing with the cross, then opening again, starts clean.
    d.getElementById('add-close').click(); await tick();
    d.querySelector('.js-add').click(); await tick();
    seen.reopened=snap();
    out.textContent=JSON.stringify(seen);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def empty_workspace(path):
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def drive(tmp_path, first, second):
    site = tmp_path / "www"
    site.mkdir()
    (site / "live.html").write_text(first, encoding="utf-8")
    embedded = json.dumps(second).replace("</", "<\\/")
    (site / "harness.html").write_text(HARNESS % {"next": embedded},
                                       encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=40000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


def test_the_window_shows_the_server_arriving(tmp_path):
    first = rl.render(empty_workspace(tmp_path / "a.db"), now=NOW)
    second_db = empty_workspace(tmp_path / "b.db")
    trl.reporting(second_db, "web-01", trl.document(listening=[trl.SSHD]))
    trl.probe_result(second_db, "web-01", 22, "v4", "connect_succeeded")
    second = rl.render(second_db, now=NOW)
    assert 'data-host="web-01"' in second

    got = drive(tmp_path, first, second)
    wait, idle, done = "wait", "idle", "done"

    # Before a command is on the window there is nothing to wait for.
    assert got["opened"]["hidden"] is True
    assert got["opened"]["asks"] == 0

    # The command is there: First report is waited for, with the spinner.
    assert got["commandText"].startswith("curl -fsSL")
    assert got["command"]["hidden"] is False
    assert [r["label"] for r in got["command"]["rows"]] == [
        "First report", "First measurement"]
    assert [(r["step"], r["spinner"], r["value"]) for r in got["command"]["rows"]] == [
        (wait, True, ""), (idle, False, "")]
    assert got["command"]["button"] == "Done"

    # Asked once, answered "nothing yet": nothing moves, and no sentence came.
    assert got["first"]["asks"] == 1
    assert [(r["step"], r["value"]) for r in got["first"]["rows"]] == [
        (wait, ""), (idle, "")]

    # The report arrived: its own hostname and the age, and the next step turns.
    report_row, probe_row = got["reported"]["rows"]
    assert report_row["step"] == done and not report_row["spinner"]
    assert re.fullmatch(r"web-01, \d+s ago", report_row["value"]), report_row
    assert (probe_row["step"], probe_row["spinner"]) == (wait, True)
    assert got["reported"]["button"] == "Done"

    # Measured: the Fleet's own number, read off the page, and the button.
    report_row, probe_row = got["measured"]["rows"]
    assert probe_row["step"] == done and not probe_row["spinner"]
    # the Fleet's cell carries its unit since 2026-10-11 (docs/record 4.451),
    # and this row reads the cell
    assert probe_row["value"] == "1 of 1 port reachable", probe_row
    assert got["measured"]["button"] == "Open server"
    assert got["measured"]["pages"] == 1

    # It stops asking once both are done, and nothing reloaded or navigated.
    assert got["later"]["asks"] == got["measured"]["asks"] == 3
    assert got["later"]["pages"] == 1
    assert got["posts"] == 1
    # The page names its own path on load, so what is held is that nothing
    # took it to the server's page before anybody pressed the button.
    assert not got["path"].startswith("/host/"), got["path"]

    # Closed and opened again: clean, and not asking about the last server.
    assert got["reopened"]["hidden"] is True
    assert got["reopened"]["button"] == "Cancel"
    assert all(r["step"] == idle and r["value"] == "" for r in got["reopened"]["rows"])


def test_a_done_step_carries_no_tick():
    """docs/DESIGN.md section 3: no tick or checkmark glyph anywhere. A done
    step is its value in ink. The one mark in a row is the spinner."""
    import build
    rows = build.arrival_rows_html()
    assert rows.count("<svg") == len(build.ARRIVAL_STEPS)
    for glyph in ("✓", "✔", "check"):
        assert glyph not in rows
