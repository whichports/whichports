"""The Host Overview's answers, driven in a real browser: a click posts and
the row repaints at once, a refusal is a toast and the row stays, a box over
the table opens its first row, and the first-look window opens on its own
once per browser and from review all ports at any time.

    Run from site/app: python3 -m pytest test_host_browser.py

The page is the live render over http, with fetch stubbed so what the page
posts can be read back. The words and the data attributes the page acts on
are covered without a browser in test_host_answers.py.
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
import render_live as rl  # noqa: E402
from test_host_answers import (  # noqa: E402
    NOW, SSHD, SSHD6, add_host, db, declare_intent, probe_result)
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

__all__ = ["db"]

# One Chrome process for the whole plan, so localStorage carries from one
# page to the next the way it does for a reader. Every step opens almabox's
# page from the fleet first, the way a reader gets there.
HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>host drive</title>
<pre id="out"></pre>
<iframe id="f" width="1400" height="900"></iframe>
<script>
var PLAN=%(plan)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
var results=[], at=0;
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument, step=PLAN[at].step;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var result={step:step,errs:[],posts:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    // The server, stubbed: a POST is recorded and answered as the step
    // says, a GET (the refresh after an answer) gets an empty page, which
    // the page throws away.
    var answer=PLAN[at].answer||{status:204};
    w.fetch=function(url,opts){
      opts=opts||{};
      if((opts.method||'GET')==='POST'){
        result.posts.push({url:String(url),body:opts.body||null});
        return Promise.resolve({ok:answer.status<300,redirected:false,status:answer.status,
          json:function(){return Promise.resolve(answer.json||{})},
          text:function(){return Promise.resolve('')}});
      }
      return Promise.resolve({ok:true,redirected:false,status:200,
        text:function(){return Promise.resolve('')}});
    };
    var row=function(){return d.querySelector('#host-almabox .pr[data-port="22/tcp"]')};
    var paint=function(){
      var r=row(), box=r.querySelector('.pra'), chip=r.querySelector('.prst .st');
      var pick=box.querySelector('.ans.pick');
      return {box:box.className, pick:pick?pick.dataset.answer:'',
              chip:chip?chip.textContent:'', chipClass:chip?chip.className:'',
              disabled:Array.prototype.map.call(box.querySelectorAll('.ans'),
                function(b){return b.disabled})}};
    d.querySelector('#fleet .row[data-host="almabox"]').click(); await tick();
    result.view=(d.querySelector('.view.on')||{}).id;
    result.modal=!!d.querySelector('#fv-almabox.on');
    if(step==='answer'||step==='refused'){
      result.before=paint();
      row().querySelector('.ans[data-answer="'+PLAN[at].word+'"]').click(); await tick();
      result.after=paint();
      result.toast=d.getElementById('toast').textContent;
      result.toastOn=d.getElementById('toast').classList.contains('on');
      // the answer did not open the row the way a click on the label does
      result.opened=d.getElementById('pr-almabox-tcp-22').checked;
    }
    if(step==='box'){
      var box=d.querySelector('#host-almabox .hstrip [data-row]');
      result.target=box.dataset.row;
      result.openedBefore=d.getElementById(box.dataset.row).checked;
      box.click(); await tick();
      result.openedAfter=d.getElementById(box.dataset.row).checked;
    }
    if(step==='review'){
      d.querySelector('#host-almabox .js-review-all').click(); await tick();
      result.modalAfter=!!d.querySelector('#fv-almabox.on');
      d.querySelector('#fv-almabox .js-fv-later').click(); await tick();
      result.modalClosed=!d.querySelector('#fv-almabox.on');
    }
    if(step==='confirm'){
      var o=d.querySelector('#fv-almabox');
      o.querySelector('.fv-r[data-port="22"] .ans[data-answer="yes"]').click();
      o.querySelector('.js-fv-confirm').click(); await tick();
      result.modalAfter=!!d.querySelector('#fv-almabox.on');
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
    `steps` is [(step, page html, extra)], extra holds the answer word and
    what the stubbed server answers. Returns one result per step."""
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    plan = []
    for i, (step, page, extra) in enumerate(steps):
        (site / f"page{i}.html").write_text(page, encoding="utf-8")
        plan.append(dict({"page": f"page{i}.html", "step": step}, **extra))
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
    for r in results:
        assert r["errs"] == [], r
        # the first look opening on its own records itself; the answer tests
        # read the answers' posts alone
        r["first_posted"] = any(p["url"].endswith("/first-look") for p in r["posts"])
        r["posts"] = [p for p in r["posts"] if not p["url"].endswith("/first-look")]
    return results


def question_page(db, families=("v4",)):
    """almabox with sshd reachable and nobody's answer yet."""
    add_host(db, "almabox", [SSHD] + ([SSHD6] if "v6" in families else []))
    for fam in families:
        probe_result(db, "almabox", 22, fam, "connect_succeeded")
    return rl.render(db, now=NOW)


DECLARE = "/api/admin/hosts/almabox/ports/tcp/22/{fam}/declare"
ACK = "/api/admin/hosts/almabox/ports/tcp/22/{fam}/acknowledge"


def test_yes_posts_open_for_both_families_and_repaints_the_row(tmp_path, db):
    (r,) = drive(tmp_path, [("answer", question_page(db), {"word": "yes"})])
    assert r["view"] == "host-almabox"
    assert r["before"]["pick"] == "" and r["before"]["chip"] == "unreviewed"
    assert r["posts"] == [
        {"url": DECLARE.format(fam="v4"), "body": '{"intent":"open"}'},
        {"url": DECLARE.format(fam="v6"), "body": '{"intent":"open"}'}]
    assert r["after"]["pick"] == "yes"
    assert "settled" in r["after"]["box"]
    assert (r["after"]["chip"], r["after"]["chipClass"]) == ("intended", "st ok")
    assert r["after"]["disabled"] == [False, False, False]
    assert r["opened"] is False and r["toastOn"] is False


def test_no_posts_closed_and_the_state_reads_conflict(tmp_path, db):
    (r,) = drive(tmp_path, [("answer", question_page(db), {"word": "no"})])
    assert [p["body"] for p in r["posts"]] == ['{"intent":"closed"}'] * 2
    assert r["after"]["pick"] == "no"
    assert (r["after"]["chip"], r["after"]["chipClass"]) == ("conflict", "st fail")


def test_later_acknowledges_the_families_with_a_state_and_moves_no_state(tmp_path, db):
    (r,) = drive(tmp_path, [("answer", question_page(db, ("v4", "v6")), {"word": "later"})])
    assert r["posts"] == [{"url": ACK.format(fam="v4"), "body": None},
                          {"url": ACK.format(fam="v6"), "body": None}]
    assert r["after"]["pick"] == "later"
    assert "settled" in r["after"]["box"]
    assert r["after"]["chip"] == r["before"]["chip"] == "unreviewed"


def test_later_on_one_measured_family_acknowledges_that_one_alone(tmp_path, db):
    (r,) = drive(tmp_path, [("answer", question_page(db), {"word": "later"})])
    assert [p["url"] for p in r["posts"]] == [ACK.format(fam="v4")]


def test_a_refusal_is_a_toast_and_the_row_stays_as_it_was(tmp_path, db):
    (r,) = drive(tmp_path, [("refused", question_page(db),
                             {"word": "yes", "answer": {"status": 409,
                                                        "json": {"detail": "Not this one."}}})])
    assert r["after"]["pick"] == "" and r["after"]["chip"] == "unreviewed"
    assert "settled" not in r["after"]["box"]
    assert r["after"]["disabled"] == [False, False, False]
    assert (r["toastOn"], r["toast"]) == (True, "Not this one.")


def test_a_picked_answer_is_not_posted_again(tmp_path, db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    (r,) = drive(tmp_path, [("answer", rl.render(db, now=NOW), {"word": "yes"})])
    assert r["before"]["pick"] == "yes"
    assert r["posts"] == []


def test_a_box_over_the_table_opens_the_first_row_it_counts(tmp_path, db):
    (r,) = drive(tmp_path, [("box", question_page(db), {})])
    assert r["target"] == "pr-almabox-tcp-22"
    assert (r["openedBefore"], r["openedAfter"]) == (False, True)


def mark_seen(db, name):
    """The first look recorded as seen, the way the route records it."""
    import sqlite3
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE IF NOT EXISTS first_looks (host_id INTEGER PRIMARY KEY,"
                " account TEXT NOT NULL, seen_at TEXT NOT NULL)")
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.execute("INSERT OR IGNORE INTO first_looks VALUES (?, 'default', '2026-08-14T12:00:00+00:00')",
                (host_id,))
    con.commit()
    con.close()


def test_the_first_look_opens_on_its_own_once_per_account(tmp_path, db):
    """The owner, 2026-09-06: once per account. The page that opens it on its
    own records that on the server, and a page rendered after that carries
    no marker and opens nothing."""
    first_page = question_page(db)
    mark_seen(db, "almabox")
    second_page = rl.render(db, now=NOW)
    assert 'data-first="1"' in first_page and 'data-first="1"' not in second_page
    first, second = drive(tmp_path, [("look", first_page, {}), ("look", second_page, {})])
    assert first["modal"] is True and first["first_posted"] is True
    assert second["modal"] is False and second["first_posted"] is False


def test_review_all_ports_opens_the_window_any_time_and_later_closes_it(tmp_path, db):
    add_host(db, "almabox", [SSHD])
    probe_result(db, "almabox", 22, "v4", "connect_succeeded")
    declare_intent(db, "almabox", "tcp", 22, "v4", "open")
    (r,) = drive(tmp_path, [("review", rl.render(db, now=NOW), {})])
    assert r["modal"] is False
    assert r["modalAfter"] is True and r["modalClosed"] is True
    assert r["posts"] == []


def test_confirm_posts_every_picked_answer_and_closes_the_window(tmp_path, db):
    (r,) = drive(tmp_path, [("confirm", question_page(db), {})])
    assert r["modal"] is True
    assert r["posts"] == [
        {"url": DECLARE.format(fam="v4"), "body": '{"intent":"open"}'},
        {"url": DECLARE.format(fam="v6"), "body": '{"intent":"open"}'}]
    assert r["modalAfter"] is False
