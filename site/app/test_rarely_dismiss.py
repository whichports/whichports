"""Dismissing the rarely-public mark on one port of one server.

The owner, 2026-10-03 (`docs/RECORD.md` 4.274): a port that truly should be open
and carries the mark can have it suppressed. Only a person does it, on the
port's opened row, one port of one server at a time, and Restore undoes it.
A dismissed port has no mark on its row, adds no chip on the Fleet, is not
counted in Needs a decision for the mark's sake, and stops counting as a sign
in the first-look window's order. No mail ever named the mark, so no mail
changes.

    Run from site/: python3 -m pytest app/test_rarely_dismiss.py
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
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_first_look_order as tfo  # noqa: E402
import test_render_live as trl  # noqa: E402
import theme  # noqa: E402
from test_rarely_public_mark import (MARK, WORD, fleet_row, header, port_row,  # noqa: E402
                                     server, sock, state_cell)
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)
from test_rename_button import QuietHandler, find_chrome, run_chrome  # noqa: E402

NOW = trl.NOW


def dismiss(db, name, port, protocol="tcp"):
    """A dismissal as the route stores it, written straight into the table the
    control plane's own module creates."""
    module = joinbridge.module("rarelydismiss")
    con = sqlite3.connect(db)
    con.executescript(module.SCHEMA)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.execute("INSERT INTO rarely_dismissed (host_id, protocol, port, dismissed_at)"
                " VALUES (?, ?, ?, ?)", (host_id, protocol, port, NOW.isoformat()))
    con.commit()
    con.close()


def a_box(db, name="box"):
    """22 and 6379 permitted by a rule of the operator's, so both read
    intended, and 3306 permitted by nothing, so it reads unreviewed. 6379 and
    3306 are on the list, and all three answered."""
    server(db, name, [sock(22, "sshd"), sock(6379, "redis-server"), sock(3306, "mariadbd")],
           permitted=(22, 6379), answers=(22, 6379, 3306))


def line(html, name, port):
    """The opened row's evidence of one port, the cards and the mark's line."""
    section = trl.host_section(html, name)
    after = section.split(f'data-port="{port}/tcp"', 1)[1]
    return after.split('<div class="pre">', 1)[1].split('<input type="checkbox" class="prsel"', 1)[0]


def label(html, name, port):
    section = trl.host_section(html, name)
    start = section.index(f'data-port="{port}/tcp"')
    return section[section.rindex("<label", 0, start):section.index(">", start) + 1]


def decision_box(html, name):
    """The number in the server page's Needs a decision box."""
    strip = trl.host_section(html, name).split('<div class="hstrip">', 1)[1]
    boxes = re.findall(r'<div class="n[^"]*">([^<]*)</div>', strip)
    return boxes[1]


def chips(html, name):
    return re.findall(r'<span class="fpc [^"]*">([^<]*)</span>', fleet_row(html, name))


# ------------------------------------------------------- what a dismissal does

def test_a_dismissed_port_loses_its_mark_and_the_others_keep_theirs(db):
    a_box(db)
    dismiss(db, "box", 6379)
    html = rl.render(db, now=NOW)
    assert MARK not in state_cell(html, "box", 6379)
    assert state_cell(html, "box", 6379) == theme.status("ok", "intended")
    assert state_cell(html, "box", 3306) == theme.status("warn", "unreviewed") + MARK


def test_the_mark_beside_the_name_stays_while_any_port_is_marked(db):
    a_box(db)
    dismiss(db, "box", 6379)
    assert MARK in header(rl.render(db, now=NOW), "box")
    dismiss(db, "box", 3306)
    html = rl.render(db, now=NOW)
    assert MARK not in header(html, "box")
    assert MARK not in fleet_row(html, "box")


def test_a_dismissed_port_is_no_chip_on_the_fleet(db):
    a_box(db)
    before = chips(rl.render(db, now=NOW), "box")
    assert any("6379" in c for c in before) and any("3306" in c for c in before)
    dismiss(db, "box", 6379)
    after = chips(rl.render(db, now=NOW), "box")
    assert not any("6379" in c for c in after)
    # 3306 is unreviewed, which is a chip whatever the mark says
    assert any("3306" in c for c in after)


def test_the_page_and_the_fleet_count_the_same_set_after_a_dismissal(db):
    a_box(db)
    html = rl.render(db, now=NOW)
    assert decision_box(html, "box") == "2" == str(len(chips(html, "box")))
    dismiss(db, "box", 6379)
    html = rl.render(db, now=NOW)
    assert decision_box(html, "box") == "1" == str(len(chips(html, "box")))
    dismiss(db, "box", 3306)
    html = rl.render(db, now=NOW)
    # 3306 still asks: no rule of the operator's permits it
    assert decision_box(html, "box") == "1" == str(len(chips(html, "box")))


def test_the_same_port_on_another_server_keeps_its_mark(db):
    a_box(db, "box")
    a_box(db, "other")
    dismiss(db, "box", 6379)
    html = rl.render(db, now=NOW)
    assert MARK not in state_cell(html, "box", 6379)
    assert MARK in state_cell(html, "other", 6379)
    assert any("6379" in c for c in chips(html, "other"))


def test_a_dismissal_stops_counting_the_list_in_the_first_look_order(db):
    a_box(db)
    before = tfo.window_ports(rl.render(db, now=NOW), "box")
    assert [p for _g, p in before] == [3306, 6379, 22]
    dismiss(db, "box", 6379)
    after = tfo.window_ports(rl.render(db, now=NOW), "box")
    # 6379 is now one more port a rule answers, ordered by its number
    assert [p for _g, p in after] == [3306, 22, 6379]


def test_a_database_from_before_dismissals_draws_every_mark(db):
    a_box(db)
    html = rl.render(db, now=NOW)
    assert MARK in state_cell(html, "box", 6379) and MARK in state_cell(html, "box", 3306)


def test_a_dismissal_on_a_removed_server_is_not_read(db):
    a_box(db, "box")
    dismiss(db, "box", 6379)
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET revoked_at = ? WHERE name = 'box'", (NOW.isoformat(),))
    con.commit()
    con.close()
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        assert rl.load_rarely_dismissed(con) == {}
    finally:
        con.close()


def test_dismissals_are_read_per_workspace(db):
    a_box(db, "box")
    dismiss(db, "box", 6379)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        assert rl.load_rarely_dismissed(con, workspace_id=1) == {"box": frozenset({"tcp/6379"})}
        assert rl.load_rarely_dismissed(con, workspace_id=2) == {}
    finally:
        con.close()


def test_load_hands_the_dismissed_marks_over_last(db):
    a_box(db)
    dismiss(db, "box", 6379)
    assert rl.load(db, now=NOW)[-1] == {"box": frozenset({"tcp/6379"})}


# ------------------------------------------------------------ the opened row

def test_a_marked_port_offers_dismiss_on_its_opened_row(db):
    a_box(db)
    opened = line(rl.render(db, now=NOW), "box", 6379)
    assert '<div class="prmk">' in opened
    assert WORD in opened
    assert ('class="btn js-rare" data-host="box" data-protocol="tcp" data-port="6379"'
            ' data-dismiss="1">Dismiss</button>') in opened


def test_a_dismissed_port_says_so_and_offers_restore(db):
    a_box(db)
    dismiss(db, "box", 6379)
    opened = line(rl.render(db, now=NOW), "box", 6379)
    assert '<div class="prmk off">' in opened
    assert theme.status("off", build.RARE_DISMISSED_WORD) in opened
    assert 'data-dismiss="0">Restore</button>' in opened


def test_a_port_the_mark_is_not_drawn_on_offers_nothing(db):
    server(db, "box", [sock(22, "sshd"), sock(6379, "redis-server"), sock(9200, "java")],
           answers=(22,), silent=(6379,))
    dismiss(db, "box", 6379)
    html = rl.render(db, now=NOW)
    for port in (22, 6379, 9200):
        assert "prmk" not in line(html, "box", port), port


def test_the_line_says_the_mark_a_state_and_an_action_and_nothing_else(db):
    a_box(db)
    dismiss(db, "box", 6379)
    html = rl.render(db, now=NOW)
    for port in (6379, 3306):
        mark_line = line(html, "box", port).split('<div class="prmk', 1)[1].split("</div>", 1)[0]
        words = re.sub(r"<[^>]+>", " ", mark_line.split(">", 1)[1])
        assert set(words.split()) <= set(WORD.split()) | {"dismissed", "Dismiss", "Restore"}


def test_only_a_port_counted_for_the_mark_alone_is_flagged_for_the_count(db):
    a_box(db)
    html = rl.render(db, now=NOW)
    assert 'data-rare-counts="1"' in label(html, "box", 6379)    # intended, counted for the mark
    assert 'data-rare-counts' not in label(html, "box", 3306)    # unreviewed, counted anyway
    assert 'data-rare-counts' not in label(html, "box", 22)


def test_the_line_is_drawn_across_both_cards():
    rule = re.search(r"(?m)^\.prmk\{[^}]*\}", build.CSS).group(0)
    assert "grid-column:1/-1" in rule and "color:var(--warn)" in rule
    assert ".prmk.off{color:var(--faint)}" in build.CSS


# ------------------------------------------------------------ in the browser

STUB = """<script>
window.__posts=[];window.__gets=0;
window.__next={status:200,body:{dismissed:true}};
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push(String(url)+' '+(opts.body||''));
    var n=window.__next;
    return Promise.resolve({ok:n.status<300,status:n.status,
      json:function(){return Promise.resolve(n.body)}});
  }
  // The quiet refresh is never answered, so what the click itself painted is
  // what is read.
  window.__gets++;
  return new Promise(function(){})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>rarely dismiss drive</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var view=function(){return d.getElementById('host-box')};
    var labelOf=function(port){return view().querySelector('label.pr[data-port="'+port+'/tcp"]')};
    var lineOf=function(port){return labelOf(port).nextElementSibling.querySelector('.prmk')};
    var state=function(port){var l=lineOf(port);
      return {marked:!!labelOf(port).querySelector('.prst .tag-rare'),
        off:l.classList.contains('off'),word:(l.querySelector('.st')||{}).textContent||'',
        button:l.querySelector('.js-rare').textContent,
        dismiss:l.querySelector('.js-rare').dataset.dismiss}};
    var count=function(){return view().querySelector('.hstrip>div:nth-child(2) .n').textContent};
    var headMarked=function(){return !!view().querySelector('.hh .stset .tag-rare')};
    var toast=function(){return d.getElementById('toast').textContent};
    var click=async function(port){lineOf(port).querySelector('.js-rare').click();await tick()};
    var seen={errs:[]};
    w.addEventListener('error',function(e){seen.errs.push(String(e.message))});

    seen.start={p6379:state(6379),p3306:state(3306),count:count(),head:headMarked()};

    w.__next={status:200,body:{dismissed:true}};
    await click(6379);
    seen.dismissed6379={p6379:state(6379),p3306:state(3306),count:count(),head:headMarked(),
      toast:toast(),post:w.__posts[w.__posts.length-1]};

    w.__next={status:200,body:{dismissed:true}};
    await click(3306);
    seen.dismissedBoth={p3306:state(3306),count:count(),head:headMarked()};

    w.__next={status:200,body:{dismissed:false}};
    await click(6379);
    seen.restored6379={p6379:state(6379),count:count(),head:headMarked(),toast:toast(),
      post:w.__posts[w.__posts.length-1]};

    w.__next={status:400,body:{detail:'this port carries no mark to dismiss'}};
    await click(6379);
    seen.refused={p6379:state(6379),count:count(),head:headMarked(),toast:toast()};
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
        port = httpd.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=20000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
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
    tmp_path = tmp_path_factory.mktemp("rare")
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    a_box(str(path))
    return drive(tmp_path, rl.render(str(path), now=NOW))


def test_the_page_script_raised_nothing(drove):
    assert drove["errs"] == []


def test_both_marked_ports_start_with_dismiss(drove):
    start = drove["start"]
    for port in ("p6379", "p3306"):
        assert start[port] == {"marked": True, "off": False, "word": "",
                               "button": "Dismiss", "dismiss": "1"}
    assert start["count"] == "2" and start["head"] is True


def test_dismiss_posts_one_port_of_one_server_and_paints_at_once(drove):
    seen = drove["dismissed6379"]
    assert seen["post"] == '/api/admin/hosts/box/rarely/tcp/6379 {"dismissed":true}'
    assert seen["p6379"] == {"marked": False, "off": True, "word": "dismissed",
                             "button": "Restore", "dismiss": "0"}
    assert seen["p3306"]["marked"] is True
    # 6379 was counted only for the mark, so the count drops with it
    assert seen["count"] == "1"
    assert seen["head"] is True
    assert seen["toast"] == "Dismissed"


def test_the_last_mark_dismissed_takes_the_one_beside_the_name(drove):
    seen = drove["dismissedBoth"]
    assert seen["p3306"]["marked"] is False and seen["head"] is False
    # 3306 asks whatever the mark says, so it stays counted
    assert seen["count"] == "1"


def test_restore_puts_the_mark_the_count_and_the_name_mark_back(drove):
    seen = drove["restored6379"]
    assert seen["post"] == '/api/admin/hosts/box/rarely/tcp/6379 {"dismissed":false}'
    assert seen["p6379"] == {"marked": True, "off": False, "word": "",
                             "button": "Dismiss", "dismiss": "1"}
    assert seen["count"] == "2" and seen["head"] is True
    assert seen["toast"] == "Restored"


def test_a_refusal_is_the_servers_words_and_nothing_moves(drove):
    seen = drove["refused"]
    assert seen["toast"] == "this port carries no mark to dismiss"
    assert seen["p6379"]["marked"] is True and seen["count"] == "2" and seen["head"] is True
