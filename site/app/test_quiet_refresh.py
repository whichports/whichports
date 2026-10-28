"""The page keeps itself current without reloading, and without touching what
the reader is looking at.

Until 2026-09-02 the page reloaded itself once a minute and after some
actions, which threw away the scroll, the open tab, the filter and the search
(docs/RECORD.md 4.141). Now it fetches itself in the background and swaps in
only the pieces whose markup changed. The rules the swap keeps:

- a fleet row the server did not change is the same element afterwards,
  handlers and all, and a changed one is replaced in place
- a server that appeared gets a row and a page, both wired, and a server that
  is gone loses both
- the four boxes over the table move with the rows
- the open tab, the scroll position and the search text are exactly what
  they were
- the footer stamp moves, which is how a reader can tell the page is current

Nothing else in the suite executes the page script, so the proof here is a
real browser, the same way test_rename_button.py drives its fix: the page is
served over http, fetch is stubbed to answer with the next render, and
Chrome's virtual time runs the minute timer.
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
from datetime import datetime, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402
from test_render_live import probe_result  # noqa: E402

SCHEMA = """
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
"""
NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
SSHD = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 22,
        "process_name": "sshd", "pid": 1}
WEB = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8096,
       "process_name": "jellyfin", "pid": 2}


def _document(listening):
    return {
        "schema_version": 1,
        "hostname": "Almabox",
        "collected_at_unix": int(NOW.timestamp()),
        "sockets": {"status": "collected", "listening": listening},
        "nftables": {"status": "not_present"},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "not_present"},
        "firewalld": {"status": "not_present"},
        "containers": {"status": "collected", "podman": []},
        "overlays": {"status": "collected"},
        "rule_files": {"status": "collected", "files": []},
    }


def make_db(path, reporting, never):
    """`reporting` is {name: listening sockets}, `never` the names of hosts
    that have never sent a document."""
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    for name, listening in reporting.items():
        cur = con.execute(
            "INSERT INTO hosts (name, token_hash, created_at, last_report_at)"
            " VALUES (?, ?, ?, ?)",
            (name, "hash-" + name, NOW.isoformat(), NOW.isoformat()))
        con.execute(
            "INSERT INTO reports (host_id, received_at, collected_at_unix,"
            " schema_version, document) VALUES (?, ?, ?, 1, ?)",
            (cur.lastrowid, NOW.isoformat(), int(NOW.timestamp()),
             json.dumps(_document(listening))))
    for name in never:
        con.execute(
            "INSERT INTO hosts (name, token_hash, created_at) VALUES (?, ?, ?)",
            (name, "hash-" + name, NOW.isoformat()))
    con.commit()
    con.close()
    return str(path)


# The page as first loaded, and the page the server answers the refresh with:
# almabox gained a port and the prober found it open, media-01 is gone, nieuw
# is new, stil did not move. Both at the same clock; the stamp differs by the
# commit it names.
def two_renders(tmp_path, monkeypatch):
    first = rl.render(make_db(tmp_path / "a.db",
                              {"almabox": [SSHD], "stil": [SSHD]}, ["media-01"]),
                      now=NOW)
    built = tmp_path / "DEPLOYED_COMMIT"
    built.write_text("abcdef1\n", encoding="utf-8")
    monkeypatch.setenv(rl.BUILD_FILE_ENV, str(built))
    second_db = make_db(tmp_path / "b.db",
                        {"almabox": [SSHD, WEB], "stil": [SSHD]}, ["nieuw"])
    probe_result(second_db, "almabox", 8096, "v4", "connect_succeeded")
    second = rl.render(second_db, now=NOW)
    return first, second


# What the harness does before the minute passes, and what it reads after.
# The iframe is short so the fleet scrolls, the filter and the search are set
# the way a reader sets them, and a tab on almabox's page is switched.
HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>refresh drive</title>
<pre id="out"></pre>
<iframe id="f" width="1200" height="260"></iframe>
<script>
var NEXT=%(next)s;
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var gets=[];
    w.fetch=function(url,opts){
      gets.push(String(url));
      return Promise.resolve({ok:true,redirected:false,status:200,
        text:function(){return Promise.resolve(NEXT)}})};
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var rows=function(){return Array.prototype.map.call(
      d.querySelectorAll('#fleet .panel .row'),function(r){
        return {host:r.dataset.host,mark:r.dataset.mark||'',
                shown:r.style.display!=='none'}})};
    d.querySelectorAll('#fleet .panel .row').forEach(function(r){r.dataset.mark='kept'});
    var strip=d.querySelector('#fleet .fstrip'); strip.dataset.mark='kept';
    var srch=d.querySelector('#fleet .srch');
    srch.value='nie'; srch.dispatchEvent(new w.Event('input'));
    d.getElementById('tb-almabox-services').click();
    w.scrollTo(0,120);
    await tick();
    var boxes=function(){return Array.prototype.map.call(
      d.querySelectorAll('#fleet .fstrip .n'),function(n){return n.textContent})};
    var before={rows:rows(),scroll:w.scrollY,stamp:d.querySelector('.pgstamp').textContent,
      boxes:boxes(),
      overview:d.getElementById('t-almabox-overview').textContent.indexOf('8096')>=0};
    await tick(61000);
    await tick();
    var after={rows:rows(),scroll:w.scrollY,stamp:d.querySelector('.pgstamp').textContent,
      boxes:boxes(),stripKept:(d.querySelector('#fleet .fstrip')||{}).dataset.mark||'',
      overview:d.getElementById('t-almabox-overview').textContent.indexOf('8096')>=0,
      search:srch.value,
      tab:d.getElementById('tb-almabox-services').checked,
      views:Array.prototype.map.call(d.querySelectorAll('.view[id^="host-"]'),
        function(v){return v.id}),
      gets:gets};
    var nieuw=d.querySelector('#fleet .row[data-host="nieuw"]');
    nieuw.click(); await tick();
    after.opened=(d.querySelector('.view.on')||{}).id;
    out.textContent=JSON.stringify({before:before,after:after});
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
// The src goes on after the handler. In markup the load could fire while
// the parser still waited for the rest of this script, and the handler
// then never ran: one run in six on the Mac this was written on.
f.src='live.html';
</script>
"""


def drive(tmp_path, first, second):
    site = tmp_path / "www"
    site.mkdir()
    (site / "live.html").write_text(first, encoding="utf-8")
    # The next render travels as a JSON string inside a script tag, so its
    # own closing script tags must not end the harness's script.
    embedded = json.dumps(second).replace("</", "<\\/")
    (site / "harness.html").write_text(HARNESS % {"next": embedded}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=90000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


def test_the_minute_refresh_swaps_what_moved_and_keeps_what_the_reader_had(tmp_path, monkeypatch):
    first, second = two_renders(tmp_path, monkeypatch)
    result = drive(tmp_path, first, second)
    before, after = result["before"], result["after"]

    # It asked the server for the address it is showing (the fleet's, which
    # applyPath put in the bar on load), once, and did not reload.
    assert after["gets"] == ["/"]

    # The rows: stil is the same element (it kept the mark the harness put on
    # it), almabox was replaced, media-01 is gone, nieuw arrived.
    marks = {r["host"]: r["mark"] for r in after["rows"]}
    assert set(marks) == {"almabox", "stil", "nieuw"}
    assert marks["stil"] == "kept"
    assert marks["almabox"] == ""
    assert marks["nieuw"] == ""

    # The search survived and applies to the new row too: only nieuw matches
    # "nie", and the swapped almabox row obeys the text already typed.
    assert after["search"] == "nie"
    assert {r["host"]: r["shown"] for r in after["rows"]} == {
        "almabox": False, "stil": False, "nieuw": True}

    # The four boxes moved with the rows: almabox's new port answered from
    # outside and nobody has ruled on it, so Needs a decision and Reachable
    # went from nothing to one each. The strip was replaced, not repainted.
    assert before["boxes"] == ["0", "0", "0", "0"]
    assert after["boxes"] == ["0", "1", "1", "0"]
    assert after["stripKept"] == ""

    # The scroll and the open tab are where the reader left them. The frame
    # is short, so the page scrolls as far as it can rather than the full
    # 120px asked for; what matters is that the refresh did not move it.
    assert before["scroll"] > 0
    assert after["scroll"] == before["scroll"]
    assert after["tab"] is True

    # Almabox's overview panel now shows the port it gained, the pages
    # follow the servers, and the stamp moved.
    assert before["overview"] is False and after["overview"] is True
    # In the render's own order, which is by name.
    assert after["views"] == ["host-almabox", "host-nieuw", "host-stil"]
    assert before["stamp"] != after["stamp"]

    # The new row is wired: clicking it opens the new page.
    assert after["opened"] == "host-nieuw"


# ------------------------------------------------------------- the shape

def test_nothing_on_the_page_reloads_it():
    """The reload is gone from the timer and from the two windows that used
    it. What replaced it is a fetch of the page's own address."""
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    assert "location.reload" not in script
    assert "fetch(location.pathname,{cache:'no-store'})" in script
    assert "new DOMParser()" in script
    # The two windows ask for the page at once when they close on something
    # they created, rather than waiting for the minute.
    assert "if(adProved){adProved=false;refresh(true)}" in script
    assert "addCreated=null;addCmds=null;refresh(true)" in script


def test_the_refresh_waits_while_somebody_is_busy():
    """Never under somebody's hands: a menu open, a field focused, text
    selected, a click still waiting on its answer, or a hand on the page a
    moment ago. A window open stops even a forced refresh."""
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    assert "var REFRESH_MS=60000" in script
    block = script[script.index("var busy=function()"):]
    block = block[:block.index("var mergeList")]
    for guard in (".rmenu.on", "activeElement", "getSelection", "inflight",
                  "lastActivity<IDLE_MS"):
        assert guard in block, guard
    go = script[script.index("var refresh=function(force)"):]
    go = go[:go.index("setInterval(refresh,REFRESH_MS)")]
    assert "if(document.querySelector('.ovl.on'))return;" in go
    assert "if(!force&&busy())return;" in go
    assert "visibilitychange" in script


def test_every_control_pass_is_registered_to_run_again():
    """A piece the refresh swaps in carries no handlers, so every pass that
    binds a control on a screen goes through onWire. A pass added beside them
    without it would leave a refreshed row dead, so this names them."""
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    for selector in (".row[data-host]", ".js-display", ".js-remove", ".js-mute",
                     ".js-pause", ".js-silence", ".js-unsilence", ".js-scan",
                     ".js-recred", '[data-open="addr-ovl"]', ".js-addr-revoke",
                     ".js-port-rm", ".js-port-add", ".js-add", "[data-menu]",
                     ".rm-p", ".rm-post", ".rm-test", ".rm-edit", "[data-open]",
                     ".tabsel", ".seg button", "[data-v]"):
        at = script.index("querySelectorAll('" + selector)
        opened = script.rfind("onWire(function(){", 0, at)
        closed = script.rfind("\n  });", 0, at)
        assert opened > closed, f"{selector} is bound outside onWire"


def test_a_piece_being_edited_is_left_alone():
    """A field somebody typed into, or a choice made for a port not yet
    added, is not swapped out from under them."""
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    fn = script[script.index("function holdsEdits(el)"):]
    fn = fn[:fn.index("document.addEventListener('DOMContentLoaded'")]
    assert "i.value!==i.defaultValue" in fn
    assert ".seg button.on" in fn
    # A display name that was stored makes the field the server's, so the
    # next refresh is not held off by a name that is already saved.
    assert "inp.defaultValue=stored;" in script


def test_an_action_that_moves_another_piece_asks_for_the_page():
    """Five actions paint the piece they are on and change something the
    server draws elsewhere: the fleet row, the header, the Overview. Each
    asks for the page the moment the server agreed, so the whole page says
    one thing. Mute, silence, mark read and the channel rows already paint
    everything they change and do not."""
    html = build.build_sample()
    script = html[html.rindex("<script>"):]
    handler = lambda start, end: script[script.index(start):script.index(end)]
    # Remove keeps its window open so the command can still be copied, and
    # asks for the page the moment the window closes.
    # Each piece runs up to the code that follows it. Three of these ended at
    # a comment until 2026-10-02, and no comment is sent to a browser now.
    remove = handler("rmGo.onclick=", "var delOvl=")
    assert "toast('Removed');goto('fleet')" in remove
    assert "if(rmDone&&!rmOvl.classList.contains('on')){rmDone=false;refresh(true)}" in remove
    assert "toast('Deleted');refresh(true)" in handler("delGo.onclick=", "var setMuted=")
    assert "refresh(true)" in handler(".js-pause'", "var setSilenced=")
    assert "refresh(true);return" in handler(".js-addr-revoke'", "var portFams=")
    assert "row.remove();refresh(true)" in handler("var wirePortRemove", "var portRow")
    assert "refresh(true)" in handler(".js-port-add'", "var ovl=document.getElementById('add-ovl')")
