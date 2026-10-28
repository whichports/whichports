"""A workspace's first server shows up at once, driven in a real browser.

Found on the test fleet on 2026-10-03 (docs/RECORD.md 4.297): after Done in
the Add server window the Fleet still said "No servers yet", and the row came
only with a reload. A new customer who has just installed the agent and reads
"No servers yet" thinks the install failed.

An empty Fleet draws a box where the table would be. The page's quiet refresh
merges the server's rows into the table that is on the screen, and with no
table there it had nowhere to put the first one. Every test of the refresh
started from a workspace that already had a server, so none of them met it.

Here the page is rendered for an empty workspace, the Add server window is
clicked through in Chrome, and the server the page talks to is the stand-in
in the page's own head: the create answers a host, and the page's fetch of
itself answers the render of the same workspace with that server in it.

    Run from site/: python3 -m pytest app/test_first_server_browser.py
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
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW

# The stand-in for the server, put in the page's head ahead of the page's own
# script so the page's wrapper around fetch wraps it
# (test_first_channel_browser.py says why that matters). It answers the three
# things the window and the refresh ask: the create, by the kind that was
# posted, the arrival of the new server, and the page itself.
STUB = """<script>
window.__posts=[];window.__gets=[];
window.fetch=function(url,opts){
  url=String(url);
  var answer=function(body,status){return Promise.resolve({ok:true,redirected:false,
    status:status||200,json:function(){return Promise.resolve(body)},
    text:function(){return Promise.resolve(%(next)s)}})};
  if(opts&&opts.method==='POST'){
    var sent=JSON.parse(opts.body||'{}');
    window.__posts.push({url:url,body:sent});
    if(sent.kind==='address')return answer({name:sent.name,kind:'address'},201);
    return answer({id:7,name:'new-abc123',kind:'agent',credential:'whp_x',
      install_command:'curl -fsSL https://get.whichports.com/install.sh | sudo sh -s -- enroll'},201);
  }
  if(url.indexOf('/api/admin/hosts/arrival/')===0)
    return answer({name:'web-01',reported_at:null,probed_at:null});
  window.__gets.push(url);
  return answer({});
};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>first server drive</title>
<pre id="out"></pre>
<iframe id="f" width="1440" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var fleet=function(){
      var view=d.getElementById('fleet');
      return {empty:!!view.querySelector('.alnone'),
        saysNone:view.textContent.indexOf('No servers yet')>=0,
        table:!!view.querySelector('.ftbl'),
        search:!!view.querySelector('.srch'),
        rows:Array.prototype.map.call(view.querySelectorAll('.ftbl .row[data-host]'),
          function(r){return r.dataset.host}),
        shown:view.classList.contains('on'),
        // What a person sees: the row is on the screen and has a size.
        rowSeen:(function(){var r=view.querySelector('.ftbl .row[data-host]');
          return !!r&&r.getBoundingClientRect().height>0})(),
        removed:(function(){var g=view.querySelector('.fgone');
          return g&&!g.hidden?g.textContent.replace(/\\s+/g,' ').trim():''})(),
        pages:d.querySelectorAll('.view[id^="host-"]').length};
    };
    var seen={before:fleet()};
    %(steps)s
    seen.windowOpen=!!d.querySelector('.ovl.on');
    // Well under the minute the background refresh waits, so a row that is
    // there now was put there by the click and not by the timer.
    await tick(1500);
    seen.after=fleet();
    seen.posts=w.__posts;seen.gets=w.__gets.length;
    // The row is live: its click goes to the server's page.
    var row=d.querySelector('#fleet .ftbl .row[data-host]');
    if(row){row.click(); await tick();
      seen.opened=w.location.pathname;
      var page=d.getElementById('host-'+row.dataset.host);
      seen.pageShown=!!page&&page.classList.contains('on');}
    out.textContent=JSON.stringify(seen);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""

# The agent's way: Linux, Agent, the command is asked for, and the window is
# closed with its cross, which is what stays on the Fleet. Done on a server
# that has arrived goes to that server's page instead.
AGENT_STEPS = """
    d.querySelector('#fleet .alnone .js-add').click(); await tick();
    d.getElementById('add-linux').click(); await tick();
    d.getElementById('add-agent').click(); await tick(200);
    d.getElementById('add-close').click();
"""

# An address and no agent: Linux, Addresses, a name, the address and the way
# to prove it, Create, and Done. Create makes nothing until all three are
# there (docs/RECORD.md 4.363, test_add_by_address_browser.py).
ADDRESS_STEPS = """
    d.querySelector('#fleet .alnone .js-add').click(); await tick();
    d.getElementById('add-linux').click(); await tick();
    d.getElementById('add-addr').click(); await tick();
    var name=d.getElementById('add-addr-name');
    name.value='edge-router'; name.dispatchEvent(new w.Event('input'));
    var address=d.getElementById('add-addr-address');
    address.value='192.0.2.9'; address.dispatchEvent(new w.Event('input'));
    d.getElementById('add-addr-http').click(); await tick();
    d.getElementById('add-addr-go').click(); await tick(200);
    d.getElementById('add-done').click();
"""


# The other way round: the only server is removed, with its name typed, and
# the window is closed. The Fleet is the box again, and the removed server is
# listed under it.
REMOVE_STEPS = """
    d.querySelector('.js-remove[data-host="web-01"]').click(); await tick();
    var typed=d.getElementById('rm-input');
    typed.value='web-01'; typed.dispatchEvent(new w.Event('input'));
    d.getElementById('rm-go').click(); await tick(200);
    d.querySelector('#rm-ovl .acts [data-close]').click();
"""


def workspace(tmp_path, name):
    path = str(tmp_path / name)
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def with_one_agent_server(tmp_path):
    path = workspace(tmp_path, "agent.db")
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "web-01"
    trl.reporting(path, "web-01", doc)
    return rl.render(path, now=NOW)


def with_its_only_server_removed(tmp_path):
    """(the page with the one server, the page after its Remove)"""
    path = workspace(tmp_path, "removed.db")
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = "web-01"
    trl.reporting(path, "web-01", doc)
    first = rl.render(path, now=NOW)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    assert joinbridge.module("store").revoke_host(con, "web-01")
    con.close()
    return first, rl.render(path, now=NOW)


def with_one_address_server(tmp_path):
    path = workspace(tmp_path, "address.db")
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    joinbridge.module("store").add_address_host(con, "edge-router")
    con.close()
    return rl.render(path, now=NOW)


def drive(tmp_path, first, second, steps):
    site = tmp_path / "www"
    site.mkdir()
    embedded = json.dumps(second).replace("</", "<\\/")
    assert first.count("<head>") == 1
    (site / "live.html").write_text(
        first.replace("<head>", "<head>" + STUB % {"next": embedded}, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS % {"steps": steps}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=10000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture()
def empty_page(tmp_path):
    page = rl.render(workspace(tmp_path, "empty.db"), now=NOW)
    assert "No servers yet" in page and 'class="panel ftbl"' not in page
    return page


def check_the_first_server_is_there(seen, name):
    before, after = seen["before"], seen["after"]
    # the page this starts from: the box, and no table to merge into
    assert before["empty"] and before["saysNone"] and not before["table"], before
    assert seen["windowOpen"] is False, "the window is still open, so nothing refreshed"
    assert seen["gets"] >= 1, "the page never asked the server for itself"
    # and after the window closed, with no reload
    assert after["rows"] == [name], after
    assert after["rowSeen"], "the row is in the page and not on the screen"
    assert after["table"] and after["search"], after
    assert not after["empty"] and not after["saysNone"], after
    assert after["shown"], "the Fleet is not the screen any more"
    assert after["pages"] == 1, "the server's own page did not come with its row"
    # the row works: it opens the server's page
    assert seen["opened"] == "/host/" + name, seen
    assert seen["pageShown"], seen


def test_the_first_server_added_with_the_agent_appears_without_a_reload(tmp_path, empty_page):
    seen = drive(tmp_path, empty_page, with_one_agent_server(tmp_path), AGENT_STEPS)
    assert [p["url"] for p in seen["posts"]] == ["/api/admin/hosts"]
    check_the_first_server_is_there(seen, "web-01")


def test_the_first_server_added_by_address_appears_without_a_reload(tmp_path, empty_page):
    seen = drive(tmp_path, empty_page, with_one_address_server(tmp_path), ADDRESS_STEPS)
    assert seen["posts"][0]["body"] == {"name": "edge-router", "kind": "address"}
    check_the_first_server_is_there(seen, "edge-router")


def test_the_last_server_removed_leaves_the_box_and_not_an_empty_table(tmp_path):
    """The same fault from the other side: with no table in the server's
    answer the rows were not merged at all, so the table stayed, with its
    search field and its header and nothing under them."""
    first, second = with_its_only_server_removed(tmp_path)
    assert 'class="panel ftbl"' in first and "No servers yet" in second
    seen = drive(tmp_path, first, second, REMOVE_STEPS)
    before, after = seen["before"], seen["after"]
    assert before["rows"] == ["web-01"] and before["table"] and not before["empty"], before
    assert seen["posts"][0]["url"] == "/api/admin/hosts/web-01/revoke", seen["posts"]
    assert seen["windowOpen"] is False
    assert after["empty"] and after["saysNone"], after
    assert not after["table"] and not after["search"] and after["rows"] == [], after
    assert after["shown"], "the Fleet is not the screen any more"
    assert after["pages"] == 0, "the removed server's page is still in the page"
    assert "web-01" in after["removed"], after
