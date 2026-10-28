"""What somebody opened or chose inside a tab is still open and still chosen
after the page has refreshed that tab, in a real browser (docs/RECORD.md
4.362, 4.363).

The quiet refresh swaps in a tab whose markup changed. A port's open row, an
open rule, the path that is drawn and the section of the Settings rail are
each a hidden checkbox or radio inside that tab, and the tab that came in
carried none of them: measured on 2026-10-04, an open row was closed and the
rail was back on its first section. Scan now asks for the page five times in
a row, so one click could close a row five times.

Two kinds of input, kept two ways:

- one whose id is built from what it is (a port, a section) keeps its state
  by that id;
- one whose id is built from where it is (the second path, the third rule)
  keeps its state only while its label still reads the same, because the
  second path of the new tab may be another port's.

A fold has no id at all and is kept the second way, by its summary's words.

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch. Four renders
of one server, each after something moved, are what it answers with.

    Run from site/: python3 -m pytest app/test_refresh_keeps_choices_browser.py
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
import test_integrations_live as til  # noqa: E402
import test_address_hosts_screen as tahs  # noqa: E402
import test_firewalld_zones_in_effect as fw  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW

STUB = """<script>
window.__gets=0;window.__serve='A';window.__pages=%(pages)s;
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    return Promise.resolve({ok:true,status:204,
      json:function(){return Promise.resolve({})}});
  }
  window.__gets++;
  var page=window.__pages[window.__serve];
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>a refresh keeps what was opened and chosen</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var list=function(sel){return Array.prototype.slice.call(d.querySelectorAll(sel))};
    var labelOf=function(input){
      var l=list('label').filter(function(x){return x.htmlFor===input.id})[0];
      return l?l.textContent.replace(/\\s+/g,' ').trim():''};
    // Whether a piece on the screen is the one the server sent last. The
    // class a screen or a tab is shown by is the page's own and is left out.
    var isServers=function(sel,name){
      var fresh=new w.DOMParser().parseFromString(w.__pages[name],'text/html');
      var strip=function(x){return x.outerHTML.replace(/ class="([^"]*)"/g,function(m,c){
        return ' class="'+c.split(' ').filter(function(k){return k!=='on'}).join(' ')+'"'})};
      var a=d.querySelector(sel), b=fresh.querySelector(sel);
      return !!a&&!!b&&strip(a)===strip(b)};
    var look=function(name){
      var row=d.getElementById('pr-box-tcp-8410'), ssh=d.getElementById('pr-box-tcp-22');
      var paths=list('#t-box-path input.rr');
      return {
        gets:w.__gets,
        overviewIsServers:isServers('#t-box-overview',name),
        rulesIsServers:isServers('#t-box-rules',name),
        pathIsServers:isServers('#t-box-path',name),
        settingsIsServers:isServers('#t-box-settings',name),
        row8410:row?row.checked:'gone',
        row22:ssh?ssh.checked:'gone',
        rail:(d.querySelector('input[name="hs-box"]:checked')||{}).id||'',
        pathsChecked:paths.filter(function(p){return p.checked}).map(labelOf),
        rulesOpen:list('#t-box-rules input.rsel').filter(function(r){return r.checked}).map(labelOf),
      }};
    var go=async function(name){
      w.__serve=name;
      await tick(61000); await tick(300);
      seen[name]=look(name)};
    // The server's page first, as a person gets there.
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    list('.ovl.on').forEach(function(o){o.classList.remove('on')});
    // A port's row, opened.
    d.querySelector('label[for="pr-box-tcp-8410"]').click(); await tick();
    // The second rule, opened.
    d.querySelector('label[for="tb-box-rules"]').click(); await tick();
    var rules=list('#t-box-rules input.rsel');
    seen.rules=rules.map(labelOf);
    list('label').filter(function(x){return x.htmlFor===rules[1].id})[0].click(); await tick();
    // The second path, drawn.
    d.querySelector('label[for="tb-box-path"]').click(); await tick();
    seen.paths=list('#t-box-path input.rr').map(labelOf);
    list('#t-box-path .ppick label').filter(function(x){
      return x.textContent==='8410/tcp v4'})[0].click(); await tick();
    // The Addresses section of the Settings rail.
    d.querySelector('label[for="tb-box-settings"]').click(); await tick();
    d.querySelector('label[for="hs-box-addresses"]').click(); await tick();
    d.activeElement&&d.activeElement.blur();
    seen.start=look('A');
    await go('B'); await go('C'); await go('D');
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def socket(port, name):
    return {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
            "port": port, "process_name": name, "pid": port}


SOCKETS = {22: socket(22, "sshd"), 80: socket(80, "caddy"), 8410: socket(8410, "uvicorn")}


def document(ports, rule_ports):
    """A server with ufw, the sockets given and one ufw rule per port given."""
    doc = trl.document(listening=[SOCKETS[p] for p in ports])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": []}
    doc["ufw"] = {"status": "collected", "conf": {"ENABLED": "yes"},
                  "defaults": {"DEFAULT_INPUT_POLICY": "DROP"},
                  "rules": [f"allow tcp {p} 0.0.0.0/0 any 0.0.0.0/0 in" for p in rule_ports],
                  "rules6": [],
                  "sources": {"ufw.conf": {"status": "collected"},
                              "user.rules": {"status": "collected"},
                              "user6.rules": {"status": "collected"}}}
    return doc


def report_again(db, name, doc, minutes):
    """A newer report for a server that has one already."""
    when = (NOW - timedelta(minutes=minutes)).isoformat()
    con = sqlite3.connect(db)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version,"
        " document) VALUES (?, ?, ?, 1, ?)",
        (host_id, when, doc["collected_at_unix"], json.dumps(doc)))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?", (when, host_id))
    con.commit()
    con.close()


def four_pages(tmp_path):
    """One server, rendered four times.

    A: ports 22 and 8410, a rule for each, both answering from outside.
    B: 8410 stopped answering, a third rule was added after the two, and an
       address was proved. Every tab moved, and nothing changed its place.
    C: port 80 came between the two, in the sockets and in the rules. The
       path for 8410 is the third now, and the second rule is another rule.
    D: nothing listens on 8410 any more and its rule is gone. Its path is
       gone with them. Its row stays, because the port was probed.
    """
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", document([22, 8410], [22, 8410]), minutes=30)
    then = NOW - timedelta(minutes=25)
    trl.probe_result(path, "box", 22, "v4", "connect_succeeded", measured_at=then)
    trl.probe_result(path, "box", 8410, "v4", "connect_succeeded", measured_at=then)
    pages = {"A": rl.render(path, now=NOW)}

    report_again(path, "box", document([22, 8410], [22, 8410, 9000]), minutes=20)
    trl.probe_result(path, "box", 8410, "v4", "no_response",
                     measured_at=NOW - timedelta(minutes=15))
    tahs.prove(path, til.host_id_of(path, "box"))
    pages["B"] = rl.render(path, now=NOW)

    report_again(path, "box", document([22, 80, 8410], [22, 80, 8410, 9000]), minutes=10)
    pages["C"] = rl.render(path, now=NOW)

    report_again(path, "box", document([22, 80], [22, 80, 9000]), minutes=5)
    pages["D"] = rl.render(path, now=NOW)
    return pages


FOLD_HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>a refresh keeps an open fold</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var list=function(sel){return Array.prototype.slice.call(d.querySelectorAll(sel))};
    var look=function(){
      return {gets:w.__gets,
        rows:list('#t-box-rules .fwr').length,
        folds:list('#t-box-rules details').map(function(x){
          return [x.querySelector('summary').textContent,x.open]})}};
    var go=async function(name){
      w.__serve=name;
      await tick(61000); await tick(300);
      seen[name]=look()};
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    list('.ovl.on').forEach(function(o){o.classList.remove('on')});
    d.querySelector('label[for="tb-box-rules"]').click(); await tick();
    seen.asSent=look();
    d.querySelector('#t-box-rules details summary').click(); await tick();
    d.activeElement&&d.activeElement.blur();
    seen.start=look();
    await go('B'); await go('C');
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def firewalld_document(zones):
    """A server with firewalld, the zones given, and the kernel entering the
    public zone on its interface, as the Fedora server's does."""
    doc = trl.document(listening=[SOCKETS[22]])
    doc.update(fw.document(zones=zones, dispatch=fw.FEDORA_DISPATCH))
    doc["hostname"] = "box"
    return doc


def three_fold_pages(tmp_path):
    """One server with firewalld, rendered three times.

    A: the zones of the Fedora server. Those not in effect are behind a fold.
    B: the public zone opened one more port. The Rules tab moved and the fold
       reads as it did.
    C: a zone that was not in effect is gone, so the fold counts one fewer
       and reads differently.
    """
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    zones = list(fw.FEDORA_ZONES)
    trl.reporting(path, "box", firewalld_document(zones), minutes=30)
    pages = {"A": rl.render(path, now=NOW)}

    public = fw.zone("public", services=("dhcpv6-client", "mdns", "ssh"),
                     ports=(("8443", "tcp"),))
    zones = [public if z["name"] == "public" else z for z in zones]
    report_again(path, "box", firewalld_document(zones), minutes=20)
    pages["B"] = rl.render(path, now=NOW)

    zones = [z for z in zones if z["name"] != "dmz"]
    report_again(path, "box", firewalld_document(zones), minutes=10)
    pages["C"] = rl.render(path, now=NOW)
    return pages


def drive(tmp_path, pages, harness=None):
    site = tmp_path / "www"
    site.mkdir()
    embedded = json.dumps(pages).replace("</", "<\\/")
    first = pages["A"]
    assert first.count("<head>") == 1
    (site / "live.html").write_text(
        first.replace("<head>", "<head>" + STUB % {"pages": embedded}, 1), encoding="utf-8")
    (site / "harness.html").write_text(harness or HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=200000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def seen(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("choices")
    return drive(tmp_path, four_pages(tmp_path))


# The second rule as its row reads, cell after cell.
RULE_8410 = "2allow8410tcp/v4anywhere"


def test_the_run_opened_and_chose_what_it_set_out_to(seen):
    """What the rest of this file rests on: the four things were open or
    chosen before the first refresh, on the page as the server first sent it."""
    assert seen["paths"] == ["22/tcp v4", "8410/tcp v4"]
    assert seen["rules"][1] == RULE_8410, seen["rules"]
    start = seen["start"]
    assert start["row8410"] is True and start["row22"] is False
    assert start["rulesOpen"] == [RULE_8410]
    assert start["pathsChecked"] == ["8410/tcp v4"]
    assert start["rail"] == "hs-box-addresses"


def test_every_refresh_swapped_every_tab_that_moved(seen):
    """The choices were kept on the server's newest tabs, not by leaving the
    old ones on the screen."""
    for name in ("B", "C", "D"):
        got = seen[name]
        assert got["overviewIsServers"], name
        assert got["rulesIsServers"], name
        assert got["pathIsServers"], name
    assert seen["B"]["settingsIsServers"]
    assert seen["B"]["gets"] < seen["C"]["gets"] < seen["D"]["gets"]


def test_an_open_port_row_is_still_open_after_its_tab_was_swapped(seen):
    assert seen["B"]["row8410"] is True
    assert seen["C"]["row8410"] is True


def test_a_row_nobody_opened_stays_closed(seen):
    for name in ("B", "C", "D"):
        assert seen[name]["row22"] is False, name


def test_the_settings_rail_stays_on_the_section_that_was_chosen(seen):
    for name in ("B", "C", "D"):
        assert seen[name]["rail"] == "hs-box-addresses", name


def test_the_path_that_was_drawn_is_still_the_one_drawn(seen):
    assert seen["B"]["pathsChecked"] == ["8410/tcp v4"]


def test_a_path_is_known_by_its_words_when_its_place_moved(seen):
    """In C the path for 8410 is the third chip, where it was the second. The
    second is another port's, and it is not the one drawn."""
    assert seen["C"]["pathsChecked"] == ["8410/tcp v4"]


def test_a_path_that_is_gone_leaves_the_servers_own_first_path_drawn(seen):
    """Exactly one path is drawn, never none."""
    assert seen["D"]["pathsChecked"] == ["22/tcp v4"]


def test_an_open_rule_is_still_open_while_it_reads_the_same(seen):
    assert seen["B"]["rulesOpen"] == [RULE_8410]


def test_a_rule_whose_place_another_rule_took_is_not_opened_in_its_name(seen):
    """In C the second rule is the one for port 80. Nobody opened that one."""
    assert seen["C"]["rulesOpen"] == []
    assert seen["D"]["rulesOpen"] == []


def test_a_port_row_stays_open_for_as_long_as_the_port_has_a_row(seen):
    """In D nothing listens on 8410 any more. It was probed, so it still has
    its row, and that row is the one somebody opened."""
    assert seen["D"]["row8410"] is True
    assert seen["D"]["overviewIsServers"]


# ------------------------------------------------------------------- a fold

@pytest.fixture(scope="module")
def folds(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("folds")
    return drive(tmp_path, three_fold_pages(tmp_path), FOLD_HARNESS)


def test_the_fold_is_sent_closed_and_was_opened_by_a_click(folds):
    assert folds["asSent"]["folds"] == [["8 zones not in effect", False]]
    assert folds["start"]["folds"] == [["8 zones not in effect", True]]


def test_an_open_fold_is_still_open_after_its_tab_was_swapped(folds):
    # The tab on the screen is the newer one: it lists the port that was added.
    assert folds["B"]["rows"] == folds["start"]["rows"] + 1
    assert folds["B"]["folds"] == [["8 zones not in effect", True]]


def test_a_fold_that_reads_differently_is_the_servers_own(folds):
    assert folds["C"]["folds"] == [["7 zones not in effect", False]]
