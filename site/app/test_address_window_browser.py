"""The window that adds an address to a server, walked in a real browser,
step by step and refusal by refusal (docs/RECORD.md 4.375, 4.379).

One button under a server's Addresses opens one window: an address, a way to
prove it, Start, the token to publish, Verify, and the registry's answer.
What is held here is what the window must never do: draw a row itself,
start a second challenge on a second click, show the registry's code word,
leave two primary buttons on the screen, take a code it does not know for a
yes, or sit dead when no answer comes.

The page talks to a stand-in server put in its own head, ahead of its script,
so the page's fetch wrapper wraps it as it wraps the real fetch. Everything
that stand-in answers with is the registry's own: the challenges
`authz.start_proof` gives for both ways, the sentences `authz.verify_proof`
gives, the words the verify route makes for a yes, and the page the renderer
draws once the proof is recorded.

    Run from site/: python3 -m pytest app/test_address_window_browser.py
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
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
ADDRESS = tahs.V4
MARKUP = '<img src=x onerror="window.__made=1">'
NO_ANSWER = "No answer. Check your connection and try again."

# What Start and Verify are answered with is set by the test, one press at a
# time: window.__start and window.__verify. `hang` is an answer that only
# comes when the test lets it, after the window has stopped waiting.
STUB = """<script>
window.__posts=[];window.__gets=0;window.__serve='before';window.__copied=[];
window.__start='ok';window.__verify='proved';window.__late=[];window.__made=0;
window.__pages=%(pages)s;window.__says=%(says)s;
Object.defineProperty(navigator,'clipboard',{configurable:true,value:{
  writeText:function(t){window.__copied.push(String(t));return Promise.resolve()}}});
window.fetch=function(url,opts){
  var u=String(url), says=window.__says;
  var answer=function(status,body){
    return {ok:status>=200&&status<300,status:status,redirected:false,
      json:function(){return Promise.resolve(body||{})},
      text:function(){return Promise.resolve('')}}};
  var later=function(made){return new Promise(function(resolve){
    window.__late.push(function(){resolve(made)})})};
  if(opts&&opts.method==='POST'){
    window.__posts.push(u+(opts.body?' '+opts.body:''));
    if(/\\/addresses$/.test(u)){
      var sent=JSON.parse(opts.body), how=window.__start;
      var challenge=sent.method==='dns-txt'?says.dns:says.http;
      if(how==='fail') return Promise.reject(new Error('down'));
      if(how==='hang') return later(answer(200,challenge));
      if(how==='refuse') return Promise.resolve(answer(400,{detail:'not an address: '+sent.address}));
      return Promise.resolve(answer(200,challenge));
    }
    if(/\\/verify$/.test(u)){
      var v=window.__verify;
      var bodies={
        proved:{ok:true,code:'proved',detail:says.yes},
        not_found:{ok:false,code:'token_not_found',detail:says.not_found},
        expired:{ok:false,code:'challenge_expired',detail:says.expired},
        unknown:{ok:true,code:'something_new',detail:says.yes},
        okwrong:{ok:true,code:'token_not_found',detail:says.yes},
        nocode:{ok:true,detail:says.yes}};
      if(v==='fail') return Promise.reject(new Error('down'));
      if(v==='hang') return later(answer(200,bodies.proved));
      if(v==='proved') window.__serve='after';
      return Promise.resolve(answer(200,bodies[v]));
    }
    return Promise.resolve(answer(204));
  }
  window.__gets++;
  var page=window.__pages[window.__serve];
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the address window</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var list=function(sel,root){return Array.prototype.slice.call((root||d).querySelectorAll(sel))};
    var ovl=d.getElementById('addr-ovl'), go=d.getElementById('ad-go');
    var field=d.getElementById('ad-address');
    var shown=function(el){return !!el&&!el.hidden&&!el.closest('[hidden]')};
    var posts=function(part){return w.__posts.filter(function(u){return u.indexOf(part)>=0})};
    var look=function(){
      var foot=list('.m-foot button',ovl).filter(shown);
      return {open:ovl.classList.contains('on'),
        buttons:foot.map(function(b){return b.textContent.trim()}),
        primaries:list('.btn.pri',ovl).filter(shown).map(function(b){return b.textContent.trim()}),
        goEnabled:!go.disabled,
        address:field.value,fixed:field.disabled,
        ways:list('.m-methods .m-card',ovl).map(function(c){
          return (c.classList.contains('sel')?'picked ':'')+(c.getAttribute('aria-disabled')==='true'?'fixed ':'')+c.dataset.method}),
        tokenShown:shown(d.getElementById('ad-token')),
        token:d.getElementById('ad-token').textContent,
        where:d.getElementById('ad-where').textContent,
        says:d.getElementById('ad-result').textContent,
        tone:d.getElementById('ad-result').className.replace('m-result','').trim(),
        error:d.getElementById('ad-err').textContent,
        starts:posts('/addresses {').length,verifies:posts('/verify').length,
        gets:w.__gets,
        rows:list('#t-box-settings .h-addresses .js-addr-revoke').map(function(b){return b.dataset.address}),
        focus:d.activeElement?d.activeElement.id:''}};
    var note=function(name){seen[name]=look();return seen[name]};
    var type=function(text){field.value=text;field.dispatchEvent(new w.Event('input',{bubbles:true}))};
    var key=function(el,k){el.dispatchEvent(new w.KeyboardEvent('keydown',{key:k,bubbles:true,cancelable:true}))};
    var opener=function(host){return d.querySelector('#t-'+host+'-settings [data-open="addr-ovl"]')};
    var open=async function(host){opener(host||'box').click(); await tick(100)};
    var pick=async function(way){d.getElementById('ad-'+way).click(); await tick()};
    var press=async function(times,ms){for(var i=0;i<(times||1);i++)go.click(); await tick(ms||200)};
    var toToken=async function(way){await open();type(%(address)s);await pick(way||'http');await press()};

    // ---- the page, before any click
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    list('.ovl.on').forEach(function(o){o.classList.remove('on')});
    d.querySelector('label[for="tb-box-settings"]').click(); await tick();
    d.querySelector('label[for="hs-box-addresses"]').click(); await tick();
    var section=d.querySelector('#t-box-settings .hstage.h-addresses');
    seen.page={buttons:list('button',section).map(function(b){return b.textContent.trim()}),
               fields:list('input',section).length,primaries:list('.btn.pri',section).length};

    // ---- the window opens: nothing to press yet
    await open(); note('opened');
    key(field,'Enter'); await tick(200); note('enterWithNoButton');
    await pick('http'); note('wayPicked');
    go.click(); await tick(200); note('startWithNoAddress');
    // ---- Start, pressed twice in a row
    type(%(address)s);
    await press(2); note('started');
    await pick('dns'); note('otherWayClicked');
    // ---- the two boxes copy
    var before=w.__copied.length;
    d.getElementById('ad-token').click(); await tick(100);
    d.getElementById('ad-where').click(); await tick(100);
    seen.copied=w.__copied.slice(before);
    // ---- a minute with the window open, and a changed page waiting
    w.__serve='after';
    await tick(61000); await tick(300); note('aMinuteLater');
    w.__serve='before';
    // ---- Verify, pressed twice, and the token is not there yet
    w.__verify='not_found'; await press(2); note('notFound');
    // ---- answers that must never be a yes
    w.__verify='unknown'; await press(); note('unknownCode');
    w.__verify='okwrong'; await press(); note('okWithAnotherCode');
    w.__verify='nocode'; await press(); note('okWithNoCode');
    // ---- no answer: a failure, and a wait that runs out
    w.__verify='fail'; await press(); note('verifyFailed');
    w.__verify='hang'; await press(1,1000); note('verifyWaiting');
    await tick(30000); note('verifyRanOut');
    w.__late.splice(0).forEach(function(release){release()}); await tick(300); note('lateAnswer');
    // ---- the challenge's day is over: Start again, the same address and way
    w.__verify='expired'; await press(); note('expired');
    await press(); note('startedAgain');
    // ---- the yes
    w.__verify='proved'; await press(); note('proved');
    await press(1,800); note('done');
    // ---- opened again: empty
    await open(); note('openedAgain');
    // ---- four ways out, none of which asks for anything
    key(d.body,'Escape'); await tick(200); seen.closedBy={escape:!look().open};
    await open(); ovl.querySelector('.m-foot [data-close="addr-ovl"]').click(); await tick(200);
    seen.closedBy.cancel=!look().open;
    await open(); ovl.querySelector('.m-x').click(); await tick(200); seen.closedBy.cross=!look().open;
    await open(); ovl.dispatchEvent(new w.MouseEvent('click',{bubbles:true})); await tick(200);
    seen.closedBy.backdrop=!look().open;
    note('afterClosing');
    // ---- a start the control plane refuses, with markup typed as the address
    await open(); type(%(markup)s); await pick('http');
    w.__start='refuse'; await press(); note('refused');
    seen.elementsMade={images:list('img',ovl).length,flag:w.__made};
    // ---- a start that fails, and one that runs out
    type(%(address)s);
    w.__start='fail'; await press(); note('startFailed');
    w.__start='hang'; await press(1,1000); note('startWaiting');
    await tick(30000); note('startRanOut');
    w.__late.splice(0).forEach(function(release){release()}); await tick(300); note('lateStart');
    // ---- Enter does what the button would, once
    w.__start='ok';
    key(field,'Enter'); key(field,'Enter'); await tick(300); note('enterStarted');
    ovl.querySelector('.m-foot [data-close="addr-ovl"]').click(); await tick(200);
    // ---- the DNS way
    await toToken('dns'); note('dns');
    ovl.querySelector('.m-foot [data-close="addr-ovl"]').click(); await tick(200);
    // ---- another server's button
    d.querySelector('[data-v="fleet"]').click(); await tick();
    d.querySelector('#fleet .row[data-host="second"]').click(); await tick(100);
    list('.ovl.on').forEach(function(o){o.classList.remove('on')});
    d.querySelector('label[for="tb-second-settings"]').click(); await tick();
    w.__posts.length=0;
    await open('second'); type(%(address)s); await pick('http'); await press();
    seen.secondServer=w.__posts.slice();
    seen.everything=Object.keys(seen).map(function(k){return seen[k]&&seen[k].says||''})
      .concat(Object.keys(seen).map(function(k){return seen[k]&&seen[k].error||''}));
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""

VIEWING_HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the address window, looking into another workspace</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="900"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var seen={};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    d.querySelector('#fleet .row[data-host="box"]').click(); await tick(100);
    Array.prototype.forEach.call(d.querySelectorAll('.ovl.on'),function(o){o.classList.remove('on')});
    d.querySelector('label[for="tb-box-settings"]').click(); await tick();
    var button=d.querySelector('#t-box-settings [data-open="addr-ovl"]');
    seen.disabled=button.disabled;
    button.click(); await tick(200);
    seen.open=d.getElementById('addr-ovl').classList.contains('on');
    seen.posts=w.__posts.length;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


def registry_words(tmp_path):
    """Two servers, the page before and after one address is proved for the
    first, and everything the registry and the route say on the way."""
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
    trl.reporting(path, "second", trl.document(listening=[trl.SSHD]))
    host_id = til.host_id_of(path, "box")
    pages = {"before": rl.render(path, now=NOW)}
    authz = tahs.registry()
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    dns = authz.start_proof(con, ADDRESS, authz.METHOD_DNS_TXT, now=NOW, host_id=host_id)
    late = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN, now=NOW, host_id=host_id)
    expired = authz.verify_proof(con, late.id, now=NOW + timedelta(hours=25),
                                 fetcher=lambda url, timeout=0: late.token)
    http = authz.start_proof(con, ADDRESS, authz.METHOD_HTTP_TOKEN, now=NOW, host_id=host_id)
    not_found = authz.verify_proof(con, http.id, now=NOW,
                                   fetcher=lambda url, timeout=0: "something else")
    yes = authz.verify_proof(con, http.id, now=NOW,
                             fetcher=lambda url, timeout=0: http.token)
    (row,) = authz.live_addresses_for_host(con, host_id, now=NOW)
    con.close()
    assert yes.recorded and not not_found.recorded and not expired.recorded
    pages["after"] = rl.render(path, now=NOW)
    as_body = lambda c: {"id": c.id, "token": c.token, "publish_at": c.publish_at}  # noqa: E731
    says = {"http": as_body(http), "dns": as_body(dns),
            "yes": rl.proof_yes_words(row), "registry_yes": yes.reason,
            "not_found": not_found.reason, "expired": expired.reason}
    return path, pages, says


def drive(tmp_path, first, pages, says, harness):
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    stub = STUB % {"pages": json.dumps(pages).replace("</", "<\\/"),
                   "says": json.dumps(says).replace("</", "<\\/")}
    assert first.count("<head>") == 1
    (site / "live.html").write_text(first.replace("<head>", "<head>" + stub, 1), encoding="utf-8")
    (site / "harness.html").write_text(harness, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=200000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"], timeout=180)
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result.get("error")
    return result


@pytest.fixture(scope="module")
def walked(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("address-window")
    _path, pages, says = registry_words(tmp_path)
    harness = HARNESS % {"address": json.dumps(ADDRESS), "markup": json.dumps(MARKUP)}
    return drive(tmp_path, pages["before"], pages, says, harness), says


@pytest.fixture(scope="module")
def seen(walked):
    return walked[0]


@pytest.fixture(scope="module")
def says(walked):
    return walked[1]


START = '/api/admin/hosts/box/addresses {"address":"%s","method":"http-token"}' % ADDRESS
HTTP_FIXED = ["picked fixed http-token", "fixed dns-txt"]


# ------------------------------------------------------------ frame by frame

def test_the_page_has_one_button_and_no_add_row(seen):
    assert seen["page"] == {"buttons": ["Add address"], "fields": 0, "primaries": 1}


def test_the_window_opens_with_cancel_and_no_primary_button(seen):
    got = seen["opened"]
    assert got["open"] is True
    assert got["buttons"] == ["Cancel"] and got["primaries"] == []
    assert got["address"] == "" and got["ways"] == ["http-token", "dns-txt"]
    assert got["tokenShown"] is False


def test_focus_goes_into_the_window_when_it_opens(seen):
    assert seen["opened"]["focus"] == "ad-address"


def test_picking_a_way_brings_start_and_starts_nothing(seen):
    got = seen["wayPicked"]
    assert got["buttons"] == ["Cancel", "Start"] and got["primaries"] == ["Start"]
    assert got["ways"] == ["picked http-token", "dns-txt"]
    assert got["starts"] == 0


def test_no_address_and_no_way_start_nothing(seen):
    assert seen["enterWithNoButton"]["starts"] == 0
    assert seen["enterWithNoButton"]["error"] == ""
    got = seen["startWithNoAddress"]
    assert got["starts"] == 0 and got["error"] == "An address is needed"


def test_start_shows_the_token_and_where_it_is_read_from_and_becomes_verify(seen, says):
    got = seen["started"]
    assert got["tokenShown"] is True
    assert got["token"] == says["http"]["token"]
    assert got["where"] == says["http"]["publish_at"]
    assert got["buttons"] == ["Cancel", "Verify"] and got["primaries"] == ["Verify"]


def test_a_double_click_on_start_posts_once(seen):
    assert seen["started"]["starts"] == 1


def test_the_address_and_the_way_are_fixed_once_a_token_is_out(seen):
    assert seen["started"]["fixed"] is True
    assert seen["started"]["ways"] == HTTP_FIXED
    # A click on the other way changes nothing and starts nothing.
    got = seen["otherWayClicked"]
    assert got["ways"] == HTTP_FIXED and got["starts"] == 1
    assert got["token"] == seen["started"]["token"]


def test_a_click_on_the_token_copies_the_token(seen, says):
    assert seen["copied"][0] == says["http"]["token"]


def test_a_click_on_read_from_copies_where_it_is_read_from(seen, says):
    assert seen["copied"][1] == says["http"]["publish_at"]
    assert len(seen["copied"]) == 2


def test_the_dns_way_shows_the_name_the_record_is_read_from(seen, says):
    got = seen["dns"]
    assert got["token"] == says["dns"]["token"]
    assert got["where"] == says["dns"]["publish_at"]
    assert got["ways"] == ["fixed http-token", "picked fixed dns-txt"]
    assert got["primaries"] == ["Verify"]


def test_a_token_that_was_not_found_keeps_verify_and_says_so_in_the_fail_tone(seen, says):
    got = seen["notFound"]
    assert got["says"] == says["not_found"] and got["tone"] == "fail"
    assert got["buttons"] == ["Cancel", "Verify"] and got["goEnabled"] is True
    assert got["rows"] == []


def test_a_double_click_on_verify_posts_once(seen):
    assert seen["notFound"]["verifies"] == 1


def test_an_expired_challenge_brings_start_back(seen, says):
    got = seen["expired"]
    assert got["says"] == says["expired"] and got["tone"] == "fail"
    assert got["buttons"] == ["Cancel", "Start"] and got["primaries"] == ["Start"]
    # The same address and the same way, started again: one more challenge.
    again = seen["startedAgain"]
    assert again["starts"] == got["starts"] + 1
    assert again["fixed"] is True and again["ways"] == HTTP_FIXED
    assert again["primaries"] == ["Verify"] and again["says"] == ""


def test_a_verified_address_is_said_in_the_rows_words_with_done_alone(seen, says):
    got = seen["proved"]
    assert got["says"] == says["yes"] and got["tone"] == "ok"
    assert got["says"].startswith(f"{ADDRESS} proved by token file until ")
    assert got["buttons"] == ["Done"] and got["primaries"] == ["Done"]


def test_the_window_draws_no_row_while_it_is_open(seen):
    """The yes is one line in the window. The row is the server's to draw."""
    assert seen["proved"]["open"] is True
    assert seen["proved"]["rows"] == []


def test_closing_after_a_proof_asks_for_the_page_and_the_row_is_the_servers(seen):
    got = seen["done"]
    assert got["open"] is False
    assert got["gets"] == seen["proved"]["gets"] + 1
    assert got["rows"] == [ADDRESS]


def test_the_window_opened_again_is_empty(seen):
    got = seen["openedAgain"]
    assert got["address"] == "" and got["fixed"] is False
    assert got["ways"] == ["http-token", "dns-txt"]
    assert got["tokenShown"] is False and got["says"] == "" and got["error"] == ""
    assert got["buttons"] == ["Cancel"]


def test_escape_closes_the_window(seen):
    assert seen["closedBy"]["escape"] is True


def test_cancel_and_the_cross_and_the_backdrop_close_the_window(seen):
    assert seen["closedBy"] == {"escape": True, "cancel": True, "cross": True,
                                "backdrop": True}


def test_closing_before_a_proof_changes_nothing_on_the_page(seen):
    got = seen["afterClosing"]
    assert got["gets"] == seen["openedAgain"]["gets"]
    assert got["starts"] == seen["openedAgain"]["starts"]
    assert got["rows"] == [ADDRESS]


# ------------------------------------------------------- what never happens

def test_a_refresh_while_the_window_is_open_keeps_it_and_asks_for_nothing(seen):
    before, after = seen["otherWayClicked"], seen["aMinuteLater"]
    assert after["open"] is True
    assert after["token"] == before["token"] and after["fixed"] is True
    assert after["ways"] == HTTP_FIXED
    assert after["gets"] == before["gets"]
    assert after["starts"] == before["starts"] and after["verifies"] == before["verifies"]


@pytest.mark.parametrize("name", ["unknownCode", "okWithAnotherCode", "okWithNoCode"])
def test_a_code_the_window_does_not_know_is_never_a_yes(seen, name):
    got = seen[name]
    assert got["tone"] == "fail"
    assert got["buttons"] == ["Cancel", "Verify"]
    assert got["rows"] == []


def test_ok_with_another_code_than_proved_is_never_a_yes(seen):
    assert seen["okWithAnotherCode"]["tone"] == "fail"
    assert "Done" not in seen["okWithAnotherCode"]["buttons"]


def test_a_verify_that_fails_brings_verify_back_and_says_so(seen):
    got = seen["verifyFailed"]
    assert got["says"] == NO_ANSWER and got["tone"] == "fail"
    assert got["buttons"] == ["Cancel", "Verify"] and got["goEnabled"] is True


def test_a_verify_that_gets_no_answer_in_time_brings_verify_back_and_says_so(seen):
    assert seen["verifyWaiting"]["goEnabled"] is False
    got = seen["verifyRanOut"]
    assert got["says"] == NO_ANSWER and got["tone"] == "fail"
    assert got["buttons"] == ["Cancel", "Verify"] and got["goEnabled"] is True


def test_an_answer_that_comes_after_the_wait_is_over_is_not_taken(seen):
    """It said proved. The window had stopped waiting, so it stays where it
    was: no yes, no Done."""
    got = seen["lateAnswer"]
    assert got["tone"] == "fail" and got["buttons"] == ["Cancel", "Verify"]


def test_a_refused_address_is_said_under_the_form_and_start_stays(seen):
    got = seen["refused"]
    assert got["error"] == "not an address: " + MARKUP
    assert got["buttons"] == ["Cancel", "Start"] and got["goEnabled"] is True
    assert got["tokenShown"] is False and got["fixed"] is False


def test_markup_typed_as_an_address_comes_back_as_words(seen):
    assert seen["elementsMade"] == {"images": 0, "flag": 0}
    assert MARKUP in seen["refused"]["error"]


def test_a_start_that_fails_brings_start_back_and_says_so(seen):
    got = seen["startFailed"]
    assert got["error"] == NO_ANSWER
    assert got["buttons"] == ["Cancel", "Start"] and got["goEnabled"] is True


def test_a_start_that_gets_no_answer_in_time_brings_start_back_and_says_so(seen):
    assert seen["startWaiting"]["goEnabled"] is False
    got = seen["startRanOut"]
    assert got["error"] == NO_ANSWER
    assert got["buttons"] == ["Cancel", "Start"] and got["goEnabled"] is True
    # And the challenge that came too late is not shown.
    late = seen["lateStart"]
    assert late["tokenShown"] is False and late["buttons"] == ["Cancel", "Start"]


def test_enter_in_the_address_field_does_what_the_primary_button_would_once(seen):
    got = seen["enterStarted"]
    assert got["starts"] == seen["lateStart"]["starts"] + 1
    assert got["tokenShown"] is True and got["primaries"] == ["Verify"]


def test_there_is_never_more_than_one_primary_button_in_the_window(seen):
    looks = [value for value in seen.values()
             if isinstance(value, dict) and isinstance(value.get("primaries"), list)]
    assert len(looks) > 25
    assert all(len(look["primaries"]) <= 1 for look in looks)


def test_no_sentence_the_window_shows_carries_a_code_word(seen, says):
    """The registry's own yes names the way by its code. The window's does
    not, and neither does anything else it said on the way."""
    assert "http_token" in says["registry_yes"]
    for sentence in seen["everything"]:
        for word in ("http_token", "dns_txt", "http-token", "dns-txt"):
            assert word not in sentence, sentence


def test_the_window_knows_which_server_it_was_opened_for(seen):
    assert seen["secondServer"] == [
        '/api/admin/hosts/second/addresses {"address":"%s","method":"http-token"}' % ADDRESS]


def test_in_a_look_into_another_workspace_the_button_is_off(tmp_path):
    path, _pages, says = registry_words(tmp_path)
    page = rl.render(path, now=NOW, workspace_id=1, viewing=(4, "Acme"))
    got = drive(tmp_path, page, {"before": page, "after": page}, says, VIEWING_HARNESS)

    assert got == {"disabled": True, "open": False, "posts": 0}
