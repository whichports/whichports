"""The sample page asks no server for anything, whatever is clicked
(docs/RECORD.md 4.443).

The sample page has nothing behind it and goes public with the repository.
A control on it that posts gets a refusal from a server that is not there:
Scan now did, and so did the answers on a port and Pause and Silence on an
alert. Every control on the sample says what it would do instead.

This test is the walk that found them, kept: it opens every screen, tab
and settings section of the sample in a real browser, presses every control
it can see, fills every field first, and fails when any press makes the
page ask for anything. A window that a press opens is walked the same way,
opened by the control that opens it. A control added to the sample tomorrow
is pressed too.

What it cannot see: a control that asks only after a field holds something
this walk does not type, and a window that no control on the sample opens.
The page's markup holds six such windows, and the test names them, so one
that becomes reachable is noticed. The top bar is walked as a place of its
own, since the Feedback button there is outside every screen.

    Run from site/: python3 -m pytest app/test_sample_asks_no_server_browser.py
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
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

# Ahead of the page's own script, so the page's wrapper around fetch wraps
# it. It writes down everything the page asks for and answers the way a
# server that is not there does.
WATCH = """<script>
window.__asked=[];
window.fetch=function(url,opts){
  window.__asked.push(((opts&&opts.method)||'GET')+' '+String(url));
  return Promise.resolve({ok:false,redirected:false,status:501,
    json:function(){return Promise.resolve({})},text:function(){return Promise.resolve('')}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>the sample asks no server</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="2400"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
var PLACES=%(places)s;
f.onload=function(){
  var seen={clicked:{},asking:[],moved:[]};
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||30)})};
    var list=function(root,sel){return Array.prototype.slice.call(root.querySelectorAll(sel))};
    var words=function(e){return (e.textContent||'').replace(/\\s+/g,' ').trim().slice(0,40)};
    var name=function(e){return '"'+(words(e)||e.getAttribute('aria-label')||'')+'" ['+e.tagName.toLowerCase()+(e.id?'#'+e.id:'')+' '+e.className+']'};
    // Everything a person can press: buttons, menu items, answers, cards,
    // switches, and anything the page's script is bound to by a js- class.
    // Links and the top bar only move between screens and are left out.
    var controls=function(root){
      var found=[];
      list(root,'button,.rm-i,.ans,.m-card,.sw,input[type=checkbox],[data-open],[class*="js-"]').forEach(function(e){
        if(found.indexOf(e)>=0)return;
        if(e.offsetParent===null||e.disabled)return;
        if(e.tagName==='A'||e.closest('nav.nav')||e.classList.contains('back'))return;
        if(e.classList.contains('prsel'))return;
        found.push(e)});
      return found};
    var fill=function(root){
      list(root,'input,textarea').forEach(function(e){
        if(e.offsetParent===null||e.disabled||e.readOnly)return;
        var kind=(e.type||'text').toLowerCase();
        if(['checkbox','radio','button','submit','file','hidden'].indexOf(kind)>=0)return;
        e.value=kind==='email'?'somebody@example.com':kind==='url'?'https://example.com/hook'
          :kind==='number'?'8080':kind==='password'?'a long enough passphrase 1':'203.0.113.7';
        e.dispatchEvent(new w.Event('input',{bubbles:true}));
        e.dispatchEvent(new w.Event('change',{bubbles:true}))})};
    var shut=function(){
      list(d,'.ovl.on').forEach(function(o){o.classList.remove('on')});
      list(d,'.rmenu.on').forEach(function(o){o.classList.remove('on')})};
    // Press every control of one place once. A press can change what is
    // there, so the place is put back before each one and the next control
    // is the first not pressed yet.
    var keyed=function(root){
      var times={};
      return controls(root).map(function(e){
        var s=name(e)+JSON.stringify(e.dataset);
        times[s]=(times[s]||0)+1;
        return [s+'#'+times[s],e]})};
    var openWindow=function(){return d.querySelector('.ovl.on')};
    var found=[];   // windows a press opened: [id, the place, the control's key, how to get to the place]
    var walk=async function(place,root,restore,inWindow){
      var done={}, count=0;
      for(var guard=0;guard<200;guard++){
        await restore();
        var next=keyed(root()).filter(function(k){return !done[k[0]]})[0];
        if(!next)break;
        done[next[0]]=1;
        fill(root());
        var before=w.__asked.length, label=name(next[1]);
        var standIn=next[1].classList.contains('js-act'), was=d.querySelector('.view.on').id;
        next[1].click(); await tick();
        count++;
        // A control that only says what it would do is pressed for itself,
        // never for the row it stands in: the screen stays the one it was.
        if(standIn&&d.querySelector('.view.on').id!==was)
          seen.moved.push(place+': '+label+' went from '+was+' to '+d.querySelector('.view.on').id);
        if(w.__asked.length>before)
          seen.asking.push(place+': '+label+' asked '+w.__asked.slice(before).join(', '));
        var opened=openWindow();
        if(!inWindow&&opened&&!found.some(function(x){return x[0]===opened.id}))
          found.push([opened.id,place,next[0],restore]);
      }
      seen.clicked[place]=count};
    await tick(100);
    seen.askedAtLoad=w.__asked.slice();
    for(var p=0;p<PLACES.screens.length;p++){
      (function(screen){
        seen.pending=walk(screen.name,function(){return d.querySelector('.view.on')},async function(){
          shut();
          if(screen.view==='host')d.querySelector('#fleet a.row').click();
          else d.querySelector('nav.nav a[data-v="'+screen.view+'"]').click();
          await tick();
          shut();
          screen.radios.forEach(function(id){
            var r=d.getElementById(id);
            r.checked=true;r.dispatchEvent(new w.Event('change',{bubbles:true}))});
          await tick()});
      })(PLACES.screens[p]);
      await seen.pending;
    }
    // The top bar, outside every screen: the Feedback button, which opens
    // its window, and the account circle. Its menu is shut before each
    // press, so the walk presses the circle and never Sign out.
    seen.pending=walk('top bar',function(){return d.querySelector('.top')},async function(){
      shut();
      d.getElementById('pm-menu').hidden=true;
      d.querySelector('nav.nav a[data-v="fleet"]').click();
      await tick()});
    await seen.pending;
    // Each window a press opened, opened again by that same press whenever
    // it is shut, so what was picked in it stays picked between presses.
    seen.windows=[];
    for(var o=0;o<found.length;o++){
      (function(win){
        seen.windows.push(win[0]+' from '+win[1]);
        seen.pending=walk('window '+win[0],function(){return d.getElementById(win[0])},async function(){
          var now=openWindow();
          if(now&&now.id===win[0])return;
          await win[3]();
          var opener=keyed(d.querySelector('.view.on')).concat(keyed(d.querySelector('.top')))
            .filter(function(k){return k[0]===win[2]})[0];
          opener[1].click(); await tick()},true);
      })(found[o]);
      await seen.pending;
    }
    delete seen.pending;
    seen.askedInAll=w.__asked.length-seen.askedAtLoad.length;
  };
  run().then(function(){out.textContent=JSON.stringify(seen)})
       .catch(function(e){seen.error=String(e&&e.stack||e);delete seen.pending;out.textContent=JSON.stringify(seen)});
};
f.src='live.html';
</script>
"""


# Windows in the page's markup that no control on the sample opens: their
# openers on the sample say what they would do instead. A window that leaves
# this list is walked, and one that joins the page without a way in fails
# the first test until it is named here.
NO_WAY_IN = {"ptok-ovl", "tfa-ovl", "rm-ovl", "del-ovl", "addr-ovl", "ask"}


def places_of(page):
    """Every screen of the sample, read from its own markup: the four views
    of the top bar, each tab of the server's page, and each section of the
    two Settings screens. And every window."""
    def radios(group):
        return re.findall(rf'<input type="radio"[^>]*id="({group}-[a-z0-9-]+)"', page)
    screens = [{"name": view, "view": view, "radios": []}
               for view in ("fleet", "alerts", "integrations")]
    for rid in radios("hs-settings"):
        screens.append({"name": f"settings, {rid.rsplit('-', 1)[1]}", "view": "settings", "radios": [rid]})
    for rid in radios("tb-host"):
        if rid != "tb-host-settings":
            screens.append({"name": f"server, {rid.rsplit('-', 1)[1]}", "view": "host", "radios": [rid]})
    for rid in radios("hs-host"):
        screens.append({"name": f"server settings, {rid.rsplit('-', 1)[1]}", "view": "host",
                        "radios": ["tb-host-settings", rid]})
    windows = re.findall(r'<div class="ovl[^"]*" id="([^"]+)"', page)
    return {"screens": screens, "windows": windows}


@pytest.fixture(scope="module")
def walked(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("sample-walk")
    site = tmp_path / "www"
    site.mkdir()
    page = build.build_sample()
    places = places_of(page)
    assert page.count("<head>") == 1
    (site / "live.html").write_text(page.replace("<head>", "<head>" + WATCH, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS % {"places": json.dumps(places)}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=55000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got and got.group(1), f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    result["places"] = places
    return result


def test_the_walk_went_everywhere_the_sample_has(walked):
    """A walk that pressed nothing would pass the test below with nothing
    proved. Every screen and every window is in the count."""
    places = walked["places"]
    assert len(places["screens"]) >= 19, [s["name"] for s in places["screens"]]
    for screen in places["screens"]:
        assert screen["name"] in walked["clicked"], f"{screen['name']} was not walked"
    assert walked["clicked"]["top bar"] >= 2, "the Feedback button and the account circle"
    reached = {line.split(" from ")[0] for line in walked["windows"]}
    assert reached == set(places["windows"]) - NO_WAY_IN, walked["windows"]


def test_the_walk_pressed_the_controls_it_found(walked):
    pressed = walked["clicked"]
    assert sum(pressed.values()) >= 110, pressed
    for place in ("fleet", "alerts", "integrations", "server, overview", "server settings, probing",
                  "window fv-host", "window conn-ovl", "window pw-ovl"):
        assert pressed[place] >= 2, (place, pressed[place])


def test_no_click_on_the_sample_asks_a_server_for_anything(walked):
    assert walked["asking"] == [], "\\n".join(walked["asking"])
    assert walked["askedInAll"] == 0


def test_the_sample_asks_nothing_by_itself_when_it_loads(walked):
    assert walked["askedAtLoad"] == [], walked["askedAtLoad"]


def test_a_control_that_says_what_it_would_do_leaves_the_reader_on_the_screen(walked):
    """Silence and Pause stand in a row that is itself a way to the server's
    page. The press is for the button and not for the row."""
    assert walked["moved"] == [], "\n".join(walked["moved"])
