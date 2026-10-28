"""The one Add window, clicked through in a real browser.

    Run from site/: python3 -m pytest app/test_layout_b_browser.py

docs/screens/alerts/SPEC-layout-b.md, section 5, the tests "in a real
browser". test_layout_b.py holds what the page is sent with. This file holds
what a click does: which step shows, when the action appears, that there is
one primary button at every step, and that saving a destination and
connecting a provider make the requests the two old windows made.

The page is the live render of a workspace with one provider and two
destinations. The server it talks to is a stand-in put in the page's own
head, ahead of its script, so the page's fetch wrapper wraps it as it wraps
the real fetch (docs/RECORD.md 4.199). Each walk runs Chrome once and
several tests read what it wrote down.
"""
import functools
import html as html_mod
import http.server
import json
import os
import pathlib
import re
import sqlite3
import sys
import threading
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_integrations_live as til  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW
FONTS = pathlib.Path(__file__).resolve().parent.parent / "fonts"
HOOK = "https://hooks.example.com/services/T0/B0/abc"
KINDS = [kind for kind, _words in build.EVENT_KINDS]

STUB = """<script>
window.__posts=[];window.__gets=[];
window.fetch=function(url,opts){
  url=String(url);
  if(opts&&opts.method==='POST'){
    var body=opts.body?JSON.parse(opts.body):null;
    window.__posts.push({url:url,body:body});
    // An edit's answer holds the kinds the row takes as stored, as the
    // control plane's does since finding E20, here the kinds that were sent.
    var answer=url.indexOf('/integrations/')>=0?{status:'connected'}
      :/[/]destination$/.test(url)?{destination:'hooks.example.com',events:body.events}
      :{type:'webhook',label:'new one',destination:'hooks.example.com',events:[]};
    return Promise.resolve({ok:true,status:201,
      json:function(){return Promise.resolve(answer)}});
  }
  window.__gets.push(url);
  // The page asking for itself is never answered here: these walks read what
  // a click did before any refresh could repaint it.
  return new Promise(function(){});
};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>layout b walk</title>
<pre id="out"></pre>
<iframe id="f" width="%(width)s" height="%(height)s" style="border:0"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument, R={};
    // This browser draws no frame, so a view or a window that arrives with a
    // motion would stand at the motion's first frame for good. Every wait
    // ends those the browser's own way, and what is measured is the page at rest.
    // `rested` keeps count, so a motion that plays again is still seen.
    var rested=[];
    var atRest=function(){d.getAnimations().forEach(function(a){
      if(['v-in','o-in','m-in'].indexOf(a.animationName)<0||a.playState==='finished')return;
      rested.push(a.animationName);a.finish()})};
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||60)}).then(atRest)};
    var q=function(s){return d.querySelector(s)};
    var all=function(s){return Array.prototype.slice.call(d.querySelectorAll(s))};
    // Drawn, which a thing inside a hidden step is not, whatever its own style says.
    var shown=function(el){return !!el&&!el.hidden&&el.getClientRects().length>0};
    var text=function(el){return el.textContent.trim()};
    var win=function(){return d.getElementById('conn-ovl')};
    // What the window shows now, as a person would read it.
    var seen=function(){
      var foot=all('#conn-ovl .m-foot .btn').filter(shown);
      return {open:win().classList.contains('on'),
        title:text(q('#conn-ovl .m-h h2')),
        kinds:all('#conn-ovl .m-kind').filter(shown).map(function(s){return s.id}),
        fields:all('#conn-ovl .m-stage[data-type]').filter(shown).map(function(s){return s.id}),
        advanced:shown(d.getElementById('chan-adv')),
        // what a person sees of the cards: a hidden row counts for nothing
        first:all('#conn-ovl .m-card[data-kind]').filter(shown).length,
        cards:all('#conn-ovl .m-kind .m-card').filter(shown).length,
        picked:all('#conn-ovl .m-card.sel').filter(shown).map(function(c){return c.dataset.kind||c.dataset.fields}),
        locked:all('#conn-ovl .m-card.m-locked').filter(shown).length,
        buttons:foot.map(text),
        primary:foot.filter(function(b){return b.classList.contains('pri')}).map(text),
        error:text(d.getElementById('conn-err')),
        // every line of the window that says something, at a field or at
        // the foot, drawn or not
        said:all('#conn-ovl .m-err').map(text).filter(function(t){return t}),
        toast:text(d.getElementById('toast')||d.body.appendChild(d.createElement('i')))};
    };
    var open=async function(){q('[data-open="conn-ovl"]').click();await tick()};
    var kind=async function(k){q('#conn-ovl .m-card[data-kind="'+k+'"]').click();await tick()};
    var card=async function(c){q('#conn-ovl .m-card[data-fields="'+c+'"]').click();await tick()};
    var planned=async function(name){
      all('#conn-ovl .m-card.planned').filter(function(c){return text(c).indexOf(name)===0})[0].click();
      await tick()};
    var act=async function(){d.getElementById('conn-go').click();await tick(300)};
    var menu=async function(label,cls){
      all('.chanp .crow .rm-i.'+cls).filter(function(b){return b.dataset.label===label})[0].click();
      await tick(300)};
    var view=async function(name){q('a[data-v="'+name+'"]').click();await tick(200)};
    // How far anything runs past its box, in px. Zero is what is wanted.
    var spill=function(){
      var doc=d.documentElement, over=[];
      var modal=q('#conn-ovl.on .modal');
      if(modal){
        var m=modal.getBoundingClientRect();
        all('#conn-ovl .m-card').filter(shown).forEach(function(c){
          var r=c.getBoundingClientRect();
          if(r.left<m.left-0.5||r.right>m.right+0.5||c.scrollWidth>c.clientWidth+1)
            over.push(text(c))});
      }
      // Where the first card stands, and in the row of cards under it how
      // many different heights the icons and the words stand at. One of each
      // is a row whose cards line up.
      var firstCard=all('#conn-ovl .m-card[data-kind]').filter(shown)[0];
      var row=all('#conn-ovl .m-kind .m-card').filter(shown);
      // Measured from each card's own top, so a kind whose cards fill two
      // rows is held to the same rule as one that fills one.
      var heights=function(sel){var seen={};row.forEach(function(c){
        seen[Math.round(c.querySelector(sel).getBoundingClientRect().top
                        -c.getBoundingClientRect().top)]=1});
        return Object.keys(seen).length};
      var box=all('.view .alnone').filter(shown)[0];
      return {page:doc.scrollWidth-doc.clientWidth,
        firstTop:firstCard?Math.round(firstCard.getBoundingClientRect().top):null,
        rowIcons:row.length?heights('svg'):null,
        rowWords:row.length?heights('.m-card-t'):null,
        boxTop:box?Math.round(box.getBoundingClientRect().top):null,
        modalLeft:modal?Math.round(modal.getBoundingClientRect().left):null,
        modalRight:modal?Math.round(w.innerWidth-modal.getBoundingClientRect().right):null,
        // room the window has, and what its content needs: more means it
        // scrolls and its foot is out of view
        modalNeeds:modal?modal.scrollHeight:null,
        modalHas:modal?modal.clientHeight:null,
        cards:over,
        rows:all('.view .al, .view .crow').filter(shown).filter(function(r){
          return r.scrollWidth>r.clientWidth+1}).length};
    };
%(steps)s
    R.posts=w.__posts;R.gets=w.__gets;
    out.textContent=JSON.stringify(R);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e&&e.stack||e)})});
};
f.src='live.html';
</script>
"""


def a_workspace(path):
    """One server, one provider, two destinations and one alert, so both
    screens draw their tables."""
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    db = str(path)
    trl.add_host(db, "box", [(NOW - timedelta(minutes=2), trl.document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    trl.add_channel_holding_its_destination(db, "ops", HOOK, channel_type="webhook")
    trl.add_channel_holding_its_destination(db, "team", "https://hooks.slack.com/services/T0/B0/abc",
                                            subscriptions="silent")
    til.connect(db, 1)
    trl.seen_an_alert(db, "box")
    return db


def nothing_at_all(path):
    """One server, and nothing connected and no alert ever."""
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.add_host(str(path), "box", [(NOW - timedelta(minutes=2), trl.document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    return str(path)


def walk(tmp_path, steps, width=1440, height=900, workspace=a_workspace, stub=STUB):
    """Load the page in Chrome, run `steps` inside it, and return what they
    wrote into `R`. `stub` is the stand-in server put in the page's head, for
    a walk that needs one that refuses."""
    page = rl.render(workspace(tmp_path / "cp.db"), now=NOW)
    assert page.count("<head>") == 1
    site = tmp_path / "www"
    site.mkdir()
    # The page's own faces, so a measured width is the width a person sees.
    os.symlink(FONTS, site / "fonts")
    (site / "live.html").write_text(page.replace("<head>", "<head>" + stub, 1), encoding="utf-8")
    (site / "harness.html").write_text(
        HARNESS % {"steps": steps, "width": width, "height": height}, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             f"--window-size={width + 40},{height + 200}",
             "--virtual-time-budget=20000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result["error"]
    return result


# --------------------------------------------------------------- the steps

STEPS = """
    await view('integrations');
    await open();                       R.opened=seen();
    await kind('dest');                 R.dest=seen();
    await planned('Syslog');            R.destPlanned=seen();
    await card('chan-webhook');         R.webhook=seen();
    await card('chan-slack');           R.slack=seen();
    await kind('prov');                 R.prov=seen();
    await planned('AWS');               R.provPlanned=seen();
    await card('intg-hetzner');         R.hetzner=seen();
    await kind('mon');                  R.mon=seen();
    await planned('Zabbix');            R.monPlanned=seen();
    await kind('dest');                 R.destAgain=seen();
    q('#conn-cancel').click();await tick(); R.cancelled=seen();
"""


@pytest.fixture(scope="module")
def steps(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("steps"), STEPS)


def test_a_kind_shows_only_its_own_cards_and_swaps(steps):
    assert steps["opened"]["open"] and steps["opened"]["title"] == "Add"
    assert steps["opened"]["kinds"] == [] and steps["opened"]["fields"] == []
    assert steps["opened"]["picked"] == []
    assert steps["dest"]["kinds"] == ["conn-dest"] and steps["dest"]["picked"] == ["dest"]
    assert steps["webhook"]["kinds"] == ["conn-dest"]
    assert steps["webhook"]["fields"] == ["chan-webhook"] and steps["webhook"]["advanced"]
    assert steps["webhook"]["picked"] == ["dest", "chan-webhook"]
    # Picking the other first card swaps the second step and clears the third.
    assert steps["prov"]["kinds"] == ["conn-prov"] and steps["prov"]["picked"] == ["prov"]
    assert steps["prov"]["fields"] == [] and not steps["prov"]["advanced"]
    assert steps["hetzner"]["kinds"] == ["conn-prov"]
    assert steps["hetzner"]["fields"] == ["intg-hetzner"]
    # Advanced settings belong to a destination and to nothing else.
    assert not steps["hetzner"]["advanced"]
    assert steps["mon"]["kinds"] == ["conn-mon"] and steps["mon"]["fields"] == []
    # Coming back to a kind starts it clean: no card of it is still picked.
    assert steps["destAgain"]["picked"] == ["dest"] and steps["destAgain"]["fields"] == []
    assert not steps["cancelled"]["open"]


def test_the_action_appears_only_with_a_built_cards_fields(steps):
    for name in ("opened", "dest", "destPlanned", "prov", "provPlanned", "mon",
                 "monPlanned", "destAgain"):
        assert steps[name]["buttons"] == ["Cancel"], f"{name}: {steps[name]['buttons']}"
    assert steps["webhook"]["buttons"] == ["Cancel", "Save"]
    assert steps["slack"]["buttons"] == ["Cancel", "Connect to Slack"]
    assert steps["hetzner"]["buttons"] == ["Cancel", "Connect"]
    # A planned card cannot be picked: the click leaves the step as it was.
    for before, after in (("dest", "destPlanned"), ("prov", "provPlanned"), ("mon", "monPlanned")):
        assert steps[after] == steps[before], after


def test_one_primary_button_at_every_step(steps, edit):
    for name, step in list(steps.items()) + list(edit.items()):
        if not isinstance(step, dict) or "primary" not in step or not step["open"]:
            continue
        assert len(step["primary"]) == 1, f"{name}: {step['primary']}"
        # The lone Cancel, then the action.
        assert step["primary"] == [step["buttons"][-1]], name


# ------------------------------------------------------------ the requests

REQUESTS = """
    await view('integrations');
    await open();await kind('dest');await card('chan-webhook');
    q('#chan-webhook-dest').value='%(hook)s';
    await act();                                    R.saved=seen();
    await open();await kind('dest');await card('chan-telegram');
    q('#chan-telegram-dest').value='123:token';
    q('#chan-telegram-chat').value='-100200';q('#chan-telegram-thread').value='42';
    q('#conn-ovl .js-event[data-kind="silent"]').click();
    await act();                                    R.telegram=seen();
    await open();await kind('dest');await card('chan-email');
    await act();                                    R.empty=seen();
    await open();await kind('prov');await card('intg-hetzner');
    await act();                                    R.noToken=seen();
    q('#intg-hetzner input').value='hzread-sample';
    await act();                                    R.connected=seen();
    await menu('ops','rm-test');                    R.tested=seen();
"""


@pytest.fixture(scope="module")
def requests(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("requests"), REQUESTS % {"hook": HOOK})


def test_saving_a_destination_makes_the_request_the_old_window_made(requests):
    posts = requests["posts"]
    assert posts[0] == {"url": "/api/admin/channels",
                        "body": {"type": "webhook", "destination": HOOK, "chat_id": "",
                                 "events": KINDS}}
    # Chat and topic are one value, and a kind switched off is left out.
    assert posts[1] == {"url": "/api/admin/channels",
                        "body": {"type": "telegram", "destination": "123:token",
                                 "chat_id": "-100200:42",
                                 "events": [k for k in KINDS if k != "silent"]}}
    assert not requests["saved"]["open"] and requests["saved"]["toast"] == "Destination added."
    # An empty field is refused in the window, at the field, and nothing is
    # asked. Until docs/RECORD.md 4.228 this was one line at the foot that
    # named no field, and this test held that line.
    assert requests["empty"]["open"]
    assert requests["empty"]["said"] == ["Enter the recipient address."]
    assert requests["empty"]["error"] == ""
    assert not [p for p in posts if p["body"] and p["body"].get("type") == "email"]


def test_connecting_a_provider_makes_the_request_the_old_window_made(requests):
    # Refused under the token's field since docs/RECORD.md 4.228. Until then
    # the line stood at the foot, and this test held it there.
    assert requests["noToken"]["open"]
    assert requests["noToken"]["said"] == ["Paste the read token."]
    assert requests["noToken"]["error"] == ""
    connects = [p for p in requests["posts"] if "/integrations/" in p["url"]]
    assert connects == [{"url": "/api/admin/integrations/hetzner",
                         "body": {"token": "hzread-sample"}}]
    assert not requests["connected"]["open"]
    assert requests["connected"]["toast"] == "Connected"


def test_send_test_from_a_rows_menu_still_sends(requests):
    assert requests["posts"][-1] == {"url": "/api/admin/channels/ops/test", "body": None}
    assert not requests["tested"]["open"], "Send test opened the window"


REFUSAL = """
    await view('integrations');
    await open();await kind('dest');await card('chan-email');
    await act();                                    R.refused=seen();
    await card('chan-webhook');                     R.otherCard=seen();
    await card('chan-email');await act();
    await kind('prov');                             R.otherKind=seen();
    await kind('dest');await card('chan-email');await act();
    q('#conn-cancel').click();await tick();
    await open();                                   R.reopened=seen();
    await kind('dest');await card('chan-email');await act();
    q('#conn-cancel').click();await tick();
    await menu('ops','rm-edit');                    R.edit=seen();
"""


def test_a_refusal_does_not_outlive_its_step(tmp_path):
    """A refusal is about the fields it was said on. In the window this one
    replaced it stayed after the window was closed and after another channel
    was picked. Here it is gone when another card is picked, when another
    kind is picked, when the window is opened again and when an edit opens,
    and a refused save asks nothing of the server.

    The refusal stands at its field since docs/RECORD.md 4.228, so what is
    held is every line of the window and not the one at its foot.
    test_add_refusal_browser.py holds the rest of what a refusal does."""
    seen = walk(tmp_path, REFUSAL)
    assert seen["refused"]["open"]
    assert seen["refused"]["said"] == ["Enter the recipient address."]
    for name in ("otherCard", "otherKind", "reopened", "edit"):
        assert seen[name]["open"] and seen[name]["said"] == [], name
    assert seen["posts"] == []


# ------------------------------------------------------------------ an edit

EDIT = """
    await view('integrations');
    await menu('ops','rm-edit');                    R.editing=seen();
    R.field=q('#chan-webhook-dest').value;
    await kind('prov');                             R.otherKind=seen();
    await kind('dest');                             R.ownKind=seen();
    await card('chan-email');                       R.otherCard=seen();
    q('#chan-webhook-dest').value='%(hook)s';
    await act();                                    R.saved=seen();
    await menu('team','rm-edit');                   R.slack=seen();
    R.switches=all('#conn-ovl .js-event').filter(function(b){
      return !b.classList.contains('off')}).map(function(b){return b.dataset.kind});
    await act();                                    R.slackSaved=seen();
    await open();                                   R.addAfter=seen();
    R.switchesAfter=all('#conn-ovl .js-event.off').length;
"""


@pytest.fixture(scope="module")
def edit(tmp_path_factory):
    return walk(tmp_path_factory.mktemp("edit"), EDIT % {"hook": HOOK + "2"})


def test_editing_a_destination_opens_its_own_fields(edit):
    editing = edit["editing"]
    assert editing["open"] and editing["title"] == "Edit ops"
    assert editing["fields"] == ["chan-webhook"]
    assert editing["advanced"]
    assert editing["buttons"] == ["Cancel", "Save"]
    # An edit is about one row. Its kind is not a choice and its type cannot
    # change, so no card is drawn at all: the fields stand under the title,
    # which says which row it is. The page is never given the stored
    # destination to show.
    assert editing["first"] == 0 and editing["cards"] == 0
    assert editing["kinds"] == [] and editing["picked"] == [] and editing["locked"] == 0
    assert edit["field"] == ""
    # A locked card changes nothing, and neither does the row's own kind.
    for name in ("otherKind", "ownKind", "otherCard"):
        assert edit[name] == editing, name
    assert edit["posts"][0] == {"url": "/api/admin/channels/ops/destination",
                                "body": {"type": "webhook", "destination": HOOK + "2",
                                         "chat_id": "", "events": KINDS}}
    assert not edit["saved"]["open"] and edit["saved"]["toast"] == "Saved."
    # A Slack row: its switches as stored, Save and never a connect, and only
    # the kinds are written.
    assert edit["slack"]["title"] == "Edit team" and edit["slack"]["fields"] == ["chan-slack"]
    assert edit["slack"]["buttons"] == ["Cancel", "Save"]
    assert edit["switches"] == ["silent"]
    assert edit["posts"][1] == {"url": "/api/admin/channels/team/events",
                                "body": {"events": ["silent"]}}
    # The next Add starts clean: its own title, nothing locked, every kind on.
    after = edit["addAfter"]
    assert after["title"] == "Add" and after["locked"] == 0 and after["picked"] == []
    assert after["first"] == len(build.ADD_KINDS) and after["cards"] == 0
    assert after["buttons"] == ["Cancel"] and edit["switchesAfter"] == 0


# ------------------------------------------------------------- the geometry

GEOMETRY = """
    await view('alerts');                           R.alerts=spill();
    await view('integrations');                     R.integrations=spill();
    await open();                                   R.first=spill();
    await kind('dest');                             R.dest=spill();
    await card('chan-telegram');                    R.telegram=spill();
    await kind('prov');                             R.prov=spill();
    await card('intg-hetzner');                     R.hetzner=spill();
    await kind('mon');                              R.mon=spill();
    R.windowMotions=rested.filter(function(n){return n==='m-in'}).length;
"""


@pytest.mark.parametrize("width,height", [(1440, 900), (1024, 768)])
def test_neither_screen_spills_at_1440_or_1024(tmp_path, width, height):
    seen = walk(tmp_path, GEOMETRY, width, height)
    for name in ("alerts", "integrations", "first", "dest", "telegram", "prov", "hetzner", "mon"):
        step = seen[name]
        assert step["page"] <= 0, f"{name} at {width}: the page runs {step['page']} px wide"
        assert step["rows"] == 0, f"{name} at {width}: a row's text is cut"
        assert step["cards"] == [], f"{name} at {width}: a card spills: {step['cards']}"
        if step["modalLeft"] is not None:
            assert step["modalLeft"] >= 0 and step["modalRight"] >= 0, f"{name} at {width}"
    # The steps before any fields fit their room, so the foot is in view.
    for name in ("first", "dest", "prov", "hetzner", "mon"):
        assert seen[name]["modalNeeds"] <= seen[name]["modalHas"], \
            f"{name} at {width} by {height}: the window scrolls, its foot is out of view"
    # The window grows downward: the first row stands at one height at every
    # step, so a card stays under the pointer that clicked it.
    tops = {name: seen[name]["firstTop"] for name in ("first", "dest", "telegram", "prov",
                                                      "hetzner", "mon")}
    assert len(set(tops.values())) == 1, f"the window moves at {width} by {height}: {tops}"
    assert seen["windowMotions"] == 1, f"the window's opening motion plays again at {width}"
    # In a row of cards the icons stand at one height and the words at one,
    # with a planned tag or without: the tag goes under.
    for name in ("dest", "prov", "mon"):
        assert seen[name]["rowIcons"] == 1 and seen[name]["rowWords"] == 1, \
            f"{name} at {width}: the cards of a row do not line up"


BOXES = """
    await view('alerts');                           R.alerts=spill();
    await view('integrations');                     R.integrations=spill();
"""


def test_the_empty_box_sits_where_a_table_would(tmp_path):
    """With nothing connected Integrations has no heading over its box. The
    box still starts where the first table of a screen starts, which is
    where the Alerts box stands under its heading."""
    seen = walk(tmp_path, BOXES, workspace=nothing_at_all)
    assert seen["alerts"]["boxTop"] and seen["integrations"]["boxTop"]
    assert seen["integrations"]["boxTop"] == seen["alerts"]["boxTop"]
