"""The account Settings screen's live half, and its controls in a real
browser (docs/screens/account-settings).

    Run from site/app: python3 -m pytest test_account_settings.py

The markup is covered in test_settings.py. This file covers what the script
does with it: whoami fills the fields, Save appears when a name changes and
posts it, the appearance control has three states and remembers the
system one, and the password window posts and closes or says why not.
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
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def script_of(html):
    return html[html.rindex("<script>"):]


def test_whoami_fills_every_marked_field_and_never_writes_markup(db):
    js = script_of(rl.render(db, now=NOW))
    assert "fillSettings(j)" in js
    for sel in (".js-who-name", ".js-who-email", ".js-who-pwd", ".js-who-totp", ".js-wsname",
                ".js-who-name-text"):
        assert f"querySelectorAll('{sel}')" in js, sel
    fn = js[js.index("var fillSettings="):js.index("var fillWho=")]
    assert "innerHTML" not in fn


def test_the_password_date_is_said_in_the_screens_words(db):
    js = script_of(rl.render(db, now=NOW))
    fn = js[js.index("var whenText="):js.index("var fillSettings=")]
    assert "'changed '+" in fn
    assert "return ''" in fn  # nothing stored is no date


def test_the_head_script_honours_the_system_choice_before_the_first_paint(db):
    html = rl.render(db, now=NOW)
    head = html.split("</head>")[0]
    assert "m==='system'&&window.matchMedia" in head
    assert "prefers-color-scheme: light" in head


def test_the_two_names_post_to_their_routes_and_only_on_a_change(db):
    js = script_of(rl.render(db, now=NOW))
    assert "wireNameField(i,'.js-name-save','/api/admin/account/name')" in js
    assert "wireNameField(i,'.js-ws-save','/api/admin/workspace/name')" in js
    fn = js[js.index("var wireNameField="):js.index("onWire(function(){\n  document.querySelectorAll('.js-who-name')")]
    assert "save.hidden=input.value.trim()===input.defaultValue.trim()" in fn
    assert "e.key==='Escape'" in fn and "e.key==='Enter'" in fn


def test_the_password_window_posts_both_and_writes_a_refusal_under_the_fields(db):
    js = script_of(rl.render(db, now=NOW))
    # Up to the next handler. The mark used to be the comment above that
    # handler, and no comment is sent to a browser since 2026-10-02.
    fn = js[js.index("var pwGo="):js.index("querySelectorAll('.js-unsilence')")]
    assert "fetch('/api/admin/account/password'" in fn
    assert "JSON.stringify({current:cur.value,new:nw.value})" in fn
    assert "pwErr.textContent=j.detail" in fn
    assert "pwOvl.classList.remove('on')" in fn


def test_the_account_routes_are_writes_the_viewing_guard_blocks(db):
    """An admin looking into somebody else's workspace must not be able to
    rename that account or change its password from there."""
    for route in ("/api/admin/account/name", "/api/admin/account/password",
                  "/api/admin/workspace/name"):
        assert route not in build.VIEWING_OPEN


# ------------------------------------------------------ in a real browser

# The page asks whoami the moment its script runs, before an iframe's onload
# can stub anything. So the stub is written into the page itself, ahead of
# every other script, and records what the page posted on the window.
STUB = """<script>
window.__posts=[];
window.fetch=function(url,opts){
  opts=opts||{};
  var answer=%(answer)s, who=%(who)s, two=%(two)s;
  if((opts.method||'GET')==='POST'){
    window.__posts.push({url:String(url),body:opts.body||null});
    // The two enrolment routes answer with their own shapes, whatever the
    // step's answer is: they are the window's own conversation.
    if(String(url).indexOf('2fa/start')>=0){
      return Promise.resolve({ok:true,status:200,
        json:function(){return Promise.resolve(two.start)}});
    }
    if(String(url).indexOf('2fa/confirm')>=0){
      return Promise.resolve({ok:true,status:200,
        json:function(){return Promise.resolve(two.confirm)}});
    }
    return Promise.resolve({ok:answer.status<300,redirected:false,status:answer.status,
      json:function(){return Promise.resolve(answer.json||{})},
      text:function(){return Promise.resolve('')}});
  }
  if(String(url).indexOf('whoami')>=0){
    return Promise.resolve({ok:true,status:200,json:function(){return Promise.resolve(who)}});
  }
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve('')}});
};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>settings drive</title>
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
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||60)})};
    var result={step:step,errs:[]};
    w.addEventListener('error',function(e){result.errs.push(String(e.message))});
    await tick(150);
    d.querySelector('.nav [data-v="settings"]').click(); await tick();
    result.view=(d.querySelector('.view.on')||{}).id;
    var name=d.querySelector('#settings .js-who-name');
    var save=d.querySelector('#settings .js-name-save');
    result.nameValue=name.value;
    result.email=d.querySelector('#settings .kv.js-who-email').textContent;
    result.pwd=d.querySelector('#settings .js-who-pwd').textContent;
    result.totpOff=d.querySelector('#settings .js-who-totp').classList.contains('off');
    result.ws=d.querySelector('#settings .js-wsname').value;
    result.saveHiddenBefore=save.hidden;
    if(step==='rename'||step==='refused'){
      name.value='New Name'; name.dispatchEvent(new w.Event('input')); await tick();
      result.saveHiddenAfterEdit=save.hidden;
      save.click(); await tick();
      result.saveHiddenAfterSave=save.hidden;
      result.nameAfter=name.value;
      result.toast=d.getElementById('toast').textContent;
    }
    if(step==='escape'){
      name.value='Typo'; name.dispatchEvent(new w.Event('input')); await tick();
      name.dispatchEvent(new w.KeyboardEvent('keydown',{key:'Escape'})); await tick();
      result.nameAfter=name.value; result.saveHiddenAfterSave=save.hidden;
    }
    if(step==='mode'){
      d.querySelector('#settings .js-mode-system').click(); await tick();
      result.stored=w.localStorage.getItem('wp-mode');
      result.onSystem=d.querySelector('#settings .js-mode-system').classList.contains('on');
      d.querySelector('#settings .js-mode-light').click(); await tick();
      result.modeAttr=d.documentElement.dataset.mode||'';
      result.storedLight=w.localStorage.getItem('wp-mode');
      d.querySelector('#settings .js-mode-dark').click(); await tick();
      result.storedDark=w.localStorage.getItem('wp-mode');
      result.modeAttrDark=d.documentElement.dataset.mode||'';
    }
    if(step==='password'||step==='pwrefused'){
      d.querySelector('#settings [data-open="pw-ovl"]').click(); await tick();
      result.opened=d.getElementById('pw-ovl').classList.contains('on');
      var newField=d.getElementById('pw-new'), again=d.getElementById('pw-again');
      d.getElementById('pw-current').value='old-passphrase-here9!';
      // typed, so the rules paint the way they do for a person
      newField.value='new-passphrase-here9!';
      newField.dispatchEvent(new w.Event('input')); await tick();
      var rules=d.querySelectorAll('#pw-ovl .rules li');
      result.rulesMet=Array.prototype.map.call(rules,function(li){
        return li.classList.contains('yes')?'yes':(li.classList.contains('no')?'no':'')});
      // a wrong confirm paints the last line red, a right one green
      again.value='new-passphrase-here9';
      again.dispatchEvent(new w.Event('input')); await tick();
      result.matchWrong=rules[rules.length-1].classList.contains('no');
      again.value='new-passphrase-here9!';
      again.dispatchEvent(new w.Event('input')); await tick();
      result.matchAfter=rules[rules.length-1].classList.contains('yes');
      d.getElementById('pw-go').click(); await tick();
      result.openAfter=d.getElementById('pw-ovl').classList.contains('on');
      result.err=d.getElementById('pw-err').textContent;
      result.pwdAfter=d.querySelector('#settings .js-who-pwd').textContent;
    }
    if(step==='pwshort'){
      var shortField=d.getElementById('pw-new');
      d.getElementById('pw-current').value='old-passphrase-here9!';
      shortField.value='short';
      shortField.dispatchEvent(new w.Event('input')); await tick();
      var li=d.querySelectorAll('#pw-ovl .rules li');
      result.rulesMet=Array.prototype.map.call(li,function(x){
        return x.classList.contains('yes')?'yes':(x.classList.contains('no')?'no':'')});
    }
    if(step==='twofactor'){
      d.querySelector('#settings .js-2fa-on').click(); await tick(150);
      result.opened=d.getElementById('tfa-ovl').classList.contains('on');
      result.key=d.getElementById('tfa-key').textContent;
      result.qrSquares=d.querySelectorAll('#tfa-qr svg path').length;
      d.getElementById('tfa-code').value='123456';
      d.getElementById('tfa-go').click(); await tick();
      result.codes=Array.prototype.map.call(
        d.querySelectorAll('#tfa-codelist span'),function(x){return x.textContent});
      result.setupGone=!d.getElementById('tfa-setup').classList.contains('on');
      result.turnOnGone=d.getElementById('tfa-go').hidden;
      result.switchOn=!d.querySelector('#settings .js-who-totp').classList.contains('off');
    }
    result.posts=w.__posts;
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
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    plan = []
    for i, (step, page, extra) in enumerate(steps):
        stub = STUB % {"answer": json.dumps(extra.get("answer", {"status": 204})),
                       "who": json.dumps(extra.get("who", {})),
                       "two": json.dumps(extra.get("two", TWO_FACTOR_ANSWERS))}
        (site / f"page{i}.html").write_text(page.replace("<head>", "<head>" + stub, 1), encoding="utf-8")
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
             "--virtual-time-budget=10000", "--dump-dom",
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
    return results


WHO = {"user": "sysadmin@example.test", "name": "Robin", "totp": True,
       "password_changed_at": "2026-08-13T10:00:00+00:00", "workspace": "ops"}
WHO_NO_2FA = dict(WHO, totp=False)

# What the two enrolment routes answer with. The matrix is three rows, which
# is not a real QR and is not meant to be: what is under test is that the
# window turns rows of "0" and "1" into squares without parsing markup.
TWO_FACTOR_ANSWERS = {
    "start": {"groups": "ABCD EFGH IJKL MNOP", "qr": ["010", "101", "010"]},
    "confirm": {"codes": ["aaaa-bbbb", "cccc-dddd", "eeee-ffff", "gggg-hhhh"]},
}


@pytest.mark.skipif(find_chrome() is None, reason="no Chrome on this machine")
def test_the_screen_fills_saves_switches_and_changes_the_password(tmp_path, db):
    trl.add_host(db, "box", [])
    page = rl.render(db, now=NOW)
    got = drive(tmp_path, [
        ("rename", page, {"who": WHO}),
        ("refused", page, {"who": WHO, "answer": {"status": 400, "json": {"detail": "Use at most 80 characters."}}}),
        ("escape", page, {"who": WHO}),
        ("mode", page, {"who": WHO}),
        ("password", page, {"who": WHO}),
        ("pwrefused", page, {"who": WHO, "answer": {"status": 400, "json": {"detail": "The current password is not right."}}}),
        ("pwshort", page, {"who": WHO}),
        ("twofactor", page, {"who": WHO_NO_2FA}),
    ])
    rename, refused, escape, mode, password, pwrefused, pwshort, two = got
    # whoami filled every field
    assert rename["view"] == "settings"
    assert (rename["nameValue"], rename["email"], rename["ws"]) == ("Robin", "sysadmin@example.test", "ops"), rename
    assert rename["pwd"] == "changed 13 Aug 2026"
    assert rename["totpOff"] is False
    # Save appears on a change, posts the name, and hides again once stored
    assert rename["saveHiddenBefore"] is True and rename["saveHiddenAfterEdit"] is False
    assert [(p["url"], json.loads(p["body"])) for p in rename["posts"]] == [
        ("/api/admin/account/name", {"name": "New Name"})]
    assert rename["saveHiddenAfterSave"] is True and rename["nameAfter"] == "New Name"
    # a refusal is a toast and the field keeps what was typed, Save still there
    assert refused["toast"] == "Use at most 80 characters."
    assert refused["saveHiddenAfterSave"] is False and refused["nameAfter"] == "New Name"
    # Escape puts the stored name back
    assert escape["nameAfter"] == "Robin" and escape["saveHiddenAfterSave"] is True
    assert escape["posts"] == []
    # three appearances, remembered per browser, dark being nothing stored
    assert (mode["stored"], mode["onSystem"]) == ("system", True)
    assert (mode["modeAttr"], mode["storedLight"]) == ("light", "light")
    assert (mode["storedDark"], mode["modeAttrDark"]) == (None, "")
    # the password window posts both, closes, and the date moves
    assert password["opened"] is True and password["openAfter"] is False
    assert [(p["url"], json.loads(p["body"])) for p in password["posts"]] == [
        ("/api/admin/account/password",
         {"current": "old-passphrase-here9!", "new": "new-passphrase-here9!"})]
    assert password["err"] == "" and password["pwdAfter"].startswith("changed ")
    # the rules went green as it was typed, and the fourth one when the second
    # field matched (the owner, 2026-09-10)
    # the three the new password meets, then Both the same, still grey:
    # the confirm box has not been typed in, and a red line about a box
    # nobody has reached yet is an error nobody made
    assert password["rulesMet"] == ["yes", "yes", "yes", ""]
    assert password["matchWrong"] is True and password["matchAfter"] is True
    # a refusal stays open and says why under the fields
    assert pwrefused["openAfter"] is True
    assert pwrefused["err"] == "The current password is not right."
    # a password that meets none of them says so, in the same three rows
    assert pwshort["rulesMet"] == ["no", "no", "no", ""]
    # the authenticator window: the key and the squares arrive, the code turns
    # it on, and the recovery codes replace the form
    assert two["opened"] is True
    assert two["key"] == "ABCD EFGH IJKL MNOP"
    assert two["qrSquares"] == 1, "the QR is one path of squares"
    assert [(p["url"], json.loads(p["body"]) if p["body"] else None) for p in two["posts"]
            if "2fa" in p["url"]] == [
        ("/api/admin/account/2fa/start", None),
        ("/api/admin/account/2fa/confirm", {"code": "123456"})]
    assert two["codes"] == TWO_FACTOR_ANSWERS["confirm"]["codes"]
    assert two["setupGone"] is True and two["turnOnGone"] is True
    # and the row behind the window says it is on, without a reload
    assert two["switchOn"] is True
