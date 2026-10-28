"""The Feedback button, its window, and where a message lands in the console.

Run from site/: python3 -m pytest app/test_feedback_window.py

docs/screens/feedback/BRIEF.md, the one exception to SI-8 (docs/record
4.425) and the delete beside Done (4.436). The ones carrying the argument:

  - the button is in the top bar on every screen and absent while an admin
    views another workspace, where the page's own guard refuses the post too
  - the window prints exactly the five lines the body carries, To first,
    and To is our host with a key and the instance's own host without one
  - the screen word is one of the twelve the wire holds, from the view and
    its tab, and never the address bar, which holds a server's name
  - nothing is posted before Send is clicked, and the first click posts
    exactly the five fields
  - every refusal class has its one line and the words stay, the no-answer
    line is the page's own with Try again, and Send waits ten seconds and
    no longer
  - the console's list escapes the words, never cuts them and never makes a
    link of them, Done moves a row under the fold and the badge counts the
    open ones, Delete asks with the page's own dialog and never the browser's

The browser walks run Chrome through ops/testfleet/browser.mjs, over the
DevTools protocol, with real clicks. The server the page talks to is a
stand-in put in the page's own head, ahead of its script, so the page's
fetch wrapper wraps it as it wraps the real fetch (docs/record 4.199): a
stub placed from outside the page bypassed that wrapper and hid a bug once.
"""
import ast
import functools
import html as html_mod
import http.server
import json
import os
import pathlib
import re
import shutil
import sqlite3
import subprocess
import threading
from datetime import datetime, timezone

import pytest

import build as tpl
import render_live as rl
import test_admin_view as tav
import test_render_live as trl

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
BROWSER_MJS = REPO / "ops" / "testfleet" / "browser.mjs"
FONTS = HERE.parent / "fonts"
WIRE = REPO / "controlplane" / "app" / "feedback.py"

NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)
OUR_HOST = "app.whichports.com"
NO_ANSWER = "No answer. Check your connection and try again."
WORDS = "The Open button at the end of a Workspaces row is cut off at 1024 wide."
A_LINK = "See https://example.com/a/page?x=1 and <b>this</b>"
MARKUP = '<img src=x onerror="window.__made=1">'

# What the page shows for each class our box or the instance can answer
# with, the brief's table, with the host put in where the line names it.
LINES = {
    "unknown_key": f"{OUR_HOST} did not accept this instance's key.",
    "too_large": "Too long. 2,000 characters at most.",
    "over_instance_pace": "Twenty messages a day is the most. Try again tomorrow.",
    "malformed_request": f"{OUR_HOST} could not read this message, HTTP 400.",
    "unsupported_version": f"{OUR_HOST} could not read this message, HTTP 400.",
}


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def page(db, **kw):
    kw.setdefault("feedback_to", OUR_HOST)
    return rl.render(db, now=NOW, workspace_id=1, **kw)


def topbar_of(html):
    start = html.index('<div class="top">')
    return html[start:html.index("</div></div>", start)]


def window_of(html):
    start = html.index('<div class="ovl js-modal" id="fb-ovl"')
    end = html.index('<div class="ovl', start + 10)
    return html[start:end]


def text_of(markup):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", markup)).strip()


def wire_screens():
    """`SCREENS` as `controlplane/app/feedback.py` holds it, read from the
    file: this tree cannot import that one (site/app/joinbridge.py says why),
    and a copy here would be the second place the list drifts in."""
    source = WIRE.read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and node.targets[0].id == "SCREENS":
            return ast.literal_eval(node.value)
    raise AssertionError("no SCREENS in the wire")


# ================================================================= the button

def test_the_button_is_in_the_top_bar_on_every_screen(db):
    trl.reporting(db, "web-01", trl.document(listening=[trl.SSHD]))
    html = page(db)
    bar = topbar_of(html)
    assert '<button class="btn" id="fb-btn" data-open="fb-ovl">Feedback</button>' in bar
    assert bar.index('id="fb-btn"') < bar.index('class="pm"'), "beside the account circle"
    assert html.count('id="fb-btn"') == 1, "once, in the bar, not per view"
    # The bar is outside every view, so it is on every screen by construction.
    assert html.index('id="fb-btn"') < html.index('<div class="wrap view"')


def test_the_button_is_absent_while_viewing_another_workspace(db):
    html = page(db, viewing=(4, "sandbox"))
    assert 'id="fb-btn"' not in html
    assert 'id="fb-ovl"' not in html
    assert 'data-viewing="1"' in html


def test_the_page_refuses_the_post_while_viewing():
    """The page's fetch guard lets two `/api/admin/` calls through while a
    page shows somebody else's workspace, and this is not one of them."""
    assert "/api/admin/feedback" not in tpl.VIEWING_OPEN
    js = (HERE / "page.js").read_text(encoding="utf-8")
    guard = js[js.index("function lockViewing"):js.index("function dimViewing")]
    assert "u.indexOf('/api/admin/') === 0 && VIEWING_OPEN.indexOf(u) < 0" in guard


# ================================================================= the window

def test_the_window_prints_exactly_the_fields_the_body_carries(db):
    win = window_of(page(db))
    assert "<h2>Feedback</h2>" in win
    labels = re.findall(r'<span class="k">(.*?)</span>', win)
    assert labels == ["To", "From", "Screen", "Version", "Kind"]
    assert '<span class="v" id="fb-to">' in win and '<span class="v" id="fb-from">' in win
    assert '<span class="v" id="fb-screen">' in win and '<span class="v" id="fb-version">' in win
    assert '<span class="v" id="fb-kind">' in win
    cards = re.findall(r'<button type="button" class="m-card pick" id="fb-(\w+)">', win)
    assert cards == ["feature", "bug"]
    assert '<textarea class="m-input" id="fb-words"' in win
    assert win.count('class="btn pri"') == 1, "one primary, Send"
    assert '<button class="btn pri" id="fb-go">Send</button>' in win
    assert '<button class="btn" data-close="fb-ovl">Cancel</button>' in win
    # One line for every answer, under the five lines and above the buttons.
    assert win.count('class="m-result"') == 1 and 'class="m-err"' not in win
    assert win.index('class="fb-facts"') < win.index('id="fb-result"') < win.index('class="m-foot"')
    assert '</div><div class="m-result" id="fb-result"></div>\n    <div class="m-foot">' in win
    # Nothing on it explains. Labels, values and the two names.
    text = text_of(win)
    for phrase in ("we ", "because", "will be", "your words", "our box", "api"):
        assert phrase not in text.lower(), phrase


def test_to_names_our_host_with_a_key_and_the_instances_own_without(db):
    with_key = window_of(page(db, feedback_to=OUR_HOST))
    assert f'<span class="v" id="fb-to">{OUR_HOST}</span>' in with_key
    without = window_of(page(db, feedback_to=""))
    assert '<span class="v" id="fb-to" data-own="1"></span>' in without, \
        "the page fills in its own host, from location.host"
    assert OUR_HOST not in without


def test_from_reads_this_instance_and_never_a_host(db):
    win = window_of(page(db))
    assert '<span class="v" id="fb-from">this instance</span>' in win
    assert "key" not in text_of(win).lower()


def test_the_version_line_is_the_commit_the_footer_shows_or_unknown(db, tmp_path, monkeypatch):
    stamp = tmp_path / "DEPLOYED_COMMIT"
    stamp.write_text("0835a67\n")
    monkeypatch.setenv(rl.BUILD_FILE_ENV, str(stamp))
    html = page(db)
    assert "built 0835a67, rendered" in html
    assert '<span class="v" id="fb-version">0835a67</span>' in window_of(html)
    # A tree with local changes: the footer says so, the wire takes hex only.
    stamp.write_text("0835a67 +local changes\n")
    html = page(db)
    assert "built 0835a67 +local changes" in html
    assert '<span class="v" id="fb-version">0835a67</span>' in window_of(html)
    monkeypatch.setenv(rl.BUILD_FILE_ENV, str(tmp_path / "none"))
    assert '<span class="v" id="fb-version">unknown</span>' in window_of(page(db))


def test_the_screen_words_are_the_wires_twelve_in_its_order():
    """One list on both sides: the page's, read by the script from the
    builder, is the wire's `SCREENS` word for word."""
    assert tpl.FEEDBACK_SCREENS == wire_screens()
    assert len(tpl.FEEDBACK_SCREENS) == 12
    js = (HERE / "page.js").read_text(encoding="utf-8")
    assert "var FEEDBACK_SCREENS=__FEEDBACK_SCREENS__;" in js, \
        "the script takes the list from the builder, never a second copy"
    assert "__FEEDBACK_SCREENS__" not in tpl.build_sample()


def test_the_screen_word_is_from_the_closed_list_and_never_a_path():
    """The page's own rule, read from the script: a host view gives `host`
    and its tab, the other views their own word, and the address bar is
    never read. A page at /host/web-01/rules yields `host/rules` in the
    browser walk below, and `web-01` is in no field."""
    js = (HERE / "page.js").read_text(encoding="utf-8")
    body = js[js.index("var feedbackScreen=function"):]
    body = body[:body.index("\n  };") + 5]
    assert "location" not in body, "the path holds a server's name"
    assert "'host/'+tab" in body and "currentTab(" in body
    assert "FEEDBACK_SCREENS.indexOf(word)>=0" in body


def test_the_characters_the_page_strips_are_the_wires_list_and_the_count_is_code_points():
    js = (HERE / "page.js").read_text(encoding="utf-8")
    clean = js[js.index("var feedbackClean=function"):]
    clean = clean[:clean.index("};") + 2]
    assert "\\r\\n" in clean
    assert "[\\u0000-\\u0009\\u000B-\\u001F\\u007F-\\u009F]" in clean
    assert "[\\u202A-\\u202E\\u2066-\\u2069]" in clean
    count = js[js.index("var feedbackCount=function"):]
    count = count[:count.index("};") + 2]
    assert "Array.from(" in count and ".length" in count
    assert tpl.FEEDBACK_MAX_WORDS == 2000
    wire = WIRE.read_text(encoding="utf-8")
    assert "MAX_WORDS = 2000" in wire
    assert "range(0x202A, 0x202F)" in wire and "range(0x2066, 0x206A)" in wire


def test_each_refusal_class_has_its_one_line_in_the_script():
    js = (HERE / "page.js").read_text(encoding="utf-8")
    lines = js[js.index("var FEEDBACK_LINES="):js.index("\n  };", js.index("var FEEDBACK_LINES=")) + 5]
    for word, line in (("unknown_key", "did not accept this instance's key."),
                       ("too_large", "Too long. 2,000 characters at most."),
                       ("over_instance_pace", "Twenty messages a day is the most. Try again tomorrow."),
                       ("malformed_request", "could not read this message, HTTP 400."),
                       ("unsupported_version", "could not read this message, HTTP 400.")):
        assert word in lines and line in lines, word
    for said in re.findall(r"'([^']*)'|\"([^\"]*)\"", lines):
        for mark in ("—", "–", ";"):
            assert mark not in "".join(said), said


def test_the_sample_shell_carries_the_window_as_a_stub_that_asks_nothing():
    html = tpl.build_sample()
    assert 'id="fb-btn"' in html and 'id="fb-ovl"' in html
    win = window_of(html)
    assert 'id="fb-go"' not in win
    assert 'class="btn pri js-act" data-close="fb-ovl" data-msg="The message would be sent here"' in win
    assert '<span class="v" id="fb-version">unknown</span>' in win


def test_the_window_carries_no_dash_and_no_semicolon(db):
    text = text_of(window_of(page(db)))
    for mark in ("—", "–", ";"):
        assert mark not in text


# ================================================================ the console

A_ROW = {"id": 7, "instance_id": 1, "workspace_id": None, "kind": "bug",
         "words": WORDS, "screen": "admin", "instance_version": "0835a67",
         "received_at": "2026-10-09T10:21:00+00:00", "done_at": None}
B_ROW = {"id": 8, "instance_id": None, "workspace_id": 4, "kind": "feature",
         "words": "A column for the agent's version on the Fleet.\nSecond line.",
         "screen": "fleet", "instance_version": "unknown",
         "received_at": "2026-10-09T11:40:00+00:00", "done_at": None}
C_ROW = {"id": 5, "instance_id": 2, "workspace_id": None, "kind": "bug",
         "words": "Done already.", "screen": "host/rules", "instance_version": "0835a67",
         "received_at": "2026-10-08T09:00:00+00:00", "done_at": "2026-10-08T12:00:00+00:00"}


def console(db, open_rows=(B_ROW, A_ROW), done_rows=(C_ROW,), **over):
    return tav.page(db, feedback={"open": list(open_rows), "done": list(done_rows)},
                    feedback_open=len(open_rows), **over)


def tab_of(html):
    view = tav.view_of(html)
    tab = view[view.index('id="t-admin-feedback"'):]
    return tab[:tab.index('<div class="tab k-')] if '<div class="tab k-' in tab else tab


def test_the_feedback_tab_is_built_and_billing_stays_planned(db):
    assert tpl.ADMIN_PLANNED == ("billing",)
    view = tav.view_of(console(db))
    assert '<input type="radio" class="tabsel k-feedback" name="tabs-admin" id="tb-admin-feedback">' in view
    assert '<div class="tab k-feedback" id="t-admin-feedback">' in view


def test_the_tab_lists_the_six_columns_and_the_actions_in_a_fixed_end_track(db):
    tab = tab_of(console(db))
    heads = re.findall(r'<div class="thead frow">(.*?)</div>', tab)
    assert len(heads) == 2, "the open list and the done fold, one head each"
    assert re.findall(r"<span[^>]*>(.*?)</span>", heads[0]) == \
        ["When", "From", "Kind", "Screen", "Version", "Words", ""]
    rule = re.search(r"\.thead\.frow,\.row\.frow\{grid-template-columns:([^}]+)\}", tpl.ADMIN_CSS).group(1)
    tracks = rule.split()
    assert len(tracks) == 7
    assert tracks[-1].endswith("px") and "(" not in tracks[-1], "the end track is fixed"
    px, gaps = tav.fixed_px(rule)
    assert px + 16 * gaps + 40 <= 972


def test_a_row_names_the_instance_or_the_workspace_and_the_words_whole(db):
    tab = tab_of(console(db))
    text = text_of(tab)
    assert "09 Oct 2026 11:40 sandbox feature fleet unknown" in text
    assert "09 Oct 2026 10:21 selfhost-test-1 bug admin 0835a67" in text
    assert WORDS in text
    # Open ones first, newest first inside them, as the wire lists them.
    assert tab.index('data-id="8"') < tab.index('data-id="7"') < tab.index('data-id="5"')
    assert "1 open, 1 done" not in text
    assert "2 open, 1 done" in text


def test_the_admin_list_escapes_the_words_and_never_cuts_them(db):
    long_words = "x" * 1999 + "y"
    rows = [dict(A_ROW, words=MARKUP + "\n" + long_words)]
    html = console(db, open_rows=rows)
    tab = tab_of(html)
    assert "<img" not in tab and "&lt;img src=x onerror=" in tab
    assert long_words in tab, "2,000 characters, whole"
    assert "…" not in tab and "..." not in tab
    cell = re.search(r'<div class="fwords">(.*?)</div>', tab, re.S).group(1)
    assert cell == html_mod.escape(MARKUP) + "\n" + long_words
    css = tpl.ADMIN_CSS
    assert ".frow .fwords{white-space:pre-wrap;overflow-wrap:anywhere" in css


def test_a_url_in_the_words_is_text_and_never_a_link(db):
    tab = tab_of(console(db, open_rows=[dict(A_ROW, words=A_LINK)]))
    assert html_mod.escape(A_LINK) in tab
    cell = re.search(r'<div class="fwords">(.*?)</div>', tab, re.S).group(1)
    assert "<a" not in cell and "href" not in cell
    assert "<b>" not in cell


def test_done_rows_sit_under_the_fold_with_delete_alone(db):
    tab = tab_of(console(db))
    fold = tab[tab.index('<details class="fs fb-done" id="fb-done">'):]
    assert '<summary><span>Done</span><span class="hint" id="fb-done-n">1</span></summary>' in fold
    done_row = fold[fold.index('data-id="5"'):]
    done_row = done_row[:done_row.index("</div></div>")]
    assert "js-fb-del" in done_row and "js-fb-done" not in done_row
    open_row = tab[tab.index('data-id="8"'):tab.index('data-id="7"')]
    assert "js-fb-done" in open_row and "js-fb-del" in open_row


def test_the_badge_counts_open_ones_on_the_tab_and_on_the_admin_entry(db):
    html = console(db)
    nav = tav.subnav_of(html)
    assert '<label class="k-feedback" for="tb-admin-feedback">Feedback<span class="nb" id="fb-open-nb">2</span></label>' in nav
    assert '<a data-v="admin">Admin<span class="nb">2</span></a>' in tav.nav_of(html)
    none = console(db, open_rows=())
    assert '<label class="k-feedback" for="tb-admin-feedback">Feedback</label>' in tav.subnav_of(none)
    assert '<a data-v="admin">Admin</a>' in tav.nav_of(none)
    assert "no message yet" in text_of(tab_of(none))


def test_the_fixture_is_one_world():
    numbers = tav.stats()
    assert numbers["feedback_open"] == len(numbers["feedback"]["open"])


def test_the_tab_carries_no_explanation(db):
    text = text_of(tab_of(console(db))).lower()
    for phrase in tav.FORBIDDEN:
        assert phrase not in text, phrase


# ======================================================= walked in a browser

# The stand-in server, in the page's own head. What Send is answered with is
# set by the walk, one press at a time: window.__answer. `hang` is an answer
# that only comes when the walk lets it, after the window has stopped
# waiting. The browser's own confirm is replaced so that a call to it is
# counted, and the page's dialog must be the one that asks.
STUB = """<script>
window.__posts=[];window.__answer='stored';window.__late=[];window.__made=0;window.__confirms=0;
window.confirm=function(){window.__confirms++;return true};
window.fetch=function(url,opts){
  var u=String(url);
  var answer=function(status,body){
    return {ok:status>=200&&status<300,status:status,redirected:false,
      json:function(){return Promise.resolve(body)},
      text:function(){return Promise.resolve('')}}};
  if(opts&&opts.method==='POST'){
    window.__posts.push({url:u,body:opts.body?JSON.parse(opts.body):null,
      headers:opts.headers||{},at:Date.now()});
    if(u==='/api/admin/feedback'){
      var a=window.__answer;
      if(a==='fail')return Promise.reject(new TypeError('Failed to fetch'));
      if(a==='hang')return new Promise(function(resolve,reject){
        window.__late.push(function(){resolve(answer(200,{stored:true}))});
        if(opts.signal)opts.signal.addEventListener('abort',function(){
          reject(new DOMException('aborted','AbortError'))});
      });
      if(a==='stored')return Promise.resolve(answer(200,{stored:true}));
      var statuses={unknown_key:401,too_large:413,over_instance_pace:429,
        malformed_request:400,unsupported_version:400,no_answer:502};
      return Promise.resolve(answer(statuses[a]||500,{error:a}));
    }
    if(/^\\/api\\/admin\\/feedback\\/\\d+\\/(done|delete)$/.test(u)){
      if(window.__answer==='refuse')return Promise.resolve(answer(404,{detail:'no such message'}));
      return Promise.resolve(answer(200,{}));
    }
    return Promise.resolve(answer(204,{}));
  }
  return new Promise(function(){});
};
</script>"""

# The driver: one Chrome through browser.mjs, real clicks, and what it saw
# written to stdout as JSON for the tests to read.
DRIVER = """
import { Browser } from %(browser)s;
const url = process.argv[2];
const b = await Browser.start();
await b.send("Emulation.setEmulatedMedia", {features: [{name: "prefers-reduced-motion", value: "reduce"}]});
await b.size(1300, 900);
await b.goto(url);
const seen = {};
const tick = (ms) => new Promise((r) => setTimeout(r, ms || 60));
const ev = (js) => b.eval(js);
const look = async () => ev(`(() => {
  const d = document, ovl = d.getElementById('fb-ovl'), go = d.getElementById('fb-go');
  const shown = (el) => !!el && !el.hidden && el.offsetParent !== null;
  const foot = [...ovl.querySelectorAll('.m-foot button')].filter(shown);
  const posts = window.__posts.filter((p) => p.url === '/api/admin/feedback');
  return {open: ovl.classList.contains('on'),
    buttons: foot.map((x) => x.textContent.trim()),
    primaries: [...ovl.querySelectorAll('.btn.pri')].filter(shown).map((x) => x.textContent.trim()),
    goEnabled: !go.disabled, waiting: go.classList.contains('fb-wait'),
    words: d.getElementById('fb-words').value,
    picked: [...ovl.querySelectorAll('.m-card.sel')].map((c) => c.id),
    to: d.getElementById('fb-to').textContent, from: d.getElementById('fb-from').textContent,
    screen: d.getElementById('fb-screen').textContent,
    version: d.getElementById('fb-version').textContent,
    kind: d.getElementById('fb-kind').textContent,
    result: d.getElementById('fb-result').textContent,
    tone: d.getElementById('fb-result').className.replace('m-result', '').trim(),
    answer: (() => { const a = d.getElementById('fb-result'), m = ovl.querySelector('.modal');
      return {id: a.id, prev: a.previousElementSibling.className, next: a.nextElementSibling.className,
        top: Math.round(a.getBoundingClientRect().top - m.getBoundingClientRect().top),
        left: Math.round(a.getBoundingClientRect().left - m.getBoundingClientRect().left)}; })(),
    posts: posts.length, lastBody: posts.length ? posts[posts.length - 1].body : null,
    lastHeaders: posts.length ? posts[posts.length - 1].headers : null,
    focus: d.activeElement ? d.activeElement.id : ''};
})()`);
const note = async (name) => { seen[name] = await look(); return seen[name]; };
const type = (text) => ev(`(() => { const f = document.getElementById('fb-words');
  f.value = ${JSON.stringify(text)}; f.dispatchEvent(new Event('input', {bubbles: true})); return f.value; })()`);
const setAnswer = (a) => ev(`window.__answer = ${JSON.stringify(a)}`);
const open = async () => { await b.click('#fb-btn'); await tick(150); };
const cancel = async () => { await b.click('#fb-ovl .m-foot [data-close="fb-ovl"]'); await tick(150); };
const press = async (ms) => { await b.click('#fb-go'); await tick(ms || 250); };

// ---- the page, before any click: nothing posted
seen.beforeAnyClick = await ev('window.__posts.length');
// ---- opened on the fleet: the facts, nothing posted, no kind picked
await open(); await note('opened');
await b.click('#fb-bug'); await tick(); await note('bugPicked');
await type(%(words)s); await note('typed');
seen.beforeSend = await ev('window.__posts.length');
// ---- pasted control characters go as typed, what is shown is what is sent
seen.cleaned = await type("a\\tb\\r\\nc\\u202Ed\\u0007e\\u2066f");
// ---- the cap, counted in code points: 2,000 emoji fit, 2,001 do not
await type("\\u{1F600}".repeat(2000)); await note('atTheCap');
seen.unitsAtTheCap = await ev("document.getElementById('fb-words').value.length");
await type("\\u{1F600}".repeat(2001)); await note('overTheCap');
await type(%(words)s);
// ---- Send: the one request, the five fields
await press(); await note('sent');
await cancel(); await note('closedAfterSent');
// ---- opened again: empty, nothing kept from the last one
await open(); await note('openedAgain');
await b.click('#fb-feature'); await tick(); await type(%(words)s);
// ---- every refusal class, one line each, the words stay
for (const cls of ['unknown_key', 'too_large', 'over_instance_pace', 'malformed_request', 'unsupported_version']) {
  await setAnswer(cls); await press(); await note('refused:' + cls);
}
// ---- an answer that is none of the five, and the page's own 502
await setAnswer('something_else'); await press(); await note('refused:something_else');
await setAnswer('no_answer'); await press(); await note('refused:no_answer');
// ---- no connection at all
await setAnswer('fail'); await press(); await note('failed');
// ---- no answer in ten seconds: the spinner, then the line, and a late answer is not taken
await setAnswer('hang'); await press(1200); await note('waiting');
await tick(4000); await note('waitingStill');
await tick(5800); await note('ranOut');
await ev("window.__late.splice(0).forEach((f) => f())"); await tick(400); await note('lateAnswer');
// ---- Try again posts once more and lands
await setAnswer('stored'); await press(); await note('triedAgain');
await cancel();
// ---- the screen word on a server's rules tab: host/rules, never the name
await b.click('#fleet .row[data-host="web-01"]'); await tick(200);
await ev("[...document.querySelectorAll('.ovl.on')].forEach((o) => o.classList.remove('on'))");
await b.click('label[for="tb-web-01-rules"]'); await tick(100);
await open(); await b.click('#fb-bug'); await tick(); await type('On the rules tab.');
await press(); await note('onRules');
await cancel();
// ---- four ways out, none of which asks for anything
const postsBefore = await ev('window.__posts.length');
await open(); await b.press('Escape'); await tick(150); seen.escape = (await look()).open;
await open(); await cancel(); seen.cancel = (await look()).open;
await open(); await b.click('#fb-ovl .m-x'); await tick(150); seen.cross = (await look()).open;
seen.postsAfterClosing = (await ev('window.__posts.length')) - postsBefore;
seen.markupMade = await ev('window.__made');
seen.confirms = await ev('window.__confirms');
console.log(JSON.stringify(seen));
await b.close();
"""

ADMIN_DRIVER = """
import { Browser } from %(browser)s;
const url = process.argv[2];
const b = await Browser.start();
await b.send("Emulation.setEmulatedMedia", {features: [{name: "prefers-reduced-motion", value: "reduce"}]});
await b.size(1300, 900);
await b.goto(url);
const seen = {};
const tick = (ms) => new Promise((r) => setTimeout(r, ms || 60));
const ev = (js) => b.eval(js);
const look = async () => ev(`(() => {
  const d = document;
  const ids = (root) => [...root.querySelectorAll('.row.frow[data-id]')].map((r) => r.dataset.id);
  const fold = d.getElementById('fb-done');
  const tab = d.getElementById('t-admin-feedback');
  const openTable = tab.querySelector('.panel.ftbl');
  const ask = d.getElementById('ask');
  const nb = (sel) => { const e = d.querySelector(sel); return e ? e.textContent : ''; };
  return {open: ids(openTable), done: ids(fold),
    tabBadge: nb('#fb-open-nb'), navBadge: nb('.nav a[data-v="admin"] .nb'),
    hint: d.getElementById('fb-hint').textContent,
    doneCount: d.getElementById('fb-done-n').textContent,
    empty: openTable.querySelector('.empty') ? openTable.querySelector('.empty').textContent : '',
    asking: ask.classList.contains('on'), askTitle: d.getElementById('ask-t').textContent,
    askBody: d.getElementById('ask-b').textContent, askWord: d.getElementById('ask-yes').textContent,
    askFocus: d.activeElement ? d.activeElement.id : '',
    links: [...tab.querySelectorAll('.fwords a')].length,
    posts: window.__posts.map((p) => p.url), confirms: window.__confirms,
    toast: d.getElementById('toast').textContent};
})()`);
const note = async (name) => { seen[name] = await look(); return seen[name]; };
await b.click('.nav a[data-v="admin"]'); await tick(150);
await b.click('label[for="tb-admin-feedback"]'); await tick(150);
await note('arrived');
// ---- Done on the newest open row: it moves under the fold, the badges count down
await b.click('.row.frow[data-id="8"] .js-fb-done'); await tick(300); await note('oneDone');
// ---- Delete asks with the page's own dialog, and Cancel changes nothing
await b.click('.row.frow[data-id="7"] .js-fb-del'); await tick(200); await note('asked');
await b.click('#ask-no'); await tick(200); await note('refusedToDelete');
// ---- Delete, confirmed: the row is gone, the list says so
await b.click('.row.frow[data-id="7"] .js-fb-del'); await tick(200);
await b.click('#ask-yes'); await tick(300); await note('deleted');
// ---- a done row can be deleted too
await b.click('#fb-done summary'); await tick(200);
await b.click('#fb-done .row.frow[data-id="5"] .js-fb-del'); await tick(200);
await b.click('#ask-yes'); await tick(300); await note('deletedDone');
// ---- a refusal leaves the row where it is
await ev("window.__answer = 'refuse'");
await b.click('#fb-done .row.frow[data-id="8"] .js-fb-del'); await tick(200);
await b.click('#ask-yes'); await tick(300); await note('refusedByServer');
seen.spills = await b.spills();
console.log(JSON.stringify(seen));
await b.close();
"""


def serve(site):
    handler = functools.partial(trl_quiet_handler(), directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def trl_quiet_handler():
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self, *_args):
            pass
    return Quiet


def walk(tmp_path, html, driver):
    """Serve the page with the stand-in in its head, run the driver through
    browser.mjs, and return what it saw."""
    site = tmp_path / "www"
    site.mkdir(exist_ok=True)
    assert html.count("<head>") == 1
    (site / "live.html").write_text(html.replace("<head>", "<head>" + STUB, 1), encoding="utf-8")
    if not (site / "fonts").exists():
        os.symlink(FONTS, site / "fonts")
    script = tmp_path / "walk.mjs"
    script.write_text(driver, encoding="utf-8")
    node = shutil.which("node")
    assert node, "node is needed to drive Chrome through ops/testfleet/browser.mjs"
    server = serve(site)
    try:
        port = server.server_address[1]
        run = subprocess.run([node, str(script), f"http://127.0.0.1:{port}/live.html"],
                             capture_output=True, text=True, timeout=240)
    finally:
        server.shutdown()
    assert run.returncode == 0, run.stderr[-3000:]
    return json.loads(run.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def seen(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("feedback-window")
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "web-01", trl.document(listening=[trl.SSHD]))
    stamp = tmp_path / "DEPLOYED_COMMIT"
    stamp.write_text("0835a67\n")
    html = rl.render(path, now=NOW, workspace_id=1, feedback_to=OUR_HOST,
                     commit_file=str(stamp))
    driver = DRIVER % {"browser": json.dumps(str(BROWSER_MJS)), "words": json.dumps(WORDS)}
    return walk(tmp_path, html, driver)


@pytest.fixture(scope="module")
def console_seen(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("feedback-console")
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(tav.SCHEMA)
    con.commit()
    con.close()
    html = console(path)
    driver = ADMIN_DRIVER % {"browser": json.dumps(str(BROWSER_MJS))}
    return walk(tmp_path, html, driver)


def test_nothing_is_posted_before_send(seen):
    assert seen["beforeAnyClick"] == 0
    assert seen["opened"]["posts"] == 0
    assert seen["bugPicked"]["posts"] == 0 and seen["typed"]["posts"] == 0
    assert seen["beforeSend"] == 0, "no request of any kind before Send"
    assert seen["sent"]["posts"] == 1


def test_the_window_opens_empty_with_the_facts_and_send_waits_for_a_kind_and_words(seen):
    got = seen["opened"]
    assert got["open"] is True
    assert got["buttons"] == ["Cancel", "Send"] and got["primaries"] == ["Send"]
    assert got["goEnabled"] is False
    assert got["picked"] == [] and got["words"] == "" and got["kind"] == ""
    assert got["to"] == OUR_HOST and got["from"] == "this instance"
    assert got["screen"] == "fleet" and got["version"] == "0835a67"
    assert got["focus"] == "fb-words"
    assert seen["bugPicked"]["picked"] == ["fb-bug"] and seen["bugPicked"]["kind"] == "bug"
    assert seen["bugPicked"]["goEnabled"] is False, "no words yet"
    assert seen["typed"]["goEnabled"] is True


def test_the_first_click_on_send_posts_exactly_the_five_fields(seen):
    got = seen["sent"]
    assert got["lastBody"] == {"version": 1, "kind": "bug", "words": WORDS,
                               "screen": "fleet", "instance_version": "0835a67"}
    assert got["lastHeaders"] == {"Content-Type": "application/json"}


def test_sent_is_said_at_once_the_field_clears_and_cancel_reads_done(seen):
    got = seen["sent"]
    assert got["result"] == "Sent" and got["tone"] == "ok"
    assert got["words"] == ""
    assert got["buttons"] == ["Done"] and got["primaries"] == []
    assert seen["closedAfterSent"]["open"] is False
    again = seen["openedAgain"]
    assert again["words"] == "" and again["picked"] == [] and again["result"] == ""
    assert again["buttons"] == ["Cancel", "Send"] and again["goEnabled"] is False


def test_control_characters_leave_the_field_as_typed_and_newlines_stay(seen):
    assert seen["cleaned"] == "ab\ncdef"


def test_the_cap_is_counted_in_code_points(seen):
    """Two thousand emoji are 4,000 UTF-16 units, the count `.length` gives
    and the page must not use: our box takes 2,000 of them."""
    assert seen["unitsAtTheCap"] == 4000
    assert len(seen["atTheCap"]["words"]) == 2000
    assert seen["atTheCap"]["goEnabled"] is True and seen["atTheCap"]["result"] == ""
    over = seen["overTheCap"]
    assert over["goEnabled"] is False
    assert over["result"] == LINES["too_large"] and over["tone"] == "fail"
    assert over["posts"] == seen["atTheCap"]["posts"], "nothing over the cap is sent"


@pytest.mark.parametrize("cls", sorted(LINES))
def test_each_refusal_class_has_its_one_line_and_the_words_stay(seen, cls):
    got = seen["refused:" + cls]
    assert got["result"] == LINES[cls] and got["tone"] == "fail"
    assert got["words"] == WORDS and got["picked"] == ["fb-feature"]
    assert got["buttons"] == ["Cancel", "Send"] and got["goEnabled"] is True


def test_an_answer_outside_the_five_classes_is_the_no_answer_line(seen):
    for name in ("refused:something_else", "refused:no_answer"):
        got = seen[name]
        assert got["result"] == NO_ANSWER and got["tone"] == "fail", name
        assert got["words"] == WORDS


def test_the_no_answer_line_keeps_the_words_and_offers_try_again(seen):
    got = seen["failed"]
    assert got["result"] == NO_ANSWER and got["tone"] == "fail"
    assert got["words"] == WORDS and got["picked"] == ["fb-feature"]
    assert got["buttons"] == ["Cancel", "Try again"] and got["goEnabled"] is True
    tried = seen["triedAgain"]
    assert tried["posts"] == seen["ranOut"]["posts"] + 1
    assert tried["result"] == "Sent" and tried["buttons"] == ["Done"]


def test_send_waits_ten_seconds_with_the_spinner_and_no_longer(seen):
    waiting = seen["waiting"]
    assert waiting["goEnabled"] is False and waiting["waiting"] is True
    assert waiting["result"] == "" and waiting["buttons"] == ["Cancel", "Send"]
    still = seen["waitingStill"]
    assert still["goEnabled"] is False and still["waiting"] is True, "five seconds in, still waiting"
    out = seen["ranOut"]
    assert out["result"] == NO_ANSWER and out["waiting"] is False
    assert out["buttons"] == ["Cancel", "Try again"] and out["goEnabled"] is True
    assert out["words"] == WORDS
    # The answer that came after the wait was over is not taken.
    late = seen["lateAnswer"]
    assert late["result"] == NO_ANSWER and late["tone"] == "fail"
    assert late["buttons"] == ["Cancel", "Try again"]


def test_the_answer_line_has_one_place_for_sent_each_refusal_and_no_answer(seen):
    """One line under the five facts and above the buttons, whatever came
    back: Sent, each of the five classes, the cap's line and the no-answer
    line all stand on the same element at the same place in the window."""
    states = ["sent", "overTheCap", "failed", "ranOut", "lateAnswer",
              "refused:something_else", "refused:no_answer"] + ["refused:" + cls for cls in LINES]
    places = {name: seen[name]["answer"] for name in states}
    for name, place in places.items():
        assert place["id"] == "fb-result", name
        assert place["prev"] == "fb-facts" and place["next"] == "m-foot", name
        assert seen[name]["result"] != "", name
    tops = {place["top"] for place in places.values()}
    lefts = {place["left"] for place in places.values()}
    assert len(tops) == 1 and len(lefts) == 1, places
    # And the empty line keeps the place, so nothing under it moves.
    assert seen["opened"]["answer"]["top"] == places["sent"]["top"]
    assert seen["sent"]["tone"] == "ok"
    assert all(seen[name]["tone"] == "fail" for name in states if name != "sent")


def test_a_page_on_a_servers_rules_tab_sends_host_rules_and_never_the_name(seen):
    got = seen["onRules"]
    assert got["screen"] == "host/rules"
    assert got["lastBody"]["screen"] == "host/rules"
    assert "web-01" not in json.dumps(got["lastBody"])
    assert set(got["lastBody"]) == {"version", "kind", "words", "screen", "instance_version"}


def test_escape_cancel_and_the_cross_close_the_window_and_ask_nothing(seen):
    assert seen["escape"] is False and seen["cancel"] is False and seen["cross"] is False
    assert seen["postsAfterClosing"] == 0


def test_markup_typed_as_words_makes_nothing_and_the_browsers_confirm_is_never_called(seen):
    assert seen["markupMade"] == 0
    assert seen["confirms"] == 0


def test_there_is_never_more_than_one_primary_button_in_the_window(seen):
    looks = [v for v in seen.values() if isinstance(v, dict) and isinstance(v.get("primaries"), list)]
    assert len(looks) > 15
    assert all(len(look["primaries"]) <= 1 for look in looks)


# ------------------------------------------------------------- the console

def test_done_moves_a_row_under_the_fold_and_the_badge_counts_open_ones(console_seen):
    before = console_seen["arrived"]
    assert before["open"] == ["8", "7"] and before["done"] == ["5"]
    assert before["tabBadge"] == "2" and before["navBadge"] == "2"
    assert before["hint"] == "2 open, 1 done" and before["doneCount"] == "1"
    after = console_seen["oneDone"]
    assert after["open"] == ["7"] and after["done"] == ["8", "5"]
    assert after["tabBadge"] == "1" and after["navBadge"] == "1"
    assert after["hint"] == "1 open, 2 done" and after["doneCount"] == "2"
    assert after["posts"][-1] == "/api/admin/feedback/8/done"


def test_delete_asks_with_the_pages_own_dialog_and_cancel_keeps_the_row(console_seen):
    asked = console_seen["asked"]
    assert asked["asking"] is True
    assert asked["askTitle"] == "Delete this message?"
    assert asked["askBody"] == "selfhost-test-1, 09 Oct 2026 10:21"
    assert asked["askWord"] == "Delete" and asked["askFocus"] == "ask-no"
    assert asked["posts"][-1] == "/api/admin/feedback/8/done", "asking posts nothing"
    kept = console_seen["refusedToDelete"]
    assert kept["asking"] is False and kept["open"] == ["7"]
    assert kept["posts"] == asked["posts"]
    assert console_seen["refusedByServer"]["confirms"] == 0


def test_delete_confirmed_takes_the_row_out_and_the_badge_follows(console_seen):
    got = console_seen["deleted"]
    assert got["open"] == [] and got["empty"] == "no message yet"
    assert got["tabBadge"] == "" and got["navBadge"] == ""
    assert got["hint"] == "0 open, 2 done"
    assert got["posts"][-1] == "/api/admin/feedback/7/delete"
    done = console_seen["deletedDone"]
    assert done["done"] == ["8"] and done["doneCount"] == "1" and done["hint"] == "0 open, 1 done"
    assert done["posts"][-1] == "/api/admin/feedback/5/delete"


def test_a_refused_delete_leaves_the_row_and_says_so(console_seen):
    got = console_seen["refusedByServer"]
    assert got["done"] == ["8"] and got["toast"] == "That did not work, HTTP 404"


def test_no_word_in_the_list_is_a_link_and_nothing_spills_at_1300(console_seen):
    assert console_seen["arrived"]["links"] == 0
    assert console_seen["spills"] == []
