"""A server's display name, as the screens show it: in bold on the Fleet row
with the hostname under it, in the header of the server's page, and in its
own row of the server's settings.

Decided by the owner on 2026-10-02 (`docs/RECORD.md` 4.238). It is a label and
never the identifier, so most of what is tested here is what must not move: the
link, the ids and every control keep the name the server is found by.

The storage, the rule and the route are the control plane's
(controlplane/app/displayname.py, controlplane/tests/test_displayname.py). The
page script is driven in a real browser against a stand-in server put in the
page's own head, as test_tags_screen.py does and for the same reason.

    Run from site/: python3 -m pytest app/test_display_name_screen.py
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
import test_tags_screen as tts  # noqa: E402
from test_rename_button import find_chrome, run_chrome, QuietHandler  # noqa: E402

NOW = trl.NOW

# The control plane's table (controlplane/app/displayname.py), copied rather
# than imported so this file stands alone.
DISPLAY_SCHEMA = """
CREATE TABLE host_display_names (
    host_id      INTEGER PRIMARY KEY REFERENCES hosts(id),
    display_name TEXT NOT NULL
);
"""


def make_db(tmp_path, with_table=True):
    path = tts.make_db(tmp_path)
    if with_table:
        con = sqlite3.connect(path)
        con.executescript(DISPLAY_SCHEMA)
        con.commit()
        con.close()
    return path


def call(db, name, display):
    con = sqlite3.connect(db)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    con.execute("INSERT INTO host_display_names (host_id, display_name) VALUES (?, ?)",
                (host_id, display))
    con.commit()
    con.close()


def bold(row):
    return re.search(r'<div class="hn">(.*?)</div>', row).group(1)


def under(row):
    found = re.search(r'<small class="fhost">(.*?)</small>', row)
    return found.group(1) if found else ""


def header_name(html, name):
    head = trl.host_section(html, name)
    return re.search(r'<span class="hname">(.*?)</span>', head).group(1)


def display_field(html, name):
    view = html[html.index(f'id="host-{name}"'):]
    start = view.index('class="in js-display"')
    return view[view.rindex("<input", 0, start):view.index(">", start) + 1]


# ---------------------------------------------------- the fleet row, as built

def row(**kw):
    return build.fleet_row_html(build.FleetRow("ok", "watched", "web-07", **kw))


def test_a_row_without_a_display_name_says_what_it_said_before():
    assert bold(row()) == "web-07" and under(row()) == ""
    assert under(row(hostname="web-07")) == ""
    other = row(hostname="ubuntu-web")
    assert bold(other) == "web-07" and under(other) == "ubuntu-web"


def test_the_display_name_is_bold_and_the_hostname_sits_under_it():
    html = row(display="Webshop", hostname="web-07", tags=("production",))
    assert ('<div class="fsrv"><div class="hn">Webshop</div>'
            '<span class="ftag">production</span>'
            '<small class="fhost">web-07</small></div>') in html


def test_with_no_hostname_the_name_it_is_found_by_sits_under_it():
    """An address-only server reports no hostname. The name is then the one
    thing that says which server this is in a URL or a command."""
    html = row(display="Office router")
    assert bold(html) == "Office router" and under(html) == "web-07"


def test_a_display_name_equal_to_what_would_sit_under_it_is_said_once():
    html = row(display="web-07", hostname="web-07")
    assert bold(html) == "web-07" and under(html) == ""


def test_the_link_and_the_row_keep_the_name_the_server_is_found_by():
    html = row(display="Webshop", hostname="web-07")
    assert html.startswith('<a class="row" href="/host/web-07" data-host="web-07" ')
    assert "/host/Webshop" not in html and 'data-host="Webshop"' not in html


def test_every_row_says_what_goes_under_its_name_for_the_page_script():
    assert 'data-under="web-07"' in row()
    assert 'data-under="ubuntu-web"' in row(hostname="ubuntu-web")
    assert 'data-under="ubuntu-web"' in row(hostname="ubuntu-web", display="Webshop")


@pytest.mark.parametrize("hostile", [
    "<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "a & b", "x' y",
])
def test_a_display_name_is_drawn_as_text_whatever_the_store_let_through(hostile):
    html = row(display=hostile)
    assert "<script>" not in html and "<img" not in html
    assert html_mod.unescape(bold(html)) == hostile


def test_a_very_long_display_name_does_not_widen_the_row():
    """The store stops at 40 characters. The cell holds anything, by wrapping."""
    rule = re.search(r"\.fsrv \.hn\{[^}]*\}", build.CSS).group(0)
    assert "overflow-wrap:anywhere" in rule
    assert "W" * 200 in row(display="W" * 200)


def test_rows_sort_by_the_name_they_show():
    rows = [build.FleetRow("ok", "watched", "aaa", display="Zebra"),
            build.FleetRow("ok", "watched", "zzz", display="apple"),
            build.FleetRow("ok", "watched", "mmm")]
    assert [r.name for r in build.sort_fleet_rows(rows)] == ["zzz", "mmm", "aaa"]


def test_two_rows_with_the_same_display_name_keep_a_stable_order():
    one = build.FleetRow("ok", "watched", "web-01", display="Webshop")
    two = build.FleetRow("ok", "watched", "web-02", display="Webshop")
    assert [r.name for r in build.sort_fleet_rows([two, one])] == ["web-01", "web-02"]
    assert [r.name for r in build.sort_fleet_rows([one, two])] == ["web-01", "web-02"]


def test_a_display_name_moves_no_row_out_of_its_band():
    bad = build.FleetRow("fail", "conflict", "zzz", display="zzz last by name")
    fine = build.FleetRow("ok", "watched", "aaa", display="Aardvark")
    assert [r.name for r in build.sort_fleet_rows([fine, bad])] == ["zzz", "aaa"]


# ------------------------------------------------------ the settings row, as built

def test_the_rows_are_labelled_name_and_id_in_that_order():
    """Decided on 2026-10-02 (`docs/RECORD.md` 4.250): the row labelled Name
    is the free label and the row labelled ID is what the server is found by."""
    html = build.server_panel("box", "box", False, tags=("web",), display="Webshop")
    assert (html.index("<b>Name</b>") < html.index('class="in js-display"')
            < html.index("<b>ID</b>") < html.index('class="idv"')
            < html.index("<b>Tags</b>"))
    assert "Display name" not in html


def test_the_remove_and_delete_windows_ask_for_the_id():
    """The field a person types into to confirm takes the name the server is
    found by, never its display name."""
    html = build.build_sample()
    for window in ("rm", "del"):
        assert (f'<input class="in mono" id="{window}-input" autocomplete="off"'
                ' spellcheck="false" aria-label="Server ID">') in html


def test_the_display_row_is_a_label_a_field_and_no_sentence():
    html = build.display_row("box", "Webshop")
    assert 'class="in js-display" value="Webshop"' in html
    assert "<b>Name</b>" in html and 'aria-label="Server name"' in html
    assert 'maxlength="40"' in html
    assert 'class="btn pri js-display-save" data-host="box" hidden' in html
    assert "<small" not in html and 'placeholder=""' in html


def test_the_display_field_is_not_mono_and_the_name_field_is():
    """Mono is for what a machine reads: the name in a URL and a command."""
    assert 'class="in js-display"' in build.display_row("box", "")
    assert '<span class="idv" id="id-box">box</span>' in build.name_row("box", "box")
    assert '.idv{flex:1;min-width:0;padding:0 13px;font-family:"IBM Plex Mono",monospace' in build.CSS


def test_the_display_field_escapes_what_it_holds():
    assert "<script>" not in build.display_row("box", '"><script>')


def test_the_sample_shell_saves_nothing():
    html = build.display_row("host", "Webshop", live=False)
    assert "js-display-save" not in html
    assert 'data-msg="The name would be saved here"' in html


# ------------------------------------------------------------ the live render

def test_a_database_from_before_display_names_renders_the_names(tmp_path):
    db = make_db(tmp_path, with_table=False)
    trl.reporting(db, "web-07", tts.named("web-07"))
    html = rl.render(db, now=NOW)
    assert bold(tts.fleet_row(html, "web-07")) == "web-07"
    assert header_name(html, "web-07") == "web-07"
    assert 'value=""' in display_field(html, "web-07")


def test_the_row_the_header_and_the_field_say_the_display_name(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "web-07", tts.named("web-07"))
    call(db, "web-07", "Webshop")
    html = rl.render(db, now=NOW)
    fleet = tts.fleet_row(html, "web-07")
    assert bold(fleet) == "Webshop" and under(fleet) == "web-07"
    assert header_name(html, "web-07") == "Webshop"
    assert 'value="Webshop"' in display_field(html, "web-07")


def test_everything_that_finds_the_server_keeps_its_name(tmp_path):
    """The page id, the tab ids, the name field and every control that posts
    carry the name, with a display name set."""
    db = make_db(tmp_path)
    trl.reporting(db, "web-07", tts.named("web-07"))
    call(db, "web-07", "Webshop")
    html = rl.render(db, now=NOW)
    assert 'id="host-web-07"' in html and 'id="host-Webshop"' not in html
    section = trl.host_section(html, "web-07")
    assert '<span class="idv" id="id-web-07">web-07</span>' in section
    hosts = set(re.findall(r'data-host="([^"]*)"', section))
    assert hosts == {"web-07"}, hosts
    assert 'data-name="web-07"' in section, "the remove window must ask for the name"
    assert 'href="/host/web-07"' in html and "/host/Webshop" not in html


def test_two_servers_with_one_display_name_are_two_rows_and_two_pages(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "web-01", tts.named("web-01"))
    trl.reporting(db, "web-02", tts.named("web-02"))
    call(db, "web-01", "Webshop")
    call(db, "web-02", "Webshop")
    html = rl.render(db, now=NOW)
    for name in ("web-01", "web-02"):
        fleet = tts.fleet_row(html, name)
        assert bold(fleet) == "Webshop" and under(fleet) == name
        assert header_name(html, name) == "Webshop"
    assert html.count('<div class="hn">Webshop</div>') == 2
    # the same order every time: by the name behind the label
    assert html.index('href="/host/web-01"') < html.index('href="/host/web-02"')


def test_another_workspaces_display_name_is_not_on_this_page(tmp_path):
    db = make_db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'w2', 'x')")
    con.commit()
    con.close()
    trl.reporting(db, "mine", tts.named("mine"))
    trl.add_host(db, "theirs", [(NOW, tts.named("theirs"))], last_report_at=NOW.isoformat(),
                 workspace_id=2)
    call(db, "theirs", "Secret project")
    assert "Secret project" not in rl.render(db, now=NOW, workspace_id=1)
    assert "Secret project" in rl.render(db, now=NOW, workspace_id=2)


def test_a_removed_servers_display_name_is_not_on_the_page(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", tts.named("box"))
    trl.add_host(db, "gone", [(NOW, tts.named("gone"))], last_report_at=NOW.isoformat(),
                 revoked=True)
    call(db, "gone", "Old shop")
    assert "Old shop" not in rl.render(db, now=NOW)


def test_a_stored_display_name_that_holds_markup_is_drawn_as_text(tmp_path):
    """The store refuses such a name. The page does not rely on that."""
    db = make_db(tmp_path)
    trl.reporting(db, "box", tts.named("box"))
    call(db, "box", "<img src=x onerror=alert(1)>")
    html = rl.render(db, now=NOW)
    assert "<img src=x" not in html
    assert "&lt;img src=x onerror=alert(1)&gt;" in tts.fleet_row(html, "box")
    assert "&lt;img src=x onerror=alert(1)&gt;" in header_name(html, "box")


def test_an_address_only_server_shows_its_name_under_its_display_name(tmp_path):
    db = make_db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO hosts (name, token_hash, kind, created_at)"
                " VALUES ('edge-1', NULL, 'address', ?)", (NOW.isoformat(),))
    con.commit()
    con.close()
    call(db, "edge-1", "Office router")
    html = rl.render(db, now=NOW)
    fleet = tts.fleet_row(html, "edge-1")
    assert bold(fleet) == "Office router" and under(fleet) == "edge-1"
    assert header_name(html, "edge-1") == "Office router"
    assert 'value="Office router"' in display_field(html, "edge-1")


def test_a_server_whose_document_will_not_read_keeps_its_display_name(tmp_path):
    db = make_db(tmp_path)
    trl.add_raw_report(db, "broken", "not a document")
    call(db, "broken", "Webshop")
    html = rl.render(db, now=NOW)
    fleet = tts.fleet_row(html, "broken")
    assert "not readable" in fleet and bold(fleet) == "Webshop"


def test_load_hands_the_display_names_over_after_the_tags(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", tts.named("box"))
    call(db, "box", "Webshop")
    assert rl.load(db, now=NOW)[-3] == {"box": "Webshop"}


# ------------------------------------------------------------------ the browser

STUB = """<script>
window.__posts=[];window.__gets=0;
// What the stand-in server answers the next POST with. The harness sets it.
window.__next={status:200,body:{display_name:''}};
// Set by the harness to leave the page asked for next unanswered, as from a
// slow server, so what a click itself painted can be read.
window.__hold=false;
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push(String(url)+' '+(opts.body||''));
    var n=window.__next;
    return Promise.resolve({ok:n.status<300,status:n.status,
      json:function(){return Promise.resolve(n.body)}});
  }
  if(window.__hold){return new Promise(function(){})}
  window.__gets++;
  var page=%(page)s.replace('class="pgstamp">','class="pgstamp">refresh '+window.__gets+' ');
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>display name drive</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var field=function(host){return d.querySelector('#host-'+host+' .js-display')};
    var save=function(host){return d.querySelector('#host-'+host+' .js-display-save')};
    var type=function(host,text){var i=field(host);i.value=text;
      i.dispatchEvent(new w.Event('input',{bubbles:true}))};
    var key=function(host,k){field(host).dispatchEvent(
      new w.KeyboardEvent('keydown',{key:k,bubbles:true}))};
    var rowOf=function(host){return d.querySelector('#fleet .row[data-host="'+host+'"]')};
    var rowSays=function(host){var r=rowOf(host);var h=r.querySelector('.fhost');
      return {bold:r.querySelector('.hn').textContent,under:h?h.textContent:'',
        tags:Array.prototype.map.call(r.querySelectorAll('.ftag'),function(t){return t.textContent}),
        href:r.getAttribute('href'),
        order:Array.prototype.map.call(r.querySelector('.fsrv').children,
          function(e){return e.className}).join(' ')}};
    var header=function(host){return d.querySelector('#host-'+host+' .hh h1 .hname').textContent};
    var shown=function(){return Array.prototype.filter.call(
      d.querySelectorAll('#fleet .row'),function(r){return r.style.display!=='none'})
      .map(function(r){return r.dataset.host})};
    var search=async function(q){var s=d.querySelector('#fleet .srch');s.value=q;
      s.dispatchEvent(new w.Event('input'));await tick();return shown()};
    var toast=function(){return d.getElementById('toast').textContent};
    var posts=function(part){return w.__posts.filter(function(p){return p.indexOf(part)>=0})};
    var seen={errs:[]};
    w.addEventListener('error',function(e){seen.errs.push(String(e.message))});

    // 1. Save is not there until the field differs, and Escape puts it back.
    seen.start={row:rowSays('web-07'),header:header('web-07'),saveHidden:save('web-07').hidden};
    type('web-07','Webshop');
    seen.saveShownWhenTyped=!save('web-07').hidden;
    key('web-07','Escape');
    seen.afterEscape={value:field('web-07').value,saveHidden:save('web-07').hidden};

    // 2. Enter saves. The header and the row say the stored spelling at once,
    // the hostname goes under it, and nothing that finds the server moves.
    w.__next={status:200,body:{display_name:'CI runner'}};
    type('web-07','  CI   runner ');
    key('web-07','Enter'); await tick();
    seen.firstPost=posts('/display-name ')[0];
    seen.afterSave={value:field('web-07').value,saveHidden:save('web-07').hidden,
      row:rowSays('web-07'),header:header('web-07'),toast:toast(),
      viewId:!!d.getElementById('host-web-07'),path:w.location.pathname,
      nameField:d.getElementById('id-web-07').textContent};

    // 3. The search finds it by the display name, by the hostname under it,
    // and still by the name it is found by.
    seen.searchDisplay=await search('ci run');
    seen.searchName=await search('web-07');
    seen.searchOther=await search('plain');
    seen.searchCleared=await search('');

    // 4. A refusal is the server's words and nothing on the page moves.
    w.__next={status:400,body:{detail:'a display name: the rule, in words'}};
    type('web-07','<b>bold</b>');
    key('web-07','Enter'); await tick();
    seen.afterRefusal={value:field('web-07').value,saveHidden:save('web-07').hidden,
      row:rowSays('web-07'),header:header('web-07'),toast:toast()};
    seen.noMarkup=d.querySelectorAll('#fleet .row b, .hh h1 .hname b').length;
    key('web-07','Escape');

    // 5. Naming a plain row draws the line under it. Clearing the name puts
    // the server's name back in bold, and the line goes when it would say
    // the same thing twice.
    w.__next={status:200,body:{display_name:'Mail'}};
    type('plain','Mail'); key('plain','Enter'); await tick();
    seen.plainNamed={row:rowSays('plain'),header:header('plain')};
    w.__next={status:200,body:{display_name:''}};
    type('plain',''); key('plain','Enter'); await tick();
    seen.plainCleared={row:rowSays('plain'),header:header('plain'),
      value:field('plain').value,saveHidden:save('plain').hidden};
    var all=posts('/display-name ');
    seen.clearPost=all[all.length-1];

    // 6. After the page has refreshed itself twice, Enter still saves once.
    await tick(61000); await tick(200);
    await tick(61000); await tick(200);
    seen.gets=w.__gets;
    var before=posts('/display-name ').length;
    w.__next={status:200,body:{display_name:'Once'}};
    type('plain','Once'); key('plain','Enter'); await tick(300);
    seen.postsAfterRefreshes=posts('/display-name ').length-before;

    out.textContent=JSON.stringify(seen);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def a_page(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "web-07", tts.named("web-07"))
    trl.reporting(db, "plain", tts.named("plain"))
    tts.tag(db, "web-07", "production")
    return rl.render(db, now=NOW)


def drive(tmp_path, page):
    site = tmp_path / "www"
    site.mkdir()
    embedded = json.dumps(page).replace("</", "<\\/")
    assert page.count("<head>") == 1
    (site / "live.html").write_text(
        page.replace("<head>", "<head>" + STUB % {"page": embedded}, 1), encoding="utf-8")
    (site / "harness.html").write_text(HARNESS, encoding="utf-8")
    handler = functools.partial(QuietHandler, directory=str(site))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        port = server.server_address[1]
        dom = run_chrome(
            [find_chrome(), "--headless=new", "--disable-gpu", "--no-sandbox",
             "--no-first-run", f"--user-data-dir={tmp_path / 'chrome-profile'}",
             "--virtual-time-budget=140000", "--dump-dom",
             f"http://127.0.0.1:{port}/harness.html"])
    finally:
        server.shutdown()
    got = re.search(r'<pre id="out">(.*?)</pre>', dom, re.S)
    assert got, f"the harness wrote nothing, the dumped page was:\n{dom[:2000]}"
    result = json.loads(html_mod.unescape(got.group(1)))
    assert "error" not in result, result
    return result


@pytest.fixture(scope="module")
def drove(tmp_path_factory):
    """One Chrome run for every assertion below, each in its own test so a
    failure names the behaviour that broke."""
    tmp_path = tmp_path_factory.mktemp("display")
    return drive(tmp_path, a_page(tmp_path))


def test_the_page_script_raised_nothing(drove):
    assert drove["errs"] == []


def test_a_server_without_a_display_name_starts_as_it_always_was(drove):
    assert drove["start"] == {
        "row": {"bold": "web-07", "under": "", "tags": ["production"],
                "href": "/host/web-07", "order": "hn ftag"},
        "header": "web-07", "saveHidden": True}


def test_save_appears_once_the_field_differs_and_escape_puts_it_back(drove):
    assert drove["saveShownWhenTyped"] is True
    assert drove["afterEscape"] == {"value": "", "saveHidden": True}


def test_enter_posts_what_was_typed_to_the_servers_name(drove):
    assert drove["firstPost"] == ('/api/admin/hosts/web-07/display-name '
                                  '{"display_name":"  CI   runner "}')


def test_a_save_shows_the_stored_name_at_once_and_moves_nothing_else(drove):
    assert drove["afterSave"] == {
        "value": "CI runner", "saveHidden": True,
        "row": {"bold": "CI runner", "under": "web-07", "tags": ["production"],
                "href": "/host/web-07", "order": "hn ftag fhost"},
        "header": "CI runner", "toast": "Saved",
        "viewId": True, "path": "/", "nameField": "web-07"}


def test_the_search_finds_a_server_by_any_of_its_names(drove):
    assert drove["searchDisplay"] == ["web-07"]
    assert drove["searchName"] == ["web-07"]
    assert drove["searchOther"] == ["plain"]
    assert sorted(drove["searchCleared"]) == ["plain", "web-07"]


def test_a_refusal_says_the_servers_words_and_changes_nothing(drove):
    assert drove["afterRefusal"] == {
        "value": "<b>bold</b>", "saveHidden": False,
        "row": {"bold": "CI runner", "under": "web-07", "tags": ["production"],
                "href": "/host/web-07", "order": "hn ftag fhost"},
        "header": "CI runner", "toast": "a display name: the rule, in words"}
    assert drove["noMarkup"] == 0


def test_naming_and_clearing_a_plain_row_draws_and_removes_the_line_under_it(drove):
    assert drove["plainNamed"] == {
        "row": {"bold": "Mail", "under": "plain", "tags": [], "href": "/host/plain",
                "order": "hn fhost"},
        "header": "Mail"}
    assert drove["plainCleared"] == {
        "row": {"bold": "plain", "under": "", "tags": [], "href": "/host/plain",
                "order": "hn"},
        "header": "plain", "value": "", "saveHidden": True}
    assert drove["clearPost"] == '/api/admin/hosts/plain/display-name {"display_name":""}'


def test_enter_saves_once_however_long_the_page_has_lived(drove):
    assert drove["gets"] >= 2, "the page did not refresh itself, so this proves nothing"
    assert drove["postsAfterRefreshes"] == 1
