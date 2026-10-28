"""Tags on a server, as the screens show them: beside the bold name on the
Fleet, the Tags row in a server's settings, and the search finding a tag.

The storage, the rule a tag follows and the route are the control plane's
(controlplane/app/tags.py, controlplane/tests/test_tags.py). This covers what
a person sees and types, and the page script is driven in a real browser,
because nothing else executes it. The page talks to a stand-in server put in
its own head, ahead of its script, so the page's fetch wrapper wraps it as it
wraps the real fetch (test_refresh_survivors_browser.py says why).

Its own file on purpose, the reason test_rename_button.py gives.

    Run from site/: python3 -m pytest app/test_tags_screen.py
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

# The control plane's table (controlplane/app/tags.py), copied rather than
# imported so this file stands alone, the posture test_mute_button.py takes.
TAGS_SCHEMA = """
CREATE TABLE host_tags (
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    tag     TEXT NOT NULL,
    PRIMARY KEY (host_id, tag)
);
"""


def make_db(tmp_path, with_tags_table=True):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    if with_tags_table:
        con.executescript(TAGS_SCHEMA)
    con.commit()
    con.close()
    return path


def tag(db, name, *words):
    con = sqlite3.connect(db)
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    for word in words:
        con.execute("INSERT INTO host_tags (host_id, tag) VALUES (?, ?)", (host_id, word))
    con.commit()
    con.close()


def named(hostname):
    """A document whose hostname is the given one, so a test picks whether
    the Fleet row has a hostname line."""
    doc = trl.document(listening=[trl.SSHD])
    doc["hostname"] = hostname
    return doc


def fleet_row(html, name):
    start = html.index(f'<a class="row" href="/host/{name}"')
    return html[start:html.index("</a>", start)]


def settings_tags(html, name):
    """The tags on one server's Tags row in order, read from its bubbles. The
    empty bubble in the row's <template> is the script's model, not a tag."""
    view = html[html.index(f'id="host-{name}"'):]
    box = view[view.index('<span class="tagc'):]
    box = box[:box.index("</span></span></div>")]
    box = re.sub(r"<template>.*?</template>", "", box, flags=re.S)
    return [html_mod.unescape(word) for word in re.findall(r'data-tag="([^"]*)"', box)]


# ---------------------------------------------------- the fleet row, as built

def row(**kw):
    return build.fleet_row_html(build.FleetRow("ok", "watched", "box", **kw))


def test_a_row_with_no_tags_is_the_markup_it_was_before_tags():
    assert '<div class="fsrv"><div class="hn">box</div></div>' in row()
    assert '<div class="fsrv"><div class="hn">box</div></div>' in row(hostname="box")
    assert ('<div class="fsrv"><div class="hn">box</div>'
            '<small class="fhost">web-07</small></div>') in row(hostname="web-07")


def test_tags_sit_beside_the_name_in_the_order_given_and_the_hostname_comes_last():
    """The owner, 2026-09-30, and again on the shots of 2026-10-02: the tags go
    beside the bold name, in a row (docs/RECORD.md 4.238). The hostname
    stays under the name."""
    html = row(hostname="web-07", tags=("production", "docker"))
    assert ('<div class="fsrv"><div class="hn">box</div>'
            '<span class="ftag">production</span><span class="ftag">docker</span>'
            '<small class="fhost">web-07</small></div>') in html


def test_tags_with_no_hostname_line_follow_the_name_and_nothing_follows_them():
    html = row(hostname="box", tags=("staging",))
    assert ('<div class="fsrv"><div class="hn">box</div>'
            '<span class="ftag">staging</span></div>') in html
    assert "fhost" not in html


def test_the_name_and_its_tags_share_a_line_and_the_hostname_takes_its_own():
    """What the stylesheet has to say for that markup to read as one line of
    name and tags over one line of hostname. The browser test below measures
    it, and this names the two rules it depends on."""
    cell = re.search(r"\.fsrv\{[^}]*\}", build.CSS).group(0)
    assert "display:flex" in cell and "flex-wrap:wrap" in cell
    assert ".fsrv .fhost{flex-basis:100%}" in build.CSS


def test_a_tag_is_drawn_dashed():
    """The owner's choice on the shots of 2026-10-02, over a solid hairline. A
    planned field is dashed too, and says PLANNED beside it: a tag says only
    its own word."""
    rule = re.search(r"\.ftag\{[^}]*\}", build.CSS).group(0)
    assert "border:1px dashed var(--line2)" in rule
    assert "planned" not in row(tags=("staging",)).lower()


def test_a_tag_is_escaped_whatever_the_store_let_through():
    html = row(tags=('<b onclick="x">',))
    assert "<b onclick" not in html
    assert "&lt;b onclick=&quot;x&quot;&gt;" in html


def test_the_tags_show_on_a_row_whose_cells_are_empty():
    """A paused or never reported server is still tagged."""
    html = build.fleet_row_html(build.FleetRow("off", "paused", "box", tags=("lab",)))
    assert '<span class="ftag">lab</span>' in html


def test_a_tag_takes_no_status_tone():
    """A tag is a word somebody typed, never a status (docs/DESIGN.md 3)."""
    rule = re.search(r"\.ftag\{[^}]*\}", build.CSS).group(0)
    for tone in ("--fail", "--warn", "--ok", "--acc"):
        assert tone not in rule, tone
    assert "var(--faint)" in rule


def test_tags_do_not_move_a_row_in_the_order():
    rows = [build.FleetRow("ok", "watched", "b", tags=("aaa",)),
            build.FleetRow("ok", "watched", "a")]
    assert [r.name for r in build.sort_fleet_rows(rows)] == ["a", "b"]


def test_tags_change_no_number_in_the_boxes():
    plain = build.FleetRow("warn", "unreviewed", "a", reach=(1, 4), chips=(("tcp/22", "warn"),))
    tagged = build.FleetRow("warn", "unreviewed", "a", reach=(1, 4), chips=(("tcp/22", "warn"),),
                            tags=("production",))
    assert build.fleet_totals([plain]) == build.fleet_totals([tagged])


# ------------------------------------------------------ the settings row, as built

def bubbles(html):
    """The words on a row's bubbles in order, the script's model left out."""
    html = re.sub(r"<template>.*?</template>", "", html, flags=re.S)
    return re.findall(r'<button type="button" class="tagb [^>]*><span>([^<]*)</span>', html)


def rule(selector):
    """One rule of the stylesheet, found by its whole selector at the start
    of a line, so a rule inside an @media block is not taken for it."""
    found = re.search(r"(?m)^" + re.escape(selector) + r"\{[^}]*\}", build.CSS)
    assert found, selector
    return found.group(0)


def test_the_tags_row_is_one_bubble_for_each_tag_in_the_order_given():
    """Decided 2026-10-03 (docs/RECORD.md 4.285): the tags show as bubbles
    in a server's settings."""
    html = build.tags_row("box", ("web", "production"))
    assert bubbles(html) == ["web", "production"]
    assert html.index("<span>production</span>") < html.index('class="in mono tagin js-tag-add"')


def test_a_bubble_is_a_button_that_says_what_a_click_does():
    """A click takes the tag off, so the bubble is a button, which the
    keyboard reaches and presses as it does any other. The word under the
    hand and the label a screen reader says name the click, so it is never
    the line and the tone alone (docs/DESIGN.md 3)."""
    html = build.tag_bubble("box", "web")
    assert html.startswith('<button type="button" class="tagb js-tag-del" data-host="box" '
                           'data-tag="web" title="Remove" aria-label="Remove tag web">')
    assert "<span>web</span><svg" in html
    assert html.endswith("</svg></button>")


def test_the_field_adds_one_tag_and_holds_none():
    """A tag is added one at a time (docs/RECORD.md 4.285). The field is
    empty whatever the server carries, and a tag is at most 32 characters
    (controlplane/app/tags.py)."""
    html = build.tags_row("box", ("web",))
    field = html[html.index('<input class="in mono tagin js-tag-add"'):]
    field = field[:field.index(">") + 1]
    assert 'value=""' in field
    assert 'placeholder="Add tag"' in field
    assert 'aria-label="Add a tag"' in field
    assert 'maxlength="32"' in field


def test_the_tags_row_has_no_save_button_and_no_sentence():
    """Every add and every delete is saved at once, so nothing waits for a
    Save. And the rule for customer screens: a label, no line under it."""
    html = build.tags_row("box", ("web",))
    assert "Save" not in html
    assert "<small" not in html
    assert "<b>Tags</b>" in html


def test_the_field_is_there_below_the_limit_and_gone_at_it():
    """Three tags at most. The control plane refuses a fourth whatever the
    page does (controlplane/tests/test_tags.py). The page takes the field
    away."""
    assert 'class="tagc"' in build.tags_row("box", ())
    assert 'class="tagc"' in build.tags_row("box", ("a", "b"))
    assert 'class="tagc full"' in build.tags_row("box", ("a", "b", "c"))
    assert ".tagc.full .tagin{display:none}" in build.CSS


def test_a_server_tagged_with_more_before_the_limit_shows_them_all_and_no_field():
    """It keeps what it carries and may drop some (docs/RECORD.md 4.274). Each
    is a bubble like any other, so each can be taken off."""
    html = build.tags_row("box", ("a", "b", "c", "d", "e"))
    assert bubbles(html) == ["a", "b", "c", "d", "e"]
    assert html.count("js-tag-del") == 6, "five bubbles and the script's model"
    assert 'class="tagc full"' in html


def test_the_limit_on_the_page_is_the_control_planes():
    """Two packages, so the number is written twice. This holds them equal."""
    source = (pathlib.Path(__file__).resolve().parents[2]
              / "controlplane" / "app" / "tags.py").read_text(encoding="utf-8")
    limit = int(re.search(r"^MAX_TAGS_PER_HOST = (\d+)$", source, re.M).group(1))
    assert build.MAX_TAGS == limit
    assert f'data-max="{limit}"' in build.tags_row("box", ())


def test_the_script_copies_its_bubble_from_the_row():
    """One <template> holding one empty bubble, so a bubble the page script
    draws is the bubble the builder draws."""
    html = build.tags_row("box", ("web",))
    assert html.count("<template>") == 1
    model = html[html.index("<template>") + len("<template>"):html.index("</template>")]
    assert model == build.tag_bubble("box", "")


def test_a_bubble_escapes_its_word():
    html = build.tags_row("box", ('"><script>',))
    assert "<script>" not in html
    assert "&quot;&gt;&lt;script&gt;" in html


def test_the_sample_shell_saves_nothing():
    html = build.tags_row("host", ("production",), live=False)
    assert "js-tag-del" not in html and "js-tag-add" not in html
    assert "<template>" not in html
    assert 'data-msg="The tag would be removed here"' in html
    assert bubbles(html) == ["production"]


def test_a_bubble_at_rest_takes_no_status_tone():
    """A tag is a word somebody typed, never a status (docs/DESIGN.md 3)."""
    for tone in ("--fail", "--warn", "--ok", "--acc"):
        assert tone not in rule(".tagb"), tone


def test_the_hand_and_the_keyboard_show_the_same_thing_on_a_bubble():
    """Decided 2026-10-03 (docs/RECORD.md 4.298): under the pointer the word
    is crossed, a click removes the tag, and the bubble pops a little. Hover
    and keyboard focus share every rule, so a bubble
    reached with Tab says it exactly as one under the pointer does: the line
    through the word, the fail tone, the bubble a little larger."""
    both = rule(".tagb:hover,.tagb:focus-visible")
    assert "var(--fail)" in both
    assert "transform:scale(1.06)" in both
    assert "transform:scaleX(1)" in rule(".tagb:hover span::after,.tagb:focus-visible span::after")
    # The ring around a bubble under the keyboard is the theme's own, the one
    # every control gets. Its rule squares the corners, and a bubble keeps its.
    assert ":focus-visible{outline:2px solid var(--acc)" in build.theme.BASE
    assert "border-radius:99px" in rule(".tagb:focus-visible")


def test_the_line_through_the_word_is_drawn_from_the_left():
    """The crossed word is a line laid over the word, at no length until the
    hand is on the bubble, growing from its left end. It is the bubble's own
    ink, so it is there whatever tone the bubble has."""
    line = rule(".tagb span::after")
    assert "transform:scaleX(0)" in line
    assert "transform-origin:left center" in line
    assert "background:currentColor" in line
    assert "position:absolute" in line


def test_the_pop_and_the_line_move_nothing_around_the_bubble():
    """The bubble grows by a transform and the line is laid over the word,
    so a bubble takes the room under the hand that it takes at rest, its
    neighbours stay where they are, and it cannot slide from under the
    pointer that is on it."""
    for selector in (".tagb:hover,.tagb:focus-visible",
                     ".tagb:hover span::after,.tagb:focus-visible span::after"):
        for moves_the_box in ("padding", "width:", "margin", "font", "height"):
            assert moves_the_box not in rule(selector), (selector, moves_the_box)


def test_nothing_bounces():
    """docs/DESIGN.md 5. The pop is one step to a slightly larger bubble on
    the one decelerating curve: no keyframes, so no overshoot to settle from."""
    for selector in (".tagb", ".tagb span::after", ".tagb:hover,.tagb:focus-visible"):
        assert "animation" not in rule(selector)
    assert "@keyframes tag" not in build.CSS


def test_a_screen_with_no_hover_shows_a_cross_on_every_bubble():
    """With no pointer to rest on a bubble there is no crossed word to see
    before the tap, so there the bubble carries a cross all the time. Under
    a pointer the cross is not drawn."""
    assert ".tagb svg{display:none}" in build.CSS
    block = re.search(r"@media \(hover:none\)\{(.*?)\}\}", build.CSS, re.S).group(1)
    assert ".tagb svg{display:block" in block


def test_the_bubbles_motion_is_the_design_files_own_and_still_under_reduced_motion():
    """docs/DESIGN.md 5: `quick` for hover and focus feedback on the one
    curve, nothing else, and the blanket rule that makes every transition
    instant for somebody who asked for reduced motion."""
    for selector in (".tagb", ".tagb span::after"):
        steps = re.search(r"transition:([^;}]*)", rule(selector)).group(1)
        for step in steps.split(","):
            assert step.strip().endswith("var(--quick) var(--ease)"), (selector, step)
    assert re.search(r"@media\(prefers-reduced-motion:reduce\)\{\*\{[^}]*"
                     r"transition-duration:\.01ms!important", build.theme.BASE)


def test_the_server_list_is_name_id_tags_environment_timezone_paused():
    html = build.server_panel("box", "box", False, tags=("web",))
    order = [html.index(f"<b>{word}</b>")
             for word in ("Name", "ID", "Tags", "Environment", "Timezone", "Paused")]
    assert order == sorted(order)
    assert html.index("<b>ID</b>") < html.index('class="idv"') < html.index("<b>Tags</b>")


def test_environment_stays_planned_and_the_planned_labels_block_is_gone():
    """Tags is what the planned Labels row became. Environment is still not
    built and still shown, with the tag and nothing else (docs/RECORD.md
    4.140: a planned thing is never deleted)."""
    html = build.server_panel("box", "box", False)
    assert "<b>Labels</b>" not in html
    assert "<h3>Labels" not in html
    env = html[html.index("<b>Environment</b>"):html.index("<b>Timezone</b>")]
    assert "disabled" in env
    assert build.PLANNED_TAG in env
    assert "<small" not in env


# ------------------------------------------------------------ the live render

def test_a_database_from_before_tags_renders_with_none(tmp_path):
    db = make_db(tmp_path, with_tags_table=False)
    trl.reporting(db, "box", named("box"))
    html = rl.render(db, now=NOW)
    assert "ftag" not in fleet_row(html, "box")
    assert settings_tags(html, "box") == []


def test_a_server_with_no_tags_has_no_bubble(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("box"))
    html = rl.render(db, now=NOW)
    assert "ftag" not in fleet_row(html, "box") and "fhost" not in fleet_row(html, "box")
    assert settings_tags(html, "box") == []


def test_the_row_and_the_bubbles_carry_the_tags_in_the_order_saved(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("web-07"))
    tag(db, "box", "web", "production")
    html = rl.render(db, now=NOW)
    assert ('<div class="hn">box</div>'
            '<span class="ftag">web</span><span class="ftag">production</span>'
            '<small class="fhost">web-07</small>') in fleet_row(html, "box")
    assert settings_tags(html, "box") == ["web", "production"]


def test_each_server_shows_its_own_tags(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "one", named("one"))
    trl.reporting(db, "two", named("two"))
    tag(db, "one", "production")
    tag(db, "two", "staging")
    html = rl.render(db, now=NOW)
    assert "production" in fleet_row(html, "one") and "staging" not in fleet_row(html, "one")
    assert "staging" in fleet_row(html, "two") and "production" not in fleet_row(html, "two")
    assert settings_tags(html, "one") == ["production"]
    assert settings_tags(html, "two") == ["staging"]


def test_another_workspaces_tags_are_not_on_this_page(tmp_path):
    db = make_db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'w2', 'x')")
    con.commit()
    con.close()
    trl.reporting(db, "mine", named("mine"))
    trl.add_host(db, "theirs", [(NOW, named("theirs"))], last_report_at=NOW.isoformat(),
                 workspace_id=2)
    tag(db, "theirs", "secret-project")
    assert "secret-project" not in rl.render(db, now=NOW, workspace_id=1)
    assert "secret-project" in rl.render(db, now=NOW, workspace_id=2)


def test_a_removed_servers_tags_are_not_on_the_page(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("box"))
    trl.add_host(db, "gone", [(NOW, named("gone"))], last_report_at=NOW.isoformat(),
                 revoked=True)
    tag(db, "gone", "old-tag")
    assert "old-tag" not in rl.render(db, now=NOW)


def test_a_stored_tag_that_holds_markup_is_drawn_as_text(tmp_path):
    """The store refuses such a tag. The page does not rely on that."""
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("box"))
    tag(db, "box", "<img src=x>")
    html = rl.render(db, now=NOW)
    assert "<img src=x>" not in html
    assert "&lt;img src=x&gt;" in fleet_row(html, "box")
    assert settings_tags(html, "box") == ["<img src=x>"]


def test_an_address_only_server_carries_its_tags_too(tmp_path):
    db = make_db(tmp_path)
    con = sqlite3.connect(db)
    con.execute("INSERT INTO hosts (name, token_hash, kind, created_at)"
                " VALUES ('outside-only', NULL, 'address', ?)", (NOW.isoformat(),))
    con.commit()
    con.close()
    tag(db, "outside-only", "customer")
    html = rl.render(db, now=NOW)
    assert '<span class="ftag">customer</span>' in fleet_row(html, "outside-only")
    assert settings_tags(html, "outside-only") == ["customer"]


def test_a_server_whose_document_will_not_read_keeps_its_tags(tmp_path):
    db = make_db(tmp_path)
    trl.add_raw_report(db, "broken", "not a document")
    tag(db, "broken", "production")
    html = rl.render(db, now=NOW)
    assert "not readable" in fleet_row(html, "broken")
    assert '<span class="ftag">production</span>' in fleet_row(html, "broken")


def test_a_server_tagged_before_the_limit_shows_every_tag_on_the_live_page(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("box"))
    tag(db, "box", "a", "b", "c", "d", "e")
    html = rl.render(db, now=NOW)
    assert settings_tags(html, "box") == ["a", "b", "c", "d", "e"]
    assert fleet_row(html, "box").count('class="ftag"') == 5
    view = html[html.index('id="host-box"'):]
    assert '<span class="tagc full" data-host="box"' in view


def test_load_hands_the_tags_over_at_the_end(tmp_path):
    """Appended, so every caller that unpacks the front of the tuple is as it
    was. The display names, the moved ports and the dismissed marks follow
    them (test_display_name_screen.py, test_first_look_order.py,
    test_rarely_dismiss.py)."""
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("box"))
    tag(db, "box", "web")
    assert rl.load(db, now=NOW)[-4] == {"box": ["web"]}


# ------------------------------------------------------------------ the browser

STUB = """<script>
window.__posts=[];window.__gets=0;
// What the stand-in server answers the next POST with. The harness sets it.
window.__next={status:200,body:{tags:[]}};
// What the stand-in server holds for each server, kept from its own answers
// and settable by the harness, so the page it serves on a refresh carries
// the tags the way the real one does: as bubbles in that server's row.
window.__have={};
window.__page=function(){
  var doc=new DOMParser().parseFromString(%(page)s,'text/html');
  Object.keys(window.__have).forEach(function(host){
    var tags=window.__have[host];
    var box=doc.querySelector('.tagc[data-host="'+host+'"]');
    box.querySelectorAll('.js-tag-del').forEach(function(b){b.remove()});
    var model=box.querySelector('template').content.querySelector('.tagb');
    var field=box.querySelector('.js-tag-add');
    tags.forEach(function(t){var b=model.cloneNode(true);b.dataset.tag=t;
      b.setAttribute('aria-label','Remove tag '+t);
      b.querySelector('span').textContent=t;box.insertBefore(b,field)});
    box.classList.toggle('full',tags.length>=3);
  });
  var stamp=doc.querySelector('.pgstamp');
  stamp.textContent='refresh '+window.__gets+' '+stamp.textContent;
  return '<!doctype html>'+doc.documentElement.outerHTML};
window.fetch=function(url,opts){
  if(opts&&opts.method==='POST'){
    window.__posts.push(String(url)+' '+(opts.body||''));
    var n=window.__next;
    var host=String(url).match(/hosts\\/([^\\/]+)\\/tags$/);
    if(host&&n.status<300)window.__have[host[1]]=n.body.tags;
    return Promise.resolve({ok:n.status<300,status:n.status,
      json:function(){return Promise.resolve(n.body)}});
  }
  window.__gets++;
  var page=window.__page();
  return Promise.resolve({ok:true,redirected:false,status:200,
    text:function(){return Promise.resolve(page)}})};
</script>"""

HARNESS = """<!doctype html>
<meta charset="utf-8">
<title>tags drive</title>
<pre id="out"></pre>
<iframe id="f" width="1300" height="800"></iframe>
<script>
var out=document.getElementById('out');
var f=document.getElementById('f');
f.onload=function(){
  var run=async function(){
    var w=f.contentWindow, d=f.contentDocument;
    var tick=function(ms){return new Promise(function(r){setTimeout(r,ms||50)})};
    var box=function(host){return d.querySelector('#host-'+host+' .tagc')};
    var field=function(host){return box(host).querySelector('.js-tag-add')};
    var fieldShown=function(host){
      return w.getComputedStyle(field(host)).display!=='none'};
    var bubbles=function(host){return Array.prototype.map.call(
      box(host).querySelectorAll('.js-tag-del'),function(b){return b.dataset.tag})};
    var bubble=function(host,tag){return Array.prototype.filter.call(
      box(host).querySelectorAll('.js-tag-del'),
      function(b){return b.dataset.tag===tag})[0]};
    var type=function(host,text){var i=field(host);i.focus();i.value=text;
      i.dispatchEvent(new w.Event('input',{bubbles:true}))};
    var key=function(host,k){field(host).dispatchEvent(
      new w.KeyboardEvent('keydown',{key:k,bubbles:true,cancelable:true}))};
    // A click with a pointer behind it. Enter or Space on a focused bubble
    // is a click whose detail is 0, which is what el.click() makes.
    var point=function(el){el.dispatchEvent(
      new w.MouseEvent('click',{bubbles:true,cancelable:true,detail:1}))};
    var focused=function(){var a=d.activeElement;
      if(!a||a===d.body)return 'nothing';
      if(a.classList.contains('js-tag-add'))
        return 'the field of '+a.closest('.tagc').dataset.host;
      if(a.classList.contains('js-tag-del'))return 'the bubble '+a.dataset.tag;
      return a.tagName};
    var rowTags=function(host){return Array.prototype.map.call(
      d.querySelectorAll('#fleet .row[data-host="'+host+'"] .ftag'),
      function(t){return t.textContent})};
    // The classes of a row's Server cell in order, and where its pieces sit.
    var cellOrder=function(host){return Array.prototype.map.call(
      d.querySelector('#fleet .row[data-host="'+host+'"] .fsrv').children,
      function(e){return e.className}).join(' ')};
    var layout=function(host){
      var cell=d.querySelector('#fleet .row[data-host="'+host+'"] .fsrv');
      var name=cell.querySelector('.hn').getBoundingClientRect();
      var tag=cell.querySelector('.ftag').getBoundingClientRect();
      var hostLine=cell.querySelector('.fhost').getBoundingClientRect();
      var mid=(tag.top+tag.bottom)/2;
      return {tagRightOfName:tag.left>=name.right,
        tagOnTheNamesLine:mid>name.top&&mid<name.bottom,
        hostUnderTheName:hostLine.top>=name.bottom,
        hostAtTheLeft:Math.abs(hostLine.left-name.left)<1,
        dashed:w.getComputedStyle(cell.querySelector('.ftag')).borderTopStyle}};
    var hostLine=function(host){var h=d.querySelector(
      '#fleet .row[data-host="'+host+'"] .fhost');return h?h.textContent:''};
    var shown=function(){return Array.prototype.filter.call(
      d.querySelectorAll('#fleet .row'),function(r){return r.style.display!=='none'})
      .map(function(r){return r.dataset.host})};
    var search=async function(q){var s=d.querySelector('#fleet .srch');s.value=q;
      s.dispatchEvent(new w.Event('input'));await tick();return shown()};
    var toast=function(){return d.getElementById('toast').textContent};
    var tagPosts=function(){return w.__posts.filter(function(p){
      return p.indexOf('/tags ')>=0})};
    var lastPost=function(){var p=tagPosts();return p[p.length-1]};
    // A hidden control takes no focus, and every screen but the one in
    // front is hidden. So the drive opens the server's Settings the way a
    // person does, by its row and its tab, and goes back by the top bar.
    var open=async function(host){
      d.querySelector('#fleet .row[data-host="'+host+'"]').click(); await tick();
      var later=Array.prototype.filter.call(d.querySelectorAll('.ovl.on button'),
        function(b){return b.textContent.trim()==='Later'})[0];
      if(later){later.click(); await tick()}
      d.querySelector('label[for="tb-'+host+'-settings"]').click(); await tick();
      return w.getComputedStyle(box(host)).display!=='none'&&
        box(host).getBoundingClientRect().width>0};
    var toFleet=async function(){
      d.querySelector('[data-v="fleet"]').click(); await tick()};
    var seen={errs:[]};
    w.addEventListener('error',function(e){seen.errs.push(String(e.message))});
    seen.settingsInFront=await open('box');

    // 1. A server with no tags: no bubble, the field, and no button in the row.
    seen.start={bubbles:bubbles('box'),fieldShown:fieldShown('box'),
      buttons:d.querySelectorAll('#host-box .tagrow .btn').length};

    // 2. Enter adds one tag. The server answers with what it stored, and the
    // bubble and the fleet row say exactly that. The field is empty again
    // and keeps the keyboard, also after the refresh swapped the row in.
    w.__next={status:200,body:{tags:['web']}};
    type('box','Web');
    var fieldBefore=field('box');
    key('box','Enter');
    seen.beforeTheAnswer=bubbles('box');
    await tick(300);
    seen.firstPost=tagPosts()[0];
    seen.afterFirst={bubbles:bubbles('box'),value:field('box').value,
      row:rowTags('box'),toast:toast(),fieldShown:fieldShown('box')};
    seen.afterFirstRefresh={swapped:field('box')!==fieldBefore,focused:focused()};

    // 3. A comma adds one as Enter does.
    w.__next={status:200,body:{tags:['web','production']}};
    type('box','production');
    key('box',',');
    await tick(300);
    seen.secondPost=lastPost();
    seen.afterSecond={bubbles:bubbles('box'),value:field('box').value,
      row:rowTags('box'),hostLine:hostLine('box')};
    await toFleet();
    seen.orderAfterSecond=cellOrder('box');
    seen.layout=layout('box');

    // 4. The search finds a tag, in either case, and only its rows.
    seen.searchTag=await search('production');
    seen.searchUpper=await search('WEB');
    seen.searchNone=await search('no-such-tag');
    seen.searchCleared=await search('');
    await open('box');

    // 5. A refusal is the server's words. The field stays as typed, the
    // bubbles and the row keep what is stored, and Escape empties the field.
    w.__next={status:400,body:{detail:'a tag: the rule, in words'}};
    type('box','two words');
    key('box','Enter'); await tick();
    seen.afterRefusal={value:field('box').value,bubbles:bubbles('box'),
      row:rowTags('box'),toast:toast()};
    key('box','Escape');
    seen.afterRefusalEscape=field('box').value;

    // 6. A tag the server already has comes back as the same list: the
    // field empties and nothing says Added.
    d.getElementById('toast').textContent='';
    w.__next={status:200,body:{tags:['web','production']}};
    type('box','WEB');
    key('box','Enter'); await tick(300);
    seen.already={bubbles:bubbles('box'),value:field('box').value,toast:toast()};

    // 7. The third tag: the field goes, and the keyboard is not put on the
    // new bubble, where a second Enter would take it off again.
    w.__next={status:200,body:{tags:['web','production','eu']}};
    type('box','eu');
    key('box','Enter'); await tick(300);
    seen.third={bubbles:bubbles('box'),fieldShown:fieldShown('box'),
      full:box('box').classList.contains('full'),focused:focused(),toast:toast()};

    // 8. A click on a bubble takes the tag off at once, before the server
    // has answered, and the field is back.
    w.__next={status:200,body:{tags:['web','eu']}};
    point(bubble('box','production'));
    seen.clickAtOnce={bubbles:bubbles('box'),row:rowTags('box'),
      fieldShown:fieldShown('box')};
    await tick(300);
    seen.clickAfter={post:lastPost(),bubbles:bubbles('box'),row:rowTags('box'),
      toast:toast()};

    // 9. The server says no: the bubble comes back, with the server's word.
    w.__next={status:500,body:{}};
    point(bubble('box','web'));
    seen.refusedAtOnce=bubbles('box');
    await tick();
    seen.refusedAfter={bubbles:bubbles('box'),row:rowTags('box'),toast:toast()};

    // 10. By keyboard: a bubble takes the focus as any button does, Enter on
    // it is a click with no pointer, and the keyboard is then on the bubble
    // that took its place, also after the refresh swapped the row in.
    w.__next={status:200,body:{tags:['eu']}};
    bubble('box','web').focus();
    seen.bubbleTakesFocus=focused();
    var bubbleBefore=bubble('box','eu');
    bubble('box','web').click();
    seen.keyAtOnce={bubbles:bubbles('box'),focused:focused()};
    await tick(300);
    seen.keyAfterRefresh={bubbles:bubbles('box'),focused:focused(),
      swapped:bubble('box','eu')!==bubbleBefore,post:lastPost()};
    // The last one by keyboard: the keyboard goes to the field.
    w.__next={status:200,body:{tags:[]}};
    bubble('box','eu').click();
    await tick(300);
    seen.lastGone={bubbles:bubbles('box'),focused:focused(),
      order:cellOrder('box'),hostLine:hostLine('box'),post:lastPost()};

    // 11. A server whose row was its name alone gets its tag beside the
    // name, and is its name alone again when the tag is taken off.
    await toFleet(); await open('plain');
    seen.plainBefore=cellOrder('plain');
    w.__next={status:200,body:{tags:['staging']}};
    type('plain','staging'); key('plain','Enter'); await tick(300);
    seen.plainTagged={order:cellOrder('plain'),row:rowTags('plain')};
    w.__next={status:200,body:{tags:[]}};
    point(bubble('plain','staging')); await tick(300);
    seen.plainCleared={order:cellOrder('plain'),row:rowTags('plain'),
      bubbles:bubbles('plain')};
    seen.clearPost=lastPost();

    // 12. A word typed and not yet added is left alone by the refresh,
    // even when the server's page has changed under it.
    type('plain','half');
    d.activeElement.blur();
    w.__have.plain=['from-elsewhere'];
    await tick(61000); await tick(200);
    seen.heldWhileTyped={value:field('plain').value,bubbles:bubbles('plain')};

    // 13. Emptied, the row catches up on the next refresh. After the page
    // has refreshed itself twice, Enter still adds once.
    field('plain').value='';
    await tick(61000); await tick(200);
    seen.gets=w.__gets;
    seen.caughtUp=bubbles('plain');
    var before=tagPosts().length;
    w.__next={status:200,body:{tags:['from-elsewhere','db']}};
    type('plain','db'); key('plain','Enter'); await tick(300);
    seen.postsAfterRefreshes=tagPosts().length-before;
    seen.postAfterRefreshes=lastPost();
    out.textContent=JSON.stringify(seen);
  };
  run().catch(function(e){out.textContent=JSON.stringify({error:String(e)})});
};
f.src='live.html';
</script>
"""


def a_page(tmp_path):
    db = make_db(tmp_path)
    trl.reporting(db, "box", named("web-07"))
    trl.reporting(db, "plain", named("plain"))
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
    tmp_path = tmp_path_factory.mktemp("tags")
    return drive(tmp_path, a_page(tmp_path))


def test_the_page_script_raised_nothing(drove):
    assert drove["errs"] == []


def test_the_drive_had_the_servers_settings_in_front(drove):
    """Or every check of where the keyboard is would pass on a hidden row,
    which takes no focus whatever the script does."""
    assert drove["settingsInFront"] is True


def test_a_server_with_no_tags_is_the_field_alone_and_no_button(drove):
    assert drove["start"] == {"bubbles": [], "fieldShown": True, "buttons": 0}


def test_enter_posts_the_whole_list_with_the_word_typed_at_its_end(drove):
    assert drove["firstPost"] == '/api/admin/hosts/box/tags {"tags":["Web"]}'
    assert drove["secondPost"] == '/api/admin/hosts/box/tags {"tags":["web","production"]}'


def test_an_added_tag_is_a_bubble_with_the_spelling_the_server_stored(drove):
    """Nothing is drawn before the server answered, because the word on the
    bubble is the server's and not the one typed."""
    assert drove["beforeTheAnswer"] == []
    assert drove["afterFirst"] == {
        "bubbles": ["web"], "value": "", "row": ["web"], "toast": "Added",
        "fieldShown": True}


def test_the_field_keeps_the_keyboard_after_an_add_and_after_the_refresh(drove):
    assert drove["afterFirstRefresh"] == {"swapped": True, "focused": "the field of box"}


def test_a_comma_adds_a_tag_as_enter_does(drove):
    assert drove["afterSecond"] == {
        "bubbles": ["web", "production"], "value": "",
        "row": ["web", "production"], "hostLine": "web-07"}


def test_an_added_tag_lands_beside_the_name_and_before_the_hostname(drove):
    assert drove["orderAfterSecond"] == "hn ftag ftag fhost"


def test_in_the_browser_the_tags_are_on_the_names_line_and_the_hostname_under_it(drove):
    assert drove["layout"] == {
        "tagRightOfName": True, "tagOnTheNamesLine": True,
        "hostUnderTheName": True, "hostAtTheLeft": True, "dashed": "dashed"}


def test_the_search_filters_on_a_tag(drove):
    assert drove["searchTag"] == ["box"]
    assert drove["searchUpper"] == ["box"]
    assert drove["searchNone"] == []
    assert sorted(drove["searchCleared"]) == ["box", "plain"]


def test_a_refusal_says_the_servers_words_and_changes_nothing(drove):
    assert drove["afterRefusal"] == {
        "value": "two words", "bubbles": ["web", "production"],
        "row": ["web", "production"], "toast": "a tag: the rule, in words"}
    assert drove["afterRefusalEscape"] == ""


def test_a_tag_the_server_already_has_adds_no_bubble_and_says_nothing(drove):
    assert drove["already"] == {"bubbles": ["web", "production"], "value": "", "toast": ""}


def test_at_three_the_field_is_gone_and_the_keyboard_is_on_no_bubble(drove):
    assert drove["third"] == {
        "bubbles": ["web", "production", "eu"], "fieldShown": False, "full": True,
        "focused": "nothing", "toast": "Added"}


def test_a_click_takes_the_tag_off_at_once_and_the_field_is_back(drove):
    """A click deletes the tag (docs/RECORD.md 4.285). The bubble and the
    fleet row's tag are gone before the server has answered."""
    assert drove["clickAtOnce"] == {
        "bubbles": ["web", "eu"], "row": ["web", "eu"], "fieldShown": True}
    assert drove["clickAfter"] == {
        "post": '/api/admin/hosts/box/tags {"tags":["web","eu"]}',
        "bubbles": ["web", "eu"], "row": ["web", "eu"], "toast": "Removed"}


def test_a_tag_the_server_would_not_take_off_comes_back(drove):
    assert drove["refusedAtOnce"] == ["eu"]
    assert drove["refusedAfter"] == {
        "bubbles": ["web", "eu"], "row": ["web", "eu"],
        "toast": "That did not work, HTTP 500"}


def test_a_bubble_is_reached_and_taken_off_by_keyboard(drove):
    """The keyboard goes to the bubble that took the place of the one taken
    off, and is put back there after the refresh swapped the row in."""
    assert drove["bubbleTakesFocus"] == "the bubble web"
    assert drove["keyAtOnce"] == {"bubbles": ["eu"], "focused": "the bubble eu"}
    assert drove["keyAfterRefresh"] == {
        "bubbles": ["eu"], "focused": "the bubble eu", "swapped": True,
        "post": '/api/admin/hosts/box/tags {"tags":["eu"]}'}


def test_after_the_last_tag_the_keyboard_is_in_the_field_and_the_hostname_stays(drove):
    assert drove["lastGone"] == {
        "bubbles": [], "focused": "the field of box", "order": "hn fhost",
        "hostLine": "web-07", "post": '/api/admin/hosts/box/tags {"tags":[]}'}


def test_a_row_gains_its_first_tag_and_is_its_name_alone_after_the_last(drove):
    assert drove["plainBefore"] == "hn"
    assert drove["plainTagged"] == {"order": "hn ftag", "row": ["staging"]}
    assert drove["plainCleared"] == {"order": "hn", "row": [], "bubbles": []}
    assert drove["clearPost"] == '/api/admin/hosts/plain/tags {"tags":[]}'


def test_a_word_typed_and_not_added_is_left_alone_by_the_refresh(drove):
    """The rule the refresh keeps everywhere: never under somebody's hands
    (page.js, holdsEdits). The row catches up once the field is empty."""
    assert drove["heldWhileTyped"] == {"value": "half", "bubbles": []}
    assert drove["caughtUp"] == ["from-elsewhere"]


def test_enter_adds_once_however_long_the_page_has_lived(drove):
    assert drove["gets"] >= 2, "the page did not refresh itself, so this proves nothing"
    assert drove["postsAfterRefreshes"] == 1
    assert drove["postAfterRefreshes"] == (
        '/api/admin/hosts/plain/tags {"tags":["from-elsewhere","db"]}')
