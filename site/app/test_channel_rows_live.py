"""A channel added or changed shows up at once, on the screen that lists it.

That screen is Integrations since layout B, under Alert destinations
(docs/screens/alerts/SPEC-layout-b.md). It was the Alerts screen.

Adding one used to change nothing on screen until the page was reloaded, which
is the one thing a click may not do (the rule for customer screens: "an action shows its result
at once"). Removing one was already right, so what these cover is the other two
halves of the same panel: the row appears on an add, and the row that was edited
says what it says now.

**The row is not written twice.** The page carries a hidden `<template>` per
channel type, drawn by the same `build.channel_row_html` every visible row is
drawn by, and the browser clones one and fills in the values. Half of this file
is about that, because a second copy of the markup living in a script is the
failure this shape exists to prevent and nothing in a browser would ever
complain about it.

Its own file, the same reason test_mute_button.py and test_scan_button.py are:
parallel branches that all grow test_render_live.py collide in it.
"""
import pathlib
import re
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def script(html):
    """The page's shared script, and nothing else on the page."""
    start = html.rindex("<script>")
    return html[start:html.index("</script>", start)]


def templates(html):
    """Every hidden row the page carries, keyed by the type it draws."""
    found = {}
    for kind, markup in re.findall(
            r'<template class="crow-tpl" data-type="([^"]*)">(.*?)</template>',
            html, re.S):
        found[kind] = markup
    return found


def stored_types():
    """The channel types the control plane can actually store."""
    return list(rl.joinbridge.module("channels").TYPES)


# --------------------------------------------- the row the browser clones

def test_every_type_the_control_plane_stores_has_a_row(db):
    """A type with no template is a channel that can be added and cannot
    appear, so the list is read from the module that owns it rather than
    written out again here."""
    trl.add_host(db, "box", [])
    found = templates(rl.render(db, now=NOW))
    for kind in stored_types():
        assert kind in found, f"no row template for {kind}"
    assert set(found) == set(stored_types())


def test_a_template_is_drawn_by_the_same_function_as_a_visible_row(db):
    """**The anti-drift assertion, and the reason `channel_row_html` is its own
    function.** If the browser's row and the rendered row stopped being the
    same markup, nothing in a browser would say so. This does."""
    trl.add_host(db, "box", [])
    found = templates(rl.render(db, now=NOW))
    for kind in stored_types():
        expected = build.channel_row_html((
            rl.CHANNEL_TYPE_WORD[kind], rl.CHANNEL_TYPE_ICON[kind],
            "", "", build.theme.status("ok", "on"), "0",
            build.row_menu_html("", enabled=True, channel_type=kind)))
        assert found[kind] == expected, kind


def test_a_template_is_the_channel_that_was_just_added(db):
    """It is on, it has sent nothing, and it offers Turn off, because that
    is what a channel looks like a second after it is created."""
    trl.add_host(db, "box", [])
    row = templates(rl.render(db, now=NOW))["slack"]
    assert '<span class="st ok">on</span>' in row
    assert '<div class="crow-u z">0</div>' in row
    assert '>Turn off<' in row and '>Turn on<' not in row


def test_a_template_carries_no_label_and_no_destination(db):
    """Both are the control plane's to give: it names an unnamed row itself and
    it decides how much of a destination may be shown. The browser writes them
    in from the answer, so the markup it clones holds neither."""
    trl.add_host(db, "box", [])
    for kind, row in templates(rl.render(db, now=NOW)).items():
        assert '<div class="d"></div>' in row, kind
        assert 'data-label=""' in row, kind
        assert 'data-events=""' in row, kind


def test_a_template_names_its_own_type_so_edit_can_reopen_the_window(db):
    """Edit finds the window's step from the row's type. A cloned row with the
    wrong one there opens the window on somebody else's step."""
    trl.add_host(db, "box", [])
    for kind, row in templates(rl.render(db, now=NOW)).items():
        assert f'data-type="{kind}"' in row, kind


def test_the_templates_sit_outside_every_view(db):
    """A hidden Slack-shaped row inside the panel headed "where it goes" reads
    as a Slack row to anything looking at the markup, this suite included. They
    live in `page`'s own slot, after the last view."""
    trl.add_host(db, "box", [])
    # A provider, so the panel is drawn with no channel in it. With nothing
    # connected the Integrations screen is its one box and has no panel.
    trl.connect_a_provider(db)
    html = rl.render(db, now=NOW)
    first = html.index('<template class="crow-tpl"')
    assert first > html.rindex('<div class="wrap view"')
    assert '<template' not in trl.channels_panel(html)


def test_the_configured_list_still_holds_only_what_is_configured(db):
    """The half the templates could have broken. A page with no stored channel
    lists no channel, whatever else the markup carries. It listed a fixed
    Email row until 2026-09-20 (`docs/RECORD.md` 4.186)."""
    trl.add_host(db, "box", [])
    # A provider, so the panel is drawn. See the test above.
    trl.connect_a_provider(db)
    panel = trl.channels_panel(rl.render(db, now=NOW))
    assert build.NO_DESTINATION_ADDED in panel
    assert panel.count('<div class="crow">') == 0
    assert "Email" not in panel
    assert "Slack" not in panel and "Telegram" not in panel


def test_the_artboard_carries_no_templates():
    """The sample rows are a drawing wired to nothing, so there is no row for
    it to add and nothing for it to clone."""
    assert "crow-tpl" not in build.sample_channel_rows_html()


# ----------------------------------------------------- what the click does

def test_a_successful_add_puts_the_row_up(db):
    """The defect. The success path closed the window and raised a toast and
    left the list exactly as it was."""
    js = script(rl.render(db, now=NOW))
    assert "addChannelRow(j)" in js
    assert "list.appendChild(row)" in js


def test_a_successful_edit_changes_the_row_it_was_opened_on(db):
    js = script(rl.render(db, now=NOW))
    # The kinds the row now takes are the server's answer, which holds them
    # as stored, and on the kinds-only path the ones sent (finding E20).
    assert "editChannelRow(editing,j,kindsOnly?events:j.events)" in js


def channels_js(html):
    """The part of the page script that handles channels.

    Scoped rather than the whole script, so this file stays about the
    channel handlers. The rest of the script is covered by
    test_quiet_refresh.py, which forbids a reload anywhere on the page.
    """
    js = script(html)
    start = js.index("var ACTS=")
    end = js.index("addChannelRow", start)
    # Through the end of the function that adds a row, which is the last of
    # the channel handlers and the one this file is really about.
    return js[start:js.index("}};", end) + 3]


def test_nothing_in_the_channels_path_reloads_the_page(db):
    """A reload is what this fixes and it is not allowed to be the fix."""
    assert "location.reload" not in channels_js(rl.render(db, now=NOW))
    assert ("location.href='/api/admin/channels/slack/connect'"
            in script(rl.render(db, now=NOW)))


def test_the_row_is_cloned_and_never_written_in_the_script(db):
    """**The rule this file exists for.** No row markup in the browser, so the
    two cannot drift. A `crow` class or an innerHTML in the script is somebody
    having written a second copy."""
    js = script(rl.render(db, now=NOW))
    assert "cloneNode(true)" in js
    assert "crow-tpl" in js
    assert '<div class="crow' not in js
    # Comments stripped first. A rule stated in a comment was tripping the
    # assertion that enforces it, which fails the file rather than the code.
    code = re.sub(r"^\s*//.*$", "", js, flags=re.MULTILINE)
    assert "innerHTML" not in code


def test_the_values_written_into_a_row_are_text_and_never_markup(db):
    """A destination and a label are somebody else's text. textContent, so a
    row cannot carry markup in from an answer."""
    js = script(rl.render(db, now=NOW))
    assert "cell.textContent=text" in js
    assert "dataset.label=label" in js


def test_the_destination_shown_is_the_one_the_answer_carried(db):
    """Never what was typed. `Channel.hint` elides a webhook's last path
    segment, so a row painted from the field would show the secret the rendered
    row hides, and would disagree with the next reload."""
    js = script(rl.render(db, now=NOW))
    assert "setRowDest(row,j.env||j.destination||'')" in js
    # and the edit takes the same route, from the answer's own field
    assert "typeof j.destination==='string'" in js


def test_a_save_with_nothing_to_say_is_not_read_as_json(db):
    """The kinds-only path answers 204, which has no body to parse. Reading one
    would turn every Slack edit into an error message."""
    js = script(rl.render(db, now=NOW))
    assert "r.status===204?null:r.json()" in js


def test_a_new_row_is_given_every_handler_a_rendered_row_has(db):
    """A row cloned into the page has nothing bound to it, so its menu opens
    nothing and its items do nothing. Each handler is a named function applied
    both page-wide and inside a new row, and this is what says none was
    forgotten."""
    js = script(rl.render(db, now=NOW))
    binders = ("bindMenu", "bindPanel", "bindPost", "bindTest", "bindEdit")
    inside = js[js.index("var wireChannelRow="):]
    inside = inside[:inside.index("};")]
    for name in binders:
        assert f"forEach({name})" in inside, f"a new row never gets {name}"
        # and the same function is what the page-wide pass uses, so a row put
        # up by a click and a row put up by a render behave the same.
        assert js.count(f"forEach({name})") == 2, name


def test_the_row_menu_still_paints_its_own_acts_at_once(db):
    """Removing, enabling and disabling were already right and stay right: the
    row changes on the click and the request goes out behind it."""
    js = script(rl.render(db, now=NOW))
    assert "if(effect&&row)effect.do(row)" in js
    assert "if(effect&&row)effect.undo(row)" in js


def test_the_screen_says_nothing_about_how_it_catches_up(db):
    """The rule for customer screens. The toast may say what happened. It may not name a render,
    a sweep, a timer, or a minute."""
    js = script(rl.render(db, now=NOW))
    said = re.findall(r"toast\('([^']*)'", js)
    for message in said:
        low = message.lower()
        for banned in ("sweep", "render", "reload", "refresh", "minute",
                       "shortly", "catch"):
            assert banned not in low, message


# ------------------------------- the attribute has to actually hide the thing
#
# `hidden` works through the browser's own `[hidden]{display:none}`, which is
# a user agent rule and loses to any author rule setting `display` on the
# element. So `row.hidden = true` on an element whose class says
# `display:grid` sets the attribute and changes nothing on screen.
#
# This project has paid for that three times: `.pm-menu`, `.rm-i`, and
# `.crow`, where deleting a channel left the row on the page until it was
# reloaded. The first two got a line and a comment each. This is a test
# instead of a third comment.
#
# **It cannot be inferred from the script.** Working out which element a
# `.hidden` assignment lands on means following `r` back through a callback
# to the `closest('.crow')` that produced it, and a regular expression that
# tries either misses cases or invents them. An earlier version of this
# guessed from every class the script selects and reported `.ch2`, which is
# selected and never hidden.
#
# So the elements are listed here by hand, and the count below is what keeps
# the list honest: add a `.hidden` assignment to the page script without
# accounting for it here and this file fails until you do.

# (what the script hides, the selector it lands on). A selector of None is an
# element whose class sets no `display`, so the browser's own rule is enough.
HIDDEN_BY_SCRIPT = (
    ("pmMenu", ".pm-menu"),
    ("r", ".crow"),
    ("proof", ".m-proof"),  # the token and where it is read from, in the two windows' form: sets no display
    ("go", None),         # a <button>, no author display rule
    ("addGo", None),      # the same button
    ("out", None),        # .code sets no display, so [hidden] works on it
    ("n", ".fnote"),      # the fleet banner, dismissed per browser
    ("b", None),          # Turn on beside the two-factor switch, gone once two-factor is on
    ("twoGo", None),      # Turn on, gone once the recovery codes are showing
    ("gone", ".fgone"),   # the Removed list under the fleet table, once its last row was deleted
    ("arrBox", None),     # the arriving server's two rows in Add server: .arr sets no display
    ("save", None),       # Save beside a server's display name, hidden again once it was stored
    ("fbGo", None),       # Send in the Feedback window, gone once the message was sent and back on open
)

# 8 since 2026-08-28: the "Try it, send nothing" card hides the Create button
# the way the two agent cards already do, because that card creates no host
# either (`docs/RECORD.md` 4.124). It is `addGo`, which is already in the list
# above with its answer, so the count is the only thing that moved.
#
# 9 since 2026-08-29: a never-reported server's settings reveal the fresh
# install command in its own row (`out`, the `.code` box the reissue answer
# lands in).
#
# 10 since 2026-09-05: the Fleet's banner is dismissed per browser (`n`, the
# `.fnote` a dismiss lands on, which sets display:flex and so carries its own
# `[hidden]` rule).
#
# 11 since 2026-09-05: Save beside a server's name hides again once the
# rename was stored (`b`, a `.btn`, which sets no display of its own, so
# the browser's own rule hides it). Showing it is a comparison assigned to
# `hidden`, which this count does not read.
#
# 13 since 2026-09-10: the authenticator window's Turn on goes when the
# recovery codes replace the form, and the Turn on beside the switch on the
# Security settings goes when two-factor is on. Both are `<button>` elements,
# which set no display of their own, so the browser's own rule hides them.
#
# 14 since 2026-09-10: reopening the authenticator window puts its Turn on
# back, because the window reopens on the form and not on the codes it showed
# last time. Same element as the one above, so only the count moved.
#
# 15 since 2026-09-14: the Removed list under the fleet table goes when the
# last removed server was deleted (`gone`, the `.fgone` block, which sets no
# display of its own, so the browser's own rule hides it). The remove
# window's two rows are hidden by comparisons assigned to `hidden`, which
# this count does not read, and `.rmrow` is a flex row with its own
# `[hidden]` rule (test_delete_server.py).
# 17 since 2026-09-20: the Add server window shows and hides the two rows of
# a server arriving (docs/screens/add-server/BRIEF-arrival.md).
#
# 18 since 2026-10-02: Save beside a server's tags hides again once they were
# stored (`save`, a `.btn` like the one beside the name, so the browser's own
# rule hides it).
#
# 19 since 2026-10-02: the same Save beside a server's display name. It is
# `save` again, so the count is the only thing that moved.
#
# 18 since 2026-10-03: the Tags row has no Save any more. A tag is added and
# taken off at once (test_tags_screen.py), so the one beside the display name
# is the only `save` left. The Tags row's field is hidden by a class on its
# box, `.tagc.full .tagin`, which this count does not read.
#
# 17 since 2026-10-03: the ID is shown and not edited (docs/RECORD.md 4.298),
# so the Save beside it is gone with the rename. That Save was `b` too, as
# the Turn on beside the two-factor switch still is, so the count moved and
# the list did not.
#
# Still 17 since 2026-10-06: the row that added an address is gone and its
# proof block with it (docs/RECORD.md 4.379). `proof` is the same block in
# the two windows' form now, shown by Start and hidden when a window opens.
# The windows' buttons are shown and hidden by comparisons assigned to
# `hidden`, which this count does not read, and a button sets no display.
#
# 19 since 2026-10-09: the Feedback window's Send goes once the message was
# sent, Done alone staying, and comes back when the window opens (`fbGo`, a
# `<button>`, which sets no display of its own, so the browser's own rule
# hides it; docs/screens/feedback/BRIEF.md).
HIDDEN_ASSIGNMENTS = 19


def _css_of(html):
    return "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", html, re.S))


def test_the_list_of_hidden_elements_is_still_complete(db):
    """The guard on the list above. A new `.hidden` assignment in the page
    script fails here, so nobody adds one without deciding whether its element
    needs a rule."""
    js = script(rl.render(db, now=NOW))
    names = re.findall(r"(\w+)\.hidden\s*=\s*(?:true|false)", js)
    assert len(names) == HIDDEN_ASSIGNMENTS, (
        f"the script now has {len(names)} hidden assignments and this file "
        f"accounts for {HIDDEN_ASSIGNMENTS}. Add the new one to "
        f"HIDDEN_BY_SCRIPT with the selector it lands on, and say whether "
        f"that selector sets display.")
    assert set(names) == {name for name, _ in HIDDEN_BY_SCRIPT}


def test_every_element_the_script_hides_can_actually_be_hidden(db):
    """The rule that would have caught the deleted channel sitting there."""
    css = _css_of(rl.render(db, now=NOW))
    assert css, "the page carries its stylesheet"
    for _name, selector in HIDDEN_BY_SCRIPT:
        if selector is None:
            continue
        sets_display = re.search(
            re.escape(selector) + r"[^{}]*\{[^{}]*display\s*:", css)
        if sets_display:
            assert f"{selector}[hidden]" in css, (
                f"{selector} sets display and the script hides it, so it "
                f"needs a `{selector}[hidden]{{display:none}}` rule or the "
                f"attribute does nothing on screen")


def test_a_deleted_channel_row_is_actually_taken_off_the_screen(db):
    """The instance. `.crow` is a grid, so it needs its own rule, and without
    it Delete removed the channel and left its row on the page."""
    css = _css_of(rl.render(db, now=NOW)).replace("\n", "")
    assert ".crow{display:grid" in css
    assert ".crow[hidden]{display:none}" in css
