"""Alerts is what happened. Integrations is everything a workspace connects.

    python -m pytest app/test_layout_b.py        (from site/)

docs/screens/alerts/SPEC-layout-b.md, section 5. The table of where alerts
go left the Alerts screen for Integrations, where it stands as Alert
destinations. One button, Add, opens one window for a destination and a
provider alike, in three steps that stay in view. The two windows it
replaces are gone from the page and from its script.

What these are built to catch, in the order it would hurt:

  1. A destination lost or changed in the move. The table on Integrations
     has to be the one the Alerts screen had, row for row, from the same
     call.
  2. A way left to an old window, or a button that names a window the page
     no longer carries.
  3. An action offered before there is something to act on, or two primary
     buttons at once.
  4. A sentence on either screen.

What a click does is held in a real browser by test_layout_b_browser.py.

Its own file for the reason test_channel_rows_live.py is: sessions that all
grow test_render_live.py collide in it.
"""
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
import test_integrations_live as til  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
PAGE_JS = pathlib.Path(__file__).resolve().parent / "page.js"
OLD_WINDOWS = ("chan-ovl", "intg-ovl")
# What only the two old windows carried: their ids, their buttons' ids and
# their error lines.
OLD_IDS = OLD_WINDOWS + ("chan-save", "intg-go", "chan-err", "intg-err")


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def a_server(db, name="box"):
    trl.add_host(db, name, [(NOW - timedelta(minutes=2), trl.document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())


def a_destination(db, label="ops", destination="https://hooks.example.com/services/T0/B0/abc"):
    trl.add_channel_holding_its_destination(db, label, destination)


def a_provider(db):
    til.connect(db, 1)


def view(html, name):
    """One view of the page, and nothing after it."""
    start = html.index(f'<div class="wrap view" id="{name}">')
    return html[start:html.index("\n</div>", start)]


def header(view_html):
    """The view's own header: its name, and its buttons when it has any."""
    start = view_html.index('<div class="ph">')
    return view_html[start:view_html.index("\n  </div>", start)]


def window(html):
    return trl.modal_markup(html, build.ADD_WINDOW)


def foot(window_html):
    return window_html[window_html.index('<div class="m-foot">'):]


def both_feeds(db):
    """The live page and the sample shell: one builder draws both."""
    return (("live", rl.render(db, now=NOW)), ("sample", build.build_sample()))


# A card, and never the grid that holds cards, whose class is `m-cards`.
CARD = re.compile(r'<(?:button type="button"|div) class="(m-card(?: [^"]*)?)"([^>]*)>(.*?)</(?:button|div)>',
                  re.S)


def cards(markup):
    """[(classes, attributes, name)] of every card in a piece of the window."""
    out = []
    for classes, attributes, body in CARD.findall(markup):
        name = re.search(r'<div class="m-card-t">([^<]+)', body + "</div>")
        out.append((classes.split(), attributes, name.group(1) if name else ""))
    return out


def kind_cards(window_html, kind):
    """The second step's cards of one kind."""
    start = window_html.index(f'id="conn-{kind}"')
    end = window_html.index('<div class="m-stage', start)
    return cards(window_html[start:end])


# ------------------------------------------------------------------ Alerts

def test_the_alerts_screen_holds_open_now_and_sent_and_no_channel(db):
    a_server(db)
    a_destination(db)
    trl.seen_an_alert(db, "box")
    html = rl.render(db, now=NOW)
    alerts = view(html, "alerts")
    assert '<h2 class="alh2">Open now' in alerts
    assert '<h2 class="alh2">Sent' in alerts
    # No table of where alerts go, and no heading for one, here or anywhere.
    assert '<h2 class="alh2">Channels' not in html
    assert 'class="crow"' not in alerts
    assert "chanp" not in alerts
    assert build.NO_DESTINATION_ADDED not in alerts


def test_the_alerts_header_has_no_button(db):
    a_server(db)
    trl.seen_an_alert(db, "box")
    for feed, html in both_feeds(db):
        alerts = view(html, "alerts")
        assert "<button" not in header(alerts), feed
        assert "data-open=" not in alerts, f"{feed}: something on Alerts opens a window"


def test_alerts_with_nothing_shows_its_box_and_no_button(db):
    """No alert ever is the one box, whatever is connected: an alert is
    recorded and shown here either way."""
    a_server(db)
    a_destination(db)
    alerts = view(rl.render(db, now=NOW), "alerts")
    assert f'<div class="w">{build.NOTHING_YET}</div>' in alerts
    assert "<button" not in alerts
    assert '<h2 class="alh2">Sent' not in alerts


# ------------------------------------------------- the destinations' table

def test_the_destinations_table_is_on_integrations_row_for_row_as_it_was_on_alerts(db, monkeypatch):
    """The table is what the one function that drew the Alerts screen's
    Channels table answers, whole and once, and nowhere else on the page."""
    a_server(db)
    a_destination(db, "ops", "https://hooks.example.com/services/T0/B0/abc")
    a_destination(db, "night", "https://hooks.example.com/services/T0/B1/def")
    trl.seen_an_alert(db, "box")
    drawn = []
    real = rl.alerts_channels_html

    def remembered(*args, **kwargs):
        drawn.append(real(*args, **kwargs))
        return drawn[-1]

    monkeypatch.setattr(rl, "alerts_channels_html", remembered)
    html = rl.render(db, now=NOW)
    assert len(drawn) == 1
    rows = drawn[0]
    assert rows.count('class="crow"') == 2
    integrations = view(html, "integrations")
    assert (f'<h2 class="alh2">Alert destinations</h2>'
            f'<div class="panel altbl chan chanp">{rows}</div>') in integrations
    # Outside the hidden rows the browser clones, the page holds these rows
    # in that one place.
    visible = re.sub(r"<template.*?</template>", "", html, flags=re.S)
    assert visible.count(rows) == 1
    assert visible.count('class="crow"') == 2
    for column in build.CHANNEL_COLUMNS:
        assert f"<span>{column}" in rows


def test_every_act_of_a_destinations_menu_is_still_there(db):
    a_server(db)
    a_destination(db, "ops")
    integrations = view(rl.render(db, now=NOW), "integrations")
    row = integrations[integrations.index('class="crow"'):]
    menu = row[row.index('<div class="rm-p">'):]
    for word, kind, act in (build.ROW_MENU_EDIT, build.ROW_MENU_TEST, build.ROW_MENU_DELETE):
        item = re.search(rf'<button type="button" class="rm-i rm-{kind}[^"]*" data-act="{act}"[^>]*>{word}<',
                         menu)
        assert item, f"{word} left the row's menu"
        assert 'data-label="ops"' in item.group(0)
    # The fourth act turns the row off, since it is on.
    assert f">{build.ROW_MENU_OFF}<" in menu


# ------------------------------------------------------------ Integrations

def test_integrations_has_one_add_button(db):
    a_server(db)
    a_destination(db)
    a_provider(db)
    for feed, html in both_feeds(db):
        integrations = view(html, "integrations")
        opener = f'<button class="btn pri" data-open="{build.ADD_WINDOW}">Add</button>'
        assert header(integrations).count(opener) == 1, feed
        # One on the whole page. The script names the same attribute once,
        # to hear a click on it, and is not a button.
        drawn = re.sub(r"<script.*?</script>", "", html, flags=re.S)
        assert drawn.count(f'data-open="{build.ADD_WINDOW}"') == 1, feed
        # and it names a window the page carries, once
        assert html.count(f'id="{build.ADD_WINDOW}"') == 1, feed


def test_the_feeds_heading_is_gone_and_planned_feeds_are_cards(db):
    a_server(db)
    a_provider(db)
    for feed, html in both_feeds(db):
        assert '<h2 class="alh2">Feeds' not in html, feed
        assert "No feed connected" not in html, feed
        integrations = view(html, "integrations")
        for name in ("Syslog", "Grafana", "Prometheus", "Zabbix"):
            assert name not in integrations, f"{feed}: {name} is on the screen, not in the window"
        add = window(html)
        assert ("Syslog" in [name for classes, _a, name in kind_cards(add, "dest")
                             if "planned" in classes]), feed
        monitoring = kind_cards(add, "mon")
        assert [name for _c, _a, name in monitoring] == ["Grafana", "Prometheus", "Zabbix"], feed
        assert all("planned" in classes for classes, _a, _n in monitoring), feed


def test_the_two_empty_lines_say_their_words(db, tmp_path):
    """With one kind connected and not the other, the empty one shows one
    line under its heading, and the page keeps its header button."""
    a_server(db)
    a_destination(db)
    only_destination = view(rl.render(db, now=NOW), "integrations")
    assert ('<h2 class="alh2">Providers</h2><div class="panel altbl">'
            '<div class="al alempty">No provider connected</div></div>') in only_destination
    assert build.NO_DESTINATION_ADDED not in only_destination
    assert f'data-open="{build.ADD_WINDOW}"' in header(only_destination)

    other = str(tmp_path / "other.db")
    con = sqlite3.connect(other)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    a_server(other)
    a_provider(other)
    only_provider = view(rl.render(other, now=NOW), "integrations")
    assert ('<h2 class="alh2">Alert destinations</h2><div class="panel altbl chan chanp">'
            '<div class="al alempty">No alert destination added</div></div>') in only_provider
    assert "No provider connected" not in only_provider
    assert f'data-open="{build.ADD_WINDOW}"' in header(only_provider)


def test_nothing_connected_shows_the_one_box_with_the_one_button(db):
    a_server(db)
    html = rl.render(db, now=NOW)
    integrations = view(html, "integrations")
    assert f'<div class="w">{build.NOTHING_CONNECTED}</div>' in integrations
    assert integrations.count("<button") == 1
    assert f'<button class="btn pri" data-open="{build.ADD_WINDOW}">Add</button>' in integrations
    assert "<button" not in header(integrations)
    # no heading over nothing, and neither empty line
    assert '<h2 class="alh2">' not in integrations
    assert "No provider connected" not in integrations
    assert build.NO_DESTINATION_ADDED not in integrations


# ------------------------------------------------------------ the one window

def test_the_add_window_opens_on_its_first_cards_and_no_action(db):
    a_server(db)
    for feed, html in both_feeds(db):
        add = window(html)
        assert '<h2>Add</h2>' in add, feed
        first = cards(add[:add.index('<div class="m-stage')])
        assert [name for _c, _a, name in first] == [name for _k, name, _g in build.ADD_KINDS], feed
        assert [name for _c, _a, name in first] == ["Alert destination", "Provider", "Monitoring"], feed
        # Nothing is picked and no step shows.
        assert 'm-stage on' not in add and " sel" not in add, feed
        # The foot: Cancel, as the one primary button, and the action hidden.
        buttons = re.findall(r"<button([^>]*)>([^<]*)</button>", foot(add))
        assert [word for _a, word in buttons] == ["Cancel", build.ADD_ACTIONS["dest"]], feed
        cancel, action = (attributes for attributes, _w in buttons)
        assert 'class="btn pri"' in cancel and " hidden" not in cancel, feed
        assert f'data-close="{build.ADD_WINDOW}"' in cancel, feed
        assert " hidden" in action, f"{feed}: an action shows before anything is picked"
        for kind, word in build.ADD_ACTIONS.items():
            assert f'data-{kind}="{word}"' in action, feed
    assert build.ADD_ACTIONS == {"dest": "Save", "prov": "Connect"}


def shape(card_markup):
    """A card with what differs from card to card taken out: its id or its
    kind, its drawing and its word."""
    card_markup = re.sub(r' (?:id|data-kind)="[^"]*"', "", card_markup)
    card_markup = re.sub(r"<svg([^>]*)>.*?</svg>",
                         lambda m: "<svg%s>" % re.sub(r' viewBox="[^"]*"', "", m.group(1)),
                         card_markup, flags=re.S)
    card_markup = re.sub(r'(<div class="m-card-t">)[^<]*', r"\1", card_markup)
    return re.sub(r"\s+", "", card_markup)


def test_the_first_cards_are_drawn_as_the_add_server_windows_first_cards(db):
    """A block with the icon above the word: the same element, the same
    classes, the same size of icon, in the same grid."""
    a_server(db)
    html = rl.render(db, now=NOW)
    server = html[html.index('id="add-ovl"'):]
    server_first = server[server.index('<div class="m-cards m3">'):server.index('<div class="m-stage')]
    add = window(html)
    add_first = add[add.index('<div class="m-cards m3 m-first">'):add.index('<div class="m-stage')]
    one = re.compile(r'<div class="m-card pick"[^>]*>.*?</div>\s*</div>', re.S)
    theirs = {shape(card) for card in one.findall(server_first)}
    ours = {shape(card) for card in one.findall(add_first)}
    assert len(one.findall(server_first)) == 3 and len(one.findall(add_first)) == 3
    assert len(theirs) == 1, "the Add server window's first cards are not one shape"
    assert ours == theirs
    assert 'width="22"height="22"' in next(iter(ours))


def test_the_monitoring_cards_are_one_entry_of_one_list(monkeypatch):
    """Where the three planned monitoring cards go was the spec's one open
    point. It is the third entry of `ADD_KINDS` and nothing else: without it
    the window opens on two cards and shows none of the three."""
    whole = build.add_modal()
    assert 'data-kind="mon"' in whole and 'id="conn-mon"' in whole
    monkeypatch.setattr(build, "ADD_KINDS", build.ADD_KINDS[:2])
    without = build.add_modal()
    first = cards(without[:without.index('<div class="m-stage')])
    assert [name for _c, _a, name in first] == ["Alert destination", "Provider"]
    assert '<div class="m-cards m2 m-first">' in without
    assert "conn-mon" not in without
    for name in ("Grafana", "Prometheus", "Zabbix"):
        assert name not in without
    # Syslog is an alert destination either way.
    assert "Syslog" in [name for _c, _a, name in kind_cards(without, "dest")]


def test_a_planned_card_is_disabled_and_says_only_planned(db):
    a_server(db)
    for feed, html in both_feeds(db):
        add = window(html)
        planned = re.findall(r'<button type="button" class="m-card planned nmo"([^>]*)>(.*?)</button>',
                             add, re.S)
        unbuilt = ([name for _k, name, _g, built in build.PROVIDERS if not built]
                   + [build.SYSLOG_CARD[1]] + [name for _k, name, _g, _b in build.MONITORING])
        assert len(planned) == len(unbuilt) == 11, f"{feed}: {len(planned)} planned cards"
        said = []
        for attributes, body in planned:
            assert attributes == ' disabled aria-disabled="true"', feed
            words = re.sub(r"<svg.*?</svg>", "", body, flags=re.S)
            name = re.fullmatch(r'<div class="m-card-t">([^<]+)'
                                r'<span class="tag-planned">planned</span></div>', words)
            assert name, f"{feed}: a planned card says more than its name and the tag: {words}"
            said.append(name.group(1))
        assert sorted(said) == sorted(unbuilt), feed
        # and no built card is among them
        assert not set(said) & {name for name, _stage in build.ADD_CHANNELS}, feed


def test_the_old_add_windows_are_not_in_the_page(db):
    a_server(db)
    a_destination(db)
    a_provider(db)
    for feed, html in both_feeds(db):
        for old in OLD_WINDOWS:
            assert f'id="{old}"' not in html, f"{feed}: {old} is still on the page"
            assert f'data-open="{old}"' not in html, feed
        for words in (">Add channel<", ">Add integration<", ">Save channel<"):
            assert words not in html, f"{feed}: {words}"
        assert html.count('class="ovl js-modal" id="conn-ovl"') == 1, feed


def test_nothing_in_the_page_or_its_script_names_the_old_windows(db):
    """Gone, not hidden: a handler left bound to a window that is not there
    is the way one comes back."""
    a_server(db)
    source = PAGE_JS.read_text(encoding="utf-8")
    for feed, text in both_feeds(db) + (("page.js", source),):
        for old in OLD_IDS:
            assert old not in text, f"{feed} still names {old}"


def test_a_rows_edit_opens_the_new_window_and_no_other():
    source = PAGE_JS.read_text(encoding="utf-8")
    start = source.index("var bindEdit=function(b){")
    edit = source[start:source.index("onWire(function(){document.querySelectorAll('.rm-edit')", start)]
    assert "connOvl.classList.add('on')" in edit
    assert "connOvl.dataset.editing=label" in edit
    # It reaches for no other window: the one it opens is the one the script
    # found by id once, above.
    assert "getElementById" not in edit
    assert source.count("document.getElementById('conn-ovl')") == 1
    # and it paints the foot for the fields it opened on
    assert "connFoot();" in edit


# ------------------------------------------------------------------ the words

def test_no_sentence_a_customer_reads_sends_them_to_alerts_for_a_destination(db):
    """What a person reads on the page, and what the script can say to them,
    with the script's comments left out."""
    a_server(db)
    a_destination(db)
    for feed, html in both_feeds(db):
        body = html[:html.rindex("<script>")]
        said = re.sub(r"<style.*?</style>", "", body, flags=re.S)
        said = re.sub(r"<[^>]+>", " ", said)
        script = html[html.rindex("<script>"):]
        strings = " ".join(re.findall(r"'((?:[^'\\\n]|\\.)*)'", re.sub(r"^\s*//.*$", "", script, flags=re.M)))
        for text in (said, strings):
            for wrong in ("Alerts screen", "on Alerts", "Add channel", "Add a channel",
                          "Add integration"):
                assert wrong not in text, f"{feed}: {wrong!r} is still said"


WHY_ROWS = (
    # kind, stored detail, declared, the tag, the Why column
    ("silent", "no report for 180 minutes, past the 35 minute threshold", "",
     "silent", "nothing from the agent for 180 min"),
    ("finding changed", "tcp/8410 on v4 was open, now conflict", "closed",
     "conflict", "you said closed"),
    ("finding changed", "tcp/8410 on v4 was closed, now conflict", "open",
     "conflict", "you said reachable"),
    ("finding changed", "tcp/8410 on v4 had no state, now unreviewed", "",
     "reachable", "nobody has said whether it should be"),
    ("finding changed", "tcp/8410 on v4 had no state, now unexplained", "",
     "reachable", "not explained"),
    ("outside view stale", "the outside view of web is 7 hours old, past 6", "",
     "stale", "the outside view of web is 7 hours old"),
)


@pytest.mark.parametrize("kind,detail,declared,tag,why", WHY_ROWS)
def test_the_why_column_says_said_with_the_messages_words(kind, detail, declared, tag, why):
    parsed = rl.parse_detail(detail)
    assert rl.alert_words(kind, parsed)[0] == tag
    assert rl.alert_why(kind, detail, parsed, declared) == why


def test_a_conflict_whose_answer_is_not_found_keeps_not_as_declared():
    detail = "tcp/8410 on v4 was open, now conflict"
    assert rl.alert_why("finding changed", detail, rl.parse_detail(detail), "") == "not as declared"


def test_the_sample_shell_shows_the_same_why_words():
    """The shell is a drawing of the product, so its rows say what a real
    row says."""
    whys = {line.why for line in build.SAMPLE_OPEN + build.SAMPLE_SENT}
    assert not whys & {"you said no", "you said yes", "not reviewed"}
    assert not [why for why in whys if why.startswith("no report for")]


def test_inside_the_flow_the_thing_is_a_destination():
    """In a sentence the thing is a destination. The column that holds Email
    and Slack is still headed Channel, on both tables that have it."""
    add = build.add_modal()
    assert "Which alerts this destination takes" in add
    assert "this channel" not in add
    source = PAGE_JS.read_text(encoding="utf-8")
    said = " ".join(re.findall(r"'((?:[^'\\\n]|\\.)*)'", re.sub(r"^\s*//.*$", "", source, flags=re.M)))
    # The refusal of an empty field was the third of these. It named no
    # field, so it left for a line at each field (docs/RECORD.md 4.228,
    # test_add_refusal.py), and no line of those calls the thing anything.
    assert "Destination added." in said
    assert "Fill in where" not in said
    # The refusal of no kind switched on was the second. It called the thing
    # a destination and went on to give a reason of ours. It says what to do
    # now and nothing more, so it names nothing (docs/RECORD.md 4.228).
    assert "Switch on at least one kind." in said
    assert "can never send anything" not in said and "Leave at least" not in said
    assert "this channel" not in said and "Channel added" not in said
    assert build.CHANNEL_COLUMNS[0] == "Channel"
    assert "Channel" in build.SENT_COLUMNS


def test_an_empty_open_now_says_no_open_alerts(db):
    a_server(db)
    trl.seen_an_alert(db, "box")
    alerts = view(rl.render(db, now=NOW), "alerts")
    assert build.NOTHING_OPEN == "No open alerts"
    assert f'<div class="w">{build.NOTHING_OPEN}</div>' in alerts


def test_docs_stands_before_its_planned_tag():
    """A tag follows its word everywhere. Before Docs it read as if Add
    itself were planned."""
    add = build.add_modal()
    head = add[add.index('<div class="m-h">'):add.index('<div class="m-cards')]
    assert head.index(">Docs") < head.index("tag-planned")
    assert head.count("tag-planned") == 1


def test_an_edit_draws_no_card():
    """Both rows of cards are marked, and the one rule that leaves them out
    of an edit names both. What a person then sees is held in a real browser
    (test_layout_b_browser.py)."""
    add = build.add_modal()
    assert add.count('class="m-cards m3 m-first"') == 1
    assert add.count('class="m-stage m-kind"') == len(build.ADD_KINDS)
    editing = '#conn-ovl[data-editing]:not([data-editing=""])'
    assert f'{editing} .m-first,\n{editing} .m-kind{{display:none}}' in build.CSS


# ------------------------------------------------------------- no sentence

def test_no_sentence_stands_on_either_screen(db):
    """A screen carries labels, values, names, statuses and one line when a
    section is empty. So no text on either screen, and none in the window,
    ends a sentence and starts another, or runs past a handful of words."""
    a_server(db)
    a_destination(db)
    a_provider(db)
    trl.seen_an_alert(db, "box")
    html = rl.render(db, now=NOW)
    pieces = {"alerts": view(html, "alerts"), "integrations": view(html, "integrations"),
              "the window": window(html)}
    for name, markup in pieces.items():
        texts = [t.strip() for t in re.findall(r">([^<>]+)<", re.sub(r"<svg.*?</svg>", "", markup, flags=re.S))]
        for text in texts:
            if not text:
                continue
            assert ". " not in text, f"{name}: two sentences: {text!r}"
            assert len(text.split()) <= 8, f"{name}: a sentence: {text!r}"
