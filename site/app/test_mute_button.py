"""Mute: the host-page button, its menu of lengths, and the muted state.

The storage and the routes are the control plane's
(controlplane/app/finding_alerts.py, controlplane/app/ingest.py, and their
tests). This covers what a person sees and clicks: the button reads Mute, it
opens this page's own menu rather than anything the browser draws, the menu
offers the lengths the owner named on 2026-08-24, and a muted server says so and
offers the way back.

Its own file on purpose, the same reason test_scan_button.py is: parallel
branches that all grow test_render_live.py collide in it, so a screen that
adds a control adds its tests here instead.
"""
import json
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import render_live as rl  # noqa: E402


def menu_labels(html):
    """The visible words on a menu's items, in the order the menu shows them."""
    panel = html.split('class="rm-p"')[1]
    return re.findall(r'<button[^>]*class="rm-i[^>]*>([^<]+)</button>', panel)


# ------------------------------------------------------------ the sample feed

def test_the_sample_header_button_reads_mute_and_the_fixed_length_is_gone():
    """The owner, 2026-08-24: the button says Mute and nothing else. The old button promised two
    hours in its own label and the label carried the machinery note."""
    html = build.sample_host_view()
    assert ">Mute<" in html
    assert "Mute 2h" not in html
    assert "arrives with the alert engine" not in html


def test_the_sample_menu_offers_the_four_lengths_in_order():
    """1h, 8h, 24h, until I turn it back on. His list, in his order, and
    nothing else offered."""
    html = build.sample_host_view()
    labels = menu_labels(html)
    assert labels == ["Unmute", "1 hour", "8 hours", "24 hours",
                      "Until I turn it back on"]


def test_the_sample_menu_is_the_pages_own_and_not_the_browsers():
    """No <select>, which every engine draws its own way, and no dialog. The
    menu is the same .rmenu shape a channel row already opens."""
    html = build.sample_host_view()
    assert "<select" not in html
    assert 'class="rmenu"' in html
    assert 'data-menu="mute-host"' in html


def test_the_sample_items_toast_and_do_not_post():
    """The sample shell is wired to nothing, so its items are js-act stubs the
    shared handler toasts, exactly like every other sample control."""
    html = build.mute_menu_html("host", live=False)
    assert "js-mute" not in html.replace("js-mute-t", "")
    assert html.count('class="rm-i js-act"') == 5


def test_the_sample_toast_says_what_happened_and_nothing_else():
    """A toast may say the mute happened. It may not teach what muting means,
    name the sweep, or promise when anything catches up."""
    html = build.mute_menu_html("host", live=False)
    for msg in re.findall(r'data-msg="([^"]*)"', html):
        assert msg in ("Unmuted.", "Muted.", "Muted for 1 hour.",
                       "Muted for 8 hours.", "Muted for 24 hours.")


def test_the_sample_unmute_item_exists_and_is_hidden():
    """In the markup so the muted paint has a bound item to reveal, hidden
    because the sample host is not muted."""
    html = build.mute_menu_html("host", live=False)
    unmute = re.search(r'<button[^>]*data-act="unmute"[^>]*>', html).group(0)
    assert " hidden" in unmute


def test_the_two_feeds_offer_the_same_menu(tmp_path):
    """The sample and the live page may differ in what a click does, never in
    what the menu is. Same items, same order, same words."""
    sample = build.mute_menu_html("host", live=False)
    live = build.mute_menu_html("host", live=True)
    assert menu_labels(sample) == menu_labels(live)
    # and the only difference in the items is which handler class they carry
    assert sample.replace("rm-i js-act", "rm-i js-mute") == live


def test_the_hidden_menu_item_rule_is_in_the_stylesheet():
    """.rm-i sets display:block, which beats the browser's own [hidden] rule,
    so without this line the Unmute item would show on every server."""
    assert ".rm-i[hidden]{display:none}" in build.CSS


def test_the_page_script_posts_the_length_and_paints_first():
    """The live handler ships on both feeds. It posts to the mute and unmute
    routes, and the paint comes before the fetch, because an action shows its
    result at once and the server's lag is ours to deal with."""
    page = build.build_sample()
    script = page.split("<script>")[-1]
    assert ".js-mute" in script
    assert "'mute':'unmute'" in script
    assert "indefinite:true" in script
    handler = script.split(".js-mute'")[1]
    assert handler.index("setMuted(box,wanted)") < handler.index("fetch(")


def test_the_menu_never_uses_the_browsers_dialogs():
    """Our own dialogs and menus, never alert, confirm or prompt."""
    page = build.build_sample()
    script = page.split("<script>")[-1]
    for banned in ("alert(", "confirm(", "prompt("):
        assert banned not in script


# --------------------------------------------------------------- the live feed

# The minimal control-plane schema, copied rather than imported so this file
# stands alone (the same posture test_scan_button.py takes and guards).
# alert_silences is deliberately absent here: a database the sweep has never
# touched has no such table, and the page has to render on one. The helper
# below adds it for the tests about the muted state.
SCHEMA = """
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL, revoked_at TEXT, last_report_at TEXT,
    paused INTEGER NOT NULL DEFAULT 0, auto_named INTEGER NOT NULL DEFAULT 0);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
"""

SILENCES = """
CREATE TABLE alert_silences (
    id INTEGER PRIMARY KEY, host_id INTEGER NOT NULL REFERENCES hosts(id),
    kind TEXT NOT NULL, protocol TEXT, port INTEGER, family TEXT,
    until TEXT, created_at TEXT NOT NULL, cleared_at TEXT);
"""

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)


def _minimal_document():
    return {
        "schema_version": 1,
        "hostname": "Almabox",
        "collected_at_unix": int(NOW.timestamp()),
        "sockets": {"status": "collected", "listening": []},
        "nftables": {"status": "not_present"},
        "iptables": {"status": "not_present"},
        "ip6tables": {"status": "not_present"},
        "ufw": {"status": "not_present"},
        "firewalld": {"status": "not_present"},
        "containers": {"status": "collected", "podman": []},
        "overlays": {"status": "collected"},
        "rule_files": {"status": "collected", "files": []},
    }


def make_db(path, mute_until="absent", cleared_at=None):
    """One reporting host. `mute_until` is "absent" for no silences table at
    all, None for an indefinite mute, or a datetime for a timed one."""
    con = sqlite3.connect(path)
    con.executescript(SCHEMA)
    con.execute(
        "INSERT INTO hosts (name, token_hash, created_at, last_report_at)"
        " VALUES (?, ?, ?, ?)",
        ("almabox", "hash-almabox", NOW.isoformat(), NOW.isoformat()))
    con.execute(
        "INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version,"
        " document) VALUES (1, ?, ?, 1, ?)",
        (NOW.isoformat(), int(NOW.timestamp()), json.dumps(_minimal_document())))
    if mute_until != "absent":
        con.executescript(SILENCES)
        until = mute_until.isoformat() if mute_until else None
        con.execute(
            "INSERT INTO alert_silences (host_id, kind, until, created_at,"
            " cleared_at) VALUES (1, 'mute', ?, ?, ?)",
            (until, NOW.isoformat(), cleared_at))
    con.commit()
    con.close()
    return str(path)


def test_a_live_host_page_mute_menu_carries_that_host_name(tmp_path):
    """The click posts to this host's own route, and it is the posting item,
    never the toasting stub."""
    html = rl.render(make_db(tmp_path / "cp.db"), now=NOW)
    assert 'data-menu="mute-almabox"' in html
    assert 'class="rm-i js-mute" data-act="mute" data-host="almabox"' in html
    assert menu_labels(html.split('data-menu="mute-almabox"')[1]) == \
        ["Unmute", "1 hour", "8 hours", "24 hours", "Until I turn it back on"]
    # The stub and its promise are gone from the live page too.
    assert "Mute 2h" not in html
    assert "arrives with the alert engine" not in html


def test_an_unmuted_host_reads_mute_and_hides_the_way_back(tmp_path):
    html = rl.render(make_db(tmp_path / "cp.db"), now=NOW)
    assert ">Mute<" in html
    unmute = re.search(r'<button[^>]*data-act="unmute"[^>]*>', html).group(0)
    assert " hidden" in unmute


def test_an_indefinitely_muted_host_says_muted_and_offers_unmute(tmp_path):
    """The control says the state and the menu holds the way back. A NULL
    `until` is the mute that lasts until somebody lifts it."""
    html = rl.render(make_db(tmp_path / "cp.db", mute_until=None), now=NOW)
    assert ">Muted<" in html
    assert ">Mute<" not in html
    unmute = re.search(r'<button[^>]*data-act="unmute"[^>]*>', html).group(0)
    assert " hidden" not in unmute


def test_a_timed_mute_shows_while_it_is_live(tmp_path):
    html = rl.render(make_db(tmp_path / "cp.db",
                             mute_until=NOW + timedelta(hours=8)), now=NOW)
    assert ">Muted<" in html


def test_an_expired_mute_does_not_show(tmp_path):
    """The row is still there, its time is over, so the screen says Mute. The
    reader of what counts as live is the control plane's own, so this page and
    the sweep cannot disagree about whether a mute holds."""
    html = rl.render(make_db(tmp_path / "cp.db",
                             mute_until=NOW - timedelta(minutes=1)), now=NOW)
    assert ">Mute<" in html
    assert ">Muted<" not in html


def test_a_withdrawn_mute_does_not_show(tmp_path):
    html = rl.render(make_db(tmp_path / "cp.db", mute_until=None,
                             cleared_at=NOW.isoformat()), now=NOW)
    assert ">Mute<" in html
    assert ">Muted<" not in html


def test_a_database_without_the_silences_table_still_renders(tmp_path):
    """The table arrives with the first mute or the first sweep. Before either
    the page renders and nothing reads as muted."""
    html = rl.render(make_db(tmp_path / "cp.db", mute_until="absent"), now=NOW)
    assert ">Mute<" in html
    assert ">Muted<" not in html


# ------------------------------------------------- the mark beside the state
# docs/DESIGN.md section 3: a second fact about a server sits beside its state
# and is never a sixth state. The rate flag set the treatment and the muted
# mark takes it unchanged: the .tag-planned shape, neutral, the word alone.

def fleet_row_of(html, name):
    """One host's fleet row, out of either feed's fleet list."""
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    return re.search(f'<a class="row" href="[^"]*" data-host="{name}".*?</a>',
                     fleet, re.S).group(0)


def host_header_of(html, name):
    """The h1 line at the top of one host's page."""
    view = html.split(f'id="host-{name}"', 1)[1]
    return re.search(r"<h1>.*?</h1>", view, re.S).group(0)


def test_the_mark_is_neutral_and_never_takes_a_status_tone():
    """Muting is the operator's own choice, so a status tone would paint it as
    a problem. Same reasoning as the rate flag, same shape, no tone."""
    mark = build.muted_flag("almabox", True)
    assert mark == ('<span class="tag-mute" data-mute-tag="almabox" title="muted">'
                    'muted</span>')
    for tone in ("warn", "fail", "ok", "off"):
        assert f"st {tone}" not in mark


def test_an_unmuted_mark_is_written_empty_and_the_css_does_not_draw_it():
    """On every header and row so the click can fill it in place, invisible
    until it is filled."""
    assert build.muted_flag("almabox", False) == \
        '<span class="tag-mute" data-mute-tag="almabox" title="muted"></span>'
    assert ".tag-mute:empty{display:none}" in build.theme.BASE


def test_the_sample_muted_host_wears_the_mark_beside_its_state():
    """lab-04 is the sample fleet's muted server. The mark rides beside the
    state word, which stays exactly what it was. The sketch has no mute mark,
    and it stays as a neutral tag rather than a marker (docs/RECORD.md 4.174)."""
    row = fleet_row_of(build.build_sample(), "lab-04")
    assert 'data-state="paused"' in row
    assert ">paused<" in row
    assert ('<span class="tag-mute" data-mute-tag="lab-04" title="muted">muted</span>'
            in row)
    # beside means after the state, never in place of it
    assert row.index(">paused<") < row.index("tag-mute")
    assert 'class="unsure"' not in row


def test_the_word_muted_is_the_mark_and_appears_nowhere_else_on_the_row():
    """The mark holds the fact. No cell repeats it as text."""
    row = fleet_row_of(build.build_sample(), "lab-04")
    assert row.count(">muted<") == 1


def test_every_sample_row_writes_the_mark_and_only_the_muted_one_fills_it():
    html = build.build_sample()
    for sample in build.FLEET_SAMPLE:
        row = fleet_row_of(html, sample.name)
        filled = f'data-mute-tag="{sample.name}" title="muted">muted</span>'
        empty = f'data-mute-tag="{sample.name}" title="muted"></span>'
        assert (filled in row) == sample.muted
        assert (empty in row) == (not sample.muted)
        # neither a filled nor an empty mark is a magenta marker (4.174)
        assert 'class="unsure"' not in row.split('<div class="fsrv">')[0]


def test_a_muted_live_host_wears_the_mark_on_its_header(tmp_path):
    """The header says the state and, beside it, that a mute covers the
    server. The state word stays reporting, because a muted host still
    reports."""
    html = rl.render(make_db(tmp_path / "cp.db", mute_until=None), now=NOW)
    head = host_header_of(html, "almabox")
    assert ">not watched<" in head
    assert ('<span class="tag-mute" data-mute-tag="almabox" title="muted">muted</span>'
            in head)
    assert head.index(">not watched<") < head.index("tag-mute")


def test_a_muted_live_host_wears_the_mark_on_its_fleet_row(tmp_path):
    row = fleet_row_of(rl.render(make_db(tmp_path / "cp.db", mute_until=None),
                                 now=NOW), "almabox")
    assert 'data-state="not watched"' in row
    assert ('<span class="tag-mute" data-mute-tag="almabox" title="muted">muted</span>'
            in row)


def test_a_timed_live_mute_fills_both_marks_while_it_holds(tmp_path):
    html = rl.render(make_db(tmp_path / "cp.db",
                             mute_until=NOW + timedelta(hours=8)), now=NOW)
    assert html.count('data-mute-tag="almabox" title="muted">muted</span>') == 2


def test_an_unmuted_live_host_writes_both_marks_empty(tmp_path):
    """Present so the click can fill them, empty so nothing shows. Expired and
    withdrawn mutes read the same as none at all."""
    for db in (make_db(tmp_path / "none.db"),
               make_db(tmp_path / "over.db",
                       mute_until=NOW - timedelta(minutes=1)),
               make_db(tmp_path / "gone.db", mute_until=None,
                       cleared_at=NOW.isoformat())):
        html = rl.render(db, now=NOW)
        assert html.count('data-mute-tag="almabox" title="muted"></span>') == 2
        assert 'data-mute-tag="almabox" title="muted">muted</span>' not in html


def test_the_click_paints_the_marks_with_the_button(tmp_path):
    """The paint reaches the header mark and the fleet row mark in the same
    stroke as the button, because an action shows its whole result at once
    (the rule for customer screens). The menu box carries the host name the paint needs."""
    html = rl.render(make_db(tmp_path / "cp.db"), now=NOW)
    assert re.search(r'<div class="rmenu"[^>]*data-host="almabox"', html)
    script = html.split("<script>")[-1]
    paint = script.split("var setMuted", 1)[1].split("};", 1)[0]
    assert "data-mute-tag" in paint
    assert "'muted':''" in paint


def test_the_muted_state_says_no_more_than_the_word(tmp_path):
    """Muted is a status and one word is the whole of it. No sentence beside
    it about what muting means, when it ends, or what the machinery does
    (the rule for customer screens)."""
    html = rl.render(make_db(tmp_path / "cp.db", mute_until=None), now=NOW)
    menu = html.split('data-menu="mute-almabox"')[0][-300:] + \
        html.split('data-menu="mute-almabox"')[1][:600]
    for banned in ("do not mail", "does not mail", "still recorded", "sweep",
                   "expires", "expiry"):
        assert banned not in menu
