"""One main state, the worse one, and slim marks beside it.

The owner, 2026-09-20: one main state is shown, the worse one. A conflict stays
as it is, and beside it sits a small alert symbol in the same red border,
slim enough to fit next to the state and not under it. Rate limited,
silenced and the rest work the same way. And once a conflict is resolved, a
green `watched` waits until every open alert is resolved too.

Three things follow. A server whose ports are fine and that still has an
alert open says `alert open`, never a green `watched`. A server with a worse
state keeps that word and carries the alert as a slim mark beside it. And the
server's own page says exactly what its Fleet row says, which it did not: the
header never drew the alert at all.

The marks are slim by the stylesheet alone. Their words stay in the page, so
a screen reader reads them and the script that fills the mute mark on a click
is untouched.
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
import test_render_live as trl  # noqa: E402
import theme  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def a_fine_server(db, name="box"):
    trl.reporting(db, name, trl.document(listening=[trl.SSHD]))
    trl.probe_result(db, name, 22, "v4", "no_response")


def a_conflicted_server(db, name="box"):
    trl.reporting(db, name, trl.document(listening=[trl.SSHD]))
    trl.probe_result(db, name, 22, "v4", "connect_succeeded")
    trl.declare_intent(db, name, "tcp", 22, "v4", "closed")


def fleet_row(html, name):
    fleet = html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]
    start = fleet.index(f'data-host="{name}"')
    return fleet[start:fleet.index("</a>", start)]


def header(html, name):
    view = html[html.index(f'id="host-{name}"'):]
    return view[view.index("<h1>"):view.index("</h1>")]


def test_a_fine_server_with_nothing_open_is_watched(db):
    a_fine_server(db)
    html = rl.render(db, now=NOW)
    assert 'data-state="watched"' in fleet_row(html, "box")
    assert "tag-alert" not in fleet_row(html, "box")


def test_a_fine_server_with_an_alert_open_says_alert_open_and_never_watched(db):
    a_fine_server(db)
    trl.add_alert(db, "box", "tcp/22 became reachable", NOW - timedelta(hours=1))
    html = rl.render(db, now=NOW)
    for place in (fleet_row(html, "box"), header(html, "box")):
        assert "watched" not in place
        assert theme.status("fail", "alert open") in place
        # It is the state, so it is not also a mark beside itself.
        assert "tag-alert" not in place


def test_when_the_alert_is_resolved_watched_comes_back(db):
    a_fine_server(db)
    trl.add_alert(db, "box", "tcp/22 became reachable", NOW - timedelta(hours=1),
                  resolved=True)
    html = rl.render(db, now=NOW)
    assert 'data-state="watched"' in fleet_row(html, "box")
    assert theme.status("ok", "watched") in header(html, "box")


def test_a_worse_state_keeps_its_word_and_carries_the_alert_as_a_mark(db):
    a_conflicted_server(db)
    trl.add_alert(db, "box", "tcp/22 became reachable", NOW - timedelta(hours=1))
    html = rl.render(db, now=NOW)
    for place in (fleet_row(html, "box"), header(html, "box")):
        assert theme.status("fail", "conflict") in place
        assert place.count('class="st ') == 1, "one main state"
        assert build.alert_mark_html("x") in place


def test_the_header_and_the_fleet_row_say_the_same(db):
    """The header never drew the alert before 2026-09-21, so a server that
    read `conflict` and `alert open` on the Fleet read `conflict` alone on
    its own page."""
    a_conflicted_server(db)
    trl.add_alert(db, "box", "tcp/22 became reachable", NOW - timedelta(hours=1))
    html = rl.render(db, now=NOW)
    marks = lambda place: sorted(re.findall(r'class="(st [a-z]+|tag-[a-z]+)"', place))
    assert marks(fleet_row(html, "box")) == marks(header(html, "box"))


def test_alert_open_sorts_under_the_port_problems_and_above_the_quiet_servers():
    order = [band for band in build.FLEET_BANDS if band]
    flat = [word for band in order for word in band]
    assert flat.index("alert open") > flat.index("unexplained")
    assert flat.index("alert open") < flat.index("watched")


# ------------------------------------------------------------ the slim marks

SLIM = ("tag-alert", "tag-mute", "tag-rate")


def test_the_marks_keep_their_words_in_the_page(db):
    a_conflicted_server(db)
    trl.add_alert(db, "box", "tcp/22 became reachable", NOW - timedelta(hours=1))
    mark = build.alert_mark_html("x")
    assert ">alert open</span>" in mark
    assert 'title="alert open"' in mark
    assert ">muted</span>" in build.muted_flag("box", True)
    assert 'title="muted"' in build.muted_flag("box", True)
    assert 'title="rate limited"' in build.rate_flag(True)
    assert 'title="silenced"' in build.silenced_flag(True)


def test_each_slim_mark_is_an_icon_in_the_tags_own_border():
    css = build.CSS
    for kind in SLIM:
        rule = re.search(re.escape("." + kind) + r"[^{]*\{[^}]*text-indent:200%[^}]*", css)
        assert rule and "overflow:hidden" in rule.group(0), f"{kind} still draws its word"
    # The word is moved, never shrunk: every font size is a step of the scale.
    assert "font-size:0" not in css
    assert css.count("mask:url(") >= 4, "alert, muted, rate limited, silenced"
    # The alert keeps the fail tone, in the same border, and nothing else
    # takes a status colour (docs/DESIGN.md section 3).
    assert ".tag-alert{border-color:var(--fail);color:var(--fail)}" in theme.BASE
    # Only the dashboard draws them, so the theme the sign-in pages share
    # carries none of it: those pages may hold no `http://` string at all.
    assert "mask:url(" not in theme.BASE and "http://" not in theme.BASE


def test_an_empty_mark_is_still_not_drawn():
    assert ".tag-mute:empty{display:none}" in theme.BASE
    # The slim rule sets a display on `.tag-mute`. It does not bring an empty
    # mark back, because `.tag-mute:empty` is the more specific selector, a
    # class and a pseudo-class against a class, whatever order they come in.
    assert ".tag-alert,.tag-mute,.tag-rate,.tag-rare{display:inline-block" in build.CSS
    assert ".tag-mute:empty" not in build.CSS


def test_no_mark_is_a_tick_or_a_shield():
    for name in build.MARK_ICONS.values():
        for claim in ("check", "shield", "seal", "lock", "badge", "medal"):
            assert claim not in name
