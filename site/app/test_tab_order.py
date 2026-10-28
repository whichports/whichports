"""The tabs of a server's page stand in one order, on every page that draws them.

    Run from site/: python3 -m pytest app/test_tab_order.py

Overview, Services, Rules, Evidence, Packet path, Changes, Settings: the
order of 2026-10-03 (docs/RECORD.md 4.325). `build.HOST_TAB_KEYS` is the one
list that holds it. Each feed still writes its own tabs out, the sample shell
and the live page, so this holds every row of tabs to that list. A tab moved
in one feed and not in the other would be two pages with two orders.

Only the order is held here. A tab's name, its address and what opens it are
the business of the tests that were there before.
"""
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import build  # noqa: E402
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import NOW, SSHD, db, document, reporting  # noqa: E402

__all__ = ["db"]

ORDER = ["overview", "services", "rules", "evidence", "path", "changes", "settings"]


def view_of(html, slug):
    return html.split(f'id="host-{slug}"', 1)[1].split('<div class="wrap view', 1)[0]


def labels(view, slug):
    """The tabs as the row draws them, left to right."""
    row = view.split('<div class="subnav">', 1)[1].split("</div>", 1)[0]
    return re.findall(rf'<label class="k-([a-z]+)" for="tb-{slug}-', row)


def radios(view, slug):
    """The radios behind the tabs, in the page's own order, which is the
    order the arrow keys walk them in."""
    return re.findall(rf'<input type="radio" class="tabsel k-([a-z]+)" name="tabs-{slug}"', view)


def panels(view, slug):
    return re.findall(rf'<div class="tab k-([a-z]+)" id="t-{slug}-', view)


def test_the_one_list_is_the_order():
    assert build.HOST_TAB_KEYS == ORDER


def test_the_sample_shell_draws_its_tabs_in_that_order():
    # The sample's one server page is the view with the id "host".
    view = build.build_sample().split('id="host"', 1)[1].split('<div class="wrap view', 1)[0]
    assert labels(view, "host") == ORDER
    assert radios(view, "host") == ORDER


def test_a_live_server_draws_its_tabs_in_that_order(db):
    doc = document(listening=[SSHD])
    doc["hostname"] = "box"
    reporting(db, "box", doc)
    view = view_of(rl.render(db, now=NOW), "box")
    assert labels(view, "box") == ORDER


def test_a_server_with_no_agent_keeps_the_order_for_the_tabs_it_has(db):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    joinbridge.module("store").add_address_host(con, "edge")
    con.close()
    view = view_of(rl.render(db, now=NOW), "edge")
    drawn = labels(view, "edge")
    assert drawn == [key for key in ORDER if key in drawn]
    assert drawn == ["overview", "evidence", "changes", "settings"]


def test_the_keyboard_and_the_panels_follow_the_row(db):
    """The arrow keys move through the radios in the page's order, and a
    panel is found by its key and not by its place. All three lists are one."""
    doc = document(listening=[SSHD])
    doc["hostname"] = "box"
    reporting(db, "box", doc)
    view = view_of(rl.render(db, now=NOW), "box")
    assert radios(view, "box") == ORDER
    assert panels(view, "box") == ORDER


def test_a_server_page_still_opens_on_the_overview(db):
    doc = document(listening=[SSHD])
    doc["hostname"] = "box"
    reporting(db, "box", doc)
    view = view_of(rl.render(db, now=NOW), "box")
    checked = re.findall(r'<input type="radio" class="tabsel k-([a-z]+)"[^>]* checked>', view)
    assert checked == ["overview"]
