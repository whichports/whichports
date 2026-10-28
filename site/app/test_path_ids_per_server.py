"""Every Packet path chip and box has an id no other server's page uses.

    Run from site/: python3 -m pytest app/test_path_ids_per_server.py

Every server's page is in the one document, so an id is only unique if it is
unique across all of them. A server installed again beside its old row is
named "<name>-2" (controlplane/app/store.py), and until 2026-10-27 its chips
were `pp-<name>-2-<n>`, the same ids as the boxes of the old server's third
path, `pp-<name>-<path>-<box>`. A label reaches the first element with its id,
which was the old server's, so the chip did nothing (second big test, 26
October). The radio groups shared a name the same way, and a checked radio
unchecks every other radio of its name in the document.
"""
import collections
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta
from html.parser import HTMLParser

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW

# Four ports, so every server has four paths and its third path's boxes
# exist, the boxes a "-2" server's chips once took the ids of.
PORTS = (22, 80, 443, 5432)


def page(tmp_path, names):
    db = str(tmp_path / "cp.db")
    con = sqlite3.connect(db)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    sockets = [{"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
                "port": port, "process_name": "sshd", "pid": 100 + port}
               for port in PORTS]
    for name in names:
        trl.add_host(db, name, [(NOW - timedelta(minutes=4),
                                 trl.document(listening=sockets))],
                     last_report_at=(NOW - timedelta(minutes=4)).isoformat())
    return rl.render(db, now=NOW)


class RadiosByView(HTMLParser):
    """Each radio's name and id, with the server whose view holds it."""

    def __init__(self):
        super().__init__()
        self.stack = []
        self.radios = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        view = self.stack[-1][1] if self.stack else None
        found = re.fullmatch(r"host-(.+)", attrs.get("id") or "")
        if found and "view" in (attrs.get("class") or "").split():
            view = found.group(1)
        if tag == "input" and attrs.get("type") == "radio":
            self.radios.append((view, attrs.get("name"), attrs.get("id")))
        if tag not in ("input", "br", "img", "meta", "link", "hr", "circle", "path"):
            self.stack.append((tag, view))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return


def radios(html):
    parser = RadiosByView()
    parser.feed(html)
    return parser.radios


def test_no_id_on_the_page_is_used_twice_with_a_server_and_its_name_2(tmp_path):
    html = page(tmp_path, ["box", "box-2"])
    ids = re.findall(r'\sid="([^"]+)"', html)
    twice = sorted(i for i, n in collections.Counter(ids).items() if n > 1)
    assert twice == [], twice


def test_no_radio_group_reaches_into_another_servers_page(tmp_path):
    html = page(tmp_path, ["box", "box-2"])
    views_of = collections.defaultdict(set)
    for view, name, _id in radios(html):
        views_of[name].add(view)
    shared = {name: views for name, views in views_of.items() if len(views) > 1}
    assert shared == {}, shared


def test_names_that_hold_the_markers_themselves_still_collide_nowhere(tmp_path):
    """A server may be called anything a hostname may be, so the ids hold
    even when a name ends in what another server's ids end in."""
    names = ["box", "box-2", "box-c1", "box-p1", "box-p1-0", "box-c", "box-2-2"]
    html = page(tmp_path, names)
    ids = re.findall(r'\sid="(pp-[^"]+)"', html)
    twice = sorted(i for i, n in collections.Counter(ids).items() if n > 1)
    assert twice == [], twice
    views_of = collections.defaultdict(set)
    for view, name, _id in radios(html):
        views_of[name].add(view)
    assert {n: v for n, v in views_of.items() if len(v) > 1} == {}


def test_every_chip_label_reaches_a_radio_in_its_own_servers_page(tmp_path):
    html = page(tmp_path, ["box", "box-2"])
    # A label reaches the first element in the document with its id.
    where = {}
    for view, _name, radio_id in radios(html):
        where.setdefault(radio_id, view)
    for view in ("box", "box-2"):
        body = html.split(f'id="host-{view}"', 1)[1]
        picker = re.search(r'<div class="ppick">(.*?)</div>', body, re.S).group(1)
        targets = re.findall(r'<label for="([^"]+)">', picker)
        assert len(targets) == len(PORTS), targets
        assert [where.get(t) for t in targets] == [view] * len(PORTS), (view, targets)
