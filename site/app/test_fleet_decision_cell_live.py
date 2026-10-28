"""The Fleet's Needs a decision cell holds the ports that need one, and
nothing else (docs/RECORD.md 4.393, C12).

It ended in "+ N", the count of the server's ports that need no decision.
Under that heading it read as N more that do: "tcp/6000 + 5" on a server
where one port of six waited for an answer. Every port that needs a decision
is a chip, so there is nothing left for a number to count.

    Run from site/: python3 -m pytest app/test_fleet_decision_cell_live.py
"""
import html as html_mod
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
ALLOW = "ip protocol tcp tcp dport %d counter accept"


def sock(port):
    return {"protocol": "tcp", "family": "v4", "port": port, "pid": port,
            "bind_address": "0.0.0.0", "process_name": f"svc{port}"}


def server(db, answering=(), permitted=(), shut=()):
    """One server: ports that answer with no rule (they need a decision),
    ports that answer with a rule that permits them, and ports measured
    shut. The last two need none."""
    ports = list(answering) + list(permitted) + list(shut)
    doc = trl.document(listening=[sock(p) for p in ports])
    doc["hostname"] = "box"
    doc["firewalld"] = {"status": "not_present"}
    doc["nftables"] = {"status": "collected", "tables": [
        {"family": "ip", "name": "filter", "chains": [
            {"name": "INPUT", "hook": "input", "priority": 0, "type": "filter",
             "policy": "drop",
             "rules": [{"text": ALLOW % p, "rendered": "full"} for p in permitted]}]}]}
    trl.reporting(db, "box", doc)
    then = NOW - timedelta(minutes=5)
    for port in list(answering) + list(permitted):
        trl.probe_result(db, "box", port, "v4", "connect_succeeded", measured_at=then)
    for port in shut:
        trl.probe_result(db, "box", port, "v4", "no_response", measured_at=then)


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def decision_cell(db):
    """(the chips, the words a browser shows in the cell) for the server."""
    html = rl.render(db, now=NOW)
    row = html.split('<a class="row', 1)[1].split("</a>", 1)[0]
    cell = row.split('class="fchips"', 1)[1].split("</div>", 1)[0].split(">", 1)[1]
    chips = re.findall(r'<span class="fpc [a-z]+">([^<]+)</span>', cell)
    words = " ".join(html_mod.unescape(re.sub(r"<[^>]+>", " ", cell)).split())
    return chips, words


def test_one_port_that_needs_a_decision_beside_five_that_need_none(db):
    """The measured case: the cell said "tcp/6000 + 5"."""
    server(db, answering=[6000], permitted=[22, 8410], shut=[5432, 9100, 9200])

    assert decision_cell(db) == (["tcp/6000"], "tcp/6000")


def test_no_port_that_needs_a_decision_is_an_empty_cell(db):
    server(db, permitted=[22], shut=[5432, 9100])

    assert decision_cell(db) == ([], "")


def test_every_port_that_needs_a_decision_is_a_chip_however_many(db):
    waiting = list(range(6000, 6012))
    server(db, answering=waiting, permitted=[22], shut=[5432])
    chips, words = decision_cell(db)

    assert chips == [f"tcp/{p}" for p in waiting]
    assert words == " ".join(chips)


def test_a_server_where_every_port_needs_a_decision(db):
    server(db, answering=[6000, 6001])

    assert decision_cell(db) == (["tcp/6000", "tcp/6001"], "tcp/6000 tcp/6001")


def test_the_reachable_cell_still_counts_every_port(db):
    """The whole server's count has one place, the cell before this one."""
    server(db, answering=[6000], permitted=[22, 8410], shut=[5432, 9100, 9200])
    html = rl.render(db, now=NOW)
    row = html.split('<a class="row', 1)[1].split("</a>", 1)[0]

    assert "<b>3</b> of 6 ports" in row
