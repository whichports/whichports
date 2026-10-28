"""A port somebody answered for that has no state yet (docs/RECORD.md 4.393,
C13).

A port has no state while nothing has measured it: a server whose address is
not proved, or a port declared before the first probe. Its row was empty from
end to end, so a declaration made for it was shown nowhere and could not be
changed from the row. The row now says who decided and shows the answer, as
the row of a port with a state does. It still claims nothing about
reachability: no state word and no tone on a mark.

    Run from site/: python3 -m pytest app/test_declared_port_without_state.py
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


def sock(port, name, address="0.0.0.0"):
    return {"protocol": "tcp", "family": "v4", "port": port, "pid": port,
            "bind_address": address, "process_name": name}


def server(db, sockets):
    doc = trl.document(listening=sockets)
    doc["hostname"] = "box"
    trl.reporting(db, "box", doc)


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def text_of(html):
    bare = re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S))
    return " ".join(html_mod.unescape(bare).split())


def overview(html):
    return html.split('id="t-box-overview"', 1)[1].split('<div class="tab k-services"', 1)[0]


def row(db, port):
    """One port's closed row on the Overview, as a browser would read it."""
    label = overview(rl.render(db, now=NOW)).split(f'for="pr-box-tcp-{port}"', 1)[1]
    label = label.split("</label>", 1)[0]
    cell = lambda cls: text_of(re.search(  # noqa: E731
        rf'<span class="{cls}[^"]*"[^>]*>(.*?)</span>', label, re.S).group(1))
    answers = re.findall(r'<button class="ans ([a-z ]+)" data-answer="([a-z]+)"', label)
    return {"state": text_of(label.split('<span class="prst">', 1)[1].split('<span class="prn">', 1)[0]),
            "decided": cell("prw"),
            "marks": re.findall(r'<i class="([a-z]*)">v[46]</i>', label),
            "answers": [word for _classes, word in answers],
            "picked": [word for classes, word in answers if "pick" in classes.split()],
            "settled": 'class="pra settled"' in label}


# ------------------------------------------------------------------ the case

def test_a_port_declared_closed_and_never_probed_says_who_decided_and_shows_no(db):
    server(db, [sock(9200, "metrics")])
    trl.declare_intent(db, "box", "tcp", 9200, "v4", "closed")
    got = row(db, 9200)

    assert got["decided"].startswith("you")
    assert got["picked"] == ["no"]
    assert got["settled"] is True


def test_a_port_declared_open_and_never_probed_shows_yes(db):
    server(db, [sock(9200, "metrics")])
    trl.declare_intent(db, "box", "tcp", 9200, "v4", "open")
    got = row(db, 9200)

    assert got["decided"].startswith("you")
    assert got["picked"] == ["yes"]


def test_the_row_offers_yes_and_no_and_never_later(db):
    """Later puts off an answer to a state, and this port has none: a Later
    here would be a button that does nothing."""
    server(db, [sock(9200, "metrics")])
    trl.declare_intent(db, "box", "tcp", 9200, "v4", "closed")

    assert row(db, 9200)["answers"] == ["yes", "no"]


def test_it_claims_nothing_about_reachability(db):
    """No state word and no tone on either mark: nothing measured it."""
    server(db, [sock(9200, "metrics")])
    trl.declare_intent(db, "box", "tcp", 9200, "v4", "closed")
    got = row(db, 9200)

    assert got["state"] == ""
    assert got["marks"] == ["", ""]


def test_it_is_not_counted_as_needing_a_decision(db):
    server(db, [sock(9200, "metrics")])
    trl.declare_intent(db, "box", "tcp", 9200, "v4", "closed")
    said = text_of(overview(rl.render(db, now=NOW)).split('class="panel ptbl"', 1)[0])

    assert "Needs a decision 0 of" in said


# ------------------------------------------------------- what stays as it was

def test_a_port_nobody_answered_for_and_never_probed_keeps_its_empty_row(db):
    server(db, [sock(9200, "metrics")])
    got = row(db, 9200)

    assert (got["state"], got["decided"], got["answers"]) == ("", "", [])


def test_a_declared_port_with_a_state_reads_as_it_did(db):
    server(db, [sock(9100, "node_exporter")])
    trl.declare_intent(db, "box", "tcp", 9100, "v4", "closed")
    trl.probe_result(db, "box", 9100, "v4", "no_response",
                     measured_at=NOW - timedelta(minutes=5))
    got = row(db, 9100)

    assert got["state"] == "intended"
    assert got["decided"].startswith("you")
    assert got["answers"] == ["yes", "no", "later"]
    assert got["picked"] == ["no"]


def test_a_loopback_port_somebody_answered_for_keeps_loopback_and_shows_the_answer(db):
    """Loopback is a fact about the socket and stays the word under Decided
    by. The answer given is shown beside it."""
    server(db, [sock(9200, "metrics", "127.0.0.1")])
    trl.declare_intent(db, "box", "tcp", 9200, "v4", "closed")
    got = row(db, 9200)

    assert got["decided"] == "loopback"
    assert got["picked"] == ["no"]
