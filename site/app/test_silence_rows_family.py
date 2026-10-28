"""A silenced port's row in a server's Settings says which address family it
is for (docs/RECORD.md 4.393, 4.395).

A silence is made for one port on one family. A port silenced on both was
two rows that read exactly the same, "8410/tcp, no end" twice (measured
2026-10-06), each with an Unsilence that ends one of them and nothing to say
which.

    Run from site/: python3 -m pytest app/test_silence_rows_family.py
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


def text_of(html):
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S)).split())


def rows(html):
    """Each silenced port's row as (what it reads, the family its button ends)."""
    section = html.split("Silenced ports</h3>", 1)[1].split("</div></div></div>", 1)[0]
    out = []
    for row in section.split('<div class="li">')[1:]:
        family = re.search(r'data-family="([^"]*)"', row)
        out.append((text_of(row), family.group(1) if family else ""))
    return out


def test_a_row_names_its_family():
    html = build.alerts_panel("box", 35, [("tcp", 8410, "v4", "no end")])
    assert rows(html) == [("8410/tcp v4 no end Unsilence", "v4")]


def test_a_port_silenced_on_both_families_is_two_rows_that_differ():
    html = build.alerts_panel("box", 35, [("tcp", 8410, "v4", "no end"),
                                          ("tcp", 8410, "v6", "no end")])
    got = rows(html)
    assert got == [("8410/tcp v4 no end Unsilence", "v4"),
                   ("8410/tcp v6 no end Unsilence", "v6")]
    assert got[0][0] != got[1][0]


def test_each_row_names_the_family_its_button_ends():
    html = build.alerts_panel("box", 35, [("tcp", 8410, "v6", "no end"),
                                          ("udp", 53, "v4", "until 3 Oct 16:00")])
    for words, family in rows(html):
        assert f" {family} " in f" {words} "


def test_the_sample_page_draws_its_silence_the_same_way():
    assert "9100/tcp v4" in text_of(build.build_sample())


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return path


def test_on_the_page_the_measured_case_reads_as_two_different_rows(db):
    uvicorn = {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0", "port": 8410,
               "process_name": "uvicorn", "pid": 7}
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD, uvicorn]))
    trl.silence_port(db, "box", "tcp", 8410, "v4")
    trl.silence_port(db, "box", "tcp", 8410, "v6")
    settings = rl.render(db, now=NOW).split('id="t-box-settings"', 1)[1]

    assert [words for words, _family in rows(settings)] == [
        "8410/tcp v4 no end Unsilence", "8410/tcp v6 no end Unsilence"]


def test_a_server_with_no_silence_keeps_its_one_empty_line(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    settings = rl.render(db, now=NOW).split('id="t-box-settings"', 1)[1]
    assert build.NO_SILENCES in settings.split("Silenced ports</h3>", 1)[1][:400]
