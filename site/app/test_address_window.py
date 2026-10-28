"""Adding an address is one button on a server's Settings and one window on
the page (docs/RECORD.md 4.375, 4.379).

The row it replaces held a field, two ways to prove, Start, a token box, a
second box and Verify in one line, and was refused on sight (4.365). The
window is the form the Add server window already draws, in the frame every
window has, so the two cannot drift apart.

    Run from site/: python3 -m pytest app/test_address_window.py
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
import test_integrations_live as til  # noqa: E402
import test_address_hosts_screen as tahs  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
    return path


def text_of(html):
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S)).split())


def addresses(html, host="box"):
    """The Addresses section of one server's Settings."""
    tab = html.split(f'id="t-{host}-settings"', 1)[1]
    return tab.split('<div class="hstage h-addresses">', 1)[1].split('<div class="hstage ', 1)[0]


def window(html):
    """The address window, up to whatever the page puts after it."""
    rest = html.split('id="addr-ovl"', 1)[1]
    return re.split(r'<div class="ovl|<div id="toast"|<div class="toast|<template|<script', rest, 1)[0]


def form(html, prefix):
    """The proof form as one window draws it, with its ids made anonymous."""
    start = html.index(f'id="{prefix}-address"')
    start = html.rindex('<div class="m-label">', 0, start)
    end = html.index("</div>", html.index(f'id="{prefix}-result"')) + len("</div>")
    return html[start:end].replace(f'id="{prefix}-', 'id="X-')


def test_the_section_has_one_button_in_its_headings_line(db):
    tahs.prove(db, til.host_id_of(db, "box"))
    section = addresses(rl.render(db, now=NOW))
    heading = section.split("</h2>", 1)[0]

    assert text_of(heading) == "Addresses Add address"
    assert heading.count("<button") == 1
    assert 'data-open="addr-ovl"' in heading and 'data-host="box"' in heading
    assert 'class="btn pri' in heading


def test_the_add_row_is_gone(db):
    tahs.prove(db, til.host_id_of(db, "box"))
    html = rl.render(db, now=NOW)
    section = addresses(html)

    assert text_of(section.split("</h2>", 1)[1]).startswith(tahs.V4)
    for gone in ("Add an address", "js-addr-start", "js-addr-verify", "js-method",
                 "Publish this token", 'id="ar-box'):
        assert gone not in section, gone
    assert "js-addr-start" not in html and "js-method" not in html
    # One row, the proved address with its Revoke, and no field in the section.
    assert section.count('class="li"') == 1
    assert "<input" not in section


def test_a_server_with_no_proved_address_has_the_button_and_one_empty_line(db):
    section = addresses(rl.render(db, now=NOW))

    assert 'data-open="addr-ovl"' in section
    assert text_of(section.split("</h2>", 1)[1]) == build.NO_ADDRESS_LINE
    assert "<input" not in section


def test_the_window_is_on_the_page_once_and_in_no_servers_page(db):
    trl.reporting(db, "second", trl.document(listening=[trl.SSHD]))
    html = rl.render(db, now=NOW)

    assert html.count('id="addr-ovl"') == 1
    assert html.count('data-open="addr-ovl" data-host=') == 2   # one button per server
    last_view = html.rindex('<div class="wrap view')
    assert html.index('id="addr-ovl"') > last_view
    # Outside every piece the quiet refresh swaps: no server's page holds it.
    for host in ("box", "second"):
        page = html.split(f'id="host-{host}"', 1)[1].split('<div class="wrap view', 1)[0]
        assert 'id="addr-ovl"' not in page


def test_the_window_is_the_frame_every_window_has(db):
    said = text_of(window(rl.render(db, now=NOW)))

    assert "Add an address Address Token file on port 80 DNS TXT record" in said
    assert said.endswith("Cancel Start")


def test_the_windows_foot_has_cancel_and_one_primary_button(db):
    foot = window(rl.render(db, now=NOW)).split('class="m-foot"', 1)[1]

    assert re.findall(r"<button[^>]*>([^<]+)</button>", foot) == ["Cancel", "Start"]
    assert foot.count('class="btn pri"') == 1
    assert 'id="ad-go"' in foot and "hidden" in foot.split('id="ad-go"', 1)[0].rsplit("<button", 1)[1] \
        + foot.split('id="ad-go"', 1)[1].split(">", 1)[0]


def test_the_shared_form_labels_read_from_and_keeps_the_token_on_one_line(db):
    html = rl.render(db, now=NOW)
    shape = form(html, "ad")

    assert '<div class="m-label">Read from</div>' in shape
    assert '<div class="m-label">at</div>' not in html
    assert "Publish this token. Click to copy" in shape
    # Both boxes copy on a click, and each is one line high: the rule that
    # made the token's box three lines tall is gone.
    assert 'class="code m-copy" id="X-token"' in shape
    assert 'class="code m-copy" id="X-where"' in shape
    assert ".m-proof .code{" in html


def test_both_windows_draw_the_same_form(db):
    html = rl.render(db, now=NOW)

    assert form(html, "ad") == form(html, "add-addr")


def test_the_sample_page_draws_the_same_section_and_window():
    html = build.build_sample()

    assert html.count('id="addr-ovl"') == 1
    assert "js-addr-start" not in html and 'class="li proof"' not in html
    assert "Add address" in html


def test_nothing_in_the_section_or_the_window_explains(db):
    """Labels, values and buttons. No sentence about how proving works."""
    html = rl.render(db, now=NOW)
    said = text_of(addresses(html)) + " " + text_of(window(html))

    for word in ("because", "we ", "will ", "you can", "in order", "note"):
        assert word not in said.lower(), word


def test_the_scripts_codes_are_the_registrys_own():
    """The window decides by the registry's typed code. Its three lists hold
    every code the registry can give and no other, so a code added there
    fails here until somebody says what the window does with it."""
    script = build.build_sample().split("<script>")[-1]
    proved = re.search(r"var PROOF_PROVED='([a-z_]+)'", script).group(1)
    lists = [re.findall(r"'([a-z_]+)'", re.search(rf"var {name}=\[(.*?)\]", script, re.S).group(1))
             for name in ("PROOF_START_AGAIN", "PROOF_VERIFY_AGAIN")]
    known = [proved] + lists[0] + lists[1]

    assert len(known) == len(set(known))
    assert set(known) == set(rl.joinbridge.module("authz").PROOF_CODES)
    assert proved == "proved"


# A proof's day is written as every other date on the page is: no zero in
# front of a single digit. The row read "proved until 03 Sep" beside a
# Changes tab that writes "3 Oct" (docs/RECORD.md 4.379, 4.393).

class Proof(dict):
    """One row of the registry, as much of it as the words need."""


def a_proof(expires="2026-09-03T12:00:00+00:00", **more):
    row = {"target": "192.0.2.9", "method": "http_token", "expires_at": expires,
           "revoked_at": None, "expired_at": None, "renewal_failure": None}
    row.update(more)
    return Proof(row)


@pytest.mark.parametrize("day, words", [("2026-09-03T12:00:00+00:00", "3 Sep"),
                                        ("2026-09-13T12:00:00+00:00", "13 Sep"),
                                        ("2026-12-01T00:00:00+00:00", "1 Dec"),
                                        ("2026-10-30T23:59:59+00:00", "30 Oct")])
def test_a_proofs_day_has_no_zero_in_front(day, words):
    assert rl.proof_day(day) == words


@pytest.mark.parametrize("value", [None, "", "not a day", 7])
def test_a_day_that_will_not_read_is_nothing(value):
    assert rl.proof_day(value) == ""


def test_the_row_and_the_windows_yes_write_the_same_day():
    row = a_proof()
    assert rl.proof_status(row, True) == "proved until 3 Sep"
    assert rl.proof_yes_words(row) == "192.0.2.9 proved by token file until 3 Sep"


def test_every_word_a_row_can_say_has_no_zero_in_front():
    early = "2026-09-04T08:00:00+00:00"
    assert rl.proof_status(a_proof(revoked_at=early), True) == "revoked 4 Sep"
    assert rl.proof_status(a_proof(expired_at=early), False) == "expired 4 Sep"
    assert rl.proof_status(a_proof(expires=early), False) == "expired 4 Sep"
    assert rl.proof_status(a_proof(expires=early, renewal_failure="HTTP 404"), True) == (
        "proved until 4 Sep · not renewed: HTTP 404")
