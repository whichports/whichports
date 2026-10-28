"""An address row on an instance that uses our probers reads proved only when
our side holds the address too (docs/PRODUCT.md 5g, the challenge of
2026-10-24).

    Run from site/: python -m pytest app/test_address_row_both_sides.py

The row could say proved while our side did not hold the address, and the
reverse. Now a live proof whose address our side does not hold reads the
words the address window says for that, `not proved with the probers`, and
never proved. A row this registry does not hold reads what it always read,
revoked or expired, which is that side saying it does not. What our side
holds is its own listing as the instance last read it
(`dispatch.api_proofs_held`), written here through the control plane's own
writer and never by hand.
"""
import sqlite3
from datetime import timedelta

import pytest

import joinbridge
import render_live as rl
import test_address_hosts_screen as tahs
import test_integrations_live as til
from test_address_window import addresses, db, text_of  # noqa: F401

NOW = tahs.NOW
V4 = tahs.V4
OTHER = "185.199.108.154"


def our_listing(path, *held):
    """Our API's listing as the instance keeps it: each address live a day."""
    dispatch = joinbridge.module("dispatch")
    con = sqlite3.connect(path)
    dispatch.remember_api_proofs(
        con, {address: (NOW - timedelta(hours=1), NOW + timedelta(days=1))
              for address in held}, NOW)
    con.close()


def rows_of(html):
    return text_of(addresses(html))


def test_with_no_prober_lines_a_row_reads_as_it_always_did(db):
    tahs.prove(db, til.host_id_of(db, "box"))
    our_listing(db)

    assert "proved until" in rows_of(rl.render(db, now=NOW))
    assert "proved until" in rows_of(rl.render(db, now=NOW, with_prober_api=False))


def test_a_row_our_side_does_not_hold_reads_not_proved_with_the_probers(db):
    tahs.prove(db, til.host_id_of(db, "box"))
    our_listing(db, OTHER)

    said = rows_of(rl.render(db, now=NOW, with_prober_api=True))

    assert "not proved with the probers" in said
    assert "proved until" not in said


def test_a_listing_never_read_holds_nothing(db):
    tahs.prove(db, til.host_id_of(db, "box"))

    said = rows_of(rl.render(db, now=NOW, with_prober_api=True))

    assert "not proved with the probers" in said


def test_a_proof_our_side_held_until_before_now_is_not_held(db):
    tahs.prove(db, til.host_id_of(db, "box"))
    dispatch = joinbridge.module("dispatch")
    con = sqlite3.connect(db)
    dispatch.remember_api_proofs(
        con, {V4: (NOW - timedelta(days=2), NOW - timedelta(minutes=1))}, NOW)
    con.close()

    assert "not proved with the probers" in rows_of(rl.render(db, now=NOW, with_prober_api=True))


@pytest.mark.parametrize("state, words", [({"revoked": True}, "revoked"),
                                          ({"days_left": -2, "expired": True}, "expired")])
def test_a_row_this_side_does_not_hold_says_so_as_it_always_did(db, state, words):
    tahs.prove(db, til.host_id_of(db, "box"), **state)
    our_listing(db, V4)

    said = rows_of(rl.render(db, now=NOW, with_prober_api=True))

    assert words in said
    assert "not proved with the probers" not in said and "proved until" not in said


def test_the_words_are_the_windows_own():
    proberproofs = joinbridge.module("proberproofs")
    assert proberproofs.verify_words(V4, "token_not_found").startswith(
        f"{V4} {proberproofs.NOT_PROVED_WITH_THE_PROBERS}: ")


def test_a_row_both_sides_hold_reads_proved(db):
    tahs.prove(db, til.host_id_of(db, "box"))
    our_listing(db, V4)

    said = rows_of(rl.render(db, now=NOW, with_prober_api=True))

    assert "proved until" in said
    assert "not proved with the probers" not in said


def header_count(html, host="edge-01"):
    """The number under "addresses proved" in one server's header."""
    page = html.split(f'id="host-{host}"', 1)[1]
    fact = page.split("addresses proved", 1)[1]
    return int(fact.split('<span class="num">', 1)[1].split("<", 1)[0])


@pytest.mark.parametrize("with_prober_api, held, count", [
    (False, (), 2), (True, (), 0), (True, (OTHER,), 0), (True, (V4,), 1),
    (True, (V4, "2606:50c0:8000::153"), 2)])
def test_the_header_counts_only_what_the_rows_call_proved(tmp_path, with_prober_api,
                                                          held, count):
    """The header's addresses proved counts the rows that read proved
    until, so the two never disagree (the challenge of 2026-10-24)."""
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(tahs.trl.SCHEMA)
    con.commit()
    con.row_factory = sqlite3.Row
    tahs.registry().init(con)
    con.close()
    host = tahs.add_address_host(path, "edge-01")
    tahs.prove(path, host, address=V4, family="v4")
    tahs.prove(path, host, address="2606:50c0:8000::153", family="v6")
    our_listing(path, *held)

    html = rl.render(path, now=NOW, with_prober_api=with_prober_api)

    assert header_count(html) == count
    said = text_of(addresses(html, "edge-01"))
    assert said.count("proved until") == count
