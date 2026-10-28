"""A server's Addresses lists each address once: its live proof where it has
one, and otherwise the newest proof it had (docs/RECORD.md 4.393, 4.395).

Every proof the registry ever recorded for an address was its own row. So an
address whose proof ran out and was proved again stood twice, "proved until"
and "expired", and both rows offered Revoke, because a row was called live
when its address was (measured 2026-10-06).

The registry is not touched: what a proof is and when it ends stays its own.
This is which of its rows the page draws.

    Run from site/: python3 -m pytest app/test_address_rows_one_per_address.py
"""
import pathlib
import re
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
import test_integrations_live as til  # noqa: E402
import test_address_hosts_screen as tahs  # noqa: E402

NOW = trl.NOW
FIRST = tahs.V4
SECOND = "185.199.109.153"
SIXTH = "2606:50c0:8000::153"


@pytest.fixture()
def db(tmp_path):
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.reporting(path, "box", trl.document(listening=[trl.SSHD]))
    return path


def prove(db, **how):
    tahs.prove(db, til.host_id_of(db, "box"), **how)


def text_of(html):
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S)).split())


def rows(db):
    """The address rows as (address, the first word of what it says, whether
    it offers Revoke)."""
    html = rl.render(db, now=NOW)
    section = html.split('id="t-box-settings"', 1)[1]
    section = section.split('<div class="hstage h-addresses">', 1)[1].split('<div class="hstage ', 1)[0]
    out = []
    for row in section.split('<div class="li">')[1:]:
        found = re.search(r'<b class="mono num">([^<]+)</b><small class="dim">([^<]*)</small>', row)
        if not found:
            continue        # not a proved address's row
        said = found.group(2).split(", ", 1)[-1]
        out.append((found.group(1), said.split(" ")[0], "js-addr-revoke" in row))
    return out


def test_an_address_proved_again_after_it_ran_out_is_one_row_the_live_one(db):
    prove(db, days_left=-2, expired=True)
    prove(db)
    assert rows(db) == [(FIRST, "proved", True)]


def test_an_address_proved_again_after_a_revoke_is_one_row_the_live_one(db):
    prove(db, revoked=True)
    prove(db)
    assert rows(db) == [(FIRST, "proved", True)]


def test_an_address_whose_only_proof_ran_out_stays_listed_without_revoke(db):
    prove(db, days_left=-2, expired=True)
    assert rows(db) == [(FIRST, "expired", False)]


def test_an_address_that_was_revoked_stays_listed_without_revoke(db):
    prove(db, revoked=True)
    assert rows(db) == [(FIRST, "revoked", False)]


def test_an_address_that_ran_out_twice_is_still_one_row(db):
    prove(db, days_left=-9, expired=True)
    prove(db, days_left=-2, expired=True)
    assert rows(db) == [(FIRST, "expired", False)]


def test_two_addresses_are_two_rows(db):
    prove(db)
    prove(db, address=SECOND, days_left=-2, expired=True)
    assert sorted(rows(db)) == [(FIRST, "proved", True), (SECOND, "expired", False)]


def test_a_v4_and_a_v6_address_are_each_their_own_row(db):
    prove(db)
    prove(db, address=SIXTH, family="v6")
    assert sorted(rows(db)) == sorted([(FIRST, "proved", True), (SIXTH, "proved", True)])


def test_only_a_live_row_offers_revoke(db):
    prove(db, days_left=-2, expired=True)
    prove(db)
    prove(db, address=SECOND, revoked=True)
    prove(db, address=SIXTH, family="v6", days_left=-2, expired=True)
    got = rows(db)
    assert len(got) == 3
    for address, word, revoke in got:
        assert revoke is (word == "proved"), (address, word)


def test_a_server_with_no_proof_has_no_address_row(db):
    assert rows(db) == []


def test_the_registry_still_holds_every_proof(db):
    """Nothing is deleted to make the list short."""
    prove(db, days_left=-2, expired=True)
    prove(db)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    # Asked of the registry: no other file reads its tables.
    held = tahs.registry().list_authorizations(con)
    con.close()
    assert len(held) == 2
    assert len(rows(db)) == 1
