"""A server made by the Add server window is shown once its agent has reported.

The owner, 2026-09-20: a server belongs in the list once the agent is installed
and reporting, not when the button is clicked. Clicking the Agent card makes
the host row at
once, because the credential the install command carries lives on that row
and the agent's first report is authenticated against it. So the row stays.
What changed is that nothing shows it: no Fleet row, no page, no count, until
the first report. A window opened and closed leaves nothing behind on the
screen, which is also where the ghost rows on his fleet came from.

Told apart by two facts the row already holds: it was named by the window and
not by a person (`auto_named`), and it has never reported. A server a person
named, with `hosts_cli add`, is theirs to see before it reports, as before.
"""
import pathlib
import sqlite3
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW


@pytest.fixture()
def db(tmp_path):
    path = tmp_path / "cp.db"
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    return str(path)


def made_by_the_window(db, name):
    trl.add_host(db, name, [])
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET auto_named = 1 WHERE name = ?", (name,))
    con.commit()
    con.close()


def fleet(html):
    return html.split('id="fleet"', 1)[1].split('<div class="wrap view"', 1)[0]


def test_a_server_the_window_made_is_nowhere_until_it_reports(db):
    trl.reporting(db, "media-01", trl.document(listening=[trl.SSHD]))
    made_by_the_window(db, "new-4ebda1")
    html = rl.render(db, now=NOW)
    assert "new-4ebda1" not in html
    assert 'data-host="media-01"' in fleet(html)


def test_a_fleet_of_only_such_servers_is_the_empty_fleet(db):
    made_by_the_window(db, "new-4ebda1")
    html = rl.render(db, now=NOW)
    assert "new-4ebda1" not in html
    assert "No servers yet" in fleet(html)


def test_it_is_on_the_fleet_the_moment_it_has_reported(db):
    trl.reporting(db, "web-01", trl.document(listening=[trl.SSHD]))
    con = sqlite3.connect(db)
    con.execute("UPDATE hosts SET auto_named = 1 WHERE name = 'web-01'")
    con.commit()
    con.close()
    html = rl.render(db, now=NOW)
    assert 'data-host="web-01"' in fleet(html)
    assert 'id="host-web-01"' in html


def test_a_server_a_person_named_is_shown_before_it_reports_as_before(db):
    trl.add_host(db, "mail-relay", [])
    html = rl.render(db, now=NOW)
    assert 'data-host="mail-relay"' in fleet(html)
    assert "not watched" in fleet(html)


def test_it_is_in_no_count(db):
    trl.reporting(db, "media-01", trl.document(listening=[trl.SSHD]))
    before = rl.render(db, now=NOW)
    made_by_the_window(db, "new-4ebda1")
    after = rl.render(db, now=NOW)
    assert fleet(before) == fleet(after)


def test_an_address_server_is_never_hidden(db):
    """It has no agent, so "has never reported" is its whole life."""
    con = sqlite3.connect(db)
    con.execute("INSERT INTO hosts (name, token_hash, kind, created_at, auto_named)"
                " VALUES ('outside-only', NULL, 'address', ?, 1)", (NOW.isoformat(),))
    con.commit()
    con.close()
    assert 'data-host="outside-only"' in fleet(rl.render(db, now=NOW))


def test_a_database_from_before_the_column_shows_every_server(tmp_path):
    """The renderer meets databases older than `auto_named`. With no column
    there is nothing to tell a window's server by, so nothing is hidden."""
    path = str(tmp_path / "old.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA.replace(" auto_named INTEGER NOT NULL DEFAULT 0,", ""))
    con.execute("INSERT INTO hosts (name, token_hash, created_at) VALUES ('old', 'h', ?)",
                (NOW.isoformat(),))
    con.commit()
    con.close()
    assert 'data-host="old"' in fleet(rl.render(path, now=NOW))
