"""Host administration from the terminal.

    python -m pytest tests/test_hosts_cli.py

This command had no tests of its own until workspaces gave it an argument.
What is covered is the argument and the credential, in that order: every
subcommand defaults to workspace 1 so nothing the owner runs today changes, a
host in another workspace cannot be listed or revoked from this one, and the
credential is printed once and stored only as a hash.
"""

import pytest

from app import db, hosts_cli, store

WORKSPACE_FLAG_DEFAULT = db.DEFAULT_WORKSPACE_ID


@pytest.fixture()
def cli(tmp_path, monkeypatch):
    """Run the command against a temporary database, returning its exit code."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))

    def run(*argv):
        monkeypatch.setattr("sys.argv", ["hosts"] + list(argv))
        return hosts_cli.main()
    return run


@pytest.fixture()
def con(cli):
    """A connection to the database the command is pointed at. Takes `cli` so
    the environment variable is already set."""
    connection = db.connect()
    db.init(connection)
    yield connection
    connection.close()


# --- the default ---

def test_add_defaults_to_workspace_one(cli, con):
    assert cli("add", "web1") == 0
    assert store.active_host_by_name(
        con, "web1", workspace_id=db.DEFAULT_WORKSPACE_ID) is not None


def test_add_prints_the_credential_once_and_stores_only_its_hash(cli, con, capsys):
    assert cli("add", "web1") == 0
    printed = capsys.readouterr().out
    credential = [word for word in printed.split()
                  if word.startswith(store.CREDENTIAL_PREFIX)][0]
    row = con.execute("SELECT token_hash FROM hosts WHERE name = 'web1'").fetchone()
    assert row["token_hash"] == store.credential_hash(credential)
    assert credential not in str(dict(row))


def test_add_refuses_a_workspace_that_does_not_exist(cli, con, capsys):
    assert cli("add", "web1", "--workspace", "99") == 1
    assert "no workspace 99" in capsys.readouterr().err
    assert store.list_hosts(con) == []


# --- naming a workspace ---

def test_add_puts_the_host_in_the_workspace_it_was_given(cli, con):
    second = db.create_workspace(con, "second")
    assert cli("add", "web2", "--workspace", str(second)) == 0
    assert store.active_host_by_name(con, "web2", workspace_id=second) is not None
    assert store.active_host_by_name(con, "web2", workspace_id=1) is None


def test_the_listing_shows_one_workspace_at_a_time(cli, con, capsys):
    second = db.create_workspace(con, "second")
    cli("add", "mine")
    cli("add", "theirs", "--workspace", str(second))
    capsys.readouterr()

    assert cli("list") == 0
    mine = capsys.readouterr().out
    assert "mine" in mine
    assert "theirs" not in mine

    assert cli("list", "--workspace", str(second)) == 0
    theirs = capsys.readouterr().out
    assert "theirs" in theirs
    assert "mine" not in theirs


def test_a_host_in_another_workspace_cannot_be_revoked(cli, con, capsys):
    second = db.create_workspace(con, "second")
    cli("add", "theirs", "--workspace", str(second))
    capsys.readouterr()
    assert cli("revoke", "theirs") == 1
    assert "no active host named 'theirs'" in capsys.readouterr().err
    assert store.active_host_by_name(con, "theirs", workspace_id=second) is not None


def test_a_host_is_revoked_from_its_own_workspace(cli, con):
    second = db.create_workspace(con, "second")
    cli("add", "theirs", "--workspace", str(second))
    assert cli("revoke", "theirs", "--workspace", str(second)) == 0
    assert store.active_host_by_name(con, "theirs", workspace_id=second) is None


def test_a_duplicate_name_is_refused_rather_than_crashing(cli, con, capsys):
    """Host names are unique across the whole database, not per workspace, so
    this is refused from a second workspace too. Documented rather than
    desired: changing it means rebuilding the table."""
    second = db.create_workspace(con, "second")
    assert cli("add", "web1") == 0
    capsys.readouterr()
    assert cli("add", "web1", "--workspace", str(second)) == 1
    assert "could not add" in capsys.readouterr().err


# --- prune the never-reported ghosts ---

def _report(con, name):
    """Give a host one stored report, so it counts as having reported."""
    row = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ("2026-08-30T12:00:00+00:00", row["id"]))
    con.commit()


def test_prune_deletes_only_never_reported_agent_hosts(cli, con):
    store.add_host(con, "ghost-a")
    store.add_host(con, "ghost-b")
    store.add_host(con, "talker")
    _report(con, "talker")
    store.add_address_host(con, "addr")   # never probed, but not a ghost
    assert cli("prune") == 0
    names = {r["name"] for r in store.list_hosts(con)}
    assert names == {"talker", "addr"}, names


def test_prune_says_when_there_is_nothing_to_do(cli, con, capsys):
    store.add_host(con, "talker")
    _report(con, "talker")
    assert cli("prune") == 0
    assert "nothing to prune" in capsys.readouterr().out


def test_prune_stays_in_its_workspace(cli, con):
    con.execute("INSERT INTO workspaces (id, name, created_at)"
                " VALUES (2, 'second', '2026-08-30T12:00:00+00:00')")
    con.commit()
    store.add_host(con, "mine-ghost", workspace_id=1)
    store.add_host(con, "their-ghost", workspace_id=2)
    assert cli("prune") == 0   # defaults to workspace 1
    names = {r["name"] for r in store.list_hosts(con)}
    assert names == {"their-ghost"}, names


# --- delete a revoked host with everything stored about it ---

def test_delete_takes_a_revoked_host_and_refuses_a_live_one(cli, con, capsys):
    store.add_host(con, "old-box")
    _report(con, "old-box")
    store.add_host(con, "live-box")
    assert cli("delete", "old-box") == 1          # still live: revoke first
    assert "revoke it first" in capsys.readouterr().err
    assert cli("revoke", "old-box") == 0
    assert cli("delete", "old-box") == 0
    assert "old-box deleted" in capsys.readouterr().out
    names = {r["name"] for r in store.list_hosts(con)}
    assert names == {"live-box"}, names


def test_delete_stays_in_its_workspace(cli, con):
    con.execute("INSERT INTO workspaces (id, name, created_at)"
                " VALUES (2, 'second', '2026-09-14T12:00:00+00:00')")
    con.commit()
    store.add_host(con, "theirs", workspace_id=2)
    assert store.revoke_host(con, "theirs", workspace_id=2)
    assert cli("delete", "theirs") == 1           # defaults to workspace 1
    assert cli("delete", "theirs", "--workspace", "2") == 0
    assert store.list_hosts(con) == []


def test_prune_takes_a_ghosts_own_rows_with_it(cli, con):
    """The box refused the first prune on 2026-09-15 with "FOREIGN KEY
    constraint failed": a never-reported host still gets a probe run row
    from the lanes, so deleting the host row alone cannot work. The ghost's
    rows go first, from every table that can hold one."""
    from app import prober, scan
    prober.init(con)
    scan.init(con)
    store.add_host(con, "ghost")
    ghost = con.execute("SELECT id FROM hosts WHERE name = 'ghost'").fetchone()["id"]
    con.execute("INSERT INTO probe_runs (host_id, vantage, started_at, finished_at)"
                " VALUES (?, 'probe1', '2026-09-15T10:00:00+00:00', '2026-09-15T10:00:01+00:00')",
                (ghost,))
    con.execute("INSERT INTO scan_requests (host_id, requested_at) VALUES (?, '2026-09-15T10:00:00+00:00')",
                (ghost,))
    con.commit()
    assert cli("prune") == 0
    assert store.list_hosts(con) == []
    assert con.execute("SELECT count(*) FROM probe_runs").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM scan_requests").fetchone()[0] == 0
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []


def test_a_table_the_list_does_not_know_stops_the_prune_whole(cli, con):
    store.add_host(con, "ghost-a")
    store.add_host(con, "ghost-b")
    con.execute("CREATE TABLE forgotten (id INTEGER PRIMARY KEY,"
                " host_id INTEGER NOT NULL REFERENCES hosts(id))")
    con.execute("INSERT INTO forgotten (host_id) VALUES"
                " ((SELECT id FROM hosts WHERE name = 'ghost-b'))")
    con.commit()
    import sqlite3
    with pytest.raises(sqlite3.IntegrityError):
        store.prune_never_reported(con)
    # neither ghost went: the prune is one transaction
    assert {r["name"] for r in store.list_hosts(con)} == {"ghost-a", "ghost-b"}
