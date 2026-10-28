"""Workspaces: the table, the upgrade onto it, and host storage scoped by it.

    python -m pytest tests/test_workspaces.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle bug in review, these tests are the review. The
ones that carry the argument, in the order a reviewer should read them:

  - the upgrade a real box walks. Rows exist, the columns are added under them,
    and every host and every account is in workspace 1 and still readable.
  - a host in workspace 2 cannot be reached by any read scoped to workspace 1,
    by name or by id, for reading or for writing.
  - `workspace_id=None` still reaches the whole fleet, because the sweeps and
    the prober run with no session and must keep watching every workspace.
"""

import sqlite3

import pytest

from app import accounts, alerts, db, finding_alerts, join, metrics, store

EMAIL = "operator@example.com"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    db.init(connection)
    accounts.init(connection)
    yield connection
    connection.close()


# --- the table ---

def test_init_creates_workspace_one_named_default(con):
    row = db.workspace_by_id(con, db.DEFAULT_WORKSPACE_ID)
    assert row is not None
    assert row["name"] == db.DEFAULT_WORKSPACE_NAME
    assert row["created_at"]


def test_init_is_idempotent(con):
    db.init(con)
    db.init(con)
    accounts.init(con)
    assert len(db.list_workspaces(con)) == 1


def test_init_never_renames_a_workspace_somebody_renamed(con):
    """The ingest runs init on every request. A workspace renamed once must not
    have its name put back a moment later."""
    con.execute("UPDATE workspaces SET name = 'robin' WHERE id = 1")
    con.commit()
    db.init(con)
    assert db.workspace_by_id(con, 1)["name"] == "robin"


def test_create_workspace_returns_a_new_id(con):
    second = db.create_workspace(con, "second")
    assert second != db.DEFAULT_WORKSPACE_ID
    assert db.workspace_by_id(con, second)["name"] == "second"
    assert [row["id"] for row in db.list_workspaces(con)] == [1, second]


@pytest.mark.parametrize("name", ["", "   ", None])
def test_create_workspace_refuses_an_empty_name(con, name):
    with pytest.raises(ValueError):
        db.create_workspace(con, name)


# --- the upgrade a real box walks ---

# The schema exactly as it was on disk before workspaces existed. Written out
# here rather than taken from db.SCHEMA, because the point of this test is what
# a production database already holds, and that is a fixed historical fact
# rather than something that should follow the file as it changes.
PRE_WORKSPACE_SCHEMA = """
CREATE TABLE hosts (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    last_report_at TEXT,
    paused      INTEGER NOT NULL DEFAULT 0,
    auto_named  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE reports (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts(id),
    received_at     TEXT NOT NULL,
    collected_at_unix INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL,
    document        TEXT NOT NULL
);
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    disabled_at   TEXT,
    last_login_at TEXT
);
CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT,
    user_agent   TEXT
);
"""


@pytest.fixture()
def upgraded(tmp_path, monkeypatch):
    """A database written before workspaces existed, holding one host and one
    account, then upgraded exactly the way a deploy upgrades it: init runs.

    The owner has three real hosts and an account on the production box. This is
    the test that says they keep working across the deploy with no manual step.
    """
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "old.db"))
    connection = db.connect()
    connection.executescript(PRE_WORKSPACE_SCHEMA)
    connection.execute(
        "INSERT INTO hosts (name, token_hash, created_at) VALUES (?, ?, ?)",
        ("almabox", store.credential_hash("whp_old"), "2026-08-01T00:00:00+00:00"))
    connection.execute(
        "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
        (EMAIL, accounts.hash_password(PASSWORD), "2026-08-01T00:00:00+00:00"))
    connection.commit()

    db.init(connection)
    accounts.init(connection)
    yield connection
    connection.close()


def test_upgrade_puts_the_existing_host_in_workspace_one(upgraded):
    row = upgraded.execute("SELECT * FROM hosts WHERE name = 'almabox'").fetchone()
    assert row["workspace_id"] == db.DEFAULT_WORKSPACE_ID


def test_upgrade_puts_the_existing_account_in_workspace_one(upgraded):
    user = accounts.get_user_by_email(upgraded, EMAIL)
    assert user is not None
    assert accounts.workspace_of(user) == db.DEFAULT_WORKSPACE_ID


def test_upgrade_leaves_the_existing_host_readable_by_its_workspace(upgraded):
    """Not just stamped with a number: reachable through the read the dashboard
    uses, which is the thing that would actually be broken on the box."""
    names = [row["name"] for row
             in store.list_hosts(upgraded, workspace_id=db.DEFAULT_WORKSPACE_ID)]
    assert names == ["almabox"]
    assert store.active_host_by_name(
        upgraded, "almabox", workspace_id=db.DEFAULT_WORKSPACE_ID) is not None


def test_upgrade_leaves_the_existing_password_working(upgraded):
    assert accounts.authenticate(upgraded, EMAIL, PASSWORD) is not None


def test_upgrade_creates_the_workspace_the_backfilled_rows_point_at(upgraded):
    assert db.workspace_by_id(upgraded, db.DEFAULT_WORKSPACE_ID) is not None


def test_upgrade_is_idempotent(upgraded):
    db.init(upgraded)
    accounts.init(upgraded)
    assert len(db.list_workspaces(upgraded)) == 1
    assert upgraded.execute(
        "SELECT COUNT(*) AS c FROM hosts").fetchone()["c"] == 1


# --- creating in a workspace ---

def test_add_host_defaults_to_workspace_one(con):
    host_id, _ = store.add_host(con, "web1")
    row = store.host_by_id(con, host_id)
    assert row["workspace_id"] == db.DEFAULT_WORKSPACE_ID


def test_add_host_lands_in_the_workspace_it_was_given(con):
    second = db.create_workspace(con, "second")
    host_id, _ = store.add_host(con, "web2", workspace_id=second)
    assert store.host_by_id(con, host_id)["workspace_id"] == second


def test_add_host_refuses_a_workspace_that_does_not_exist(con):
    with pytest.raises(ValueError):
        store.add_host(con, "web3", workspace_id=99)
    assert store.list_hosts(con) == []


def test_create_user_refuses_a_workspace_that_does_not_exist(con):
    with pytest.raises(accounts.AccountError):
        accounts.create_user(con, EMAIL, PASSWORD, workspace_id=99)
    assert accounts.get_user_by_email(con, EMAIL) is None


def test_create_user_lands_in_the_workspace_it_was_given(con):
    second = db.create_workspace(con, "second")
    accounts.create_user(con, EMAIL, PASSWORD, workspace_id=second)
    assert accounts.workspace_of(accounts.get_user_by_email(con, EMAIL)) == second


# --- reading is scoped ---

@pytest.fixture()
def two_workspaces(con):
    """One host in workspace 1, one in workspace 2, and the id of the second."""
    second = db.create_workspace(con, "second")
    store.add_host(con, "mine", workspace_id=db.DEFAULT_WORKSPACE_ID)
    store.add_host(con, "theirs", workspace_id=second)
    return second


def test_list_hosts_in_one_workspace_leaves_the_other_out(con, two_workspaces):
    mine = [row["name"] for row in store.list_hosts(con, workspace_id=1)]
    theirs = [row["name"] for row in store.list_hosts(con, workspace_id=two_workspaces)]
    assert mine == ["mine"]
    assert theirs == ["theirs"]


def test_list_hosts_with_no_workspace_is_the_whole_fleet(con, two_workspaces):
    """The sweeps and the prober run with no session and must see everything."""
    assert sorted(row["name"] for row in store.list_hosts(con)) == ["mine", "theirs"]


def test_a_host_in_another_workspace_is_not_found_by_name(con, two_workspaces):
    assert store.active_host_by_name(con, "theirs", workspace_id=1) is None
    assert store.active_host_by_name(con, "theirs",
                                     workspace_id=two_workspaces) is not None


def test_a_host_in_another_workspace_is_not_found_by_id(con, two_workspaces):
    theirs = store.active_host_by_name(con, "theirs", workspace_id=two_workspaces)
    assert store.host_by_id(con, theirs["id"], workspace_id=1) is None
    assert store.host_by_id(con, theirs["id"],
                            workspace_id=two_workspaces) is not None


def test_a_host_in_another_workspace_cannot_be_revoked(con, two_workspaces):
    assert store.revoke_host(con, "theirs", workspace_id=1) is False
    assert store.active_host_by_name(con, "theirs",
                                     workspace_id=two_workspaces) is not None


def test_a_host_in_another_workspace_cannot_be_paused(con, two_workspaces):
    assert store.pause_host(con, "theirs", True, workspace_id=1) is False
    theirs = store.active_host_by_name(con, "theirs", workspace_id=two_workspaces)
    assert theirs["paused"] == 0


def test_a_host_in_your_own_workspace_still_answers_every_write(con, two_workspaces):
    """The other half of the tests above: scoping refuses the neighbour and
    changes nothing about your own."""
    assert store.pause_host(con, "mine", True, workspace_id=1) is True
    assert store.revoke_host(con, "mine", workspace_id=1) is True


def test_the_credential_lookup_takes_no_workspace(con, two_workspaces):
    """An agent proves which host it is with its own credential. A workspace it
    could pass would be a workspace it could pass wrongly, so the ingest path
    never takes one."""
    _, credential = store.add_host(con, "third", workspace_id=two_workspaces)
    found = store.host_for_credential(con, credential)
    assert found is not None
    assert found["name"] == "third"


def test_host_names_stay_unique_across_workspaces(con, two_workspaces):
    """Documented rather than desired: the pre-workspace UNIQUE index is left
    alone, so a name taken anywhere is taken everywhere. This test exists so
    that changing it is a deliberate act rather than a surprise."""
    with pytest.raises(sqlite3.IntegrityError):
        store.add_host(con, "theirs", workspace_id=1)


# --- reading the column off an account ---

def test_workspace_of_reads_the_column(con):
    second = db.create_workspace(con, "second")
    accounts.create_user(con, EMAIL, PASSWORD, workspace_id=second)
    assert accounts.workspace_of(accounts.get_user_by_email(con, EMAIL)) == second


@pytest.mark.parametrize("value", [None, 0, -1, "2", True, 1.5])
def test_workspace_of_falls_back_to_one_on_anything_unreadable(value):
    """A hand-edited row, or a Row from a connection that never ran init. Both
    answer workspace 1, which is where the migration puts everything, so the
    fallback is the migration's answer rather than a guess."""
    assert accounts.workspace_of({"workspace_id": value}) == db.DEFAULT_WORKSPACE_ID


def test_workspace_of_handles_a_row_without_the_column():
    assert accounts.workspace_of({"email": "x@example.com"}) == db.DEFAULT_WORKSPACE_ID


def test_workspace_of_handles_no_user_at_all():
    assert accounts.workspace_of(None) == db.DEFAULT_WORKSPACE_ID


# ================================== the background jobs stay fleet-wide
#
# The sweeps, the prober selection and the metrics run with no session at all.
# Scoping one of them to a workspace nobody is signed in to would stop it
# watching every other workspace's hosts, which is a monitoring tool failing
# silently, the thing `docs/PRODUCT.md` 4c exists to prevent.
#
# So these are the tests that say the scoping work did *not* reach them.


@pytest.fixture()
def fleet(con):
    """Two hosts, in two workspaces, both long silent and both reporting once
    so there is something for every sweep to have an opinion about."""
    alerts.init(con)
    finding_alerts.init(con)
    second = db.create_workspace(con, "second")
    old = "2026-01-01T00:00:00+00:00"
    for name, workspace in (("mine", db.DEFAULT_WORKSPACE_ID), ("theirs", second)):
        host_id, _ = store.add_host(con, name, workspace_id=workspace)
        store.insert_report(con, host_id, 0, 1,
                            '{"schema_version": 1, "hostname": "' + name + '"}')
        con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                    (old, host_id))
    con.commit()
    return second


def test_the_dead_man_sweep_checks_every_workspace(con, fleet):
    result = alerts.sweep(con)
    assert sorted(result["raised"]) == ["mine", "theirs"]


def test_the_open_alerts_it_raised_cover_every_workspace(con, fleet):
    alerts.sweep(con)
    names = {row["host_name"] for row in alerts.pending_notifications(con)}
    assert names == {"mine", "theirs"}


def test_the_join_engine_still_walks_the_whole_fleet(con, fleet):
    """`join.fleet_findings` feeds the finding-alert sweep, which has no
    session either."""
    assert sorted(host.host_name for host in join.fleet_findings(con)) == [
        "mine", "theirs"]


def test_the_silence_listing_with_no_workspace_is_the_whole_fleet(con, fleet):
    finding_alerts.mute_host(con, "mine")
    finding_alerts.mute_host(con, "theirs", workspace_id=fleet)
    assert len(finding_alerts.list_silences(con)) == 2


def test_the_metrics_cover_every_workspace(con, fleet):
    """`/metrics` is scraped by whatever already watches the estate, with no
    session to read. It stays fleet-wide, and that is a deliberate choice
    rather than an oversight: a scraper is watching the box."""
    body = metrics.render(con)
    assert 'host="mine"' in body
    assert 'host="theirs"' in body


def test_the_prober_selects_hosts_from_every_workspace(con, fleet):
    """The prober runs on a timer with no session. Scoping it to workspace 1
    would silently stop probing every other workspace's servers."""
    from app import prober_cli
    covered, _left_out = prober_cli._selected(con)
    assert sorted(host["name"] for host in covered) == ["mine", "theirs"]


def test_the_ingest_credential_path_is_not_scoped(con, fleet):
    """An agent proves which host it is with its own credential. There is no
    workspace on that path and there must not be one."""
    _id, credential = store.add_host(con, "third", workspace_id=fleet)
    assert store.host_for_credential(con, credential)["name"] == "third"
