"""A host may have no credential since 2026-08-26 (RECORD 4.104): an address
host is watched from outside only. This is the review of the one-time hosts
rebuild that makes that possible on a database from before, and of the store
functions that create and refuse such hosts."""
import sqlite3

import pytest

from app import db, store

# The hosts table exactly as every database created before 2026-08-26 has
# it, so the rebuild is tested against the real starting point rather than
# against whatever SCHEMA says today.
HOSTS_BEFORE = """
CREATE TABLE workspaces (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE hosts (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    token_hash  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT,
    last_report_at TEXT,
    paused      INTEGER NOT NULL DEFAULT 0,
    auto_named  INTEGER NOT NULL DEFAULT 0,
    workspace_id INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    received_at TEXT NOT NULL, collected_at_unix INTEGER NOT NULL,
    schema_version INTEGER NOT NULL, document TEXT NOT NULL);
CREATE INDEX idx_hosts_workspace ON hosts(workspace_id, name);
"""


def token_hash_is_required(con) -> bool:
    for row in con.execute("PRAGMA table_info(hosts)"):
        if row[1] == "token_hash":
            return bool(row[3])
    raise AssertionError("no token_hash column")


@pytest.fixture()
def old_db(tmp_path):
    """A database as it stands on the box before this change: two hosts, a
    report on one, a workspace row, and NOT NULL on the credential."""
    path = tmp_path / "old.db"
    con = db.connect(str(path))
    con.executescript(HOSTS_BEFORE)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (1, 'w', 't0')")
    con.execute("INSERT INTO hosts (id, name, token_hash, created_at, revoked_at,"
                " last_report_at, paused, auto_named, workspace_id)"
                " VALUES (7, 'alpha', 'hash-a', 't1', NULL, 't9', 1, 0, 1)")
    con.execute("INSERT INTO hosts (id, name, token_hash, created_at, revoked_at,"
                " last_report_at, paused, auto_named, workspace_id)"
                " VALUES (9, 'beta', 'hash-b', 't2', 't3', NULL, 0, 1, 1)")
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix,"
                " schema_version, document) VALUES (7, 't9', 1, 1, '{}')")
    con.commit()
    con.close()
    return str(path)


def rows(con):
    return [tuple(r) for r in con.execute(
        "SELECT id, name, token_hash, created_at, revoked_at, last_report_at,"
        " paused, auto_named, workspace_id FROM hosts ORDER BY id")]


def test_the_rebuild_keeps_every_row_and_every_foreign_key(old_db):
    con = db.connect(old_db)
    assert token_hash_is_required(con)
    before = rows(con)
    db.init(con)
    assert not token_hash_is_required(con)
    assert rows(con) == before, "a row changed in the rebuild"
    # ids survived, so the report still points at its host
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    assert con.execute("SELECT host_id FROM reports").fetchone()[0] == 7
    # the new column arrived with its default on the old rows
    assert [r[0] for r in con.execute("SELECT kind FROM hosts ORDER BY id")] == \
        [db.HOST_KIND_AGENT, db.HOST_KIND_AGENT]
    # the index the fleet queries lean on came back
    names = [r[1] for r in con.execute("PRAGMA index_list(hosts)")]
    assert "idx_hosts_workspace" in names
    # and foreign keys are back on for the rest of the process
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    con.close()


def test_a_second_init_finds_nothing_to_rebuild(old_db):
    con = db.connect(old_db)
    db.init(con)
    after_first = rows(con)
    db.init(con)
    assert rows(con) == after_first
    assert not token_hash_is_required(con)
    con.close()


def test_a_fresh_database_never_needs_the_rebuild(tmp_path):
    con = db.connect(str(tmp_path / "fresh.db"))
    db.init(con)
    assert not token_hash_is_required(con)
    assert "kind" in [r[1] for r in con.execute("PRAGMA table_info(hosts)")]
    con.close()


def test_the_rebuild_refuses_to_lose_a_referenced_host(old_db):
    """If the copy could ever drop a row a report points at, the rebuild must
    roll back rather than commit a database with a dangling foreign key."""
    con = db.connect(old_db)
    original = db.HOSTS_TABLE_BODY
    # sabotage: a rebuilt table that cannot hold the existing ids. Patching the
    # body reaches the rebuild and not SCHEMA, which is built from it once at
    # import, so only the copy under test is broken.
    db.HOSTS_TABLE_BODY = original.replace(
        "id          INTEGER PRIMARY KEY",
        "id          INTEGER PRIMARY KEY CHECK (id < 9)")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            db.init(con)
    finally:
        db.HOSTS_TABLE_BODY = original
    # nothing changed: the old table, its rows and its constraint are intact
    assert token_hash_is_required(con)
    assert len(rows(con)) == 2
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    con.close()


# ---------------------------------------------------------------- the store

@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "s.db"))
    db.init(c)
    yield c
    c.close()


def test_an_agent_host_is_marked_as_one(con):
    host_id, credential = store.add_host(con, "box")
    row = con.execute("SELECT kind, token_hash FROM hosts WHERE id = ?", (host_id,)).fetchone()
    assert row["kind"] == db.HOST_KIND_AGENT
    assert row["token_hash"] == store.credential_hash(credential)


def test_an_address_host_has_no_credential(con):
    host_id = store.add_address_host(con, "outside-only")
    row = con.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    assert row["kind"] == db.HOST_KIND_ADDRESS
    assert row["token_hash"] is None
    assert row["auto_named"] == 0


def test_two_address_hosts_may_both_have_no_credential(con):
    """UNIQUE on token_hash must not stop a second NULL, or the second address
    host could never be created."""
    store.add_address_host(con, "one")
    store.add_address_host(con, "two")
    assert con.execute("SELECT COUNT(*) FROM hosts WHERE token_hash IS NULL").fetchone()[0] == 2


def test_an_address_host_can_never_authenticate(con):
    """Nothing holds a credential for it, so no credential may ever match it,
    including the degenerate ones."""
    store.add_address_host(con, "outside-only")
    for candidate in ("", "None", "null", store.CREDENTIAL_PREFIX):
        assert store.host_for_credential(con, candidate) is None


@pytest.mark.parametrize("bad", ["", "   ", "Has Space", "-leading", "x" * 33])
def test_an_address_host_name_is_checked_like_an_agent_host_name(con, bad):
    with pytest.raises(ValueError):
        store.add_address_host(con, bad)


def test_an_address_host_name_must_be_free(con):
    store.add_host(con, "taken")
    with pytest.raises(sqlite3.IntegrityError):
        store.add_address_host(con, "taken")


def test_an_address_host_needs_a_real_workspace(con):
    with pytest.raises(ValueError):
        store.add_address_host(con, "outside-only", workspace_id=42)


def test_an_address_host_lists_and_pauses_and_revokes_like_any_host(con):
    store.add_address_host(con, "outside-only")
    assert [r["name"] for r in store.list_hosts(con)] == ["outside-only"]
    assert store.pause_host(con, "outside-only", True)
    assert store.active_host_by_name(con, "outside-only")["paused"] == 1
    assert store.revoke_host(con, "outside-only")
    assert store.active_host_by_name(con, "outside-only") is None


# ------------------------------------- the table refuses a row that mixes kinds
#
# Until 2026-08-27 the two kinds were an invariant in `store.py` and nothing
# else. All three rows below were inserted successfully against the table as it
# stood, which is why these are tests and not comments.

@pytest.fixture()
def fresh(tmp_path):
    con = db.connect(str(tmp_path / "fresh.db"))
    db.init(con)
    yield con
    con.close()


def test_an_agent_host_cannot_exist_without_a_credential(fresh):
    with pytest.raises(sqlite3.IntegrityError):
        fresh.execute(
            "INSERT INTO hosts (name, token_hash, created_at, kind)"
            " VALUES ('web1', NULL, 't', ?)", (db.HOST_KIND_AGENT,))


def test_an_address_host_cannot_hold_a_credential(fresh):
    """The one that matters most. An address host with a credential is a row
    the ingest could authenticate, for a machine that runs no agent."""
    with pytest.raises(sqlite3.IntegrityError):
        fresh.execute(
            "INSERT INTO hosts (name, token_hash, created_at, kind)"
            " VALUES ('edge-router', 'somehash', 't', ?)", (db.HOST_KIND_ADDRESS,))


def test_a_kind_nobody_defined_is_refused(fresh):
    """`range` is the obvious next word somebody reaches for, and PRODUCT 3a
    says ranges need a proof model that does not exist. A row carrying it
    would be probed as neither kind."""
    with pytest.raises(sqlite3.IntegrityError):
        fresh.execute(
            "INSERT INTO hosts (name, token_hash, created_at, kind)"
            " VALUES ('block1', 'somehash', 't', 'range')")


def test_the_kinds_the_store_writes_are_both_accepted(fresh):
    """The CHECK has to admit everything the product actually creates, or it
    is a constraint that breaks the feature it was meant to protect."""
    agent_id, _ = store.add_host(fresh, "web1")
    address_id = store.add_address_host(fresh, "edge-router")
    kinds = {row[0]: row[1] for row in fresh.execute("SELECT id, kind FROM hosts")}
    assert kinds[agent_id] == db.HOST_KIND_AGENT
    assert kinds[address_id] == db.HOST_KIND_ADDRESS


def test_the_check_survives_an_update_that_does_not_touch_either_column(fresh):
    """Pause and revoke both UPDATE a host row, and a CHECK is re-evaluated
    on every UPDATE. If it were written wrongly these would start failing on
    rows that are perfectly valid."""
    store.add_address_host(fresh, "edge-router")
    assert store.pause_host(fresh, "edge-router", True) is True
    assert store.revoke_host(fresh, "edge-router") is True


def test_an_upgraded_database_gets_the_check_too(old_db):
    """A CHECK on a fresh database and not on an upgraded one is worse than no
    CHECK, because the box that matters is the upgraded one."""
    con = db.connect(old_db)
    db.init(con)
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO hosts (name, token_hash, created_at, kind)"
                    " VALUES ('edge-router', 'somehash', 't', ?)",
                    (db.HOST_KIND_ADDRESS,))
    assert len(rows(con)) == 2
    con.close()


def test_a_database_already_migrated_once_still_gains_the_check(tmp_path):
    """The box may already have run the first version of this migration, which
    dropped NOT NULL and added no CHECK. It needs one more rebuild, and then it
    must settle."""
    path = str(tmp_path / "half.db")
    con = db.connect(path)
    con.executescript(HOSTS_BEFORE.replace("token_hash  TEXT NOT NULL UNIQUE",
                                           "token_hash  TEXT UNIQUE")
                      .replace("workspace_id INTEGER NOT NULL DEFAULT 1\n);",
                               "workspace_id INTEGER NOT NULL DEFAULT 1,\n"
                               "    kind TEXT NOT NULL DEFAULT 'agent'\n);"))
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (1, 'w', 't0')")
    con.execute("INSERT INTO hosts (id, name, token_hash, created_at, kind)"
                " VALUES (7, 'alpha', 'hash-a', 't1', 'agent')")
    con.commit()
    assert not token_hash_is_required(con)          # already half migrated
    assert db._hosts_needs_rebuild(con) is True     # and still missing the CHECK

    db.init(con)
    assert db._hosts_needs_rebuild(con) is False    # settles after one pass
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO hosts (name, token_hash, created_at, kind)"
                    " VALUES ('edge', 'h', 't', 'address')")
    assert [r[0] for r in con.execute("SELECT id FROM hosts")] == [7]
    con.close()


# -------------------------------------- the rebuild refuses to lose things

def test_a_column_the_rebuild_does_not_carry_stops_it(old_db):
    """The copy names its columns, so a column absent from HOST_COLUMNS would
    be dropped with its data and nothing would say so. Measured against the
    previous version of this rebuild: an extra column and its values were gone
    afterwards, no error raised."""
    con = db.connect(old_db)
    con.execute("ALTER TABLE hosts ADD COLUMN owner_email TEXT")
    con.execute("UPDATE hosts SET owner_email = 'a@example.com' WHERE id = 7")
    con.commit()

    with pytest.raises(RuntimeError) as raised:
        db.init(con)
    assert "owner_email" in str(raised.value)

    # nothing moved: the old table, its rows and its extra column are intact
    assert token_hash_is_required(con)
    assert len(rows(con)) == 2
    assert con.execute("SELECT owner_email FROM hosts WHERE id = 7"
                       ).fetchone()[0] == "a@example.com"
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    con.close()


def test_an_index_the_rebuild_never_heard_of_comes_back(old_db):
    """Dropping the table drops its indexes. Only idx_hosts_workspace was put
    back by name, so any other one was lost. A missing index is not a wrong
    answer, which is why nothing failed and nobody would have found out."""
    con = db.connect(old_db)
    con.execute("CREATE INDEX idx_hosts_last_report ON hosts(last_report_at)")
    con.commit()

    db.init(con)

    names = {row[0] for row in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'index'"
        " AND tbl_name = 'hosts'")}
    assert "idx_hosts_last_report" in names
    assert "idx_hosts_workspace" in names
    assert len(rows(con)) == 2
    con.close()
