"""Delete for a removed server, and the two proofs that come before it.

    Run from controlplane: .venv/bin/python -m pytest tests/test_delete_host.py

Remove revokes and keeps the row. Delete is the second act, on a removed
server only, and takes the row with every row stored about it (the owner,
2026-09-13, docs/RECORD.md 4.179). Foreign keys are on and nothing cascades,
so the danger is not a dangling row but a delete that forgets a table and
fails, or one that is written table by table and leaves a half. The two
proofs here are the ones the Decisions card asked for before the feature:

- one test fills every table that can hold a host's row, deletes the host,
  and asserts `foreign_key_check` is empty and no table holds anything,
- one walks the schema, every foreign key and every `host_id` column, and
  fails if a table can reach hosts that `store.HOST_TABLES` does not name,
  so a table added next month cannot orphan quietly.

The tables are found from the schema rather than listed here again, so the
test and the list cannot drift apart without one of them failing.
"""

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import (accounts, alerts, authz, channels, cvedismiss, cvetell, db, displayname, finding_alerts,
                 hetzner,
                 identities, ingest, intent, onetime, prober, rarelydismiss, scan, store, tags,
                 vantages)
from test_admin import in_workspace, signed_in_operator

# Every module that creates tables. Each init is additive and idempotent, so
# running all of them is the whole schema the box has.
MODULES = (db, accounts, authz, alerts, channels, intent, hetzner, identities,
           finding_alerts, prober, onetime, scan, vantages, tags, displayname,
           rarelydismiss, cvetell, cvedismiss)


def whole_schema(con):
    for module in MODULES:
        module.init(con)


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    whole_schema(connection)
    yield connection
    connection.close()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    whole_schema(connection)
    connection.close()
    return TestClient(ingest.app)


# ------------------------------------------------------------- the schema walk

def tables(con):
    return [r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
        " AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def foreign_keys(con, table):
    """(column, parent table, parent column) for every foreign key of a table."""
    return [(r["from"], r["table"], r["to"])
            for r in con.execute(f"PRAGMA foreign_key_list({table})")]


def columns(con, table):
    return con.execute(f"PRAGMA table_info({table})").fetchall()


def reaches_hosts(con, table, seen=()):
    """Whether a row of this table can point at a host, through one foreign
    key or a chain of them."""
    if table in seen:
        return False
    for _column, parent, _to in foreign_keys(con, table):
        if parent == "hosts" or reaches_hosts(con, parent, seen + (table,)):
            return True
    return False


def host_tables(con):
    """Every table whose rows can be one host's: through a foreign key to
    hosts, through a chain of them, or through a column named host_id with
    no REFERENCES clause, which is what ALTER TABLE leaves."""
    found = set()
    for table in tables(con):
        if table == "hosts":
            continue
        by_name = any(c["name"] == "host_id" for c in columns(con, table))
        if by_name or reaches_hosts(con, table):
            found.add(table)
    return found


def fill(con, table, host_id, made):
    """Put one row in `table` that belongs to the host, and return its id.

    Every NOT NULL column without a default gets a value of its type. A
    foreign key gets the parent's row, made first, so a table two steps from
    hosts gets a chain that really reaches the host. The row id comes back
    so a child can point at it.
    """
    if table in made:
        return made[table]
    values = {}
    for column, parent, _to in foreign_keys(con, table):
        values[column] = host_id if parent == "hosts" else fill(con, parent, host_id, made)
    keys = [c for c in columns(con, table) if c["pk"]]
    for c in columns(con, table):
        name = c["name"]
        if name in values:
            continue
        if name == "host_id":
            values[name] = host_id
        elif c["pk"] and c["type"].upper() == "INTEGER" and len(keys) == 1:
            continue    # the rowid, SQLite assigns it. Only a lone integer
                        # key is one: a column of a composite key is data.
        elif c["notnull"] and c["dflt_value"] is None:
            values[name] = 1 if c["type"].upper() in ("INTEGER", "REAL") else "x"
    names = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    cur = con.execute(f"INSERT INTO {table} ({names}) VALUES ({marks})",
                      tuple(values.values()))
    made[table] = cur.lastrowid
    return made[table]


def fill_every_table(con, host_id):
    made = {}
    for table in sorted(host_tables(con)):
        fill(con, table, host_id, made)
    con.commit()


def counts(con):
    return {table: con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
            for table in sorted(host_tables(con))}


def removed_host(con, name="box", workspace_id=1):
    host_id, _credential = store.add_host(con, name, workspace_id=workspace_id)
    assert store.revoke_host(con, name, workspace_id=workspace_id)
    return host_id


# -------------------------------------------------------------- the two proofs

def test_the_walk_finds_the_seventeen_tables_the_card_named_and_the_one_since(con):
    """The walk is only a proof if it finds what is known to be there. The
    card of 2026-09-13 named seventeen, and authz_challenges is the one the
    foreign keys alone would miss. probe_latest is the eighteenth, since
    2026-09-20 (docs/RECORD.md 4.192), host_tags and host_display_names the
    nineteenth and twentieth, since 2026-10-02, and rarely_dismissed the
    twenty-first, since 2026-10-03. cve_started, cve_told and cve_dismissed
    came with the CVE check: what it has looked at and told for a server,
    and what a person dismissed its mark for."""
    assert host_tables(con) == {
        "reports", "report_digests", "authorizations", "authz_challenges",
        "alerts", "alert_deliveries", "port_intents", "port_acknowledgements",
        # Who was told an agent stopped reporting, since 2026-10-12. The walk
        # finds it through the alert it points at.
        "silence_told",
        "port_names", "first_looks", "finding_changes", "finding_states",
        "alert_silences", "probe_runs", "probe_results", "probe_tls",
        "scan_requests", "probe_latest", "host_tags", "host_display_names",
        "rarely_dismissed", "cve_started", "cve_told", "cve_dismissed"}


def test_every_table_that_can_hold_a_hosts_row_is_on_the_delete_list(con):
    """A table added later that references hosts, or carries a host_id, has
    to be named in store.HOST_TABLES or this fails, by name."""
    named = {table for table, _where in store.HOST_TABLES}
    assert host_tables(con) == named, {
        "not on the list": host_tables(con) - named,
        "on the list but not in the schema": named - host_tables(con)}


def test_delete_takes_every_row_of_the_host_and_leaves_no_dangling_key(con):
    host_id = removed_host(con)
    fill_every_table(con, host_id)
    before = counts(con)
    assert all(n >= 1 for n in before.values()), before

    assert store.delete_host(con, "box") is True

    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    assert counts(con) == {table: 0 for table in before}
    assert con.execute("SELECT count(*) FROM hosts").fetchone()[0] == 0


def test_a_table_the_list_does_not_know_stops_the_delete_whole(con):
    """Foreign keys on, nothing cascading: a table the list forgot makes the
    delete fail loudly, and the failure leaves everything as it was rather
    than a host half gone."""
    host_id = removed_host(con)
    fill_every_table(con, host_id)
    con.execute("CREATE TABLE forgotten (id INTEGER PRIMARY KEY,"
                " host_id INTEGER NOT NULL REFERENCES hosts(id))")
    con.execute("INSERT INTO forgotten (host_id) VALUES (?)", (host_id,))
    con.commit()
    before = counts(con)

    with pytest.raises(sqlite3.IntegrityError):
        store.delete_host(con, "box")

    assert counts(con) == before
    assert con.execute("SELECT name FROM hosts").fetchone()["name"] == "box"
    assert con.execute("SELECT count(*) FROM forgotten").fetchone()[0] == 1


# ------------------------------------------------------------- what it refuses

def test_delete_refuses_a_host_that_is_not_removed(con):
    store.add_host(con, "live")
    assert store.delete_host(con, "live") is False
    assert con.execute("SELECT name FROM hosts").fetchone()["name"] == "live"


def test_delete_of_an_unknown_name_is_false(con):
    assert store.delete_host(con, "ghost") is False


def test_delete_stays_in_its_workspace(con):
    con.execute("INSERT INTO workspaces (id, name, created_at)"
                " VALUES (2, 'second', '2026-09-14T12:00:00+00:00')")
    con.commit()
    removed_host(con, "theirs", workspace_id=1)
    assert store.delete_host(con, "theirs", workspace_id=2) is False
    assert con.execute("SELECT name FROM hosts").fetchone()["name"] == "theirs"
    assert store.delete_host(con, "theirs", workspace_id=1) is True


def test_delete_works_on_a_database_that_lacks_the_other_modules_tables(tmp_path):
    """A database only db.init ran against has hosts and reports and none of
    the rest. A table that does not exist holds nothing of the host's."""
    con = db.connect(str(tmp_path / "bare.db"))
    db.init(con)
    host_id = removed_host(con)
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix,"
                " schema_version, document) VALUES (?, 'x', 1, 1, '{}')", (host_id,))
    con.commit()
    assert store.delete_host(con, "box") is True
    assert con.execute("SELECT count(*) FROM hosts").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM reports").fetchone()[0] == 0
    con.close()


def test_the_name_is_free_again_after_the_delete(con):
    """The row is gone, not marked, so the name a test box used can be
    enrolled again, which a revoked row's UNIQUE name never allowed."""
    removed_host(con)
    assert store.delete_host(con, "box") is True
    host_id, _credential = store.add_host(con, "box")
    assert store.active_host_by_name(con, "box")["id"] == host_id


def test_an_address_host_is_deleted_the_same_way(con):
    store.add_address_host(con, "addr")
    assert store.revoke_host(con, "addr")
    host_id = con.execute("SELECT id FROM hosts WHERE name = 'addr'").fetchone()["id"]
    fill_every_table(con, host_id)
    assert store.delete_host(con, "addr") is True
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    assert con.execute("SELECT count(*) FROM hosts").fetchone()[0] == 0


# ------------------------------------------------------------------- the route

def host_names(client):
    con = db.connect()
    names = [r["name"] for r in con.execute("SELECT name FROM hosts ORDER BY name")]
    con.close()
    return names


def test_delete_without_a_session_is_403(client):
    for headers in ({}, {"X-Admin-Gate": "1", "X-Auth-User": "robin"}):
        assert client.post("/api/admin/hosts/box/delete",
                           headers=headers).status_code == 403


def test_delete_route_takes_a_removed_host_and_answers_204(client):
    op = signed_in_operator()
    assert op.post("/api/admin/hosts", content=json.dumps({"name": "box"})).status_code == 201
    assert op.post("/api/admin/hosts/box/revoke").status_code == 204
    assert op.post("/api/admin/hosts/box/delete").status_code == 204
    assert host_names(client) == []
    # gone is gone: the second delete finds nothing, as revoke does
    assert op.post("/api/admin/hosts/box/delete").status_code == 404


def test_delete_route_refuses_a_live_host_with_409_and_keeps_it(client):
    op = signed_in_operator()
    assert op.post("/api/admin/hosts", content=json.dumps({"name": "box"})).status_code == 201
    resp = op.post("/api/admin/hosts/box/delete")
    assert resp.status_code == 409
    assert resp.json()["detail"] == "remove the server first"
    assert host_names(client) == ["box"]


def test_delete_route_answers_404_for_an_unknown_name(client):
    assert signed_in_operator().post("/api/admin/hosts/ghost/delete").status_code == 404


def test_one_workspace_cannot_delete_anothers_removed_server(client):
    """The other workspace's removed server answers exactly what an unknown
    name answers, and it stays."""
    mine = in_workspace("one@example.com", 1)
    theirs = in_workspace("two@example.com", 2)
    assert mine.post("/api/admin/hosts", content=json.dumps({"name": "box"})).status_code == 201
    assert mine.post("/api/admin/hosts/box/revoke").status_code == 204
    assert theirs.post("/api/admin/hosts/box/delete").status_code == 404
    assert host_names(client) == ["box"]
    assert mine.post("/api/admin/hosts/box/delete").status_code == 204
    assert host_names(client) == []
