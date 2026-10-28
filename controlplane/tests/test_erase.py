"""Erase one account with its workspace and its servers, and every row about them.

    Run from controlplane: .venv/bin/python -m pytest tests/test_erase.py

`python -m app.users_cli erase <address>` says what would go, and with
`--yes` deletes it and writes the file again so the deleted bytes go too
(`app/erase.py`). The tests build the schema the way the box has it, from
every module under app/ that makes a table, and fill every table: one row of
each for the account that is erased, the same for a second workspace that is
kept, and one row in each table that holds nobody's rows. So a table added
later is filled and checked here without anybody naming it first.

Every address is on a reserved example domain.
"""

import argparse
import dataclasses
import importlib
import pathlib
import sqlite3

import pytest

from app import authz, db, dispatch, erase, store, users_cli

APP = pathlib.Path(__file__).resolve().parents[1] / "app"
NOW = "2026-10-28T12:00:00+00:00"

GONE = "erase-me@example.com"
KEPT = "keep-me@example.org"

# A module whose table is made by something other than an `init`, and that
# something. The prober API's list of live proofs is made the first time an
# instance keeps one (`dispatch.remember_api_proofs`).
NO_INIT = {"dispatch": lambda con: con.executescript(dispatch.API_PROOFS_SCHEMA)}

# Run first, in this order: every other init may read hosts or users.
FIRST = ("db", "accounts")


# ------------------------------------------------------------ the real schema

def table_modules():
    """Every module under app/ whose source makes a table. Read from the
    files, so a module added later is in the schema here without being named."""
    found = sorted(path.stem for path in APP.glob("*.py")
                   if "CREATE TABLE" in path.read_text(encoding="utf-8"))
    return list(FIRST) + [name for name in found if name not in FIRST]


def whole_schema(con):
    for name in table_modules():
        if name in NO_INIT:
            NO_INIT[name](con)
        else:
            importlib.import_module(f"app.{name}").init(con)


@pytest.fixture()
def path(tmp_path):
    return tmp_path / "cp.db"


@pytest.fixture()
def con(path):
    connection = db.connect(str(path))
    whole_schema(connection)
    yield connection
    connection.close()


def tables(con):
    return sorted(r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
        " AND name NOT LIKE 'sqlite_%'"))


def columns(con, table):
    return con.execute(f"PRAGMA table_info({table})").fetchall()


def foreign_keys(con, table):
    """(column, parent table) for every foreign key of a table."""
    return [(r["from"], r["table"]) for r in con.execute(
        f"PRAGMA foreign_key_list({table})")]


# A column with one of these names holds an account, a workspace, a server,
# an address or a challenge one of them started.
OWNER_COLUMNS = {"host_id", "user_id", "link_user_id", "workspace_id", "email",
                 "invited_by", "account", "challenge_id"}
OWNER_TABLES = {"hosts", "users", "workspaces"}


def reaches(con, table, parents, seen=()):
    """Whether a row of this table can point at one of `parents`, through one
    foreign key or a chain of them."""
    if table in seen:
        return False
    return any(parent in parents or reaches(con, parent, parents, seen + (table,))
               for _column, parent in foreign_keys(con, table))


def can_hold_an_account(con, table, seen=()):
    """Whether a row of this table can belong to an account, its workspace or
    one of its servers: by a column named for one of them, or by a foreign key
    to a table whose rows can. The second is how `cve_batch_deliveries` is
    found: it points at a batch, and the batch names the workspace."""
    if table in OWNER_TABLES:
        return True
    if any(c["name"] in OWNER_COLUMNS for c in columns(con, table)):
        return True
    if table in seen:
        return False
    return any(can_hold_an_account(con, parent, seen + (table,))
               for _column, parent in foreign_keys(con, table))


def reaches_a_host(con, table):
    return table != "hosts" and (
        any(c["name"] == "host_id" for c in columns(con, table))
        or reaches(con, table, {"hosts"}))


# ------------------------------------------------------------ filling it

@dataclasses.dataclass
class Owner:
    email: str
    workspace_id: int
    user_id: int
    host_ids: list

    @property
    def account(self):
        return authz.account_for_workspace(self.workspace_id)


def make_owner(con, email, tag, admin=False):
    """An account alone in its own workspace, with an agent server and an
    address server."""
    workspace_id = db.create_workspace(con, f"{email} workspace")
    user_id = con.execute(
        "INSERT INTO users (email, password_hash, created_at, workspace_id,"
        " is_admin, display_name) VALUES (?, ?, ?, ?, ?, ?)",
        (email, f"{email} hash", NOW, workspace_id, int(admin), f"{email} name")).lastrowid
    con.commit()
    agent, _credential = store.add_host(con, f"agent-{tag}", workspace_id=workspace_id)
    address = store.add_address_host(con, f"address-{tag}", workspace_id=workspace_id)
    return Owner(email, workspace_id, user_id, [agent, address])


def value_by_name(owner, host_id, name):
    return {"host_id": host_id, "user_id": owner.user_id,
            "link_user_id": owner.user_id, "workspace_id": owner.workspace_id,
            "email": owner.email, "invited_by": owner.email,
            "account": owner.account}.get(name)


def fill(con, table, owner, host_id, made):
    """Put one row in `table` that belongs to `owner` (or to nobody, when
    `owner` is None), and return its id.

    Every column gets a value. A foreign key gets the parent's row, made
    first for the same owner. A column named for an owner gets that owner's.
    A number gets 1, and text carries the owner's address, so the address is
    in every table an owner's rows are in and the bytes test can count it."""
    if table in made:
        return made[table]
    values = {}
    for column, parent in foreign_keys(con, table):
        if parent == "hosts":
            values[column] = host_id
        elif parent == "users":
            values[column] = owner.user_id
        else:
            values[column] = fill(con, parent, owner, host_id, made)
    keys = [c for c in columns(con, table) if c["pk"]]
    for c in columns(con, table):
        name = c["name"]
        if name in values:
            continue
        if owner is not None and value_by_name(owner, host_id, name) is not None:
            values[name] = value_by_name(owner, host_id, name)
        elif name == "challenge_id" and owner is not None:
            values[name] = fill(con, "authz_challenges", owner, host_id, made)
        elif table == "feedback" and name == "instance_id":
            continue    # exactly one of instance and workspace, a CHECK says
        elif table == "feedback" and name == "kind":
            values[name] = "bug"
        elif c["pk"] and c["type"].upper() == "INTEGER" and len(keys) == 1:
            continue    # the rowid, SQLite assigns it
        elif c["type"].upper() in ("INTEGER", "REAL"):
            values[name] = 1
        else:
            who = owner.email if owner is not None else "nobody"
            values[name] = f"{who} {table}.{name}"
    names = ", ".join(values)
    marks = ", ".join("?" for _ in values)
    made[table] = con.execute(f"INSERT INTO {table} ({names}) VALUES ({marks})",
                              tuple(values.values())).lastrowid
    return made[table]


def fill_owner(con, owner):
    """A row in every table that can hold an account's, and a second row in
    every table that hangs off a server, for the owner's second server."""
    first, second = owner.host_ids
    made = {"users": owner.user_id, "workspaces": owner.workspace_id, "hosts": first}
    for table in tables(con):
        if can_hold_an_account(con, table):
            fill(con, table, owner, first, made)
    made = {"hosts": second}
    for table in tables(con):
        if reaches_a_host(con, table):
            fill(con, table, owner, second, made)
    con.commit()


def fill_nobody(con):
    """A row in every table that holds nobody's rows. A table an init already
    put its one row in (`sweep_state`, which a CHECK keeps to one) has its row."""
    made = {}
    for table in tables(con):
        if can_hold_an_account(con, table):
            continue
        if con.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 0:
            fill(con, table, None, None, made)
    con.commit()


def counts(con):
    return {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in tables(con)}


def dump(con):
    """Every row of every table, sorted, so two dumps compare row for row."""
    return {t: sorted(tuple(r) for r in con.execute(f"SELECT * FROM {t}"))
            for t in tables(con)}


@pytest.fixture()
def world(con):
    """A kept workspace and the nobody rows first, then the account to erase.
    Returns (gone, kept, the dump before the erased account existed, the rows
    its making added per table)."""
    fill_nobody(con)
    kept = make_owner(con, KEPT, "kept", admin=True)
    fill_owner(con, kept)
    before = dump(con)
    counted = counts(con)
    gone = make_owner(con, GONE, "gone")
    fill_owner(con, gone)
    added = {t: n - counted[t] for t, n in counts(con).items() if n != counted[t]}
    return gone, kept, before, added


def run(con, *argv):
    """The real parser and the real command, on this connection."""
    args = users_cli.build_parser().parse_args(["erase", *argv])
    return users_cli.run(con, args)


def times_in(path, needle):
    path = pathlib.Path(path)
    return path.read_bytes().count(needle.encode()) if path.exists() else 0


def wal_of(path):
    return pathlib.Path(str(path) + "-wal")


# ------------------------------------------------------------ the schema walk

def test_the_schema_is_built_from_every_module_that_makes_a_table():
    """The walk below is only a proof if the schema is whole, and a scan that
    finds nothing passes in silence. These are known to make tables."""
    found = set(table_modules())
    assert {"db", "accounts", "authz", "alerts", "feedback", "betasignup",
            "hetzner", "proberproofs", "dispatch", "cvesend"} <= found
    assert "erase" not in found


def test_the_walk_finds_what_is_known_to_hold_an_account(con):
    holding = {t for t in tables(con) if can_hold_an_account(con, t)}
    assert {"users", "sessions", "oidc_flows", "one_time_links", "beta_signups",
            "workspaces", "feedback", "notification_channels", "sent_log",
            "provider_tokens", "cve_batch_deliveries", "hosts", "reports",
            "report_digests", "probe_results", "authorizations",
            "authz_challenges", "prober_challenges"} <= holding
    assert not {"authz_exclusions", "sweep_state", "probe_instances",
                "vantages"} & holding


def test_every_table_of_the_schema_is_erased_from_or_left_with_a_reason(con):
    schema = set(tables(con))
    named = erase.ERASED_TABLES | set(erase.LEFT)
    assert schema == named, {"in neither": schema - named,
                             "named but not in the schema": named - schema}
    assert not erase.ERASED_TABLES & set(erase.LEFT)
    assert all(reason.strip() for reason in erase.LEFT.values())


def test_a_table_that_can_hold_an_account_a_workspace_or_a_server_is_erased_from(con):
    holding = {t for t in tables(con) if can_hold_an_account(con, t)}
    assert holding - erase.ERASED_TABLES == set()


# ------------------------------------------------------------ the dry run

def test_the_dry_run_changes_nothing_and_counts_right(con, world, capsys):
    gone, _kept, _before, added = world
    whole = dump(con)

    assert run(con, GONE) == 0

    assert dump(con) == whole
    said = capsys.readouterr().out
    listed = {}
    for line in said.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].isdigit():
            listed[parts[0]] = int(parts[1])
    assert listed == added
    assert f"{sum(added.values())} rows would go" in said
    assert "nothing was changed" in said


def test_the_dry_run_counts_both_servers(con, world):
    """Every table that hangs off a server holds two rows of the account's,
    one per server, and both are counted."""
    gone, _kept, _before, _added = world
    erased = erase.erase(con, GONE, delete=False)
    assert erased.counts["reports"] == 2
    assert erased.counts["hosts"] == 2
    assert erased.counts["users"] == erased.counts["workspaces"] == 1


# ------------------------------------------------------------ the erase

def test_after_yes_no_row_in_any_table_refers_to_the_account_its_workspace_or_its_servers(
        con, world):
    gone, _kept, _before, _added = world
    assert run(con, GONE, "--yes") == 0

    for table in tables(con):
        for c in columns(con, table):
            name = c["name"]
            wrong = {"host_id": gone.host_ids, "user_id": [gone.user_id],
                     "link_user_id": [gone.user_id],
                     "workspace_id": [gone.workspace_id],
                     "email": [GONE], "invited_by": [GONE],
                     "account": [gone.account]}.get(name)
            if wrong:
                marks = ", ".join("?" for _ in wrong)
                found = con.execute(f"SELECT count(*) FROM {table} WHERE {name}"
                                    f" IN ({marks})", wrong).fetchone()[0]
                assert found == 0, f"{table}.{name} still holds {found} of the account's"
            if c["type"].upper() in ("TEXT", ""):
                found = con.execute(f"SELECT count(*) FROM {table} WHERE"
                                    f" instr({name}, ?) > 0", (GONE,)).fetchone()[0]
                assert found == 0, f"{table}.{name} still holds the address {found} times"
    assert con.execute("SELECT count(*) FROM hosts WHERE id IN (?, ?)",
                       gone.host_ids).fetchone()[0] == 0
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []


def test_a_second_workspace_with_rows_in_every_table_is_untouched_row_for_row(con, world):
    """The database after the erase is the database before the erased account
    was made: the kept workspace, its account and the nobody rows, row for
    row, and nothing else."""
    _gone, kept, before, _added = world
    for table, rows in before.items():
        if can_hold_an_account(con, table):
            assert rows, f"the kept workspace has no row in {table}, so this proves nothing"

    assert run(con, GONE, "--yes") == 0

    assert dump(con) == before


def test_the_address_bytes_are_no_longer_in_the_database_file(con, path, world, capsys):
    """Counted in the file and its -wal, the way 4.444 counted a batch. A
    session of the account's deleted earlier by a connection that did not
    overwrite what it deleted is set up first: its bytes stay in a free page,
    which only writing the file again takes away."""
    gone, _kept, _before, _added = world
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    live = times_in(path, GONE)
    old = sqlite3.connect(str(path))
    old.execute("PRAGMA secure_delete = OFF")
    old.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at,"
                " user_agent) VALUES ('old', ?, ?, ?, ?)",
                (gone.user_id, NOW, NOW, (GONE + " ") * 400))
    old.commit()
    old.execute("DELETE FROM sessions WHERE token_hash = 'old'")
    old.commit()
    old.close()
    con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    # 400 copies went in. A copy that runs over the end of a page is in two
    # pieces in the file and is not counted, so a few fewer are found.
    assert times_in(path, GONE) >= live + 390, "the old session's bytes are not there to find"

    assert run(con, GONE, "--yes") == 0

    assert times_in(path, GONE) == 0
    assert times_in(wal_of(path), GONE) == 0
    assert times_in(path, KEPT) + times_in(wal_of(path), KEPT) > 0
    said = capsys.readouterr().out
    assert "the address is in the database file 0 times and in its -wal 0 times" in said
    assert "bytes before" in said and "bytes after" in said


def test_the_erase_prints_one_line_per_table_that_changed(con, world, capsys):
    _gone, _kept, _before, added = world
    assert run(con, GONE, "--yes") == 0
    said = capsys.readouterr().out
    for table, n in added.items():
        assert f"  {table:<24} {n:>6}" in said
    assert f"{sum(added.values())} rows deleted" in said


# ------------------------------------------------------------ the refusals

def refused(con, capsys, *argv):
    """Run, and return the one line said on stderr, after checking that the
    command failed, said one line and changed nothing."""
    whole = dump(con)
    assert run(con, *argv) == 1
    said = capsys.readouterr()
    assert said.out == ""
    lines = said.err.strip().splitlines()
    assert len(lines) == 1, lines
    assert dump(con) == whole
    return lines[0]


def test_refuses_an_address_with_no_account(con, world, capsys):
    line = refused(con, capsys, "nobody@example.com", "--yes")
    assert line == "no account for nobody@example.com, nothing was changed"


def test_refuses_the_only_admin(con, capsys):
    owner = make_owner(con, GONE, "gone", admin=True)
    fill_owner(con, owner)
    line = refused(con, capsys, GONE, "--yes")
    assert "the only account with the admin flag" in line


def test_an_admin_with_another_admin_beside_it_is_erased(con, world, capsys):
    gone, _kept, _before, _added = world
    con.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (gone.user_id,))
    con.commit()
    assert run(con, GONE, "--yes") == 0
    assert con.execute("SELECT count(*) FROM users WHERE email = ?", (GONE,)).fetchone()[0] == 0


def test_refuses_a_workspace_another_account_also_uses(con, world, capsys):
    gone, _kept, _before, _added = world
    con.execute("INSERT INTO users (email, password_hash, created_at, workspace_id)"
                " VALUES ('colleague@example.com', 'x', ?, ?)", (NOW, gone.workspace_id))
    con.commit()
    line = refused(con, capsys, GONE, "--yes")
    assert f"workspace {gone.workspace_id} is also used by 1 other account" in line


def test_refuses_a_database_it_cannot_lock(con, path, world, capsys):
    other = db.connect(str(path))
    other.execute("BEGIN IMMEDIATE")
    con.execute("PRAGMA busy_timeout = 50")
    try:
        line = refused(con, capsys, GONE, "--yes")
    finally:
        other.rollback()
        other.close()
    assert "locked" in line


def test_refuses_workspace_one(con, capsys):
    con.execute("INSERT INTO users (email, password_hash, created_at, workspace_id)"
                " VALUES (?, 'x', ?, 1)", (GONE, NOW))
    con.commit()
    line = refused(con, capsys, GONE, "--yes")
    assert "workspace 1" in line


def test_refuses_a_database_that_holds_a_table_it_has_no_rule_for(con, world, capsys):
    """A table this code does not know, on a box, could keep the account's
    rows quietly. So it is named and nothing is deleted."""
    con.execute("CREATE TABLE later (id INTEGER PRIMARY KEY, workspace_id INTEGER)")
    con.commit()
    line = refused(con, capsys, GONE, "--yes")
    assert "later" in line


def test_a_delete_that_fails_rolls_everything_back_and_says_so_in_one_line(
        con, world, capsys, monkeypatch):
    """A server's documents left off the list: the server's own delete then
    fails on the foreign key, and every delete before it is rolled back."""
    monkeypatch.setattr(store, "HOST_TABLES",
                        tuple(e for e in store.HOST_TABLES if e[0] != "reports"))
    line = refused(con, capsys, GONE, "--yes")
    assert "FOREIGN KEY" in line and line.endswith("nothing was changed")


def test_the_dry_run_refuses_what_the_erase_refuses(con, capsys):
    line = refused(con, capsys, "nobody@example.com")
    assert line.startswith("no account for")


# ------------------------------------------------------------ the parser

def test_the_parser_takes_erase_with_and_without_yes():
    parser = users_cli.build_parser()
    assert parser.parse_args(["erase", GONE]).yes is False
    assert parser.parse_args(["erase", GONE, "--yes"]).yes is True


def test_the_address_is_matched_as_every_other_command_matches_it(con, world, capsys):
    """An address typed with capitals finds the account, as `add` stores it."""
    assert run(con, GONE.upper(), "--yes") == 0
    assert con.execute("SELECT count(*) FROM users WHERE email = ?", (GONE,)).fetchone()[0] == 0


def test_erase_works_on_a_database_that_lacks_the_other_modules_tables(tmp_path, capsys):
    """users_cli makes db's, accounts' and identities' tables. A table that is
    not there holds nothing of the account's."""
    con = db.connect(str(tmp_path / "bare.db"))
    for name in FIRST:
        importlib.import_module(f"app.{name}").init(con)
    owner = make_owner(con, GONE, "gone")
    args = argparse.Namespace(command="erase", email=GONE, yes=True)
    assert users_cli.run(con, args) == 0
    assert con.execute("SELECT count(*) FROM hosts").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM workspaces WHERE id = ?",
                       (owner.workspace_id,)).fetchone()[0] == 0
    con.close()
