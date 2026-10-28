"""The admin flag: the column, the reader, and the command that sets it.

    python -m pytest tests/test_admin_flag.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle security bug in review, these tests are the review.
The ones carrying the argument, in the order a reviewer should read them:

  - a new account does not have it, and nothing but `set_admin` ever gives it
  - `is_admin` answers False for every unreadable shape a row can take, so a
    column that cannot be read is never a grant
  - the value has to be exactly 1. Anything else, including a hand-written 2,
    is not the flag
  - the flag is on the account and not on the session, so revoking it takes
    effect on the very next read without anybody being signed out
"""

import sqlite3

import pytest

from app import accounts, db, users_cli

PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    db.init(connection)
    accounts.init(connection)
    yield connection
    connection.close()


def make(con, email="ops@example.com"):
    return accounts.create_user(con, email, PASSWORD)


def row(con, email="ops@example.com"):
    return accounts.get_user_by_email(con, email)


# ==================================================== nobody starts with it

def test_a_new_account_is_not_an_admin(con):
    make(con)
    assert accounts.is_admin(row(con)) is False


def test_the_column_exists_after_init(con):
    columns = {c[1] for c in con.execute("PRAGMA table_info(users)")}
    assert "is_admin" in columns


def test_init_twice_does_not_fail(con):
    """The additive ALTER pattern: the duplicate-column error is the
    idempotence check, so a second init on a database that already has the
    column must be a no-op rather than a crash on the next deploy."""
    make(con)
    accounts.set_admin(con, "ops@example.com", True)
    accounts.init(con)
    accounts.init(con)
    assert accounts.is_admin(row(con)) is True


def test_an_upgraded_database_backfills_every_existing_account(tmp_path,
                                                               monkeypatch):
    """The ALTER's default is the backfill, so an account made before this
    existed is not an admin afterwards."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "old.db"))
    con = db.connect()
    db.init(con)
    # The accounts table as it was before the column, built by hand.
    con.executescript("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
            disabled_at TEXT, last_login_at TEXT,
            workspace_id INTEGER NOT NULL DEFAULT 1);
    """)
    con.execute("INSERT INTO users (email, password_hash, created_at)"
                " VALUES ('old@example.com', 'x', '2026-01-01T00:00:00+00:00')")
    con.commit()
    accounts.init(con)
    assert accounts.is_admin(row(con, "old@example.com")) is False
    con.close()


# ============================================ every unreadable shape is False

def test_none_is_not_an_admin():
    assert accounts.is_admin(None) is False


def test_a_row_without_the_column_is_not_an_admin(tmp_path, monkeypatch):
    """A Row read through a connection that has not run init does not carry
    the column at all, and asking it for one raises. False is the answer."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "bare.db"))
    con = db.connect()
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)")
    con.execute("INSERT INTO users (email) VALUES ('x@example.com')")
    con.commit()
    bare = con.execute("SELECT * FROM users").fetchone()
    assert accounts.is_admin(bare) is False
    con.close()


@pytest.mark.parametrize("stored", ["yes", "true", "", "on", 0.5])
def test_a_value_that_is_not_an_integer_is_not_an_admin(con, stored):
    """A hand-edited row, or one written by something that thought the column
    was text. None of these is the flag."""
    make(con)
    con.execute("UPDATE users SET is_admin = ?", (stored,))
    con.commit()
    assert accounts.is_admin(row(con)) is False


def test_the_text_one_is_the_flag_because_sqlite_converts_it(con):
    """Measured rather than assumed, and it surprised this test first time
    round. The column has INTEGER affinity, so SQLite converts a stored "1"
    to the integer 1 on the way in and the row really does hold 1. Nothing in
    `is_admin` special-cases text: the value it reads back is an int."""
    make(con)
    con.execute("UPDATE users SET is_admin = ?", ("1",))
    con.commit()
    assert con.execute("SELECT typeof(is_admin) FROM users").fetchone()[0] == "integer"
    assert accounts.is_admin(row(con)) is True


def test_null_is_refused_by_the_column(con):
    """NOT NULL, so the unreadable case `is_admin` guards against cannot even
    be written through this connection."""
    make(con)
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("UPDATE users SET is_admin = NULL")


@pytest.mark.parametrize("stored", [0, 2, -1, 99])
def test_only_one_is_the_flag(con, stored):
    """Exactly 1, so a column that picked up some other integer is not a
    grant. Truthiness would have made 2 and -1 admins."""
    make(con)
    con.execute("UPDATE users SET is_admin = ?", (stored,))
    con.commit()
    assert accounts.is_admin(row(con)) is False


def test_true_is_an_admin(con):
    """sqlite3 stores a Python True as 1, and a Row can come back as bool from
    a hand-written INSERT in a test. It means the same thing."""
    make(con)
    con.execute("UPDATE users SET is_admin = ?", (True,))
    con.commit()
    assert accounts.is_admin(row(con)) is True


# ================================================== granting and taking away

def test_granting_and_revoking(con):
    make(con)
    assert accounts.set_admin(con, "ops@example.com", True) is True
    assert accounts.is_admin(row(con)) is True
    assert accounts.set_admin(con, "ops@example.com", False) is True
    assert accounts.is_admin(row(con)) is False


def test_granting_an_unknown_address_changes_nothing(con):
    make(con)
    assert accounts.set_admin(con, "nobody@example.com", True) is False
    assert accounts.is_admin(row(con)) is False


def test_the_address_is_normalised(con):
    make(con, "Ops@Example.com")
    assert accounts.set_admin(con, "OPS@EXAMPLE.COM", True) is True
    assert accounts.is_admin(row(con, "ops@example.com")) is True


def test_granting_one_account_does_not_grant_another(con):
    make(con, "one@example.com")
    make(con, "two@example.com")
    accounts.set_admin(con, "one@example.com", True)
    assert accounts.is_admin(row(con, "two@example.com")) is False


def test_no_email_address_is_written_into_the_code():
    """The module's own comment: a hardcoded address
    could not be revoked without a deploy and would stay true on a database
    restored anywhere. The column is the whole of it."""
    import inspect
    import re
    source = inspect.getsource(accounts)
    # Any address at all, so the test itself names nobody's.
    assert re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", source) is None


# ================================== the flag is on the account, not the session

def test_a_live_session_reflects_a_grant_without_signing_in_again(con):
    user_id = make(con)
    token, _ = accounts.issue_session(con, user_id)
    assert accounts.is_admin(accounts.resolve_session(con, token)) is False
    accounts.set_admin(con, "ops@example.com", True)
    assert accounts.is_admin(accounts.resolve_session(con, token)) is True


def test_a_live_session_loses_it_the_moment_it_is_revoked(con):
    user_id = make(con)
    accounts.set_admin(con, "ops@example.com", True)
    token, _ = accounts.issue_session(con, user_id)
    assert accounts.is_admin(accounts.resolve_session(con, token)) is True
    accounts.set_admin(con, "ops@example.com", False)
    assert accounts.is_admin(accounts.resolve_session(con, token)) is False


def test_a_disabled_admin_has_no_session_at_all(con):
    """Disabling already refuses the session, and the flag must not be a way
    back in around that."""
    user_id = make(con)
    accounts.set_admin(con, "ops@example.com", True)
    token, _ = accounts.issue_session(con, user_id)
    accounts.set_disabled(con, "ops@example.com", True)
    assert accounts.resolve_session(con, token) is None


# ================================================================ the command

def run(con, *argv):
    """One users_cli command against this database, as the terminal runs it."""
    parser_args = users_cli.build_parser().parse_args(argv)
    return users_cli.run(con, parser_args)


def test_the_command_grants_and_revokes(con, capsys):
    make(con)
    assert run(con, "admin", "grant", "ops@example.com") == 0
    assert "now has the admin flag" in capsys.readouterr().out
    assert accounts.is_admin(row(con)) is True
    assert run(con, "admin", "revoke", "ops@example.com") == 0
    assert "no longer has" in capsys.readouterr().out
    assert accounts.is_admin(row(con)) is False


def test_granting_twice_says_it_was_already_true(con, capsys):
    """A command that prints "granted" over an unchanged row is how somebody
    ends up believing a second box is set up too."""
    make(con)
    run(con, "admin", "grant", "ops@example.com")
    capsys.readouterr()
    assert run(con, "admin", "grant", "ops@example.com") == 0
    assert "already has the admin flag" in capsys.readouterr().out


def test_revoking_from_somebody_who_never_had_it(con, capsys):
    make(con)
    assert run(con, "admin", "revoke", "ops@example.com") == 0
    assert "already does not have the admin flag" in capsys.readouterr().out


def test_the_command_refuses_an_unknown_account(con, capsys):
    assert run(con, "admin", "grant", "nobody@example.com") == 1
    assert "no account for" in capsys.readouterr().err


def test_the_list_names_only_the_admins(con, capsys):
    make(con, "one@example.com")
    make(con, "two@example.com")
    accounts.set_admin(con, "two@example.com", True)
    assert run(con, "admin", "list") == 0
    out = capsys.readouterr().out
    assert "two@example.com" in out
    assert "one@example.com" not in out


def test_the_list_says_so_when_nobody_has_it(con, capsys):
    make(con)
    assert run(con, "admin", "list") == 0
    assert "no account has the admin flag" in capsys.readouterr().out


def test_the_account_list_shows_the_flag(con, capsys):
    make(con, "one@example.com")
    make(con, "two@example.com")
    accounts.set_admin(con, "two@example.com", True)
    assert run(con, "list") == 0
    lines = {line.split()[0]: line for line in capsys.readouterr().out.splitlines()}
    assert lines["two@example.com"].endswith("admin")
    assert not lines["one@example.com"].endswith("admin")
