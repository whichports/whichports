"""An account gets its own email channel, a real row (the owner, 2026-09-20).

`docs/RECORD.md` 4.186. The first outside workspace held no email row, so an
alert on its server mailed nobody, and the Alerts screen drew a hard-coded
"Email, set on the server" row nobody could remove. His choice from three:
making an account also makes an enabled email channel for its address, in its
own workspace, which the tester can edit, turn off or delete like any other.
"""

import pytest

from app import accounts, channels, channels_cli, db

PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    accounts.init(connection)
    channels.init(connection)
    yield connection
    connection.close()


def backfill(con):
    return channels_cli.run(con, channels_cli.parse_args(["backfill-accounts"]))


def email_rows(con, workspace_id):
    return [(c.label, c.resolve({}), c.enabled)
            for c in channels.live(con, channels.TYPE_EMAIL,
                                   workspace_id=workspace_id)]


def test_a_new_account_gets_an_enabled_email_row_in_its_workspace(con):
    ws = db.create_workspace(con, "acme")
    accounts.create_user(con, "Tester@Example.org", PASSWORD, workspace_id=ws)
    assert email_rows(con, ws) == [("email", "tester@example.org", True)]
    assert email_rows(con, db.DEFAULT_WORKSPACE_ID) == []


def test_the_row_is_made_even_when_the_channels_table_does_not_exist_yet(tmp_path):
    """A fresh box: `users_cli add` is the first thing anybody runs, before
    anything has created the channels table."""
    connection = db.connect(str(tmp_path / "fresh.db"))
    db.init(connection)
    accounts.init(connection)
    accounts.create_user(connection, "first@example.org", PASSWORD)
    assert email_rows(connection, 1) == [("email", "first@example.org", True)]
    connection.close()


def test_a_second_account_in_the_workspace_gets_its_own_row(con):
    accounts.create_user(con, "one@example.org", PASSWORD)
    accounts.create_user(con, "two@example.org", PASSWORD)
    assert email_rows(con, 1) == [("email", "one@example.org", True),
                                  ("email 2", "two@example.org", True)]


def test_an_address_the_workspace_already_mails_is_not_added_twice(con):
    channels.add(con, channels.TYPE_EMAIL, "ops", "",
                 destination="ops@example.org")
    accounts.create_user(con, "ops@example.org", PASSWORD)
    assert email_rows(con, 1) == [("ops", "ops@example.org", True)]


def test_a_row_the_tester_deleted_stays_deleted(con):
    """Nothing re-creates it: not a second init, and not the backfill, because
    another account's row still stands in the workspace."""
    accounts.create_user(con, "one@example.org", PASSWORD)
    accounts.create_user(con, "two@example.org", PASSWORD)
    assert channels.remove(con, "email")
    channels.init(con)
    accounts.init(con)
    assert backfill(con) == 0
    assert email_rows(con, 1) == [("email 2", "two@example.org", True)]


def test_a_refused_account_leaves_no_row_behind(con):
    accounts.create_user(con, "one@example.org", PASSWORD)
    with pytest.raises(accounts.AccountError):
        accounts.create_user(con, "one@example.org", PASSWORD)
    with pytest.raises(accounts.AccountError):
        accounts.create_user(con, "short@example.org", "x")
    assert email_rows(con, 1) == [("email", "one@example.org", True)]


# ------------------------------------------------------------ the backfill
#
# For the accounts made before this existed. On production on 2026-09-20 that
# is workspace 2 and workspace 3. Workspace 1 already holds email rows and must
# be left exactly as it is.

def an_account_from_before(con, email, workspace_id):
    """An account row with no channel, which is what every account made
    before 2026-09-20 looks like."""
    con.execute(
        "INSERT INTO users (email, password_hash, created_at, workspace_id)"
        " VALUES (?, 'x', '2026-09-01T00:00:00+00:00', ?)",
        (email, workspace_id))
    con.commit()


def test_the_backfill_reaches_only_a_workspace_with_no_email_row(con, capsys):
    ws2 = db.create_workspace(con, "two")
    ws3 = db.create_workspace(con, "three")
    an_account_from_before(con, "operator@example.org", 1)
    channels.add(con, channels.TYPE_EMAIL, "ops", "",
                 destination="somebody-else@example.org", workspace_id=1)
    an_account_from_before(con, "tester@example.org", ws3)
    channels.add(con, channels.TYPE_WEBHOOK, "webhook", "",
                 destination="https://hooks.example.org/x", workspace_id=ws3)

    assert backfill(con) == 0

    assert email_rows(con, 1) == [("ops", "somebody-else@example.org", True)]
    assert email_rows(con, ws2) == []          # no account, so nobody to mail
    assert email_rows(con, ws3) == [("email", "tester@example.org", True)]
    out = capsys.readouterr().out
    assert "workspace 3" in out
    # The address is an account's login and the terminal is the operator's,
    # but nothing here needs it printed, so it is not.
    assert "tester@example.org" not in out


def test_a_switched_off_row_counts_as_a_row_for_the_backfill(con):
    """The same rule the sweep follows: a configured channel that is off is an
    answer, and the backfill does not overrule it."""
    ws = db.create_workspace(con, "two")
    an_account_from_before(con, "tester@example.org", ws)
    channels.add(con, channels.TYPE_EMAIL, "mine", "",
                 destination="tester@example.org", workspace_id=ws)
    channels.set_enabled(con, "mine", False, workspace_id=ws)
    assert backfill(con) == 0
    assert email_rows(con, ws) == [("mine", "tester@example.org", False)]


def test_a_disabled_account_is_not_backfilled(con):
    ws = db.create_workspace(con, "two")
    an_account_from_before(con, "gone@example.org", ws)
    accounts.set_disabled(con, "gone@example.org", True)
    assert backfill(con) == 0
    assert email_rows(con, ws) == []


def test_the_backfill_run_twice_adds_nothing_the_second_time(con):
    ws = db.create_workspace(con, "two")
    an_account_from_before(con, "tester@example.org", ws)
    backfill(con)
    backfill(con)
    assert email_rows(con, ws) == [("email", "tester@example.org", True)]
