"""Accounts from the terminal, which is the only place they are created.

    python -m pytest tests/test_users_cli.py

The property worth reading first: the password is never an argument, because a
command line is visible in `ps` to every user on the machine and lands in shell
history besides.
"""

import argparse
import io
import re

import pytest

from app import accounts, db, envfile, identities, oidc, onetime, totp, users_cli
from app.providers import PROVIDERS

EMAIL = "sysadmin@example.com"
PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    accounts.init(connection)
    identities.init(connection)
    yield connection
    connection.close()


def run(con, monkeypatch, command, email=None, password=PASSWORD,
        workspace=db.DEFAULT_WORKSPACE_ID):
    if password is not None:
        monkeypatch.setattr(users_cli, "read_password", lambda confirm=True: password)
    # `workspace` is here because parse_args puts it on every namespace `add`
    # is given, so a namespace without it would not be what a terminal hands
    # the command.
    args = argparse.Namespace(command=command, workspace=workspace)
    if email is not None:
        args.email = email
    return users_cli.run(con, args)


def test_add_creates_an_account_that_can_authenticate(con, monkeypatch, capsys):
    assert run(con, monkeypatch, "add", EMAIL) == 0
    assert "created" in capsys.readouterr().out
    assert accounts.authenticate(con, EMAIL, PASSWORD) is not None


def test_add_refuses_a_short_password_and_creates_nothing(con, monkeypatch, capsys):
    assert run(con, monkeypatch, "add", EMAIL, password="short") == 1
    assert "at least" in capsys.readouterr().err
    assert accounts.get_user_by_email(con, EMAIL) is None


def test_add_refuses_a_malformed_address(con, monkeypatch, capsys):
    assert run(con, monkeypatch, "add", "not-an-address") == 1
    assert "email address" in capsys.readouterr().err


def test_add_refuses_the_same_address_twice(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run(con, monkeypatch, "add", EMAIL.upper()) == 1
    assert "already exists" in capsys.readouterr().err


def test_every_command_that_names_an_account_says_so_when_it_is_missing(
        con, monkeypatch, capsys):
    for command in ("passwd", "disable", "enable", "sign-out"):
        assert run(con, monkeypatch, command, "ghost@example.com") == 1
        assert "no account" in capsys.readouterr().err


def test_list_prints_state_and_live_session_count(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    accounts.issue_session(con, user["id"])
    capsys.readouterr()
    assert run(con, monkeypatch, "list") == 0
    out = capsys.readouterr().out
    assert EMAIL in out and "active" in out and "sessions: 1" in out


def test_list_never_prints_a_hash(con, monkeypatch, capsys):
    """A password hash on a terminal is a password hash in a scrollback buffer
    and in whatever recorded that session."""
    run(con, monkeypatch, "add", EMAIL)
    stored = accounts.get_user_by_email(con, EMAIL)["password_hash"]
    capsys.readouterr()
    run(con, monkeypatch, "list")
    out = capsys.readouterr().out
    assert stored not in out
    assert "scrypt$" not in out


def test_passwd_changes_the_password_and_signs_every_session_out(
        con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    token, _ = accounts.issue_session(con, user["id"])
    capsys.readouterr()
    assert run(con, monkeypatch, "passwd", EMAIL, password="a-brand-new-password-9") == 0
    assert "1 session(s) signed out" in capsys.readouterr().out
    assert accounts.resolve_session(con, token) is None
    assert accounts.authenticate(con, EMAIL, "a-brand-new-password-9") is not None
    assert accounts.authenticate(con, EMAIL, PASSWORD) is None


def test_passwd_refuses_a_short_password_and_leaves_the_sessions_alone(
        con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    token, _ = accounts.issue_session(con, user["id"])
    assert run(con, monkeypatch, "passwd", EMAIL, password="short") == 1
    assert accounts.resolve_session(con, token) is not None
    assert accounts.authenticate(con, EMAIL, PASSWORD) is not None


def test_disable_then_enable(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    token, _ = accounts.issue_session(con, user["id"])
    capsys.readouterr()
    assert run(con, monkeypatch, "disable", EMAIL) == 0
    assert "disabled" in capsys.readouterr().out
    assert accounts.resolve_session(con, token) is None
    assert accounts.authenticate(con, EMAIL, PASSWORD) is None
    assert run(con, monkeypatch, "enable", EMAIL) == 0
    assert accounts.authenticate(con, EMAIL, PASSWORD) is not None


def test_sign_out_revokes_every_session_and_keeps_the_account(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    tokens = [accounts.issue_session(con, user["id"])[0] for _ in range(3)]
    capsys.readouterr()
    assert run(con, monkeypatch, "sign-out", EMAIL) == 0
    assert "3 session(s) signed out" in capsys.readouterr().out
    assert all(accounts.resolve_session(con, t) is None for t in tokens)
    assert accounts.authenticate(con, EMAIL, PASSWORD) is not None


def test_a_piped_password_is_read_from_standard_input(monkeypatch):
    """The scripted path, so a provisioning run never puts a password in an
    argument list either."""
    monkeypatch.setattr("sys.stdin", io.StringIO("piped-in-password\n"))
    assert users_cli.read_password() == "piped-in-password"


def test_a_mismatched_confirmation_changes_nothing(monkeypatch):
    answers = iter(["first-password", "second-password"])

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setattr("sys.stdin", Tty())
    monkeypatch.setattr(users_cli.getpass, "getpass", lambda prompt: next(answers))
    with pytest.raises(SystemExit):
        users_cli.read_password()


def test_the_password_is_not_a_command_line_argument():
    """A guard on the interface itself: adding a --password flag later would
    put secrets in `ps` output and in shell history, so the parser must not
    grow one without this test being deliberately changed."""
    parser_source = users_cli.main.__doc__ or ""
    assert "--password" not in parser_source
    import inspect
    assert "--password" not in inspect.getsource(users_cli.main)


# ----------------------------------------------------------- the shown name
#
# `name` fills the display_name column the account menu and the avatar chip
# read through whoami. Nothing invents one: an account without a stored name
# answers empty and the page falls back to the email.

def run_name(con, display_name, email=EMAIL):
    args = argparse.Namespace(command="name", email=email,
                              display_name=display_name)
    return users_cli.run(con, args)


def test_name_stores_what_the_menu_will_show(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_name(con, "Robin Sample") == 0
    assert "now shows as Robin Sample" in capsys.readouterr().out
    assert accounts.display_name_of(
        accounts.get_user_by_email(con, EMAIL)) == "Robin Sample"


def test_name_echoes_the_trimmed_value_it_stored(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_name(con, "  Robin Sample  ") == 0
    assert "now shows as Robin Sample" in capsys.readouterr().out


def test_name_with_empty_text_clears_it(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    run_name(con, "Robin Sample")
    capsys.readouterr()
    assert run_name(con, "") == 0
    assert "shows its email address" in capsys.readouterr().out
    assert accounts.get_user_by_email(con, EMAIL)["display_name"] is None


def test_name_refuses_an_account_that_does_not_exist(con, capsys):
    assert run_name(con, "Ghost", email="ghost@example.com") == 1
    assert "no account" in capsys.readouterr().err


def test_name_past_the_bound_is_refused_and_changes_nothing(con, monkeypatch,
                                                            capsys):
    run(con, monkeypatch, "add", EMAIL)
    run_name(con, "Robin Sample")
    capsys.readouterr()
    assert run_name(con, "a" * (accounts.DISPLAY_NAME_MAX_CHARS + 1)) == 1
    assert "name not changed" in capsys.readouterr().err
    assert accounts.display_name_of(
        accounts.get_user_by_email(con, EMAIL)) == "Robin Sample"


def parse_db(tmp_path, monkeypatch):
    """A database that exists, pointed at by the environment.

    The parser tests drive `main()`, and since `app/cli.py` a `main()` refuses
    to run against a database that is not there. They used to patch
    `db.connect` and leave the *resolved* path to whatever the ambient
    environment said, which was a path nothing checked. Pointing the variable
    at a real file is both simpler and what the box actually looks like.
    """
    path = tmp_path / "parse.db"
    db.connect(str(path)).close()
    monkeypatch.setenv(db.DB_ENV, str(path))
    return path


def test_the_parser_accepts_the_name_command(tmp_path, monkeypatch):
    """The documented invocation, quoted name included, has to parse."""
    seen = {}
    parse_db(tmp_path, monkeypatch)
    monkeypatch.setattr("sys.argv", ["users", "name", EMAIL, "Robin Sample"])
    monkeypatch.setattr(users_cli, "run",
                        lambda con, args: seen.setdefault("args", args) and 0)
    assert users_cli.main() == 0
    assert seen["args"].command == "name"
    assert seen["args"].email == EMAIL
    assert seen["args"].display_name == "Robin Sample"


# ------------------------------------------------------- the second factor
#
# Enrolment lives here and nowhere else, so these cover the whole of turning
# two-factor on and off. The one that matters most is that a wrong confirming
# code leaves it off: enabling on a secret an authenticator never really stored
# is how an operator locks themselves out of their own control plane.

NOW = 1_700_000_015.0


def run_2fa(con, action, email=EMAIL, answers=None, monkeypatch=None):
    """Drive a `2fa` subcommand. `answers` feeds the enrolment prompt."""
    if answers is not None:
        supplied = iter(answers)
        monkeypatch.setattr("builtins.input", lambda *a: next(supplied))
    args = argparse.Namespace(command="2fa", action=action, email=email)
    return users_cli.run(con, args)


@pytest.fixture()
def enrolled(con, monkeypatch):
    """An account with two-factor on, and the secret it was enrolled with."""
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    secret = accounts.begin_totp_enrollment(con, user["id"])
    accounts.confirm_totp_enrollment(
        con, user["id"], totp.code_at_time(secret, NOW), at_time=NOW)
    return secret


def test_status_says_off_for_a_new_account(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_2fa(con, "status") == 0
    assert "two-factor off" in capsys.readouterr().out


def test_status_says_on_and_counts_the_recovery_codes(con, enrolled, capsys):
    capsys.readouterr()
    assert run_2fa(con, "status") == 0
    out = capsys.readouterr().out
    assert "two-factor on" in out
    assert f"{accounts.RECOVERY_CODE_COUNT} recovery code(s) left" in out


def test_enable_turns_two_factor_on_when_the_code_is_right(con, monkeypatch, capsys):
    """Driven the way an operator drives it: read the key off the output, put
    the code the app would show back in at the prompt."""
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    monkeypatch.setattr(users_cli.time, "time", lambda: NOW)

    seen = {}
    real_begin = accounts.begin_totp_enrollment

    def capture(connection, user_id):
        seen["secret"] = real_begin(connection, user_id)
        return seen["secret"]

    monkeypatch.setattr(accounts, "begin_totp_enrollment", capture)
    monkeypatch.setattr("builtins.input",
                        lambda *a: totp.code_at_time(seen["secret"], NOW))

    args = argparse.Namespace(command="2fa", action="enable", email=EMAIL)
    assert users_cli.run(con, args) == 0
    out = capsys.readouterr().out
    assert "key: " in out
    assert "otpauth://totp/whichports:" in out
    assert totp.format_secret_groups(seen["secret"]) in out
    assert "two-factor is on" in out
    assert accounts.totp_enabled(accounts.get_user_by_email(con, EMAIL))


def test_enable_prints_the_recovery_codes_once(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    monkeypatch.setattr(users_cli.time, "time", lambda: NOW)
    seen = {}
    real_begin = accounts.begin_totp_enrollment
    monkeypatch.setattr(accounts, "begin_totp_enrollment",
                        lambda c, u: seen.setdefault("secret", real_begin(c, u)))
    monkeypatch.setattr("builtins.input",
                        lambda *a: totp.code_at_time(seen["secret"], NOW))
    users_cli.run(con, argparse.Namespace(command="2fa", action="enable", email=EMAIL))
    out = capsys.readouterr().out
    assert "only time" in out
    user = accounts.get_user_by_email(con, EMAIL)
    assert accounts.recovery_codes_remaining(con, user["id"]) == accounts.RECOVERY_CODE_COUNT
    # Ten codes, each on its own line, in the printed shape.
    assert len(re.findall(r"^  [a-z2-9]{4}-[a-z2-9]{4}$", out, re.M)) == \
        accounts.RECOVERY_CODE_COUNT


def test_a_wrong_confirming_code_leaves_two_factor_off(con, monkeypatch, capsys):
    """The single most important case in this file."""
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    monkeypatch.setattr(users_cli.time, "time", lambda: NOW)
    monkeypatch.setattr("builtins.input", lambda *a: "000000")
    assert users_cli.run(
        con, argparse.Namespace(command="2fa", action="enable", email=EMAIL)) == 1
    captured = capsys.readouterr()
    assert "still off" in captured.err
    assert not accounts.totp_enabled(accounts.get_user_by_email(con, EMAIL))
    user = accounts.get_user_by_email(con, EMAIL)
    assert accounts.recovery_codes_remaining(con, user["id"]) == 0


def test_abandoning_the_prompt_turns_nothing_on(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()

    def interrupted(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupted)
    assert users_cli.run(
        con, argparse.Namespace(command="2fa", action="enable", email=EMAIL)) == 1
    assert "nothing was turned on" in capsys.readouterr().err
    assert not accounts.totp_enabled(accounts.get_user_by_email(con, EMAIL))


def test_enable_refuses_when_it_is_already_on(con, enrolled, capsys):
    capsys.readouterr()
    assert run_2fa(con, "enable") == 1
    assert "already on" in capsys.readouterr().err


def test_disable_turns_it_off_and_destroys_the_codes(con, enrolled, capsys):
    capsys.readouterr()
    user = accounts.get_user_by_email(con, EMAIL)
    assert run_2fa(con, "disable") == 0
    assert "recovery codes destroyed" in capsys.readouterr().out
    assert not accounts.totp_enabled(accounts.get_user_by_email(con, EMAIL))
    assert accounts.recovery_codes_remaining(con, user["id"]) == 0


def test_disable_on_an_account_that_never_had_it_is_not_an_error(con, monkeypatch, capsys):
    """The lockout path has to be safe to run twice by somebody who is not
    sure whether the first one took."""
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_2fa(con, "disable") == 0
    assert "already off" in capsys.readouterr().out


def test_reset_codes_replaces_them_all(con, enrolled, capsys):
    user = accounts.get_user_by_email(con, EMAIL)
    before = {row["code_hash"] for row in
              con.execute("SELECT code_hash FROM totp_recovery_codes")}
    capsys.readouterr()
    assert run_2fa(con, "reset-codes") == 0
    after = {row["code_hash"] for row in
             con.execute("SELECT code_hash FROM totp_recovery_codes")}
    assert before & after == set()
    assert accounts.recovery_codes_remaining(con, user["id"]) == accounts.RECOVERY_CODE_COUNT
    assert len(re.findall(r"^  [a-z2-9]{4}-[a-z2-9]{4}$", capsys.readouterr().out, re.M)) == \
        accounts.RECOVERY_CODE_COUNT


def test_reset_codes_refuses_when_two_factor_is_off(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_2fa(con, "reset-codes") == 1
    assert "two-factor is off" in capsys.readouterr().err


def test_every_2fa_action_refuses_an_account_that_does_not_exist(con, capsys):
    for action in ("status", "enable", "disable", "reset-codes"):
        assert run_2fa(con, action, email="nobody@example.com") == 1
        assert "no account" in capsys.readouterr().err


def test_the_parser_accepts_every_documented_2fa_invocation(tmp_path, monkeypatch):
    """The docstring at the top of users_cli.py is the operator's instructions,
    so every line of it has to parse. Driven through main(), against a real
    temporary database, with only the command body stubbed."""
    parse_db(tmp_path, monkeypatch)
    for action in ("status", "enable", "disable", "reset-codes"):
        seen = {}
        monkeypatch.setattr("sys.argv", ["users", "2fa", action, EMAIL])
        monkeypatch.setattr(users_cli, "run",
                            lambda con, args: seen.setdefault("args", args) and 0)
        assert users_cli.main() == 0
        assert seen["args"].command == "2fa"
        assert seen["args"].action == action
        assert seen["args"].email == EMAIL


def test_the_2fa_command_requires_an_action(monkeypatch):
    """`users_cli 2fa sysadmin@example.com` with no action is a mistake somebody
    will make, and argparse has to catch it rather than run something."""
    monkeypatch.setattr("sys.argv", ["users", "2fa", EMAIL])
    with pytest.raises(SystemExit):
        users_cli.main()


# --------------------------------------------------- connecting a provider
#
# `link` is the reason a valid Google token signs nobody in on its own. The
# property worth reading first: the URL it prints is the secret, it is printed
# once, and the row holds only its SHA-256.

def run_link(con, provider="google", email=EMAIL):
    args = argparse.Namespace(command="link", email=email, provider=provider)
    return users_cli.run(con, args)


def test_link_prints_a_single_use_url(con, monkeypatch, capsys):
    monkeypatch.setenv(oidc.BASE_URL_ENV, "https://app.whichports.example")
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_link(con) == 0
    out = capsys.readouterr().out
    match = re.search(r"https://app\.whichports\.example/login/link/(\S+)", out)
    assert match, out
    assert "works once" in out
    token = match.group(1)
    assert token.startswith(identities.TICKET_PREFIX)
    # The token itself is nowhere in the database.
    rows = con.execute("SELECT * FROM oidc_link_tickets").fetchall()
    assert len(rows) == 1
    assert rows[0]["token_hash"] != token
    assert identities.take_ticket(con, token) is not None
    assert identities.take_ticket(con, token) is None


def test_link_prints_the_path_when_no_base_url_is_set(con, monkeypatch, capsys):
    """Better than printing a wrong address. The operator knows their own."""
    monkeypatch.delenv(oidc.BASE_URL_ENV, raising=False)
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_link(con) == 0
    out = capsys.readouterr().out
    assert "/login/link/whp_link_" in out
    assert oidc.BASE_URL_ENV in out


def test_link_refuses_an_account_that_does_not_exist(con, capsys):
    assert run_link(con, email="nobody@example.com") == 1
    assert "no account" in capsys.readouterr().err


def test_identities_says_none_before_anything_is_linked(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert users_cli.run(
        con, argparse.Namespace(command="identities", email=EMAIL)) == 0
    assert "no provider sign-ins" in capsys.readouterr().out


def test_identities_lists_what_is_linked(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    identities.link(con, "google", "sub-123", user["id"], email_shown=EMAIL)
    capsys.readouterr()
    users_cli.run(con, argparse.Namespace(command="identities", email=EMAIL))
    out = capsys.readouterr().out
    assert "google" in out
    assert EMAIL in out
    # The subject is a key, not something to print on a terminal by default.
    assert "sub-123" not in out


def test_unlink_removes_it_and_says_so_when_there_was_nothing(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    identities.link(con, "google", "sub-123", user["id"])
    capsys.readouterr()
    args = argparse.Namespace(command="unlink", email=EMAIL, provider="google")
    assert users_cli.run(con, args) == 0
    assert "removed" in capsys.readouterr().out
    assert users_cli.run(con, args) == 1
    assert "has no google sign-in" in capsys.readouterr().err


def test_the_parser_refuses_a_provider_this_build_does_not_have(monkeypatch):
    """`choices` on the argument, so a typo is caught before any database work
    rather than minting a ticket nothing can ever answer."""
    monkeypatch.setattr("sys.argv", ["users", "link", EMAIL, "facebook"])
    with pytest.raises(SystemExit):
        users_cli.main()


def test_link_mints_a_ticket_for_the_provider_that_was_asked_for(con, monkeypatch,
                                                                capsys):
    """The ticket carries the provider, so a ticket minted for one cannot be
    spent on another's consent screen."""
    monkeypatch.setenv(oidc.BASE_URL_ENV, "https://app.whichports.example")
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_link(con, provider="microsoft") == 0
    out = capsys.readouterr().out
    assert "sign in with microsoft" in out
    rows = con.execute("SELECT * FROM oidc_link_tickets").fetchall()
    assert [row["provider"] for row in rows] == ["microsoft"]


def test_identities_lists_every_provider_an_account_has(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    identities.link(con, "google", "sub-123", user["id"], email_shown=EMAIL)
    identities.link(con, "microsoft",
                    "aaaabbbb-0000-cccc-1111-dddd2222eeee:"
                    "00aa00aa-bb11-cc22-dd33-44ee44ee44ee",
                    user["id"], email_shown=EMAIL)
    capsys.readouterr()
    users_cli.run(con, argparse.Namespace(command="identities", email=EMAIL))
    out = capsys.readouterr().out
    assert "google" in out
    assert "microsoft" in out
    # The subject is a key, not something to print on a terminal by default.
    assert "sub-123" not in out
    assert "aaaabbbb" not in out


def test_unlink_removes_one_provider_and_leaves_the_other(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    user = accounts.get_user_by_email(con, EMAIL)
    identities.link(con, "google", "sub-123", user["id"])
    identities.link(con, "microsoft", "tenant:object", user["id"])
    capsys.readouterr()
    args = argparse.Namespace(command="unlink", email=EMAIL, provider="microsoft")
    assert users_cli.run(con, args) == 0
    assert "microsoft sign-in removed" in capsys.readouterr().out
    assert users_cli.run(con, args) == 1
    assert "has no microsoft sign-in" in capsys.readouterr().err
    assert [row["provider"] for row in identities.for_user(con, user["id"])] \
        == ["google"]


@pytest.mark.parametrize("command", ["link", "unlink"])
def test_the_parser_accepts_every_provider_this_build_has(tmp_path, monkeypatch,
                                                          command):
    """`choices` comes from PROVIDERS, so adding a provider is one line there
    and this is what says the command line followed it."""
    parse_db(tmp_path, monkeypatch)
    for provider in sorted(users_cli.PROVIDERS):
        seen = {}
        monkeypatch.setattr("sys.argv", ["users", command, EMAIL, provider])
        monkeypatch.setattr(users_cli, "run",
                            lambda con, args: seen.setdefault("args", args) and 0)
        assert users_cli.main() == 0
        assert seen["args"].command == command
        assert seen["args"].provider == provider
    assert sorted(users_cli.PROVIDERS) == ["google", "microsoft"]


# ------------------------------------------------------------- workspaces

def test_add_defaults_to_workspace_one(con, monkeypatch, capsys):
    """Nothing the owner runs today grows an argument, and workspace 1 is where
    the account he already has was backfilled."""
    assert run(con, monkeypatch, "add", email=EMAIL) == 0
    assert accounts.workspace_of(
        accounts.get_user_by_email(con, EMAIL)) == db.DEFAULT_WORKSPACE_ID


def test_add_puts_the_account_in_the_workspace_it_was_given(con, monkeypatch):
    second = db.create_workspace(con, "second")
    assert run(con, monkeypatch, "add", email=EMAIL, workspace=second) == 0
    assert accounts.workspace_of(accounts.get_user_by_email(con, EMAIL)) == second


def test_add_refuses_a_workspace_that_does_not_exist(con, monkeypatch, capsys):
    """A typo must not create an account that can never see anything."""
    assert run(con, monkeypatch, "add", email=EMAIL, workspace=99) == 1
    assert "no workspace 99" in capsys.readouterr().err
    assert accounts.get_user_by_email(con, EMAIL) is None


def test_the_listing_says_which_workspace_each_account_is_in(con, monkeypatch,
                                                            capsys):
    second = db.create_workspace(con, "second")
    run(con, monkeypatch, "add", email=EMAIL)
    run(con, monkeypatch, "add", email="two@example.com", workspace=second)
    capsys.readouterr()
    run(con, monkeypatch, "list")
    out = capsys.readouterr().out
    assert f"workspace: {db.DEFAULT_WORKSPACE_ID}" in out
    assert f"workspace: {second}" in out


# ------------------------------------------------ is a provider configured
#
# This command exists because its absence cost a real afternoon: the credentials
# were in /etc/whichports/controlplane.env, the ingest unit had no
# EnvironmentFile line, so the file was read by nothing and the only symptom was
# a login page with no buttons.

def run_providers(con, check=False):
    return users_cli.run(con, argparse.Namespace(command="providers", check=check))


@pytest.fixture()
def configured(monkeypatch):
    monkeypatch.setenv(oidc.BASE_URL_ENV, "https://app.whichports.example")
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_ID", "123.apps.googleusercontent.com")
    monkeypatch.setenv("WHICHPORTS_GOOGLE_CLIENT_SECRET", "the-secret-value")
    monkeypatch.setenv("WHICHPORTS_MICROSOFT_CLIENT_ID", "abc")
    monkeypatch.setenv("WHICHPORTS_MICROSOFT_CLIENT_SECRET", "the-secret-value")
    monkeypatch.setenv("WHICHPORTS_MICROSOFT_TENANT", "organizations")


def test_providers_reports_nothing_configured_and_says_so_in_its_exit_code(
        con, monkeypatch, capsys):
    for name in (oidc.BASE_URL_ENV, "WHICHPORTS_GOOGLE_CLIENT_ID",
                 "WHICHPORTS_GOOGLE_CLIENT_SECRET", "WHICHPORTS_MICROSOFT_CLIENT_ID",
                 "WHICHPORTS_MICROSOFT_CLIENT_SECRET", "WHICHPORTS_MICROSOFT_TENANT"):
        monkeypatch.delenv(name, raising=False)
    assert run_providers(con) == 1
    out = capsys.readouterr().out
    assert "NOT SET" in out
    assert "answers 404" in out


def test_providers_reports_a_good_configuration(con, configured, capsys):
    assert run_providers(con) == 0
    out = capsys.readouterr().out
    assert "on the login page                yes" in out
    assert "https://app.whichports.example/login/google/callback" in out
    assert "https://app.whichports.example/login/microsoft/callback" in out


def test_providers_never_prints_a_secret(con, configured, capsys):
    """The one thing this command must not do. A client id is not a secret and
    is shown, because reading it back is the point."""
    run_providers(con)
    out = capsys.readouterr().out
    assert "the-secret-value" not in out
    assert "set" in out
    assert "123.apps.googleusercontent.com" in out


def test_providers_prints_the_microsoft_authority_because_it_is_not_a_secret(
        con, configured, capsys):
    """A typo in the authority reads as "not configured" and looks exactly like
    a credential that never arrived, so it has to be readable back."""
    run_providers(con)
    assert "organizations" in capsys.readouterr().out


def test_a_missing_base_url_turns_every_provider_off(con, configured, monkeypatch,
                                                     capsys):
    monkeypatch.delenv(oidc.BASE_URL_ENV)
    assert run_providers(con) == 1
    out = capsys.readouterr().out
    assert out.count("answers 404") == len(PROVIDERS)


def test_a_client_id_without_a_secret_is_reported_as_off(con, configured,
                                                         monkeypatch, capsys):
    monkeypatch.delenv("WHICHPORTS_GOOGLE_CLIENT_SECRET")
    assert run_providers(con) == 1
    assert "/login/google answers 404" in capsys.readouterr().out


def test_providers_says_who_a_sign_in_is_connected_to(con, configured, monkeypatch,
                                                      capsys):
    monkeypatch.setattr(users_cli, "read_password", lambda confirm=True: PASSWORD)
    users_cli.run(con, argparse.Namespace(
        command="add", email=EMAIL, workspace=db.DEFAULT_WORKSPACE_ID))
    user = accounts.get_user_by_email(con, EMAIL)
    identities.link(con, "google", "sub-123", user["id"])
    capsys.readouterr()
    run_providers(con)
    out = capsys.readouterr().out
    assert f"connected to                     {EMAIL}" in out
    assert "nobody yet" in out, "microsoft should still say nobody"


def test_providers_does_not_touch_the_network_without_the_flag(con, configured,
                                                               monkeypatch, capsys):
    """The whole point of `--check` being a flag. A command that reports on
    configuration must work on a box with no route out."""
    def refuse(*args, **kwargs):
        raise AssertionError("providers reached the network without --check")

    monkeypatch.setattr(oidc, "build_opener", refuse)
    assert run_providers(con) == 0
    out = capsys.readouterr().out
    # The result line, not the word. The closing hint mentions the discovery
    # document by name, which an "is the word absent" check trips over.
    assert not [line for line in out.splitlines()
                if line.strip().startswith("discovery ")]


def test_the_check_flag_reports_a_provider_it_cannot_reach(con, configured,
                                                           monkeypatch, capsys):
    oidc.forget_discovery()

    def unreachable(*args, **kwargs):
        raise oidc.OIDCError("could not read the discovery document")

    monkeypatch.setattr(oidc, "discovery", unreachable)
    assert run_providers(con, check=True) == 1
    assert "FAILED" in capsys.readouterr().out


def test_the_parser_accepts_the_command_and_its_flag(tmp_path, monkeypatch):
    parse_db(tmp_path, monkeypatch)
    for argv in (["users", "providers"], ["users", "providers", "--check"]):
        seen = {}
        monkeypatch.setattr("sys.argv", argv)
        monkeypatch.setattr(users_cli, "run",
                            lambda con, args: seen.setdefault("args", args) and 0)
        assert users_cli.main() == 0
        assert seen["args"].command == "providers"
        assert seen["args"].check is ("--check" in argv)


# --------------------------------------------- opening the right database
#
# On 2026-08-23 every command run from a shell on the box opened a database
# nobody meant. A shell does not inherit a service's environment, and
# db.DEFAULT_DB is a relative path, so each command made a second database
# beside the working directory and reported truthfully on that one. `list` said
# there were no accounts. An account created that way went nowhere. Nothing
# errored and nothing was logged.
#
# **The sentence that used to be here said WHICHPORTS_DB lives in the unit's
# EnvironmentFile. It does not, and that was the whole reason the fix did not
# work.** The units set it with `Environment=`, and `EnvironmentFile=` carries
# the credentials, so the file `envfile.load()` reads never had it. On
# 2026-08-27 `users_cli admin grant` on the production box made
# /srv/controlplane/whichports.db and reported no such account. Corrected here
# rather than deleted, because a wrong claim in a test comment is how the next
# session reaches the same wrong conclusion.

def test_the_command_line_reads_the_environment_file_the_units_read(monkeypatch,
                                                                    tmp_path):
    """Without this a command sees none of the service's configuration."""
    chosen = tmp_path / "from-the-file.db"
    db.connect(str(chosen)).close()
    envpath = tmp_path / "cp.env"
    envpath.write_text(f"WHICHPORTS_DB={chosen}\n")
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(envpath))
    monkeypatch.delenv(db.DB_ENV, raising=False)
    monkeypatch.setattr("sys.argv", ["users", "list"])
    seen = {}
    monkeypatch.setattr(users_cli, "run",
                        lambda con, args: seen.setdefault("path", db.db_path()) and 0)
    assert users_cli.main() == 0
    assert seen["path"] == str(chosen)


def test_the_real_environment_still_wins_over_the_file(monkeypatch, tmp_path):
    """Otherwise a file on the box could take the decision away from whoever ran
    the command, and from every test in this suite."""
    chosen = tmp_path / "chosen.db"
    db.connect(str(chosen)).close()
    envpath = tmp_path / "cp.env"
    envpath.write_text("WHICHPORTS_DB=/var/lib/whichports-controlplane/whichports.db\n")
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(envpath))
    monkeypatch.setenv(db.DB_ENV, str(chosen))
    monkeypatch.setattr("sys.argv", ["users", "list"])
    seen = {}
    monkeypatch.setattr(users_cli, "run",
                        lambda con, args: seen.setdefault("path", db.db_path()) and 0)
    users_cli.main()
    assert seen["path"] == str(chosen)


def test_a_database_that_is_not_there_is_refused_rather_than_made(monkeypatch,
                                                                  tmp_path,
                                                                  capsys):
    """**This used to assert a note, and the note was printed on the production
    box on 2026-08-27 while the command carried on regardless.** A note is the
    wrong shape: it is one line of stderr above an answer that looks fine."""
    absent = tmp_path / "brand-new.db"
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(absent))
    monkeypatch.setattr("sys.argv", ["users", "list"])
    ran = []
    monkeypatch.setattr(users_cli, "run", lambda con, args: ran.append(1) or 0)
    with pytest.raises(SystemExit) as refused:
        users_cli.main()
    assert not ran, "the command ran anyway, which is the bug"
    assert not absent.exists(), "the database was made anyway, which is the bug"
    message = str(refused.value)
    assert "brand-new.db" in message
    assert db.DB_ENV in message
    assert envfile.DEFAULT_PATH in message
    assert "--create-database" in message


def test_the_flag_is_how_a_first_run_makes_one(monkeypatch, tmp_path):
    """Bootstrapping is real and happens once. It is a flag somebody types,
    never a side effect of a command that only meant to read."""
    fresh = tmp_path / "fresh.db"
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(fresh))
    monkeypatch.setattr("sys.argv", ["users", "--create-database", "list"])
    monkeypatch.setattr(users_cli, "run", lambda con, args: 0)
    assert users_cli.main() == 0
    assert fresh.exists()


def test_opening_a_database_that_exists_says_nothing(monkeypatch, tmp_path, capsys):
    """A note on every invocation would be noise, and noise is not read."""
    existing = tmp_path / "already.db"
    db.connect(str(existing)).close()
    monkeypatch.setattr(envfile, "DEFAULT_PATH", str(tmp_path / "absent.env"))
    monkeypatch.setenv(db.DB_ENV, str(existing))
    monkeypatch.setattr("sys.argv", ["users", "list"])
    monkeypatch.setattr(users_cli, "run", lambda con, args: 0)
    assert users_cli.main() == 0
    assert capsys.readouterr().err == ""


# ------------------------------------------------- mailing somebody a link
#
# `mail` is the CLI half of docs/screens/sign-in: the three flows the product
# cannot start on its own, because sign-ups are closed and Members is not
# built. The properties worth reading first: the URL is printed whatever the
# relay does, an invitation claims no role, and nothing is sent to an address
# that has no account except an invitation, which is only sent to one that
# has none.

def run_mail(con, kind, email, inviter=None, workspace=None, print_only=True):
    args = argparse.Namespace(command="mail", kind=kind, email=email,
                              inviter=inviter, workspace=workspace,
                              print_only=print_only)
    return users_cli.run(con, args)


@pytest.fixture()
def sent(monkeypatch):
    out = []

    def fake_send(subject, body, config=None, html=""):
        out.append({"subject": subject, "body": body, "html": html,
                    "to": getattr(config, "to", "")})
        return True, ""

    monkeypatch.setattr(users_cli.notify, "send", fake_send)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "mail.example.test")
    return out


def link_printed(capsys):
    out = capsys.readouterr().out
    found = re.findall(r"https://\S+", out)
    assert len(found) == 1, out
    return found[0]


def test_mail_set_password_prints_a_link_that_works(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_mail(con, "set-password", EMAIL) == 0
    url = link_printed(capsys)
    assert "/set-password/" in url
    token = url.rsplit("/", 1)[1]
    assert onetime.look_up(con, onetime.SET_PASSWORD, token) is not None


def test_mail_sends_the_account_mail_to_that_address(con, monkeypatch, capsys, sent):
    run(con, monkeypatch, "add", EMAIL)
    assert run_mail(con, "set-password", EMAIL, print_only=False) == 0
    assert len(sent) == 1
    assert sent[0]["to"] == EMAIL
    assert sent[0]["subject"] == "[whichports] Your whichports account"
    # the link is in both halves of the mail
    url = re.findall(r"https://\S+", sent[0]["body"])[0]
    assert url in sent[0]["html"]


def test_mail_prints_the_link_even_when_the_relay_refuses(con, monkeypatch, capsys):
    """A relay that is down must not leave the operator with nothing: the link
    exists, it is the only copy, and handing it over another way is their
    call."""
    run(con, monkeypatch, "add", EMAIL)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "mail.example.test")
    monkeypatch.setattr(users_cli.notify, "send", lambda *a, **k: (False, "relay refused"))
    capsys.readouterr()
    assert run_mail(con, "set-password", EMAIL, print_only=False) == 1
    assert "/set-password/" in link_printed(capsys)


def test_mail_to_an_address_with_no_account_is_refused(con, capsys):
    assert run_mail(con, "set-password", "nobody@example.com") == 1
    assert "no account" in capsys.readouterr().err


def test_mail_confirm_issues_a_confirm_link(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_mail(con, "confirm", EMAIL) == 0
    token = link_printed(capsys).rsplit("/", 1)[1]
    assert onetime.look_up(con, onetime.CONFIRM, token) is not None


def test_an_invitation_carries_the_workspace_and_claims_no_role(con, monkeypatch, capsys, sent):
    run(con, monkeypatch, "add", EMAIL)
    assert run_mail(con, "invite", "dad@example.com", inviter=EMAIL,
                    print_only=False) == 0
    link = onetime.look_up(
        con, onetime.INVITE,
        re.findall(r"https://\S+", sent[0]["body"])[0].rsplit("/", 1)[1])
    assert link is not None
    assert link["invited_by"] == EMAIL
    assert link["workspace_id"] == db.DEFAULT_WORKSPACE_ID
    assert not link["role"]
    # and the mail says who and where, and nothing about a permission level
    assert ", as ." not in sent[0]["body"]
    assert "Admin" not in sent[0]["body"]


def test_an_invitation_needs_an_inviter_that_exists(con, capsys):
    assert run_mail(con, "invite", "dad@example.com", inviter="nobody@example.com") == 1
    assert "no account" in capsys.readouterr().err


def test_an_invitation_to_an_address_that_has_an_account_is_refused(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_mail(con, "invite", EMAIL, inviter=EMAIL) == 1
    assert "already has an account" in capsys.readouterr().err


def test_an_invitation_into_a_workspace_that_does_not_exist_is_refused(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    assert run_mail(con, "invite", "dad@example.com", inviter=EMAIL, workspace=999) == 1
    assert "no workspace" in capsys.readouterr().err


def test_asking_twice_replaces_the_earlier_link(con, monkeypatch, capsys):
    run(con, monkeypatch, "add", EMAIL)
    capsys.readouterr()
    run_mail(con, "set-password", EMAIL)
    first = link_printed(capsys).rsplit("/", 1)[1]
    run_mail(con, "set-password", EMAIL)
    second = link_printed(capsys).rsplit("/", 1)[1]
    assert onetime.look_up(con, onetime.SET_PASSWORD, first) is None
    assert onetime.look_up(con, onetime.SET_PASSWORD, second) is not None
