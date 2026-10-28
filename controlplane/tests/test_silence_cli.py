"""The one command that stops a server or a port mailing.

    python -m pytest tests/test_silence_cli.py

`docs/PRODUCT.md` 4c asks for a mute from the dashboard or one CLI command, and
this is the command. The tests are about refusals rather than formatting: a
typo must not quietly mute nothing, and a mute must not be openable for zero
hours or for a negative number of them.
"""

import argparse
from datetime import datetime, timedelta, timezone

import pytest

from app import (alerts, db, finding_alerts, intent, prober, silence_cli,
                 store)

NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    prober.init(connection)
    intent.init(connection)
    alerts.init(connection)
    finding_alerts.init(connection)
    store.add_host(connection, "one")
    yield connection
    connection.close()


def run(con, command, **kw):
    # The same defaults parse_args produces, `workspace` included, so this
    # drives the command with what a terminal would actually hand it.
    args = argparse.Namespace(command=command, host="one", protocol="tcp",
                              port=443, family="v4",
                              workspace=db.DEFAULT_WORKSPACE_ID,
                              hours=finding_alerts.DEFAULT_MUTE_SECONDS / 3600)
    for key, value in kw.items():
        setattr(args, key, value)
    return silence_cli.run(con, args)


def host_id(con):
    return con.execute("SELECT id FROM hosts WHERE name = 'one'").fetchone()["id"]


# ------------------------------------------------------------------- the mute

def test_a_mute_takes_effect_and_expires(con):
    assert run(con, "mute") == 0
    now = datetime.now(timezone.utc)
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4",
                                  now=now + timedelta(hours=1)) is not None
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4",
                                  now=now + timedelta(hours=3)) is None


def test_a_mute_can_be_given_a_length(con):
    assert run(con, "mute", hours=8) == 0
    now = datetime.now(timezone.utc)
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4",
                                  now=now + timedelta(hours=7)) is not None


@pytest.mark.parametrize("hours", [0, -1])
def test_a_mute_for_no_time_at_all_is_refused(con, hours):
    assert run(con, "mute", hours=hours) == 1
    assert finding_alerts.list_silences(con) == []


def test_muting_the_wrong_name_is_refused_rather_than_ignored(con, capsys):
    assert run(con, "mute", host="nosuchhost") == 1
    assert "no host named" in capsys.readouterr().err
    assert finding_alerts.list_silences(con) == []


def test_unmuting_something_that_was_not_muted_reports_it(con, capsys):
    assert run(con, "unmute") == 1
    assert "was not muted" in capsys.readouterr().err


def test_unmuting_lifts_the_mute(con):
    run(con, "mute")
    assert run(con, "unmute") == 0
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4") is None


def test_muting_twice_leaves_one_live_mute(con):
    run(con, "mute")
    run(con, "mute", hours=6)
    live = [row for row in finding_alerts.list_silences(con)
            if row["kind"] == finding_alerts.SILENCE_MUTE]
    assert len(live) == 1


# ---------------------------------------------------------------- the silence

def test_a_silenced_port_stays_silenced(con):
    assert run(con, "silence") == 0
    far = datetime.now(timezone.utc) + timedelta(days=4000)
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4",
                                  now=far) == finding_alerts.SILENCE_PORT


def test_a_silence_covers_only_the_port_it_names(con):
    run(con, "silence", port=80)
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4") is None


def test_unsilencing_something_that_was_not_silenced_reports_it(con, capsys):
    assert run(con, "unsilence") == 1
    assert "was not silenced" in capsys.readouterr().err


def test_unsilencing_lifts_it(con):
    run(con, "silence")
    assert run(con, "unsilence") == 0
    assert finding_alerts.silenced(con, host_id(con), "tcp", 443, "v4") is None


# ------------------------------------------------------------------ the listing

def test_the_listing_says_nothing_is_muted_when_nothing_is(con, capsys):
    assert run(con, "list") == 0
    assert "nothing is muted or silenced" in capsys.readouterr().out


def test_the_listing_names_the_scope_of_each_row(con, capsys):
    run(con, "mute")
    run(con, "silence", port=2019)
    assert run(con, "list") == 0
    printed = capsys.readouterr().out
    assert "every port" in printed
    assert "tcp/2019 on v4" in printed
    assert "no expiry" in printed


def test_the_listing_drops_a_mute_that_has_expired(con, capsys):
    finding_alerts.mute_host(con, "one", now=NOW - timedelta(days=1))
    assert run(con, "list") == 0
    assert "nothing is muted or silenced" in capsys.readouterr().out


# ----------------------------------------------------------------- the parser

def test_the_parser_refuses_a_family_that_is_not_one(capsys):
    with pytest.raises(SystemExit):
        silence_cli.parse_args(["silence", "one", "tcp", "443", "v5"])


def test_the_parser_needs_a_command(capsys):
    with pytest.raises(SystemExit):
        silence_cli.parse_args([])


def test_the_parser_defaults_a_mute_to_two_hours():
    args = silence_cli.parse_args(["mute", "one"])
    assert args.hours == 2


# ------------------------------------------------------------- workspaces

def test_every_command_defaults_to_workspace_one():
    """Nothing the owner runs today grows an argument. Read from the parser rather
    than assumed, for every subcommand, because a flag added to five of six is
    the one that would be missed."""
    for argv in (["mute", "one"], ["unmute", "one"],
                 ["silence", "one", "tcp", "443", "v4"],
                 ["unsilence", "one", "tcp", "443", "v4"], ["list"]):
        assert silence_cli.parse_args(argv).workspace == db.DEFAULT_WORKSPACE_ID


def test_a_server_in_another_workspace_cannot_be_muted(con, capsys):
    second = db.create_workspace(con, "second")
    store.add_host(con, "theirs", workspace_id=second)
    assert run(con, "mute", host="theirs") == 1
    assert "no host named 'theirs'" in capsys.readouterr().err
    assert finding_alerts.list_silences(con) == []


def test_a_server_in_another_workspace_cannot_be_silenced(con, capsys):
    second = db.create_workspace(con, "second")
    store.add_host(con, "theirs", workspace_id=second)
    assert run(con, "silence", host="theirs") == 1
    assert finding_alerts.list_silences(con) == []


def test_naming_the_workspace_reaches_its_own_server(con):
    second = db.create_workspace(con, "second")
    store.add_host(con, "theirs", workspace_id=second)
    assert run(con, "mute", host="theirs", workspace=second) == 0
    assert len(finding_alerts.list_silences(con, workspace_id=second)) == 1
    assert finding_alerts.list_silences(con, workspace_id=1) == []


def test_the_listing_shows_only_this_workspaces_silences(con, capsys):
    second = db.create_workspace(con, "second")
    store.add_host(con, "theirs", workspace_id=second)
    run(con, "mute")
    run(con, "mute", host="theirs", workspace=second)
    capsys.readouterr()

    run(con, "list")
    mine = capsys.readouterr().out
    assert "one" in mine
    assert "theirs" not in mine

    run(con, "list", workspace=second)
    theirs = capsys.readouterr().out
    assert "theirs" in theirs
