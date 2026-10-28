"""Where alerts go, as rows that hold no secret.

    python -m pytest tests/test_channels.py

The property this file exists to hold: **there is no way to put a credential in
this table.** A row names an environment variable and the value is read at send
time, so the renderer can be told a channel exists without being told its URL.
`docs/RECORD.md` 4.86.
"""
import ast
import inspect
import re
from datetime import datetime, timezone

import pytest

from app import channels, channels_cli, db, outbound

NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
ENV = {"WHICHPORTS_WEBHOOK_URL": "https://hooks.example.com/T00/SUPERSECRET"}


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    channels.init(connection)
    yield connection
    connection.close()


def a_webhook(con, label="ops", env_name="WHICHPORTS_WEBHOOK_URL"):
    return channels.add(con, channels.TYPE_WEBHOOK, label, env_name, now=NOW)


# ------------------------------------------------ no row can hold a secret

def test_the_row_holds_a_name_and_the_value_comes_from_the_environment(con):
    channel = a_webhook(con)
    assert channel.destination_env == "WHICHPORTS_WEBHOOK_URL"
    assert channel.resolve(ENV) == ENV["WHICHPORTS_WEBHOOK_URL"]
    stored = con.execute("SELECT * FROM notification_channels").fetchone()
    assert "SUPERSECRET" not in " ".join(str(v) for v in tuple(stored))


def test_a_row_may_hold_its_destination_now(con):
    """**This test used to assert the opposite**, that no column could hold a
    destination, and called it a property of the schema rather than a promise
    about the code. The owner reversed that on 2026-08-22: store it the way
    every other product does. The column exists, and what guards it is the two
    tests below rather than its absence."""
    columns = {row[1] for row in
               con.execute("PRAGMA table_info(notification_channels)")}
    assert "destination" in columns
    assert "destination_env" in columns


def test_a_channel_is_configured_one_way_or_the_other_and_not_both(con):
    """Two sources for one answer is two things to keep in step, and the sender
    would have to pick. It cannot arise."""
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_SLACK, "both", "WHICHPORTS_SLACK_URL",
                     destination="https://hooks.slack.com/services/T/B/X")
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_SLACK, "neither", "")


def test_what_a_renderer_gets_has_no_destination_on_it(con):
    """**The guard that replaced the schema guarantee.** The old table had no
    column a destination could go in, so a renderer could not leak one by
    accident. It can now, so the renderer is handed an object that does not
    carry it."""
    stored = channels.add(con, channels.TYPE_SLACK, "ops", "",
                          destination="https://hooks.slack.com/services/T/B/SUPERSECRET")
    assert stored.destination.endswith("SUPERSECRET"), "the sender still gets it"
    shown = stored.for_display()
    assert shown.destination == ""
    assert "SUPERSECRET" not in repr(shown)
    # everything a screen actually needs survives
    assert shown.label == "ops"
    assert shown.type == channels.TYPE_SLACK
    assert shown.enabled is True


def test_a_stored_destination_never_reaches_a_repr(con):
    """It reaches a log the moment anything formats a row, which is how
    app/notify.py leaked a relay password until 4.83."""
    stored = channels.add(con, channels.TYPE_SLACK, "ops", "",
                          destination="https://hooks.slack.com/services/T/B/SUPERSECRET")
    assert "SUPERSECRET" not in repr(stored)
    assert "destination=set" in repr(stored)


def test_a_stored_destination_is_what_the_sender_resolves_to(con):
    stored = channels.add(con, channels.TYPE_SLACK, "ops", "",
                          destination="https://hooks.slack.com/services/T/B/X")
    # and it does not consult the environment at all for such a row
    assert stored.resolve({}) == "https://hooks.slack.com/services/T/B/X"


def test_a_variable_row_still_works_exactly_as_before(con):
    """The production box is configured this way and nothing on it changes."""
    stored = a_webhook(con)
    assert stored.destination == ""
    assert stored.resolve({"WHICHPORTS_WEBHOOK_URL": "https://x.example/h"}) \
        == "https://x.example/h"


def test_two_rows_holding_one_destination_are_one_delivery_key(con):
    """The 4.87 property, kept. Keyed on the row id, adding a second row for a
    destination already configured would look new and re-post every open alert
    to it."""
    from app import alerts as alerts_mod
    url = "https://hooks.slack.com/services/T/B/X"
    one = channels.add(con, channels.TYPE_SLACK, "one", "", destination=url)
    two = channels.add(con, channels.TYPE_SLACK, "two", "", destination=url)
    assert alerts_mod.key_for_channel(one) == alerts_mod.key_for_channel(two)


def test_the_delivery_key_of_a_stored_destination_is_not_the_destination(con):
    """A key is read by a person debugging a delivery and is written into
    alert_deliveries, so it must not be the credential."""
    from app import alerts as alerts_mod
    url = "https://hooks.slack.com/services/T/B/SUPERSECRET"
    stored = channels.add(con, channels.TYPE_SLACK, "ops", "", destination=url)
    key = alerts_mod.key_for_channel(stored)
    assert "SUPERSECRET" not in key
    assert url not in key
    assert key.startswith("slack:#")


def test_two_different_destinations_are_two_keys(con):
    from app import alerts as alerts_mod
    one = channels.add(con, channels.TYPE_SLACK, "one", "",
                       destination="https://hooks.slack.com/services/T/B/ONE")
    two = channels.add(con, channels.TYPE_SLACK, "two", "",
                       destination="https://hooks.slack.com/services/T/B/TWO")
    assert alerts_mod.key_for_channel(one) != alerts_mod.key_for_channel(two)


def test_a_destination_that_is_not_a_url_is_refused_without_being_echoed(con):
    for bad in ("hooks.slack.com/services/T/B/SUPERSECRET", "ftp://x", "SUPERSECRET"):
        try:
            channels.add(con, channels.TYPE_SLACK, f"c{len(bad)}", "", destination=bad)
        except channels.ChannelError as exc:
            assert "SUPERSECRET" not in str(exc)
        else:
            raise AssertionError(f"{bad!r} should be refused")


def test_a_repr_cannot_carry_a_value(con):
    text = repr(a_webhook(con))
    assert "SUPERSECRET" not in text
    assert "WHICHPORTS_WEBHOOK_URL" in text


def test_an_unset_variable_is_an_empty_destination_not_a_crash(con):
    assert a_webhook(con).resolve({}) == ""


# --------------------------------------------- a row may only name ours

@pytest.mark.parametrize("name", [
    "PATH", "HOME", "AWS_SECRET_ACCESS_KEY", "whichports_webhook_url",
    "WHICHPORTS_", "SOMETHING_WHICHPORTS_URL", "WHICHPORTS_URL; rm -rf /",
    "", "   ",
])
def test_a_row_cannot_name_a_variable_that_is_not_ours(con, name):
    """The database is reachable by more things than the environment is, so a
    row that could name any variable is a row that could point the sender at
    one we never meant it to read."""
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_WEBHOOK, "x", name, now=NOW)


def test_naming_one_of_ours_is_allowed(con):
    for name in ("WHICHPORTS_WEBHOOK_URL", "WHICHPORTS_WEBHOOK_URL_2",
                 "WHICHPORTS_A"):
        channels.add(con, channels.TYPE_WEBHOOK, f"c {name}", name, now=NOW)
    assert len(channels.live(con)) == 3


def test_naming_a_variable_is_not_permission_to_use_what_is_in_it(con):
    """A narrowing and never a permission. The sender still checks what it got,
    so a row naming a variable that holds a token rather than a URL delivers
    nothing."""
    from app import webhook
    channel = channels.add(con, channels.TYPE_WEBHOOK, "wrong",
                           "WHICHPORTS_HETZNER_TOKEN", now=NOW)
    value = channel.resolve({"WHICHPORTS_HETZNER_TOKEN": "abc123token"})
    complaint = webhook.check_url(value, resolver=lambda h: ["185.199.108.153"])
    assert complaint
    assert "abc123token" not in complaint, "a refusal echoed the value"


# ------------------------------------------------------------ the label

@pytest.mark.parametrize("label", ["", " ", "-starts-with-a-dash", "x" * 49,
                                   "has\nnewline", "<script>"])
def test_a_label_is_bounded_at_the_door(con, label):
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_WEBHOOK, label,
                     "WHICHPORTS_WEBHOOK_URL", now=NOW)


def test_two_channels_cannot_share_a_label(con):
    """Labels are how a person tells two webhooks apart."""
    a_webhook(con, label="ops")
    with pytest.raises(channels.ChannelError):
        a_webhook(con, label="ops")


def test_a_removed_label_can_be_used_again(con):
    a_webhook(con, label="ops")
    assert channels.remove(con, "ops") is True
    a_webhook(con, label="ops")
    assert [c.label for c in channels.live(con)] == ["ops"]


def test_an_unknown_type_is_refused(con):
    with pytest.raises(channels.ChannelError):
        channels.add(con, "carrier pigeon", "x", "WHICHPORTS_A", now=NOW)


# ------------------------------------------------------- on, off, removed

def test_off_is_not_removed(con):
    """Turning one off for an afternoon is a different act from deciding it
    should not exist, so a screen listing where alerts go still shows it."""
    a_webhook(con)
    assert channels.set_enabled(con, "ops", False) is True
    assert [c.enabled for c in channels.live(con)] == [False]
    assert channels.sending(con, channels.TYPE_WEBHOOK, ENV) == []


def test_a_removed_channel_leaves_every_list(con):
    a_webhook(con)
    channels.remove(con, "ops")
    assert channels.live(con) == []
    assert channels.sending(con, channels.TYPE_WEBHOOK, ENV) == []


def test_a_channel_with_an_unset_variable_is_listed_but_does_not_send(con):
    """Configured and not deliverable is a thing an operator needs to see on a
    screen, and not a thing for a sender to act on."""
    a_webhook(con, env_name="WHICHPORTS_NOT_SET")
    assert len(channels.live(con)) == 1
    assert channels.sending(con, channels.TYPE_WEBHOOK, ENV) == []


def test_types_are_kept_apart(con):
    a_webhook(con, label="hook")
    channels.add(con, channels.TYPE_EMAIL, "mail", "WHICHPORTS_ALERT_TO", now=NOW)
    assert [c.label for c in channels.live(con, channels.TYPE_WEBHOOK)] == ["hook"]
    assert [c.label for c in channels.live(con, channels.TYPE_EMAIL)] == ["mail"]


def test_a_database_without_the_table_lists_nothing_rather_than_raising(tmp_path):
    """The renderer meets databases the sweep has not touched yet."""
    con = db.connect(str(tmp_path / "bare.db"))
    db.init(con)
    assert channels.live(con) == []
    con.close()


# ------------------------------------------------------------- the command

def test_the_listing_says_whether_a_variable_is_set_and_never_its_value(con, capsys):
    a_webhook(con)
    a_webhook(con, label="quiet", env_name="WHICHPORTS_NOT_SET")
    channels_cli.run(con, channels_cli.parse_args(["list"]), ENV)
    out = capsys.readouterr().out
    assert "SUPERSECRET" not in out
    assert "WHICHPORTS_WEBHOOK_URL  (set)" in out
    assert "NOT SET in this environment" in out


def test_adding_says_at_once_when_the_variable_is_missing(con, capsys):
    """Said when it is created rather than discovered later when an alert does
    not arrive."""
    channels_cli.run(con, channels_cli.parse_args(
        ["add", "--type", "webhook", "--label", "ops",
         "--env", "WHICHPORTS_NOT_SET"]), ENV)
    assert "delivers nothing yet" in capsys.readouterr().out


def test_an_empty_list_says_alerts_go_nowhere(con, capsys):
    channels_cli.run(con, channels_cli.parse_args(["list"]), ENV)
    assert "delivered nowhere" in capsys.readouterr().out


def test_a_bad_variable_name_exits_non_zero(con, capsys):
    code = channels_cli.run(con, channels_cli.parse_args(
        ["add", "--type", "webhook", "--label", "x", "--env", "PATH"]), ENV)
    assert code == 2
    assert "WHICHPORTS_" in capsys.readouterr().err


def test_switching_an_unknown_channel_is_an_error(con, capsys):
    assert channels_cli.run(con, channels_cli.parse_args(
        ["off", "--label", "nope"]), ENV) == 1


# --------------------------------------- telegram's destination is its token
#
# With the environment expander gone from the Add channel window (the owner,
# 2026-08-23), pasting the bot token is the screen's only route to a telegram
# channel, and a token is not a URL. Telegram shows the shape without defining
# a grammar (core.telegram.org/bots/api, Authorizing your bot, read
# 2026-08-23), so the pattern is deliberately loose and these tests hold its
# edges.

TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"


def test_a_telegram_destination_is_the_bot_token(con):
    stored = channels.add(con, channels.TYPE_TELEGRAM, "tg", "",
                          destination=TOKEN,
                          destination_extra="-1001234567890")
    assert stored.resolve({}) == TOKEN


def test_a_url_pasted_as_a_telegram_destination_is_refused_without_echo(con):
    """The mistake worth catching: the thing pasted here by accident is a
    webhook URL, and app/senders.py would build a request no endpoint answers
    from it."""
    for bad in ("https://hooks.slack.com/T/B/SUPERSECRET",
                "http://example.com/SUPERSECRET",
                "not a token", "ABC:123def", ":", "123456:", ":abc", ""):
        try:
            channels.add(con, channels.TYPE_TELEGRAM, f"t{len(bad)}", "",
                         destination=bad, destination_extra="-100123")
        except channels.ChannelError as exc:
            assert "SUPERSECRET" not in str(exc), bad
        else:
            raise AssertionError(f"{bad!r} should be refused")


def test_the_telegram_token_length_boundary(con):
    """256 is ours, said so in channels.py. The last one that fits and the
    first that does not."""
    fits = "1:" + "a" * 254
    channels.add(con, channels.TYPE_TELEGRAM, "fits", "", destination=fits,
                 destination_extra="-100123")
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_TELEGRAM, "over", "",
                     destination=fits + "a", destination_extra="-100123")


def test_a_telegram_token_row_builds_the_documented_request(con):
    """End to end: the sender puts the stored token in the URL Telegram
    documents, api.telegram.org/bot<token>/sendMessage."""
    from app import senders
    stored = channels.add(con, channels.TYPE_TELEGRAM, "tg", "",
                          destination=TOKEN,
                          destination_extra="-1001234567890")
    config, extras = senders.target(stored, env={})
    assert config.url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"


# --------------------------------------------------- replacing a destination

NEW_URL = "https://hooks.slack.com/services/T/B/NEWSECRET"


def a_slack(con, label="ops", url="https://hooks.slack.com/services/T/B/OLD"):
    return channels.add(con, channels.TYPE_SLACK, label, "", destination=url)


def test_set_destination_replaces_the_value(con):
    a_slack(con)
    assert channels.set_destination(con, "ops", NEW_URL) is True
    stored = channels.live(con)[0]
    assert stored.destination == NEW_URL


def test_set_destination_moves_a_variable_row_onto_its_own_value(con):
    """One of the two, never both: the variable name is cleared the moment the
    row holds a value."""
    a_webhook(con)
    assert channels.set_destination(con, "ops", NEW_URL) is True
    stored = channels.live(con)[0]
    assert stored.destination == NEW_URL
    assert stored.destination_env == ""


def test_set_destination_validates_by_the_rows_own_type(con):
    """Same rules as add, chosen by what the row is, not by what was sent."""
    a_slack(con)
    with pytest.raises(channels.ChannelError):
        channels.set_destination(con, "ops", "not-a-url-SUPERSECRET")
    channels.add(con, channels.TYPE_EMAIL, "mail", "",
                 destination="old@example.com")
    with pytest.raises(channels.ChannelError):
        channels.set_destination(con, "mail", NEW_URL)
    assert channels.set_destination(con, "mail", "new@example.com") is True


def test_set_destination_writes_the_kinds_it_is_given_in_the_same_write(con):
    """An Edit window holds the destination and the kinds, and its one Save
    writes both. The kinds were dropped and the answer still said saved (the
    second big test, finding E20). None leaves the kinds as they are, for a
    caller that sends no kinds."""
    a_slack(con)
    assert channels.set_destination(con, "ops", NEW_URL,
                                    subscriptions=["silent", "cve"]) is True
    stored = channels.live(con)[0]
    assert (stored.destination, stored.subscriptions) == (NEW_URL, "cve,silent")
    assert channels.set_destination(con, "ops", NEW_URL + "2") is True
    assert channels.live(con)[0].subscriptions == "cve,silent"
    assert channels.set_destination(con, "ops", NEW_URL, subscriptions=[]) is True
    assert channels.live(con)[0].subscriptions == ""


def test_set_destination_with_a_kind_that_does_not_exist_writes_nothing(con):
    a_slack(con)
    with pytest.raises(channels.ChannelError):
        channels.set_destination(con, "ops", NEW_URL, subscriptions=["silent", "nonsense"])
    stored = channels.live(con)[0]
    assert stored.destination.endswith("OLD") and stored.subscriptions == ""


def test_set_destination_refuses_an_empty_value(con):
    a_slack(con)
    with pytest.raises(channels.ChannelError):
        channels.set_destination(con, "ops", "   ")
    assert channels.live(con)[0].destination.endswith("OLD")


def test_set_destination_on_an_unknown_or_removed_label_is_false(con):
    assert channels.set_destination(con, "ghost", NEW_URL) is False
    a_slack(con)
    channels.remove(con, "ops", now=NOW)
    assert channels.set_destination(con, "ops", NEW_URL) is False


def test_set_destination_checks_the_extra_against_the_type(con):
    a_slack(con)
    with pytest.raises(channels.ChannelError):
        channels.set_destination(con, "ops", NEW_URL,
                                 destination_extra="-100123")
    stored = channels.add(con, channels.TYPE_TELEGRAM, "tg", "",
                          destination=TOKEN,
                          destination_extra="-1001234567890")
    with pytest.raises(channels.ChannelError):
        channels.set_destination(con, "tg", TOKEN, destination_extra="")
    assert channels.set_destination(con, "tg", TOKEN,
                                    destination_extra="-100999:7") is True
    assert channels.live(con)[1].destination_extra == "-100999:7"


def test_set_destination_refusals_never_echo_the_value(con):
    a_slack(con)
    for value, extra in (("not-a-url-SUPERSECRET", ""),
                         ("https://x.example/SUPERSECRET", "-100123"),
                         ("", "")):
        try:
            channels.set_destination(con, "ops", value,
                                     destination_extra=extra)
        except channels.ChannelError as exc:
            assert "SUPERSECRET" not in str(exc), (value, extra)
        else:
            raise AssertionError(f"{(value, extra)!r} should be refused")


def test_a_replaced_destination_is_a_new_delivery_key(con):
    """Said in the docstring and held here: replacing the value moves the row
    to a new key, exactly as removing it and adding it back would."""
    from app import alerts as alerts_mod
    stored = a_slack(con)
    old_key = alerts_mod.key_for_channel(stored)
    channels.set_destination(con, "ops", NEW_URL)
    new_key = alerts_mod.key_for_channel(channels.live(con)[0])
    assert old_key != new_key


# ------------------------------------------- test, from the terminal
#
# The Alerts screen hands this command over for every row whose secret the
# dashboard process does not hold, so it is part of that answer. A command the
# answer names and which does not send would make the answer a lie, which is
# what `python -m app.sweep_cli --dry-run` was: "sweep, print, send nothing".

def test_the_command_sends_to_a_channel_reading_the_environment(con, capsys,
                                                               monkeypatch):
    """The case the screen hands over: a row naming a variable, run in a shell
    where that variable is set."""
    posted = []
    monkeypatch.setattr(channels_cli.senders.webhook, "send",
                        lambda body, config, **kw: (posted.append(config.url),
                                                    (True, ""))[1])
    a_webhook(con)
    assert channels_cli.run(con, channels_cli.parse_args(
        ["test", "--label", "ops"]), ENV) == 0
    assert posted == [ENV["WHICHPORTS_WEBHOOK_URL"]]
    assert "sent a test message to ops" in capsys.readouterr().out


def test_the_command_says_why_when_the_variable_is_not_set_here(con, capsys,
                                                               monkeypatch):
    """Run without sourcing alerts.env, which is the mistake this is for."""
    posted = []
    monkeypatch.setattr(channels_cli.senders.webhook, "send",
                        lambda body, config, **kw: (posted.append(1), (True, ""))[1])
    a_webhook(con, env_name="WHICHPORTS_NOT_SET")
    assert channels_cli.run(con, channels_cli.parse_args(
        ["test", "--label", "ops"]), ENV) == 1
    err = capsys.readouterr().err
    assert "WHICHPORTS_NOT_SET" in err
    assert posted == [], "a send was attempted with nothing to send to"


def test_the_command_never_prints_a_destination(con, capsys, monkeypatch):
    """Same rule as every refusal in this module: the failure reason is a class
    name or one of our sentences, never the URL."""
    monkeypatch.setattr(channels_cli.senders.webhook, "send",
                        lambda body, config, **kw: (False, "TimeoutError"))
    a_webhook(con)
    assert channels_cli.run(con, channels_cli.parse_args(
        ["test", "--label", "ops"]), ENV) == 1
    both = capsys.readouterr()
    assert "TimeoutError" in both.err
    assert "SUPERSECRET" not in both.err + both.out


def test_testing_an_unknown_channel_is_an_error(con, capsys):
    assert channels_cli.run(con, channels_cli.parse_args(
        ["test", "--label", "nope"]), ENV) == 1
    assert "nope" in capsys.readouterr().err


def test_testing_a_mail_channel_needs_the_relay_in_this_environment(con, capsys):
    """The relay password is in the same file as the channel variables, so an
    unsourced shell is told rather than getting an SMTP error."""
    channels.add(con, channels.TYPE_EMAIL, "ops inbox", "",
                 destination="ops@example.com", now=NOW)
    assert channels_cli.run(con, channels_cli.parse_args(
        ["test", "--label", "ops inbox"]), ENV) == 1
    assert "alerts.env" in capsys.readouterr().err


def test_the_command_goes_through_the_same_path_an_alert_takes(con, monkeypatch):
    """A test that took a different route would prove the wrong thing. This
    asserts it reaches `webhook.send`, which is where every safety property
    lives: no proxy, no redirect, every resolved address globally routable."""
    seen = {}
    monkeypatch.setattr(channels_cli.senders.webhook, "send",
                        lambda body, config, **kw: (seen.update(body=body), (True, ""))[1])
    a_webhook(con)
    channels_cli.run(con, channels_cli.parse_args(["test", "--label", "ops"]), ENV)
    # and it says it is a test, because whoever reads it may not be whoever ran
    # the command, and it names no host because none is involved
    assert seen["body"]["kind"] == "test"


# --------------------------------------------- one workspace's rows, not all
#
# Channels were fleet-wide until 2026-08-29, which was fine while the owner was
# the only account and became a tenant leak the moment a second workspace
# could exist: every workspace's Alerts page listed every other workspace's
# channel labels. A row belongs to one workspace now, the way hosts and users
# already do.

def test_live_scoped_to_a_workspace_lists_only_its_rows(con):
    channels.add(con, channels.TYPE_WEBHOOK, "ours", "WHICHPORTS_WEBHOOK_URL",
                 now=NOW, workspace_id=1)
    channels.add(con, channels.TYPE_WEBHOOK, "theirs", "WHICHPORTS_WEBHOOK_URL",
                 now=NOW, workspace_id=2)
    assert [c.label for c in channels.live(con, workspace_id=1)] == ["ours"]
    assert [c.label for c in channels.live(con, workspace_id=2)] == ["theirs"]
    # None is every row, which is the sweep's view and the CLI's, never a
    # screen's.
    assert {c.label for c in channels.live(con)} == {"ours", "theirs"}


def test_two_workspaces_can_both_call_a_channel_ops(con):
    """The label is how a person tells their own channels apart, so the
    uniqueness is per workspace: workspace 2 naming a channel "ops" is not a
    fact about workspace 1."""
    channels.add(con, channels.TYPE_WEBHOOK, "ops", "WHICHPORTS_WEBHOOK_URL",
                 now=NOW, workspace_id=1)
    two = channels.add(con, channels.TYPE_WEBHOOK, "ops",
                       "WHICHPORTS_WEBHOOK_URL", now=NOW, workspace_id=2)
    assert two.workspace_id == 2


def test_one_workspace_still_cannot_reuse_its_own_label(con):
    a_webhook(con, label="ops")
    with pytest.raises(channels.ChannelError):
        a_webhook(con, label="ops")


def test_a_label_action_scoped_to_another_workspace_changes_nothing(con):
    """The refusal is "not found", the same answer the host routes give for
    another workspace's host, so a probe with a guessed label learns nothing
    and changes less."""
    a_webhook(con, label="ops")  # workspace 1
    assert channels.set_enabled(con, "ops", False, workspace_id=2) is False
    assert channels.remove(con, "ops", workspace_id=2) is False
    assert channels.rename(con, "ops", "theirs", workspace_id=2) is False
    assert channels.set_subscriptions(con, "ops", ["silent"],
                                      workspace_id=2) is False
    assert channels.set_destination(
        con, "ops", "https://hooks.example.com/T0/B0/x",
        workspace_id=2) is False
    row = channels.live(con, workspace_id=1)[0]
    assert row.enabled and row.label == "ops"
    # And the scoped action from its own workspace still works.
    assert channels.set_enabled(con, "ops", False, workspace_id=1) is True


def test_a_database_from_before_workspaces_is_migrated_by_init(tmp_path):
    """The box's own table predates the column and carries the fleet-wide
    label index. init() has to add the column with every existing row landing
    in workspace 1, and swap the index for the per-workspace one, with no
    manual step."""
    connection = db.connect(str(tmp_path / "old.db"))
    connection.executescript("""
    CREATE TABLE notification_channels (
        id INTEGER PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
        destination_env TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL, removed_at TEXT);
    CREATE UNIQUE INDEX idx_channels_label
        ON notification_channels(label) WHERE removed_at IS NULL;
    INSERT INTO notification_channels (type, label, destination_env, created_at)
        VALUES ('webhook', 'ops', 'WHICHPORTS_WEBHOOK_URL', '2026-08-22T12:00:00+00:00');
    """)
    connection.commit()
    channels.init(connection)
    old = channels.live(connection, workspace_id=1)
    assert [c.label for c in old] == ["ops"]
    # The old fleet-wide index is gone, so another workspace may use the label.
    channels.add(connection, channels.TYPE_WEBHOOK, "ops",
                 "WHICHPORTS_WEBHOOK_URL", now=NOW, workspace_id=2)
    # And the per-workspace index still refuses the real duplicate.
    with pytest.raises(channels.ChannelError):
        channels.add(connection, channels.TYPE_WEBHOOK, "ops",
                     "WHICHPORTS_WEBHOOK_URL", now=NOW, workspace_id=2)
    connection.close()


# ------------------------------------- a refusal names its field, as a class
#
# Found in a round of the test fleet (docs/RECORD.md 4.228): the
# bot token and the chat id were typed into each other's field, and the
# refusal named no field. A screen can put a refusal at the field it is about
# only when this module says which field that is. So every refusal carries
# two fixed words beside its sentence, the field and the reason, and these
# tests hold each of them.

# Not the chat id the module's own sentence gives as its example, so a test
# that says a refusal repeats nothing is not fooled by that example.
CHAT = "-1009876543210"
HOOK = "https://hooks.example.com/services/T0/B0/abc"


def refused(act):
    """The ChannelError `act` raises. A call that raises none fails here."""
    with pytest.raises(channels.ChannelError) as caught:
        act()
    return caught.value


def add_telegram(con, token, chat, label="tg"):
    return channels.add(con, channels.TYPE_TELEGRAM, label, "",
                        destination=token, destination_extra=chat)


def add_holding(con, channel_type, destination, **more):
    return channels.add(con, channel_type, "x", "", destination=destination,
                        **more)


def test_swapped_telegram_fields_are_each_refused_by_name(con):
    """The mistake the finding is about. The bot token's field holds the chat
    id, so the destination is refused. With that put right the chat id's
    field still holds the token, so the chat id is. Neither refusal carries
    either value, and nothing is stored."""
    first = refused(lambda: add_telegram(con, CHAT, TOKEN))
    assert (first.field, first.reason) == ("destination", "shape")
    second = refused(lambda: add_telegram(con, TOKEN, TOKEN))
    assert (second.field, second.reason) == ("chat_id", "shape")
    for exc in (first, second):
        assert TOKEN not in str(exc) and CHAT not in str(exc)
    assert channels.live(con) == []


def no_label_left(con):
    """Ninety nine channels called ops, ops 2 and so on, then one more."""
    for _ in range(99):
        channels.add(con, channels.TYPE_WEBHOOK,
                     channels.free_label(con, "ops", 1), "WHICHPORTS_A")
    channels.free_label(con, "ops", 1)


def a_label_somebody_holds(con):
    a_webhook(con, label="ops")
    a_webhook(con, label="ops")


def a_new_name_somebody_holds(con):
    a_webhook(con, label="ops")
    a_webhook(con, label="two")
    channels.rename(con, "two", "ops")


def a_new_name_that_is_no_label(con):
    a_webhook(con, label="ops")
    channels.rename(con, "ops", "<b>")


def kinds_changed_to_one_nobody_raises(con):
    a_webhook(con, label="ops")
    channels.set_subscriptions(con, "ops", ["made up"])


def replaced_with(con, destination, chat=""):
    """A telegram row, then its destination replaced."""
    add_telegram(con, TOKEN, CHAT)
    channels.set_destination(con, "tg", destination, chat)


# What was asked, the call that asks it, and the field and the reason the
# refusal has to name.
REFUSALS = [
    ("a type that is none of ours",
     lambda con: channels.add(con, "carrier pigeon", "x", "WHICHPORTS_A"),
     "type", "unknown"),
    ("a label that is no label",
     lambda con: channels.add(con, channels.TYPE_WEBHOOK, "<script>",
                              "WHICHPORTS_A"),
     "label", "shape"),
    ("a label somebody holds", a_label_somebody_holds, "label", "taken"),
    ("no label left to make up", no_label_left, "label", "taken"),
    ("a destination and a variable both",
     lambda con: channels.add(con, channels.TYPE_WEBHOOK, "x", "WHICHPORTS_A",
                              destination=HOOK),
     "env", "not_taken"),
    ("a variable that is not ours",
     lambda con: channels.add(con, channels.TYPE_WEBHOOK, "x", "PATH"),
     "env", "shape"),
    ("neither a destination nor a variable",
     lambda con: channels.add(con, channels.TYPE_WEBHOOK, "x", ""),
     "destination", "missing"),
    ("mail to half an address",
     lambda con: add_holding(con, channels.TYPE_EMAIL, "ops@"),
     "destination", "shape"),
    ("two addresses in mail's one field",
     lambda con: add_holding(con, channels.TYPE_EMAIL,
                             "ops@example.com, noc@example.com"),
     "destination", "shape"),
    ("a chat id where the bot token belongs",
     lambda con: add_telegram(con, CHAT, CHAT),
     "destination", "shape"),
    ("a URL where the bot token belongs",
     lambda con: add_telegram(con, HOOK, CHAT),
     "destination", "shape"),
    ("a bot token past its length",
     lambda con: add_telegram(con, "1:" + "a" * 255, CHAT),
     "destination", "shape"),
    ("a webhook that is no URL",
     lambda con: add_holding(con, channels.TYPE_WEBHOOK, "hooks.example.com/x"),
     "destination", "shape"),
    ("a Discord webhook that is no URL",
     lambda con: add_holding(con, channels.TYPE_DISCORD, TOKEN),
     "destination", "shape"),
    ("a webhook at a private address",
     lambda con: add_holding(con, channels.TYPE_WEBHOOK,
                             "https://10.0.0.5/hook"),
     "destination", "private"),
    ("a webhook at the machine's own address",
     lambda con: add_holding(con, channels.TYPE_WEBHOOK,
                             "http://127.0.0.1:8065/hook"),
     "destination", "unsendable"),
    ("telegram with no chat id",
     lambda con: add_telegram(con, TOKEN, ""),
     "chat_id", "missing"),
    ("the bot token where the chat id belongs",
     lambda con: add_telegram(con, TOKEN, TOKEN),
     "chat_id", "shape"),
    ("a topic that is no number",
     lambda con: add_telegram(con, TOKEN, CHAT + ":general"),
     "chat_id", "shape"),
    ("a chat id on a type that takes none",
     lambda con: add_holding(con, channels.TYPE_WEBHOOK, HOOK,
                             destination_extra=CHAT),
     "chat_id", "not_taken"),
    ("a kind nobody raises",
     lambda con: add_holding(con, channels.TYPE_WEBHOOK, HOOK,
                             subscriptions=["made up"]),
     "events", "unknown"),
    ("kinds changed to one nobody raises",
     kinds_changed_to_one_nobody_raises, "events", "unknown"),
    ("a replacement that is empty",
     lambda con: replaced_with(con, "   ", CHAT),
     "destination", "missing"),
    ("a replacement with the chat id where the token belongs",
     lambda con: replaced_with(con, CHAT, TOKEN),
     "destination", "shape"),
    ("a replacement with no chat id",
     lambda con: replaced_with(con, TOKEN, ""),
     "chat_id", "missing"),
    ("a replacement with the token where the chat id belongs",
     lambda con: replaced_with(con, TOKEN, TOKEN),
     "chat_id", "shape"),
    ("a new name that is no label", a_new_name_that_is_no_label,
     "label", "shape"),
    ("a new name somebody holds", a_new_name_somebody_holds,
     "label", "taken"),
]


@pytest.mark.parametrize("what,act,field,reason", REFUSALS,
                         ids=[refusal[0] for refusal in REFUSALS])
def test_every_refusal_names_its_field_and_its_reason(con, monkeypatch, what,
                                                      act, field, reason):
    # The setting that lets a private address through is off, as it is on
    # every instance that did not ask for it (app/outbound.py).
    monkeypatch.delenv(outbound.SETTING, raising=False)
    exc = refused(lambda: act(con))
    assert (exc.field, exc.reason) == (field, reason)
    assert exc.field in channels.FIELDS and exc.reason in channels.REASONS
    assert str(exc), "the sentence a terminal prints is still there"


def test_the_classes_are_fixed_words_that_can_hold_no_value():
    """A class is one of a handful of words written in the module. None is
    built from anything a request sent, so none can carry a value back."""
    for word in channels.FIELDS + channels.REASONS:
        assert re.fullmatch(r"[a-z_]+", word), word
    assert len(set(channels.FIELDS)) == len(channels.FIELDS)
    assert len(set(channels.REASONS)) == len(channels.REASONS)


def test_no_refusal_is_raised_without_both_classes():
    """Read from the module's own source, so a refusal added later cannot
    leave its field or its reason out and still pass."""
    tree = ast.parse(inspect.getsource(channels))
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and getattr(node.func, "id", "") == "ChannelError"]
    assert len(calls) >= 12, "the refusals this module raises"
    for call in calls:
        named = {keyword.arg for keyword in call.keywords}
        assert named == {"field", "reason"}, f"channels.py line {call.lineno}"


def test_the_sentence_check_and_the_class_agree_on_every_destination(
        monkeypatch):
    """`check_destination` is the sentence and `destination_refusal` the class
    with it. One decides and the other reads it, so the two cannot differ."""
    monkeypatch.delenv(outbound.SETTING, raising=False)
    samples = [(channels.TYPE_EMAIL, "ops@example.com"),
               (channels.TYPE_EMAIL, "ops@"),
               (channels.TYPE_TELEGRAM, TOKEN), (channels.TYPE_TELEGRAM, CHAT),
               (channels.TYPE_WEBHOOK, HOOK),
               (channels.TYPE_WEBHOOK, "hooks.example.com/x"),
               (channels.TYPE_WEBHOOK, "https://10.0.0.5/hook"),
               (channels.TYPE_SLACK, "http://[::1]/hook")]
    for channel_type, destination in samples:
        reason, sentence = channels.destination_refusal(channel_type,
                                                        destination)
        assert sentence == channels.check_destination(channel_type, destination)
        assert bool(reason) == bool(sentence)
        assert reason in channels.REASONS + ("",)
