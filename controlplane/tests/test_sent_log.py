"""The log of what went out, `sent_log` in app/alerts.py.

    python -m pytest tests/test_sent_log.py

The Alerts screen's Sent list and each channel's Sent number read this table
and nothing else. Until 2026-10-03 they read `alerts.notified_at` and
`alert_deliveries`, and said three things that were not so (docs/RECORD.md
4.228): a deleted server's sends were gone and the count with them, a mail a
stored email channel sent was listed twice, and an alert of a kind a channel
does not take was listed as sent to it. Each is a test here, shown on the
tables the old list read.

The fill that copies the older tables into the log runs once on a real
database at a deploy, so it is tested the ways it can go wrong there: twice,
on a database with nothing in it, and on the mail both old tables hold.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, channels, db, store, sweep_cli
# The sweep's own harness: a database with a change that is due, the channel
# rows, and the stand-ins for the relay and the wire. Fixtures are imported by
# name so pytest finds them here.
from test_sweep_cli import (a_change_is_due, a_typed_channel,  # noqa: F401
                            an_email_channel, con_for, dbpath, delivered,
                            hooked, mailed, posted, sent)

SLACK_ENV = "WHICHPORTS_SLACK_URL"
SLACK_URL = "https://hooks.slack.com/services/T/B/X"


def log(path):
    """Every line of the log, oldest first, as plain dicts."""
    con = con_for(path)
    rows = [dict(row) for row in con.execute(
        "SELECT workspace_id, host_name, detail, channel, sent_at FROM sent_log ORDER BY id")]
    con.close()
    return rows


def old_tables(path):
    """What the Sent list read before: how many alerts carry `notified_at`,
    and every delivery row's channel."""
    con = con_for(path)
    mailed_alerts = con.execute(
        "SELECT COUNT(*) FROM alerts WHERE notified_at IS NOT NULL").fetchone()[0]
    keys = [row["channel"] for row in con.execute(
        "SELECT channel FROM alert_deliveries ORDER BY id")]
    con.close()
    return mailed_alerts, keys


def mail_by_environment(monkeypatch):
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "sysadmin@example.org")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")


# ----------------------------------------------- a send that succeeded

def test_a_mail_to_the_environments_recipient_is_one_line(dbpath, mailed, posted,
                                                          monkeypatch):
    mail_by_environment(monkeypatch)
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert len(mailed) == 1
    lines = log(dbpath)
    assert [(l["workspace_id"], l["host_name"], l["channel"]) for l in lines] == [
        (1, "one", alerts.SENT_BY_ENVIRONMENT_MAIL)]
    con = con_for(dbpath)
    alert = con.execute("SELECT detail, notified_at FROM alerts").fetchone()
    con.close()
    assert lines[0]["detail"] == alert["detail"]
    assert lines[0]["sent_at"] == alert["notified_at"]


def test_a_mail_from_a_stored_email_channel_is_one_line_under_its_key(
        dbpath, mailed, posted, monkeypatch):
    """The first thing the old list said that was not so. One mail went out,
    and the two tables it read hold it twice: the column and the row."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    channel = an_email_channel(dbpath, "ops inbox", "ops@example.com")
    assert sweep_cli.main([]) == 0
    assert [to for to, _ in mailed] == ["ops@example.com"]
    key = alerts.key_for_channel(channel)
    assert old_tables(dbpath) == (1, [key])          # twice, where the old list read
    assert [l["channel"] for l in log(dbpath)] == [key]   # once, where the new one reads


def test_two_email_channels_are_two_lines(dbpath, mailed, posted, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    first = an_email_channel(dbpath, "ops inbox", "ops@example.com")
    second = an_email_channel(dbpath, "night rota", "night@example.com")
    assert sweep_cli.main([]) == 0
    assert sorted(l["channel"] for l in log(dbpath)) == sorted(
        [alerts.key_for_channel(first), alerts.key_for_channel(second)])


def test_a_post_to_a_chat_channel_is_one_line(dbpath, sent, delivered, monkeypatch):
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    a_change_is_due(dbpath)
    channel = a_typed_channel(dbpath, "slack", "ops slack", SLACK_ENV)
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 1
    assert alerts.key_for_channel(channel) in [l["channel"] for l in log(dbpath)]
    assert [l["channel"] for l in log(dbpath)].count(alerts.key_for_channel(channel)) == 1


def test_eight_ports_in_one_message_are_eight_lines(dbpath, sent, delivered,
                                                    monkeypatch):
    """One message, and one line per port in it, which is what the list has
    always drawn: the port is what a line is about."""
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    a_change_is_due(dbpath, tuple(range(8000, 8008)))
    channel = a_typed_channel(dbpath, "slack", "ops slack", SLACK_ENV)
    assert sweep_cli.main([]) == 0
    assert len(delivered) == 1
    key = alerts.key_for_channel(channel)
    assert len([l for l in log(dbpath) if l["channel"] == key]) == 8


def test_a_second_sweep_adds_no_line(dbpath, sent, delivered, monkeypatch):
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", SLACK_ENV)
    sweep_cli.main([])
    before = log(dbpath)
    sweep_cli.main([])
    assert log(dbpath) == before


# ------------------------------------------- a send that did not happen

def test_a_kind_the_channel_does_not_take_writes_no_line(dbpath, sent, delivered,
                                                         monkeypatch):
    """The third thing the old list said that was not so. The sweep writes a
    delivery row so the channel's queue lets go of the alert, and nothing was
    posted. The old list read that row as sent to the channel."""
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    a_change_is_due(dbpath)
    channel = a_typed_channel(dbpath, "slack", "silence only", SLACK_ENV)
    con = con_for(dbpath)
    channels.set_subscriptions(con, "silence only", ["silent"])
    con.close()
    assert sweep_cli.main([]) == 0
    key = alerts.key_for_channel(channel)
    assert delivered == []                                   # nothing went out
    assert key in old_tables(dbpath)[1]                      # the old list's row is there
    assert key not in [l["channel"] for l in log(dbpath)]    # the log has no line


def test_an_email_channel_that_does_not_take_the_kind_writes_no_line(
        dbpath, mailed, posted, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    a_change_is_due(dbpath)
    an_email_channel(dbpath, "silence only", "ops@example.com")
    con = con_for(dbpath)
    channels.set_subscriptions(con, "silence only", ["silent"])
    con.close()
    assert sweep_cli.main([]) == 0
    assert mailed == []
    assert log(dbpath) == []


def test_a_post_the_endpoint_refused_writes_no_line(dbpath, sent, posted, hooked):
    posted.ok = False
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    assert [l for l in log(dbpath) if l["channel"].startswith("webhook")] == []


# ----------------------------------------------- a deleted server's lines

def test_a_deleted_servers_lines_stay(dbpath, sent, delivered, monkeypatch):
    """The second thing the old list said that was not so, and the one the owner
    saw: the Sent count back at 0 after every server the test fleet deleted.
    A Delete empties `alerts` and `alert_deliveries` for the server, as it
    has to, and the log names the server as text."""
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", SLACK_ENV)
    sweep_cli.main([])
    before = log(dbpath)
    assert before, "nothing was logged, so this would prove nothing"

    con = con_for(dbpath)
    assert store.revoke_host(con, "one")
    assert store.delete_host(con, "one")
    gone = (con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            con.execute("SELECT COUNT(*) FROM alert_deliveries").fetchone()[0],
            con.execute("SELECT COUNT(*) FROM hosts").fetchone()[0])
    con.close()
    assert gone == (0, 0, 0)                 # the Delete took what it takes
    assert log(dbpath) == before             # and the log is as it was
    assert {l["host_name"] for l in before} == {"one"}


def test_the_log_links_to_no_server():
    """No host id and no foreign key, which is what lets a line outlive its
    server. A column added later that points at a host would bring the fault
    back, so the shape is held here."""
    con = sqlite3.connect(":memory:")
    con.executescript("CREATE TABLE hosts (id INTEGER PRIMARY KEY);" + alerts.SCHEMA)
    columns = [row[1] for row in con.execute("PRAGMA table_info(sent_log)")]
    assert columns == ["id", "workspace_id", "host_name", "detail", "channel", "sent_at"]
    assert con.execute("PRAGMA foreign_key_list(sent_log)").fetchall() == []
    con.close()


# --------------------------------------------------------- thirty days

def a_line(con, sent_at, host_name="old-box", channel="slack:X", workspace_id=1):
    con.execute("INSERT INTO sent_log (workspace_id, host_name, detail, channel, sent_at)"
                " VALUES (?, ?, 'no report for 40 minutes', ?, ?)",
                (workspace_id, host_name, channel, sent_at.isoformat()))
    con.commit()


def test_a_line_older_than_the_longest_range_goes_and_a_newer_one_stays(dbpath):
    now = datetime(2026, 10, 3, 12, 0, 0, tzinfo=timezone.utc)
    edge = now - timedelta(days=alerts.SENT_LOG_DAYS)
    con = con_for(dbpath)
    a_line(con, edge - timedelta(seconds=1), host_name="too old")
    a_line(con, edge, host_name="on the edge")
    a_line(con, now - timedelta(days=1), host_name="yesterday")
    assert alerts.prune_sent_log(con, now) == 1
    con.close()
    assert [l["host_name"] for l in log(dbpath)] == ["on the edge", "yesterday"]


def test_the_sweep_drops_the_old_lines(dbpath, sent, posted):
    con = con_for(dbpath)
    wall = datetime.now(timezone.utc)
    a_line(con, wall - timedelta(days=alerts.SENT_LOG_DAYS + 1), host_name="too old")
    a_line(con, wall - timedelta(days=2), host_name="recent")
    con.close()
    assert sweep_cli.main([]) == 0
    assert [l["host_name"] for l in log(dbpath)] == ["recent"]


def test_the_log_keeps_thirty_days():
    """The number the Sent list's longest range is headed with. The site's own
    test holds the two together (site/app/test_sent_counts.py)."""
    assert alerts.SENT_LOG_DAYS == 30


# ------------------------------------------------- the fill, at an upgrade

def as_before_the_log(path):
    """The database as it was before this table existed: every other table of
    today, and no `sent_log`. The next `alerts.init` is the upgrade."""
    con = con_for(path)
    con.execute("DROP TABLE sent_log")
    con.commit()
    con.close()


def upgrade(path):
    con = con_for(path)
    alerts.init(con)
    con.close()


def an_old_alert(con, host_id, port, notified_at=None):
    return con.execute(
        "INSERT INTO alerts (host_id, kind, detail, raised_at, notified_at, subject)"
        " VALUES (?, 'finding changed', ?, ?, ?, ?)",
        (host_id, f"tcp/{port}/v4 became reachable", "2026-10-01T10:00:00+00:00",
         notified_at, f"tcp/{port}/v4")).lastrowid


def an_old_delivery(con, alert_id, channel, delivered_at="2026-10-01T10:05:00+00:00"):
    con.execute("INSERT INTO alert_deliveries (alert_id, channel, delivered_at)"
                " VALUES (?, ?, ?)", (alert_id, channel, delivered_at))


@pytest.fixture()
def old(dbpath):
    """An upgrade waiting to happen: one server in each of two workspaces,
    and four alerts sent the four ways the old tables could record."""
    con = con_for(dbpath)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'second', ?)",
                ("2026-09-01T00:00:00+00:00",))
    mine, _ = store.add_host(con, "mybox")
    theirs, _ = store.add_host(con, "theirbox", workspace_id=2)
    mailed_at = "2026-10-01T10:05:00+00:00"
    # 1. mailed to the environment's recipient: the column alone
    an_old_alert(con, mine, 8001, notified_at=mailed_at)
    # 2. mailed by a stored email channel: the column and the row
    by_row = an_old_alert(con, mine, 8002, notified_at=mailed_at)
    an_old_delivery(con, by_row, "email:#0123456789abcdef")
    # 3. posted to a chat channel, in the other workspace
    posted_alert = an_old_alert(con, theirs, 8003)
    an_old_delivery(con, posted_alert, "slack:WHICHPORTS_SLACK_URL")
    # 4. raised and never sent
    an_old_alert(con, mine, 8004)
    con.commit()
    con.close()
    as_before_the_log(dbpath)
    return dbpath


def test_the_fill_copies_what_the_old_tables_say_went_out(old):
    upgrade(old)
    lines = sorted((l["workspace_id"], l["host_name"], l["detail"], l["channel"], l["sent_at"])
                   for l in log(old))
    assert lines == [
        (1, "mybox", "tcp/8001/v4 became reachable", "email", "2026-10-01T10:05:00+00:00"),
        (1, "mybox", "tcp/8002/v4 became reachable", "email:#0123456789abcdef",
         "2026-10-01T10:05:00+00:00"),
        (2, "theirbox", "tcp/8003/v4 became reachable", "slack:WHICHPORTS_SLACK_URL",
         "2026-10-01T10:05:00+00:00"),
    ]


def test_a_mail_the_old_tables_hold_twice_becomes_one_line(old):
    """The fill must not carry the doubled mail into the new table."""
    upgrade(old)
    about_8002 = [l["channel"] for l in log(old) if "8002" in l["detail"]]
    assert about_8002 == ["email:#0123456789abcdef"]


def test_the_fill_run_twice_adds_nothing(old):
    upgrade(old)
    once = log(old)
    upgrade(old)                       # the next start of the same build
    assert log(old) == once
    con = con_for(old)
    assert alerts.fill_sent_log(con) == 0   # and called by hand on a filled log
    con.commit()
    con.close()
    assert log(old) == once


def test_a_database_with_no_older_tables_fills_nothing_and_does_not_fail(tmp_path,
                                                                         monkeypatch):
    """A new instance's first start: no alerts table, no deliveries table and
    no log. `init` makes all three and has nothing to copy."""
    path = str(tmp_path / "new.db")
    monkeypatch.setenv(db.DB_ENV, path)
    con = db.connect(path)
    db.init(con)
    alerts.init(con)
    count = con.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0]
    con.close()
    assert count == 0


def test_a_log_emptied_by_time_is_not_filled_again(old):
    """Thirty quiet days empty the log. The older tables still hold their
    rows, and a restart must not bring them back as if they were new."""
    upgrade(old)
    con = con_for(old)
    con.execute("DELETE FROM sent_log")
    con.commit()
    con.close()
    upgrade(old)
    assert log(old) == []


def test_a_line_written_since_the_upgrade_is_not_copied_again(dbpath, sent, delivered,
                                                              monkeypatch):
    """After the upgrade the sweep writes the old tables and the log both. A
    restart finds the table and copies nothing."""
    monkeypatch.setenv(SLACK_ENV, SLACK_URL)
    a_change_is_due(dbpath)
    a_typed_channel(dbpath, "slack", "ops slack", SLACK_ENV)
    sweep_cli.main([])
    before = log(dbpath)
    upgrade(dbpath)
    assert log(dbpath) == before
