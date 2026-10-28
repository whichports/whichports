"""What the Alerts screen says was sent, read from the log of what went out.

The Sent list and each channel's Sent number read `sent_log`, which the
sweep writes beside every send that succeeded
(`controlplane/app/alerts.py`). The list is on the Alerts screen. The number
is on the Integrations screen since layout B, in the Alert destinations table
(docs/screens/alerts/SPEC-layout-b.md). Until 2026-10-03 they read
`alerts.notified_at` and `alert_deliveries`, and four things on the screen
were not so, all seen on the test fleet's workspace (docs/RECORD.md 4.228):

- A deleted server's sends left the list, and every channel's number went
  back to 0 with them. The owner saw this one.
- A mail a stored email channel sent was listed twice, once as "email" with
  no address under it and once with the address.
- A channel's Sent number was counted from the rows of the Sent list after
  the list had been cut to its fifty lines, so a week with more sends than
  that read fifty.
- An alert of a kind a channel does not take was listed as sent to it. That
  one is held from the sweep's side, in the control plane's
  tests/test_sent_log.py.

    Run from site/: python3 -m pytest app/test_sent_counts.py
"""
import pathlib
import re
import sqlite3
import sys
from datetime import timedelta

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402

NOW = trl.NOW
WEBHOOK = "webhook:WHICHPORTS_WEBHOOK_URL"
WEEK = NOW - timedelta(days=7)


@pytest.fixture()
def db(tmp_path):
    """One server that reports, in a database with the page's own schema."""
    path = str(tmp_path / "cp.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.close()
    trl.add_host(path, "box", [(NOW - timedelta(minutes=2), trl.document(listening=[trl.SSHD]))],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    return path


def told(db, port, when, mailed="", host="box"):
    """One alert about one port, raised at `when`. Returns its id.

    `mailed` says who mailed it, the way the sweep records each: "environment"
    is the single recipient with no row, logged as sent under the plain word
    email, and "channel" is a stored email channel, whose line the test adds
    with `add_delivery` under the channel's own key."""
    return trl.add_alert(db, host, f"{port}/tcp became reachable", when,
                         notified=bool(mailed), kind="finding",
                         subject=f"tcp/{port}/v4", logged=mailed == "environment")


def email_channel(db, label="me@example.com", env_name="WHICHPORTS_ALERT_TO"):
    """A stored email channel, and the key its deliveries are recorded under,
    worked out by the control plane's own rule."""
    trl.add_channel(db, label=label, channel_type="email", env_name=env_name)
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    stored = [c for c in joinbridge.module("channels").live(con) if c.label == label][0]
    con.close()
    return joinbridge.module("alerts").key_for_channel(stored)


def sent(db, since=WEEK, limit=rl.SENT_LIMIT, workspace_id=None):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        return rl.load_sent(con, since, limit, workspace_id)
    finally:
        con.close()


def counts(db, since=WEEK, workspace_id=None):
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    try:
        return rl.load_sent_counts(con, since, workspace_id)
    finally:
        con.close()


def drawn_numbers(db):
    """Every channel row's Sent number, as the page draws it. A zero carries
    one more class, which draws it faint."""
    panel = trl.channels_panel(rl.render(db, now=NOW))
    return re.findall(r'<div class="crow-u(?: [a-z]+)?">(\d+)</div>', panel)


# ------------------------------------------------- each channel's number

def test_a_channels_number_counts_every_send_of_the_week(db):
    """Sixty deliveries in an hour read sixty. The list holds fifty lines, and
    the number was counted from the list."""
    trl.add_channel(db, label="ops")
    for i in range(60):
        when = NOW - timedelta(hours=1, minutes=i)
        trl.add_delivery(db, WEBHOOK, when=when, alert_id=told(db, 8000 + i, when))
    assert drawn_numbers(db) == ["60"]
    rows, total = sent(db)
    assert (len(rows), total) == (rl.SENT_LIMIT, 60)   # the list is still cut


def test_the_number_is_the_past_seven_days_only(db):
    """The column is headed for seven days and the list reads thirty."""
    trl.add_channel(db, label="ops")
    for port, days in ((8001, 2), (8002, 9)):
        when = NOW - timedelta(days=days)
        trl.add_delivery(db, WEBHOOK, when=when, alert_id=told(db, port, when))
    assert drawn_numbers(db) == ["1"]
    assert counts(db) == {WEBHOOK: 1}
    assert counts(db, since=NOW - timedelta(days=30)) == {WEBHOOK: 2}


def test_a_channel_with_nothing_sent_reads_zero(db):
    trl.add_channel(db, label="ops")
    told(db, 8001, NOW - timedelta(hours=1))
    assert drawn_numbers(db) == ["0"]
    assert counts(db) == {}


def test_one_channels_number_is_not_anothers(db):
    trl.add_channel(db, label="ops")
    when = NOW - timedelta(hours=1)
    alert_id = told(db, 8001, when)
    trl.add_delivery(db, WEBHOOK, when=when, alert_id=alert_id)
    trl.add_delivery(db, "slack:WHICHPORTS_SLACK_URL", when=when, alert_id=alert_id)
    assert counts(db) == {WEBHOOK: 1, "slack:WHICHPORTS_SLACK_URL": 1}
    assert drawn_numbers(db) == ["1"]


def test_a_database_from_before_the_log_has_nothing_sent(tmp_path):
    """No log table: nothing sent, and no error. The control plane makes the
    table and fills it when it starts, so this is a page drawn before that."""
    path = str(tmp_path / "old.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.commit()
    con.row_factory = sqlite3.Row
    assert rl.load_sent_counts(con, WEEK) == {}
    assert rl.load_sent(con, WEEK, rl.SENT_LIMIT) == ([], 0)
    con.close()


# ------------------------------------------------------- one mail, one line

def test_a_mail_a_stored_channel_sent_is_one_line_under_its_key(db):
    key = email_channel(db)
    when = NOW - timedelta(hours=1)
    trl.add_delivery(db, key, when=when, alert_id=told(db, 22, when, mailed="channel"))
    rows, total = sent(db)
    assert total == 1
    assert [row["channel"] for row in rows] == [key]
    assert counts(db) == {key: 1}
    assert drawn_numbers(db) == ["1"]


def test_a_mail_the_environment_sent_is_still_a_line(db):
    """The single recipient the environment names has no channel row, and
    the sweep logs that mail under the plain word."""
    told(db, 22, NOW - timedelta(hours=1), mailed="environment")
    rows, total = sent(db)
    assert total == 1
    assert [row["channel"] for row in rows] == ["email"]


def test_two_email_channels_are_two_lines_and_never_three(db):
    first = email_channel(db, "one@example.com", "WHICHPORTS_ALERT_TO")
    second = email_channel(db, "two@example.com", "WHICHPORTS_SECOND_TO")
    assert first != second
    when = NOW - timedelta(hours=1)
    alert_id = told(db, 22, when, mailed="channel")
    trl.add_delivery(db, first, when=when, alert_id=alert_id)
    trl.add_delivery(db, second, when=when, alert_id=alert_id)
    rows, total = sent(db)
    assert total == 2
    assert sorted(row["channel"] for row in rows) == sorted([first, second])


def test_a_mail_and_a_chat_message_about_one_alert_are_two_lines(db):
    key = email_channel(db)
    when = NOW - timedelta(hours=1)
    alert_id = told(db, 22, when, mailed="channel")
    trl.add_delivery(db, key, when=when, alert_id=alert_id)
    trl.add_delivery(db, WEBHOOK, when=when, alert_id=alert_id)
    rows, total = sent(db)
    assert total == 2
    assert sorted(row["channel"] for row in rows) == sorted([key, WEBHOOK])


def test_the_environments_mail_and_a_chat_message_are_two_lines(db):
    when = NOW - timedelta(hours=1)
    trl.add_delivery(db, WEBHOOK, when=when,
                     alert_id=told(db, 22, when, mailed="environment"))
    rows, total = sent(db)
    assert total == 2
    assert sorted(row["channel"] for row in rows) == ["email", WEBHOOK]


def test_the_page_draws_one_mail_once(db):
    key = email_channel(db)
    when = NOW - timedelta(hours=1)
    trl.add_delivery(db, key, when=when, alert_id=told(db, 22, when, mailed="channel"))
    section = trl.sent_section(rl.render(db, now=NOW))
    assert section.count("Email") == 1, section


# ------------------------------------------- a deleted server's lines stay

def delete_the_server(db, name="box"):
    """Remove, then Delete, by the control plane's own two functions."""
    store = joinbridge.module("store")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    assert store.revoke_host(con, name)
    assert store.delete_host(con, name)
    con.close()


def test_a_deleted_servers_sends_stay_in_the_list_and_in_the_number(db):
    """What the owner saw on 2026-10-03: the Sent count at 0 in a workspace whose
    five channels had just taken a message, because the test fleet deletes its
    server after every case and the count went with it."""
    trl.add_channel(db, label="ops")
    when = NOW - timedelta(hours=1)
    trl.add_delivery(db, WEBHOOK, when=when,
                     alert_id=told(db, 8080, when, mailed="environment"))
    assert sent(db)[1] == 2
    assert drawn_numbers(db) == ["1"]

    delete_the_server(db)

    rows, total = sent(db)
    assert total == 2
    assert {row["host_name"] for row in rows} == {"box"}
    assert counts(db) == {"email": 1, WEBHOOK: 1}
    assert drawn_numbers(db) == ["1"]
    section = trl.sent_section(rl.render(db, now=NOW))
    assert "box" in section and "8080" in section


def test_a_removed_servers_sends_stay_too(db):
    """Remove alone never took them. Held so the two acts stay alike here."""
    when = NOW - timedelta(hours=1)
    trl.add_delivery(db, WEBHOOK, when=when, alert_id=told(db, 8080, when))
    store = joinbridge.module("store")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    assert store.revoke_host(con, "box")
    con.close()
    assert sent(db)[1] == 1


# ----------------------------------------------------- one workspace's own

def test_one_workspace_never_counts_anothers_sends(tmp_path):
    path = str(tmp_path / "two.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'second', ?)",
                (NOW.isoformat(),))
    con.commit()
    con.close()
    when = NOW - timedelta(hours=1)
    for name, workspace in (("mybox", 1), ("theirbox", 2)):
        trl.add_host(path, name, [(NOW - timedelta(minutes=4), trl.document(listening=[trl.SSHD]))],
                     last_report_at=(NOW - timedelta(minutes=4)).isoformat(),
                     workspace_id=workspace)
        trl.add_delivery(path, WEBHOOK, when=when, alert_id=told(path, 8080, when, host=name))
    assert counts(path, workspace_id=1) == {WEBHOOK: 1}
    assert counts(path, workspace_id=2) == {WEBHOOK: 1}
    assert counts(path) == {WEBHOOK: 2}
    mine, total = sent(path, workspace_id=1)
    assert (total, [row["host_name"] for row in mine]) == (1, ["mybox"])


def test_a_deleted_servers_lines_stay_in_its_own_workspace(tmp_path):
    """The line carries the workspace itself, since there is no server left
    to ask which one it was in."""
    path = str(tmp_path / "two.db")
    con = sqlite3.connect(path)
    con.executescript(trl.SCHEMA)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'second', ?)",
                (NOW.isoformat(),))
    con.commit()
    con.close()
    trl.add_host(path, "theirbox", [(NOW - timedelta(minutes=4), trl.document(listening=[trl.SSHD]))],
                 last_report_at=(NOW - timedelta(minutes=4)).isoformat(), workspace_id=2)
    when = NOW - timedelta(hours=1)
    trl.add_delivery(path, WEBHOOK, when=when, alert_id=told(path, 8080, when, host="theirbox"))
    delete_the_server(path, "theirbox")
    assert counts(path, workspace_id=2) == {WEBHOOK: 1}
    assert counts(path, workspace_id=1) == {}


# ------------------------------------------ the two halves say one thing

def test_the_log_is_kept_as_long_as_the_lists_longest_range():
    """The sweep drops a line older than `alerts.SENT_LOG_DAYS`. A list that
    offered a longer range than that would show a range that is always
    short."""
    assert joinbridge.module("alerts").SENT_LOG_DAYS == rl.tpl.SENT_READ_DAYS


def test_these_tests_write_the_table_the_control_plane_makes(tmp_path):
    """The schema here is a copy (`test_render_live.SENT_LOG_SCHEMA`), like
    every other table these tests make. This holds it to the real one."""
    def columns(schema):
        con = sqlite3.connect(":memory:")
        con.executescript("CREATE TABLE hosts (id INTEGER PRIMARY KEY);" + schema)
        found = [tuple(row[1:4]) for row in con.execute("PRAGMA table_info(sent_log)")]
        con.close()
        return found
    assert columns(trl.SENT_LOG_SCHEMA) == columns(joinbridge.module("alerts").SCHEMA)
