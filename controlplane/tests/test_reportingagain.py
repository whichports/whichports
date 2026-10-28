"""One short message when a silent agent reports again.

    python -m pytest tests/test_reportingagain.py

`docs/screens/mails/SPEC-alert-messages.md`, section 2.7. A person who was
told an agent stopped reporting was never told it reports again, and silence
then quiet reads as still broken (docs/RECORD.md 4.228, 4.452). So each
channel that accepted the message about the silence gets one message when
the agent is back, and nobody else does.

The edges first: who is never told, then once, then what it says. The
servers are made up. Every time here is handed in, and the sweep that raises
and resolves is the real one (`alerts.sweep`).
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import (alerts, alertwords, channels, db, displayname, finding_alerts, intent, notify,
                 reportingagain, store, webhook)

# The last report before the silence.
T0 = datetime(2026, 10, 12, 6, 0, tzinfo=timezone.utc)
CONFIG = notify.Config(to="operator@example.com", host="smtp.example.com", sender="alerts@example.com")
ENV_MAIL = alerts.SENT_BY_ENVIRONMENT_MAIL


def at(minutes):
    return T0 + timedelta(minutes=minutes)


@pytest.fixture
def con(tmp_path):
    con = db.connect(str(tmp_path / "cp.db"))
    for module in (db, intent, alerts, finding_alerts, channels, displayname):
        module.init(con)
    SWEPT["to"] = 0
    return con


# How far the timer has run in this test, in minutes after T0.
SWEPT = {"to": 0}


def sweep_to(con, minutes):
    """The five-minute timer, from where it stood to `minutes` after T0."""
    for minute in range(SWEPT["to"] + 5, minutes + 1, 5):
        alerts.sweep(con, now=at(minute))
    SWEPT["to"] = minutes


def reported(con, host_id, when):
    """A report as `store.insert_report` writes one, at a time of ours."""
    con.execute("INSERT INTO reports (host_id, received_at, collected_at_unix, schema_version, document)"
                " VALUES (?, ?, ?, 1, '{}')", (host_id, when.isoformat(), int(when.timestamp())))
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?", (when.isoformat(), host_id))
    con.commit()


def hook(con, label="hook", workspace_id=db.DEFAULT_WORKSPACE_ID, subscriptions=None, url=None):
    return channels.add(con, channels.TYPE_WEBHOOK, label, "", now=T0, subscriptions=subscriptions,
                        destination=url or f"https://hooks.example.com/{label}", workspace_id=workspace_id)


def mailbox(con, address="ops@example.com", workspace_id=db.DEFAULT_WORKSPACE_ID):
    return channels.add(con, channels.TYPE_EMAIL, address.split("@")[0], "", now=T0,
                        destination=address, workspace_id=workspace_id)


def key(channel):
    return alerts.key_for_channel(channel)


def tell(con, alert_id, *keys, when=None):
    """What the sweep writes when a channel accepts the silence's message."""
    for one in keys:
        alerts.mark_delivered(con, alert_id, one, when or at(40))
        alerts.log_sent(con, alert_id, one, when or at(40))


def went_silent(con, name="web-07", told=(), workspace_id=db.DEFAULT_WORKSPACE_ID):
    """A server that reported at T0 and whose silence the sweep raised at
    40 minutes. `told` are the channel keys that accepted the message."""
    host_id, _ = store.add_host(con, name, workspace_id=workspace_id)
    # An older report too, so the last one before the silence is not the
    # only one before it.
    reported(con, host_id, at(-30))
    reported(con, host_id, T0)
    sweep_to(con, 40)
    alert = alerts.open_alert(con, host_id, alerts.KIND_SILENT)
    assert alert is not None, "the sweep did not raise the silence"
    tell(con, alert["id"], *told)
    return host_id, alert["id"]


def came_back(con, host_id, minutes=72):
    """A report `minutes` after T0, and the sweeps until it is seen."""
    reported(con, host_id, at(minutes))
    sweep_to(con, minutes + 3 + (5 - (minutes + 3) % 5) % 5)
    assert alerts.open_alert(con, host_id, alerts.KIND_SILENT) is None, "the sweep did not resolve it"


class Sent:
    """Stands where the relay and the chat services stand, and keeps what
    each was handed. `refuse` names the destinations that fail."""

    def __init__(self, refuse=()):
        self.mails, self.posts, self.refuse = [], [], set(refuse)

    def mail(self, subject, body, config, html=""):
        if config.to in self.refuse:
            return False, "the relay refused it"
        self.mails.append((config.to, subject, body, html))
        return True, ""

    def chat(self, channel, text, payload, env=None, resolver=None, opener=None, message=None):
        if channel.label in self.refuse:
            return False, "timed out"
        self.posts.append((channel.label, text, payload, message))
        return True, ""


def deliver(con, sent, minutes=80, use_environment=False):
    return reportingagain.deliver(
        con, at(minutes), config=CONFIG, use_environment=use_environment,
        mail_rows=[c for c in channels.live(con, channels.TYPE_EMAIL) if c.enabled],
        chat_rows=[c for t in channels.SENDING_TYPES for c in channels.sending(con, t)],
        send_mail=sent.mail, send_chat=sent.chat)


def labels(sent):
    return sorted(label for label, *_ in sent.posts)


# ------------------------------------------------------- who is never told

def test_a_server_that_never_reported_is_never_said_to_report_again(con):
    """An alert an older build raised against a server nobody installed. The
    sweep retracts it, and no report ever came."""
    one = hook(con)
    host_id, _ = store.add_host(con, "never-installed")
    alert, _new = alerts.raise_alert(con, host_id, alerts.KIND_SILENT, alerts.silent_detail(40), at(40))
    con.commit()
    tell(con, alert["id"], key(one))
    sweep_to(con, 45)
    assert alerts.open_alert(con, host_id, alerts.KIND_SILENT) is None
    sent = Sent()
    assert deliver(con, sent) == 0 and sent.posts == []


def test_a_silence_closed_by_a_pause_is_not_reporting_again_until_a_report_comes(con):
    """Closed is not resolved: nothing reported, so nothing is said. A
    report that then comes inside the day is the agent reporting again,
    paused or not, because that is what was measured."""
    one = hook(con)
    host_id, _alert = went_silent(con, told=[key(one)])
    store.pause_host(con, "web-07", True)
    sweep_to(con, 45)
    assert alerts.open_alert(con, host_id, alerts.KIND_SILENT) is None
    sent = Sent()
    for minutes in (50, 55):
        assert deliver(con, sent, minutes) == 0
    reported(con, host_id, at(60))
    sweep_to(con, 65)
    assert deliver(con, sent, 70) == 1
    assert sent.posts[0][3].title == "web-07 is reporting again"
    assert dict(sent.posts[0][3].fields)["no report for"] == "60 minutes"


def test_the_spec_says_plainly_that_a_paused_server_that_reports_is_told():
    """The test above is the decision. The spec's When said only that a
    silence closed by a pause is not a report, and the second big test read
    it as no message at all for a paused server (25 October, case E10b).
    Decided on 26 October: the code stands, and the spec
    says it."""
    import pathlib
    spec = pathlib.Path(__file__).resolve().parents[2] / "docs" / "screens" / "mails" \
        / "SPEC-alert-messages.md"
    when = " ".join(spec.read_text(encoding="utf-8").split("- **When.**")[1]
                    .split("- **Once.**")[0].split())
    assert ("A paused server whose agent reports after its silence is told it reports "
            "again, paused or not, because a report is what was measured.") in when
    assert "A silence closed by a pause or by removing the server is not itself a report." in when


def test_a_removed_server_is_never_said_to_report_again(con):
    one = hook(con)
    host_id, _alert = went_silent(con, told=[key(one)])
    reported(con, host_id, at(72))
    store.revoke_host(con, "web-07")
    sweep_to(con, 75)
    sent = Sent()
    assert deliver(con, sent) == 0 and sent.posts == []


def test_only_a_channel_that_was_told_of_the_silence_is_told(con):
    told, _later = hook(con, "told"), hook(con, "added-later")
    host_id, _alert = went_silent(con, told=[key(told)])
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent) == 1
    assert labels(sent) == ["told"]


def test_a_channel_that_let_the_silence_go_was_not_told_of_it(con):
    """A channel that does not take the kind is written down as done with
    the alert, so its queue lets go. That is no message, and it is not told
    the agent is back."""
    quiet = hook(con, "findings-only", subscriptions=[channels.KIND_FINDING])
    host_id, alert_id = went_silent(con)
    alerts.mark_delivered(con, alert_id, key(quiet), at(40))
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent) == 0 and sent.posts == []
    assert con.execute("SELECT COUNT(*) FROM silence_told").fetchone()[0] == 0


def test_a_message_that_is_not_about_a_silence_writes_down_nobody_as_told(con):
    one = hook(con)
    host_id, _ = store.add_host(con, "web-07")
    alert, _new = alerts.raise_alert(con, host_id, finding_alerts.KIND_OUTSIDE_STALE, "stale", at(40))
    con.commit()
    tell(con, alert["id"], key(one))
    assert con.execute("SELECT COUNT(*) FROM silence_told").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0] == 1


def test_another_workspaces_channel_is_told_nothing_also_at_the_same_address(con):
    """Two workspaces post to one address, so their two rows have one
    delivery key. Each row is asked about its own workspace's servers."""
    other = db.create_workspace(con, "another")
    ours = hook(con, "ours", url="https://hooks.example.com/shared")
    theirs = hook(con, "theirs", workspace_id=other, url="https://hooks.example.com/shared")
    assert key(ours) == key(theirs)
    host_id, _alert = went_silent(con, told=[key(ours)])
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent) == 1
    assert labels(sent) == ["ours"]


# -------------------------------------------------------------------- once

def test_a_channel_is_told_once(con):
    one, two = hook(con, "one"), hook(con, "two")
    mail = mailbox(con)
    host_id, _alert = went_silent(con, told=[key(one), key(two), key(mail)])
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent) == 3
    assert labels(sent) == ["one", "two"] and [to for to, *_ in sent.mails] == ["ops@example.com"]
    for minutes in (85, 90, 95):
        sweep_to(con, minutes)
        assert deliver(con, sent, minutes) == 0
    assert len(sent.posts) == 2 and len(sent.mails) == 1


def test_a_destination_that_failed_is_tried_again_and_the_others_are_not_told_twice(con):
    works, broken = hook(con, "works"), hook(con, "broken")
    host_id, _alert = went_silent(con, told=[key(works), key(broken)])
    came_back(con, host_id)
    sent = Sent(refuse={"broken"})
    assert deliver(con, sent) == 1
    assert deliver(con, sent, 85) == 0
    sent.refuse.clear()
    assert deliver(con, sent, 90) == 1
    assert labels(sent) == ["broken", "works"]


def test_a_message_a_day_late_is_sent_to_nobody(con):
    """A destination that could not be reached for a day does not hear a day
    later that an agent came back."""
    one = hook(con)
    host_id, _alert = went_silent(con, told=[key(one)])
    came_back(con, host_id)
    sent = Sent(refuse={"hook"})
    assert deliver(con, sent) == 0
    sent.refuse.clear()
    a_day_on = 75 + 24 * 60 + 5
    assert deliver(con, sent, a_day_on) == 0 and sent.posts == []
    # And it is settled, so it is not read again at every sweep.
    assert con.execute("SELECT COUNT(*) FROM silence_told WHERE again_at IS NULL").fetchone()[0] == 0
    assert con.execute("SELECT COUNT(*) FROM sent_log WHERE detail LIKE 'reporting again%'").fetchone()[0] == 0


def test_a_server_that_went_silent_again_is_not_said_to_report(con):
    """It came back, the message could not be sent, and it stopped again.
    Saying it reports would be false at the moment it is said. When it is
    back for good the channel hears it once, not once for each silence."""
    one = hook(con)
    host_id, _first = went_silent(con, told=[key(one)])
    came_back(con, host_id)
    sent = Sent(refuse={"hook"})
    assert deliver(con, sent) == 0
    sweep_to(con, 115)
    second = alerts.open_alert(con, host_id, alerts.KIND_SILENT)
    assert second is not None, "the second silence was not raised"
    tell(con, second["id"], key(one), when=at(115))
    sent.refuse.clear()
    assert deliver(con, sent, 120) == 0
    came_back(con, host_id, 150)
    assert deliver(con, sent, 160) == 1
    assert deliver(con, sent, 165) == 0
    assert len(sent.posts) == 1


def test_a_muted_server_sends_nothing_also_when_the_mute_ends(con):
    """A mute records and does not queue (docs/PRODUCT.md 4c)."""
    one = hook(con)
    host_id, _alert = went_silent(con, told=[key(one)])
    finding_alerts.mute_host(con, "web-07", now=at(60))
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent) == 0
    finding_alerts.unmute_host(con, "web-07", now=at(82))
    assert deliver(con, sent, 85) == 0 and sent.posts == []


def test_a_channel_that_no_longer_takes_the_kind_is_told_nothing(con):
    one = hook(con)
    host_id, _alert = went_silent(con, told=[key(one)])
    channels.set_subscriptions(con, "hook", [channels.KIND_FINDING])
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent) == 0
    channels.set_subscriptions(con, "hook", [channels.KIND_FINDING, channels.KIND_SILENT])
    assert deliver(con, sent, 85) == 0 and sent.posts == []


def test_the_environments_recipient_is_told_when_it_was_told_of_the_silence(con):
    host_id, _alert = went_silent(con, told=[ENV_MAIL])
    came_back(con, host_id)
    sent = Sent()
    assert deliver(con, sent, use_environment=False) == 0
    assert deliver(con, sent, 85, use_environment=True) == 1
    assert [(to, subject) for to, subject, *_ in sent.mails] == [
        ("operator@example.com", "[whichports] web-07 is reporting again")]
    assert deliver(con, sent, 90, use_environment=True) == 0


# -------------------------------------------------------------- what it says

def test_the_message_is_a_title_two_labelled_values_and_one_button(con):
    got = alertwords.said_reporting_again("web-07", 72)
    assert got == alertwords.Said(
        title="web-07 is reporting again",
        fields=(("server", "web-07"), ("no report for", "72 minutes")),
        button="Open web-07", link=got.link)
    assert got.link.endswith("/host/web-07")
    # Nothing is pending after it, so no line says what will not be sent.
    assert got.closing == "" and got.sentence == ""
    for label, _value in got.fields:
        assert label in alertwords.LABELS


def test_a_display_name_is_said_with_the_name_the_server_is_found_by():
    got = alertwords.said_reporting_again("web-07", 72, "Webshop")
    assert got.title == "Webshop is reporting again"
    assert got.fields[0] == ("server", "Webshop (web-07)") and got.button == "Open Webshop"


@pytest.mark.parametrize("minutes,said", [
    (1, "1 minute"), (36, "36 minutes"), (119, "119 minutes"),
    (120, "2 hours"), (179, "2 hours"), (47 * 60 + 59, "47 hours"),
    (48 * 60, "2 days"), (3 * 24 * 60 + 500, "3 days")])
def test_how_long_is_said_in_the_largest_unit_that_is_whole_and_never_rounded_up(minutes, said):
    assert dict(alertwords.said_reporting_again("web-07", minutes).fields)["no report for"] == said


def test_a_length_nobody_measured_is_left_out():
    assert alertwords.said_reporting_again("web-07", None).fields == (("server", "web-07"),)


def test_the_length_is_from_the_last_report_before_to_the_first_after(con):
    """The reports' own times, T0 and 72 minutes later, not the sweep's."""
    one = hook(con)
    host_id, _alert = went_silent(con, told=[key(one)])
    came_back(con, host_id, 72)
    reported(con, host_id, at(78))
    sent = Sent()
    deliver(con, sent)
    assert dict(sent.posts[0][3].fields) == {"server": "web-07", "no report for": "72 minutes"}


def test_the_mail_says_it_in_both_halves_and_carries_no_time(con):
    mail = mailbox(con)
    host_id, _alert = went_silent(con, told=[key(mail)])
    displayname.set_display_name(con, "web-07", "Webshop")
    came_back(con, host_id)
    sent = Sent()
    deliver(con, sent)
    to, subject, body, html = sent.mails[0]
    assert (to, subject) == ("ops@example.com", "[whichports] Webshop is reporting again")
    assert body == ("Webshop is reporting again\n\n"
                    "  server: Webshop (web-07)\n  no report for: 72 minutes\n\n"
                    f"  {alertwords.said_reporting_again('web-07', 72).link}\n")
    assert "Webshop is reporting again" in html and "72 minutes" in html
    for half in (subject, body, html):
        assert "2026" not in half and "UTC" not in half


def test_the_webhook_gets_the_same_words_and_a_typed_document(con):
    """The fields every one-line kind carries. `raised_at` is the silence's
    own, so a program can pair this with the message it follows."""
    one = hook(con)
    host_id, alert_id = went_silent(con, told=[key(one)])
    raised = con.execute("SELECT raised_at FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0]
    came_back(con, host_id)
    sent = Sent()
    deliver(con, sent)
    _label, text, payload, message = sent.posts[0]
    assert "whichports: web-07 is reporting again" in text
    assert payload == {"version": webhook.PAYLOAD_VERSION, "kind": "reporting again", "server": "web-07",
                       "detail": "reporting again, no report for 72 minutes", "raised_at": raised}
    assert message.title == "web-07 is reporting again"
    assert "CVE" not in json.dumps(payload) and "password" not in text


def test_what_went_out_is_in_the_sent_log_once_for_each_destination_that_took_it(con):
    works, broken = hook(con, "works"), hook(con, "broken")
    host_id, _alert = went_silent(con, told=[key(works), key(broken)])
    came_back(con, host_id)
    deliver(con, Sent(refuse={"broken"}))
    rows = con.execute("SELECT workspace_id, host_name, detail, channel, sent_at FROM sent_log"
                       " WHERE detail LIKE 'reporting again%'").fetchall()
    assert [tuple(row) for row in rows] == [
        (db.DEFAULT_WORKSPACE_ID, "web-07", "reporting again, no report for 72 minutes", key(works),
         at(80).isoformat())]


def test_deleting_a_server_takes_who_was_told_with_it(con):
    one = hook(con)
    _host_id, _alert = went_silent(con, told=[key(one)])
    assert con.execute("SELECT COUNT(*) FROM silence_told").fetchone()[0] == 1
    assert store.revoke_host(con, "web-07") and store.delete_host(con, "web-07")
    assert con.execute("SELECT COUNT(*) FROM silence_told").fetchone()[0] == 0
