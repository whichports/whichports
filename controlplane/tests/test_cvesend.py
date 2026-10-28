"""Handing a batch of told CVEs to every destination of its workspace, once.

    python -m pytest tests/test_cvesend.py

`docs/SPEC-cve-check.md`, section 2, point 7. `app/cvetell.py` writes down
what is told and `app/cvewords.py` says it. This is the third part: the
message goes to each destination that takes the kind, a destination that
failed is tried again without the others being sent twice, and what went
out is in the sent log. The servers and the CVE numbers are made up.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, channels, cvesend, cvetell, db, displayname, finding_alerts, intent, notify, store

NOW = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)
CONFIG = notify.Config(to="operator@example.com", host="smtp.example.com", sender="alerts@example.com")


@pytest.fixture
def con(tmp_path):
    con = db.connect(str(tmp_path / "cp.db"))
    for module in (db, intent, alerts, finding_alerts, channels, displayname, cvetell, cvesend):
        module.init(con)
    return con


def batch(con, *servers, workspace_id=db.DEFAULT_WORKSPACE_ID, when=NOW):
    """A batch as `cvetell.evaluate` writes one: (name, ports, cves, offered)."""
    told = []
    for name, ports, cves, offered in servers:
        row = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()
        host_id = row[0] if row else store.add_host(con, name, workspace_id=workspace_id)[0]
        told.append({"host_id": host_id, "host_name": name, "ports": [list(p) for p in ports],
                     "cves": list(cves), "offered": offered})
    batch_id = con.execute("INSERT INTO cve_batches (workspace_id, created_at, told) VALUES (?, ?, ?)",
                           (workspace_id, when.isoformat(), json.dumps(told))).lastrowid
    con.commit()
    return batch_id


WEB = ("web-07", [("tcp", 22), ("tcp", 80)], ["CVE-2026-00001", "CVE-2026-00002", "CVE-2026-00003"], False)
MAIL = ("mail-01", [("tcp", 22)], ["CVE-2026-00001"], True)


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


def hook(con, label="hook", workspace_id=db.DEFAULT_WORKSPACE_ID, subscriptions=None):
    return channels.add(con, channels.TYPE_WEBHOOK, label, "", now=NOW, subscriptions=subscriptions,
                        destination=f"https://hooks.example.com/{label}", workspace_id=workspace_id)


def mailbox(con, address="ops@example.com", workspace_id=db.DEFAULT_WORKSPACE_ID, subscriptions=None):
    return channels.add(con, channels.TYPE_EMAIL, address.split("@")[0], "", now=NOW,
                        subscriptions=subscriptions, destination=address, workspace_id=workspace_id)


def deliver(con, sent, now=NOW, use_environment=False, extract_for=None):
    more = {} if extract_for is None else {"extract_for": extract_for}
    return cvesend.deliver(con, now, config=CONFIG, use_environment=use_environment,
                           mail_rows=[c for c in channels.live(con, channels.TYPE_EMAIL) if c.enabled],
                           chat_rows=[c for t in channels.SENDING_TYPES for c in channels.sending(con, t)],
                           send_mail=sent.mail, send_chat=sent.chat, **more)


# ------------------------------------------------------------- once each

def test_a_batch_goes_once_to_every_destination_of_its_workspace(con):
    hook(con)
    mailbox(con)
    batch(con, WEB, MAIL)
    sent = Sent()
    assert deliver(con, sent) == 2
    assert [to for to, *_ in sent.mails] == ["ops@example.com"]
    assert [label for label, *_ in sent.posts] == ["hook"]
    for _ in range(3):
        assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 0
    assert len(sent.mails) == 1 and len(sent.posts) == 1


def test_the_mail_that_goes_out_says_the_batch_and_counts_each_cve_once(con):
    """The count in a mail that was really handed to the relay."""
    mailbox(con)
    batch(con, WEB, MAIL)
    sent = Sent()
    deliver(con, sent)
    _to, subject, body, html = sent.mails[0]
    assert subject == "[whichports] A newer version fixes CVEs on 2 servers"
    assert "  servers: mail-01, web-07\n  CVEs: 3\n  new: 3\n" in body
    assert "Nothing else will be sent about these CVEs on the same ports." in body
    assert "CVE-2026" not in subject + body + html
    assert "A newer version fixes CVEs on 2 servers" in html


def test_one_server_whose_lists_offer_every_fix_says_an_update_with_its_display_name(con):
    mailbox(con)
    batch(con, MAIL)
    displayname.set_display_name(con, "mail-01", "Mail relay")
    sent = Sent()
    deliver(con, sent)
    _to, subject, body, _html = sent.mails[0]
    assert subject == "[whichports] An update fixes CVEs on Mail relay"
    assert "  server: Mail relay (mail-01)\n  port: 22\n  CVEs: 1\n  new: 1\n" in body
    assert "Nothing else will be sent about these CVEs on the same port." in body


def test_a_chat_gets_the_same_words_and_a_payload_with_no_cve_id(con):
    hook(con)
    batch(con, WEB)
    sent = Sent()
    deliver(con, sent)
    _label, text, payload, message = sent.posts[0]
    assert message.title == "A newer version fixes CVEs on web-07"
    assert dict(message.fields) == {"server": "web-07", "ports": "22, 80", "CVEs": "3", "new": "3"}
    assert "whichports: A newer version fixes CVEs on web-07" in text
    assert payload == {"version": payload["version"], "kind": channels.KIND_CVE,
                       "servers": [{"server": "web-07", "ports": ["22", "80"]}], "cves": 3, "new": 3}
    assert "CVE-2026" not in text + json.dumps(payload)


# ------------------------------------------------------ one fails, one not

def test_a_destination_that_failed_is_tried_again_and_the_others_are_not_sent_twice(con):
    hook(con, "works")
    hook(con, "broken")
    mailbox(con)
    batch(con, WEB)
    sent = Sent(refuse={"broken"})
    assert deliver(con, sent) == 2
    assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 0
    sent.refuse.clear()
    assert deliver(con, sent, now=NOW + timedelta(minutes=10)) == 1
    assert sorted(label for label, *_ in sent.posts) == ["broken", "works"]
    assert len(sent.mails) == 1


def test_a_mail_the_relay_refused_is_tried_again(con):
    mailbox(con)
    batch(con, WEB)
    sent = Sent(refuse={"ops@example.com"})
    assert deliver(con, sent) == 0 and sent.mails == []
    sent.refuse.clear()
    assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 1
    assert deliver(con, sent, now=NOW + timedelta(minutes=10)) == 0


def test_a_batch_a_day_old_is_sent_to_nobody_any_more_and_is_deleted(con):
    """A destination that could not be reached for a day does not get the
    message a day late, and one added a week later does not get every old
    one. The CVEs are on the server's page. And a batch nobody is sent any
    more is not kept: it goes with its delivery rows at that pass."""
    batch(con, WEB)
    late = Sent()
    hook(con)
    assert deliver(con, late, now=NOW + timedelta(hours=23)) == 1
    hook(con, "added-later")
    assert deliver(con, late, now=NOW + timedelta(hours=24, minutes=1)) == 0
    assert [label for label, *_ in late.posts] == ["hook"]
    for table in ("cve_batches", "cve_batch_deliveries"):
        assert con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0, table


def test_a_batch_younger_than_a_day_is_kept_with_its_delivery_rows(con):
    hook(con)
    batch(con, WEB)
    batch(con, MAIL, when=NOW - timedelta(hours=25))
    deliver(con, Sent())
    assert con.execute("SELECT COUNT(*) FROM cve_batches").fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM cve_batch_deliveries").fetchone()[0] == 1


# ------------------------------------------------- a mute, at every try

def looked(con, name="web-07"):
    """A server the check has looked at once, and then a second time with a
    CVE new on each of its two ports. Returns the batch's id."""
    from test_cvetell import FIRST, LATER, extracts, report, reports
    from app.cveextract import Row
    host_id, _ = store.add_host(con, name)
    reports(con, host_id, report())
    cvetell.evaluate(con, now=NOW, extract_for=extracts(FIRST))
    later = LATER + [Row("nginx", "CVE-2026-00004", "1.22.1-9+deb12u11", "low")]
    [batch_id] = cvetell.evaluate(con, now=NOW, extract_for=extracts(later))
    return batch_id


def test_a_server_muted_before_a_try_is_out_of_the_batch_for_good(con):
    """A mute records and does not queue: the message does not go out when
    the mute ends, though the batch is not a day old."""
    hook(con)
    batch_id = looked(con)
    sent = Sent(refuse={"hook"})
    assert deliver(con, sent) == 0
    finding_alerts.mute_host(con, "web-07", now=NOW)
    sent.refuse.clear()
    assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 0
    finding_alerts.unmute_host(con, "web-07", now=NOW + timedelta(minutes=6))
    assert deliver(con, sent, now=NOW + timedelta(minutes=10)) == 0
    assert sent.posts == []
    assert con.execute("SELECT COUNT(*) FROM cve_batches WHERE id = ?", (batch_id,)).fetchone()[0] == 0


def test_a_port_silenced_before_a_try_leaves_with_its_own_cves_and_no_others(con):
    hook(con)
    looked(con)
    sent = Sent(refuse={"hook"})
    assert deliver(con, sent) == 0
    finding_alerts.silence_port(con, "web-07", "tcp", 80, "v4", now=NOW)
    sent.refuse.clear()
    assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 1
    _label, _text, payload, message = sent.posts[0]
    fields = dict(message.fields)
    assert fields["port"] == "22" and "ports" not in fields
    # The mark on the page leaves the silenced port out, so the count is
    # port 22's two, and one of them is told. Port 22's lists offer every
    # fix, so the title says an update, as that mark does.
    assert (fields["CVEs"], fields["new"]) == ("2", "1")
    assert message.title == "An update fixes CVEs on web-07"
    assert payload["servers"] == [{"server": "web-07", "ports": ["22"]}]
    assert (payload["cves"], payload["new"]) == (2, 1)


def test_a_port_silenced_before_its_cves_were_new_is_out_of_every_count_of_the_message(con):
    """The second big test, finding G9: port 6379 silenced, then redis's 2
    CVEs and nginx's 12 new on one report, and the message said "CVEs: 14"
    for port 80. The mail, the chat card and the webhook's JSON count what
    the page's mark stands for, and the page leaves a silenced port out."""
    from test_cvetell import FIRST, LATER, extracts, report, reports
    from app.cveextract import Row
    hook(con)
    mailbox(con)
    host_id, _ = store.add_host(con, "web-07")
    reports(con, host_id, report())
    cvetell.evaluate(con, now=NOW, extract_for=extracts(FIRST))
    finding_alerts.silence_port(con, "web-07", "tcp", 22, "v4", now=NOW)
    later = LATER + [Row("nginx", "CVE-2026-00004", "1.22.1-9+deb12u11", "low")]
    cvetell.evaluate(con, now=NOW, extract_for=extracts(later))
    sent = Sent()
    assert deliver(con, sent) == 2
    _label, _text, payload, message = sent.posts[0]
    fields = dict(message.fields)
    assert (fields["port"], fields["CVEs"], fields["new"]) == ("80", "2", "1")
    assert (payload["cves"], payload["new"]) == (2, 1)
    _to, _subject, body, _html = sent.mails[0]
    assert "  port: 80\n  CVEs: 2\n  new: 1\n" in body


def test_one_muted_server_leaves_and_the_other_is_still_told(con):
    hook(con)
    batch(con, WEB, MAIL)
    finding_alerts.mute_host(con, "mail-01", now=NOW)
    sent = Sent()
    assert deliver(con, sent) == 1
    assert sent.posts[0][3].title == "A newer version fixes CVEs on web-07"
    assert "mail-01" not in json.dumps(sent.posts[0][2])


def test_another_workspaces_mute_never_takes_a_server_out_of_this_workspaces_batch(con):
    """Workspace 1 deletes mail-01 while its batch is still going out, and
    another workspace makes a server of that name, which SQLite gives the id
    that came free. Muting that one is the other workspace's business."""
    other = db.create_workspace(con, "another")
    hook(con, "ours")
    batch(con, MAIL)
    was = con.execute("SELECT id FROM hosts WHERE name = 'mail-01'").fetchone()[0]
    assert store.revoke_host(con, "mail-01") and store.delete_host(con, "mail-01")
    now_is, _ = store.add_host(con, "mail-01", workspace_id=other)
    assert now_is == was, "the id did not come free, so this test holds nothing"
    finding_alerts.mute_host(con, "mail-01", now=NOW, workspace_id=other)
    sent = Sent()
    assert deliver(con, sent) == 1
    assert sent.posts[0][3].title == "An update fixes CVEs on mail-01"


# ------------------------------------------------------ a display name

def test_a_display_name_is_said_only_for_the_server_the_batch_was_written_for(con):
    """The id and the name of a deleted server can each go to another
    server. A display name is said while all three still match: the id, the
    name and the batch's workspace."""
    hook(con)
    batch(con, MAIL)
    displayname.set_display_name(con, "mail-01", "Mail relay")
    sent = Sent()
    deliver(con, sent)
    assert sent.posts[0][3].title == "An update fixes CVEs on Mail relay"
    # The same workspace deletes it and makes a new server of that name.
    batch(con, MAIL)
    assert store.revoke_host(con, "mail-01") and store.delete_host(con, "mail-01")
    store.add_host(con, "placeholder")
    store.add_host(con, "mail-01")
    displayname.set_display_name(con, "mail-01", "Another box")
    deliver(con, sent, now=NOW + timedelta(minutes=5))
    assert sent.posts[1][3].title == "An update fixes CVEs on mail-01"


# -------------------------------------------------------------- who gets it

def test_a_destination_that_does_not_take_the_kind_gets_nothing_and_is_not_asked_again(con):
    hook(con, "findings-only", subscriptions=[channels.KIND_FINDING])
    hook(con, "takes-cves", subscriptions=[channels.KIND_CVE])
    hook(con, "takes-all")
    batch(con, WEB)
    sent = Sent()
    assert deliver(con, sent) == 2
    assert sorted(label for label, *_ in sent.posts) == ["takes-all", "takes-cves"]
    # The sent log says what went out: two lines, none for the destination
    # that let the batch go.
    assert con.execute("SELECT COUNT(*) FROM sent_log").fetchone()[0] == 2
    channels.set_subscriptions(con, "findings-only", [channels.KIND_FINDING, channels.KIND_CVE])
    assert deliver(con, sent, now=NOW + timedelta(minutes=5)) == 0, "a batch it had let go of came back"


def test_another_workspaces_destination_gets_nothing(con):
    other = db.create_workspace(con, "another")
    hook(con, "ours")
    hook(con, "theirs", workspace_id=other)
    mailbox(con, "them@example.com", workspace_id=other)
    batch(con, WEB)
    batch(con, ("their-box", [("tcp", 22)], ["CVE-2026-00009"], True), workspace_id=other)
    sent = Sent()
    assert deliver(con, sent) == 3
    by_label = {label: message.title for label, _text, _payload, message in sent.posts}
    assert by_label == {"ours": "A newer version fixes CVEs on web-07",
                        "theirs": "An update fixes CVEs on their-box"}
    assert [(to, subject) for to, subject, *_ in sent.mails] == [
        ("them@example.com", "[whichports] An update fixes CVEs on their-box")]


def test_the_environments_recipient_is_mailed_about_the_operators_workspace_and_no_other(con):
    other = db.create_workspace(con, "another")
    batch(con, WEB)
    batch(con, ("their-box", [("tcp", 22)], ["CVE-2026-00009"], True), workspace_id=other)
    sent = Sent()
    assert deliver(con, sent, use_environment=True) == 1
    assert [(to, subject) for to, subject, *_ in sent.mails] == [
        ("operator@example.com", "[whichports] A newer version fixes CVEs on web-07")]
    assert deliver(con, sent, now=NOW + timedelta(minutes=5), use_environment=True) == 0
    assert deliver(con, Sent(), use_environment=False) == 0


# ------------------------------------------------------------ what is kept

def test_what_went_out_is_in_the_sent_log_once_for_each_destination_that_took_it(con):
    hook(con, "works")
    hook(con, "broken")
    batch(con, WEB, MAIL)
    deliver(con, Sent(refuse={"broken"}))
    rows = con.execute("SELECT workspace_id, host_name, detail, sent_at FROM sent_log").fetchall()
    assert [tuple(row) for row in rows] == [
        (db.DEFAULT_WORKSPACE_ID, "mail-01, web-07", "A newer version fixes CVEs on 2 servers", NOW.isoformat())]


def test_nothing_is_sent_about_a_cve_twice_from_the_look_to_the_relay(con):
    """The whole of the promise, end to end: look, tell, send, and look
    again with nothing changed."""
    from test_cvetell import FIRST, LATER, extracts, report, reports
    host_id, _ = store.add_host(con, "web-07")
    reports(con, host_id, report())
    mailbox(con)
    sent = Sent()
    for rows in (FIRST, LATER, LATER, LATER):
        cvetell.evaluate(con, now=NOW, extract_for=extracts(rows))
        deliver(con, sent)
    assert [subject for _to, subject, *_ in sent.mails] == ["[whichports] A newer version fixes CVEs on web-07"]
    assert "  CVEs: 3\n  new: 1\n" in sent.mails[0][2]


# ---------------------------------------- what is still true, at every try
#
# The second big test, 2026-10-25, case E10a: nginx and then apache2 held at
# old versions were told in the morning, then removed with every hold
# lifted, and no port of that server carried a mark from then. A Webhook
# added an hour later was sent both morning messages at the next sweep: a
# batch is handed out for a day to every destination that has not had it,
# as it was written. A message says what is true now (docs/PRODUCT.md 4c),
# so at every try a port whose card no longer marks what it told leaves the
# batch, the way a port silenced since leaves it.

def later_rows():
    from test_cvetell import LATER
    from app.cveextract import Row
    return LATER + [Row("nginx", "CVE-2026-00004", "1.22.1-9+deb12u11", "low")]


def reported_again(con, doc, name="web-07"):
    from test_cvetell import reports
    host_id = con.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
    reports(con, host_id, doc)


def test_a_destination_added_after_the_packages_went_is_told_nothing(con):
    from test_cvetell import extracts, report
    hook(con, "first")
    looked(con)
    sent = Sent()
    assert deliver(con, sent, extract_for=extracts(later_rows())) == 1
    gone = report()
    gone["sockets"]["listening"] = []
    reported_again(con, gone)
    hook(con, "added-later")
    assert deliver(con, sent, now=NOW + timedelta(hours=1), extract_for=extracts(later_rows())) == 0
    assert [label for label, *_ in sent.posts] == ["first"]


def test_a_destination_added_later_is_told_only_what_still_stands(con):
    """OpenSSH was upgraded past every fix, nginx was not: port 22 leaves
    the message and port 80 keeps the CVE that was new on it."""
    from test_cvetell import extracts, report
    hook(con, "first")
    looked(con)
    sent = Sent()
    assert deliver(con, sent, extract_for=extracts(later_rows())) == 1
    reported_again(con, report(ssh="1:9.2p1-2+deb12u10"))
    hook(con, "added-later")
    assert deliver(con, sent, now=NOW + timedelta(hours=1), extract_for=extracts(later_rows())) == 1
    label, _text, payload, message = sent.posts[-1]
    assert label == "added-later"
    fields = dict(message.fields)
    assert fields["port"] == "80" and "ports" not in fields
    assert (fields["CVEs"], fields["new"]) == ("2", "1")
    assert payload["servers"] == [{"server": "web-07", "ports": ["80"]}]


def test_a_failed_destination_tried_again_is_told_only_what_still_stands(con):
    from test_cvetell import extracts, report
    hook(con)
    looked(con)
    sent = Sent(refuse={"hook"})
    assert deliver(con, sent, extract_for=extracts(later_rows())) == 0
    gone = report()
    gone["sockets"]["listening"] = []
    reported_again(con, gone)
    sent.refuse.clear()
    assert deliver(con, sent, now=NOW + timedelta(minutes=10), extract_for=extracts(later_rows())) == 0
    assert sent.posts == []


def test_a_report_the_check_cannot_read_leaves_the_batch_as_it_was_written(con):
    """No data for the release now: nothing read says the CVEs went, so the
    message is still what was written."""
    from test_cvetell import report
    hook(con, "first")
    looked(con)
    reported_again(con, report())
    hook(con, "added-later")
    sent = Sent()
    assert deliver(con, sent, extract_for=lambda distribution, version_id: None) == 2
    assert sorted(label for label, *_ in sent.posts) == ["added-later", "first"]


# -------------------------------- a destination hears what is written after it
#
# Decided on 26 October 2026, after the second big test's E10a: a destination
# hears what is raised after it was added, a CVE message as much as an alert.
# A batch written before a destination was added stays with the destinations
# that were there, also while what it tells still stands.

def test_a_destination_added_after_a_batch_was_written_is_not_handed_it(con):
    hook(con, "first")
    batch(con, WEB)
    channels.add(con, channels.TYPE_WEBHOOK, "added-later", "", now=NOW + timedelta(hours=1),
                 destination="https://hooks.example.com/added-later")
    sent = Sent()
    assert deliver(con, sent, now=NOW + timedelta(hours=2)) == 1
    assert [label for label, *_ in sent.posts] == ["first"]
    assert deliver(con, sent, now=NOW + timedelta(hours=3)) == 0


def test_a_batch_written_after_a_destination_was_added_reaches_it(con):
    channels.add(con, channels.TYPE_WEBHOOK, "early", "", now=NOW - timedelta(hours=1),
                 destination="https://hooks.example.com/early")
    batch(con, WEB)
    sent = Sent()
    assert deliver(con, sent) == 1
    assert [label for label, *_ in sent.posts] == ["early"]
