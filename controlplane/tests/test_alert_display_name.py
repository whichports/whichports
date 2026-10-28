"""An alert's first line says the server's display name.

    python -m pytest tests/test_alert_display_name.py

Decided on 2026-10-02 (`docs/RECORD.md` 4.238): the mail's subject and
heading, and a chat channel's first line, say the display name when a server
has one. Two servers may carry the same display name, so such a message also
gives the name the server is found by. Since the alert messages became
labelled values (docs/screens/mails/SPEC-alert-messages.md) it gives it in
the `server` field, `Webshop (web-07)`, where it had a line `id` of its own.

What must not move is tested as hard as what moves: a server without a
display name is said by its one name, once, and a program reading the
webhook's `server` field gets what it always got.
"""
import re

import pytest

from app import db, displayname, mailhtml, notify, senders, store, sweep_cli, webhook
from test_sweep_cli import (a_change_is_due, con_for, dbpath, hooked,  # noqa: F401
                            posted, sent)

ID = "web-07"
DISPLAY = "Webshop"
DETAIL = "no report for 180 minutes, past the 35 minute threshold"
STALE_DETAIL = ("no probing pass has finished for web-07 in 7 hours, so what the"
                " screen says about reachability is that old")
RAISED = "2026-10-02T10:00:00+00:00"


def change(**kw):
    base = dict(where="tcp/443 on v4", was="intended", now="conflict",
                description="Reachable from outside, and you declared it closed.",
                vantage="probe1", measured_at="2026-10-02T10:00:00+00:00",
                port=443, family="v4", answers=True)
    return notify.Change(**{**base, **kw})


CHANGES = [change(), change(where="tcp/80 on v4", port=80)]

# Each formatter three ways: without the argument, with an empty display name,
# and with one. (name, call without, call with display)
MAILS = [
    ("silence",
     lambda display=None: (notify.format_silence(ID, DETAIL, RAISED) if display is None
                           else notify.format_silence(ID, DETAIL, RAISED, display))),
    ("outside stale",
     lambda display=None: (notify.format_outside_stale(ID, STALE_DETAIL, RAISED)
                           if display is None
                           else notify.format_outside_stale(ID, STALE_DETAIL, RAISED, display))),
    ("finding changes",
     lambda display=None: (notify.format_finding_changes(ID, CHANGES) if display is None
                           else notify.format_finding_changes(ID, CHANGES, display))),
]


def seen(html):
    """What a reader sees of a mail's HTML half."""
    body = html[html.index("<body"):]
    return " ".join(re.sub(r"<[^>]+>", " ", body).split())


# --------------------------------------------- a server with one name only

@pytest.mark.parametrize("name, mail", MAILS, ids=[m[0] for m in MAILS])
def test_a_server_without_a_display_name_is_said_by_its_one_name(name, mail):
    assert mail("") == mail()
    subject, body, html = mail()
    assert ID in subject
    assert f"\n  server: {ID}\n" in body
    assert "(" not in body and "(" not in seen(html)


def test_a_server_without_a_display_name_is_said_once_in_a_chat_text():
    assert senders.text_for_alert("silent", ID, DETAIL, RAISED, "") == \
        senders.text_for_alert("silent", ID, DETAIL, RAISED)
    assert senders.text_for_changes(ID, CHANGES, "") == senders.text_for_changes(ID, CHANGES)
    lines = senders.text_for_alert("silent", ID, DETAIL, RAISED).split("\n")
    assert lines[0] == f"whichports: {ID} stopped reporting"
    assert lines[1] == f"server: {ID}"
    assert "(" not in senders.text_for_changes(ID, CHANGES)


# ------------------------------------------------------------- the first line

@pytest.mark.parametrize("name, mail", MAILS, ids=[m[0] for m in MAILS])
def test_the_subject_and_the_heading_say_the_display_name(name, mail):
    subject, body, html = mail(DISPLAY)
    assert subject.startswith("[whichports] ")
    assert DISPLAY in subject and ID not in subject
    assert DISPLAY in body.split("\n")[0] and ID not in body.split("\n")[0]
    # the mail's title is its heading, and both are the first line a reader sees
    heading = html.split("<title>", 1)[1].split("</title>", 1)[0]
    assert DISPLAY in heading and ID not in heading
    assert f">{heading}</div>" in html


def test_the_finding_mail_says_the_display_name_in_its_title():
    subject, _body, _html = notify.format_finding_changes(ID, [change()], DISPLAY)
    assert subject == "[whichports] Port 443 on Webshop is reachable from the internet"


@pytest.mark.parametrize("name, mail", MAILS, ids=[m[0] for m in MAILS])
def test_a_mail_that_says_a_display_name_also_gives_the_id(name, mail):
    """Two servers may carry the same display name. The mail has to say
    which, and says it in the server's own field (docs/RECORD.md 4.255)."""
    _subject, body, html = mail(DISPLAY)
    assert f"\n  server: {DISPLAY} ({ID})\n" in body
    assert f"server {DISPLAY} ({ID})" in seen(html)
    # And its one link is that server's page.
    assert f"/host/{ID}" in body and f'/host/{ID}"' in html


def test_two_servers_with_one_display_name_get_two_mails_that_differ_by_the_id():
    one = notify.format_silence("web-01", DETAIL, RAISED, DISPLAY)
    two = notify.format_silence("web-02", DETAIL, RAISED, DISPLAY)
    assert one[0] == two[0]                       # the same first line
    assert one[1] != two[1] and one[2] != two[2]  # and still two different mails
    assert "Webshop (web-01)" in one[1] and "Webshop (web-02)" in two[1]
    # A reader who sees only the designed half can tell them apart as well.
    assert "Webshop (web-01)" in seen(one[2]) and "Webshop (web-02)" in seen(two[2])


def test_the_only_difference_a_display_name_makes_to_a_mail_is_the_name_and_the_id():
    """Take the display name back out and the mail is the one a server
    without one gets."""
    _s, plain, _h = notify.format_silence(ID, DETAIL, RAISED)
    _s, named, _h = notify.format_silence(ID, DETAIL, RAISED, DISPLAY)
    restored = named.replace(f"{DISPLAY} ({ID})", ID).replace(DISPLAY, ID)
    assert restored == plain


@pytest.mark.parametrize("hostile", ["<script>alert(1)</script>", '"><img src=x>', "a & b"])
def test_a_display_name_is_escaped_in_the_html_mail(hostile):
    """The store refuses markup (app/displayname.py). The mail does not rely
    on that."""
    for said in (notify.said_silence(ID, DETAIL, hostile),
                 notify.said_outside_stale(ID, STALE_DETAIL, hostile),
                 notify.said_changes(ID, CHANGES, hostile)):
        html = mailhtml.alert(said)
        assert "<script>" not in html and "<img" not in html
        assert "a & b" not in html


def test_a_display_name_adds_no_header_line_to_the_subject():
    """A line break in a subject would be a way to add mail headers. The store
    refuses one, and a subject built from a stored name never holds one."""
    with pytest.raises(displayname.DisplayNameError):
        displayname.checked("Webshop\r\nBcc: someone@example.com")
    subject, _b, _h = notify.format_silence(ID, DETAIL, RAISED, DISPLAY)
    assert "\n" not in subject and "\r" not in subject


# ------------------------------------------------------------------- the chat

def test_a_chat_messages_first_line_says_the_display_name_and_the_next_both_names():
    text = senders.text_for_alert("silent", ID, DETAIL, RAISED, DISPLAY)
    lines = text.split("\n")
    assert lines[0] == "whichports: Webshop stopped reporting"
    assert lines[1] == f"server: {DISPLAY} ({ID})"
    assert lines[2] == "no report for: 180 minutes"

    lines = senders.text_for_changes(ID, CHANGES, DISPLAY).split("\n")
    assert lines[0] == "whichports: 2 ports changed on Webshop"
    assert lines[1] == f"server: {DISPLAY} ({ID})"
    assert lines[2] == "reachable: 80, 443"


# ---------------------------------------------------------------- the webhook

@pytest.mark.parametrize("display", ["", DISPLAY])
def test_a_consumer_reading_only_server_gets_what_it_got_before(display):
    """`server` is the name the server is found by, with or without a display
    name, and the version of the payload does not move."""
    before = webhook.payload_for_alert("silent", ID, DETAIL, RAISED)
    after = webhook.payload_for_alert("silent", ID, DETAIL, RAISED, display)
    assert after["server"] == before["server"] == ID
    assert after["version"] == before["version"] == webhook.PAYLOAD_VERSION
    for key, value in before.items():
        assert after[key] == value, key

    before = webhook.payload_for_changes(ID, CHANGES)
    after = webhook.payload_for_changes(ID, CHANGES, display)
    assert after["server"] == ID
    for key, value in before.items():
        assert after[key] == value, key


def test_without_a_display_name_the_payload_is_exactly_the_old_one():
    assert webhook.payload_for_alert("silent", ID, DETAIL, RAISED, "") == \
        webhook.payload_for_alert("silent", ID, DETAIL, RAISED) == {
            "version": webhook.PAYLOAD_VERSION, "kind": "silent", "server": ID,
            "detail": DETAIL, "raised_at": RAISED}
    assert "server_name" not in webhook.payload_for_changes(ID, CHANGES)


def test_a_display_name_is_one_added_field_and_nothing_else():
    plain = webhook.payload_for_changes(ID, CHANGES)
    named = webhook.payload_for_changes(ID, CHANGES, DISPLAY)
    assert set(named) - set(plain) == {"server_name"}
    assert named["server_name"] == DISPLAY


# ------------------------------------------------------------------ the sweep

def name_it(path, host_name, display):
    con = con_for(path)
    displayname.init(con)
    assert displayname.set_display_name(con, host_name, display) == display
    con.close()


def test_the_sweep_mails_the_display_name_and_posts_both_names(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    name_it(dbpath, "one", DISPLAY)
    assert sweep_cli.main([]) == 0

    assert len(sent) == 1
    subject, body = sent[0]
    assert subject == "[whichports] Port 443 on Webshop does not answer from the internet"
    assert "  server: Webshop (one)\n" in body

    assert len(posted) == 1
    assert posted[0]["server"] == "one"
    assert posted[0]["server_name"] == DISPLAY


def test_the_sweep_on_a_server_without_one_says_what_it_always_said(dbpath, sent, posted, hooked):
    a_change_is_due(dbpath)
    assert sweep_cli.main([]) == 0
    subject, body = sent[0]
    assert subject == "[whichports] Port 443 on one does not answer from the internet"
    assert "  server: one\n" in body and "(" not in body
    assert posted[0]["server"] == "one" and "server_name" not in posted[0]


def test_the_sweep_runs_on_a_database_from_before_display_names(dbpath, sent):
    """No table at all, which is every box until its first display name is
    saved: the sweep sends the old message and does not fail."""
    a_change_is_due(dbpath)
    con = con_for(dbpath)
    assert con.execute("SELECT count(*) FROM sqlite_master WHERE name ="
                       " 'host_display_names'").fetchone()[0] == 0
    con.close()
    assert sweep_cli.main([]) == 0
    assert sent[0][0] == "[whichports] Port 443 on one does not answer from the internet"


def test_a_silence_alert_from_the_sweep_says_the_display_name(dbpath, sent):
    from datetime import datetime, timedelta, timezone
    host_id = a_change_is_due(dbpath)
    name_it(dbpath, "one", DISPLAY)
    con = con_for(dbpath)
    con.execute("UPDATE hosts SET last_report_at = ? WHERE id = ?",
                ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(), host_id))
    con.commit()
    con.close()
    sweep_cli.main([])
    subjects = sorted(subject for subject, _ in sent)
    assert "[whichports] Webshop stopped reporting" in subjects
    assert all("one" not in subject for subject in subjects)


def test_a_display_name_cleared_puts_the_id_back_in_the_next_message(dbpath, sent):
    a_change_is_due(dbpath)
    name_it(dbpath, "one", DISPLAY)
    con = con_for(dbpath)
    assert displayname.set_display_name(con, "one", "") == ""
    con.close()
    assert sweep_cli.main([]) == 0
    assert sent[0][0] == "[whichports] Port 443 on one does not answer from the internet"


def test_one_servers_display_name_is_not_said_about_another(dbpath, sent):
    a_change_is_due(dbpath)
    con = con_for(dbpath)
    store.add_host(con, "two")
    displayname.init(con)
    displayname.set_display_name(con, "two", "Somebody else")
    con.close()
    assert sweep_cli.main([]) == 0
    assert sent[0][0] == "[whichports] Port 443 on one does not answer from the internet"
    assert "Somebody else" not in sent[0][1]
