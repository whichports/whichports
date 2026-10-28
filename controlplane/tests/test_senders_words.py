"""A chat message says what the mail says.

    python -m pytest tests/test_senders_words.py

Every alert is one description (`app/alertwords.py`). The mail draws it
(`app/notify.py`) and `app/senders.py` builds the chat message from the same
one, which every channel then shapes. These hold a chat message's title, its
labelled values, its closing line and its link to the mail's text half, so
the two cannot come to say different things. What a shape looks like is held
in test_senders_shapes.py. This file is about the words only.
"""
import json
import re

import pytest

from app import alerts, finding_alerts, join, notify, publicurl, senders

ID = "web-07"
DETAIL = "no report for 180 minutes, past the 35 minute threshold"
STALE_DETAIL = ("no probing pass has finished for web-07 in 7 hours, so what the"
                " screen says about reachability is that old")
RAISED = "2026-10-02T10:00:00+00:00"
RULE = "tcp dport 3000 counter accept in ip filter ufw-user-input"
DISPLAYS = ["", "Webshop"]


def change(**kw):
    base = dict(where="tcp/443 on v4", was="intended", now=join.STATE_CONFLICT,
                description="Reachable from outside, and you declared it closed.",
                vantage="probe1", measured_at="2026-10-02T10:00:00+00:00",
                port=443, family="v4", answers=True)
    return notify.Change(**{**base, **kw})


REACHABLE = change(where="tcp/3000 on v4", port=3000, was="", now=join.STATE_INTENDED,
                   became_reachable=True, program="python3", program_said="python3",
                   rule=RULE, allowed_by=join.LAYER_HOST_FIREWALL)
SAID_YES = change(where="tcp/3001 on v6", port=3001, family="v6", was="",
                  now=join.STATE_INTENDED, became_reachable=True, program="node",
                  program_said="node")
NEW_PROGRAM = change(where="tcp/3002 on v4", port=3002, now=join.STATE_INTENDED,
                     program="porttest-b", program_said="porttest-b",
                     was_program="porttest-a", was_program_said="porttest-a",
                     rule=RULE, allowed_by=join.LAYER_HOST_FIREWALL)
FIRST_SEEN = change(where="tcp/22 on v6", port=22, family="v6", was="",
                    now=join.STATE_UNREVIEWED)
CHANGES = [change(), REACHABLE, SAID_YES, NEW_PROGRAM, FIRST_SEEN]


def every_word_of(message) -> list:
    """Everything a message holds, the title aside."""
    said = [message.lead] if message.lead else []
    said += [f"{label}: {value}" for label, value in message.fields]
    if message.closing:
        said.append(message.closing)
    return said


def is_the_mails(message, mail):
    """A chat message against the mail about the same thing: the same
    title, each value the mail's text half holds under the same label, the
    same closing line and the same link."""
    subject, body, _html = mail
    assert subject == f"[whichports] {message.title}"
    assert message.fields
    for label, value in message.fields:
        assert f"  {label}: {value}\n" in body
    # And the mail holds no value the chat message lacks.
    assert body.count("\n  ") == len(message.fields) + 1
    assert message.closing and message.closing in body
    assert f"  {message.link}\n" in body
    # No line `id`, no rows and no time: the description has none.
    assert message.server_id == "" and message.rows == ()
    assert "since" not in dict(message.fields)


@pytest.mark.parametrize("display", DISPLAYS)
def test_the_silent_message_is_the_mails_words(display):
    message = senders.message_for_alert(alerts.KIND_SILENT, ID, DETAIL, RAISED,
                                        display)
    is_the_mails(message, notify.format_silence(ID, DETAIL, RAISED, display))
    assert dict(message.fields)["no report for"] == "180 minutes"
    assert message.closing.startswith("Nothing else will be sent")


@pytest.mark.parametrize("display", DISPLAYS)
def test_the_stale_message_is_the_mails_words(display):
    kind = finding_alerts.KIND_OUTSIDE_STALE
    message = senders.message_for_alert(kind, ID, STALE_DETAIL, RAISED, display)
    is_the_mails(message, notify.format_outside_stale(ID, STALE_DETAIL, RAISED, display))
    assert dict(message.fields)["no check for"] == "7 hours"
    # It says what stopped, and nothing about the ports or about a mail.
    assert message.lead == ""


@pytest.mark.parametrize("display", DISPLAYS)
@pytest.mark.parametrize("changes", [CHANGES] + [[one] for one in CHANGES],
                         ids=["five", "closed", "a rule", "a yes", "program", "first seen"])
def test_the_changes_message_is_the_mails_words(display, changes):
    message = senders.message_for_changes(ID, changes, display)
    is_the_mails(message, notify.format_finding_changes(ID, changes, display))


def test_a_kind_with_no_words_of_its_own_is_said_as_it_is():
    message = senders.message_for_alert("something new", ID, DETAIL, RAISED, "Webshop")
    assert message.title == "Webshop, something new"
    assert message.fields == (("server", "Webshop (web-07)"),)
    assert message.link == publicurl.server(ID)


def test_the_test_message_is_the_mails_words():
    message = senders.message_for_test()
    subject, body, _html = notify.format_test()
    assert subject == f"[whichports] {message.title}" == "[whichports] Test message"
    assert message.lead == "Sent from the Integrations screen." and message.lead in body
    assert message.fields == () and message.closing == ""
    assert message.link == publicurl.integrations() and message.link_words == "Open Integrations"


def test_a_port_that_became_reachable_says_what_allowed_it_and_not_its_state():
    message = senders.message_for_changes(ID, [REACHABLE])
    assert message.title == "Port 3000 on web-07 became reachable from the internet"
    assert message.fields == (
        ("server", "web-07"), ("port", "3000"),
        ("allowed by", "a rule in the server's firewall"), ("program", "python3"))
    text = senders.plain(message)
    assert "had no state" not in text and "intended" not in text
    # Which firewall, and not the rule's own text or where it was measured.
    assert RULE not in text and "probe1" not in text
    yes = senders.message_for_changes(ID, [SAID_YES])
    assert dict(yes.fields)["allowed by"] == "your yes"


def test_a_different_program_says_both_programs():
    message = senders.message_for_changes(ID, [NEW_PROGRAM])
    assert message.title == "A different program answers port 3002 on web-07"
    assert message.fields[2:] == (
        ("program", "porttest-b"), ("before", "porttest-a"),
        ("allowed by", "a rule in the server's firewall"))


def test_a_first_measurement_says_nothing_of_a_state():
    message = senders.message_for_changes(ID, [FIRST_SEEN])
    assert message.title == "Port 22 on web-07 is reachable from the internet"
    assert dict(message.fields)["you said"] == "nothing yet"
    assert "state" not in senders.plain(message)


def test_the_plain_text_holds_every_word_and_ends_at_the_servers_page():
    message = senders.message_for_changes(ID, CHANGES, "Webshop")
    text = senders.plain(message)
    lines = text.split("\n")
    assert lines[0] == "whichports: 5 ports changed on Webshop"
    assert lines[1] == "server: Webshop (web-07)"
    assert lines[-1] == publicurl.server(ID)
    # As often as the message holds it, and no more.
    words = every_word_of(message)
    assert len(lines) == len(words) + 2
    for said in words:
        assert text.count(said) == words.count(said), said


@pytest.mark.parametrize("changes", [CHANGES, [REACHABLE], [NEW_PROGRAM]],
                         ids=["five", "a rule", "program"])
@pytest.mark.parametrize("shape", ["slack", "discord", "telegram"])
def test_every_shape_holds_every_word_of_the_message(shape, changes):
    """Whatever a channel does to the look, no label and no value goes
    missing, and the link is the message's own."""
    message = senders.message_for_changes(ID, changes, "Webshop")
    if shape == "slack":
        shown = json.dumps(senders.slack_blocks(message), ensure_ascii=False)
    elif shape == "discord":
        shown = json.dumps(senders.discord_embed(message), ensure_ascii=False)
    else:
        shown = senders.telegram_html(message)
    assert message.link in shown and "Open Webshop" in shown
    # The marks a shape adds around a word are not the word.
    shown = re.sub(r"</?(b|code|a)\b[^>]*>", "", shown)
    shown = re.sub(r"\s+", " ", shown.replace("\\n", " ").replace("`", "").replace("*", ""))
    for label, value in message.fields:
        assert label in shown and value in shown, (label, value)
    assert message.closing in shown
