"""An alert mail says no time, and the webhook keeps the time as it is stored.

    python -m pytest tests/test_mail_time.py

Until the alert messages were rebuilt as labelled values
(docs/screens/mails/SPEC-alert-messages.md) each alert mail said when: a
`since` line, and `measured from ... at ...` under a port. Neither half says
one now. The time is on the server's page, which the mail's one link opens.
The webhook, which a program reads, keeps both of its time fields.
"""
import re

import pytest

from app import notify, webhook

STORED = "2026-10-03T15:20:00.123456+00:00"
WRITTEN_FOR_PEOPLE = "2026-09-06 09:12 UTC"


def change(measured_at=STORED):
    return notify.Change(where="tcp/443 on v4", was="intended", now="conflict",
                         description="Reachable from outside, and you declared it closed.",
                         vantage="probe1", measured_at=measured_at,
                         port=443, family="v4", answers=True)


MAILS = [
    ("silence", lambda when: notify.format_silence(
        "box", "no report for 41 minutes, past the 35 minute threshold", when)),
    ("outside stale", lambda when: notify.format_outside_stale(
        "box", "no probing pass has finished for box in 7 hours, so what the"
               " screen says about reachability is that old", when)),
    ("finding changes",
     lambda when: notify.format_finding_changes("box", [change(when)])),
]


@pytest.mark.parametrize("when", [STORED, WRITTEN_FOR_PEOPLE])
@pytest.mark.parametrize("name, mail", MAILS, ids=[m[0] for m in MAILS])
def test_neither_half_of_an_alert_mail_says_a_time(name, mail, when):
    subject, body, html = mail(when)
    seen = re.sub(r"<[^>]+>", " ", html[html.index("<body"):])
    for part in (subject, body, seen):
        assert when not in part
        assert not re.search(r"\d{4}-\d{2}-\d{2}|\d{2}:\d{2}|UTC", part), part
        assert "since" not in part and "measured" not in part
        assert "probe1" not in part


def test_how_long_is_still_said_and_it_is_a_length_not_a_moment():
    _subject, silence, _html = MAILS[0][1](STORED)
    assert "  no report for: 41 minutes\n" in silence
    _subject, stale, _html = MAILS[1][1](STORED)
    assert "  no check for: 7 hours\n" in stale


def test_the_webhook_keeps_the_time_as_it_is_stored():
    """A program reads these two fields, so they do not change."""
    alert = webhook.payload_for_alert("silent", "box", "no report", STORED)
    assert alert["raised_at"] == STORED
    changes = webhook.payload_for_changes("box", [change()])
    assert changes["changes"][0]["measured_at"] == STORED
