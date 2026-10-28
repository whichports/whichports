"""The Sent list's row for the message that an agent reports again.

    Run from site/: python3 -m pytest app/test_sent_reporting_again.py

The message itself and who gets it are the control plane's
(`controlplane/app/reportingagain.py`, its tests beside it). What went out
is a line in the sent log, and this holds how the Alerts screen draws that
line: the tag says what happened, and the few grey words beside it say how
long nothing came, in the words the silence's own row uses. The stored
sentence is made by the control plane's own function, so this cannot drift
from it.
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
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)

NOW = trl.NOW


def back(db, minutes, name="back"):  # noqa: F811
    """A server that was silent, reports again, and one sent line for each:
    the silence's, an hour ago, and the one that says it is back, now."""
    trl.add_host(db, name, [(NOW - timedelta(minutes=2), trl.document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    trl.add_alert(db, name, "no report for 40 minutes, past the 35 minute threshold",
                  NOW - timedelta(hours=1), resolved=True, notified=True)
    con = sqlite3.connect(db)
    con.executescript(trl.SENT_LOG_SCHEMA)
    con.execute("INSERT INTO sent_log (workspace_id, host_name, detail, channel, sent_at)"
                " VALUES (1, ?, ?, 'email', ?)",
                (name, joinbridge.module("reportingagain").detail(minutes), NOW.isoformat()))
    con.commit()
    con.close()


def rows(db):  # noqa: F811
    """The text of each row of the Sent list, newest first."""
    section = trl.sent_section(rl.render(db, now=NOW))
    found = re.findall(r'<div class="al[^"]*"[^>]*>.*?</div>\s*(?=<div class="al|</div>)', section, re.S)
    return [re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", row)).strip() for row in found]


def test_the_row_says_reporting_again_once_and_how_long_nothing_came(db):  # noqa: F811
    back(db, 72)
    section = trl.sent_section(rl.render(db, now=NOW))
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", section))
    assert text.count("reporting again") == 1, text
    assert "nothing from the agent for 72 min" in text
    # The silence's own row stands under it, in the same words.
    assert "nothing from the agent for 40 min" in text
    assert text.index("reporting again") < text.index("nothing from the agent for 40 min")


@pytest.mark.parametrize("minutes,said", [(72, "72 min"), (300, "5 hours"), (3 * 24 * 60, "3 days")])
def test_a_long_silence_is_said_in_hours_or_days_as_the_message_says_it(db, minutes, said):  # noqa: F811
    back(db, minutes)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", trl.sent_section(rl.render(db, now=NOW))))
    assert f"nothing from the agent for {said}" in text


def test_a_line_with_no_length_says_reporting_again_and_nothing_more(db):  # noqa: F811
    back(db, None)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", trl.sent_section(rl.render(db, now=NOW))))
    assert text.count("reporting again") == 1 and "nothing from the agent for 40 min" in text
    assert text.count("nothing from the agent for") == 1


def test_the_stored_sentence_opens_with_the_words_this_page_looks_for():
    """Spelled on both sides and held together here, as the silence's
    sentence is."""
    made = joinbridge.module("reportingagain").detail
    assert made(72).startswith(rl.AGAIN_STORED) and made(None) == rl.AGAIN_STORED
    assert made(72) == rl.AGAIN_STORED + ", " + rl.SILENT_STORED + "72 minutes"
