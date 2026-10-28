"""The Sent list's row for an outside view that went stale.

    Run from site/: python3 -m pytest app/test_sent_outside_stale.py

The sent log keeps the words that went out and not the alert's kind, so the
Alerts screen reads the kind from how the words open. Until 2026-10-26 it
did not know this kind's opening, and its Sent row carried the alert's whole
first clause as its tag, in capitals, with the same clause again beside it,
where the row on Open now reads `stale` (docs/screens/alerts/SPEC.md: Sent
has the same six columns as Open now). The stored sentence is made here by
the control plane's own function, so this cannot drift from it.
"""
import pathlib
import re
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
KIND = "outside view stale"


def stale_detail(vantage):
    """The alert's sentence as the control plane writes it, from one named
    vantage, or from the newest run whoever took it."""
    return joinbridge.module("finding_alerts")._stale_detail("web", [(vantage, 3)])


def first_clause(detail):
    return detail.split(",", 1)[0]


def row_texts(section):
    """Each row of a table: its tag, and its text with the tags taken out."""
    found = re.findall(r'<div class="al"[^>]*>.*?</div>', section, re.S)
    out = []
    for row in found:
        tag = re.search(r'<span class="altag">(.*?)</span></span>', row, re.S)
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", row)).strip()
        out.append((re.sub(r"<[^>]+>", "", tag.group(1)) if tag else "", text))
    return out


@pytest.mark.parametrize("vantage", ["probe1", None])
def test_the_sent_line_is_tagged_stale_and_its_why_is_the_first_clause(vantage):
    detail = stale_detail(vantage)
    rows = [dict(host_name="web", detail=detail, sent_at=NOW.isoformat(), channel="email")]
    (line,) = rl.sent_alert_lines(rows)
    assert line.word == "stale"
    assert line.why == first_clause(detail)
    assert (line.protocol, line.port, line.families) == ("", "", ())


def test_the_stored_sentence_opens_with_the_words_this_page_looks_for():
    """Spelled on both sides and held together here, as the silence's and
    the reporting again sentences are."""
    for vantage in ("probe1", None):
        assert stale_detail(vantage).startswith(rl.STALE_STORED)


def test_the_sent_row_carries_the_tag_open_now_carries(db):  # noqa: F811
    trl.add_host(db, "web", [(NOW - timedelta(minutes=2), trl.document())],
                 last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    detail = stale_detail("probe1")
    trl.add_alert(db, "web", detail, NOW - timedelta(hours=1), notified=True, kind=KIND)
    html = rl.render(db, now=NOW)
    (open_row,) = row_texts(trl._open_section(html))
    (sent_row,) = row_texts(trl.sent_section(html))
    assert open_row[0] == sent_row[0] == "stale"
    # The clause is said once on the row, in Why, and never as the tag.
    assert sent_row[1].count(first_clause(detail)) == 1


def test_the_other_kinds_keep_their_tags():
    """The words the Sent list already read right stay as they were."""
    rows = [dict(host_name="web", detail=detail, sent_at=NOW.isoformat(), channel="email")
            for detail in ("no report for 40 minutes, past the 35 minute threshold",
                           "tcp/443 on v4 was open, now conflict",
                           joinbridge.module("reportingagain").detail(72))]
    assert [line.word for line in rl.sent_alert_lines(rows)] == [
        "silent", "conflict", "reporting again"]
