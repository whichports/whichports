"""A server's Settings, Alerts: the two mail rows say what is so.

    Run from site/: python3 -m pytest app/test_settings_mail_rows.py

The outside review of 2026-10-06 read "On a change to this server PLANNED"
and "When the agent goes quiet PLANNED" while both alerts are built and
raised for every server (docs/RECORD.md 4.460). What was planned was a
switch per server, drawn on and disabled beside the tag. Neither switch
exists: a server's change mails stop while it is muted, from the Mute in
its header, and its quiet alert stops while it is paused, from Paused under
Server (controlplane/app/alerts.py). So each row is a fact, with nothing at
its right. A server with no agent never raises the quiet alert, since only
a report ends one and such a server never sends one, so it has no quiet row.
"""
import pathlib
import re
import sys
from datetime import timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402
from test_render_live import (NOW, SSHD, add_address_host_row, add_host,  # noqa: E402,F401
                              db, document)

CHANGE = "On a change to this server"
QUIET = "When the agent goes quiet"


def mail_list(section):
    """The Mail list of the Alerts category: from its heading to the next."""
    alerts = section.split('<div class="hstage h-alerts">', 1)[1]
    return alerts.split("<h3>Mail", 1)[1].split("<h3>", 1)[0]


def live_section(db, name):
    html = rl.render(db, now=NOW)
    return html.split(f'id="host-{name}"', 1)[1]


def an_agent_server(db):
    add_host(db, "box", [(NOW - timedelta(minutes=2), document(listening=[SSHD]))],
             last_report_at=(NOW - timedelta(minutes=2)).isoformat())
    return live_section(db, "box")


# ------------------------------------------------------------ edge cases

def test_a_server_without_an_agent_has_no_quiet_row(db):
    add_address_host_row(db, "edge")
    mail = mail_list(live_section(db, "edge"))
    assert CHANGE in mail
    assert QUIET not in mail


def test_no_mail_row_is_tagged_planned_or_carries_a_switch(db):
    mail = mail_list(an_agent_server(db))
    assert build.PLANNED_TAG not in mail and "planned" not in mail.lower()
    assert 'class="sw' not in mail


def test_the_sample_says_the_same(db):
    page = build.build_sample()
    mail = mail_list(page[page.index('<div class="wrap view" id="host"'):])
    assert CHANGE in mail and QUIET in mail
    assert "planned" not in mail.lower() and 'class="sw' not in mail


# --------------------------------------------------------- the usual case

def test_a_server_with_an_agent_names_both_alerts_and_the_delay(db):
    mail = mail_list(an_agent_server(db))
    words = " ".join(re.sub(r"<[^>]+>", " ", mail).split())
    minutes = rl.joinbridge.module("alerts").SILENT_AFTER_SECONDS // 60
    assert words == f"{CHANGE} {QUIET} after {minutes} minutes"
