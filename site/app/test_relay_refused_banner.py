"""The Fleet's banner for an email destination the relay is refusing.

    python -m pytest app/test_relay_refused_banner.py      (from site/)

docs/screens/fleet/SPEC.md section 1: one line above the title, "Alert mail
to <the address in bold> was refused by the relay.", one action and a
dismiss. The second big test, finding E22 (25 October 2026): the relay
refused alert mail and nothing on the page said so, because nothing kept a
refusal. The sweep keeps it now (controlplane/app/alerts.py,
`note_mail_answer`), and this page draws it in its own words and never the
class of the refusal. The addresses are made up.
"""
import pathlib
import re
import sqlite3
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import joinbridge  # noqa: E402
import render_live as rl  # noqa: E402
import test_render_live as trl  # noqa: E402
from test_render_live import db  # noqa: E402,F401  (the empty database fixture)

NOW = trl.NOW


def refused(db, label, reason="SMTPAuthenticationError", ok=False, workspace_id=1):
    """What the sweep keeps when the relay answers a mail to this row."""
    alerts = joinbridge.module("alerts")
    channels = joinbridge.module("channels")
    con = sqlite3.connect(db)
    con.row_factory = sqlite3.Row
    con.executescript(alerts.SCHEMA)
    row = next(c for c in channels.live(con, workspace_id=workspace_id) if c.label == label)
    alerts.note_mail_answer(con, row, ok, reason, NOW)
    con.close()


def mailbox(db, label, address, workspace_id=1):
    trl.add_channel_holding_its_destination(db, label, address, channel_type="email",
                                            workspace_id=workspace_id)


def notes(html):
    """The banner region of the Fleet, up to the title row."""
    fleet = html[html.index('class="fnotes"'):]
    return fleet[:fleet.index('<div class="ph">')].strip()


def text(html):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()


def test_with_no_refusal_the_region_draws_nothing(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    assert notes(rl.render(db, now=NOW)) == 'class="fnotes"></div>'


def test_a_refused_destination_is_one_banner_with_its_address_in_bold(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    refused(db, "ops")
    region = notes(rl.render(db, now=NOW))
    assert region.count('class="fnote ') == 1
    assert '<div class="fnote fail" data-note="relay-refused:' in region
    assert '<span class="t">Alert mail to <b>ops@example.com</b> was refused by the relay.</span>' in region
    assert '<button class="btn" data-go="integrations">Open channel</button>' in region
    assert '<button class="x" aria-label="Dismiss">&times;</button>' in region
    # The page's words, never the class the sweep kept (SI-8 keeps the
    # class, and the class is ours, not the reader's).
    assert "SMTP" not in rl.render(db, now=NOW)


def test_the_dismissal_key_names_no_address(db):
    """It goes into the browser's storage when dismissed."""
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    refused(db, "ops")
    key = re.search(r'data-note="([^"]*)"', notes(rl.render(db, now=NOW))).group(1)
    assert "ops@example.com" not in key and NOW.isoformat() in key


def test_a_mail_the_relay_took_ends_the_banner(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    refused(db, "ops")
    refused(db, "ops", reason="sent", ok=True)
    assert 'class="fnote ' not in notes(rl.render(db, now=NOW))


def test_a_relay_out_of_reach_draws_no_banner(db):
    """The sentence says refused, and a timeout is not a refusal."""
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    refused(db, "ops", reason="TimeoutError")
    assert 'class="fnote ' not in notes(rl.render(db, now=NOW))


def test_a_destination_switched_off_draws_no_banner(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    refused(db, "ops")
    con = sqlite3.connect(db)
    con.execute("UPDATE notification_channels SET enabled = 0 WHERE label = 'ops'")
    con.commit()
    con.close()
    assert 'class="fnote ' not in notes(rl.render(db, now=NOW))


def test_another_workspaces_refusal_is_not_on_this_page(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "night", "night@example.com", workspace_id=2)
    refused(db, "night", workspace_id=2)
    page = rl.render(db, now=NOW, workspace_id=1)
    assert 'class="fnote ' not in notes(page) and "night@example.com" not in page


def test_two_refused_destinations_are_two_banners_and_the_stylesheet_shows_one(db):
    trl.reporting(db, "box", trl.document(listening=[trl.SSHD]))
    mailbox(db, "ops", "ops@example.com")
    mailbox(db, "night", "night@example.com")
    refused(db, "ops")
    refused(db, "night")
    region = notes(rl.render(db, now=NOW))
    assert region.count('class="fnote fail"') == 2
    assert text(region).count("was refused by the relay.") == 2


def test_an_empty_fleet_draws_no_banner_either(db):
    """The empty Fleet is one box and nothing else (SPEC.md, When there is
    no server)."""
    mailbox(db, "ops", "ops@example.com")
    refused(db, "ops")
    assert "was refused by the relay" not in rl.render(db, now=NOW)
