"""Which email destination the relay is refusing, for the Fleet's banner.

    python -m pytest tests/test_mail_refusals.py

The second big test, finding E22 (25 October 2026): the relay's password
was made wrong and the relay refused alert mail, and nothing on the
dashboard said so. Send test's toast was the one place, and it named the
exception. docs/screens/fleet/SPEC.md section 1 draws a banner for "an
alert channel that is refusing delivery", and nothing fed it.

So every mail the sweep hands the relay for an email destination leaves
its answer here: a refusal by the relay starts a row, with the class of
the refusal and never the relay's words (SI-8), and a mail taken ends it.
A relay out of reach is not a relay that refused, and leaves the row as it
was. The addresses here are made up.
"""
import smtplib
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, channels, db, notify

NOW = datetime(2026, 10, 25, 11, 0, tzinfo=timezone.utc)


@pytest.fixture
def con(tmp_path):
    con = db.connect(str(tmp_path / "cp.db"))
    for module in (db, alerts, channels):
        module.init(con)
    return con


def mailbox(con, address="ops@example.com", workspace_id=db.DEFAULT_WORKSPACE_ID):
    return channels.add(con, channels.TYPE_EMAIL, address.split("@")[0], "", now=NOW,
                        destination=address, workspace_id=workspace_id)


# ------------------------------------------------- what a refusal is

@pytest.mark.parametrize("reason", [
    "SMTPAuthenticationError", "SMTPSenderRefused", "SMTPRecipientsRefused",
    "SMTPDataError", "SMTPHeloError", "SMTPConnectError", "SMTPResponseException"])
def test_a_relay_that_answered_with_a_refusal_refused(reason):
    assert notify.refused_by_the_relay(reason)


@pytest.mark.parametrize("reason", [
    "sent", "not configured", "TimeoutError", "ConnectionRefusedError", "gaierror",
    "SSLCertVerificationError", "SMTPServerDisconnected", "SMTPNotSupportedError",
    "relay offers no starttls and a credential is configured",
    "the relay refused it", ""])
def test_a_relay_out_of_reach_or_none_at_all_did_not_refuse(reason):
    assert not notify.refused_by_the_relay(reason)


def test_every_class_that_carries_the_relays_code_is_a_refusal():
    """Held to Python's own smtplib: every class that carries an SMTP reply
    code, and the one for refused recipients, which carries a code for each.
    A class smtplib adds later fails here until it is placed."""
    carrying = {name for name in dir(smtplib)
                if isinstance(getattr(smtplib, name), type)
                and issubclass(getattr(smtplib, name), smtplib.SMTPResponseException)}
    assert carrying | {"SMTPRecipientsRefused"} == set(notify.RELAY_REFUSALS)


# ------------------------------------------------- what is kept

def test_a_refusal_is_kept_with_its_class_and_a_mail_taken_ends_it(con):
    ops = mailbox(con)
    alerts.note_mail_answer(con, ops, False, "SMTPAuthenticationError", NOW)
    assert alerts.mail_refusals(con, db.DEFAULT_WORKSPACE_ID) == {alerts.key_for_channel(ops): NOW.isoformat()}
    row = con.execute("SELECT error FROM mail_refusals").fetchone()
    assert row[0] == "SMTPAuthenticationError"
    alerts.note_mail_answer(con, ops, True, "sent", NOW + timedelta(minutes=5))
    assert alerts.mail_refusals(con, db.DEFAULT_WORKSPACE_ID) == {}


def test_refusals_that_go_on_keep_the_time_they_began(con):
    """So a banner a person dismissed stays dismissed while the relay goes
    on refusing, and a new run of refusals is a new fact."""
    ops = mailbox(con)
    alerts.note_mail_answer(con, ops, False, "SMTPAuthenticationError", NOW)
    alerts.note_mail_answer(con, ops, False, "SMTPAuthenticationError", NOW + timedelta(minutes=5))
    assert alerts.mail_refusals(con, 1) == {alerts.key_for_channel(ops): NOW.isoformat()}
    alerts.note_mail_answer(con, ops, True, "sent", NOW + timedelta(minutes=10))
    alerts.note_mail_answer(con, ops, False, "SMTPSenderRefused", NOW + timedelta(minutes=15))
    assert alerts.mail_refusals(con, 1) == {
        alerts.key_for_channel(ops): (NOW + timedelta(minutes=15)).isoformat()}


def test_a_relay_out_of_reach_leaves_what_was_kept(con):
    ops = mailbox(con)
    alerts.note_mail_answer(con, ops, False, "TimeoutError", NOW)
    assert alerts.mail_refusals(con, 1) == {}
    alerts.note_mail_answer(con, ops, False, "SMTPAuthenticationError", NOW)
    alerts.note_mail_answer(con, ops, False, "ConnectionRefusedError", NOW + timedelta(minutes=5))
    assert alerts.mail_refusals(con, 1) == {alerts.key_for_channel(ops): NOW.isoformat()}


def test_a_refusal_of_a_destination_nobody_mails_any_more_is_forgotten(con):
    """Removed or switched off: the sweep mails it no more, so no mail can
    end its refusal, and the row would stay for ever."""
    ops, night = mailbox(con), mailbox(con, "night@example.com")
    alerts.note_mail_answer(con, ops, False, "SMTPAuthenticationError", NOW)
    alerts.note_mail_answer(con, night, False, "SMTPAuthenticationError", NOW)
    alerts.forget_mail_refusals_but(con, [night])
    assert list(alerts.mail_refusals(con, 1)) == [alerts.key_for_channel(night)]
    alerts.forget_mail_refusals_but(con, [])
    assert alerts.mail_refusals(con, 1) == {}


def test_the_sweep_forgets_a_refusal_of_a_destination_switched_off(monkeypatch, tmp_path):
    import test_sweep_cli as tsc
    from app import finding_alerts, intent, prober, sweep_cli
    path = str(tmp_path / "sweep.db")
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    con = db.connect(path)
    for module in (db, prober, intent, alerts, finding_alerts):
        module.init(con)
    con.close()
    monkeypatch.setattr(sweep_cli.notify, "send",
                        lambda subject, body, config=None, html="": (False, "SMTPAuthenticationError"))
    tsc.a_change_is_due(path)
    tsc.an_email_channel(path, "ops inbox", "ops@example.com")
    assert sweep_cli.main([]) == 0
    con = db.connect(path)
    assert len(alerts.mail_refusals(con, 1)) == 1
    channels.set_enabled(con, "ops inbox", False)
    con.close()
    assert sweep_cli.main([]) == 0
    con = db.connect(path)
    assert alerts.mail_refusals(con, 1) == {}
    con.close()


def test_one_workspace_never_reads_anothers_refusals(con):
    other = db.create_workspace(con, "another")
    theirs = mailbox(con, "night@example.com", workspace_id=other)
    alerts.note_mail_answer(con, theirs, False, "SMTPAuthenticationError", NOW)
    assert alerts.mail_refusals(con, db.DEFAULT_WORKSPACE_ID) == {}
    assert list(alerts.mail_refusals(con, other)) == [alerts.key_for_channel(theirs)]


def test_no_address_and_no_relay_words_are_kept(con):
    """The delivery key is a digest of the address, and the class is one of
    a closed list."""
    ops = mailbox(con)
    alerts.note_mail_answer(con, ops, False, "SMTPAuthenticationError", NOW)
    kept = con.execute("SELECT * FROM mail_refusals").fetchone()
    assert "ops@example.com" not in " ".join(str(value) for value in tuple(kept))
    columns = [row[1] for row in con.execute("PRAGMA table_info(mail_refusals)")]
    assert columns == ["workspace_id", "channel", "error", "refused_at"]


def test_a_database_from_before_the_table_has_no_refusals(tmp_path):
    import sqlite3
    bare = sqlite3.connect(str(tmp_path / "old.db"))
    assert alerts.mail_refusals(bare, 1) == {}


def test_the_refusals_read_on_a_bare_connection(tmp_path, con):
    """The page reads with its own connection, whose rows may be tuples."""
    import sqlite3
    ops = mailbox(con)
    alerts.note_mail_answer(con, ops, False, "SMTPDataError", NOW)
    path = con.execute("PRAGMA database_list").fetchone()[2]
    bare = sqlite3.connect(path)
    assert alerts.mail_refusals(bare, 1) == {alerts.key_for_channel(ops): NOW.isoformat()}


# ------------------------------------------------- every sending path

def test_the_sweeps_alert_mail_to_a_row_keeps_the_relays_refusal(monkeypatch, tmp_path):
    import test_sweep_cli as tsc
    from app import finding_alerts, intent, prober, sweep_cli
    path = str(tmp_path / "sweep.db")
    monkeypatch.setenv(db.DB_ENV, path)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example")
    con = db.connect(path)
    for module in (db, prober, intent, alerts, finding_alerts):
        module.init(con)
    con.close()
    answer = {"ok": False, "reason": "SMTPAuthenticationError"}
    monkeypatch.setattr(sweep_cli.notify, "send",
                        lambda subject, body, config=None, html="": (answer["ok"], answer["reason"]))
    tsc.a_change_is_due(path)
    ops = tsc.an_email_channel(path, "ops inbox", "ops@example.com")
    assert sweep_cli.main([]) == 0
    con = db.connect(path)
    assert list(alerts.mail_refusals(con, 1)) == [alerts.key_for_channel(ops)]
    con.close()
    answer.update(ok=True, reason="sent")
    assert sweep_cli.main([]) == 0
    con = db.connect(path)
    assert alerts.mail_refusals(con, 1) == {}
    con.close()


def test_a_cve_mail_to_a_row_keeps_the_relays_refusal(con):
    from test_cvesend import CONFIG, MAIL, batch
    from app import cvesend, cvetell, displayname, finding_alerts, intent
    for module in (intent, finding_alerts, displayname, cvetell, cvesend):
        module.init(con)
    ops = mailbox(con)
    batch(con, MAIL, when=NOW)

    def refuse(subject, body, config, html=""):
        return False, "SMTPRecipientsRefused"

    cvesend.deliver(con, NOW, config=CONFIG, mail_rows=[ops], send_mail=refuse)
    assert list(alerts.mail_refusals(con, 1)) == [alerts.key_for_channel(ops)]
    cvesend.deliver(con, NOW, config=CONFIG, mail_rows=[ops],
                    send_mail=lambda subject, body, config, html="": (True, "sent"))
    assert alerts.mail_refusals(con, 1) == {}


def test_a_reporting_again_mail_to_a_row_keeps_the_relays_refusal(con):
    import test_reportingagain as tra
    from app import displayname, finding_alerts, intent, reportingagain
    for module in (intent, finding_alerts, displayname):
        module.init(con)
    tra.SWEPT["to"] = 0
    ops = mailbox(con)
    host_id, _alert = tra.went_silent(con, told=[alerts.key_for_channel(ops)])
    tra.came_back(con, host_id)

    def refuse(subject, body, config, html=""):
        return False, "SMTPAuthenticationError"

    reportingagain.deliver(con, tra.at(80), config=tra.CONFIG, mail_rows=[ops], send_mail=refuse)
    assert list(alerts.mail_refusals(con, 1)) == [alerts.key_for_channel(ops)]
    reportingagain.deliver(con, tra.at(85), config=tra.CONFIG, mail_rows=[ops],
                           send_mail=lambda subject, body, config, html="": (True, "sent"))
    assert alerts.mail_refusals(con, 1) == {}
