"""Alert delivery.

    python -m pytest tests/test_notify.py

The tests that matter are the ones about not sending: this module must be
silent by default (docs/CONTEXT.md section 6), must never raise into the sweep,
and must never put a relay credential on a cleartext connection.
"""

import smtplib

import pytest

from app import notify


def test_nothing_is_sent_without_configuration():
    """Merging a branch must not start mailing anybody."""
    sent, reason = notify.send("s", "b", notify.Config())
    assert sent is False
    assert reason == "not configured"


def test_a_recipient_without_a_relay_is_not_configured():
    assert notify.Config(to="a@b.c").configured is False
    assert notify.Config(host="smtp.example").configured is False
    assert notify.Config(to="a@b.c", host="smtp.example").configured is True


def test_config_reads_the_environment():
    cfg = notify.config_from_env({
        "WHICHPORTS_ALERT_TO": " ops@example.org ",
        "WHICHPORTS_SMTP_HOST": "mail.smtp2go.com",
        "WHICHPORTS_SMTP_PORT": "2525",
        "WHICHPORTS_SMTP_USER": "u",
        "WHICHPORTS_SMTP_PASSWORD": "p",
    })
    assert cfg.to == "ops@example.org"
    assert cfg.port == 2525
    assert cfg.sender == "ops@example.org"   # defaults to the recipient
    assert cfg.configured is True


def test_a_bad_port_falls_back_instead_of_raising():
    """A typo in a unit file must not take the sweep down."""
    cfg = notify.config_from_env({"WHICHPORTS_ALERT_TO": "a@b.c",
                                  "WHICHPORTS_SMTP_HOST": "h",
                                  "WHICHPORTS_SMTP_PORT": "not-a-number"})
    assert cfg.port == 587


def test_a_dead_relay_is_reported_not_raised(monkeypatch):
    """The sweep found the problem. A broken mail path must not lose that."""
    def boom(*args, **kwargs):
        raise OSError("connection refused")
    monkeypatch.setattr(notify.smtplib, "SMTP", boom)
    sent, reason = notify.send("s", "b", notify.Config(to="a@b.c", host="h"))
    assert sent is False
    assert reason == "OSError"


def test_an_smtp_error_is_reported_not_raised(monkeypatch):
    def boom(*args, **kwargs):
        raise smtplib.SMTPServerDisconnected("gone")
    monkeypatch.setattr(notify.smtplib, "SMTP", boom)
    sent, reason = notify.send("s", "b", notify.Config(to="a@b.c", host="h"))
    assert sent is False
    assert reason == "SMTPServerDisconnected"


class FakeSMTP:
    """Records what a send did, without a network."""
    def __init__(self, host, port, timeout=None):
        self.host, self.port = host, port
        self.starttls_called = False
        self.logged_in = None
        self.sent = None
        self.extns = {"starttls"}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def ehlo(self):
        pass

    def has_extn(self, name):
        return name in self.extns

    def starttls(self, context=None):
        self.starttls_called = True

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, message):
        self.sent = message


def test_a_send_upgrades_to_tls_before_logging_in(monkeypatch):
    made = {}

    def factory(host, port, timeout=None):
        made["smtp"] = FakeSMTP(host, port, timeout)
        return made["smtp"]

    monkeypatch.setattr(notify.smtplib, "SMTP", factory)
    sent, reason = notify.send("subject", "body",
                               notify.Config(to="a@b.c", host="h", user="u", password="p"))
    assert sent is True and reason == "sent"
    assert made["smtp"].starttls_called is True
    assert made["smtp"].logged_in == ("u", "p")
    assert made["smtp"].sent["To"] == "a@b.c"
    assert made["smtp"].sent["Subject"] == "subject"


def test_a_credential_is_never_sent_over_a_cleartext_connection(monkeypatch):
    """A relay that cannot upgrade and a login that exists means give up, not
    log in anyway."""
    made = {}

    def factory(host, port, timeout=None):
        smtp = FakeSMTP(host, port, timeout)
        smtp.extns = set()          # no starttls offered
        made["smtp"] = smtp
        return smtp

    monkeypatch.setattr(notify.smtplib, "SMTP", factory)
    sent, reason = notify.send("s", "b",
                               notify.Config(to="a@b.c", host="h", user="u", password="p"))
    assert sent is False
    assert "starttls" in reason
    assert made["smtp"].logged_in is None


def test_the_email_states_what_was_measured_and_draws_no_conclusion():
    subject, body, html = notify.format_silence("almabox", "no report for 90 minutes",
                                                "2026-08-14T12:00:00+00:00")
    assert "almabox" in subject
    assert "stopped reporting" in subject
    assert "no report for: 90 minutes" in body
    # It must not conclude the host is down, because that was not measured and
    # this estate has already met the case where it was wrong (RECORD 4.36).
    # Both parts, because a designed half that says more than the text half
    # would be the restraint undone by a template.
    for forbidden in ("is down", "is offline", "unreachable", "secure", "safe"):
        assert forbidden not in body.lower(), f"the alert draws a conclusion: {forbidden}"
        assert forbidden not in html.lower(), f"the html draws a conclusion: {forbidden}"
    # And it promises the thing that stops it becoming noise.
    assert "Nothing else will be sent" in body
    assert "Nothing else will be sent" in html


def test_a_sent_alert_carries_the_text_part_first_and_the_designed_one_beside_it(monkeypatch):
    """multipart/alternative, plain text first. A client that prefers text, or
    cannot render html, shows the part that is the authority on what is said,
    and the order is what tells it which one that is. The designed half is
    added beside the text and never instead of it."""
    captured = {}

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def has_extn(self, name):
            return True

        def starttls(self, **k):
            pass

        def login(self, user, password):
            pass

        def send_message(self, message):
            captured["message"] = message

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    config = notify.Config(to="a@b.c", host="relay", sender="x@y.z")
    subject, body, html = notify.format_finding_changes(
        "box", [notify.Change("tcp/22", "", "conflict", "It answers from outside.")])
    assert notify.send(subject, body, config, html) == (True, "sent")

    message = captured["message"]
    assert message.get_content_type() == "multipart/alternative"
    parts = [part.get_content_type() for part in message.walk()]
    assert parts.index("text/plain") < parts.index("text/html")


def test_a_mail_with_no_designed_half_is_still_sent_as_plain_text(monkeypatch):
    """The html argument is optional, so a caller that has none sends exactly
    what it sent before rather than an empty second part."""
    captured = {}

    class FakeSMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            pass

        def has_extn(self, name):
            return True

        def starttls(self, **k):
            pass

        def login(self, user, password):
            pass

        def send_message(self, message):
            captured["message"] = message

    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    config = notify.Config(to="a@b.c", host="relay", sender="x@y.z")
    assert notify.send("s", "b", config) == (True, "sent")
    assert captured["message"].get_content_type() == "text/plain"


# ------------------------------------------------------------ account mails
#
# docs/screens/mails/SPEC.md, accepted 2026-09-07. Each carries one link that
# works once and expires, says how long, and nothing else.

LINK = "https://app.whichports.com/set-password/abc"


def account_mails():
    return {
        "account": notify.format_account("dad@example.net", LINK),
        "reset": notify.format_reset("sysadmin@example.net", LINK),
        "confirm": notify.format_confirm("sysadmin@example.net", LINK),
        "invite": notify.format_invite("Robin", "sysadmin@example.net", "whichports", "Admin", LINK),
    }


@pytest.mark.parametrize("kind", ["account", "reset", "confirm", "invite"])
def test_every_account_mail_carries_its_link_in_both_halves_and_says_how_long(kind):
    subject, body, html = account_mails()[kind]
    assert subject.startswith("[whichports] ")
    assert LINK in body and LINK in html
    assert "The link works once and for" in body
    assert "The link works once and for" in html
    # the dashboard link is an alert's, not an account mail's
    assert "https://app.whichports.com/\n" not in body


def test_the_account_mails_say_what_the_sketch_says():
    mails = account_mails()
    assert mails["account"][0] == "[whichports] Your whichports account"
    assert "An account was made for you at app.whichports.com." in mails["account"][1]
    assert "  email:  dad@example.net" in mails["account"][1]
    assert "for 24 hours" in mails["account"][1]
    assert mails["reset"][0] == "[whichports] Reset your password"
    assert "A reset was asked for sysadmin@example.net." in mails["reset"][1]
    assert "If you did not ask for this, nothing changes." in mails["reset"][1]
    assert "for 30 minutes" in mails["reset"][1]
    assert mails["confirm"][0] == "[whichports] Confirm your email"
    assert "One click finishes your account at app.whichports.com." in mails["confirm"][1]
    assert mails["invite"][0] == "[whichports] Robin invited you to whichports"
    assert "Robin invited you to the workspace whichports at app.whichports.com, as Admin." in mails["invite"][1]
    assert "for 7 days" in mails["invite"][1]


@pytest.mark.parametrize("kind", ["account", "reset", "confirm", "invite"])
def test_an_account_mail_keeps_to_the_writing_rules_and_holds_no_secret(kind):
    subject, body, html = account_mails()[kind]
    for text in (subject, body, html):
        low = text.lower()
        for banned in ("secure", "protected", "safe", "compliant", "guaranteed", "certified",
                       "\u2014", "\u2013", ";"):
            if banned == ";" and text is html:
                continue  # CSS needs them, prose does not
            assert banned not in low, f"{kind} says {banned!r}"
        assert "password:" not in low or "set your password:" in low or "choose" in low
    assert "code" not in body.lower()


def test_the_how_long_words_are_named_once():
    assert notify.ACCOUNT_LINK_LASTS == "24 hours"
    assert notify.RESET_LINK_LASTS == "30 minutes"
    assert notify.CONFIRM_LINK_LASTS == "24 hours"
    assert notify.INVITE_LINK_LASTS == "7 days"
    assert "for 24 hours" in notify.format_account("a@b.c", LINK)[1]


def test_an_invitation_with_no_role_claims_none():
    """Roles are enforced nowhere in the code, so an invitation this product
    can issue today carries none. "as Admin" over a permission level that does
    not exist is the claim the accuracy rule forbids."""
    subject, body, html = notify.format_invite(
        "Robin", "sysadmin@example.net", "whichports", "", LINK)
    assert "as" not in body.split(LINK)[0].split("workspace whichports")[1]
    assert ">role<" not in html and "Admin" not in html
    # and the role is still said when there is one
    _s, with_role, with_html = notify.format_invite(
        "Robin", "sysadmin@example.net", "whichports", "Admin", LINK)
    assert "as Admin" in with_role
    assert "Admin" in with_html
