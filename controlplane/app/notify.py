"""Alert delivery. Stdlib smtplib only, and off unless configured.

The notification module of an earlier project of the author's was the
reviewed starting point and two of its properties are carried over
deliberately. Delivery is best effort,
so a dead mail relay logs and returns rather than raising, because one broken
notification path must never wedge the sweep that found the problem. And the
text is factual: what was measured and when, never a verdict.

**It sends nothing until the owner turns it on.** `docs/CONTEXT.md` section 6 says
nothing in this repository sends email, and that if a tool here ever wants to
talk SMTP it is his decision first. That rule is about outreach and this is a
product alert, which `docs/PRODUCT.md` section 7 has in v1 scope, but the
spirit of it is worth keeping: with no configuration present this module
reports "not configured" and the sweep records the alert without mailing
anyone. Nothing starts sending because a branch was merged.

Configuration is environment only, never the database and never the
repository, because it carries a relay credential:

    WHICHPORTS_ALERT_TO      the recipient. Absent means send nothing.
    WHICHPORTS_SMTP_HOST     relay host. SMTP2GO survives from that
                             project (docs/RECORD.md 4.10).
    WHICHPORTS_SMTP_PORT     defaults to 587, STARTTLS
    WHICHPORTS_SMTP_USER     optional, relay login
    WHICHPORTS_SMTP_PASSWORD optional, relay password
    WHICHPORTS_ALERT_FROM    defaults to the recipient
"""

import logging
import os
import re
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

from . import alertwords, mailhtml, publicurl

log = logging.getLogger("whichports.notify")

# Long enough for a slow relay, short enough that the sweep timer cannot be
# held open by one. The sweep runs every five minutes.
SMTP_TIMEOUT_SECONDS = 20

# The classes of failure `send` hands back that mean the relay answered and
# refused: every smtplib class that carries the relay's reply code, and the
# one for refused recipients, which carries a code for each (Python's
# smtplib, read from 3.12's own classes on 2026-10-25). A relay out of reach,
# a broken connection or no relay at all is not a refusal and is not here.
# The Fleet's banner says a relay refused mail, so it is drawn from these
# alone (`alerts.note_mail_answer`, the second big test's finding E22).
RELAY_REFUSALS = frozenset({
    "SMTPAuthenticationError", "SMTPConnectError", "SMTPDataError", "SMTPHeloError",
    "SMTPResponseException", "SMTPSenderRefused", "SMTPRecipientsRefused"})


def refused_by_the_relay(reason: str) -> bool:
    """Whether the reason `send` gave is the relay refusing the mail."""
    return reason in RELAY_REFUSALS


@dataclass(frozen=True)
class Config:
    to: str = ""
    host: str = ""
    port: int = 587
    user: str = ""
    password: str = ""
    sender: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.to and self.host)

    def __repr__(self) -> str:
        """`password=set`, never the password.

        A dataclass prints every field, so the default one rendered the relay
        credential in full anywhere a Config reached a log or a traceback.
        Nothing formatted one, which is why it was never noticed, and
        `app/webhook.py` arriving beside it with a URL that is frequently a
        secret is what made it worth fixing rather than noting.
        `app/hetzner.py` has done this for its token since it was written.
        """
        return (f"Config(to={self.to!r}, host={self.host!r}, port={self.port},"
                f" user={self.user!r},"
                f" password={'set' if self.password else 'unset'},"
                f" sender={self.sender!r})")


def config_from_env(env=None) -> Config:
    env = os.environ if env is None else env
    to = (env.get("WHICHPORTS_ALERT_TO") or "").strip()
    try:
        port = int(env.get("WHICHPORTS_SMTP_PORT") or 587)
    except ValueError:
        # A typo in a unit file must not take the sweep down. Fall back to the
        # default and say so, rather than raising inside a timer nobody watches.
        log.warning("WHICHPORTS_SMTP_PORT is not a number, using 587")
        port = 587
    return Config(
        to=to,
        host=(env.get("WHICHPORTS_SMTP_HOST") or "").strip(),
        port=port,
        user=(env.get("WHICHPORTS_SMTP_USER") or "").strip(),
        password=env.get("WHICHPORTS_SMTP_PASSWORD") or "",
        sender=(env.get("WHICHPORTS_ALERT_FROM") or "").strip() or to,
    )


@dataclass(frozen=True)
class Change:
    """One finding that changed, ready to be written into a mail.

    Scalars rather than a database row, the same shape `format_silence` takes
    its arguments in, so this module never learns a column name. `was` is the
    empty string when there was no previous state, and `vantage` and
    `measured_at` are empty when the stored run did not record them, which a
    run written before `docs/RECORD.md` 4.54 did not.
    """
    where: str
    was: str
    now: str
    description: str
    vantage: str = ""
    measured_at: str = ""
    # A port that became reachable and that a rule or a yes already answers
    # (`docs/PRODUCT.md` 4c, 2026-09-27). Its lines are facts rather than
    # `description`: what answers, and what answered for it.
    became_reachable: bool = False
    program: str = ""
    rule: str = ""
    # A different program answering a port that already has an answer
    # (`docs/PRODUCT.md` 4c, 2026-09-27): what answered before. Empty on
    # every other change, which is how the two notices are told apart.
    was_program: str = ""
    # What a message says about this change, each value frozen with it and
    # none worked out when it is sent (docs/screens/mails/SPEC-alert-messages.md,
    # rule 3.4). A change stored before these existed reads as the defaults,
    # which say nothing.
    port: int = 0
    protocol: str = "tcp"
    family: str = ""
    # Whether the outside view connected when the change was seen.
    answers: bool = False
    # What the port's other address family did then: one of
    # `alertwords.OTHER_FAMILY`, or empty when it has no finding.
    other_family: str = ""
    # The layer whose rule lets the port answer, `join.LAYER_PROVIDER` or
    # `join.LAYER_HOST_FIREWALL`, or empty when the engine named none.
    allowed_by: str = ""
    # `join.Finding.answered_outside_the_rules_source` (docs/RECORD.md 4.377).
    outside_source: bool = False
    # The program in the words a message may carry, or empty when a name
    # behind the port is not plain (`alertwords.program_words`). `program`
    # above stays whole for the server's page.
    program_said: str = ""
    was_program_said: str = ""



# ------------------------------------------------------------- alert mails
#
# Every alert is one description (app/alertwords.py), and the mail is two
# drawings of it: the text half here and the designed half in
# app/mailhtml.py. The chat channels draw the same description
# (app/senders.py), so no channel says a thing another does not.
#
# The spec is docs/screens/mails/SPEC-alert-messages.md. A mail says what
# was measured in a title, labelled values under it, the line that nothing
# else will be sent, and one link. No time and no state word: both are on
# the server's page, which the link opens.

_SILENT_MINUTES = re.compile(r"^no report for (\d+) minutes")
_STALE_HOURS = re.compile(r" in (\d+) hours")


def silent_minutes(detail: str):
    """How long an agent has been quiet, read back out of the sentence the
    silence alert stores (`alerts.silent_detail`), or None when the sentence
    is not that one. The alert's row holds the sentence and no number."""
    found = _SILENT_MINUTES.match(detail or "")
    return int(found.group(1)) if found else None


def stale_hours(detail: str):
    """How long no check from outside has finished, read back out of the
    sentence the stale alert stores (`finding_alerts._stale_detail`), or
    None. With two vantages the sentence names two lengths, and the shorter
    is the one that is true of the server: a check finished that recently
    from nowhere."""
    found = [int(hours) for hours in _STALE_HOURS.findall(detail or "")]
    return min(found) if found else None


def said_silence(host_name: str, detail: str, display: str = ""):
    return alertwords.said_silence(host_name, silent_minutes(detail), display)


def said_outside_stale(host_name: str, detail: str, display: str = ""):
    return alertwords.said_outside_stale(host_name, stale_hours(detail), display)


def said_changes(host_name: str, changes, display: str = ""):
    return alertwords.said_changes(host_name, changes, display)


def said_test():
    return alertwords.said_test()


def text_of(said) -> str:
    """The text half: the title, each field as `label: value`, the closing
    line and the link, a blank line between the parts."""
    parts = [said.title]
    if said.sentence:
        parts.append(said.sentence)
    if said.fields:
        parts.append("\n".join(f"  {label}: {value}" for label, value in said.fields))
    if said.closing:
        parts.append(said.closing)
    parts.append(f"  {said.link}")
    return "\n\n".join(parts) + "\n"


def mail(said) -> tuple[str, str, str]:
    """One alert as a mail: the subject, the text half and the designed
    half, all three from the one description."""
    return f"[whichports] {said.title}", text_of(said), mailhtml.alert(said)


def format_test() -> tuple[str, str, str]:
    """The mail behind Send test. It says it is a test in the subject,
    because whoever receives it may not be whoever pressed the button, and a
    mail that read like an alert would send somebody to check a server that
    is fine."""
    return mail(said_test())


def format_silence(host_name: str, detail: str, raised_at: str,
                   display: str = "") -> tuple[str, str, str]:
    """An agent that stopped reporting.

    It says the agent stopped reporting, which is the measurement. It does
    not say the host is down, because that was not measured: the host can be
    fine and the path between it and here broken, which has already happened
    on this estate (docs/RECORD.md 4.36). The mail does not explain that
    restraint either. The absence is the statement.

    `raised_at` is taken and not said. No message carries a time.
    """
    return mail(said_silence(host_name, detail, display))


def format_outside_stale(host_name: str, detail: str, raised_at: str,
                         display: str = "") -> tuple[str, str, str]:
    """An outside view that stopped being refreshed.

    It says what stopped, not what is now true. Probing stopping tells you
    nothing about whether the ports moved, and saying they might have would
    be inventing a finding out of an absence (docs/PRODUCT.md 4b).
    """
    return mail(said_outside_stale(host_name, detail, display))


def format_finding_changes(host_name: str, changes,
                           display: str = "") -> tuple[str, str, str]:
    """One mail for every finding on one server that changed.

    One mail rather than one per port is docs/PRODUCT.md 4c's coalescing
    rule, and it is the difference between this being useful and being
    filtered into a folder: recreating a stack moves eight ports at once.
    """
    return mail(said_changes(host_name, changes, display))


# ------------------------------------------------------------ account mails
#
# The four mails the beta needs around an account (docs/screens/mails/SPEC.md,
# accepted 2026-09-07). Each carries one link that works once and expires,
# and how long it lasts is said in the mail, so the page that issues the
# link passes the words in beside it. The host the links point at is this
# control plane's own (app/publicurl.py), the way the dashboard link is.
#
# **What each of these does not say.** No password, no code, no name of a
# device, and nothing about what happens if the link is used by somebody
# else: the link is the whole of the claim, and a sentence about its safety
# is the posture the writing rules keeps off every surface.

ACCOUNT_LINK_LASTS = "24 hours"
RESET_LINK_LASTS = "30 minutes"
CONFIRM_LINK_LASTS = "24 hours"
INVITE_LINK_LASTS = "7 days"
SIGNUP_CODE_LASTS = "24 hours"


def format_account(email: str, link: str,
                   how_long: str = ACCOUNT_LINK_LASTS) -> tuple[str, str, str]:
    """An account made by hand on the box, for the alpha testers: one link to
    choose a password."""
    subject = "[whichports] Your whichports account"
    body = (
        f"An account was made for you at {publicurl.host()}.\n"
        f"\n"
        f"  email:  {email}\n"
        f"\n"
        f"Set your password:\n"
        f"\n"
        f"  {link}\n"
        f"\n"
        f"The link works once and for {how_long}.\n"
    )
    return subject, body, mailhtml.account(email, link, publicurl.host(), how_long)


def format_reset(email: str, link: str,
                 how_long: str = RESET_LINK_LASTS) -> tuple[str, str, str]:
    """Forgot your password, on the sign-in page. Sent to the address as
    typed, so somebody who did not ask is told that nothing changes."""
    subject = "[whichports] Reset your password"
    body = (
        f"A reset was asked for {email}.\n"
        f"\n"
        f"Choose a new password:\n"
        f"\n"
        f"  {link}\n"
        f"\n"
        f"If you did not ask for this, nothing changes. The link works once and for {how_long}.\n"
    )
    return subject, body, mailhtml.reset(email, link, how_long)


def format_confirm(email: str, link: str,
                   how_long: str = CONFIRM_LINK_LASTS) -> tuple[str, str, str]:
    """Sign-up, at the beta: the one click that finishes the account."""
    subject = "[whichports] Confirm your email"
    body = (
        f"One click finishes your account at {publicurl.host()}.\n"
        f"\n"
        f"  email:  {email}\n"
        f"\n"
        f"Confirm:\n"
        f"\n"
        f"  {link}\n"
        f"\n"
        f"The link works once and for {how_long}.\n"
    )
    return subject, body, mailhtml.confirm(email, link, how_long)


def format_invite(inviter: str, inviter_email: str, workspace: str,
                  role: str = "", link: str = "",
                  how_long: str = INVITE_LINK_LASTS) -> tuple[str, str, str]:
    """Members, when it is built: a place in a workspace, and the role when
    there is one.

    **An empty role is said as nothing at all.** Roles are enforced nowhere in
    the code yet, so the invitations this product can issue today carry none,
    and "as Admin" over a permission level that does not exist is the claim
    the accuracy rule forbids. The argument stays for when Members lands.
    """
    subject = f"[whichports] {inviter} invited you to {workspace}"
    as_role = f", as {role}" if role else ""
    body = (
        f"{inviter} invited you to the workspace {workspace} at {publicurl.host()}{as_role}.\n"
        f"\n"
        f"Join:\n"
        f"\n"
        f"  {link}\n"
        f"\n"
        f"The link works once and for {how_long}.\n"
    )
    return subject, body, mailhtml.invite(inviter, inviter_email, workspace, role, link, how_long)


def format_signup_code(code: str, how_long: str = SIGNUP_CODE_LASTS) -> tuple[str, str, str]:
    """The open signup's one mail to the person (app/instancesignup.py): the
    eight digits the installer asks for, in one line. No link and no button,
    so nothing in it can be clicked, forwarded into a collect or opened by
    a scanner, and no key and no name of anything."""
    subject = "[whichports] Your code"
    body = f"Your code is {code}. It works for {how_long}.\n"
    return subject, body, mailhtml.signup_code(code, how_long)


def format_signup_ended(link: str, days: int) -> tuple[str, str, str]:
    """To the address of a signup instance the sweep ended for sending no
    batch and making no proof (app/instancesignup.py). What happened in one
    line, and one button to the install, which signs up again. No key and no
    name of anything."""
    subject = "[whichports] Your instance ended"
    body = (f"Your instance sent no batch and made no proof for {days} days, so it ended.\n"
            f"Running the install again gives you a new one:\n"
            f"\n"
            f"  {link}\n")
    return subject, body, mailhtml.signup_ended(link, days)


def format_signup_made(live: int) -> tuple[str, str]:
    """To the owner: an instance signed up. How many are live, and nothing
    of whose it is."""
    subject = "[whichports] An instance signed up"
    body = ("An instance signed up.\n"
            "\n"
            f"  live signup instances:  {live}\n")
    return subject, body


def format_signup_full(signups: int, made: int, live: int,
                       today_only: bool = True) -> tuple[str, str]:
    """To the owner, once a day at most: signup answers full.

    `today_only` is False when the cap spent is the one on live signup
    instances. That one clears when an instance is revoked, not at midnight,
    so the mail must not say tomorrow."""
    if today_only:
        subject = "[whichports] Signup is full today"
        said = "Signup answers full until tomorrow.\n"
    else:
        subject = "[whichports] Signup is full"
        said = "Signup answers full until a signup instance is revoked.\n"
    body = (said +
            "\n"
            f"  signups today:           {signups}\n"
            f"  instances made today:    {made}\n"
            f"  live signup instances:   {live}\n")
    return subject, body


def send(subject: str, body: str, config: Config | None = None,
         html: str = "") -> tuple[bool, str]:
    """Returns (sent, reason). Never raises: the caller is a timer, and a
    relay that is refusing connections must not stop the sweep from recording
    what it found.

    `html` is the designed alternative from `mailhtml`. The text part stays
    the authority on what is said and is what a client shows when it prefers
    plain text or cannot render the other, so it is set first and the HTML is
    added beside it rather than instead of it. A mail with no html argument is
    text only, exactly as before.
    """
    config = config or config_from_env()
    if not config.configured:
        return False, "not configured"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = config.sender
    message["To"] = config.to
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP(config.host, config.port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
            smtp.ehlo()
            # STARTTLS where the relay offers it. The credential is not sent
            # over a cleartext connection: if the relay cannot upgrade and a
            # login exists, this gives up rather than leaking it.
            if smtp.has_extn("starttls"):
                smtp.starttls(context=ssl.create_default_context())
                smtp.ehlo()
            elif config.user:
                return False, "relay offers no starttls and a credential is configured"
            if config.user:
                smtp.login(config.user, config.password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        # The class of failure, not the raw text, for the same reason the
        # agent ships typed error causes (SI-8).
        reason = type(exc).__name__
        log.warning("alert delivery failed: %s", reason)
        return False, reason
    return True, "sent"
