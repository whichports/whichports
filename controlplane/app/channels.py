"""Where alerts go, as rows, without any row holding a secret.

`app/notify.py` sends mail and `app/webhook.py` posts. This is the piece that
says which channels exist, what they are called, and whether they are on.

## The split this rests on, which comes from an earlier project

The notification module of an earlier project of the author's states it in
one line: **where alerts go is operator configuration, how they are sent is
infrastructure configuration.** That works for mail because a recipient is
not a secret, and that project never carried it across to webhooks. Its
`notification_channels.destination` is a
plain string column holding the webhook URL, which is the credential, rendered
in full on its own settings page.

whichports had the two fused instead: one environment variable was both the
destination and the secret, so nothing could be told a webhook exists without
being told its URL. That is why the dashboard could not list it
(`docs/RECORD.md` 4.86).

**So a row names the environment variable rather than holding its value.** The
row carries the type, a label, whether it is enabled, and the name. The sweep
reads the value at send time from its own environment. The renderer reads the
row, shows the channel, and holds no credential, which is the whole point: the
render unit and the sweep unit are different units with different environments
and only one of them should ever see a relay password.

## Why the name is restricted

The database is reachable by more things than the environment is, and a row
that could name any variable is a row that could point the sender at one we
never meant it to read. So a name has to look like ours and nothing else.
That is a narrowing and never a permission: naming a variable does not make its
contents a valid destination, and `app/webhook.py` still checks what it got.

## The reversal of 2026-08-22, and why

Everything above describes a schema with **no column a destination could go in**.
The owner reversed that the same day: store the destination the way every other
product does.

He is right, and the reason the old shape existed is worth keeping rather than
defending. The real problem it solved was that the render unit and the sweep
unit are different units and the renderer must not hold credentials. **The
ordinary answer to that is that the renderer does not read the column.**
Removing the column entirely
was an extreme answer to it, and it made Slack OAuth impossible, because the
whole point of OAuth is that the operator never handles the URL and there was
nowhere for us to put it.

So a row may now hold its destination, and `destination_env` stays supported
beside it. A row has exactly one of the two:

  - **`destination` set**: the value lives here. The ordinary case, and the one
    an OAuth callback writes.
  - **`destination_env` set**: the value lives in the sweep's environment under
    that name. Every row written before today is this, and the production box is
    configured this way, so nothing on it changes.

What replaces the schema guarantee is a property that is asserted rather than
structural, and it is the one that actually matters: **nothing that renders a
page ever reads the destination.** `Channel.for_display()` is what the renderer
gets, it has no destination on it at all, and a test fails if a destination
reaches the rendered HTML.

**No refusal in this module or in the sender ever echoes what it was given**,
for the same reason, and that is a rule about every field rather than about the
value the variable holds. A refusal is reachable from an operator who has just
pasted a URL into the wrong box, and it is printed to a terminal, written to
the journal and, since the admin endpoint exists, returned in an HTTP response
body. So a bad value is refused by its shape and the shape is what gets
printed.
"""

import ipaddress
import os
import re
import urllib.parse
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from . import outbound

TYPE_EMAIL = "email"
TYPE_WEBHOOK = "webhook"
TYPE_SLACK = "slack"
TYPE_TELEGRAM = "telegram"
TYPE_DISCORD = "discord"
TYPES = (TYPE_EMAIL, TYPE_WEBHOOK, TYPE_SLACK, TYPE_TELEGRAM, TYPE_DISCORD)

# Everything that is not mail. Mail is configured by environment alone and has
# no row (`docs/RECORD.md` 4.87), so these are the types a row can carry into
# the sweep's delivery loop.
SENDING_TYPES = (TYPE_WEBHOOK, TYPE_SLACK, TYPE_TELEGRAM, TYPE_DISCORD)

# Mail is not in SENDING_TYPES and that is not an oversight: those are the types
# `app/senders.py` posts to a URL, and mail goes over SMTP through
# `app/notify.py` instead. It has its own loop in the sweep for the same reason.
#
# **It stopped being environment-only on 2026-08-23**, when the owner asked why
# email could not be set up on the screen. An email channel
# is a row holding a recipient, which is not a credential, so it sits in the same
# `destination` column every other channel uses. The relay password stays in the
# environment, which is the split this module has always described.

# Ours and nothing else. Anchored at both ends, so `PATH` and
# `SOMETHING_WHICHPORTS_X` are both refused.
ENV_NAME_RE = re.compile(r"^WHICHPORTS_[A-Z0-9_]+$")

# A label is shown on a screen and typed by an operator, so it is bounded at
# the door rather than escaped in three places later. The same posture
# `app/store.py` takes for a host name.
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$")

# ------------------------------------------- what a refusal is about
#
# Every refusal carries two fixed words beside its sentence: the field of the
# request it is about, and why that field was refused. The sentence is for a
# person at a terminal. The two words are for a screen, which says its own few
# words at the field they name and prints no sentence of ours. A round of the
# test fleet found why: a bot token and a chat id typed into each other's
# field were refused by a sentence that named neither field
# (docs/RECORD.md 4.228).
#
# **A class is never built from what a request sent.** Each is one of the
# words below, so a class cannot carry a value back, the rule every refusal
# in this module follows.
#
# A field is called what the request calls it (`app/ingest.py`,
# CHANNEL_FIELDS, and `events`).
FIELD_TYPE = "type"
FIELD_LABEL = "label"
FIELD_ENV = "env"
FIELD_DESTINATION = "destination"
FIELD_CHAT_ID = "chat_id"
FIELD_EVENTS = "events"
FIELDS = (FIELD_TYPE, FIELD_LABEL, FIELD_ENV, FIELD_DESTINATION,
          FIELD_CHAT_ID, FIELD_EVENTS)

REASON_MISSING = "missing"        # nothing was given where something is needed
REASON_SHAPE = "shape"            # it does not look like what this field holds
REASON_UNKNOWN = "unknown"        # not one of the words this field takes
REASON_TAKEN = "taken"            # another channel of the workspace holds it
REASON_NOT_TAKEN = "not_taken"    # this type, or this request, takes none here
REASON_PRIVATE = "private"        # an address inside a private network
REASON_UNSENDABLE = "unsendable"  # an address no alert can be sent to
REASONS = (REASON_MISSING, REASON_SHAPE, REASON_UNKNOWN, REASON_TAKEN,
           REASON_NOT_TAKEN, REASON_PRIVATE, REASON_UNSENDABLE)


# Telegram's destination: a chat, and optionally one topic inside it.
#
# **Two claims in the first version of this comment were wrong and are
# corrected here**, both found by reading the Bot API rather than remembering
# it (core.telegram.org, read 2026-08-22, Bot API 10.2).
#
# 1. It said Telegram "gives no length for either form". False for the number.
#    The `Chat` object's own `id` field says: "it has at most 52 significant
#    bits, so a signed 64-bit integer or double-precision float type are safe
#    for storing this identifier" (#chat). 2**52 is sixteen digits, so the old
#    bound of thirty two digits was twice as permissive as Telegram's own
#    documented range. It is Telegram's bound now, not ours.
# 2. It said a chat id is "negative for a group". **Telegram documents that
#    nowhere.** The whole API page contains no `-100` prefix and never says a
#    group id is negative. It is true in practice and it is folklore, so the
#    minus is accepted and no longer explained as though Telegram said it.
#
# What `sendMessage` does document about where a message lands:
#
#   chat_id            "Integer or String", "Unique identifier for the target
#                      chat or username of the target bot, supergroup or
#                      channel in the format @username"
#   message_thread_id  "Integer", "Optional", "Unique identifier for the target
#                      message thread (topic) of a forum; for forum supergroups
#                      and private chats of bots with forum topic mode enabled
#                      only"
#
# **One topic is one destination**, which is why the thread id is stored here
# beside the chat rather than as decoration: `alerts.key_for_channel` is built
# from this field, so two topics in one chat are two delivery keys and each is
# posted to once. Written `chat:thread`, colon separated, because a chat id can
# start with a minus and a colon cannot be confused with one.
#
# The `@name` bound is still ours. Telegram documents no length for a channel
# username. BotFather's guide says usernames are "5-32 characters long", but
# that paragraph is about creating a bot, so applying it to a channel would be
# extrapolation rather than a quote.
#
# The thread bound is ours too. Telegram documents no range for it at all.
TELEGRAM_CHAT_MAX_DIGITS = 16          # 2**52, from the Chat.id field
TELEGRAM_CHAT_RE = re.compile(
    r"^(-?[0-9]{1,16}|@[A-Za-z0-9_]{1,64})(:[0-9]{1,10})?$")


# What a destination looks like, per type. **Mail and Telegram are the two
# that are not URLs.** Mail's destination is not a credential: a recipient is
# operator configuration, which is the line this module's docstring opens
# with and `docs/RECORD.md` 4.87 quotes. The relay password stays in the
# environment
# where it always was, because that is infrastructure and is shared by every
# recipient.
#
# Deliberately loose, one @ with something either side and no space. **A stricter
# pattern rejects real addresses**, RFC 5322 allows more than anyone expects, and
# the cost of being wrong here is refusing a person's own mailbox. The relay is
# what actually decides, and a bad address comes back as a refusal an operator
# can read.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Telegram's destination is the bot token, and the token is the credential.
# Telegram shows the shape without defining a grammar: "The token looks
# something like 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
# (core.telegram.org/bots/api, Authorizing your bot, read 2026-08-23, Bot API
# 10.2). So this pattern is ours and is deliberately loose for the same reason
# EMAIL_RE is: digits, one colon, then the characters the example shows, and
# the cost of being stricter is refusing a real token. The length cap is ours
# too. A URL cannot match this, which is the mistake worth catching: the thing
# pasted here by accident is a webhook URL.
TELEGRAM_TOKEN_RE = re.compile(r"^[0-9]+:[A-Za-z0-9_-]+$")
TELEGRAM_TOKEN_MAX = 256


def destination_refusal(channel_type: str,
                        destination: str) -> tuple[str, str]:
    """("", "") when this destination fits this type. Otherwise why it does
    not, as one of REASONS, and a sentence saying so.

    **The value is never repeated back**, for the reason the whole module
    follows: the thing people paste into the wrong box is the secret one.
    """
    if channel_type == TYPE_EMAIL:
        if not EMAIL_RE.match(destination):
            return REASON_SHAPE, (
                "an email channel goes to an address, something like"
                " ops@example.com. It is not repeated back here")
        return "", ""
    if channel_type == TYPE_TELEGRAM:
        # `app/senders.py` builds api.telegram.org/bot<token>/sendMessage from
        # this value, so a URL stored here would produce a request no endpoint
        # answers. Refused by shape, and the shape is what is printed.
        if (len(destination) > TELEGRAM_TOKEN_MAX
                or not TELEGRAM_TOKEN_RE.match(destination)):
            return REASON_SHAPE, (
                "a telegram destination is the bot token, digits and a"
                " colon and then the rest of the token, never a URL. It is"
                " not repeated back here")
        return "", ""
    if not destination.startswith(("https://", "http://")):
        return REASON_SHAPE, (
            "a destination is an http or https URL. It is not repeated"
            " back here, because the thing people paste into the wrong"
            " box is the secret one")
    return _address_refusal(destination)


def check_destination(channel_type: str, destination: str) -> str:
    """"" when this destination fits this type, or a sentence saying why not.
    The sentence half of `destination_refusal`, for a caller that has no use
    for the class."""
    return destination_refusal(channel_type, destination)[1]


def _address_refusal(destination: str) -> tuple[str, str]:
    """A destination written as an address that an alert cannot be sent to
    is refused here, at the door, because that needs no lookup and is
    certain. A destination written as a name is not resolved here: a name's
    answer can change, so the lock is at sending (`app/webhook.py`) and Send
    test is where it shows.

    The reason is read from the one function the sentence is read from
    (`outbound.refusal`), so the two say the same thing."""
    try:
        host = urllib.parse.urlsplit(destination).hostname or ""
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "", ""
    if outbound.guard()(ip):
        return "", ""
    reason = (REASON_PRIVATE if outbound.in_a_private_network(ip)
              else REASON_UNSENDABLE)
    return reason, "this destination is an address " + outbound.refusal(ip)


def split_telegram_target(destination_extra: str) -> tuple[str, str]:
    """`chat:thread` as (chat_id, message_thread_id), thread empty when absent.

    Split from the right on the first colon, because an `@name` cannot contain
    one and a numeric id cannot either, so the only colon in a valid value is
    the separator.
    """
    chat, _, thread = (destination_extra or "").partition(":")
    return chat, thread


@dataclass(frozen=True)
class ExtraRule:
    """The non-secret half of a destination, for the one type that has one.

    `field` is what an operator is asked for, `pattern` is what it has to look
    like, and `says` is the sentence a refusal prints. A refusal never echoes
    the value, the same rule the environment variable name follows above.
    """
    field: str
    pattern: object
    says: str


# One entry per type in TYPES, and a test asserts that, because a type added
# without a rule here would silently accept anything in the extra field.
#
# **Only Telegram has one, and the reason is worth keeping.** Every other
# channel here is one URL, and a URL is a secret often enough that it belongs
# in the environment and nowhere else. Telegram splits in two: the bot token is
# the credential and goes in the variable, and the chat id names which chat and
# is not documented as a secret anywhere in the Bot API. Two chats behind one
# token are two destinations, which is why the chat id is part of the delivery
# key in `app/alerts.py` and not only a field on the row.
TYPE_RULES = {
    TYPE_EMAIL: None,
    TYPE_WEBHOOK: None,
    TYPE_SLACK: None,
    TYPE_DISCORD: None,
    TYPE_TELEGRAM: ExtraRule(
        field="chat id",
        pattern=TELEGRAM_CHAT_RE,
        # "chat id" and not "chat", because that is the words on the field the
        # operator just typed into, and a refusal that renames the field is a
        # refusal they have to translate.
        says="a Telegram chat id is a number or an @name, and may carry a topic"
             " after a colon, as in -1001234567890:42. It is not the bot"
             " token, which is the credential and belongs in the environment"
             " variable this channel names"),
}

# ---------------------------------------------------------- which alerts
#
# The three kinds the sweep can actually raise today, each with the words a
# person reads on a screen. **This list is the authority for the UI and it is
# not the authority for the engine**: the strings have to equal the constants
# in `app/alerts.py` and `app/finding_alerts.py`, and a test asserts that by
# reading them rather than by trusting this comment. A fourth kind added there
# and not here would silently be a kind nobody can subscribe to.
#
# Why a channel chooses at all (the owner, 2026-08-22): a chat channel a team
# watches all day and a mailbox one person reads at night do not want the same
# traffic, and `docs/PRODUCT.md` 4c is about a tool staying usable rather than
# being filtered into a folder.
KIND_SILENT = "silent"
KIND_FINDING = "finding changed"
KIND_OUTSIDE_STALE = "outside view stale"
# The CVE check's message, one for a workspace (`app/cvetell.py`).
KIND_CVE = "cve"

# The order here is the order the screen draws them, worst first.
KINDS = (
    (KIND_FINDING, "A port's finding changed",
     "a port started or stopped answering from outside, or now"
     " disagrees with what you marked"),
    (KIND_SILENT, "An agent stopped reporting",
     "the dead-man switch, exactly one alert however long it stays quiet"),
    (KIND_OUTSIDE_STALE, "The outside view went stale",
     "probing stopped, so what the screen says about reachability is old"),
    (KIND_CVE, "A newer version fixes a CVE",
     "for a package behind a listening port, each CVE told once"),
)

KIND_NAMES = tuple(kind for kind, _, _ in KINDS)


SCHEMA = """
CREATE TABLE IF NOT EXISTS notification_channels (
    id              INTEGER PRIMARY KEY,
    type            TEXT NOT NULL,
    label           TEXT NOT NULL,
    -- The NAME of an environment variable holding the destination, for a row
    -- configured that way. Empty when `destination` carries the value instead.
    destination_env TEXT NOT NULL,
    -- The destination itself, for a row configured the ordinary way.
    --
    -- **This column holds credentials.** A Slack or Discord webhook URL is one,
    -- and Slack says so in as many words and revokes leaked ones. Two things
    -- follow, both enforced outside this schema: nothing that renders a page
    -- reads it, and no log line, repr or refusal prints it. Backups carry it,
    -- which ops/RUNBOOK.md says out loud rather than leaving to be discovered.
    destination     TEXT NOT NULL DEFAULT '',
    -- The non-secret half of a destination, for the one type that has one.
    -- Also ALTERed in below, because production has this table without it.
    destination_extra TEXT NOT NULL DEFAULT '',
    -- Which kinds of alert this channel takes, comma separated and sorted.
    -- **Empty means every kind**, which is what every row written before this
    -- column existed meant, so the default is the old behaviour rather than a
    -- channel that silently stops delivering.
    subscriptions   TEXT NOT NULL DEFAULT '',
    -- Which workspace configured this channel and which workspace's alerts it
    -- takes. Channels were fleet-wide until 2026-08-29, which was fine while
    -- the owner was the only account and became a tenant leak the day a second
    -- workspace could exist: every workspace's Alerts page listed every other
    -- workspace's channel labels. Also ALTERed in below, because production
    -- has this table without it, and the default is 1 because that is where
    -- every pre-workspace row was backfilled, the same rule hosts and users
    -- follow (app/db.py).
    workspace_id    INTEGER NOT NULL DEFAULT 1,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT NOT NULL,
    removed_at      TEXT
);
"""

# The label index is per workspace, so two workspaces can both call their
# channel "ops" without seeing each other's refusal. It is created outside
# SCHEMA because an existing database carries the old fleet-wide index under
# the same purpose, and that one has to go first: CREATE INDEX IF NOT EXISTS
# would leave both standing and the old one would keep refusing across
# workspaces.
LABEL_INDEX = """
DROP INDEX IF EXISTS idx_channels_label;
CREATE UNIQUE INDEX IF NOT EXISTS idx_channels_workspace_label
    ON notification_channels(workspace_id, label) WHERE removed_at IS NULL;
"""


class ChannelError(ValueError):
    """A channel that cannot be created, said in words an operator can act on.

    `field` is the field of the request the refusal is about, one of FIELDS,
    and `reason` is why, one of REASONS. Both are asked for by name on every
    raise, so a refusal cannot be written without them."""

    def __init__(self, sentence: str, *, field: str, reason: str):
        super().__init__(sentence)
        self.field = field
        self.reason = reason


# Added after this table first shipped, so production has one without it. The
# ALTER is the way `db.init` and `alerts.init` do it: SQLite has no ADD COLUMN
# IF NOT EXISTS, so the duplicate-column error is the idempotence check.
#
#   destination_extra  the non-secret half of a destination, for a type whose
#                      rule in TYPE_RULES names one. Empty for every other
#                      type. **This is still not a column a credential can go
#                      in**, which is the property the whole table rests on:
#                      what may go here is fixed per type by a pattern, and
#                      the only type with a rule takes a chat id.
#   subscriptions      which kinds this channel takes. Empty means every kind,
#                      so a row written before this column existed keeps
#                      doing exactly what it did.
#   destination        the destination itself, for a row not naming a variable.
LATER_COLUMNS = ("destination_extra TEXT NOT NULL DEFAULT ''",
                 "subscriptions TEXT NOT NULL DEFAULT ''",
                 "destination TEXT NOT NULL DEFAULT ''",
                 # DEFAULT 1 backfills every existing row into workspace 1 in
                 # the ALTER itself, so the box needs no manual step across
                 # the deploy, the same arrangement hosts and users had.
                 "workspace_id INTEGER NOT NULL DEFAULT 1")


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the additive rule every other table here follows."""
    con.executescript(SCHEMA)
    for column in LATER_COLUMNS:
        try:
            con.execute(f"ALTER TABLE notification_channels ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    # After the columns, because the index it creates names workspace_id.
    con.executescript(LABEL_INDEX)
    con.commit()


@dataclass(frozen=True)
class Channel:
    id: int
    type: str
    label: str
    destination_env: str
    enabled: bool
    # The destination itself, when this row does not name a variable. **Never
    # printed and never handed to a renderer**, see `for_display`.
    destination: str = ""
    # The host of the above, set only by `for_display`, so a screen can say
    # which service a row points at without holding the credential.
    destination_hint: str = ""
    # The non-secret half, empty for every type whose TYPE_RULES entry is None.
    destination_extra: str = ""
    # Which kinds this channel takes. Empty is every kind, never none.
    subscriptions: str = ""
    # Whose alerts this row takes and whose screen lists it. None means every
    # workspace, and exactly one row is ever built that way: the synthetic
    # legacy row `sweep_cli.channel_targets` makes for the environment-only
    # arrangement, which is the operator's own channel and watches the fleet.
    workspace_id: int | None = 1
    # When the row was added. A destination hears what is raised after it
    # was added and nothing raised before (decided on 26 October 2026, the
    # second big test's E10a). Empty for the environment's own arrangement,
    # which has no row and hears everything, as it always did.
    created_at: str = ""

    def takes(self, kind: str) -> bool:
        """Whether this channel wants an alert of this kind.

        **Empty takes everything.** A row that has never been told what to
        subscribe to is a row that behaves as it always did, and a channel
        that silently stopped delivering because a column was added would be
        the monitoring tool failing quietly that `docs/PRODUCT.md` 4c exists
        to prevent.

        A kind this build does not know is taken by a channel that subscribes
        to everything and refused by one that chose, which is the safe answer
        in both directions: the operator who chose three kinds did not choose
        a fourth nobody had invented yet.
        """
        if not self.subscriptions:
            return True
        return kind in self.subscriptions.split(",")

    def for_display(self) -> "Channel":
        """The same row with no destination on it, for anything that renders.

        **This is what replaced the schema guarantee.** The old table had no
        column a destination could go in, so a renderer could not leak one by
        accident. The column exists now, so the guard has to be something a
        caller holds instead, and this is it: `site/app/render_live.py` takes
        one of these and there is no value on the object to reach.

        It is a narrowing and never a promise about the caller. A caller that
        wanted the value could still read the row itself. What this gives is
        that the renderer does not have it by default, so leaking one takes a
        deliberate change rather than a careless template.
        """
        return replace(self, destination="", destination_hint=self.hint())

    def hint(self) -> str:
        """What the Destination column shows for a row that holds its own
        destination.

        **This used to be the host and nothing else, and that was wrong.**
        The owner, 2026-08-23: the Destination column shows the destination. A
        column headed Destination that says `hooks.slack.com`, or worse says
        `set on this screen`, is not answering its own heading. Where an alert
        goes is the one fact this row exists to carry.

        **A recipient is not a credential and shows in full.** That is mail and
        Telegram's chat: an address, a chat id, an optional topic. Nothing about
        them needs hiding, and mail is the case that prompted this.

        **A webhook URL is a bearer credential, so its last path segment is
        elided.** Anyone holding Slack's `services/T00/B00/XXXX`, or Discord's
        id and token, can post into that channel, and this page is
        screenshotted, screenshared and pasted into support threads. So the row
        shows the address up to that segment, which names which webhook it is
        and hands nobody the ability to use it. Slack's own incoming-webhook
        page says it "actively searches out and revokes leaked secrets", which
        is them agreeing the string is the secret.

        **Showing those three in full instead is one line here**, and the
        decision is the owner's rather than this function's.

        Empty for a row configured by variable, because that row's screen line
        is the variable name and there is nothing to summarise.
        """
        if not self.destination:
            return ""
        if self.type == TYPE_EMAIL:
            return self.destination
        if self.type == TYPE_TELEGRAM:
            chat, thread = split_telegram_target(self.destination_extra)
            return f"{chat} topic {thread}" if thread else chat
        parts = urllib.parse.urlsplit(self.destination)
        host = parts.hostname or ""
        # Split on the path's own separator and drop the last piece. A path with
        # nothing to drop, or none at all, leaves the host standing alone rather
        # than inventing a segment to elide.
        kept = [bit for bit in parts.path.split("/") if bit][:-1]
        return f"{host}/{'/'.join(kept)}/…" if kept else host

    def resolve(self, env=None) -> str:
        """Where this channel actually delivers, right now.

        **Named `resolve` and not `destination` because the row now has a
        `destination` field and the two are different things.** The field is
        what is stored, which is empty for a row configured by variable. This
        answers the question a sender asks, which is where to post, and it
        takes either route.

        Empty means a channel that is configured and cannot deliver: a variable
        that is not set in this process. The caller says so rather than this
        pretending.
        """
        if self.destination:
            return self.destination.strip()
        if not self.destination_env:
            return ""
        env = os.environ if env is None else env
        return (env.get(self.destination_env) or "").strip()

    def __repr__(self) -> str:
        """No credential can reach this, because the row does not hold one.

        The variable's name is printed because a name is not a secret and an
        operator debugging a quiet channel needs to see which one it read. The
        extra is printed for the same reason and on the same grounds: the only
        type that has one takes a Telegram chat id, which names a destination
        and which the Bot API documents as an identifier rather than as a
        credential. The credential is the bot token, and that is in the
        environment variable named beside it, never here."""
        return (f"Channel(type={self.type!r}, label={self.label!r},"
                f" destination={'set' if self.destination else 'unset'},"
                f" destination_env={self.destination_env!r},"
                f" destination_extra={self.destination_extra!r},"
                f" subscriptions={self.subscriptions or 'every kind'!r},"
                f" enabled={self.enabled})")


def _row(row) -> Channel:
    # `.keys()` rather than a bare index, because a row read through a
    # connection opened before init() ALTERed the column in does not carry it.
    extra = row["destination_extra"] if "destination_extra" in row.keys() else ""
    subs = row["subscriptions"] if "subscriptions" in row.keys() else ""
    return Channel(id=row["id"], type=row["type"], label=row["label"],
                   destination_env=row["destination_env"],
                   destination=(row["destination"]
                                if "destination" in row.keys() else "") or "",
                   enabled=bool(row["enabled"]),
                   destination_extra=extra or "",
                   subscriptions=subs or "",
                   workspace_id=(row["workspace_id"]
                                 if "workspace_id" in row.keys() else 1) or 1,
                   created_at=(row["created_at"] if "created_at" in row.keys() else "") or "")


def check_extra(channel_type: str, destination_extra: str) -> str:
    """The non-secret half, cleaned, or a ChannelError saying what is wrong.

    A type whose TYPE_RULES entry is None takes none, and being handed one is
    an error rather than something to drop quietly: a chat id typed against a
    Slack channel means the operator believes something about this row that is
    not true, and storing it and ignoring it hides that.
    """
    rule = TYPE_RULES[channel_type]
    destination_extra = (destination_extra or "").strip()
    if rule is None:
        if destination_extra:
            raise ChannelError(
                f"a {channel_type} channel is one destination and takes no"
                " second field. Only telegram does, because its credential and"
                " the chat it posts to are two different things",
                field=FIELD_CHAT_ID, reason=REASON_NOT_TAKEN)
        return ""
    if not rule.pattern.match(destination_extra):
        raise ChannelError(
            rule.says, field=FIELD_CHAT_ID,
            reason=REASON_SHAPE if destination_extra else REASON_MISSING)
    return destination_extra


def check_subscriptions(chosen) -> str:
    """The chosen kinds, normalised, or a ChannelError naming what is wrong.

    Takes a string, a list or None. Returns "" for "every kind", which is what
    an empty choice means everywhere in this module.

    **Choosing nothing and choosing everything are the same answer here**, and
    that is deliberate rather than sloppy. A channel subscribed to no kind is a
    channel that exists and can never deliver, which is a row an operator would
    have to debug. The screen offers no way to reach it either: unticking every
    box means every kind, and the window says so.

    Sorted and de-duplicated, so two rows that chose the same kinds hold the
    same string and a column of them can be read at a glance.
    """
    if not chosen:
        return ""
    if isinstance(chosen, str):
        chosen = chosen.split(",")
    # Stripped whatever the input was. A list arriving from JSON can hold a
    # blank the same way a comma separated string can, and only the string form
    # was cleaned before, so `["", " "]` was refused as an unknown kind rather
    # than read as "no choice made".
    wanted = sorted({part.strip() for part in chosen if part and part.strip()})
    if not wanted:
        return ""
    unknown = [part for part in wanted if part not in KIND_NAMES]
    if unknown:
        # Named rather than echoed: these are ours and short, and the operator
        # needs to see which of their words this build does not have.
        raise ChannelError(
            f"{len(unknown)} of those are not kinds of alert. The kinds are "
            + ", ".join(KIND_NAMES),
            field=FIELD_EVENTS, reason=REASON_UNKNOWN)
    if set(wanted) == set(KIND_NAMES):
        # Every kind is stored as "every kind", so a channel does not quietly
        # stop covering a fourth kind added in a later build.
        return ""
    return ",".join(wanted)


def add(con: sqlite3.Connection, channel_type: str, label: str,
        destination_env: str, now: datetime | None = None,
        destination_extra: str = "", subscriptions=None,
        destination: str = "", workspace_id: int = 1) -> Channel:
    """One channel. Every argument is checked before anything is written."""
    if channel_type not in TYPES:
        # The word is not repeated back. It is usually harmless and it is not
        # always: every refusal in this module is reachable from an operator
        # who has just pasted a URL into the wrong field, and one that quotes
        # what it was given puts that value in a log, a terminal and, since the
        # admin endpoint exists, an HTTP response body.
        raise ChannelError(
            "that is not a channel type. It is one of " + ", ".join(TYPES),
            field=FIELD_TYPE, reason=REASON_UNKNOWN)
    label = (label or "").strip()
    if not LABEL_RE.match(label):
        raise ChannelError(
            "a label is letters, digits, space, dot, dash and underscore,"
            " starting with a letter or a digit, at most 48 characters",
            field=FIELD_LABEL, reason=REASON_SHAPE)
    destination = (destination or "").strip()
    destination_env = (destination_env or "").strip()
    if destination and destination_env:
        raise ChannelError(
            "a channel is configured one way or the other, not both. Either"
            " give it the destination, or name the environment variable the"
            " sweep should read it from",
            field=FIELD_ENV, reason=REASON_NOT_TAKEN)
    if destination:
        # Checked for shape here and checked again by the sender, which for a
        # URL resolves the host and refuses anything not globally routable.
        # This is the door, `app/webhook.py` is the lock.
        _refuse_a_bad_destination(channel_type, destination)
        return _insert(con, channel_type, label, destination_env, destination,
                       destination_extra, subscriptions, now, workspace_id)
    if not destination_env:
        raise ChannelError(
            "a channel needs somewhere to deliver. Give it the destination, or"
            " name the environment variable the sweep should read it from",
            field=FIELD_DESTINATION, reason=REASON_MISSING)
    if not ENV_NAME_RE.match(destination_env):
        # **Not quoted, and this is the refusal that made the rule.** The
        # mistake this catches is pasting the webhook URL itself into the field
        # that wants a variable name, which `app/channels_cli.py` says out loud
        # is the first thing an operator gets wrong. Quoting it back would put
        # a credential in a terminal, a journal and an HTTP response body, so
        # the shape is described and the value is not repeated.
        raise ChannelError(
            "that is not an environment variable this may read. The name has"
            " to start with WHICHPORTS_ and hold only capitals, digits and"
            " underscores, so a row can name one of ours and nothing else."
            " It is the NAME of the variable, never the URL or token itself",
            field=FIELD_ENV, reason=REASON_SHAPE)
    return _insert(con, channel_type, label, destination_env, "",
                   destination_extra, subscriptions, now, workspace_id)


def _refuse_a_bad_destination(channel_type: str, destination: str) -> None:
    """Raise when this destination does not fit this type. `add` and
    `set_destination` both come through here, so a create and a replacement
    are refused for the same reason in the same words."""
    reason, sentence = destination_refusal(channel_type, destination)
    if sentence:
        raise ChannelError(sentence, field=FIELD_DESTINATION, reason=reason)


def free_label(con: sqlite3.Connection, base: str, workspace_id: int) -> str:
    """A label nobody had to invent, and one that is free in this workspace.

    Labels are unique among one workspace's live channels, so a second channel
    of the same kind would fail on the duplicate. A number is appended rather
    than refusing, because whoever asked did nothing wrong.
    """
    taken = {c.label for c in live(con, workspace_id=workspace_id)}
    if base not in taken:
        return base
    for n in range(2, 100):
        candidate = f"{base} {n}"
        if candidate not in taken:
            return candidate
    raise ChannelError("too many channels with that name already",
                       field=FIELD_LABEL, reason=REASON_TAKEN)


def ensure_account_email(con: sqlite3.Connection, email: str,
                         workspace_id: int) -> Channel | None:
    """The email channel an account gets for its own address, or None when its
    workspace already holds a live email row for that address.

    The owner, 2026-09-20 (`docs/RECORD.md` 4.186): an account's alerts reach its
    own address with nothing to set up, through a real row the tester can
    edit, switch off or delete. **Called when an account is made and by the
    one backfill, never on a schedule**, so a row somebody deleted is not put
    back.

    A row that is switched off for the same address counts as holding it:
    switching it off was an answer.
    """
    init(con)
    email = (email or "").strip().lower()
    for channel in live(con, TYPE_EMAIL, workspace_id=workspace_id):
        if (channel.resolve({}) or "").strip().lower() == email:
            return None
    return add(con, TYPE_EMAIL, free_label(con, TYPE_EMAIL, workspace_id), "",
               destination=email, workspace_id=workspace_id)


def _insert(con, channel_type, label, destination_env, destination,
            destination_extra, subscriptions, now, workspace_id):
    """The write both routes end at, so the two ways of configuring a channel
    cannot drift apart in what they validate or what they store."""
    destination_extra = check_extra(channel_type, destination_extra)
    subscriptions = check_subscriptions(subscriptions)
    now = now or datetime.now(timezone.utc)
    try:
        cur = con.execute(
            "INSERT INTO notification_channels (type, label, destination_env,"
            " destination, destination_extra, subscriptions, workspace_id,"
            " enabled, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)",
            (channel_type, label, destination_env, destination,
             destination_extra, subscriptions, workspace_id, now.isoformat()))
    except sqlite3.IntegrityError:
        raise ChannelError(
            f"a channel called {label!r} already exists. Labels are how a"
            " person tells two webhooks apart, so they have to differ",
            field=FIELD_LABEL, reason=REASON_TAKEN) from None
    con.commit()
    return _row(con.execute("SELECT * FROM notification_channels WHERE id = ?",
                            (cur.lastrowid,)).fetchone())


def _scope(workspace_id):
    """The WHERE tail that keeps a label action inside one workspace.

    None is unscoped and stays available to the box CLI, which predates
    workspaces and is run by whoever operates the whole service. Every HTTP
    route passes the session's workspace, so an operator can only ever act on
    a row their own screen lists (docs/RECORD.md 4.98 is the same rule on
    hosts).
    """
    if workspace_id is None:
        return "", ()
    return " AND workspace_id = ?", (workspace_id,)


def remove(con: sqlite3.Connection, label: str,
           now: datetime | None = None, workspace_id: int | None = None) -> bool:
    """Marked removed rather than deleted, so an alert delivered through it
    keeps a row its delivery can still be read against."""
    now = now or datetime.now(timezone.utc)
    scope, params = _scope(workspace_id)
    cur = con.execute(
        "UPDATE notification_channels SET removed_at = ?"
        " WHERE label = ? AND removed_at IS NULL" + scope,
        (now.isoformat(), label, *params))
    con.commit()
    return cur.rowcount > 0


def set_enabled(con: sqlite3.Connection, label: str, enabled: bool,
                workspace_id: int | None = None) -> bool:
    """Off is not removed. A channel switched off keeps its row and its label,
    because turning one off for an afternoon is a different act from deciding
    it should not exist."""
    scope, params = _scope(workspace_id)
    cur = con.execute(
        "UPDATE notification_channels SET enabled = ?"
        " WHERE label = ? AND removed_at IS NULL" + scope,
        (1 if enabled else 0, label, *params))
    con.commit()
    return cur.rowcount > 0


def set_subscriptions(con: sqlite3.Connection, label: str, chosen,
                      workspace_id: int | None = None) -> bool:
    """Change which kinds one channel takes. Validated the same way `add` does,
    so there is one rule and not two."""
    subscriptions = check_subscriptions(chosen)
    scope, params = _scope(workspace_id)
    cur = con.execute(
        "UPDATE notification_channels SET subscriptions = ?"
        " WHERE label = ? AND removed_at IS NULL" + scope,
        (subscriptions, label, *params))
    con.commit()
    return cur.rowcount > 0


def set_destination(con: sqlite3.Connection, label: str, destination: str,
                    destination_extra: str = "",
                    workspace_id: int | None = None, subscriptions=None) -> bool:
    """Replace where one channel delivers. False when no live channel has
    this label, exactly like the other label actions.

    **Validated the way `add` validates**, same shape rules per type, so there
    is one rule and not two. The extra is validated against the row's own type,
    which means a telegram edit has to carry its chat id and every other type
    has to carry none.

    `destination_env` is cleared, because a row holds one of the two and this
    row now holds its value. The variable in the sweep's environment is
    untouched and unread here.

    **A replaced destination is a new delivery key** (`alerts.key_for_channel`
    digests the value), so an open alert not yet delivered to the new place
    goes there on the next sweep. That is the same behaviour as removing the
    row and adding it back, and it is what replacing a destination means.

    **`subscriptions` are the kinds, written in the same statement**, checked
    as `set_subscriptions` checks them, before anything is written. None
    leaves the row's kinds as they are. The Edit window holds a destination
    and its kinds and saves both with one click, and this wrote the
    destination alone while the click was answered as saved (the second big
    test, finding E20).
    """
    found = [c for c in live(con, workspace_id=workspace_id)
             if c.label == label]
    if not found:
        return False
    channel = found[0]
    destination = (destination or "").strip()
    if not destination:
        raise ChannelError(
            "a replacement needs the new destination. To stop deliveries"
            " instead, disable or remove the channel",
            field=FIELD_DESTINATION, reason=REASON_MISSING)
    _refuse_a_bad_destination(channel.type, destination)
    destination_extra = check_extra(channel.type, destination_extra)
    kinds = channel.subscriptions if subscriptions is None else check_subscriptions(subscriptions)
    scope, params = _scope(workspace_id)
    cur = con.execute(
        "UPDATE notification_channels SET destination = ?,"
        " destination_extra = ?, destination_env = '', subscriptions = ?"
        " WHERE label = ? AND removed_at IS NULL" + scope,
        (destination, destination_extra, kinds, label, *params))
    con.commit()
    return cur.rowcount > 0


def rename(con: sqlite3.Connection, label: str, new_label: str,
           workspace_id: int | None = None) -> bool:
    """Change what a channel is called, keeping everything else.

    **The label is not the delivery key**, which is why this is safe to offer:
    `alerts.channel_key` is built from the type, the variable and the extra, so
    renaming a channel does not make its open alerts look undelivered and does
    not re-post any of them. If the key were the label this would be a
    destructive operation wearing a friendly word.
    """
    new_label = (new_label or "").strip()
    if not LABEL_RE.match(new_label):
        raise ChannelError(
            "a label is letters, digits, space, dot, dash and underscore,"
            " starting with a letter or a digit, at most 48 characters",
            field=FIELD_LABEL, reason=REASON_SHAPE)
    scope, params = _scope(workspace_id)
    try:
        cur = con.execute(
            "UPDATE notification_channels SET label = ?"
            " WHERE label = ? AND removed_at IS NULL" + scope,
            (new_label, label, *params))
    except sqlite3.IntegrityError:
        raise ChannelError(
            "a channel with that label already exists. Labels are how a"
            " person tells two of the same kind apart, so they have to differ",
            field=FIELD_LABEL, reason=REASON_TAKEN) from None
    con.commit()
    return cur.rowcount > 0


def live(con: sqlite3.Connection, channel_type: str | None = None,
         workspace_id: int | None = None) -> list:
    """Every channel that still exists, enabled or not, oldest first.

    Not filtered by enabled, because a screen listing where alerts go has to
    show one that is switched off. The sender filters.

    `workspace_id` narrows to one workspace's rows. None is every row, which
    is the sweep's view and the CLI's, never a screen's: anything rendering a
    page for a session passes that session's workspace, because listing every
    workspace's channels to any of them is the leak this parameter closes.
    """
    try:
        rows = con.execute(
            "SELECT * FROM notification_channels WHERE removed_at IS NULL"
            " ORDER BY id").fetchall()
    except sqlite3.OperationalError:
        # A database this meets before the table exists. The same posture
        # site/app/render_live.py takes for alerts and declared names: the
        # page renders, with nothing in this list.
        return []
    found = [_row(row) for row in rows]
    if channel_type is not None:
        found = [c for c in found if c.type == channel_type]
    if workspace_id is not None:
        found = [c for c in found if c.workspace_id == workspace_id]
    return found


def sending(con: sqlite3.Connection, channel_type: str, env=None) -> list:
    """The channels of one type that are on and have a destination to use.

    A channel that is enabled and whose variable is unset is left out here and
    is still listed by `live`, because "configured and not deliverable" is a
    thing an operator needs to see on a screen and not a thing to act on in a
    sender.
    """
    return [c for c in live(con, channel_type)
            if c.enabled and c.resolve(env)]
