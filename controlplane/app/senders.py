"""One alert, rendered for whichever channel is carrying it.

`app/webhook.py` is the transport and owns every safety property: no proxy, no
redirect, every resolved address globally routable, a timeout, a bounded read.
This module owns the part that differs per channel, which is only two things:
**what URL it posts to and what body it posts.** Nothing here opens a socket.

## Why these three, and what they have in common

The owner's decision of 2026-08-22 (`docs/RECORD.md` #259) is webhook, Slack,
Telegram and Discord this round, with ntfy and Microsoft Teams later. Slack and
Discord are the same shape as the webhook already here: an operator pastes a
URL that is itself the credential, and a JSON body goes to it.

**Telegram is the one that is not.** Its credential is a bot token and its
destination is a chat id, and the token goes in the URL path:

    https://api.telegram.org/bot<token>/sendMessage

(core.telegram.org/bots/api#making-requests, read 2026-08-22). Two consequences
run through everything below. The host is fixed rather than operator-supplied,
so there is nothing to paste. And **any message that echoes the request URL
leaks the credential**, which is why nothing here ever puts a URL in a return
value, a log line or a repr, and why `webhook.Config.__repr__` printing
`url=set` is load-bearing rather than tidy.

## What may cross the wire

The same ceiling `app/webhook.py` states: never more than the mail already
sends. The chat text is built from the strings `app/notify.py` puts in a
message, not from a richer decomposition of them, because a shape that is
easier to consume is a shape that discloses more.

## The limits are the vendors' own, except where they are ours and say so

    Discord    content is "up to 2000 characters"
               docs.discord.com/developers/resources/webhook, read 2026-08-22
    Telegram   text is "1-4096 characters after entities parsing"
               core.telegram.org/bots/api#sendmessage, read 2026-08-22
    Slack      no published limit was found on
               docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/
               read 2026-08-22, so the bound below is ours and is marked as ours

A message over the limit is cut and **says it was cut**, with the count of what
is missing and where to read it. Silently dropping the tail of a coalesced
alert would lose findings out of the one mail `docs/PRODUCT.md` 4c exists to
make readable.

## The shape per channel, and the page each part was read from

The words are the mail's (`app/notify.py`), and each chat channel gets them in
its own formatting. Every capability used is one the vendor documents for the
kind of destination an operator gives us. All read 2026-10-03.

    Slack      an incoming webhook takes `blocks` beside `text`: "You can use
               all the usual formatting and layout blocks with incoming
               webhooks"
               docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/
               "You can include up to 50 blocks in each message"
               docs.slack.dev/reference/block-kit/blocks/
               header: plain_text, "Maximum length for the text in this field
               is 150 characters"   .../blocks/header-block/
               section: text "maximum length is 3000 characters", fields
               "Maximum number of items is 10. Maximum length for the text in
               each item is 2000 characters"   .../blocks/section-block/
               context: elements, "Maximum number of items is 10"
               .../blocks/context-block/
               mrkdwn: "*bold* will produce bold text", code between
               backticks, a link as <url|words>, and "&, <, and >" replaced by
               their entities
               docs.slack.dev/messaging/formatting-message-text/
               `text` stays, because "Mobile notifications exclusively use
               message.text" (the same page)
    Discord    a webhook takes `embeds`, an "array of up to 10 embed objects"
               docs.discord.com/developers/resources/webhook
               an embed has a description, fields (name, value, and
               inline, "whether or not this field should display inline")
               and a footer with text. Limits: title 256, description 4096, "Up to 25 field
               objects", field name 256, field value 1024, footer text 2048,
               and all of those together "must not exceed 6000 characters"
               docs.discord.com/developers/resources/message
               `allowed_mentions` with an empty `parse` is how to "completely
               suppress all mentions in the message" (the same page)
    Telegram   sendMessage takes `parse_mode` and `link_preview_options`
               core.telegram.org/bots/api#sendmessage
               HTML style: <b>, <code>, <a href>, and "All <, > and & symbols that are
               not a part of a tag or an HTML entity must be replaced with the
               corresponding HTML entities"
               core.telegram.org/bots/api#html-style
               LinkPreviewOptions.is_disabled: "True, if the link preview is
               disabled"   core.telegram.org/bots/api#linkpreviewoptions

**Not read from a page:** which markdown Discord renders inside an embed. Its
developer pages say only that it "utilizes a subset of markdown for rendering
message content", and its own list of that subset refused an automated read.
So the embed's structure does the work, with one exception that was seen
rather than read: the link to the dashboard, written `[words](address)` in
the embed's last field, drew as a link in a Discord client on 2026-10-03.
"""

import html
import json
import urllib.parse
from dataclasses import dataclass

from . import (alerts, alertwords, channels, finding_alerts, notify, publicurl,
               webhook)

# Where a reader goes for the whole thing is publicurl.dashboard(), the same
# address the mail signs off with, so a truncated chat message points at the
# screen that is never cut.

# Documented by the vendor, both read 2026-08-22, sources in the docstring.
DISCORD_TEXT_LIMIT = 2000
TELEGRAM_TEXT_LIMIT = 4096

# **Ours, not Slack's.** Slack publishes no limit for an incoming webhook's
# `text` on the page above, so rather than invent one this takes Telegram's,
# which is the smallest documented number that is not Discord's. A bound we
# chose is still a bound, and one this size cannot cut a real alert.
SLACK_TEXT_LIMIT = 4096

# **Ours.** A generic webhook has no vendor, so there is no page to read a
# limit from. The same bound the Slack text takes, for the same reason.
WEBHOOK_TEXT_LIMIT = 4096

TEXT_LIMITS = {
    channels.TYPE_SLACK: SLACK_TEXT_LIMIT,
    channels.TYPE_TELEGRAM: TELEGRAM_TEXT_LIMIT,
    channels.TYPE_DISCORD: DISCORD_TEXT_LIMIT,
}

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"

# Telegram answers a successful sendMessage with the whole Message it created,
# which contains the text we just sent. So the reply is bigger than the request
# and `webhook.MAX_RESPONSE_BYTES` at 4096 would cut it in the common case.
# A cut body does not parse, and a body that does not parse would be reported
# as a delivery that failed when it in fact arrived, which the next sweep would
# then send again. 4096 characters can reach about four times that in UTF-8
# bytes, so this leaves room several times over and is still a bound.
TELEGRAM_MAX_RESPONSE_BYTES = 65536

# Discord's `wait` parameter, verbatim from the webhook resource page: it
# "waits for server confirmation of message send before response", and with the
# default of false "a message that is not saved does not return an error".
#
# We record a delivery in `alert_deliveries` and never send that alert to that
# destination again, so a success we did not actually earn is a message nobody
# ever receives and nothing ever retries. Asking to be told is the honest
# choice, and it costs one query parameter.
DISCORD_WAIT = "wait=true"


class SenderError(ValueError):
    """A channel that cannot be delivered to, said in words an operator can act
    on. Never carries a URL, a token or a body."""


# ---------------------------------------------------------------- the words
#
# One alert as the mail says it, before any channel shapes it. Every word is
# `app/alertwords.py`'s, the one description the mail is drawn from too, so
# a chat message cannot come to say what the mail does not.

# The words on the link when a message names none of its own.
DASHBOARD_WORDS = "Open the dashboard"

@dataclass(frozen=True)
class Line:
    """One line under a port. `quoted` is the part that is a rule as its
    owner wrote it, which a channel that can sets in fixed width."""
    words: str
    quoted: str = ""

    @property
    def plain(self) -> str:
        return f"{self.words} {self.quoted}".strip()


@dataclass(frozen=True)
class Row:
    """One changed finding: the mail's first line for it, and the lines
    under it."""
    head: str
    lines: tuple = ()


@dataclass(frozen=True)
class Message:
    """`server_id` is the name the server is found by, set only when the
    title says its display name, because two servers may carry the same
    display name (app/displayname.py)."""
    title: str
    server_id: str = ""
    lead: str = ""
    fields: tuple = ()
    rows: tuple = ()
    closing: str = ""
    # Where the message sends its reader and the words on that link: the
    # server's own page for an alert about one (app/alertwords.py). Empty
    # means the dashboard, which is what a message had before it had these.
    link: str = ""
    link_words: str = ""


def message(said) -> Message:
    """A chat message from the one description every channel draws
    (app/alertwords.py), so a chat says what the mail says and no more."""
    return Message(title=said.title, lead=said.sentence, fields=said.fields,
                   closing=said.closing, link=said.link, link_words=said.button)


def message_for_alert(kind: str, host_name: str, detail: str,
                      raised_at: str, display: str = "") -> Message:
    """The two kinds about a server and not a port: an agent gone quiet, an
    outside view gone stale. `raised_at` is taken and not said, because no
    message carries a time (docs/screens/mails/SPEC-alert-messages.md)."""
    if kind == alerts.KIND_SILENT:
        return message(notify.said_silence(host_name, detail, display))
    if kind == finding_alerts.KIND_OUTSIDE_STALE:
        return message(notify.said_outside_stale(host_name, detail, display))
    return message(alertwords.said_other(host_name, kind, display))


def message_for_changes(host_name: str, changes, display: str = "") -> Message:
    """The coalesced kind. One message for every finding on one server that
    changed, which is the same grouping the mail uses (docs/PRODUCT.md 4c)."""
    return message(notify.said_changes(host_name, changes, display))


def message_for_test() -> Message:
    """Send test. It says it is a test and names no host, no port and no
    finding."""
    return message(notify.said_test())


def _link(message: Message) -> tuple[str, str]:
    """Where a message sends its reader, and the words on that link."""
    return (message.link or publicurl.dashboard(),
            message.link_words or DASHBOARD_WORDS)


def plain(message: Message) -> str:
    """The words as plain text: the generic webhook's `text`, and what a
    chat channel shows where it cannot show its own shape."""
    lines = [f"whichports: {message.title}"]
    if message.server_id:
        lines.append(f"id {message.server_id}")
    if message.lead:
        lines.append(message.lead)
    lines.extend(f"{label}: {value}" for label, value in message.fields)
    for row in message.rows:
        lines.append("")
        lines.append(row.head)
        lines.extend(f"  {line.plain}" for line in row.lines)
    if message.rows:
        lines.append("")
    if message.closing:
        lines.append(message.closing)
    lines.append(_link(message)[0])
    return "\n".join(lines)


def text_for_alert(kind: str, host_name: str, detail: str,
                   raised_at: str, display: str = "") -> str:
    return plain(message_for_alert(kind, host_name, detail, raised_at, display))


def text_for_changes(host_name: str, changes, display: str = "") -> str:
    return plain(message_for_changes(host_name, changes, display))


def fit(text: str, limit: int) -> str:
    """`text` cut to `limit` characters, saying so when it had to cut.

    Characters and not bytes, because that is the unit both vendors state their
    limit in. The tail names how much went missing and where the whole thing
    is, so a cut message is still an honest one.

    A limit too small to hold even the notice is not something a caller can
    recover from, so it raises rather than returning something misleading.
    """
    if len(text) <= limit:
        return text
    notice = f"\n[cut, {{n}} more characters at {publicurl.dashboard()}]"
    # The count goes inside the notice, so the notice's own length depends on
    # the count. Measured with the longest count it could hold rather than
    # solved, because one character of slack is cheaper than an off-by-one on
    # a limit a vendor enforces.
    room = limit - len(notice.format(n=len(text)))
    if room < 1:
        raise SenderError(f"a limit of {limit} characters is too small to hold"
                          " a message and the notice that it was cut")
    kept = text[:room]
    return kept + notice.format(n=len(text) - room)


def slack_escaped(text: str) -> str:
    """`text` with the three characters Slack parses written as entities.

    Slack's page on formatting, read 2026-10-03
    (docs.slack.dev/messaging/formatting-message-text/): "Slack uses &, <,
    and > as control characters for special parsing in text objects, so they
    must be converted to HTML entities if they're not going to be used for
    their parsing purpose." A program's name or a quoted rule is text the
    server wrote, and none of it is meant for Slack to parse.

    The ampersand first, or the two entities written after it would be
    escaped a second time. Done after the text is cut to its limit, so a cut
    never lands inside an entity.
    """
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def shortened(text: str, limit: int) -> str:
    """A heading cut to `limit` characters. Nothing is lost by it: a heading
    that had to be cut is said whole in the part under it."""
    return text if len(text) <= limit else text[:limit - 3] + "..."


# --------------------------------------------------------------- the shapes
#
# The same words, in each channel's own formatting. The limits and the page
# each was read from are in the docstring at the top. A message with more
# findings than a shape can hold shows as many as fit and says how many more
# there are and where.

SLACK_HEADER_LIMIT = 150
SLACK_SECTION_LIMIT = 3000
SLACK_BLOCKS_LIMIT = 50


def _slack_line(line: Line) -> str:
    # A rule that holds a backtick cannot sit between backticks, so it stays
    # plain rather than breaking the line it is on.
    if line.quoted and "`" not in line.quoted:
        return f"{slack_escaped(line.words)} `{slack_escaped(line.quoted)}`".strip()
    return slack_escaped(line.plain)


# What a webhook's typed document says for a test, where a finding has its
# sentence. Send test is pressed on the Integrations screen.
TEST_PAYLOAD_DETAIL = "a test message from the Integrations screen"


def _slack_text(text: str) -> dict:
    """One piece of Slack's own markup, which Slack is told to leave as it is.

    Slack makes a link of what looks like one. A display name that is a
    domain was drawn as a link in a field's value (docs/RECORD.md 4.409), and
    no channel may link what a name holds. Slack's page for a text object,
    read on 2026-10-06, says of `verbatim`: with false, the default, "URLs
    will be auto-converted into links, conversation names will be link-ified,
    and certain mentions will be automatically parsed". With true Slack "will
    continue to process all markdown formatting and manual parsing strings,
    but it won't modify any plain-text content". So the bold labels and the
    one link of ours still work, and nothing else is made into anything.
    Every mrkdwn object the sender builds is made here.
    """
    return {"type": "mrkdwn", "text": text, "verbatim": True}


def _slack_section(text: str) -> dict:
    return {"type": "section", "text": _slack_text(text)}


def in_fixed_width(value: str) -> str:
    """A field's value for Slack and for Discord, set between backticks
    when it holds an underscore.

    Both read a pair of underscores as italics, and neither names an escape
    for one. Slack's page says "Text within inline code blocks will not use
    any other formatting" (docs.slack.dev/messaging/formatting-message-text/,
    read 2026-10-06). A server's ID may hold an underscore, and so may a
    container's name, which Docker itself writes with one when a container
    is started without a name. Every such value is held to a set with no
    backtick in it before it reaches a message, so the backticks cannot be
    closed from inside. One that held a backtick all the same is sent as it
    is, which is what every value was before this.
    """
    if "_" in value and "`" not in value:
        return f"`{value}`"
    return value


def slack_blocks(message: Message) -> list:
    link, link_words = _link(message)
    title = f"whichports: {message.title}"
    blocks = [{"type": "header",
               "text": {"type": "plain_text",
                        "text": shortened(title, SLACK_HEADER_LIMIT)}}]
    if len(title) > SLACK_HEADER_LIMIT:
        blocks.append(_slack_section(slack_escaped(title)))
    if message.server_id:
        blocks.append({"type": "context", "elements": [
            _slack_text(f"id `{slack_escaped(message.server_id)}`")]})
    if message.lead:
        blocks.append(_slack_section(slack_escaped(message.lead)))
    if message.fields:
        blocks.append({"type": "section", "fields": [
            _slack_text(f"*{slack_escaped(label)}*\n{in_fixed_width(slack_escaped(value))}")
            for label, value in message.fields]})
    # Two blocks are kept back: the closing line, and the line that says how
    # many findings did not fit.
    room = SLACK_BLOCKS_LIMIT - len(blocks) - 2
    for row in message.rows[:room]:
        text = "\n".join([f"*{slack_escaped(row.head)}*"]
                         + [_slack_line(line) for line in row.lines])
        if len(text) > SLACK_SECTION_LIMIT:
            plain_row = "\n".join([row.head] + [line.plain for line in row.lines])
            text = slack_escaped(fit(plain_row, SLACK_SECTION_LIMIT // 2))
        blocks.append(_slack_section(text))
    more = len(message.rows) - len(message.rows[:room])
    if more:
        blocks.append(_slack_section(f"and {more} more at <{link}>"))
    closing = [_slack_text(slack_escaped(message.closing))] \
        if message.closing else []
    blocks.append({"type": "context", "elements": closing + [
        _slack_text(f"<{link}|{slack_escaped(link_words)}>")]})
    return blocks


DISCORD_TITLE_LIMIT = 256
DISCORD_FIELD_NAME_LIMIT = 256
DISCORD_FIELD_VALUE_LIMIT = 1024
DISCORD_FIELDS_LIMIT = 25
DISCORD_EMBED_TOTAL_LIMIT = 6000
# Kept back out of the total for the field that says how many did not fit
# and for the link.
DISCORD_MORE_ROOM = 400


def discord_embed(message: Message) -> dict:
    """One embed under the first line. Its own parts carry the shape, and
    the one piece of markdown in it is the link at its end. No colour: a
    coloured edge on a whole message reads as a verdict on it, and no other
    channel has one."""
    description = message.lead
    fields = []
    if message.server_id:
        fields.append({"name": "id", "value": message.server_id})
    for label, value in message.fields:
        # Side by side, as Slack sets them: `inline` is "whether or not this
        # field should display inline" (the message page).
        fields.append({"name": label, "inline": True,
                       "value": in_fixed_width(fit(value, DISCORD_FIELD_VALUE_LIMIT - 2))})
    used = (len(description) + len(message.closing)
            + sum(len(f["name"]) + len(f["value"]) for f in fields))
    shown = 0
    for row in message.rows:
        name = shortened(row.head, DISCORD_FIELD_NAME_LIMIT)
        value = fit("\n".join(line.plain for line in row.lines),
                    DISCORD_FIELD_VALUE_LIMIT)
        # Two fields are kept back: the one that says how many did not fit,
        # and the link.
        if (len(fields) >= DISCORD_FIELDS_LIMIT - 2 or used + len(name)
                + len(value) > DISCORD_EMBED_TOTAL_LIMIT - DISCORD_MORE_ROOM):
            break
        fields.append({"name": name, "value": value})
        used += len(name) + len(value)
        shown += 1
    more = len(message.rows) - shown
    if more:
        fields.append({"name": f"and {more} more", "value": "on the dashboard"})
    # The link, last inside the embed, under the one label that is Discord's
    # alone (`alertwords.DISCORD_LINK_LABEL`). **Seen, not documented:** a
    # field's value written `[words](address)` drew as a link in a Discord
    # client on 2026-10-03 and again on 2026-10-06. No page that could be
    # read says an embed does that.
    link, link_words = _link(message)
    fields.append({"name": alertwords.DISCORD_LINK_LABEL,
                   "value": f"[{link_words}]({link})"})
    embed = {"fields": fields}
    if description:
        embed["description"] = description
    if message.closing:
        embed["footer"] = {"text": message.closing}
    return embed


# Kept back for the line that says how many findings did not fit.
TELEGRAM_MORE_ROOM = 200


def _telegram(text: str) -> str:
    """The three characters Telegram's HTML style reads as markup."""
    return html.escape(text, quote=False)


def _telegram_line(line: Line) -> str:
    if line.quoted:
        return (f"{_telegram(line.words)} "
                f"<code>{_telegram(line.quoted)}</code>").strip()
    return _telegram(line.plain)


def telegram_html(message: Message) -> str:
    """The message in Telegram's HTML style. It is cut between findings and
    never inside one, because a tag left open is a message Telegram refuses.

    A field is one line, its label bold, because Telegram sets nothing side
    by side. An underscore is not markup in this style, where "Only the tags
    mentioned above are currently supported" (core.telegram.org/bots/api,
    read 2026-10-06), so a value is sent as it is."""
    link, link_words = _link(message)
    top = [f"<b>whichports: {_telegram(message.title)}</b>"]
    if message.server_id:
        top.append(f"id <code>{_telegram(message.server_id)}</code>")
    # A blank line between the parts, which is the only spacing a chat has.
    if message.lead:
        top += ["", _telegram(message.lead)]
    if message.fields:
        top.append("")
        top.extend(f"<b>{_telegram(label)}</b>: {_telegram(value)}"
                   for label, value in message.fields)
    bottom = [""]
    if message.closing:
        bottom.append(_telegram(message.closing))
    # `<a href="...">` is in the HTML style's list of tags.
    bottom.append(f'<a href="{html.escape(link, quote=True)}">'
                  f"{_telegram(link_words)}</a>")
    room = (TELEGRAM_TEXT_LIMIT - TELEGRAM_MORE_ROOM
            - len("\n".join(top)) - len("\n".join(bottom)))
    middle = []
    shown = 0
    for row in message.rows:
        block = "\n".join(["", f"<b>{_telegram(row.head)}</b>"]
                          + [_telegram_line(line) for line in row.lines])
        if len(block) + 1 > room:
            break
        middle.append(block)
        room -= len(block) + 1
        shown += 1
    more = len(message.rows) - shown
    if more:
        middle.append(f"\nand {more} more on the dashboard")
    return "\n".join(top + middle + bottom)


# -------------------------------------------------------------- the wiring
#
# Per type: where it posts and what it posts. Everything below returns a
# `webhook.Config` and a dict, and `deliver` hands both to `webhook.send`.


def _discord_url(pasted: str) -> str:
    """The pasted webhook URL with `wait=true` on it, whatever it already had.

    Parsed and rebuilt rather than having a string appended, because a URL that
    already carries a query would otherwise get a second `?` and stop being the
    address the operator pasted.
    """
    parts = urllib.parse.urlsplit(pasted)
    query = f"{parts.query}&{DISCORD_WAIT}" if parts.query else DISCORD_WAIT
    return urllib.parse.urlunsplit(
        (parts.scheme, parts.netloc, parts.path, query, parts.fragment))


def telegram_ok(body_bytes: bytes) -> str:
    """"" when Telegram said it sent the message, or why not.

    Its documentation defines success as the `ok` field rather than as the
    status, so that is what is read. **The `description` it returns beside a
    failure is the endpoint's own free text and is never passed on**, which is
    the same rule `app/webhook.py` follows for an exception message and the
    same reason the agent ships typed causes rather than strings (SI-8).
    """
    try:
        answer = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return "Telegram answered something that is not the JSON it documents"
    if not isinstance(answer, dict):
        return "Telegram answered something that is not the JSON it documents"
    if answer.get("ok") is True:
        return ""
    # **The one field of theirs worth passing on, and it is an integer.**
    # `ResponseParameters.migrate_to_chat_id` is "The group has been migrated
    # to a supergroup with the specified identifier". A stored numeric group id
    # stops working the day the group is upgraded, and without this the channel
    # simply goes quiet with no hint that the id moved. It is an id and not
    # free text, so SI-8's rule about not repeating an endpoint's prose holds.
    parameters = answer.get("parameters")
    if isinstance(parameters, dict):
        moved = parameters.get("migrate_to_chat_id")
        if isinstance(moved, int):
            return ("Telegram says this group moved to a supergroup, and the"
                    f" chat id is now {moved}. Update the channel and it"
                    " delivers again")
    return "Telegram accepted the request and did not send the message"


def target(channel, env=None) -> tuple:
    """(config, extras) for one channel, or a SenderError saying what is wrong.

    `extras` is the keyword arguments `webhook.send` needs beyond the body, so
    every caller passes one thing whatever the channel is.

    The value of the environment variable is read here, used, and never stored
    anywhere. Nothing in the return value carries it except the URL inside the
    Config, whose repr does not print it.
    """
    value = channel.resolve(env)
    if not value:
        raise SenderError(
            f"{channel.destination_env} is not set in this environment, so"
            f" {channel.label} has nowhere to deliver to")

    if channel.type == channels.TYPE_TELEGRAM:
        chat, _ = channels.split_telegram_target(channel.destination_extra)
        if not chat:
            raise SenderError(
                f"{channel.label} is a telegram channel with no chat id, so"
                " there is no chat to post to")
        return (webhook.Config(url=TELEGRAM_API.format(token=value),
                               source_env=channel.destination_env),
                {"check_body": telegram_ok,
                 "max_response_bytes": TELEGRAM_MAX_RESPONSE_BYTES})

    if channel.type == channels.TYPE_DISCORD:
        return (webhook.Config(url=_discord_url(value),
                               source_env=channel.destination_env), {})

    if channel.type in (channels.TYPE_WEBHOOK, channels.TYPE_SLACK):
        return (webhook.Config(url=value,
                               source_env=channel.destination_env), {})

    # A type that reached here is one somebody added to channels.TYPES and did
    # not wire up. Loud, because the alternative is a channel that silently
    # never delivers.
    raise SenderError(f"{channel.type!r} is not a channel this build can send"
                      " to, which is a gap in this build and not in the row")


def body_for(channel, text: str, payload: dict, message=None) -> dict:
    """What this channel's body actually is.

    The webhook keeps the typed document `app/webhook.py` builds, because a
    machine reads it. The three chat channels take the rendered text, each
    under the key its own vendor documents, cut to its own limit. Given the
    `message` the text was rendered from, each also gets its own shape of
    it beside or in place of that text.
    """
    if channel.type == channels.TYPE_WEBHOOK:
        # The typed document whole, and the rendered text beside it under
        # `text`. Mattermost's incoming webhook lists `text` as required "If
        # `attachments` is not set" (developers.mattermost.com, read
        # 2026-09-20), and a body with neither is what answered the owner's Send
        # test with a 400. Additive, so nothing reading the typed keys sees a
        # change, and a typed key of that name would win over this one.
        return {"text": fit(text, WEBHOOK_TEXT_LIMIT), **payload}
    fitted = fit(text, TEXT_LIMITS[channel.type])
    if channel.type == channels.TYPE_SLACK:
        body = {"text": slack_escaped(fitted)}
        if message is not None:
            # `text` stays beside the blocks: it is what a notification on a
            # phone shows.
            body["blocks"] = slack_blocks(message)
        return body
    if channel.type == channels.TYPE_DISCORD:
        # A program's name or a quoted rule is text the server wrote, and
        # with nothing said Discord parses every mention in a message: "all
        # included mentions will be parsed". An empty `parse` is its way to
        # "completely suppress all mentions in the message"
        # (docs.discord.com/developers/resources/message, read 2026-10-03).
        # The text itself is not rewritten: what was measured is said as it
        # is, and it notifies nobody.
        body = {"content": fitted}
        if message is not None:
            # The first line as it always read, then the rest in one embed.
            # The line stays outside the embed so that a reader who has
            # embeds switched off still gets what happened and to which
            # server.
            body["content"] = fit(f"whichports: {message.title}",
                                  DISCORD_TEXT_LIMIT)
            body["embeds"] = [discord_embed(message)]
        body["allowed_mentions"] = {"parse": []}
        return body
    if channel.type == channels.TYPE_TELEGRAM:
        chat, thread = channels.split_telegram_target(channel.destination_extra)
        body = {"chat_id": chat, "text": fitted}
        if message is not None:
            body["text"] = telegram_html(message)
            body["parse_mode"] = "HTML"
            # The last line is the dashboard's address, and a preview of a
            # sign-in page under every alert is noise.
            body["link_preview_options"] = {"is_disabled": True}
        if thread:
            # Documented Integer, so it is sent as one. A forum supergroup
            # needs it to land in the right topic
            # (core.telegram.org/bots/api#sendmessage, read 2026-08-22).
            body["message_thread_id"] = int(thread)
        return body
    raise SenderError(f"{channel.type!r} has no body in this build")


def deliver(channel, text: str, payload: dict, env=None,
            resolver=None, opener=None, message=None) -> tuple[bool, str]:
    """Send one already-rendered alert to one channel. Returns (sent, reason).

    Never raises, for the same reason `webhook.send` does not: the caller is a
    timer and one dead channel must not wedge the sweep that found the problem.
    """
    try:
        config, extras = target(channel, env)
        body = body_for(channel, text, payload, message)
    except SenderError as exc:
        return False, str(exc)
    return webhook.send(body, config, resolver=resolver, opener=opener, **extras)


def deliver_alert(channel, kind: str, host_name: str, detail: str,
                  raised_at: str, env=None, resolver=None,
                  opener=None, display: str = "") -> tuple[bool, str]:
    """The one-line kinds, rendered both ways and sent whichever way fits.
    `display` is the server's display name, or empty."""
    message = message_for_alert(kind, host_name, detail, raised_at, display)
    return deliver(channel, plain(message),
                   webhook.payload_for_alert(kind, host_name, detail, raised_at,
                                             display),
                   env, resolver, opener, message)


def deliver_changes(channel, host_name: str, changes, env=None,
                    resolver=None, opener=None,
                    display: str = "") -> tuple[bool, str]:
    """The coalesced kind, one message per server however many ports moved.
    `display` is the server's display name, or empty."""
    message = message_for_changes(host_name, changes, display)
    return deliver(channel, plain(message),
                   webhook.payload_for_changes(host_name, changes, display),
                   env, resolver, opener, message)


def deliver_test(channel, env=None, resolver=None, opener=None) -> tuple[bool, str]:
    """One short real message, so an operator can watch a channel deliver.

    Sent through exactly the path an alert takes, guarded opener included,
    because a test that goes a different way proves the wrong thing. The body
    says it is a test and names no host, no port and no finding, so nothing
    about the fleet crosses the wire that an alert would not carry.
    """
    message = message_for_test()
    # The same fields payload_for_alert ships, with the kind saying what this
    # is, so a consumer parsing real alerts can tell a test from a finding.
    payload = {"version": webhook.PAYLOAD_VERSION, "kind": "test",
               "detail": TEST_PAYLOAD_DETAIL}
    return deliver(channel, plain(message), payload, env, resolver, opener,
                   message)
