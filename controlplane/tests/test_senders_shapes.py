"""Each chat channel gets the message in its own shape, inside its vendor's limits.

    python -m pytest tests/test_senders_shapes.py

`tests/test_senders_words.py` holds what a message says. This file holds what
a channel is posted: the keys its vendor documents, every limit the vendor
states for the part a line lands in, the characters each vendor parses
written so that it does not, the same labelled values in the same order in
every channel, and a message about a hundred ports no longer than one about
six. The limits are the ones in `app/senders.py`'s docstring, with the page
each was read from.
"""
import html
import json
import re

import pytest

from app import (alerts, alertwords, channels, finding_alerts, join, mailhtml,
                 notify, publicurl, senders)
from test_senders import ENV, FakeOpener, a_channel, resolves_public

ID = "web-07"
RULE = "tcp dport 3000 counter accept in ip filter ufw-user-input"
SILENT_DETAIL = "no report for 35 minutes, past the 35 minute threshold"
STALE_DETAIL = ("no probing pass has finished for web-07 in 7 hours, so what the"
                " screen says about reachability is that old")
# Text a server could write, holding what each vendor parses.
HOSTILE = "<!channel> & <b>bold</b> `tick` @everyone"


def change(number=0, **kw):
    base = dict(where=f"tcp/{3000 + number} on v4", was="intended",
                now=join.STATE_CONFLICT,
                description="Reachable from outside, and you declared it closed.",
                vantage="probe1", measured_at="2026-10-02T10:00:00+00:00",
                port=3000 + number, family="v4", answers=True)
    return notify.Change(**{**base, **kw})


REACHABLE = change(1, was="", now=join.STATE_INTENDED, became_reachable=True,
                   program="python3", program_said="python3", rule=RULE,
                   allowed_by=join.LAYER_HOST_FIREWALL)
FEW = [change(), REACHABLE]
# Far more findings than any message names.
MANY = [change(n, description="word " * 130) for n in range(120)]


def few_said(display="Webshop"):
    return notify.said_changes(ID, FEW, display)


def few(display="Webshop"):
    return senders.message(few_said(display))


def one_port():
    return senders.message(notify.said_changes(ID, [REACHABLE], "Webshop"))


def many():
    return senders.message_for_changes(ID, MANY, "Webshop")


def underscored_said():
    """A server whose ID holds an underscore, and a container with the name
    Docker gives one that was started without a name."""
    return notify.said_changes("web_07", [change(
        now=join.STATE_UNREVIEWED,
        program_said=alertwords.program_words(["quirky_hopper"], container=True))])


def underscored():
    return senders.message(underscored_said())


def silent():
    return senders.message_for_alert(alerts.KIND_SILENT, ID, SILENT_DETAIL,
                                     "2026-10-02T10:00:00+00:00", "Webshop")


def stale():
    return senders.message_for_alert(finding_alerts.KIND_OUTSIDE_STALE, ID,
                                     STALE_DETAIL, "2026-10-02T10:00:00+00:00")


EVERY_KIND = [few, one_port, many, underscored, silent, stale, senders.message_for_test]


def body(channel_type, message, extra=""):
    names = {channels.TYPE_SLACK: "WHICHPORTS_SLACK_URL",
             channels.TYPE_DISCORD: "WHICHPORTS_DISCORD_URL",
             channels.TYPE_TELEGRAM: "WHICHPORTS_TELEGRAM_TOKEN",
             channels.TYPE_WEBHOOK: "WHICHPORTS_SLACK_URL"}
    channel = a_channel(channel_type, names[channel_type], extra)
    return senders.body_for(channel, senders.plain(message), {"kind": "test"},
                            message)


def link_of(message) -> tuple:
    return message.link, message.link_words


# ---------------------------------------------------------------------- Slack

def slack_texts(blocks) -> list:
    """Every piece of text in a list of blocks, with the kind it is."""
    found = []
    for block in blocks:
        if "text" in block:
            found.append((block["type"], block["text"]["text"]))
        for part in block.get("fields", []) + block.get("elements", []):
            found.append((block["type"] + " part", part["text"]))
    return found


def slack_fields(blocks) -> list:
    return [part["text"] for block in blocks for part in block.get("fields", [])]


def slack_text_objects(blocks) -> list:
    """Every text object in a list of blocks, whole."""
    found = []
    for block in blocks:
        if "text" in block:
            found.append(block["text"])
        found += block.get("fields", []) + block.get("elements", [])
    return found


@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_no_slack_text_is_left_for_slack_to_link(build):
    """Slack makes a link of what looks like one unless it is told not to. A
    display name that is a domain was drawn as a link in a field's value
    (docs/RECORD.md 4.409), and no channel may link what a name holds.

    Slack's own page for a text object, read on 2026-10-06: with `verbatim`
    false, the default, "URLs will be auto-converted into links, conversation
    names will be link-ified, and certain mentions will be automatically
    parsed". With it true Slack "will continue to process all markdown
    formatting and manual parsing strings, but it won't modify any plain-text
    content". So every mrkdwn object says so, which keeps the bold labels and
    the one link of ours. The header is plain_text, where Slack reads no
    markup at all."""
    blocks = body(channels.TYPE_SLACK, build())["blocks"]
    objects = slack_text_objects(blocks)
    assert objects
    for text_object in objects:
        if text_object["type"] == "plain_text":
            continue
        assert text_object["type"] == "mrkdwn", text_object
        assert text_object.get("verbatim") is True, text_object
    assert blocks[0]["type"] == "header"
    assert blocks[0]["text"]["type"] == "plain_text"


def test_a_display_name_that_is_a_domain_is_not_left_for_slack_to_link():
    """The message his own channel drew: the server's field read
    `shop.example.com (web-07)` with the first part made a link."""
    message = senders.message(notify.said_changes(ID, [change()], "shop.example.com"))
    blocks = body(channels.TYPE_SLACK, message)["blocks"]
    holding = [o for o in slack_text_objects(blocks) if "shop.example.com" in o["text"]]
    assert holding
    for text_object in holding:
        assert text_object["type"] == "plain_text" or text_object.get("verbatim") is True


@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_slack_gets_blocks_beside_the_whole_text_and_inside_slacks_limits(build):
    message = build()
    posted = body(channels.TYPE_SLACK, message)
    assert set(posted) == {"text", "blocks"}
    # The text a phone's notification shows is the plain message, escaped.
    assert posted["text"] == senders.slack_escaped(
        senders.fit(senders.plain(message), senders.SLACK_TEXT_LIMIT))
    blocks = posted["blocks"]
    assert len(blocks) <= 50
    assert blocks[0]["type"] == "header"
    assert blocks[0]["text"]["type"] == "plain_text"
    assert len(blocks[0]["text"]["text"]) <= 150
    for block in blocks:
        assert block["type"] in ("header", "section", "context")
        if block["type"] == "section" and "text" in block:
            assert 1 <= len(block["text"]["text"]) <= 3000
        assert len(block.get("fields", [])) <= 10
        assert len(block.get("elements", [])) <= 10
        for part in block.get("fields", []):
            assert len(part["text"]) <= 2000


def test_slacks_blocks_read_as_the_message_does():
    message = few()
    blocks = body(channels.TYPE_SLACK, message)["blocks"]
    texts = [text for _kind, text in slack_texts(blocks)]
    assert texts == [
        "whichports: 2 ports changed on Webshop",
        "*server*\nWebshop (web-07)",
        "*reachable*\n3000, 3001",
        "Nothing else will be sent about these ports until they change again.",
        f"<{publicurl.server(ID)}|Open Webshop>"]


def test_the_fields_sit_side_by_side_in_slack():
    """One section's `fields`, which Slack itself sets two to a row."""
    blocks = body(channels.TYPE_SLACK, silent())["blocks"]
    groups = [block["fields"] for block in blocks if "fields" in block]
    assert [[part["text"] for part in group] for group in groups] == [
        ["*server*\nWebshop (web-07)", "*no report for*\n35 minutes"]]
    for group in groups:
        assert all(part["type"] == "mrkdwn" for part in group)


def test_slack_is_handed_nothing_of_a_servers_to_parse_in_any_block():
    # A name that is not plain never becomes `program_said`
    # (tests/test_alert_words.py). Slack's escaping does not lean on that.
    message = senders.message(notify.said_changes(
        ID, [change(program_said=HOSTILE)], HOSTILE[:40]))
    blocks = body(channels.TYPE_SLACK, message)["blocks"]
    for kind, text in slack_texts(blocks):
        if kind == "header":
            continue  # plain_text: Slack parses nothing in it
        if text.startswith(f"<{publicurl.server(ID)}|"):
            # The one link is ours. What sits inside it is escaped too.
            text = text[len(f"<{publicurl.server(ID)}|"):-1]
        assert "<" not in text and ">" not in text, text
    said = " ".join(text for _kind, text in slack_texts(blocks))
    assert "&lt;!channel&gt; &amp; &lt;b&gt;bold&lt;/b&gt;" in said


# -------------------------------------------------------------------- Discord

def embed_total(embeds) -> int:
    """The characters Discord counts against its 6000 across all embeds."""
    total = 0
    for embed in embeds:
        total += len(embed.get("title", "")) + len(embed.get("description", ""))
        total += len(embed.get("footer", {}).get("text", ""))
        total += sum(len(f["name"]) + len(f["value"]) for f in embed.get("fields", []))
    return total


@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_discord_gets_its_first_line_and_embeds_inside_discords_limits(build):
    message = build()
    posted = body(channels.TYPE_DISCORD, message)
    assert set(posted) == {"content", "embeds", "allowed_mentions"}
    assert posted["allowed_mentions"] == {"parse": []}
    assert posted["content"] == f"whichports: {message.title}"
    assert len(posted["content"]) <= 2000
    assert len(posted["embeds"]) == 1
    assert embed_total(posted["embeds"]) <= 6000
    for embed in posted["embeds"]:
        assert "color" not in embed
        assert len(embed.get("title", "")) <= 256
        assert len(embed.get("description", "")) <= 4096
        assert len(embed.get("footer", {}).get("text", "")) <= 2048
        assert len(embed.get("fields", [])) <= 25
        for field in embed.get("fields", []):
            assert 1 <= len(field["name"]) <= 256
            assert 1 <= len(field["value"]) <= 1024


@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_discords_link_label_is_the_one_label_outside_the_thirteen(build):
    """A link under the fields, where the mail has its button, has only a
    field to live in on Discord, and a field has a name: Discord's own page
    gives an embed a title, a description, a url, fields and a footer, and a
    field a name and a value (read on 2026-10-06). So `dashboard` is the
    fourteenth label, Discord's alone (docs/RECORD.md 4.409). It is the last
    field, there is one of it, every other field's name is one of the
    thirteen, and no other channel says the word."""
    message = build()
    assert alertwords.DISCORD_LINK_LABEL == "dashboard"
    assert alertwords.DISCORD_LINK_LABEL not in alertwords.LABELS
    embed = body(channels.TYPE_DISCORD, message)["embeds"][0]
    names = [field["name"] for field in embed["fields"]]
    assert names[-1] == alertwords.DISCORD_LINK_LABEL
    assert names.count(alertwords.DISCORD_LINK_LABEL) == 1
    for name in names[:-1]:
        assert name in alertwords.LABELS, name
    elsewhere = [senders.plain(message), senders.telegram_html(message),
                 json.dumps(body(channels.TYPE_SLACK, message)["blocks"])]
    for text in elsewhere:
        assert alertwords.DISCORD_LINK_LABEL not in text.lower()


def test_no_mail_says_discords_label():
    saids = [notify.said_changes(ID, [change()], "Webshop"),
             notify.said_silence(ID, SILENT_DETAIL),
             notify.said_outside_stale(ID, STALE_DETAIL), notify.said_test()]
    for said in saids:
        for part in notify.mail(said):
            assert alertwords.DISCORD_LINK_LABEL not in part.lower(), said.title


def test_discords_embed_reads_as_the_message_does():
    embed = body(channels.TYPE_DISCORD, one_port())["embeds"][0]
    assert [(field["name"], field["value"]) for field in embed["fields"]] == [
        ("server", "Webshop (web-07)"), ("port", "3001"),
        ("allowed by", "a rule in the server's firewall"), ("program", "python3"),
        ("dashboard", f"[Open Webshop]({publicurl.server(ID)})")]
    assert embed["footer"]["text"] == \
        "Nothing else will be sent about this port until it changes again."
    assert "description" not in embed


@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_discords_link_is_the_last_field_of_the_embed(build):
    """`[words](address)` in a field's value was seen to draw as a link in a
    Discord client on 2026-10-03. It is the one piece of markdown an embed
    of ours holds, so it is held to one place and one form."""
    message = build()
    embed = body(channels.TYPE_DISCORD, message)["embeds"][0]
    link, words = link_of(message)
    assert embed["fields"][-1] == {"name": "dashboard", "value": f"[{words}]({link})"}
    others = json.dumps(embed["fields"][:-1]) + embed.get("description", "")
    assert "](" not in others


def test_the_fields_sit_side_by_side_in_discord_and_the_link_does_not():
    fields = body(channels.TYPE_DISCORD, silent())["embeds"][0]["fields"]
    inline = [(field["name"], field.get("inline", False)) for field in fields]
    assert inline == [("server", True), ("no report for", True), ("dashboard", False)]


# ------------------------------------------------------------------- Telegram

@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_telegram_gets_html_inside_its_limit_with_every_tag_closed(build):
    message = build()
    posted = body(channels.TYPE_TELEGRAM, message, "-100123")
    assert set(posted) == {"chat_id", "text", "parse_mode", "link_preview_options"}
    assert posted["chat_id"] == "-100123"
    assert posted["parse_mode"] == "HTML"
    assert posted["link_preview_options"] == {"is_disabled": True}
    text = posted["text"]
    assert len(text) <= senders.TELEGRAM_TEXT_LIMIT
    for tag in ("b", "code", "a"):
        assert len(re.findall(rf"<{tag}\b", text)) == text.count(f"</{tag}>"), tag
    # Only the tags this writes are left as tags.
    assert re.sub(r"</?(b|code)>|<a href=\"[^\"<>]*\">|</a>", "", text).count("<") == 0
    link, words = link_of(message)
    assert text.split("\n")[-1] == f'<a href="{link}">{words}</a>'


def test_telegram_sets_one_field_a_line_with_its_label_bold():
    text = body(channels.TYPE_TELEGRAM, one_port(), "-100123")["text"]
    assert text.split("\n") == [
        "<b>whichports: Port 3001 on Webshop became reachable from the internet</b>",
        "",
        "<b>server</b>: Webshop (web-07)",
        "<b>port</b>: 3001",
        "<b>allowed by</b>: a rule in the server's firewall",
        "<b>program</b>: python3",
        "",
        "Nothing else will be sent about this port until it changes again.",
        f'<a href="{publicurl.server(ID)}">Open Webshop</a>']


def test_telegram_keeps_the_topic_of_a_forum():
    posted = body(channels.TYPE_TELEGRAM, few(), "-100123:77")
    assert posted["message_thread_id"] == 77


def test_telegram_is_handed_nothing_of_a_servers_to_parse():
    message = senders.message(notify.said_changes(
        ID, [change(program_said=HOSTILE)], HOSTILE[:40]))
    text = body(channels.TYPE_TELEGRAM, message, "-100123")["text"]
    assert "<!channel>" not in text and "<b>bold</b>" not in text
    assert "&lt;!channel&gt; &amp; &lt;b&gt;bold&lt;/b&gt;" in text


# ------------------------------------------------- every channel, one message

def plain_pairs(lines) -> list:
    return [tuple(line.split(": ", 1)) for line in lines if ": " in line]


@pytest.mark.parametrize("said", [few_said(), notify.said_changes(ID, [REACHABLE]),
                                  notify.said_changes(ID, MANY), underscored_said(),
                                  notify.said_silence(ID, SILENT_DETAIL, "Webshop"),
                                  notify.said_outside_stale(ID, STALE_DETAIL),
                                  notify.said_test()],
                         ids=["few", "one port", "many", "underscored", "silent",
                              "stale", "test"])
def test_every_channel_draws_the_same_fields_in_the_same_order(said):
    expected = list(said.fields)
    message = senders.message(said)
    # The mail's two halves.
    _subject, text, designed = notify.mail(said)
    assert plain_pairs(line[2:] for line in text.split("\n")
                       if line.startswith("  ") and "://" not in line) == expected
    seen = html.unescape(re.sub(r"<[^>]+>", " ", designed[designed.index("<body"):]))
    seen = " ".join(seen.split())
    at = 0
    for label, value in expected:
        at = seen.index(f"{label} {value}", at) + 1
    # Slack, Discord and Telegram, the marks each adds taken off.
    slack = [tuple(part.replace("*", "").replace("`", "").split("\n", 1))
             for part in slack_fields(body(channels.TYPE_SLACK, message)["blocks"])]
    assert slack == expected
    embed = body(channels.TYPE_DISCORD, message)["embeds"][0]
    assert [(f["name"], f["value"].replace("`", "")) for f in embed["fields"][:-1]] == expected
    telegram = body(channels.TYPE_TELEGRAM, message, "-100123")["text"]
    assert [(label, value) for label, value in
            re.findall(r"^<b>([^<]+)</b>: (.*)$", telegram, re.M)
            if not label.startswith("whichports")] == expected
    # And the webhook's text.
    assert plain_pairs(senders.plain(message).split("\n")[1:-1]) == expected


@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_no_message_has_more_fields_than_slack_takes(build):
    """A section's `fields` holds ten at most
    (docs.slack.dev/reference/block-kit/blocks/section-block/, read
    2026-10-03). No kind comes near it, and this is what says so."""
    assert len(build().fields) <= 6


def test_a_message_about_many_ports_is_no_longer_than_one_about_six():
    """A hundred and twenty ports are a count and five numbers, so no shape
    has anything to leave out."""
    message = many()
    assert message.title == "120 ports changed on Webshop"
    assert message.fields == (
        ("server", "Webshop (web-07)"),
        ("reachable", "3000, 3001, 3002, 3003, 3004 and 115 more"))
    assert len(body(channels.TYPE_SLACK, message)["blocks"]) == 3
    assert len(body(channels.TYPE_DISCORD, message)["embeds"][0]["fields"]) == 3
    assert len(body(channels.TYPE_TELEGRAM, message, "-100123")["text"]) < 400
    assert "word word" not in senders.plain(message)


# ------------------------------------------------------------- an underscore
#
# Slack and Discord both read a pair of underscores as italics, and neither
# names an escape for one (the spec's rule 3.6 holds the pages). A server's
# ID may hold an underscore, and Docker names a container with one when it
# is started without a name.

def test_a_value_with_an_underscore_is_between_backticks_in_slack_and_discord():
    message = underscored()
    assert dict(message.fields)["program"] == "container quirky_hopper"
    slack = slack_fields(body(channels.TYPE_SLACK, message)["blocks"])
    assert "*server*\n`web_07`" in slack
    assert "*program*\n`container quirky_hopper`" in slack
    # A value without one is as it was.
    assert "*port*\n3000" in slack
    embed = body(channels.TYPE_DISCORD, message)["embeds"][0]
    named = {field["name"]: field["value"] for field in embed["fields"]}
    assert named["server"] == "`web_07`"
    assert named["program"] == "`container quirky_hopper`"
    assert named["port"] == "3000"
    # Telegram's HTML style, the mail and the webhook's text read no markup
    # in an underscore, so there the value is as it is.
    telegram = body(channels.TYPE_TELEGRAM, message, "-100123")["text"]
    assert "<b>program</b>: container quirky_hopper" in telegram
    assert "program: container quirky_hopper" in senders.plain(message)
    assert "`" not in notify.text_of(underscored_said())
    assert "`" not in mailhtml.alert(underscored_said())


def test_no_underscore_reaches_slack_or_discord_outside_backticks():
    """In a field's value. The title and the words on the link also name the
    server and are not values: what the two channels draw for an underscore
    there is seen in real samples, not held here."""
    message = senders.message(notify.said_changes(
        "my_web_07", [change(program_said=alertwords.program_words(
            ["my_project_web_1", "db_1"], container=True))], "Shop_one"))
    outside = re.compile(r"`[^`]*`")
    for part in slack_fields(body(channels.TYPE_SLACK, message)["blocks"]):
        _label, value = part.split("\n", 1)
        assert "_" not in outside.sub("", value), part
    embed = body(channels.TYPE_DISCORD, message)["embeds"][0]
    for field in embed["fields"][:-1]:
        assert "_" not in outside.sub("", field["value"]), field
        assert len(field["value"]) <= 1024


def test_a_hostile_program_and_display_name_through_every_shape():
    """The rule on a program's name is the first line: such a name is never
    said. Each shape escapes all the same, so this hands every one of them
    the name as if that rule had failed, with a display name beside it."""
    assert alertwords.program_words([HOSTILE]) == ""
    assert alertwords.program_words([HOSTILE], container=True) == ""
    said = notify.said_changes(ID, [change(program_said=HOSTILE)], HOSTILE[:40])
    message = senders.message(said)
    _subject, _text, designed = notify.mail(said)
    assert "<b>bold</b>" not in designed and "&lt;b&gt;bold&lt;/b&gt;" in designed
    slack = body(channels.TYPE_SLACK, message)
    for _kind, text in slack_texts(slack["blocks"])[1:]:
        assert "<!channel>" not in text and "<b>" not in text
    assert "<!channel>" not in slack["text"]
    discord = body(channels.TYPE_DISCORD, message)
    assert discord["allowed_mentions"] == {"parse": []}
    assert "](" not in json.dumps(discord["embeds"][0]["fields"][:-1])
    telegram = body(channels.TYPE_TELEGRAM, message, "-100123")["text"]
    assert "<b>bold</b>" not in telegram and "<!channel>" not in telegram


# ---------------------------------------------------------- what did not move

@pytest.mark.parametrize("build", EVERY_KIND, ids=lambda f: f.__name__)
def test_the_webhook_is_the_plain_text_and_the_typed_fields_as_before(build):
    message = build()
    posted = body(channels.TYPE_WEBHOOK, message)
    assert posted == {"text": senders.fit(senders.plain(message),
                                          senders.WEBHOOK_TEXT_LIMIT),
                      "kind": "test"}


@pytest.mark.parametrize("channel_type, key", [
    (channels.TYPE_SLACK, "text"), (channels.TYPE_DISCORD, "content"),
    (channels.TYPE_TELEGRAM, "text")])
def test_a_text_with_no_message_behind_it_is_posted_as_text(channel_type, key):
    """`deliver` may still be handed a text alone. Then nothing is shaped."""
    names = {channels.TYPE_SLACK: "WHICHPORTS_SLACK_URL",
             channels.TYPE_DISCORD: "WHICHPORTS_DISCORD_URL",
             channels.TYPE_TELEGRAM: "WHICHPORTS_TELEGRAM_TOKEN"}
    posted = senders.body_for(a_channel(channel_type, names[channel_type], "-100123"),
                              "hello", {})
    assert posted[key] == "hello"
    for shaped in ("blocks", "embeds", "parse_mode"):
        assert shaped not in posted


def test_every_kind_the_sweep_sends_arrives_shaped():
    """Through `deliver_alert`, `deliver_changes` and `deliver_test`, the
    three ways a message leaves, and not only through `body_for`."""
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    sends = (
        lambda opener: senders.deliver_alert(
            channel, alerts.KIND_SILENT, ID, SILENT_DETAIL, "2026-10-02T10:00:00+00:00",
            ENV, resolver=resolves_public, opener=opener),
        lambda opener: senders.deliver_changes(
            channel, ID, FEW, ENV, resolver=resolves_public, opener=opener),
        lambda opener: senders.deliver_test(
            channel, ENV, resolver=resolves_public, opener=opener),
    )
    for send in sends:
        opener = FakeOpener()
        ok, reason = send(opener)
        assert ok is True, reason
        assert opener.body_sent["blocks"][0]["type"] == "header"
        json.dumps(opener.body_sent)
