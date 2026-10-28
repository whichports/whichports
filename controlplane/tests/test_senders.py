"""Slack, Telegram and Discord, and what each one actually puts on the wire.

    python -m pytest tests/test_senders.py

**No test here opens a socket**, the same rule `tests/test_webhook.py` states:
the resolver and the opener are arguments, so the real logic runs against
stand-ins and nothing in this repository connects to Slack, Telegram or Discord
to prove a guard works.

The three that matter most, because they are the ones that would be expensive
to find in production:

  - **The bot token never appears in anything a person or a log can read.**
    Telegram puts its credential in the URL path, so the usual "do not print
    the URL" rule stops being a nicety.
  - **A key is one destination.** `docs/RECORD.md` 4.87 records the delivery
    key being keyed on the wrong thing and two webhooks getting one post. Two
    Telegram chats behind one token are the same trap one level further in.
  - **An existing webhook row's key does not change spelling**, or every open
    alert on the box looks undelivered and goes out a second time.
"""

import json
import re
from datetime import datetime, timezone

import pytest

from app import alerts, alertwords, channels, db, notify, publicurl, senders, webhook

from app import outbound  # noqa: E402

# The two ways a refused address is said (app/outbound.py).
REFUSALS = (outbound.REFUSED_AS_PRIVATE, outbound.REFUSED_ALWAYS)

NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)

# A shape like a real bot token, and nothing that was ever issued. It is here
# so a test can assert it does not leak, which needs something distinctive.
TOKEN = "123456:AA-NOT-A-REAL-TOKEN-nEvErIsSuEd-0000"
SLACK_URL = "https://hooks.slack.com/services/T00/B00/XXXX"
DISCORD_URL = "https://discord.com/api/webhooks/12345/abcdefSECRET"

ENV = {
    "WHICHPORTS_SLACK_URL": SLACK_URL,
    "WHICHPORTS_DISCORD_URL": DISCORD_URL,
    "WHICHPORTS_TELEGRAM_TOKEN": TOKEN,
    "WHICHPORTS_WEBHOOK_URL": "https://hooks.example.com/T00/SECRET",
}

PUBLIC = ["185.199.108.153"]
PRIVATE = ["10.0.0.5"]


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    alerts.init(connection)
    channels.init(connection)
    yield connection
    connection.close()


def a_channel(channel_type, env_name, extra=""):
    """A row without a database, for the tests that only need its fields."""
    return channels.Channel(id=1, type=channel_type, label=f"ops {channel_type}",
                            destination_env=env_name, enabled=True,
                            destination_extra=extra)


class FakeOpener:
    """Records what would go on the wire and answers with a status and a body."""

    def __init__(self, status=200, body=b""):
        self.status = status
        self.body = body
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        outer = self

        class Response:
            status = outer.status

            def read(self_inner, n=None):
                return outer.body if n is None else outer.body[:n]

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

        return Response()

    @property
    def body_sent(self):
        return json.loads(self.requests[-1].data.decode("utf-8"))

    @property
    def url_sent(self):
        return self.requests[-1].full_url


def resolves_public(host):
    return PUBLIC


CHANGES = [
    notify.Change(where="tcp/443 on v4", was="intended", now="conflict",
                  description="answered from outside and you marked it closed",
                  port=443, family="v4", answers=True),
    notify.Change(where="tcp/22 on v4", was="", now="unreviewed",
                  description="answered from outside, nobody has said whether"
                              " that is intended",
                  port=22, family="v4", answers=True),
]


# ----------------------------------------------------------------- the text

def test_a_one_line_alert_carries_the_facts_and_nothing_more():
    text = senders.text_for_alert(
        alerts.KIND_SILENT, "almabox",
        "no report for 41 minutes, past the 35 minute threshold", "2026-08-22T11:00:00")
    assert text.split("\n") == [
        "whichports: almabox stopped reporting",
        "server: almabox",
        "no report for: 41 minutes",
        "Nothing else will be sent about this server until it reports again.",
        publicurl.server("almabox")]
    # How long, and never the moment: no message carries a time.
    assert "2026-08-22T11:00:00" not in text


def test_a_kind_with_no_words_is_named_and_nothing_is_made_up_for_it():
    text = senders.text_for_alert("agent sleepy", "almabox",
                                  "last report 41 minutes ago", "2026-08-22T11:00:00")
    assert text.split("\n") == ["whichports: almabox, agent sleepy",
                                "server: almabox", publicurl.server("almabox")]


def test_one_port_is_named_and_two_are_counted():
    one = senders.text_for_changes("one", CHANGES[:1])
    two = senders.text_for_changes("one", CHANGES)
    assert one.split("\n")[0] == "whichports: Port 443 on one is reachable from the internet"
    assert two.split("\n")[0] == "whichports: 2 ports changed on one"


def test_every_changed_port_reaches_the_text_and_no_sentence_about_it_does():
    text = senders.text_for_changes("one", CHANGES)
    assert "reachable: 22, 443" in text
    for change in CHANGES:
        # The engine's sentence and the state words are on the server's page.
        assert change.description not in text
    assert "intended" not in text and "conflict" not in text


def test_a_port_with_no_previous_state_reads_as_any_other():
    text = senders.text_for_changes("one", CHANGES[1:])
    assert "you said: nothing yet" in text
    assert "state" not in text and "was , now" not in text


# ------------------------------------------------------------------- fit()

def test_a_short_message_is_untouched():
    assert senders.fit("short", 100) == "short"


def test_a_message_exactly_at_the_limit_is_untouched():
    text = "x" * 50
    assert senders.fit(text, 50) == text


@pytest.mark.parametrize("limit", [120, 300, 2000, 4096])
def test_a_cut_message_never_exceeds_the_limit(limit):
    """The bound is the vendor's, so going one character over is the whole
    failure this function exists to prevent."""
    text = "y" * (limit * 3)
    assert len(senders.fit(text, limit)) <= limit


def test_a_cut_message_says_it_was_cut_and_where_to_read_the_rest():
    text = "z" * 5000
    out = senders.fit(text, 2000)
    assert "cut" in out
    assert publicurl.dashboard() in out


def test_a_cut_message_names_how_much_is_missing():
    out = senders.fit("z" * 5000, 2000)
    # The number in the notice is a real count of dropped characters, not a
    # decoration: a reader deciding whether to open the dashboard needs it.
    digits = [int(part) for part in out.replace("[", " ").replace(",", " ").split()
              if part.isdigit()]
    assert any(0 < d < 5000 for d in digits)


def test_a_limit_too_small_to_hold_the_notice_refuses_rather_than_misleads():
    with pytest.raises(senders.SenderError):
        senders.fit("z" * 500, 10)


# ------------------------------------------------------------- the bodies

def test_slack_sends_the_key_slack_documents():
    body = senders.body_for(a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL"),
                            "hello", {"ignored": True})
    assert body == {"text": "hello"}


def test_discord_sends_the_key_discord_documents():
    body = senders.body_for(a_channel(channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL"),
                            "hello", {"ignored": True})
    assert body == {"content": "hello", "allowed_mentions": {"parse": []}}


def test_telegram_sends_the_chat_id_beside_the_text():
    body = senders.body_for(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"),
        "hello", {"ignored": True})
    assert body == {"chat_id": "-100123", "text": "hello"}


def test_the_webhook_sends_the_typed_document_whole_and_the_text_beside_it():
    """The webhook is read by a machine, so every typed key stays exactly as
    it was and nothing already consuming it sees a changed value.

    `text` is added beside them since 2026-09-20. The owner pointed a generic
    webhook at Mattermost and Send test said "the endpoint answered 400".
    Mattermost's incoming webhook page, read that day, lists `text` as
    required "If `attachments` is not set", and the typed document has
    neither (docs/RECORD.md 4.189)."""
    payload = webhook.payload_for_alert("agent silent", "one", "detail", "2026")
    body = senders.body_for(a_channel(channels.TYPE_WEBHOOK, "WHICHPORTS_WEBHOOK_URL"),
                            "the text", payload)
    assert {key: body[key] for key in payload} == payload
    assert set(body) == set(payload) | {"text"}
    assert body["text"] == "the text"


def test_the_webhooks_text_never_replaces_a_typed_key():
    """A typed key called `text` does not exist today. If one is ever added,
    the document's own value must win and this test says so first."""
    body = senders.body_for(a_channel(channels.TYPE_WEBHOOK, "WHICHPORTS_WEBHOOK_URL"),
                            "rendered", {"version": 1, "text": "typed"})
    assert body["text"] == "typed"


def test_the_webhooks_text_is_cut_like_any_other():
    body = senders.body_for(a_channel(channels.TYPE_WEBHOOK, "WHICHPORTS_WEBHOOK_URL"),
                            "x" * 10000, {"version": 1})
    assert len(body["text"]) <= senders.WEBHOOK_TEXT_LIMIT


def test_the_test_message_to_a_webhook_carries_text(monkeypatch):
    sent = {}

    def fake_send(payload, config, **_kwargs):
        sent.update(payload)
        return True, "sent"

    monkeypatch.setattr(senders.webhook, "send", fake_send)
    channel = a_channel(channels.TYPE_WEBHOOK, "WHICHPORTS_WEBHOOK_URL")
    senders.deliver_test(channel, {"WHICHPORTS_WEBHOOK_URL": "https://hooks.example.org/x"})
    assert sent.get("kind") == "test"
    assert "Test message" in sent.get("text", "")


def test_discord_body_is_cut_to_discords_own_limit():
    body = senders.body_for(a_channel(channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL"),
                            "d" * 9000, {})
    assert len(body["content"]) <= senders.DISCORD_TEXT_LIMIT


def test_telegram_body_is_cut_to_telegrams_own_limit():
    body = senders.body_for(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"),
        "t" * 9000, {})
    assert len(body["text"]) <= senders.TELEGRAM_TEXT_LIMIT


def test_the_two_vendor_limits_are_the_numbers_they_publish():
    """Read from the vendors' own documentation on 2026-08-22, cited in
    app/senders.py. A change to either of these is a claim about somebody
    else's API and should have to be deliberate."""
    assert senders.DISCORD_TEXT_LIMIT == 2000
    assert senders.TELEGRAM_TEXT_LIMIT == 4096


# ---------------------------------------------------------------- the URLs

def test_slack_posts_to_exactly_what_the_operator_configured():
    config, extras = senders.target(
        a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL"), ENV)
    assert config.url == SLACK_URL
    assert extras == {}


def test_discord_asks_to_be_told_whether_the_message_was_saved():
    """Discord's default does not report a message that was not saved, and we
    record a delivery and never send that alert to that destination again."""
    config, _ = senders.target(
        a_channel(channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL"), ENV)
    assert config.url.startswith(DISCORD_URL)
    assert "wait=true" in config.url


def test_a_discord_url_that_already_has_a_query_keeps_it_and_stays_one_url():
    channel = a_channel(channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL")
    config, _ = senders.target(
        channel, {"WHICHPORTS_DISCORD_URL": DISCORD_URL + "?thread_id=9"})
    assert config.url.count("?") == 1
    assert "thread_id=9" in config.url
    assert "wait=true" in config.url


def test_telegram_builds_the_url_telegram_documents():
    config, extras = senders.target(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"), ENV)
    assert config.url == f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    assert extras["check_body"] is senders.telegram_ok


def test_telegram_reads_enough_of_the_answer_to_parse_it():
    """Its success reply echoes the message we sent, so a 4096 byte bound would
    cut it, and a cut body would be read as a delivery that failed."""
    _, extras = senders.target(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"), ENV)
    assert extras["max_response_bytes"] > senders.TELEGRAM_TEXT_LIMIT * 4


# ------------------------------------------------- the token does not leak

def test_the_bot_token_is_not_in_the_config_repr():
    config, _ = senders.target(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"), ENV)
    assert TOKEN not in repr(config)


def test_the_bot_token_is_not_in_a_refusal_when_the_endpoint_is_unreachable():
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    ok, reason = senders.deliver(channel, "text", {}, ENV,
                                 resolver=lambda h: PRIVATE)
    assert ok is False
    assert TOKEN not in reason


def test_the_bot_token_is_not_in_a_refusal_when_telegram_says_no():
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    opener = FakeOpener(body=json.dumps({"ok": False, "description": "x"}).encode())
    ok, reason = senders.deliver(channel, "text", {}, ENV,
                                 resolver=resolves_public, opener=opener)
    assert ok is False
    assert TOKEN not in reason


def test_a_channel_repr_carries_no_credential():
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    printed = repr(channel)
    assert TOKEN not in printed
    # The variable's name is not a secret and an operator debugging a quiet
    # channel needs it.
    assert "WHICHPORTS_TELEGRAM_TOKEN" in printed


# ------------------------------------------------------ telegram's envelope

def test_telegram_saying_ok_is_a_delivery():
    assert senders.telegram_ok(json.dumps({"ok": True, "result": {}}).encode()) == ""


def test_telegram_saying_not_ok_is_not_a_delivery():
    assert senders.telegram_ok(json.dumps({"ok": False}).encode()) != ""


def test_telegrams_own_error_text_is_never_passed_on():
    """SI-8's posture. An endpoint's free text is not ours to repeat and not
    ours to trust."""
    body = json.dumps({"ok": False,
                       "description": "Bad Request: chat not found"}).encode()
    complaint = senders.telegram_ok(body)
    assert "chat not found" not in complaint
    assert "Bad Request" not in complaint


@pytest.mark.parametrize("body", [b"", b"not json", b"[1,2,3]", b"null", b"\xff\xfe"])
def test_an_answer_that_is_not_the_documented_shape_is_not_a_delivery(body):
    assert senders.telegram_ok(body) != ""


def test_a_two_hundred_with_a_refusal_inside_it_is_not_recorded_as_sent():
    """Telegram documents success as the ok field rather than as the status, so
    reading the status alone would record a message nobody received."""
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    opener = FakeOpener(status=200, body=json.dumps({"ok": False}).encode())
    ok, _ = senders.deliver(channel, "text", {}, ENV,
                            resolver=resolves_public, opener=opener)
    assert ok is False


# --------------------------------------------------------- what is refused

def test_a_channel_whose_variable_is_unset_says_which_variable():
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    ok, reason = senders.deliver(channel, "text", {}, {})
    assert ok is False
    assert "WHICHPORTS_SLACK_URL" in reason


def test_a_telegram_channel_with_no_chat_id_has_nowhere_to_post():
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "")
    ok, reason = senders.deliver(channel, "text", {}, ENV)
    assert ok is False
    assert "chat" in reason


def test_a_type_nobody_wired_up_is_loud_rather_than_quiet():
    """A channel that silently never delivers is the monitoring tool failing
    quietly, which is what docs/PRODUCT.md 4c exists to prevent."""
    channel = a_channel("carrier pigeon", "WHICHPORTS_SLACK_URL")
    ok, reason = senders.deliver(channel, "text", {}, ENV)
    assert ok is False
    assert "carrier pigeon" in reason


def test_every_sending_type_can_actually_be_sent_to():
    """The other half of the test above. A type in SENDING_TYPES that target()
    does not know is a row an operator can create and nothing can deliver."""
    for channel_type in channels.SENDING_TYPES:
        extra = "-100123" if channel_type == channels.TYPE_TELEGRAM else ""
        env_name = {
            channels.TYPE_WEBHOOK: "WHICHPORTS_WEBHOOK_URL",
            channels.TYPE_SLACK: "WHICHPORTS_SLACK_URL",
            channels.TYPE_DISCORD: "WHICHPORTS_DISCORD_URL",
            channels.TYPE_TELEGRAM: "WHICHPORTS_TELEGRAM_TOKEN",
        }[channel_type]
        config, _ = senders.target(a_channel(channel_type, env_name, extra), ENV)
        assert config.url


def test_a_destination_on_this_box_is_refused_for_every_channel_type():
    """app/webhook.py's check, reached through every sender rather than only
    through the one it was written for."""
    for channel_type, extra in ((channels.TYPE_SLACK, ""),
                                (channels.TYPE_DISCORD, ""),
                                (channels.TYPE_WEBHOOK, "")):
        channel = a_channel(channel_type, "WHICHPORTS_SLACK_URL", extra)
        ok, reason = senders.deliver(channel, "text", {}, ENV,
                                     resolver=lambda h: PRIVATE)
        assert ok is False
        assert reason.endswith(REFUSALS)


def test_delivery_never_raises_whatever_the_row_says():
    """The caller is a timer. One broken channel must not wedge the sweep that
    found the problem."""
    for channel in (a_channel("nonsense", "WHICHPORTS_SLACK_URL"),
                    a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", ""),
                    a_channel(channels.TYPE_SLACK, "WHICHPORTS_NOT_SET")):
        ok, reason = senders.deliver(channel, "text", {}, ENV)
        assert ok is False
        assert reason


# ------------------------------------------------------- end to end, no socket

def test_slack_gets_the_text_at_the_url_it_was_given():
    opener = FakeOpener()
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    ok, _ = senders.deliver_alert(channel, "agent silent", "one", "quiet",
                                  "2026-08-22T11:00:00", ENV,
                                  resolver=resolves_public, opener=opener)
    assert ok is True
    assert opener.url_sent == SLACK_URL
    assert "one" in opener.body_sent["text"]


def test_telegram_gets_the_chat_id_and_the_text():
    opener = FakeOpener(body=json.dumps({"ok": True}).encode())
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    ok, _ = senders.deliver_changes(channel, "one", CHANGES, ENV,
                                    resolver=resolves_public, opener=opener)
    assert ok is True
    assert opener.body_sent["chat_id"] == "-100123"
    assert "2 ports changed on one" in opener.body_sent["text"]


def test_discord_gets_the_content_key():
    opener = FakeOpener(status=204)
    channel = a_channel(channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL")
    ok, _ = senders.deliver_changes(channel, "one", CHANGES, ENV,
                                    resolver=resolves_public, opener=opener)
    assert ok is True
    assert "one" in opener.body_sent["content"]


SLACK_PARSES = ["<!channel>", "<!here>", "<@U012AB3CD>", "<#C0838UC2D|general>",
                "<https://example.org|a link>", "a & b", "ip saddr > 10"]


@pytest.mark.parametrize("written", SLACK_PARSES)
def test_slack_is_never_handed_a_servers_text_to_parse(written):
    """Slack parses &, < and > in a message, and its page says to write them
    as entities. The sentence the engine wrote about a port and the detail
    of an alert quote the server, and neither reaches a message any more.
    A name somebody typed for a server does, and none of the three is left
    in it as it was written."""
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    changes = [notify.Change(where="tcp/80 on v4", was="", now="unreviewed",
                             description=f"The host is listening: {written} on 0.0.0.0.",
                             port=80, family="v4", answers=True)]
    escaped = (written.replace("&", "&amp;").replace("<", "&lt;")
               .replace(">", "&gt;"))

    def sends(display):
        return (
            lambda opener: senders.deliver_alert(
                channel, "silent", "one", f"quiet, {written}", "2026-08-22T11:00:00",
                ENV, resolver=resolves_public, opener=opener, display=display),
            lambda opener: senders.deliver_changes(
                channel, "one", changes, ENV, resolver=resolves_public,
                opener=opener, display=display),
        )

    for send in sends(""):
        opener = FakeOpener()
        ok, reason = send(opener)
        assert ok is True, reason
        text = opener.body_sent["text"]
        assert "<" not in text and ">" not in text
        assert written not in text and escaped not in text
    for send in sends(written):
        opener = FakeOpener()
        ok, reason = send(opener)
        assert ok is True, reason
        text = opener.body_sent["text"]
        assert "<" not in text and ">" not in text
        assert escaped in text
        # Every ampersand left is the start of one of the three entities.
        assert len(re.findall(r"&(?!amp;|lt;|gt;)", text)) == 0


def test_the_ampersand_is_escaped_once():
    assert senders.slack_escaped("a & <b> &amp; c") == \
        "a &amp; &lt;b&gt; &amp;amp; c"


def test_a_slack_text_without_the_three_characters_is_what_it_was():
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    text = senders.text_for_alert("silent", "one", "quiet", "2026-08-22T11:00:00")
    assert senders.body_for(channel, text, {}) == {"text": text}


def test_only_slack_gets_the_entities():
    """They are Slack's. Discord, Telegram and the webhook are posted the
    text as it is, as before."""
    for channel_type, env_name, extra, key in (
            (channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL", "", "content"),
            (channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123", "text"),
            (channels.TYPE_WEBHOOK, "WHICHPORTS_SLACK_URL", "", "text")):
        body = senders.body_for(a_channel(channel_type, env_name, extra),
                                "a & <b>", {})
        assert body[key] == "a & <b>", channel_type


def discord_bodies_of_every_kind(program: str) -> dict:
    """What Discord is posted for each kind of message, with `program` as
    the text a server controls: the sentence under a port, and the detail."""
    channel = a_channel(channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL")
    changes = [notify.Change(where="tcp/80 on v4", was="", now="unreviewed",
                             description=f"The host is listening: {program} on 0.0.0.0.",
                             port=80, family="v4", answers=True, program=program,
                             program_said=alertwords.program_words([program]))]
    sends = {
        "alert": lambda opener: senders.deliver_alert(
            channel, "silent", "one", f"quiet, {program}", "2026-08-22T11:00:00",
            ENV, resolver=resolves_public, opener=opener, display=program),
        "changes": lambda opener: senders.deliver_changes(
            channel, "one", changes, ENV, resolver=resolves_public, opener=opener),
        "test": lambda opener: senders.deliver_test(
            channel, ENV, resolver=resolves_public, opener=opener),
    }
    bodies = {}
    for kind, send in sends.items():
        opener = FakeOpener(status=204)
        ok, reason = send(opener)
        assert ok is True, reason
        bodies[kind] = opener.body_sent
    return bodies


@pytest.mark.parametrize("program", ["@everyone", "@here", "<@&1234>", "<@5678>"])
def test_no_discord_message_of_ours_mentions_anybody(program):
    """A program's name is the server's own text. With nothing said Discord
    parses every mention in a message, so every body says to parse none."""
    bodies = discord_bodies_of_every_kind(program)
    assert set(bodies) == {"alert", "changes", "test"}
    for kind, body in bodies.items():
        assert body["allowed_mentions"] == {"parse": []}, kind
    # A name somebody typed for a server is said as it is, not rewritten,
    # which is why every body says to parse no mention.
    assert program in json.dumps(bodies["alert"]["embeds"], ensure_ascii=False)
    # A program's name that is not plain is not said at all.
    assert program not in json.dumps(bodies["changes"], ensure_ascii=False)


def test_only_discord_bodies_carry_the_mentions_field():
    """It is Discord's field. Slack, Telegram and the webhook get the bodies
    they always got."""
    for channel_type, env_name, extra in (
            (channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL", ""),
            (channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"),
            (channels.TYPE_WEBHOOK, "WHICHPORTS_SLACK_URL", "")):
        body = senders.body_for(a_channel(channel_type, env_name, extra),
                                "hello", {"kind": "test"})
        assert "allowed_mentions" not in body, channel_type


def test_a_post_is_a_post_and_says_it_is_json():
    opener = FakeOpener()
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    senders.deliver(channel, "text", {}, ENV,
                    resolver=resolves_public, opener=opener)
    request = opener.requests[-1]
    assert request.method == "POST"
    assert request.headers["Content-type"] == "application/json"


# ------------------------------------------------------------ the delivery key

def test_a_webhook_rows_key_is_spelled_exactly_as_it_always_was():
    """The one that would be expensive. Changing this spelling makes every open
    alert on the box look undelivered and posts it a second time
    (docs/RECORD.md 4.87)."""
    assert alerts.channel_key("webhook", "WHICHPORTS_WEBHOOK_URL") == \
        "webhook:WHICHPORTS_WEBHOOK_URL"
    assert alerts.webhook_channel("WHICHPORTS_WEBHOOK_URL") == \
        alerts.channel_key("webhook", "WHICHPORTS_WEBHOOK_URL")


def test_the_type_is_part_of_the_key():
    """Two rows naming one variable but of two types are two destinations, and
    a shared key would deliver to one of them and mark both done."""
    assert alerts.channel_key("slack", "WHICHPORTS_X") != \
        alerts.channel_key("webhook", "WHICHPORTS_X")


def test_two_telegram_chats_behind_one_token_are_two_destinations():
    """The 4.87 trap one level further in: the token is not the destination."""
    first = alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    second = alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100999")
    assert first != second


def test_two_rows_on_one_chat_are_one_destination():
    """The other direction, and the reason the key is not the row id: adding a
    second row for a chat already configured must not re-post every open alert."""
    assert alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123") == \
        alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123")


def test_the_type_prefix_is_what_a_screen_reads_back():
    """site/app/render_live.py names the channel by splitting the key on the
    first colon, so a three part telegram key still reads as telegram."""
    key = alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    assert key.split(":", 1)[0] == "telegram"


# ----------------------------------------------------------------- the rows

def test_every_type_has_a_rule():
    """A type added without one would accept anything in the extra field, which
    is the field that exists to be narrow."""
    for channel_type in channels.TYPES:
        assert channel_type in channels.TYPE_RULES


def test_the_new_types_can_be_stored(con):
    for channel_type, env_name, extra in (
            (channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL", ""),
            (channels.TYPE_DISCORD, "WHICHPORTS_DISCORD_URL", ""),
            (channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123")):
        stored = channels.add(con, channel_type, f"ops {channel_type}", env_name,
                              now=NOW, destination_extra=extra)
        assert stored.type == channel_type
        assert stored.destination_extra == extra


def test_a_telegram_channel_without_a_chat_id_is_refused_at_the_door(con):
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_TELEGRAM, "ops", "WHICHPORTS_TELEGRAM_TOKEN",
                     now=NOW)


@pytest.mark.parametrize("chat_id", [
    "https://example.com/hook",          # a URL is not a chat
    "not a chat id",
    "-",
    "12 34",
    "@",
    "1" * 40,                            # past the bound this module sets
])
def test_a_chat_id_that_is_not_one_is_refused(con, chat_id):
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_TELEGRAM, "ops", "WHICHPORTS_TELEGRAM_TOKEN",
                     now=NOW, destination_extra=chat_id)


@pytest.mark.parametrize("chat_id", ["-1001234567890", "123456", "@whichports_ops"])
def test_the_chat_id_forms_telegram_documents_are_accepted(con, chat_id):
    # The label is not built from the chat id, because a label may not hold an
    # @ and an @name is one of the two forms Telegram documents. The two fields
    # have different rules and this test is about the chat id.
    stored = channels.add(con, channels.TYPE_TELEGRAM, f"ops {abs(hash(chat_id)) % 999}",
                          "WHICHPORTS_TELEGRAM_TOKEN", now=NOW,
                          destination_extra=chat_id)
    assert stored.destination_extra == chat_id


def test_a_type_with_no_second_field_refuses_one_rather_than_dropping_it(con):
    """Storing it and ignoring it would hide that the operator believes
    something about this row that is not true."""
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_SLACK, "ops", "WHICHPORTS_SLACK_URL",
                     now=NOW, destination_extra="-100123")


def test_a_refusal_never_echoes_what_was_typed(con):
    """The same rule the variable name follows: a value that is refused by its
    shape has its shape printed, not itself."""
    try:
        channels.add(con, channels.TYPE_TELEGRAM, "ops", "WHICHPORTS_TELEGRAM_TOKEN",
                     now=NOW, destination_extra=TOKEN)
    except channels.ChannelError as exc:
        assert TOKEN not in str(exc)
    else:
        raise AssertionError("a bot token in the chat id field should be refused")


def test_the_extra_survives_a_round_trip_through_the_database(con):
    channels.add(con, channels.TYPE_TELEGRAM, "ops", "WHICHPORTS_TELEGRAM_TOKEN",
                 now=NOW, destination_extra="-100123")
    read = channels.live(con, channels.TYPE_TELEGRAM)[0]
    assert read.destination_extra == "-100123"


def test_a_database_written_before_this_column_existed_gains_it(tmp_path):
    """Production has this table without the column. The ALTER is the way
    db.init and alerts.init do it, and this proves it rather than assuming."""
    path = str(tmp_path / "old.db")
    con = db.connect(path)
    con.executescript("""
        CREATE TABLE notification_channels (
            id INTEGER PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
            destination_env TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL, removed_at TEXT);
    """)
    con.execute("INSERT INTO notification_channels (type, label,"
                " destination_env, enabled, created_at)"
                " VALUES ('webhook', 'old row', 'WHICHPORTS_WEBHOOK_URL', 1, ?)",
                (NOW.isoformat(),))
    con.commit()

    channels.init(con)
    rows = channels.live(con)
    assert len(rows) == 1
    assert rows[0].label == "old row"
    assert rows[0].destination_extra == ""

    # And twice, because the sweep calls init on every run.
    channels.init(con)
    assert len(channels.live(con)) == 1
    con.close()


def test_sending_lists_each_type_separately(con):
    channels.add(con, channels.TYPE_SLACK, "ops slack", "WHICHPORTS_SLACK_URL", now=NOW)
    channels.add(con, channels.TYPE_TELEGRAM, "ops tg", "WHICHPORTS_TELEGRAM_TOKEN",
                 now=NOW, destination_extra="-100123")
    assert len(channels.sending(con, channels.TYPE_SLACK, ENV)) == 1
    assert len(channels.sending(con, channels.TYPE_TELEGRAM, ENV)) == 1
    assert channels.sending(con, channels.TYPE_DISCORD, ENV) == []


def test_email_is_not_a_sending_type():
    """Mail is configured by environment alone and has no row, so it must never
    reach the loop that posts (docs/RECORD.md 4.87)."""
    assert channels.TYPE_EMAIL not in channels.SENDING_TYPES


# ------------------------------------------- a refusal repeats nothing back

PASTED_SECRET = "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE"


def test_a_url_pasted_into_the_variable_name_field_is_not_repeated_back(con):
    """The first mistake an operator makes here, by `app/channels_cli.py`'s own
    account: pasting the webhook URL into the field that wants a variable name.
    The refusal reaches a terminal, the journal and an HTTP response body, so
    it describes the shape and never quotes the value."""
    try:
        channels.add(con, channels.TYPE_SLACK, "ops", PASTED_SECRET, now=NOW)
    except channels.ChannelError as exc:
        assert PASTED_SECRET not in str(exc)
        assert "SUPERSECRET" not in str(exc)
        # and it still says what to do instead
        assert "WHICHPORTS_" in str(exc)
    else:
        raise AssertionError("a URL in the variable name field should be refused")


def test_a_bad_channel_type_is_not_repeated_back(con):
    try:
        channels.add(con, PASTED_SECRET, "ops", "WHICHPORTS_SLACK_URL", now=NOW)
    except channels.ChannelError as exc:
        assert PASTED_SECRET not in str(exc)
        assert channels.TYPE_SLACK in str(exc), "it still lists the real types"
    else:
        raise AssertionError("a URL as a channel type should be refused")


def test_no_refusal_in_this_module_quotes_its_input(con):
    """Swept rather than listed, so a refusal added later is covered the day it
    appears rather than the day somebody remembers this test."""
    attempts = [
        (PASTED_SECRET, "ops", "WHICHPORTS_SLACK_URL", ""),
        (channels.TYPE_SLACK, PASTED_SECRET, "WHICHPORTS_SLACK_URL", ""),
        (channels.TYPE_SLACK, "ops", PASTED_SECRET, ""),
        (channels.TYPE_TELEGRAM, "ops", "WHICHPORTS_TELEGRAM_TOKEN", PASTED_SECRET),
        (channels.TYPE_SLACK, "ops", "WHICHPORTS_SLACK_URL", PASTED_SECRET),
    ]
    refusals = 0
    for channel_type, label, env_name, extra in attempts:
        try:
            channels.add(con, channel_type, label, env_name, now=NOW,
                         destination_extra=extra)
        except channels.ChannelError as exc:
            refusals += 1
            assert PASTED_SECRET not in str(exc), (channel_type, env_name, extra)
    assert refusals == len(attempts), "one of these was accepted"


# ------------------------------------------ which alerts a channel takes

def test_a_channel_that_chose_nothing_takes_everything():
    """A row written before this column existed has an empty subscription, and
    it must keep doing exactly what it did. A channel that silently stopped
    delivering because a column was added is the monitoring tool failing
    quietly that docs/PRODUCT.md 4c exists to prevent."""
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    for kind in channels.KIND_NAMES:
        assert channel.takes(kind)


def test_a_channel_takes_only_what_it_chose():
    channel = channels.Channel(id=1, type=channels.TYPE_SLACK, label="ops",
                               destination_env="WHICHPORTS_SLACK_URL",
                               enabled=True, subscriptions="silent")
    assert channel.takes(channels.KIND_SILENT)
    assert not channel.takes(channels.KIND_FINDING)
    assert not channel.takes(channels.KIND_OUTSIDE_STALE)


def test_a_kind_this_build_does_not_know_goes_to_the_channels_that_chose_nothing():
    """Safe in both directions. The operator who ticked three boxes did not
    tick a fourth nobody had invented, and the one who ticked none said they
    want everything."""
    every = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    chose = channels.Channel(id=1, type=channels.TYPE_SLACK, label="ops",
                             destination_env="WHICHPORTS_SLACK_URL",
                             enabled=True, subscriptions="silent")
    assert every.takes("a kind from 2027")
    assert not chose.takes("a kind from 2027")


def test_choosing_every_kind_is_stored_as_choosing_nothing():
    """So a channel does not quietly stop covering a fourth kind added later."""
    assert channels.check_subscriptions(list(channels.KIND_NAMES)) == ""


def test_choosing_nothing_is_every_kind_rather_than_no_kind():
    """A channel subscribed to no kind would exist and never deliver, which is
    a row an operator would have to debug. The screen offers no way to reach
    it and neither does this."""
    for empty in (None, "", [], ["", " "]):
        assert channels.check_subscriptions(empty) == ""


def test_a_subscription_is_sorted_and_deduplicated():
    once = channels.check_subscriptions(["silent"])
    twice = channels.check_subscriptions(["silent", "silent"])
    assert once == twice == "silent"
    both = channels.check_subscriptions(["outside view stale", "silent"])
    assert both == "outside view stale,silent"


def test_a_kind_that_is_not_one_is_refused_without_being_echoed(con):
    try:
        channels.check_subscriptions(["silent", PASTED_SECRET])
    except channels.ChannelError as exc:
        assert PASTED_SECRET not in str(exc)
        assert channels.KIND_SILENT in str(exc), "it still lists the real kinds"
    else:
        raise AssertionError("an unknown kind should be refused")


def test_the_kinds_are_the_kinds_the_engine_actually_raises():
    """The vocabulary is spelled in channels.py for the UI and in the engine
    for the sweep. Spelled twice and never compared is the drift 4.88 audited,
    so this reads the engine's own constants rather than trusting a comment."""
    from app import alerts as alerts_mod
    from app import finding_alerts
    assert channels.KIND_SILENT == alerts_mod.KIND_SILENT
    assert channels.KIND_FINDING == finding_alerts.KIND_FINDING
    assert channels.KIND_OUTSIDE_STALE == finding_alerts.KIND_OUTSIDE_STALE
    # The fourth is the CVE check's, which the engine does not raise as an
    # alert: `cvetell` writes it as a batch and `cvesend` hands it out. Its
    # box on the screen is held by site/app/test_render_live.py, which
    # compares the screen's kinds with these.
    assert [kind for kind, _title, _help in channels.KINDS][3:] == [channels.KIND_CVE]
    assert len(channels.KINDS) == 4, "a kind was added and the screen has no box for it"


def test_a_subscription_survives_a_round_trip(con):
    channels.add(con, channels.TYPE_SLACK, "ops", "WHICHPORTS_SLACK_URL",
                 now=NOW, subscriptions=["silent"])
    assert channels.live(con)[0].subscriptions == "silent"


def test_a_subscription_can_be_changed_afterwards(con):
    channels.add(con, channels.TYPE_SLACK, "ops", "WHICHPORTS_SLACK_URL", now=NOW)
    assert channels.set_subscriptions(con, "ops", ["silent"]) is True
    assert channels.live(con)[0].subscriptions == "silent"
    assert channels.set_subscriptions(con, "ops", []) is True
    assert channels.live(con)[0].subscriptions == ""


def test_changing_the_subscription_of_a_channel_that_is_not_there_says_so(con):
    assert channels.set_subscriptions(con, "nobody", ["silent"]) is False


def test_a_database_written_before_subscriptions_existed_gains_the_column(tmp_path):
    path = str(tmp_path / "old.db")
    con = db.connect(path)
    con.executescript("""
        CREATE TABLE notification_channels (
            id INTEGER PRIMARY KEY, type TEXT NOT NULL, label TEXT NOT NULL,
            destination_env TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL, removed_at TEXT);
    """)
    con.execute("INSERT INTO notification_channels (type, label,"
                " destination_env, enabled, created_at)"
                " VALUES ('webhook', 'old row', 'WHICHPORTS_WEBHOOK_URL', 1, ?)",
                (NOW.isoformat(),))
    con.commit()
    channels.init(con)
    row = channels.live(con)[0]
    assert row.subscriptions == ""
    assert row.takes(channels.KIND_SILENT), "an old row stopped taking an alert"
    channels.init(con)          # the sweep calls init every run
    assert len(channels.live(con)) == 1
    con.close()


# ------------------------------------------------------------- renaming

def test_a_channel_can_be_renamed(con):
    channels.add(con, channels.TYPE_SLACK, "old name", "WHICHPORTS_SLACK_URL", now=NOW)
    assert channels.rename(con, "old name", "new name") is True
    assert channels.live(con)[0].label == "new name"


def test_renaming_does_not_change_where_it_delivers(con):
    """The reason a rename is safe to offer at all. The delivery key is the
    type, the variable and the extra, so a rename cannot make this channel's
    open alerts look undelivered and re-post them."""
    channels.add(con, channels.TYPE_TELEGRAM, "old name",
                 "WHICHPORTS_TELEGRAM_TOKEN", now=NOW, destination_extra="-100123")
    before = channels.live(con)[0]
    key_before = alerts.channel_key(before.type, before.destination_env,
                                    before.destination_extra)
    channels.rename(con, "old name", "new name")
    after = channels.live(con)[0]
    key_after = alerts.channel_key(after.type, after.destination_env,
                                   after.destination_extra)
    assert key_before == key_after


def test_renaming_to_a_label_that_is_taken_is_refused(con):
    channels.add(con, channels.TYPE_SLACK, "one", "WHICHPORTS_SLACK_URL", now=NOW)
    channels.add(con, channels.TYPE_DISCORD, "two", "WHICHPORTS_DISCORD_URL", now=NOW)
    with pytest.raises(channels.ChannelError):
        channels.rename(con, "one", "two")
    assert {c.label for c in channels.live(con)} == {"one", "two"}


@pytest.mark.parametrize("bad", ["", "   ", "x" * 49, "has@at", "<script>"])
def test_renaming_to_something_that_is_not_a_label_is_refused(con, bad):
    channels.add(con, channels.TYPE_SLACK, "ops", "WHICHPORTS_SLACK_URL", now=NOW)
    with pytest.raises(channels.ChannelError):
        channels.rename(con, "ops", bad)
    assert channels.live(con)[0].label == "ops"


def test_renaming_a_channel_that_is_not_there_says_so(con):
    assert channels.rename(con, "nobody", "somebody") is False


# ------------------------------------------- telegram posts into a topic

def test_a_chat_without_a_topic_sends_no_thread_id():
    """The ordinary case, and the one every existing row is."""
    body = senders.body_for(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123"),
        "hello", {})
    assert body == {"chat_id": "-100123", "text": "hello"}
    assert "message_thread_id" not in body


def test_a_chat_with_a_topic_sends_the_thread_id_as_an_integer():
    """Telegram documents it as Integer, so it goes as one."""
    body = senders.body_for(
        a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN", "-100123:42"),
        "hello", {})
    assert body == {"chat_id": "-100123", "text": "hello",
                    "message_thread_id": 42}


def test_two_topics_in_one_chat_are_two_destinations():
    """The reason the topic is stored beside the chat rather than as a
    decoration on it: keyed on the chat alone, the first topic's delivery would
    mark the alert done and the second would never hear about it."""
    one = alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123:1")
    two = alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123:2")
    bare = alerts.channel_key("telegram", "WHICHPORTS_TELEGRAM_TOKEN", "-100123")
    assert len({one, two, bare}) == 3


@pytest.mark.parametrize("value,chat,thread", [
    ("-1001234567890", "-1001234567890", ""),
    ("-1001234567890:42", "-1001234567890", "42"),
    ("@ops_channel", "@ops_channel", ""),
    ("@ops_channel:7", "@ops_channel", "7"),
    ("", "", ""),
])
def test_the_chat_and_the_topic_split_apart_again(value, chat, thread):
    assert channels.split_telegram_target(value) == (chat, thread)


@pytest.mark.parametrize("stored", ["-1001234567890:42", "@ops:7", "123456"])
def test_every_stored_form_is_one_the_validator_accepts(con, stored):
    """The two halves have to agree: what `add` lets in must be what
    `split_telegram_target` can take apart."""
    channels.add(con, channels.TYPE_TELEGRAM, f"c{len(stored)}",
                 "WHICHPORTS_TELEGRAM_TOKEN", now=NOW, destination_extra=stored)
    read = channels.live(con, channels.TYPE_TELEGRAM)[-1]
    chat, _ = channels.split_telegram_target(read.destination_extra)
    assert chat


def test_a_chat_id_longer_than_telegram_documents_is_refused(con):
    """**Telegram's bound, not ours.** Chat.id is documented as "at most 52
    significant bits", which is sixteen digits. The first version of this code
    said Telegram documented no length and allowed thirty two."""
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_TELEGRAM, "toolong",
                     "WHICHPORTS_TELEGRAM_TOKEN", now=NOW,
                     destination_extra="-" + "1" * 17)


def test_sixteen_digits_is_still_accepted(con):
    """The boundary itself, so the bound is not quietly one out."""
    channels.add(con, channels.TYPE_TELEGRAM, "sixteen",
                 "WHICHPORTS_TELEGRAM_TOKEN", now=NOW,
                 destination_extra="1" * 16)
    assert channels.live(con, channels.TYPE_TELEGRAM)


@pytest.mark.parametrize("bad", ["-100:", ":42", "-100:x", "@ops:", "1:2:3"])
def test_a_malformed_topic_is_refused(con, bad):
    with pytest.raises(channels.ChannelError):
        channels.add(con, channels.TYPE_TELEGRAM, f"b{len(bad)}",
                     "WHICHPORTS_TELEGRAM_TOKEN", now=NOW, destination_extra=bad)


def test_a_migrated_group_says_where_it_went():
    """A stored numeric group id stops working the day the group is upgraded,
    and Telegram hands back the replacement. Without this the channel goes
    quiet with no hint the id moved."""
    body = json.dumps({"ok": False, "description": "Bad Request: group migrated",
                       "parameters": {"migrate_to_chat_id": -1009876543210}}).encode()
    complaint = senders.telegram_ok(body)
    assert "-1009876543210" in complaint
    # and their prose still does not come through
    assert "Bad Request" not in complaint


def test_a_plain_refusal_still_says_nothing_of_theirs():
    body = json.dumps({"ok": False, "description": "chat not found"}).encode()
    assert "chat not found" not in senders.telegram_ok(body)


def test_a_migrate_field_that_is_not_a_number_is_ignored():
    """It reaches a sentence an operator reads, so it is typed on the way in."""
    body = json.dumps({"ok": False,
                       "parameters": {"migrate_to_chat_id": "<script>"}}).encode()
    assert "<script>" not in senders.telegram_ok(body)


# ------------------------------------------------------------- the test send
#
# One short real message so an operator can watch a channel deliver, added
# with the per-row Send test menu (2026-08-23). It has to take exactly the
# path an alert takes, or the test proves the wrong thing.

def test_deliver_test_posts_through_the_ordinary_path():
    opener = FakeOpener()
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    sent, reason = senders.deliver_test(channel, env=ENV,
                                        resolver=resolves_public,
                                        opener=opener)
    assert sent is True
    assert len(opener.requests) == 1
    assert "Test message" in opener.body_sent["text"]


def test_deliver_test_says_it_is_a_test_and_names_no_host():
    """Nothing about the fleet crosses the wire that an alert would not carry,
    and a consumer parsing real alerts can tell a test from a finding."""
    opener = FakeOpener()
    channel = a_channel(channels.TYPE_WEBHOOK, "WHICHPORTS_WEBHOOK_URL")
    senders.deliver_test(channel, env=ENV, resolver=resolves_public,
                         opener=opener)
    body = opener.body_sent
    assert body["kind"] == "test"
    assert body["version"] == webhook.PAYLOAD_VERSION
    assert "server" not in body


def test_deliver_test_keeps_the_guarded_opener_rules():
    """The same refusal an alert gets: a host resolving to a private address
    is not posted to, test or no test."""
    opener = FakeOpener()
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    sent, reason = senders.deliver_test(channel, env=ENV,
                                        resolver=lambda h: PRIVATE,
                                        opener=opener)
    assert sent is False
    assert opener.requests == []
    assert reason.endswith(REFUSALS)


def test_deliver_test_with_nothing_to_send_to_says_so_without_the_value():
    channel = a_channel(channels.TYPE_SLACK, "WHICHPORTS_SLACK_URL")
    sent, reason = senders.deliver_test(channel, env={})
    assert sent is False
    assert "WHICHPORTS_SLACK_URL" in reason
    assert SLACK_URL not in reason


def test_deliver_test_reaches_a_telegram_chat_like_an_alert_does():
    opener = FakeOpener(body=json.dumps({"ok": True}).encode())
    channel = a_channel(channels.TYPE_TELEGRAM, "WHICHPORTS_TELEGRAM_TOKEN",
                        extra="-1001234567890")
    sent, _ = senders.deliver_test(channel, env=ENV,
                                   resolver=resolves_public, opener=opener)
    assert sent is True
    body = opener.body_sent
    assert body["chat_id"] == "-1001234567890"
    assert "Test message" in body["text"]
