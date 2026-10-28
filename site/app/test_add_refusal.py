"""What the Add window says at a field it refuses.

    python -m pytest app/test_add_refusal.py        (from site/)

Found in a round of the test fleet (docs/RECORD.md 4.228): a bot token and a
chat id typed into each other's field were refused by one line at the foot of
the window. It named no field, began in lower case and carried a reason of
ours. What is held here is the pattern every product uses: a refusal stands
at the field it is about, says in a few plain words what that field must be,
and repeats nothing that was typed.

This file holds what the page is sent with: a line under every field, the
words for each reason a field can be refused for, and that the page checks a
field as the server does. The server decides and the page's check is a
convenience, so the two are compared here and never trusted to agree. What a
click does is held in a real browser by test_add_refusal_browser.py.
"""
import html as html_mod
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import build  # noqa: E402
import render_live as rl  # noqa: E402

# Made-up values in the shape each field takes. The token is the example in
# Telegram's own documentation and was never issued.
TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
CHAT = "-1009876543210"
HOOK = "https://hooks.example.com/services/T0/B0/abc"

# Which type each step stores, and the label over its first field.
STEPS = {stage: (fields[0], fields[1]) for stage, fields in build.CHANNEL_FIELDS.items()}


def engine():
    """The control plane's channels module, the one that decides."""
    return rl.joinbridge.module("channels")


def every_check():
    """(step, field, check) for every field the window asks for."""
    return [(stage, name, check)
            for stage, checks in build.CHANNEL_CHECKS.items()
            for name, check in checks.items()]


def page_reason(check, value):
    """Why the page refuses this value in this field, or "" when it lets it
    through. The rule page.js applies, written out once more so the table can
    be held to the server without a browser: trimmed, then empty, then too
    long, then the pattern."""
    value = value.strip()
    if not value:
        return "" if check.optional else "missing"
    if check.longest and len(value) > check.longest:
        return "shape"
    return "" if re.search(check.pattern, value) else "shape"


# ----------------------------------------------------- what the page is sent

def test_every_field_of_every_step_has_a_check():
    """Each field, not only the first. A step that asks for nothing has
    none, and that is Slack."""
    assert set(build.CHANNEL_CHECKS) == set(build.CHANNEL_FIELDS)
    for stage, (_type, holds) in STEPS.items():
        inputs = re.findall(r"<input[^>]*>", build.channel_stage(stage))
        assert len(inputs) == len(build.CHANNEL_CHECKS[stage]), stage
        if not holds:
            assert inputs == [], stage
    assert sorted(build.CHANNEL_CHECKS["chan-telegram"]) == ["chat", "dest", "thread"]
    for stage in ("chan-email", "chan-webhook", "chan-discord"):
        assert list(build.CHANNEL_CHECKS[stage]) == ["dest"], stage
    assert build.CHANNEL_CHECKS["chan-slack"] == {}


@pytest.mark.parametrize("stage,name,check", every_check(),
                         ids=[f"{s}-{n}" for s, n, _c in every_check()])
def test_a_field_carries_its_check_and_its_line_stands_under_it(stage, name, check):
    step = build.channel_stage(stage)
    field_id = f"{stage}-{name}"
    tags = [tag for tag in re.findall(r"<input[^>]*>", step) if f'id="{field_id}"' in tag]
    assert len(tags) == 1, field_id
    tag = tags[0]
    # The line is the field's own, named by it, and the next thing after it.
    assert f'aria-describedby="{field_id}-err"' in tag
    line = f'<div class="m-err m-quiet" id="{field_id}-err"></div>'
    assert step.count(line) == 1
    assert re.search(re.escape(tag) + r"\s*" + re.escape(line), step), field_id
    # What it must look like, and the words for each reason.
    assert f'data-pattern="{html_mod.escape(check.pattern)}"' in tag
    assert f'data-wire="{check.wire}"' in tag
    assert ("data-optional" in tag) == check.optional
    assert (f'data-longest="{check.longest}"' in tag) == bool(check.longest)
    for reason, words in check.says.items():
        assert f'data-says-{reason}="{html_mod.escape(words)}"' in tag, reason
    assert tag.count("data-says-") == len(check.says)
    # Our own line and never the browser's bubble.
    assert "required" not in tag and " pattern=" not in tag


def test_a_providers_field_has_its_own_line_under_it():
    """The same pattern as a destination's field: the line a refusal of that
    field stands in is its own, named by it, and the next thing after it."""
    built = [key for key, _name, _glyph, is_built in build.PROVIDERS if is_built]
    assert built == ["hetzner"], "a provider built since: hold its fields here too"
    for key in built:
        step = build.integration_stage_html(key)
        tags = re.findall(r"<input[^>]*>", step)
        assert len(tags) == len(build.INTEGRATION_FIELDS[key])
        for number, tag in enumerate(tags, 1):
            field_id = f"intg-{key}-{number}"
            assert f'id="{field_id}"' in tag
            assert f'aria-describedby="{field_id}-err"' in tag
            line = f'<div class="m-err m-quiet" id="{field_id}-err"></div>'
            assert step.count(line) == 1
            assert re.search(re.escape(tag) + r"\s*" + re.escape(line), step), field_id
            # Our own line and never the browser's bubble.
            assert "required" not in tag and " pattern=" not in tag


def test_the_line_at_the_foot_is_still_there_for_what_is_no_field():
    """The kinds switched off, and an answer that is about no field."""
    assert '<div class="m-err m-quiet" id="conn-err"></div>' in build.add_modal()


# ------------------------------------------------------ the words of a line

def every_line():
    return [(stage, name, reason, words)
            for stage, name, check in every_check()
            for reason, words in check.says.items()]


@pytest.mark.parametrize("stage,name,reason,words", every_line(),
                         ids=[f"{s}-{n}-{r}" for s, n, r, _w in every_line()])
def test_a_line_is_a_few_plain_words_and_no_reason_of_ours(stage, name, reason, words):
    assert words[0].isupper(), words
    assert words.endswith("."), words
    assert len(words.split()) <= 14, words
    # No dash and no semicolon in a line a customer reads.
    for mark in ("—", "–", ";", "  "):
        assert mark not in words, words
    # What the field must be, and nothing about why we ask or what we keep.
    for ours in ("because", "repeated", "never", "environment", "credential",
                 "server", "we ", "our ", "sweep", "variable"):
        assert ours not in words.lower(), words
    # Nothing shaped like a value somebody could copy into the field.
    assert not re.search(r"[0-9]{3}", words), words
    assert "@example" not in words and "example.com" not in words, words


@pytest.mark.parametrize("stage,name,check", every_check(),
                         ids=[f"{s}-{n}" for s, n, _c in every_check()])
def test_a_line_names_its_field_by_the_words_on_its_label(stage, name, check):
    """A refusal that renames the field is one a person has to translate."""
    label = {"dest": STEPS[stage][1], "chat": "chat id", "thread": "topic"}[name]
    step = build.channel_stage(stage)
    # The label is on the page in those words, first letter raised.
    assert f">{label[0].upper()}{label[1:]}<" in step, label
    if check.optional:
        assert "missing" not in check.says
    else:
        assert check.says["missing"] == f"Enter the {label}."
    assert label in check.says["shape"][0].lower() + check.says["shape"][1:]


def test_no_line_is_shared_by_two_fields_of_one_step():
    """With two lines showing, each has to say which field it is about."""
    for stage, checks in build.CHANNEL_CHECKS.items():
        lines = [words for check in checks.values()
                 for reason, words in check.says.items()
                 if reason in ("missing", "shape")]
        assert len(lines) == len(set(lines)), stage


# ------------------------------------------- the page checks as the server does

def test_the_patterns_are_the_servers_own():
    """Spelled twice, because the page has to check before it asks, and
    compared here so the two cannot drift (the shape docs/RECORD.md 4.88
    settled on for a vocabulary both sides hold)."""
    channels = engine()
    checks = build.CHANNEL_CHECKS
    assert checks["chan-email"]["dest"].pattern == channels.EMAIL_RE.pattern
    token = checks["chan-telegram"]["dest"]
    assert token.pattern == channels.TELEGRAM_TOKEN_RE.pattern
    assert token.longest == channels.TELEGRAM_TOKEN_MAX
    # The server takes the chat id and the topic as one value, chat:topic.
    # The window asks for them in two fields and joins them, so its two
    # patterns put together are the server's one.
    chat, topic = checks["chan-telegram"]["chat"], checks["chan-telegram"]["thread"]
    for part in (chat.pattern, topic.pattern):
        assert part.startswith("^") and part.endswith("$")
    joined = f"^{chat.pattern[1:-1]}(:{topic.pattern[1:-1]})?$"
    assert joined == channels.TELEGRAM_CHAT_RE.pattern
    assert topic.optional and not chat.optional
    # Every bound is in a pattern or in `longest`, so no field has one the
    # server does not.
    for stage, name, check in every_check():
        if (stage, name) != ("chan-telegram", "dest"):
            assert check.longest == 0, (stage, name)


# One row per sample: the step, what is typed into each of its fields, and
# the reason the server gives for the first field it refuses ("" for none).
SAMPLES = [
    ("chan-email", {"dest": "ops@example.com"}),
    ("chan-email", {"dest": "  ops@example.com  "}),
    ("chan-email", {"dest": ""}),
    ("chan-email", {"dest": "   "}),
    ("chan-email", {"dest": "ops@"}),
    ("chan-email", {"dest": "ops.example.com"}),
    ("chan-email", {"dest": "ops@example"}),
    ("chan-email", {"dest": "ops@example.com, noc@example.com"}),
    ("chan-email", {"dest": "ops@example.com,noc@example.com"}),
    ("chan-email", {"dest": HOOK}),
    ("chan-webhook", {"dest": HOOK}),
    ("chan-webhook", {"dest": "http://hooks.example.com/x"}),
    ("chan-webhook", {"dest": ""}),
    ("chan-webhook", {"dest": "hooks.example.com/x"}),
    ("chan-webhook", {"dest": "ftp://hooks.example.com/x"}),
    ("chan-webhook", {"dest": "HTTPS://hooks.example.com/x"}),
    ("chan-webhook", {"dest": TOKEN}),
    ("chan-webhook", {"dest": "ops@example.com"}),
    ("chan-discord", {"dest": HOOK}),
    ("chan-discord", {"dest": ""}),
    ("chan-discord", {"dest": TOKEN}),
    ("chan-discord", {"dest": "discord.example.com/api/webhooks/1/x"}),
    ("chan-telegram", {"dest": TOKEN, "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": CHAT, "thread": "42"}),
    ("chan-telegram", {"dest": TOKEN, "chat": "@ops_room", "thread": ""}),
    ("chan-telegram", {"dest": " " + TOKEN + " ", "chat": " " + CHAT + " ", "thread": " 42 "}),
    # The two in each other's field, and each of them alone.
    ("chan-telegram", {"dest": CHAT, "chat": TOKEN, "thread": ""}),
    ("chan-telegram", {"dest": CHAT, "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": TOKEN, "thread": ""}),
    # Each field empty.
    ("chan-telegram", {"dest": "", "chat": "", "thread": ""}),
    ("chan-telegram", {"dest": "", "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": "", "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": "", "thread": "42"}),
    # A URL where the token belongs.
    ("chan-telegram", {"dest": HOOK, "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": "123456:", "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": ":ABC", "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": "1:" + "a" * 254, "chat": CHAT, "thread": ""}),
    ("chan-telegram", {"dest": "1:" + "a" * 255, "chat": CHAT, "thread": ""}),
    # The chat id and the topic at their edges.
    ("chan-telegram", {"dest": TOKEN, "chat": "1" * 16, "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": "1" * 17, "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": "ops room", "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": "@", "thread": ""}),
    ("chan-telegram", {"dest": TOKEN, "chat": CHAT, "thread": "general"}),
    ("chan-telegram", {"dest": TOKEN, "chat": CHAT, "thread": "-4"}),
    ("chan-telegram", {"dest": TOKEN, "chat": CHAT, "thread": "1" * 10}),
    ("chan-telegram", {"dest": TOKEN, "chat": CHAT, "thread": "1" * 11}),
]


def server_refuses(channels, channel_type, typed):
    """Whether the server refuses what the window would send for `typed`:
    the destination trimmed as the server trims it, and for Telegram the chat
    id and the topic joined as page.js joins them."""
    destination = typed["dest"].strip()
    if not destination:
        return True
    if channels.destination_refusal(channel_type, destination)[0]:
        return True
    rule = channels.TYPE_RULES[channel_type]
    if rule is None:
        return False
    chat, topic = typed["chat"].strip(), typed["thread"].strip()
    return not rule.pattern.match(f"{chat}:{topic}" if topic else chat)


@pytest.mark.parametrize("stage,typed", SAMPLES)
def test_the_page_refuses_what_the_server_refuses_and_nothing_else(stage, typed):
    channels = engine()
    refused_here = [name for name, check in build.CHANNEL_CHECKS[stage].items()
                    if page_reason(check, typed[name])]
    assert bool(refused_here) == server_refuses(channels, STEPS[stage][0], typed), refused_here


def test_swapped_telegram_fields_are_both_refused_and_the_topic_is_not():
    """The mistake the finding is about, held to its fields."""
    checks = build.CHANNEL_CHECKS["chan-telegram"]
    typed = {"dest": CHAT, "chat": TOKEN, "thread": ""}
    assert {name: page_reason(check, typed[name]) for name, check in checks.items()} == \
        {"dest": "shape", "chat": "shape", "thread": ""}


def test_a_chat_id_and_its_topic_go_in_their_own_fields():
    """The one place the page is narrower than the wire. The server takes
    chat:topic as one value, and the window has a field for each, so a colon
    typed into the chat id's field is refused there."""
    channels = engine()
    assert channels.TYPE_RULES["telegram"].pattern.match(CHAT + ":42")
    assert page_reason(build.CHANNEL_CHECKS["chan-telegram"]["chat"], CHAT + ":42") == "shape"


def test_the_page_has_words_for_every_reason_the_server_can_give_a_field(monkeypatch):
    """And for no other. A field named by the server with a reason the page
    has no line for would fall to the line at the foot, which says only that
    it did not work."""
    channels = engine()
    # The setting that lets a private address through is off, as it is on
    # every instance that did not ask for it.
    monkeypatch.delenv(rl.joinbridge.module("outbound").SETTING, raising=False)
    for stage, name, check in every_check():
        assert set(check.says) <= set(channels.REASONS), (stage, name)
        assert check.wire in channels.FIELDS + ("",), (stage, name)
    # What the server can say of a destination, asked of it type by type.
    asked = {"missing": "", "shape": "x", "private": "https://10.0.0.5/hook",
             "unsendable": "http://127.0.0.1:8065/hook"}
    for stage, (channel_type, holds) in STEPS.items():
        if not holds:
            continue
        given = {"missing"}
        for destination in asked.values():
            if destination:
                given.add(channels.destination_refusal(channel_type, destination)[0])
        check = build.CHANNEL_CHECKS[stage]["dest"]
        assert check.wire == channels.FIELD_DESTINATION
        assert set(check.says) == given, stage
    chat = build.CHANNEL_CHECKS["chan-telegram"]["chat"]
    assert chat.wire == channels.FIELD_CHAT_ID
    assert set(chat.says) == {channels.REASON_MISSING, channels.REASON_SHAPE}
    # The topic travels inside chat_id, so the server never names it alone.
    topic = build.CHANNEL_CHECKS["chan-telegram"]["thread"]
    assert topic.wire == "" and set(topic.says) == {channels.REASON_SHAPE}


def test_the_address_lines_say_what_the_servers_sentences_say():
    """The two sentences for an address an alert cannot go to were settled
    in docs/RECORD.md 4.336. The lines here are those, said of the field."""
    outbound = rl.joinbridge.module("outbound")
    assert outbound.REFUSED_AS_PRIVATE == ("which is inside a private network."
                                           " Alerts are sent to public addresses only.")
    assert outbound.REFUSED_ALWAYS == "which is not an address an alert can be sent to."
    for stage in ("chan-webhook", "chan-discord"):
        says = build.CHANNEL_CHECKS[stage]["dest"].says
        assert says["private"] == ("This address is inside a private network."
                                   " Alerts are sent to public addresses only.")
        assert says["unsendable"] == "An alert cannot be sent to this address."
