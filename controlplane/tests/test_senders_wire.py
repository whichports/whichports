"""What actually goes down a socket, proved against a real server.

    python -m pytest tests/test_senders_wire.py

`tests/test_senders.py` proves the logic against an injected opener, which is
the right shape for the guards: nothing there resolves or connects to anything.
**But an injected opener proves our code and not urllib's.** Every test in that
file would still pass if the real request never formed correctly, because the
real request is never built.

So this file runs a **real HTTP server on the loopback interface** and posts to
it through `app/webhook.py`'s own opener. Real socket, real headers, real
body, real status handling. If urllib is handed something it cannot send, this
is where it shows.

## How it gets past our own address check, and why that is honest

`webhook.check_url` refuses any host whose addresses are not globally routable,
which is exactly what `127.0.0.1` is not. The resolver is an injected argument
though, so these tests hand it one that answers with a public address while the
URL names the loopback port. urllib then connects to the loopback.

**That is deliberately the DNS rebinding case `app/webhook.py`'s docstring
already names as not closed**, used here as a test seam rather than discovered
as a surprise. It is worth saying out loud: if that hole is ever closed, by
connecting to the address that was checked, these tests are the ones that break
and they should be rewritten rather than the fix reverted.

Nothing here reaches the internet. No test in this repository has ever sent a
message to Slack, Telegram or Discord.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from app import channels, senders, webhook

from app import outbound  # noqa: E402

# The two ways a refused address is said (app/outbound.py).
REFUSALS = (outbound.REFUSED_AS_PRIVATE, outbound.REFUSED_ALWAYS)

PUBLIC = ["185.199.108.153"]


class Recorder(BaseHTTPRequestHandler):
    """Records one request and answers with whatever the test set up."""

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.server.seen.append({
            "path": self.path,
            "body": self.rfile.read(length),
            "content_type": self.headers.get("Content-Type"),
            "user_agent": self.headers.get("User-Agent"),
        })
        body = self.server.reply_body
        self.send_response(self.server.reply_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        """Silent. pytest output is not the place for an access log."""


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Recorder)
    httpd.seen = []
    httpd.reply_status = 200
    httpd.reply_body = b"ok"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=5)


def url_for(server, path="/hook"):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


def resolves_public(host):
    return PUBLIC


def a_channel(server, channel_type, extra="", path="/hook"):
    env_name = "WHICHPORTS_WIRE_TEST"
    channel = channels.Channel(id=1, type=channel_type, label=f"wire {channel_type}",
                               destination_env=env_name, enabled=True,
                               destination_extra=extra)
    return channel, {env_name: url_for(server, path)}


# ------------------------------------------------------- it really posts

def test_a_webhook_really_reaches_a_real_server(server):
    channel, env = a_channel(server, channels.TYPE_WEBHOOK)
    ok, reason = senders.deliver_alert(
        channel, "silent", "box", "last report 41 minutes ago",
        "2026-08-22T11:00:00", env, resolver=resolves_public)
    assert ok is True, reason
    assert len(server.seen) == 1
    sent = json.loads(server.seen[0]["body"])
    assert sent["server"] == "box"
    assert sent["kind"] == "silent"


def test_slack_really_posts_its_own_key(server):
    channel, env = a_channel(server, channels.TYPE_SLACK)
    ok, reason = senders.deliver_alert(
        channel, "silent", "box", "quiet", "2026-08-22T11:00:00", env,
        resolver=resolves_public)
    assert ok is True, reason
    sent = json.loads(server.seen[0]["body"])
    assert set(sent) == {"text", "blocks"}
    assert "box" in sent["text"]


def test_discord_really_posts_its_own_key_and_asks_to_be_told(server):
    server.reply_status = 200
    channel, env = a_channel(server, channels.TYPE_DISCORD)
    ok, reason = senders.deliver_alert(
        channel, "silent", "box", "quiet", "2026-08-22T11:00:00", env,
        resolver=resolves_public)
    assert ok is True, reason
    sent = json.loads(server.seen[0]["body"])
    assert set(sent) == {"content", "embeds", "allowed_mentions"}
    assert sent["allowed_mentions"] == {"parse": []}
    # wait=true, so a message Discord did not save comes back as an error
    assert "wait=true" in server.seen[0]["path"]


def test_the_headers_are_the_ones_we_think_we_send(server):
    channel, env = a_channel(server, channels.TYPE_SLACK)
    senders.deliver_alert(channel, "silent", "box", "quiet", "2026-08-22T11:00:00",
                          env, resolver=resolves_public)
    assert server.seen[0]["content_type"] == "application/json"
    assert server.seen[0]["user_agent"] == webhook.USER_AGENT
    # It names itself. An operator reading their own logs can tell our posts
    # from anyone else's.
    assert "whichports" in server.seen[0]["user_agent"]


# ---------------------------------------------- telegram's envelope, for real

def test_telegram_is_a_delivery_only_when_the_body_says_ok(server):
    """Its documentation defines success as the `ok` field rather than as the
    status, so a 200 carrying ok:false must not be recorded as sent."""
    server.reply_body = json.dumps({"ok": False, "description": "chat not found"}).encode()
    channel, env = a_channel(server, channels.TYPE_TELEGRAM, extra="-100123")
    # The telegram sender builds api.telegram.org from the token, so the URL
    # cannot be pointed at the test server through the channel. The transport
    # is what is under test here, so it is driven directly with the same
    # arguments the sender would hand it.
    ok, reason = webhook.send(
        {"chat_id": "-100123", "text": "hello"},
        webhook.Config(url=url_for(server), source_env="WHICHPORTS_WIRE_TEST"),
        resolver=resolves_public, check_body=senders.telegram_ok,
        max_response_bytes=senders.TELEGRAM_MAX_RESPONSE_BYTES)
    assert ok is False
    assert "chat not found" not in reason, "the endpoint's own text was passed on"


def test_telegram_is_a_delivery_when_the_body_says_ok(server):
    server.reply_body = json.dumps({"ok": True, "result": {"message_id": 1}}).encode()
    ok, reason = webhook.send(
        {"chat_id": "-100123", "text": "hello"},
        webhook.Config(url=url_for(server), source_env="WHICHPORTS_WIRE_TEST"),
        resolver=resolves_public, check_body=senders.telegram_ok,
        max_response_bytes=senders.TELEGRAM_MAX_RESPONSE_BYTES)
    assert ok is True, reason


def test_a_long_telegram_reply_is_read_whole_rather_than_cut(server):
    """Its success reply echoes the text we sent, so a 4096 byte bound would
    cut it, and a cut body does not parse and would be reported as a delivery
    that failed when it in fact arrived."""
    server.reply_body = json.dumps(
        {"ok": True, "result": {"text": "x" * 5000}}).encode()
    ok, reason = webhook.send(
        {"chat_id": "-100123", "text": "hello"},
        webhook.Config(url=url_for(server), source_env="WHICHPORTS_WIRE_TEST"),
        resolver=resolves_public, check_body=senders.telegram_ok,
        max_response_bytes=senders.TELEGRAM_MAX_RESPONSE_BYTES)
    assert ok is True, reason


def test_the_same_long_reply_under_the_old_bound_would_have_been_read_as_failure(server):
    """The other half, so the test above cannot pass for some other reason.
    This is what the default bound does to the same body."""
    server.reply_body = json.dumps(
        {"ok": True, "result": {"text": "x" * 5000}}).encode()
    ok, _ = webhook.send(
        {"chat_id": "-100123", "text": "hello"},
        webhook.Config(url=url_for(server), source_env="WHICHPORTS_WIRE_TEST"),
        resolver=resolves_public, check_body=senders.telegram_ok)
    assert ok is False, "a cut body parsed, so this test proves nothing"


# ------------------------------------------------------ what a server says back

@pytest.mark.parametrize("status", [400, 401, 403, 404, 429, 500, 503])
def test_an_endpoint_that_refuses_is_not_recorded_as_delivered(server, status):
    server.reply_status = status
    channel, env = a_channel(server, channels.TYPE_SLACK)
    ok, reason = senders.deliver_alert(
        channel, "silent", "box", "quiet", "2026-08-22T11:00:00", env,
        resolver=resolves_public)
    assert ok is False
    assert str(status) in reason


def test_a_redirect_is_a_refusal_and_is_not_followed(server):
    """`app/webhook.py` refuses redirects on purpose: following one would let
    the endpoint move the request to an address the check already declined."""
    server.reply_status = 302
    channel, env = a_channel(server, channels.TYPE_SLACK)
    ok, reason = senders.deliver_alert(
        channel, "silent", "box", "quiet", "2026-08-22T11:00:00", env,
        resolver=resolves_public)
    assert ok is False
    assert "302" in reason
    assert len(server.seen) == 1, "it followed the redirect"


def test_nothing_is_posted_when_the_address_check_refuses(server):
    """The guard, exercised against a real server rather than a stub: with an
    honest resolver the loopback is refused and no request is made at all."""
    channel, env = a_channel(server, channels.TYPE_SLACK)
    ok, reason = senders.deliver_alert(
        channel, "silent", "box", "quiet", "2026-08-22T11:00:00", env,
        resolver=lambda h: ["127.0.0.1"])
    assert ok is False
    assert reason.endswith(REFUSALS)
    assert server.seen == [], "a request was made to an address we refused"
