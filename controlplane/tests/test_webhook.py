"""Alert delivery to a URL the operator chooses.

    python -m pytest tests/test_webhook.py

**No test here opens a socket to anything.** The resolver and the opener are
arguments to the code under test, so the real logic runs against stand-ins and
nothing in this repository resolves or connects to a real host to prove a
guard works.
"""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app import alerts, db, notify, store, webhook

from app import outbound  # noqa: E402

# The two ways a refused address is said (app/outbound.py).
REFUSALS = (outbound.REFUSED_AS_PRIVATE, outbound.REFUSED_ALWAYS)

NOW = datetime(2026, 8, 21, 12, 0, 0, tzinfo=timezone.utc)
PUBLIC = ["185.199.108.153"]
CONFIGURED = webhook.Config(url="https://hooks.example.com/T00/SECRET")


@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    alerts.init(connection)
    yield connection
    connection.close()


class FakeOpener:
    """Records what would go on the wire and answers with a status."""

    def __init__(self, status=200):
        self.status = status
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        outer = self

        class Response:
            status = outer.status
            def read(self, n=None):
                return b""
            def __enter__(self_inner):
                return self_inner
            def __exit__(self_inner, *a):
                return False
        return Response()


class RefusingOpener:
    """An opener that must never be called."""

    def open(self, request, timeout=None):
        raise AssertionError(
            f"a request was made to {request.full_url} and this test exists"
            " because it must not be")


# --------------------------------------------------------- nothing by default

def test_nothing_is_sent_without_configuration():
    """Nothing starts posting because a branch merged, which is the rule
    app/notify.py states for the mail half."""
    ok, reason = webhook.send({"a": 1}, webhook.Config(), opener=RefusingOpener())
    assert ok is False
    assert reason == "no webhook configured"


def test_an_empty_url_in_the_environment_is_not_configured():
    assert webhook.config_from_env({}).configured is False
    assert webhook.config_from_env({"WHICHPORTS_WEBHOOK_URL": "  "}).configured is False
    assert webhook.config_from_env(
        {"WHICHPORTS_WEBHOOK_URL": " https://x.example/h "}).url == "https://x.example/h"


# ------------------------------------------------------- where it may send

@pytest.mark.parametrize("address", [
    "127.0.0.1", "::1", "10.0.0.5", "192.168.1.10", "172.16.4.4",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1",
])
def test_an_address_that_is_not_globally_routable_is_refused(address):
    """The control plane runs beside the ingest on 127.0.0.1:8410, Caddy and
    the only database in the project. 169.254.169.254 is in this list by name:
    it is the cloud metadata address."""
    complaint = webhook.check_url("https://hook.test/x", resolver=lambda h: [address])
    assert complaint, f"{address} was allowed"
    assert complaint.endswith(REFUSALS)


def test_a_public_address_is_allowed():
    assert webhook.check_url("https://hook.test/x", resolver=lambda h: PUBLIC) == ""


def test_every_answer_is_checked_and_not_just_the_first():
    """A name answering with one public address and one private address is a
    name that reaches the private one."""
    mixed = PUBLIC + ["127.0.0.1"]
    assert webhook.check_url("https://hook.test/x", resolver=lambda h: mixed)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x.test/a",
                                 "gopher://x.test/a", "://nonsense"])
def test_only_http_and_https_are_posted_to(url):
    complaint = webhook.check_url(url, resolver=lambda h: PUBLIC)
    assert complaint


def test_a_host_that_does_not_resolve_is_a_refusal_not_a_crash():
    def boom(host):
        raise OSError("no such name")
    complaint = webhook.check_url("https://hook.test/x", resolver=boom)
    assert "did not resolve" in complaint


def test_a_host_resolving_to_nothing_is_refused():
    complaint = webhook.check_url("https://hook.test/x", resolver=lambda h: [])
    assert "no address" in complaint


def test_a_refused_url_sends_nothing():
    ok, reason = webhook.send({"a": 1}, CONFIGURED,
                              resolver=lambda h: ["127.0.0.1"],
                              opener=RefusingOpener())
    assert ok is False
    assert reason.endswith(REFUSALS)


# ------------------------------------------------------------ the request

def test_a_configured_url_posts_json():
    opener = FakeOpener()
    ok, reason = webhook.send({"kind": "test"}, CONFIGURED,
                              resolver=lambda h: PUBLIC, opener=opener)
    assert ok is True, reason
    request = opener.requests[0]
    assert request.method == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert json.loads(request.data) == {"kind": "test"}


def test_the_request_names_itself():
    """The prober publishes who it is and so does this. An endpoint operator
    reading their own log should be able to tell who called."""
    opener = FakeOpener()
    webhook.send({}, CONFIGURED, resolver=lambda h: PUBLIC, opener=opener)
    assert "whichports" in opener.requests[0].get_header("User-agent")


@pytest.mark.parametrize("status", [301, 302, 307, 400, 401, 500])
def test_a_status_that_is_not_success_is_not_a_delivery(status):
    """A 3xx reaches here as a failure because redirects are refused. Following
    one would let the endpoint move the request to an address this module
    already decided not to send to."""
    ok, _reason = webhook.send({}, CONFIGURED, resolver=lambda h: PUBLIC,
                               opener=FakeOpener(status=status))
    assert ok is False


def test_an_endpoint_that_raises_is_a_reason_not_an_exception():
    """The caller is a timer. One broken delivery path must never wedge the
    sweep that found the problem."""
    class Broken:
        def open(self, request, timeout=None):
            raise OSError("connection reset by peer")
    ok, reason = webhook.send({}, CONFIGURED, resolver=lambda h: PUBLIC,
                              opener=Broken())
    assert ok is False
    assert "OSError" in reason
    # The class, never the endpoint's own message.
    assert "connection reset by peer" not in reason


# ------------------------------------------------------- what it discloses

def test_the_url_is_never_in_a_repr():
    """A webhook URL routinely carries its own secret in the path."""
    text = repr(webhook.Config(url="https://hooks.example.com/T00/B01/SUPERSECRET"))
    assert "SUPERSECRET" not in text
    assert "url=set" in text


def test_the_relay_password_is_never_in_a_repr():
    """app/notify.py's Config printed it in full until this change. Nothing
    formatted one, which is why it was never noticed."""
    text = repr(notify.Config(to="a@b.c", host="relay", password="SUPERSECRET"))
    assert "SUPERSECRET" not in text
    assert "password=set" in text


def test_the_payload_carries_the_same_strings_the_mail_does():
    """The mail is the ceiling on disclosure. The description is passed
    through rather than taken apart, because lifting quoted firewall rule text
    into its own field would make it easier to consume, which is the same
    thing as disclosing more."""
    change = notify.Change(where="tcp/443 v4", was="intended", now="conflict",
                           description="host firewall permits it: ...",
                           vantage="probe1", measured_at=NOW.isoformat())
    payload = webhook.payload_for_changes("box", [change])
    assert payload["server"] == "box"
    assert payload["version"] == webhook.PAYLOAD_VERSION
    assert payload["changes"][0]["description"] == change.description
    assert set(payload["changes"][0]) == {
        "where", "was", "now", "description", "vantage", "measured_at"}


def test_the_one_line_payload_carries_no_more_than_the_mail():
    payload = webhook.payload_for_alert("agent silent", "box", "silent 40m",
                                        NOW.isoformat())
    assert set(payload) == {"version", "kind", "server", "detail", "raised_at"}


def test_the_payload_is_json_serialisable():
    change = notify.Change(where="tcp/22 v6", was="", now="unreviewed",
                           description="d")
    json.dumps(webhook.payload_for_changes("box", [change]))
    json.dumps(webhook.payload_for_alert("agent silent", "box", "d", "t"))
