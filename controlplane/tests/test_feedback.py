"""The Feedback window's wire, the control plane's half
(docs/screens/feedback/BRIEF.md, docs/record 4.425).

SI-8 has one exception: the words a person types into the Feedback window
and sends with a click. These hold the exception to exactly that. Five
fields leave an instance and nothing else, only an instance's API key is
taken, the words reach no log, and nothing is kept or sent again when our
box does not answer.

Two routes. `POST /api/v1/feedback` is ours, asked by an instance with its
key. `POST /api/admin/feedback` is the one a signed-in person's browser
asks on whatever instance they are signed in to: it sends the message on to
us when that instance has our key, and writes it into its own table when it
has none.
"""
import importlib
import io
import json
import logging
import sqlite3
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app import (accounts, authz, db, dispatch, feedback, feedback_routes,
                 ingest, instances, proberapi, store, vantages, web_auth)

OURS = "/api/v1/feedback"
THEIRS = "/api/admin/feedback"
EMAIL = "operator@example.com"
OTHER_EMAIL = "somebody-else@example.com"
PASSWORD = "correct-horse-battery-9"
A_SECRET_NAME = "web-01-in-the-cellar"
AN_ADDRESS = "185.199.108.153"
WORDS = "The Open button is cut off at 1024.\nSecond line."


def body(**overrides) -> dict:
    base = {"version": 1, "kind": "bug", "words": WORDS, "screen": "host/rules",
            "instance_version": "0835a67"}
    base.update(overrides)
    return base


def as_sent(payload: dict) -> bytes:
    """A body as an instance writes it: UTF-8 as it is, nothing escaped."""
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def rows(path=None) -> list:
    con = sqlite3.connect(path or db.db_path())
    con.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in con.execute("SELECT * FROM feedback ORDER BY id")]
    finally:
        con.close()


# ------------------------------------------------------------- our box

@pytest.fixture()
def ours(tmp_path, monkeypatch):
    """Our box: the ingest behind Caddy on loopback, two instances issued.
    Returns (client, {name: Issued})."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "ours.db"))
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    con = db.connect()
    for module in (db, authz, vantages, instances, proberapi, feedback):
        module.init(con)
    issued = {name: instances.add(con, name, origin=authz.ORIGIN_INVITED)
              for name in ("one", "two")}
    con.close()
    return TestClient(ingest.app, client=("127.0.0.1", 40000)), issued


def key(issued, kind="api") -> dict:
    return {"Authorization": "Bearer " + (issued.api_key if kind == "api"
                                          else issued.proof_key)}


def send(client, issued, payload=None, raw: bytes | None = None, **headers):
    sent = dict(key(issued))
    sent.update(headers)
    return client.post(OURS, headers=sent,
                       content=raw if raw is not None else as_sent(payload or body()))


def assert_refused(answer, error):
    assert answer.status_code == proberapi.ERRORS[error], answer.text
    assert answer.json() == {"error": error}


def test_our_side_stores_the_instance_by_its_key_and_never_the_source_address(ours):
    client, issued = ours
    answer = send(client, issued["one"], **{"X-Forwarded-For": AN_ADDRESS,
                                           "User-Agent": "a-browser-of-somebody"})
    assert answer.status_code == 200, answer.text
    [row] = rows()
    assert row["instance_id"] == issued["one"].instance.id
    assert row["workspace_id"] is None
    assert (row["kind"], row["words"], row["screen"], row["instance_version"]) == (
        "bug", WORDS, "host/rules", "0835a67")
    assert row["done_at"] is None
    assert datetime.fromisoformat(row["received_at"]).tzinfo is not None
    # The whole row, every column: no address and no user agent in it, and
    # no column to hold one.
    assert set(row) == {"id", "instance_id", "workspace_id", "kind", "words",
                        "screen", "instance_version", "received_at", "done_at"}
    everything = json.dumps(row)
    assert AN_ADDRESS not in everything and "127.0.0.1" not in everything
    assert "a-browser-of-somebody" not in everything


def test_the_answer_is_a_status_and_carries_nothing_back(ours):
    """SI-2 on the way back: nothing in the answer for an instance to act on."""
    client, issued = ours
    answer = send(client, issued["one"])
    assert answer.status_code == 200 and answer.json() == {"stored": True}


def test_an_unknown_and_a_revoked_key_get_the_same_refusal(ours):
    client, issued = ours
    con = db.connect()
    instances.revoke(con, "two")
    con.close()
    never_issued = client.post(OURS, content=as_sent(body()),
                               headers={"Authorization": "Bearer whpi_" + "0" * 64})
    revoked = send(client, issued["two"])
    no_key = client.post(OURS, content=as_sent(body()))
    for answer in (never_issued, revoked, no_key):
        assert_refused(answer, "unknown_key")
    assert never_issued.content == revoked.content == no_key.content
    assert rows() == []


def test_a_proof_key_gets_the_same_refusal_as_a_key_nobody_issued(ours):
    """The proof key is in every agent's install command. If it were taken
    here, whoever holds a server could write into the console, which is what
    the exception to SI-8 does not cover: nothing an agent sends."""
    client, issued = ours
    with_proof_key = client.post(OURS, content=as_sent(body()),
                                 headers=key(issued["one"], "proof"))
    never_issued = client.post(OURS, content=as_sent(body()),
                               headers={"Authorization": "Bearer whpp_" + "0" * 64})
    assert_refused(with_proof_key, "unknown_key")
    assert with_proof_key.content == never_issued.content
    assert rows() == []


def test_the_refusals_are_five_classes_of_the_prober_apis_set_and_the_set_is_unchanged():
    assert feedback.REFUSALS == ("unknown_key", "malformed_request",
                                 "unsupported_version", "too_large",
                                 "over_instance_pace")
    assert set(feedback.REFUSALS) < set(proberapi.ERRORS)
    assert sorted(proberapi.ERRORS) == sorted([
        "unknown_key", "malformed_request", "unsupported_version", "too_large",
        "unknown_vantage", "names_a_vantage_address", "target_refused",
        "batch_in_flight", "over_instance_pace", "unknown_batch",
        "unknown_challenge"])


def test_a_body_over_eight_kib_is_refused_before_it_is_parsed(ours):
    """8,193 bytes that are not JSON at all. Parsed, they would be
    malformed_request. Refused on their length, they are too_large."""
    client, issued = ours
    assert feedback.MAX_BODY_BYTES == 8192
    assert_refused(send(client, issued["one"], raw=b"{" * 8193), "too_large")
    assert_refused(send(client, issued["one"], raw=b"{" * 8192), "malformed_request")
    assert rows() == []


def test_words_over_two_thousand_characters_are_refused_as_too_large(ours):
    client, issued = ours
    assert send(client, issued["one"], body(words="a" * 2000)).status_code == 200
    assert_refused(send(client, issued["one"], body(words="a" * 2001)), "too_large")
    assert len(rows()) == 1


def test_two_thousand_characters_of_any_alphabet_fit_under_the_byte_cap(ours):
    """Sent as UTF-8, 2,000 four-byte characters are 8,000 bytes and fit.
    Escaped the way json does by default they would be 24,000 and every
    report in Chinese would read "Too long" a sixth of the way in."""
    client, issued = ours
    words = "\U0001F41B" * 2000
    sent = as_sent(body(words=words, screen="host/evidence", instance_version="f" * 40))
    assert len(sent) <= feedback.MAX_BODY_BYTES
    assert len(json.dumps(body(words=words)).encode()) > feedback.MAX_BODY_BYTES
    answer = send(client, issued["one"], raw=sent)
    assert answer.status_code == 200, answer.text
    assert rows()[0]["words"] == words


@pytest.mark.parametrize("payload", [
    body(host="web-01"),                       # a sixth field
    {k: v for k, v in body().items() if k != "screen"},   # one missing
    body(kind="praise"),
    body(kind=7),
    body(words=7),
    body(words=""),
    body(words="‮\t\r"),                  # nothing left once cleaned
    body(instance_version="0835a6"),            # six characters
    body(instance_version="0835A67"),
    body(instance_version="g" * 7),
    body(instance_version="f" * 41),
    body(version="1"),
    [1, 2, 3],
    "words",
])
def test_a_body_that_is_not_the_five_fields_is_refused_as_malformed(ours, payload):
    client, issued = ours
    assert_refused(send(client, issued["one"], payload), "malformed_request")
    assert rows() == []


def test_a_sixth_field_is_refused_as_malformed(ours):
    client, issued = ours
    assert_refused(send(client, issued["one"], body(address=AN_ADDRESS)),
                   "malformed_request")
    assert rows() == []


def test_another_shape_number_is_refused_as_unsupported_version(ours):
    client, issued = ours
    for number in (0, 2, 99):
        assert_refused(send(client, issued["one"], body(version=number)),
                       "unsupported_version")
    assert rows() == []


def test_on_our_box_an_unknown_screen_word_of_a_good_shape_is_taken(ours):
    """An instance and our box are at different commits most of the time.
    The day a screen is added, our box must still take a report from it."""
    client, issued = ours
    assert "a-screen-we-add/next-year" not in feedback.SCREENS
    answer = send(client, issued["one"], body(screen="a-screen-we-add/next-year"))
    assert answer.status_code == 200, answer.text
    assert rows()[0]["screen"] == "a-screen-we-add/next-year"


@pytest.mark.parametrize("word", [
    "", "Host/Rules", "host rules", "/host/web-01.example.org/rules", "host.rules",
    "host/rules?x=1", "<b>", "-host", "a" * 41, 7])
def test_on_our_box_a_screen_word_of_a_bad_shape_is_refused(ours, word):
    """Lower-case letters, slash and hyphen, forty at most. So a path with a
    server's name in it, which has dots, cannot arrive as a screen."""
    client, issued = ours
    assert_refused(send(client, issued["one"], body(screen=word)), "malformed_request")
    assert rows() == []


def stored_at(when: datetime, **where) -> None:
    con = db.connect()
    feedback.store(con, feedback.parse(body(), closed_list=False), now=when, **where)
    con.close()


def test_a_twenty_first_message_in_a_day_is_refused_as_over_instance_pace(ours):
    client, issued = ours
    assert feedback.PER_DAY == 20
    for _ in range(20):
        assert send(client, issued["one"]).status_code == 200
    assert_refused(send(client, issued["one"]), "over_instance_pace")
    assert len(rows()) == 20
    # Another instance has a day of its own.
    assert send(client, issued["two"]).status_code == 200


def test_a_day_is_the_last_24_hours_and_a_done_message_still_counts(ours):
    client, issued = ours
    one = issued["one"].instance.id
    now = datetime.now(timezone.utc)
    for _ in range(19):
        stored_at(now - timedelta(hours=23, minutes=59), instance_id=one)
    stored_at(now - timedelta(hours=24, minutes=1), instance_id=one)
    con = db.connect()
    for row in rows():
        feedback.mark_done(con, row["id"])
    con.close()
    # Nineteen inside the day, one just outside it: one more fits, then none.
    assert send(client, issued["one"]).status_code == 200
    assert_refused(send(client, issued["one"]), "over_instance_pace")


def test_control_characters_are_stripped_and_newlines_kept(ours):
    """One list, the page's and both servers': every control character but
    the newline, and the marks that turn the direction of a line, which
    survive escaping and can make a row read as something it is not."""
    client, issued = ours
    dirty = "one\ttwo\x00\x07\x1b[31m\r\nthree\rfour‮drow⁦x⁩\x7f\x85 fünf \U0001F41B"
    answer = send(client, issued["one"], body(words=dirty))
    assert answer.status_code == 200, answer.text
    assert rows()[0]["words"] == "onetwo[31m\nthreefourdrowx fünf \U0001F41B"
    assert feedback.clean("a\r\nb") == "a\nb"
    assert feedback.clean("a\nb") == "a\nb"
    for mark in ("‪", "‫", "‬", "‭", "‮",
                 "⁦", "⁧", "⁨", "⁩"):
        assert feedback.clean(f"a{mark}b") == "ab"
    # Nothing else of Unicode goes: a joiner inside an emoji stays.
    assert feedback.clean("\U0001F468‍\U0001F469") == "\U0001F468‍\U0001F469"


def test_the_words_are_counted_after_cleaning(ours):
    client, issued = ours
    answer = send(client, issued["one"], body(words="a" * 2000 + "\r\t\x00"))
    assert answer.status_code == 200, answer.text
    assert len(rows()[0]["words"]) == 2000


class EveryRecord(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.said = []

    def emit(self, record):
        self.said.append(record.getMessage() + " " + repr(record.args))


@pytest.fixture()
def every_log_line():
    handler = EveryRecord()
    root = logging.getLogger()
    before = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    yield handler.said
    root.removeHandler(handler)
    root.setLevel(before)


A_PHRASE = "the-words-nobody-may-log"


def test_the_words_never_reach_a_log_on_our_box(ours, every_log_line):
    client, issued = ours
    assert send(client, issued["one"], body(words=A_PHRASE)).status_code == 200
    assert_refused(send(client, issued["one"], body(words=A_PHRASE, version=2)),
                   "unsupported_version")
    assert_refused(send(client, issued["one"], body(words=A_PHRASE, extra=1)),
                   "malformed_request")
    assert_refused(client.post(OURS, content=as_sent(body(words=A_PHRASE))), "unknown_key")
    assert_refused(send(client, issued["one"], body(words=A_PHRASE + "a" * 2000)),
                   "too_large")
    assert not any(A_PHRASE in line for line in every_log_line)


# --------------------------------------------------------- an instance

class Recorder:
    """Stands where the client's opener stands. It writes down every request
    it is handed and answers the way it was told to."""

    def __init__(self, answer=None, error=None):
        self.requests, self.timeouts = [], []
        self.answer, self.error = answer, error

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        return self.answer if self.answer is not None else _Answer(200, b'{"stored": true}')


class _Answer:
    def __init__(self, status, raw):
        self.status, self._raw = status, raw

    def read(self, _limit=None):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(status: int, error: str):
    return urllib.error.HTTPError("https://ours.example/api/v1/feedback", status, "refused",
                                  {}, io.BytesIO(json.dumps({"error": error}).encode()))


class NothingLeaves:
    def open(self, request, timeout=None):
        raise AssertionError(f"a request left this instance: {request.full_url}")


@pytest.fixture()
def instance(tmp_path, monkeypatch):
    """An instance somebody runs: a signed-in account in workspace 1, a
    second account in a workspace of its own, a server with a name, an
    address and a document. No prober API key unless a test sets one.
    Returns the signed-in client."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "theirs.db"))
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    con = db.connect()
    for module in (db, accounts, feedback):
        module.init(con)
    accounts.create_user(con, EMAIL, PASSWORD)
    other = db.create_workspace(con, "Somebody else")
    accounts.create_user(con, OTHER_EMAIL, PASSWORD, workspace_id=other)
    host_id, _ = store.add_host(con, A_SECRET_NAME)
    store.insert_report(con, host_id, 1, 1, json.dumps({
        "interface_addresses": {"addresses": [{"address": AN_ADDRESS}]}}))
    con.close()
    return signed_in(EMAIL)


def signed_in(email: str) -> TestClient:
    con = db.connect()
    user = accounts.get_user_by_email(con, email)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def with_our_key(monkeypatch, opener, base="https://ours.example",
                 api_key="whpi_" + "a" * 64):
    monkeypatch.setenv(dispatch.PROBER_API_ENV, base)
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, api_key)
    monkeypatch.setattr(feedback_routes, "opener", lambda: opener)
    return api_key


def press_send(client, payload=None, raw: bytes | None = None):
    return client.post(THEIRS, content=raw if raw is not None else as_sent(payload or body()),
                       headers={"Content-Type": "application/json"})


def test_without_a_session_nothing_is_taken(instance, monkeypatch):
    with_our_key(monkeypatch, NothingLeaves())
    answer = press_send(TestClient(ingest.app))
    assert answer.status_code == 403
    assert rows() == []


def test_without_a_prober_api_key_the_row_is_written_here_and_nothing_leaves(
        instance, monkeypatch):
    monkeypatch.setattr(feedback_routes, "opener", lambda: NothingLeaves())
    answer = press_send(instance)
    assert answer.status_code == 200, answer.text
    [row] = rows()
    assert row["workspace_id"] == db.DEFAULT_WORKSPACE_ID
    assert row["instance_id"] is None
    assert row["words"] == WORDS


def test_with_a_key_one_request_leaves_with_the_five_fields_and_nothing_else(
        instance, monkeypatch):
    """A fleet with a named server, an address and a document behind the
    page. The body that leaves is searched whole for each of them."""
    out = Recorder()
    api_key = with_our_key(monkeypatch, out)
    words = "It broke on the Rules tab. Größe 北京 \U0001F41B"
    answer = press_send(instance, body(words=words))
    assert answer.status_code == 200, answer.text
    [request] = out.requests
    assert request.full_url == "https://ours.example/api/v1/feedback"
    assert request.get_method() == "POST"
    sent = json.loads(request.data.decode("utf-8"))
    assert tuple(sent) == feedback.FIELDS
    assert sent == body(words=words)
    # UTF-8 as it is, so the byte cap means what the window says.
    assert words.encode("utf-8") in request.data
    whole = request.data.decode("utf-8") + json.dumps(dict(request.header_items()))
    for never in (A_SECRET_NAME, AN_ADDRESS, EMAIL, "theirs.db", "testserver",
                  "Cookie", web_auth.SESSION_COOKIE):
        assert never not in whole.replace(api_key, ""), never
    # Stored on our side, so nothing is stored here.
    assert rows() == []


def test_the_outbound_request_carries_the_bearer_key_and_no_cookie(instance, monkeypatch):
    out = Recorder()
    api_key = with_our_key(monkeypatch, out)
    assert press_send(instance).status_code == 200
    headers = {name.lower(): value for name, value in out.requests[0].header_items()}
    assert headers["authorization"] == f"Bearer {api_key}"
    assert "cookie" not in headers
    assert headers["user-agent"] == "whichports-prober-api-client"
    assert set(headers) == {"authorization", "content-type", "user-agent"}


def test_it_gives_up_before_the_window_does(instance, monkeypatch):
    """The window waits ten seconds. If this request could take ten too, the
    person would read "No answer" while our box stored the message a moment
    later, and send it twice."""
    out = Recorder()
    with_our_key(monkeypatch, out)
    assert press_send(instance).status_code == 200
    assert out.timeouts == [dispatch.FEEDBACK_REQUEST_SECONDS]
    assert dispatch.FEEDBACK_REQUEST_SECONDS == 8.0


@pytest.mark.parametrize("failure", [
    urllib.error.URLError("no route"), TimeoutError("timed out"), OSError("reset")])
def test_no_answer_writes_nothing_and_retries_nothing(instance, monkeypatch, failure):
    out = Recorder(error=failure)
    with_our_key(monkeypatch, out)
    answer = press_send(instance)
    assert answer.status_code == 502
    assert answer.json() == {"error": "no_answer"}
    assert len(out.requests) == 1, "one request, and no second try"
    assert rows() == []


@pytest.mark.parametrize("error", ["unknown_key", "too_large", "over_instance_pace",
                                   "malformed_request", "unsupported_version"])
def test_our_boxs_refusal_reaches_the_window_as_its_class(instance, monkeypatch, error):
    out = Recorder(error=http_error(proberapi.ERRORS[error], error))
    with_our_key(monkeypatch, out)
    answer = press_send(instance)
    assert answer.status_code == proberapi.ERRORS[error]
    assert answer.json() == {"error": error}
    assert len(out.requests) == 1 and rows() == []


@pytest.mark.parametrize("status, said", [
    (404, "unknown_vantage"),            # a class of the set that is not one of the five
    (500, "a sentence our box would never say"),
    (502, ""),                           # no class at all: this once read as stored
    (500, "stored"),
    (400, True),
    (400, ["malformed_request"]),
])
def test_anything_else_our_box_says_is_no_answer_and_none_of_it_is_passed_on(
        instance, monkeypatch, status, said):
    """The window prints five classes and "No answer". Nothing our box says
    beyond those reaches the page, so nothing in an answer is acted on."""
    out = Recorder(error=http_error(status, said))
    with_our_key(monkeypatch, out)
    answer = press_send(instance)
    assert answer.status_code == 502
    assert answer.json() == {"error": "no_answer"}
    assert rows() == []


def test_a_redirect_is_never_followed_with_the_key(instance, monkeypatch):
    """Through the prober API's own client, which refuses a redirect: urllib
    would carry the Authorization header to wherever it pointed."""
    monkeypatch.setenv(dispatch.PROBER_API_ENV, "https://ours.example")
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, "whpi_" + "a" * 64)
    assert feedback_routes.opener() is None, "the client's own opener, and no other"
    client = dispatch.ApiTransport("-", base_url="https://ours.example",
                                   key="whpi_" + "a" * 64)
    assert any(isinstance(handler, dispatch._RefuseRedirects)
               for handler in client._opener.handlers)


@pytest.mark.parametrize("base", ["http://ours.example", "https://ours.example/api",
                                  "ours.example"])
def test_an_address_that_is_not_plain_https_sends_nothing(instance, monkeypatch, base):
    with_our_key(monkeypatch, NothingLeaves(), base=base)
    answer = press_send(instance)
    assert answer.status_code == 502 and answer.json() == {"error": "no_answer"}
    assert rows() == []


@pytest.mark.parametrize("present", [dispatch.PROBER_API_ENV, dispatch.PROBER_API_KEY_ENV])
def test_one_setting_without_the_other_sends_nothing_and_stores_nothing(
        instance, monkeypatch, present):
    """Half configured, as a pass refuses it. Storing here would tell the
    person they had reached us."""
    monkeypatch.setenv(present, "https://ours.example"
                       if present == dispatch.PROBER_API_ENV else "whpi_" + "a" * 64)
    monkeypatch.setattr(feedback_routes, "opener", lambda: NothingLeaves())
    answer = press_send(instance)
    assert answer.status_code == 502 and answer.json() == {"error": "no_answer"}
    assert rows() == []


def test_a_post_lands_under_the_sessions_own_workspace_and_no_other(instance, monkeypatch):
    monkeypatch.setattr(feedback_routes, "opener", lambda: NothingLeaves())
    theirs = signed_in(OTHER_EMAIL)
    assert press_send(theirs).status_code == 200
    assert press_send(instance).status_code == 200
    con = db.connect()
    other = accounts.workspace_of(accounts.get_user_by_email(con, OTHER_EMAIL))
    con.close()
    assert [row["workspace_id"] for row in rows()] == [other, db.DEFAULT_WORKSPACE_ID]
    # No field names a workspace: one that tries is a sixth field.
    answer = press_send(instance, body(workspace_id=other))
    assert answer.status_code == 400 and answer.json() == {"error": "malformed_request"}
    assert len(rows()) == 2


def test_a_screen_word_off_the_list_is_refused_as_malformed(instance, monkeypatch):
    """On an instance the page and this route are one commit, so the list is
    closed here, and a word the page cannot have sent is refused before
    anything leaves."""
    with_our_key(monkeypatch, NothingLeaves())
    assert feedback.SCREENS == (
        "fleet", "host", "host/services", "host/evidence", "host/rules", "host/path",
        "host/changes", "host/settings", "alerts", "integrations", "settings", "admin")
    for word in ("a-screen-we-add/next-year", "host/web-01/rules", ""):
        answer = press_send(instance, body(screen=word))
        assert answer.status_code == 400 and answer.json() == {"error": "malformed_request"}
    assert rows() == []


def test_what_is_wrong_with_a_body_is_refused_here_before_anything_leaves(
        instance, monkeypatch):
    with_our_key(monkeypatch, NothingLeaves())
    for payload, status, error in (
            (body(extra=1), 400, "malformed_request"),
            (body(version=2), 400, "unsupported_version"),
            (body(words="a" * 2001), 413, "too_large")):
        answer = press_send(instance, payload)
        assert (answer.status_code, answer.json()) == (status, {"error": error})
    assert press_send(instance, raw=b"{" * 8193).status_code == 413


def test_what_leaves_is_the_words_as_cleaned(instance, monkeypatch):
    """The page takes these characters out as they are typed, so the person
    saw the words without them. A page that did not is not believed."""
    out = Recorder()
    with_our_key(monkeypatch, out)
    assert press_send(instance, body(words="left‮\tright\r\nnext")).status_code == 200
    assert json.loads(out.requests[0].data)["words"] == "leftright\nnext"


def test_the_local_path_has_the_cap_too_twenty_a_day_for_a_workspace(instance, monkeypatch):
    monkeypatch.setattr(feedback_routes, "opener", lambda: NothingLeaves())
    for _ in range(20):
        assert press_send(instance).status_code == 200
    answer = press_send(instance)
    assert answer.status_code == 429 and answer.json() == {"error": "over_instance_pace"}
    assert press_send(signed_in(OTHER_EMAIL)).status_code == 200
    assert len(rows()) == 21


def test_the_words_never_reach_a_log_on_an_instance(instance, monkeypatch, every_log_line):
    out = Recorder()
    with_our_key(monkeypatch, out)
    assert press_send(instance, body(words=A_PHRASE)).status_code == 200
    out.error = urllib.error.URLError("no route")
    assert press_send(instance, body(words=A_PHRASE)).status_code == 502
    out.error = http_error(429, "over_instance_pace")
    assert press_send(instance, body(words=A_PHRASE)).status_code == 429
    assert press_send(instance, body(words=A_PHRASE, extra=1)).status_code == 400
    monkeypatch.delenv(dispatch.PROBER_API_ENV)
    monkeypatch.delenv(dispatch.PROBER_API_KEY_ENV)
    assert press_send(instance, body(words=A_PHRASE)).status_code == 200
    assert not any(A_PHRASE in line for line in every_log_line)


def test_the_body_shape_matches_what_the_site_sends():
    """The one tuple of field names. The page's own test holds its side to
    the same tuple."""
    assert feedback.FIELDS == ("version", "kind", "words", "screen", "instance_version")
    assert feedback.BODY_VERSION == 1
    assert feedback.KINDS == ("feature", "bug")
    assert feedback.MAX_WORDS == 2000


# ------------------------------------------------- the table, and his console

@pytest.fixture()
def table(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "table.db"))
    con = db.connect()
    for module in (db, instances, feedback):
        module.init(con)
    yield con
    con.close()


def insert(con, **values):
    row = {"instance_id": None, "workspace_id": 1, "kind": "bug", "words": "w",
           "screen": "fleet", "instance_version": "unknown",
           "received_at": "2026-10-07T12:00:00+00:00"}
    row.update(values)
    con.execute(f"INSERT INTO feedback ({', '.join(row)}) VALUES"
                f" ({', '.join('?' for _ in row)})", tuple(row.values()))


def test_a_row_is_from_an_instance_or_from_a_workspace_and_never_both_or_neither(table):
    insert(table)
    insert(table, instance_id=3, workspace_id=None)
    for both_or_neither in ({"instance_id": 3, "workspace_id": 1},
                            {"instance_id": None, "workspace_id": None}):
        with pytest.raises(sqlite3.IntegrityError):
            insert(table, **both_or_neither)


def test_a_kind_is_one_of_the_two_words_in_the_table_itself(table):
    with pytest.raises(sqlite3.IntegrityError):
        insert(table, kind="praise")


def test_the_count_of_a_day_has_an_index_on_each_side(table):
    indexed = {tuple(r[2] for r in table.execute(f"PRAGMA index_info({row[1]})"))
               for row in table.execute("PRAGMA index_list(feedback)")}
    assert ("instance_id", "received_at") in indexed
    assert ("workspace_id", "received_at") in indexed


def test_init_twice_changes_nothing(table):
    insert(table)
    feedback.init(table)
    assert table.execute("SELECT COUNT(*) FROM feedback").fetchone()[0] == 1


def test_the_console_reads_open_ones_newest_first_and_done_ones_apart(table):
    message = feedback.parse(body(), closed_list=False)
    then = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
    first = feedback.store(table, message, workspace_id=1, now=then)
    second = feedback.store(table, message, instance_id=4, now=then + timedelta(minutes=5))
    assert [row["id"] for row in feedback.listing(table, done=False)] == [second, first]
    assert feedback.listing(table, done=True) == []
    assert feedback.mark_done(table, first, now=then + timedelta(hours=1)) is True
    assert [row["id"] for row in feedback.listing(table, done=False)] == [second]
    [done] = feedback.listing(table, done=True)
    assert done["id"] == first and done["done_at"] == "2026-10-07T13:00:00+00:00"
    assert feedback.count_open(table) == 1
    # Done twice is done once: the first time stays.
    assert feedback.mark_done(table, first, now=then + timedelta(hours=9)) is False
    assert feedback.listing(table, done=True)[0]["done_at"] == "2026-10-07T13:00:00+00:00"
    assert feedback.mark_done(table, 999) is False


def test_a_deleted_message_is_gone_from_the_table(table):
    """For the person who typed a secret by mistake (docs/record 4.436). The
    row is deleted, not hidden: nothing of it is left in this table."""
    message = feedback.parse(body(words=A_PHRASE), closed_list=False)
    kept = feedback.store(table, message, workspace_id=1)
    gone = feedback.store(table, message, instance_id=4)
    assert feedback.delete(table, gone) is True
    assert [row["id"] for row in feedback.listing(table, done=False)] == [kept]
    assert table.execute("SELECT COUNT(*) FROM feedback WHERE id = ?", (gone,)).fetchone()[0] == 0
    assert feedback.delete(table, gone) is False
    assert feedback.delete(table, 999) is False


def test_a_deleted_message_no_longer_counts_towards_the_day(table):
    message = feedback.parse(body(), closed_list=False)
    ids = [feedback.store(table, message, instance_id=4) for _ in range(20)]
    assert feedback.sent_in_the_last_day(table, instance_id=4) == 20
    feedback.delete(table, ids[0])
    assert feedback.sent_in_the_last_day(table, instance_id=4) == 19


# --------------------------------------------- the window's To line, and
# the console's two writes, built with the page (docs/screens/feedback/
# BRIEF.md, docs/record 4.425 and 4.436)

def test_the_to_line_is_our_host_with_both_settings_and_nothing_without():
    """The window's To line: the host of the prober API when both settings
    are set, so a message leaves, and nothing otherwise, when the message
    stays on the instance and the page names its own host."""
    both = {dispatch.PROBER_API_ENV: "https://ours.example",
            dispatch.PROBER_API_KEY_ENV: "whpi_" + "a" * 64}
    assert feedback_routes.destination(both) == "ours.example"
    assert feedback_routes.destination({dispatch.PROBER_API_ENV: "https://ours.example:8443/"}
                                       | {dispatch.PROBER_API_KEY_ENV: "k"}) == "ours.example:8443"
    assert feedback_routes.destination({}) == ""
    assert feedback_routes.destination({dispatch.PROBER_API_ENV: "https://ours.example"}) == ""
    assert feedback_routes.destination({dispatch.PROBER_API_KEY_ENV: "k"}) == ""
    assert feedback_routes.destination({dispatch.PROBER_API_ENV: "not a url",
                                        dispatch.PROBER_API_KEY_ENV: "k"}) == ""


def test_the_page_carries_the_to_line_from_the_settings(instance, monkeypatch):
    # app/dashboard.py, loaded by its dotted name: the export's check reads
    # a test that names the superseded Reflex app by that word, and this
    # one is the page module that the public tree has.
    dashboard = importlib.import_module("app.dashboard")
    monkeypatch.setenv(dispatch.PROBER_API_ENV, "https://ours.example")
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, "whpi_" + "a" * 64)
    assert '<span class="v" id="fb-to">ours.example</span>' in dashboard.page(1)
    monkeypatch.delenv(dispatch.PROBER_API_ENV)
    monkeypatch.delenv(dispatch.PROBER_API_KEY_ENV)
    assert '<span class="v" id="fb-to" data-own="1"></span>' in dashboard.page(1)


def grant_admin(email):
    con = db.connect()
    assert accounts.set_admin(con, email, True)
    con.close()


def stored_rows():
    con = db.connect()
    try:
        return feedback.listing(con, done=False), feedback.listing(con, done=True)
    finally:
        con.close()


def test_done_and_delete_are_the_consoles_two_writes_under_the_admin_flag(instance):
    """An account with the flag marks a message done and deletes one. An
    account without it gets the answer the lookup gives a signed-in
    stranger, 404, and no session gets 403. Nothing moves either way."""
    assert press_send(instance, body(words="first")).status_code == 200
    assert press_send(instance, body(words="second")).status_code == 200
    (second, first), _done = stored_rows()
    done_path = f"{THEIRS}/{first['id']}/done"
    delete_path = f"{THEIRS}/{second['id']}/delete"
    # A signed-in account without the flag: refused, nothing moves.
    assert instance.post(done_path).status_code == 404
    assert instance.post(delete_path).status_code == 404
    assert signed_in(OTHER_EMAIL).post(done_path).status_code == 404
    assert TestClient(ingest.app).post(done_path).status_code == 403
    assert TestClient(ingest.app).post(delete_path).status_code == 403
    assert len(stored_rows()[0]) == 2 and stored_rows()[1] == []
    grant_admin(EMAIL)
    admin = signed_in(EMAIL)
    answer = admin.post(done_path)
    assert answer.status_code == 200 and answer.json() == {"done": True}
    assert answer.headers["cache-control"] == "no-store"
    open_rows, done_rows = stored_rows()
    assert [r["words"] for r in open_rows] == ["second"]
    assert [r["words"] for r in done_rows] == ["first"]
    # Done twice does not move the time of the first.
    assert admin.post(done_path).status_code == 404
    answer = admin.post(delete_path)
    assert answer.status_code == 200 and answer.json() == {"deleted": True}
    assert stored_rows() == ([], done_rows)
    assert admin.post(delete_path).status_code == 404
    assert admin.post(f"{THEIRS}/999999/done").status_code == 404


def test_the_consoles_writes_take_a_number_and_nothing_else(instance):
    grant_admin(EMAIL)
    admin = signed_in(EMAIL)
    for path in (f"{THEIRS}/x/done", f"{THEIRS}/1;2/delete", f"{THEIRS}//done"):
        assert admin.post(path).status_code in (404, 422), path
