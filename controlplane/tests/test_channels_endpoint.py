"""The channels admin API: its gate, its refusals, and what it will not say.

    python -m pytest tests/test_channels_endpoint.py

The fixture and the gate pattern are test_admin.py's, read there first.

`app/channels.py` owns every rule about what a channel may be, and
tests/test_channels.py is the review of those rules. This file reviews the four
endpoints in front of them, and there are four things it is here to hold:

- the gate refuses before anything is read or written, on every one of them,
- a refusal arrives as a 400 carrying channels.py's own sentence rather than a
  second sentence written here,
- a label arriving in a URL either names a live channel or is a 404, whatever
  it holds,
- no response and no refusal ever carries the value of an environment
  variable.
"""

import json
import shlex
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from app import accounts, channels, db, ingest, web_auth
from operator_gate import gate, sign_in


# A value that must never come back out of an endpoint. Tests that need it put
# it in the process environment, which is the closest a test gets to the
# alerts.env only the sweep unit reads on the box.
SECRET = "https://hooks.example.com/T00/B00/SUPERSECRETVALUE"

OPERATOR = "operator@example.com"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def an_account_with_no_channel(con, email, workspace_id=1):
    """An account, with the email channel it is given on creation taken out
    again (`tests/test_account_email_channel.py` holds that it is given).

    Every test in this file is about the routes acting on rows the test put
    there itself, and asserts the whole table, so it starts from an empty one.
    Deleted outright rather than removed, because `state()` lists removed
    rows too.
    """
    accounts.create_user(con, email, "correct-horse-battery-9",
                         workspace_id=workspace_id)
    con.execute("DELETE FROM notification_channels WHERE type = 'email'"
                " AND destination = ?", (email,))
    con.commit()


def signed_in_operator():
    """A browser signed in as a real operator, carrying its session cookie and
    no gate header. test_admin.py explains why both proofs are tested."""
    con = db.connect()
    db.init(con)
    accounts.init(con)
    if accounts.get_user_by_email(con, OPERATOR) is None:
        an_account_with_no_channel(con, OPERATOR)
    user = accounts.get_user_by_email(con, OPERATOR)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def add(client, headers=None, **fields):
    """POST /api/admin/channels with exactly the fields a test names, so a
    test can leave one out as easily as it can send a bad one."""
    if headers is None:
        headers = gate()
    return client.post("/api/admin/channels", content=json.dumps(fields),
                       headers=headers)


def a_webhook(client, label="ops"):
    return add(client, type="webhook", label=label,
               env="WHICHPORTS_WEBHOOK_URL")


def act(client, label, action, headers=None):
    """One of the three label actions, with the label encoded as a browser
    would encode it, so a space or a slash stays inside one path segment."""
    if headers is None:
        headers = gate()
    return client.post(f"/api/admin/channels/{quote(label, safe='')}/{action}",
                       headers=headers)


def rows():
    """Every channel row, live or removed, straight out of the database."""
    con = db.connect()
    try:
        channels.init(con)
        return con.execute("SELECT * FROM notification_channels"
                           " ORDER BY id").fetchall()
    finally:
        con.close()


def state():
    """Label, on or off, and removed or not, for every row. What a test asserts
    when it wants to say nothing moved."""
    return [(r["label"], r["enabled"], r["removed_at"] is not None)
            for r in rows()]


def live_labels():
    con = db.connect()
    try:
        channels.init(con)
        return [c.label for c in channels.live(con)]
    finally:
        con.close()


ACTIONS = ["enable", "disable", "remove"]


# ------------------------------------------------------------------ the gate

@pytest.mark.parametrize("path,body", [
    ("/api/admin/channels", "{}"),
    ("/api/admin/channels/ops/enable", None),
    ("/api/admin/channels/ops/disable", None),
    ("/api/admin/channels/ops/remove", None),
    ("/api/admin/channels/ops/test", None),
    ("/api/admin/channels/ops/destination", "{}"),
    ("/api/admin/channels/ops/events", "{}"),
])
def test_without_the_gate_header_every_endpoint_is_403(client, path, body):
    resp = (client.post(path) if body is None
            else client.post(path, content=body))
    assert resp.status_code == 403


def test_the_gate_refuses_before_the_lookup(client):
    """A live label and an unknown one answer identically without the gate, so
    an ungated caller cannot use these routes to find out which channels
    exist."""
    a_webhook(client, "real")
    assert client.post("/api/admin/channels/real/enable").status_code == 403
    assert client.post("/api/admin/channels/ghost/enable").status_code == 403


def test_an_ungated_call_changes_nothing(client):
    """The refusal is not only a status code. Nothing is created, nothing is
    switched off and nothing is removed."""
    a_webhook(client, "ops")
    assert add(client, headers={}, type="webhook", label="sneak",
               env="WHICHPORTS_A").status_code == 403
    assert act(client, "ops", "disable", headers={}).status_code == 403
    assert act(client, "ops", "remove", headers={}).status_code == 403
    assert state() == [("ops", 1, False)]


def test_a_bad_body_without_the_gate_is_still_403(client):
    """The gate comes first, so a caller who is not an operator learns nothing
    about how the body is parsed."""
    resp = client.post("/api/admin/channels", content="not json")
    assert resp.status_code == 403


# --------------------------------- the session path: a cookie, no gate header

def test_create_accepts_a_session_with_no_gate_header(client):
    op = signed_in_operator()
    resp = op.post("/api/admin/channels",
                   content=json.dumps({"type": "webhook", "label": "ops",
                                       "env": "WHICHPORTS_WEBHOOK_URL"}))
    assert resp.status_code == 201
    assert resp.json()["label"] == "ops"


def test_the_three_label_actions_accept_a_session_with_no_gate_header(client):
    op = signed_in_operator()
    assert op.post("/api/admin/channels",
                   content=json.dumps({"type": "webhook", "label": "ops",
                                       "env": "WHICHPORTS_WEBHOOK_URL"})
                   ).status_code == 201
    assert op.post("/api/admin/channels/ops/disable").status_code == 204
    assert op.post("/api/admin/channels/ops/enable").status_code == 204
    assert op.post("/api/admin/channels/ops/remove").status_code == 204


def test_a_revoked_session_with_no_gate_header_is_403(client):
    """Fail closed, and it also shows the tests above pass because the session
    is live rather than because the gate is open."""
    op = signed_in_operator()
    assert op.post("/api/admin/channels",
                   content=json.dumps({"type": "webhook", "label": "ops",
                                       "env": "WHICHPORTS_WEBHOOK_URL"})
                   ).status_code == 201
    con = db.connect()
    user = accounts.get_user_by_email(con, OPERATOR)
    accounts.revoke_all_sessions(con, user["id"])
    con.close()
    assert op.post("/api/admin/channels/ops/disable").status_code == 403
    assert state() == [("ops", 1, False)]


def test_a_made_up_session_cookie_is_403(client):
    made_up = accounts.SESSION_PREFIX + "not-real"
    bogus = TestClient(ingest.app,
                       cookies={web_auth.SESSION_COOKIE: made_up})
    assert bogus.post("/api/admin/channels", content="{}").status_code == 403
    assert bogus.post("/api/admin/channels/ops/remove").status_code == 403


# --------------------------------------------------------------- creating one

def test_creating_one_answers_201_with_the_channel_and_writes_the_row(client):
    resp = a_webhook(client, "ops")
    assert resp.status_code == 201
    assert resp.json() == {"type": "webhook", "label": "ops",
                           "env": "WHICHPORTS_WEBHOOK_URL", "chat_id": "",
                           "destination": "", "enabled": True, "events": []}
    assert state() == [("ops", 1, False)]


def test_the_response_has_exactly_the_seven_keys(client):
    """Five until 2026-08-22, six when a channel gained the choice of which
    kinds of alert it takes, seven when it gained a destination of its own."""
    body = a_webhook(client, "ops").json()
    assert set(body) == {"type", "label", "env", "chat_id", "destination",
                         "enabled", "events"}
    assert body["events"] == []


# ------------------------------------------- a destination, the ordinary way

SLACK_URL = "https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE"


def test_a_channel_can_be_created_with_the_destination_itself(client):
    resp = add(client, type="slack", label="ops", destination=SLACK_URL)
    assert resp.status_code == 201
    assert rows()[0]["destination"] == SLACK_URL


def test_the_response_never_gives_back_the_secret_segment(client):
    """The browser just sent it and does not need it back, and a response body
    is not a place a credential should be. Slack revokes leaked webhook URLs.

    **What a row shows widened on 2026-08-23** so the Destination column answers
    its own heading (`channels.Channel.hint`), and the part that must never come
    back is unchanged: the last path segment, which is the part that lets anybody
    post."""
    body = add(client, type="slack", label="ops", destination=SLACK_URL).json()
    assert body["destination"] == "hooks.slack.com/services/T00/B00/…"
    assert "SUPERSECRETVALUE" not in json.dumps(body)


def test_a_mail_row_gives_back_the_whole_address(client):
    """A recipient is not a credential, and mail is the row that read
    "set on this screen" until the owner pointed at it."""
    body = add(client, type="email", label="ops inbox",
               destination="ops@example.com").json()
    assert body["destination"] == "ops@example.com"


def test_sending_both_a_destination_and_a_variable_is_refused(client):
    """One or the other. Two sources for one answer is two things to keep in
    step and the sender would have to pick."""
    resp = add(client, type="slack", label="ops", env="WHICHPORTS_SLACK_URL",
               destination=SLACK_URL)
    assert resp.status_code == 400


def test_sending_neither_is_refused(client):
    resp = add(client, type="slack", label="ops")
    assert resp.status_code == 400


def test_a_destination_that_is_not_a_url_is_refused_without_being_echoed(client):
    resp = add(client, type="slack", label="ops",
               destination="hooks.slack.com/services/T/B/SUPERSECRETVALUE")
    assert resp.status_code == 400
    assert "SUPERSECRETVALUE" not in resp.text


def test_a_destination_never_reaches_an_error_body(client):
    """Every refusal reachable from this field, swept, because the thing an
    operator pastes into the wrong box is the secret one."""
    # The empty label used to be a refusal in this sweep. It is a generated
    # label since 2026-08-23, so a label that is refused for its shape stands
    # in for it.
    for kwargs in ({"type": "nonsense", "label": "ops", "destination": SLACK_URL},
                   {"type": "slack", "label": "-bad", "destination": SLACK_URL},
                   {"type": "slack", "label": "ops", "env": "WHICHPORTS_X",
                    "destination": SLACK_URL}):
        resp = add(client, **kwargs)
        assert resp.status_code == 400, kwargs
        assert "SUPERSECRETVALUE" not in resp.text, kwargs


def test_a_new_channel_is_on(client):
    a_webhook(client, "ops")
    assert rows()[0]["enabled"] == 1


def test_the_row_holds_the_variable_name_and_no_value(client, monkeypatch):
    """The property the whole table rests on, asserted through the API: what
    is written is a name, and the value stays in the environment."""
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", SECRET)
    a_webhook(client, "ops")
    stored = rows()[0]
    assert stored["destination_env"] == "WHICHPORTS_WEBHOOK_URL"
    assert SECRET not in " ".join(str(v) for v in tuple(stored))


TYPE_CASES = {
    "email": {},
    "webhook": {},
    "slack": {},
    "discord": {},
    "telegram": {"chat_id": "-1001234567890"},
}


def test_the_type_cases_below_are_every_type_there_is():
    """A type added to channels.py without a case here would go untested by
    this file, quietly."""
    assert set(TYPE_CASES) == set(channels.TYPES)


@pytest.mark.parametrize("channel_type", sorted(TYPE_CASES))
def test_every_type_can_be_created(client, channel_type):
    resp = add(client, type=channel_type, label=channel_type,
               env="WHICHPORTS_SOMETHING", **TYPE_CASES[channel_type])
    assert resp.status_code == 201
    assert resp.json()["type"] == channel_type
    assert live_labels() == [channel_type]


def test_a_telegram_chat_id_is_stored_on_the_row(client):
    resp = add(client, type="telegram", label="ops",
               env="WHICHPORTS_TELEGRAM_TOKEN", chat_id="-1001234567890")
    assert resp.status_code == 201
    assert resp.json()["chat_id"] == "-1001234567890"
    assert rows()[0]["destination_extra"] == "-1001234567890"


@pytest.mark.parametrize("chat_id", ["-1001234567890", "1234567890",
                                     "@a_channel_name"])
def test_the_chat_id_forms_the_bot_api_documents_are_accepted(client, chat_id):
    resp = add(client, type="telegram", label="ops",
               env="WHICHPORTS_TELEGRAM_TOKEN", chat_id=chat_id)
    assert resp.status_code == 201
    assert resp.json()["chat_id"] == chat_id


def test_channels_are_listed_oldest_first(client):
    a_webhook(client, "first")
    a_webhook(client, "second")
    assert live_labels() == ["first", "second"]


# ------------------------------------------------ what a create request may be

@pytest.mark.parametrize("body", ["not json", "", "   ", "{oops}",
                                  "{'single': 'quotes'}", "{\"a\": }"])
def test_a_body_that_is_not_json_is_400(client, body):
    resp = client.post("/api/admin/channels", content=body, headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not JSON"


@pytest.mark.parametrize("body", [b"\xff\xff\xff", b"\x80abc", b"\xfe\xff",
                                  b"\xff\xfe", b"\xc3\x28"])
def test_a_body_that_is_not_utf8_is_400_and_not_a_crash(client, body):
    """Bytes that are not UTF-8 raise UnicodeDecodeError rather than reaching
    the JSON parser at all, so both are caught. Without that this is a 500."""
    resp = client.post("/api/admin/channels", content=body, headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not JSON"
    assert state() == []


@pytest.mark.parametrize("body", ["null", "[]", '"a string"', "123", "true"])
def test_a_json_body_that_is_not_an_object_is_400(client, body):
    """Read as no fields at all, which channels.py refuses by type, so it is a
    400 with a sentence rather than a crash."""
    resp = client.post("/api/admin/channels", content=body, headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"]
    assert state() == []


def test_an_empty_object_is_400(client):
    resp = client.post("/api/admin/channels", content="{}", headers=gate())
    assert resp.status_code == 400
    assert state() == []


@pytest.mark.parametrize("field", ["type", "label", "env", "chat_id"])
@pytest.mark.parametrize("value", [["x"], {"a": 1}, 5, True, 1.5])
def test_a_field_that_is_not_text_is_400(client, field, value):
    """JSON can carry a list where a string belongs, and channels.py's rules
    are written for strings, so this is refused at the door rather than raising
    an AttributeError deep inside."""
    fields = {"type": "webhook", "label": "ops", "env": "WHICHPORTS_A"}
    fields[field] = value
    resp = client.post("/api/admin/channels", content=json.dumps(fields),
                       headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"] == f"{field} must be text"
    assert state() == []


@pytest.mark.parametrize("field", ["type", "env"])
def test_a_null_field_is_read_as_missing_and_refused(client, field):
    """`label` left this list on 2026-08-23: a missing label is generated
    rather than refused, which the generated-label tests below cover."""
    fields = {"type": "webhook", "label": "ops", "env": "WHICHPORTS_A"}
    fields[field] = None
    resp = client.post("/api/admin/channels", content=json.dumps(fields),
                       headers=gate())
    assert resp.status_code == 400
    assert state() == []


# --------------------------------------------- a label nobody had to invent
#
# The Add channel window stopped asking for a label, on the owner's word of
# 2026-08-23. Rows are still keyed by label in every
# route here, so a request without one gets a free label made from the type,
# the same way a Slack connect gets one made from the channel name.

def test_a_missing_label_is_generated_from_the_type(client):
    resp = add(client, type="webhook", env="WHICHPORTS_A")
    assert resp.status_code == 201
    assert resp.json()["label"] == "webhook"
    assert live_labels() == ["webhook"]


@pytest.mark.parametrize("label", ["", "   ", None])
def test_an_empty_label_is_generated_too(client, label):
    resp = add(client, type="webhook", label=label, env="WHICHPORTS_A")
    assert resp.status_code == 201
    assert resp.json()["label"] == "webhook"


def test_generated_labels_count_up_rather_than_colliding(client):
    for want in ("webhook", "webhook 2", "webhook 3"):
        resp = add(client, type="webhook", env="WHICHPORTS_A")
        assert resp.status_code == 201
        assert resp.json()["label"] == want


def test_a_generated_label_steps_over_one_the_operator_took(client):
    a_webhook(client, "webhook 2")
    for want in ("webhook", "webhook 3"):
        assert add(client, type="webhook",
                   env="WHICHPORTS_A").json()["label"] == want


def test_a_named_label_is_kept_exactly_as_sent(client):
    """The CLI and any caller that names its own label keep working."""
    resp = add(client, type="webhook", label="night rota", env="WHICHPORTS_A")
    assert resp.status_code == 201
    assert resp.json()["label"] == "night rota"


def test_a_generated_label_passes_the_module_rule(client):
    """Every generated label has to satisfy LABEL_RE, or the route would mint
    names its own validation refuses."""
    for _ in range(3):
        resp = add(client, type="telegram", env="WHICHPORTS_TG",
                   chat_id="-1001234567890")
        assert resp.status_code == 201
        assert channels.LABEL_RE.match(resp.json()["label"])


def test_a_missing_chat_id_is_an_empty_one(client):
    """The only optional field. A webhook sends no chat_id at all and that is
    not an error."""
    assert a_webhook(client, "ops").status_code == 201
    assert rows()[0]["destination_extra"] == ""


def test_an_unknown_field_is_ignored(client):
    """Only the four fields are read. Something else in the body neither
    creates a column nor fails the request."""
    # `destination` used to be the unknown field here. It is a real one since
    # 2026-08-23, and sending it beside `env` is now correctly a 400, so this
    # needs a field that is genuinely not read.
    resp = add(client, type="webhook", label="ops", env="WHICHPORTS_A",
               enabled=False, id=99, colour="purple")
    assert resp.status_code == 201
    assert resp.json()["enabled"] is True
    assert rows()[0]["id"] != 99


# ------------------------------- the refusals, and whose sentence they carry

def refusal_from_channels(tmp_path, channel_type, label, env, chat_id=""):
    """The sentence channels.py itself raises for these arguments. Used so a
    test compares the API against the module rather than against prose copied
    into this file, which is the copy that goes stale."""
    con = db.connect(str(tmp_path / "compare.db"))
    try:
        db.init(con)
        channels.init(con)
        channels.add(con, channel_type, label, env, destination_extra=chat_id)
    except channels.ChannelError as exc:
        return str(exc)
    finally:
        con.close()
    return None


@pytest.mark.parametrize("channel_type", [
    "carrier pigeon", "", "  ", "WEBHOOK", "web hook", "sms", "email ",
])
def test_a_bad_type_is_400_carrying_the_module_sentence(client, tmp_path,
                                                        channel_type):
    resp = add(client, type=channel_type, label="ops", env="WHICHPORTS_A")
    assert resp.status_code == 400
    assert resp.json()["detail"] == refusal_from_channels(
        tmp_path, channel_type, "ops", "WHICHPORTS_A")
    assert state() == []


@pytest.mark.parametrize("label", [
    "-leading", ".leading", "_leading", "x" * 49, "has\nnewline",
    "<script>", "semi;colon", "sla/sh", "quote'mark", "tab\there",
])
def test_a_bad_label_is_400_carrying_the_module_sentence(client, tmp_path,
                                                         label):
    """An empty label is no longer in this list: since the window stopped
    asking for one, empty means "make one up for me" and is tested with the
    generated labels below."""
    resp = add(client, type="webhook", label=label, env="WHICHPORTS_A")
    assert resp.status_code == 400
    assert resp.json()["detail"] == refusal_from_channels(
        tmp_path, "webhook", label, "WHICHPORTS_A")
    assert state() == []


@pytest.mark.parametrize("label,expected", [("a", 201), ("x" * 48, 201),
                                            ("x" * 49, 400)])
def test_the_label_length_boundary(client, label, expected):
    """Forty eight is the last one that fits, forty nine is the first that does
    not."""
    assert add(client, type="webhook", label=label,
               env="WHICHPORTS_A").status_code == expected


@pytest.mark.parametrize("env", [
    "PATH", "HOME", "AWS_SECRET_ACCESS_KEY", "whichports_webhook_url",
    "WHICHPORTS_", "SOMETHING_WHICHPORTS_URL", "WHICHPORTS_URL; rm -rf /",
    "", "   ", "WHICHPORTS_A B", "WHICHPORTS-A", "$WHICHPORTS_A",
])
def test_a_bad_env_name_is_400_carrying_the_module_sentence(client, tmp_path,
                                                            env):
    resp = add(client, type="webhook", label="ops", env=env)
    assert resp.status_code == 400
    assert resp.json()["detail"] == refusal_from_channels(
        tmp_path, "webhook", "ops", env)
    assert state() == []


@pytest.mark.parametrize("chat_id", [
    "abc", "@", "12 34", "123:ABC", "-", "+123", "1" * 33, "@" + "a" * 65,
    "@bad-name", "-", "1.5", "<script>",
])
def test_a_bad_telegram_chat_id_is_400_carrying_the_module_sentence(
        client, tmp_path, chat_id):
    resp = add(client, type="telegram", label="ops", env="WHICHPORTS_TG",
               chat_id=chat_id)
    assert resp.status_code == 400
    assert resp.json()["detail"] == refusal_from_channels(
        tmp_path, "telegram", "ops", "WHICHPORTS_TG", chat_id)
    assert state() == []


@pytest.mark.parametrize("chat_id", ["", "   "])
def test_telegram_without_a_chat_id_is_400(client, chat_id):
    """Telegram is the one type that needs two things, so a row without the
    second one is not a destination."""
    resp = add(client, type="telegram", label="ops", env="WHICHPORTS_TG",
               chat_id=chat_id)
    assert resp.status_code == 400
    assert "chat id" in resp.json()["detail"]
    assert state() == []


def test_telegram_with_no_chat_id_field_at_all_is_400(client):
    resp = add(client, type="telegram", label="ops", env="WHICHPORTS_TG")
    assert resp.status_code == 400
    assert state() == []


@pytest.mark.parametrize("channel_type", ["email", "webhook", "slack",
                                          "discord"])
def test_a_chat_id_on_a_type_that_takes_none_is_400(client, channel_type):
    """Stored and ignored would hide that the operator believes something about
    this row that is not true."""
    resp = add(client, type=channel_type, label="ops", env="WHICHPORTS_A",
               chat_id="-1001234567890")
    assert resp.status_code == 400
    assert "takes no second field" in resp.json()["detail"]
    assert state() == []


def test_a_duplicate_label_is_400(client):
    assert a_webhook(client, "twin").status_code == 201
    resp = a_webhook(client, "twin")
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"]
    assert live_labels() == ["twin"]


def test_a_duplicate_label_of_a_different_type_is_still_400(client):
    """Labels are how a person tells two channels apart, so the type does not
    make a second one a different name."""
    a_webhook(client, "twin")
    resp = add(client, type="slack", label="twin", env="WHICHPORTS_SLACK_URL")
    assert resp.status_code == 400
    assert live_labels() == ["twin"]


def test_a_removed_label_can_be_created_again(client):
    a_webhook(client, "ops")
    assert act(client, "ops", "remove").status_code == 204
    assert a_webhook(client, "ops").status_code == 201
    assert live_labels() == ["ops"]


# ------------------------------------------------------ enable and disable

def test_disable_switches_the_row_off_and_keeps_it(client):
    a_webhook(client, "ops")
    assert act(client, "ops", "disable").status_code == 204
    assert state() == [("ops", 0, False)]
    # Off is not removed, so a screen listing where alerts go still shows it.
    assert live_labels() == ["ops"]


def test_enable_switches_it_back_on(client):
    a_webhook(client, "ops")
    act(client, "ops", "disable")
    assert act(client, "ops", "enable").status_code == 204
    assert state() == [("ops", 1, False)]


def test_disable_and_enable_round_trip(client):
    a_webhook(client, "ops")
    for _ in range(3):
        assert act(client, "ops", "disable").status_code == 204
        assert rows()[0]["enabled"] == 0
        assert act(client, "ops", "enable").status_code == 204
        assert rows()[0]["enabled"] == 1


def test_enabling_an_enabled_channel_is_still_204(client):
    """The row matched, so the request did what it asked for. An operator
    clicking twice is not an error."""
    a_webhook(client, "ops")
    assert act(client, "ops", "enable").status_code == 204
    assert rows()[0]["enabled"] == 1


def test_disabling_a_disabled_channel_is_still_204(client):
    a_webhook(client, "ops")
    act(client, "ops", "disable")
    assert act(client, "ops", "disable").status_code == 204
    assert rows()[0]["enabled"] == 0


def test_one_channel_switching_off_leaves_the_others_alone(client):
    a_webhook(client, "first")
    a_webhook(client, "second")
    act(client, "first", "disable")
    assert state() == [("first", 0, False), ("second", 1, False)]


# ---------------------------------------------------------------- removing

def test_remove_takes_it_out_of_live_but_keeps_the_row(client):
    """Soft removal, so an alert already delivered through this channel keeps
    a row its delivery can still be read against."""
    a_webhook(client, "ops")
    assert act(client, "ops", "remove").status_code == 204
    assert live_labels() == []
    assert state() == [("ops", 1, True)]
    assert rows()[0]["destination_env"] == "WHICHPORTS_WEBHOOK_URL"


def test_removing_twice_is_404(client):
    a_webhook(client, "ops")
    assert act(client, "ops", "remove").status_code == 204
    assert act(client, "ops", "remove").status_code == 404


@pytest.mark.parametrize("action", ACTIONS)
def test_an_action_on_a_removed_channel_is_404(client, action):
    a_webhook(client, "ops")
    act(client, "ops", "remove")
    assert act(client, "ops", action).status_code == 404
    # And the removed row is untouched by the refusal.
    assert state() == [("ops", 1, True)]


def test_removing_one_leaves_the_others_alone(client):
    a_webhook(client, "first")
    a_webhook(client, "second")
    act(client, "first", "remove")
    assert live_labels() == ["second"]


# ------------------------------------------------- a label arriving in a URL

def test_a_label_with_spaces_and_dots_is_reachable_once_encoded(client):
    """LABEL_RE allows a space, a dot, a dash and an underscore, so a browser
    encoding the label is enough to address one. Nothing else is needed."""
    label = "ops team.1_a-b"
    assert a_webhook(client, label).status_code == 201
    assert act(client, label, "disable").status_code == 204
    assert state() == [(label, 0, False)]


HOSTILE_LABELS = [
    "ghost",
    "ops/../secrets",
    "..",
    "../../etc/passwd",
    "%00",
    "ops\x00",
    "ops?q=1",
    "ops#frag",
    "ops&x=1",
    "ops name",
    "<script>alert(1)</script>",
    "ops'; DROP TABLE notification_channels; --",
    "' OR 1=1 --",
    "x" * 500,
    "ops\n",
    "OPS",
]


@pytest.mark.parametrize("action", ACTIONS)
@pytest.mark.parametrize("label", HOSTILE_LABELS)
def test_a_label_matching_no_channel_is_404_whatever_it_holds(client, action,
                                                              label):
    """404 and not 500, and never a match. The label is a bound parameter in
    channels.py, so nothing here is built into SQL or into a message."""
    a_webhook(client, "ops")
    assert act(client, label, action).status_code == 404
    assert state() == [("ops", 1, False)]


@pytest.mark.parametrize("action", ACTIONS)
def test_an_empty_label_matches_no_route_at_all(client, action):
    """`/api/admin/channels//enable` is not a route, because the path segment
    needs at least one character. Nothing runs and nothing changes."""
    a_webhook(client, "ops")
    resp = client.post(f"/api/admin/channels//{action}", headers=gate())
    assert resp.status_code == 404
    assert state() == [("ops", 1, False)]


@pytest.mark.parametrize("action", ACTIONS)
def test_an_unencoded_slash_in_a_label_matches_no_route(client, action):
    """A client that does not encode gets a longer path, which is not a route
    either. It is a 404 rather than an action on some other label."""
    a_webhook(client, "ops")
    resp = client.post(f"/api/admin/channels/ops/extra/{action}", headers=gate())
    assert resp.status_code == 404
    assert state() == [("ops", 1, False)]


def test_the_table_survives_a_label_that_is_a_sql_fragment(client):
    a_webhook(client, "ops")
    act(client, "ops'; DROP TABLE notification_channels; --", "remove")
    assert state() == [("ops", 1, False)]
    assert live_labels() == ["ops"]


# ------------------------------- no response and no refusal carries a value

def test_no_response_carries_the_value_of_the_variable_a_channel_names(
        client, monkeypatch):
    """The ingest never reads the value, and this is the assertion that says
    so. The variable is set in this process, the channel names it, and the
    value appears in nothing the API returns."""
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", SECRET)
    created = a_webhook(client, "ops")
    assert created.status_code == 201
    assert SECRET not in created.text
    assert created.json()["env"] == "WHICHPORTS_WEBHOOK_URL"
    for action in ("disable", "enable", "remove"):
        resp = act(client, "ops", action)
        assert resp.status_code == 204
        assert SECRET not in resp.text


def test_a_refusal_carries_no_value_either(client, monkeypatch):
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", SECRET)
    a_webhook(client, "ops")
    duplicate = a_webhook(client, "ops")
    assert duplicate.status_code == 400
    assert SECRET not in duplicate.text
    missing = act(client, "ghost", "enable")
    assert missing.status_code == 404
    assert SECRET not in missing.text


@pytest.mark.parametrize("channel_type", ["email", "webhook", "slack",
                                          "discord"])
def test_a_value_pasted_into_a_field_that_takes_none_is_not_echoed(
        client, channel_type):
    """chat_id is the field a slack, discord, webhook or email channel should
    not take, and a URL is the thing an operator is most likely to paste into
    it. It is refused, and the refusal says what is wrong without repeating
    what was sent."""
    resp = add(client, type=channel_type, label="ops", env="WHICHPORTS_A",
               chat_id=SECRET)
    assert resp.status_code == 400
    assert SECRET not in resp.text
    assert state() == []


def test_a_bot_token_pasted_into_the_chat_id_field_is_not_echoed(client):
    """The mistake the Telegram sentence exists to catch. The token is the
    credential, so the refusal must not repeat it."""
    token = "123456789:AAF-SUPERSECRETBOTTOKENVALUE"
    resp = add(client, type="telegram", label="ops", env="WHICHPORTS_TG",
               chat_id=token)
    assert resp.status_code == 400
    assert token not in resp.text
    assert "SUPERSECRETBOTTOKENVALUE" not in resp.text
    assert state() == []


def test_a_process_environment_variable_never_reaches_a_response(client,
                                                                 monkeypatch):
    """Broader than the channel's own variable: nothing the ingest holds in its
    environment comes back, including a name a request never mentioned."""
    monkeypatch.setenv("WHICHPORTS_OTHER_URL", SECRET)
    monkeypatch.setenv("WHICHPORTS_TELEGRAM_TOKEN", "AAF-ANOTHERSECRET")
    created = add(client, type="telegram", label="ops",
                  env="WHICHPORTS_TELEGRAM_TOKEN", chat_id="-1001234567890")
    assert created.status_code == 201
    assert SECRET not in created.text
    assert "ANOTHERSECRET" not in created.text
    assert created.json()["env"] == "WHICHPORTS_TELEGRAM_TOKEN"


# --------------------------------------------------------------- at once

def test_only_one_of_many_simultaneous_creates_wins_the_label(client):
    """Two operators clicking Add at the same moment, or one clicking twice.
    The unique index does the deciding, so exactly one row exists whatever the
    threads do, and the losers are 400 rather than 500."""
    # The file is opened once first, on purpose. `PRAGMA journal_mode = WAL` in
    # db.connect takes a lock the busy timeout does not cover, so several
    # connections racing to be the very first to open a brand new database file
    # can each get "database is locked". Measured, and it is a property of a
    # database that has never been opened rather than of these endpoints: the
    # box's file has been in WAL since the day it was made. So the race under
    # test here is the one that can really happen, two writers on a live file.
    warm_up = a_webhook(client, "warm")
    assert warm_up.status_code == 201

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = sorted(pool.map(lambda _: a_webhook(client, "ops").status_code,
                                range(8)))
    assert codes.count(201) == 1
    assert codes.count(400) == 7
    assert live_labels() == ["warm", "ops"]


def test_simultaneous_switches_leave_the_row_in_one_of_the_two_states(client):
    """Enable and disable racing each other. Either answer is correct, and
    neither may lose the row or answer 500."""
    a_webhook(client, "ops")
    actions = ["enable", "disable"] * 6

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = set(pool.map(lambda a: act(client, "ops", a).status_code,
                             actions))
    assert codes == {204}
    assert rows()[0]["enabled"] in (0, 1)
    assert live_labels() == ["ops"]


def test_only_one_of_many_simultaneous_removes_answers_204(client):
    """Soft removal is an UPDATE with removed_at IS NULL in its WHERE clause,
    so only the first one matches a row and the rest are 404."""
    a_webhook(client, "ops")

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = sorted(pool.map(lambda _: act(client, "ops", "remove").status_code,
                                range(8)))
    assert codes.count(204) == 1
    assert codes.count(404) == 7
    assert state() == [("ops", 1, True)]


# ----------------------------------------------------------------- send test
#
# This file used to assert there was NO send-test route, with a docstring
# saying a route added later is a change somebody has to argue for. The owner
# asked for per-channel Send test on 2026-08-23, and the argument is in the
# endpoint's docstring: a row holding its own destination is sent to from
# here, and a row whose secret only the sweep unit holds gets the honest
# answer and the command instead. The split of RECORD #266 is untouched, no
# process gains a credential it did not have.

def sent_calls(monkeypatch):
    """Replace the real sender with a recorder, so no test opens a socket."""
    calls = []

    def fake(channel, env=None, resolver=None, opener=None):
        calls.append(channel)
        return True, "posted"

    monkeypatch.setattr(ingest.senders, "deliver_test", fake)
    return calls


def test_send_test_needs_the_gate(client):
    a_webhook(client, "ops")
    assert client.post("/api/admin/channels/ops/test").status_code == 403


def test_send_test_on_an_unknown_label_is_404(client):
    assert client.post("/api/admin/channels/ghost/test",
                       headers=gate()).status_code == 404


def test_a_row_holding_its_own_destination_is_sent_to_from_here(client,
                                                                monkeypatch):
    calls = sent_calls(monkeypatch)
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = client.post("/api/admin/channels/ops/test", headers=gate())
    assert resp.status_code == 200
    assert resp.json() == {"sent": True, "detail": "posted"}
    assert [c.label for c in calls] == ["ops"]


def test_a_variable_row_whose_value_this_process_lacks_hands_over_the_command(
        client, monkeypatch):
    """The honest answer. The ingest does not read alerts.env and is not going
    to be given it for a button (docs/RECORD.md #266), so the response is the
    line that does it on the box."""
    monkeypatch.delenv("WHICHPORTS_WEBHOOK_URL", raising=False)
    calls = sent_calls(monkeypatch)
    a_webhook(client, "ops")
    resp = client.post("/api/admin/channels/ops/test", headers=gate())
    assert resp.status_code == 200
    body = resp.json()
    assert body["sent"] is False
    # **The command has to be one that sends.** This asserted
    # `python -m app.sweep_cli --dry-run`, whose own module documents that flag
    # as "sweep, print, send nothing", so the answer promised a test and named
    # a command that could not deliver one.
    assert body["command"] == 'python -m app.channels_cli test --label "ops"'
    assert "WHICHPORTS_WEBHOOK_URL" in body["detail"]
    assert calls == [], "a send was attempted with nothing to send to"


def test_a_variable_row_whose_value_this_process_holds_is_sent(client,
                                                               monkeypatch):
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", SECRET)
    calls = sent_calls(monkeypatch)
    a_webhook(client, "ops")
    resp = client.post("/api/admin/channels/ops/test", headers=gate())
    assert resp.status_code == 200
    assert resp.json()["sent"] is True
    assert [c.label for c in calls] == ["ops"]
    assert SECRET not in resp.text


def test_a_mail_row_without_the_relay_hands_over_the_command(client):
    """The relay credential lives in alerts.env, which only the sweep unit
    reads. That split is deliberate (docs/RECORD.md #266) and the button does
    not widen it."""
    add(client, type="email", label="ops", destination="ops@example.com")
    resp = client.post("/api/admin/channels/ops/test", headers=gate())
    assert resp.status_code == 200
    body = resp.json()
    assert body["sent"] is False
    assert body["command"] == 'python -m app.channels_cli test --label "ops"'
    assert "sweep unit" in body["detail"]


def test_a_mail_row_with_a_relay_in_this_environment_is_mailed(client,
                                                               monkeypatch):
    """Not the box's arrangement, and still the honest behaviour when it is
    true: with a relay in this process's environment the mail goes, to the
    row's own recipient."""
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example.com")
    sent_to = []

    def fake(subject, body, config=None, html=""):
        sent_to.append((subject, config.to))
        return True, "sent"

    monkeypatch.setattr(ingest.notify, "send", fake)
    add(client, type="email", label="ops", destination="ops@example.com")
    resp = client.post("/api/admin/channels/ops/test", headers=gate())
    assert resp.status_code == 200
    assert resp.json()["sent"] is True
    assert sent_to == [("[whichports] Test message", "ops@example.com")]


def test_a_failed_send_answers_the_senders_reason(client, monkeypatch):
    def fake(channel, env=None, resolver=None, opener=None):
        return False, "the endpoint answered 500"

    monkeypatch.setattr(ingest.senders, "deliver_test", fake)
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = client.post("/api/admin/channels/ops/test", headers=gate())
    assert resp.status_code == 200
    assert resp.json() == {"sent": False, "detail": "the endpoint answered 500"}


def test_no_test_response_carries_a_destination(client, monkeypatch):
    """The #284 rule, on the new route: the row's URL and the value of a named
    variable stay out of every answer."""
    monkeypatch.setenv("WHICHPORTS_WEBHOOK_URL", SECRET)
    sent_calls(monkeypatch)
    add(client, type="slack", label="stored", destination=SLACK_URL)
    a_webhook(client, "named")
    for label in ("stored", "named"):
        resp = client.post(f"/api/admin/channels/{label}/test", headers=gate())
        assert "SUPERSECRETVALUE" not in resp.text, label


def test_a_test_on_a_removed_channel_is_404(client, monkeypatch):
    calls = sent_calls(monkeypatch)
    add(client, type="slack", label="ops", destination=SLACK_URL)
    act(client, "ops", "remove")
    assert client.post("/api/admin/channels/ops/test",
                       headers=gate()).status_code == 404
    assert calls == []


# ------------------------------------------------------ replace a destination

def put_destination(client, label, headers=None, **fields):
    if headers is None:
        headers = gate()
    return client.post(f"/api/admin/channels/{quote(label, safe='')}/destination",
                       content=json.dumps(fields), headers=headers)


def test_replacing_a_destination_needs_the_gate(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_destination(client, "ops", headers={},
                           destination=SLACK_URL + "2")
    assert resp.status_code == 403
    assert rows()[0]["destination"] == SLACK_URL


def test_replacing_a_destination_on_an_unknown_label_is_404(client):
    assert put_destination(client, "ghost",
                           destination=SLACK_URL).status_code == 404


def test_the_destination_is_replaced_and_the_answer_is_the_hint(client):
    """**This used to answer a bare 204 and now answers the hint.** The reason
    for the 204 was that a response body is not a place a credential should be,
    and that is kept: the hint is the summary with a webhook's last path
    segment elided, which is what the create route has always answered with.

    It is here because the row on the alerts screen shows that summary and has
    to show the new one on the click rather than on a reload.
    """
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_destination(client, "ops", destination=SLACK_URL + "NEW")
    assert resp.status_code == 200
    # And the kinds the row takes as stored, which the Edit window holds to
    # what it sent before it says saved (finding E20). Sent none, so every
    # kind stays, each named.
    assert resp.json() == {"destination": "hooks.slack.com/services/T00/B00/…",
                           "events": list(channels.KIND_NAMES)}
    assert rows()[0]["destination"] == SLACK_URL + "NEW"


def test_an_edit_keeps_the_kinds_it_switched_off_with_the_destination(client):
    """The second big test, finding E20: a Webhook row's Edit, its address
    typed again and one kind switched off, answered 200 and kept every kind,
    because this route wrote the destination alone."""
    add(client, type="webhook", label="ops", destination="https://example.com/hook")
    assert rows()[0]["subscriptions"] == ""
    resp = put_destination(client, "ops", destination="https://example.com/hook",
                           events=["silent", "outside view stale", "cve"])
    assert resp.status_code == 200
    assert rows()[0]["subscriptions"] == "cve,outside view stale,silent"
    assert resp.json()["events"] == ["silent", "outside view stale", "cve"]
    # Every kind back on is every kind again.
    resp = put_destination(client, "ops", destination="https://example.com/hook",
                           events=list(channels.KIND_NAMES))
    assert rows()[0]["subscriptions"] == "" and resp.json()["events"] == list(channels.KIND_NAMES)


def test_an_edit_with_a_kind_that_does_not_exist_changes_nothing(client):
    add(client, type="webhook", label="ops", destination="https://example.com/hook")
    resp = put_destination(client, "ops", destination="https://example.com/other",
                           events=["silent", "nonsense"])
    assert resp.status_code == 400
    assert (rows()[0]["destination"], rows()[0]["subscriptions"]) == ("https://example.com/hook", "")


def test_the_replacement_answer_never_carries_the_value_itself(client):
    """The one property the old 204 was protecting, asserted directly rather
    than by there being no body at all."""
    add(client, type="slack", label="ops",
        destination="https://hooks.slack.com/services/T00/B00/OLDSECRET")
    resp = put_destination(
        client, "ops",
        destination="https://hooks.slack.com/services/T00/B00/SUPERSECRETVALUE")
    assert resp.status_code == 200
    assert "SUPERSECRETVALUE" not in resp.text
    assert "OLDSECRET" not in resp.text


def test_the_replacement_answer_is_the_stored_row_and_not_the_request(client):
    """A mail recipient is not a credential and the hint is the whole of it, so
    this is the case where the answer and the request do read the same. It is
    read back from the row rather than echoed, which is what makes the two
    agree rather than what makes them identical."""
    add(client, type="email", label="ops", destination="ops@example.com")
    resp = put_destination(client, "ops", destination="noc@example.com")
    assert resp.json()["destination"] == "noc@example.com"
    assert rows()[0]["destination"] == "noc@example.com"


def test_a_telegram_replacement_answers_with_the_chat_and_the_topic(client):
    """Telegram's hint is built from the extra rather than from the token, so
    the row that changed is the one the answer describes."""
    add(client, type="telegram", label="ops", destination="123456:ABC-DEF_ghi",
        chat_id="-1001234567890")
    resp = put_destination(client, "ops", destination="123456:ABC-DEF_ghi",
                           chat_id="-1009876543210:42")
    assert resp.json()["destination"] == "-1009876543210 topic 42"
    assert "ABC-DEF_ghi" not in resp.text


def test_replacing_moves_a_variable_row_onto_its_own_destination(client):
    """The row held a name and holds a value now, one of the two, never both."""
    a_webhook(client, "ops")
    resp = put_destination(client, "ops", destination="https://example.com/hook")
    assert resp.status_code == 200
    stored = rows()[0]
    assert stored["destination"] == "https://example.com/hook"
    assert stored["destination_env"] == ""


def test_a_replacement_is_validated_like_a_create(client, tmp_path):
    """One rule, not two: the module's own sentence comes back and the row is
    untouched."""
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_destination(client, "ops",
                           destination="hooks.slack.com/T/B/SUPERSECRETVALUE")
    assert resp.status_code == 400
    assert resp.json()["detail"] == channels.check_destination(
        "slack", "hooks.slack.com/T/B/SUPERSECRETVALUE")
    assert "SUPERSECRETVALUE" not in resp.text
    assert rows()[0]["destination"] == SLACK_URL


def test_an_empty_replacement_is_refused_rather_than_clearing_the_row(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_destination(client, "ops", destination="")
    assert resp.status_code == 400
    assert "disable or remove" in resp.json()["detail"]
    assert rows()[0]["destination"] == SLACK_URL


def test_a_telegram_replacement_carries_its_chat_id(client):
    add(client, type="telegram", label="ops", env="WHICHPORTS_TG",
        chat_id="-1001234567890")
    resp = put_destination(client, "ops", destination="123456:ABC-DEF_ghi",
                           chat_id="-1009876543210:42")
    assert resp.status_code == 200
    stored = rows()[0]
    assert stored["destination"] == "123456:ABC-DEF_ghi"
    assert stored["destination_extra"] == "-1009876543210:42"
    assert stored["destination_env"] == ""


def test_a_telegram_replacement_without_a_chat_id_is_refused(client):
    add(client, type="telegram", label="ops", env="WHICHPORTS_TG",
        chat_id="-1001234567890")
    resp = put_destination(client, "ops", destination="123456:ABC-DEF_ghi")
    assert resp.status_code == 400
    assert "chat id" in resp.json()["detail"]
    assert rows()[0]["destination_env"] == "WHICHPORTS_TG"


def test_a_replacement_body_that_is_not_json_is_400(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = client.post("/api/admin/channels/ops/destination",
                       content="not json", headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not JSON"


@pytest.mark.parametrize("value", [None, ["x"], 5, True])
def test_a_replacement_destination_that_is_not_text_is_400(client, value):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_destination(client, "ops", destination=value)
    assert resp.status_code == 400
    assert rows()[0]["destination"] == SLACK_URL


def test_no_replacement_refusal_echoes_the_value(client):
    """Every refusal reachable from this field, swept, same as create."""
    add(client, type="slack", label="ops", destination=SLACK_URL)
    for kwargs in ({"destination": "hooks.example.com/SUPERSECRETVALUE"},
                   {"destination": "https://x.example/SUPERSECRETVALUE",
                    "chat_id": "not a chat"},
                   {"destination": ""}):
        resp = put_destination(client, "ops", **kwargs)
        assert resp.status_code == 400, kwargs
        assert "SUPERSECRETVALUE" not in resp.text, kwargs


# ------------------------------------------- change which kinds a row takes
#
# **The dashboard posts here since 2026-08-24**, for a row whose step has no
# destination field, which is Slack. Its webhook came back from the connect and
# is not on the page, so an edit there can change the switches and must be
# unable to touch anything else. These assert that second half.


def put_events(client, label, headers=None, **fields):
    if headers is None:
        headers = gate()
    return client.post(f"/api/admin/channels/{quote(label, safe='')}/events",
                       content=json.dumps(fields), headers=headers)


def test_changing_the_kinds_needs_the_gate(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_events(client, "ops", headers={}, events=["silent"])
    assert resp.status_code == 403
    assert rows()[0]["subscriptions"] == ""


def test_changing_the_kinds_on_an_unknown_label_is_404(client):
    assert put_events(client, "ghost", events=["silent"]).status_code == 404


def test_the_kinds_are_written_and_the_answer_is_a_bare_204(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_events(client, "ops", events=["silent"])
    assert resp.status_code == 204
    assert resp.text == ""
    assert rows()[0]["subscriptions"] == "silent"


def test_changing_the_kinds_leaves_the_destination_alone(client):
    """**The property the Slack edit rests on.** A connected row keeps its
    webhook whatever is done to its switches, because the page has no way to
    put that value back if this route cleared it."""
    add(client, type="slack", label="ops", destination=SLACK_URL)
    assert put_events(client, "ops", events=["silent"]).status_code == 204
    stored = rows()[0]
    assert stored["destination"] == SLACK_URL
    assert stored["destination_env"] == ""
    assert stored["enabled"] == 1


def test_an_empty_list_of_kinds_means_every_kind(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    assert put_events(client, "ops", events=["silent"]).status_code == 204
    assert put_events(client, "ops", events=[]).status_code == 204
    assert rows()[0]["subscriptions"] == ""


def test_a_kind_nobody_serves_is_400_and_writes_nothing(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    assert put_events(client, "ops", events=["silent"]).status_code == 204
    resp = put_events(client, "ops", events=["carrier pigeon"])
    assert resp.status_code == 400
    assert rows()[0]["subscriptions"] == "silent"


def test_a_kinds_body_that_is_not_json_is_400(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = client.post("/api/admin/channels/ops/events",
                       content="not json", headers=gate())
    assert resp.status_code == 400
    assert resp.json()["detail"] == "not JSON"


@pytest.mark.parametrize("value", ["silent", 5, {"a": 1}])
def test_kinds_that_are_not_a_list_are_400(client, value):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    assert put_events(client, "ops", events=value).status_code == 400


def test_no_kinds_refusal_echoes_the_destination(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    resp = put_events(client, "ops", events=["carrier pigeon"])
    assert "SUPERSECRETVALUE" not in resp.text


def test_changing_the_kinds_on_a_removed_channel_is_404(client):
    add(client, type="slack", label="ops", destination=SLACK_URL)
    act(client, "ops", "remove")
    assert put_events(client, "ops", events=["silent"]).status_code == 404


# ------------------------------------------------------- connect to Slack

CONNECT = "/api/admin/channels/slack/connect"
CALLBACK = "/api/admin/channels/slack/callback"
SLACK_ENV = {"WHICHPORTS_SLACK_CLIENT_ID": "242341083157.104",
             "WHICHPORTS_SLACK_CLIENT_SECRET": "SUPERSECRETCLIENTSECRET"}
SLACK_HOOK = "https://hooks.slack.com/services/T00/B00/SUPERSECRETHOOKPATH"


def slack_configured(monkeypatch):
    for name, value in SLACK_ENV.items():
        monkeypatch.setenv(name, value)


def slack_answer(**kw):
    base = {"ok": True,
            "incoming_webhook": {"url": SLACK_HOOK, "channel": "#ops"}}
    base.update(kw)
    return json.dumps(base).encode()


def fake_exchange(payload):
    def exchange(code, redirect_uri, env=None, opener=None):
        return payload
    return exchange


def test_connect_and_callback_both_need_the_operator_gate(client):
    """They are under /api/admin/ and that is not decoration: it is what puts
    them behind Caddy's basic auth and this app's own gate."""
    assert client.get(CONNECT).status_code == 403
    assert client.get(CALLBACK).status_code == 403


def test_connect_says_so_when_no_slack_app_is_configured(client, monkeypatch):
    """Absent is a state, not a broken route."""
    monkeypatch.delenv("WHICHPORTS_SLACK_CLIENT_ID", raising=False)
    monkeypatch.delenv("WHICHPORTS_SLACK_CLIENT_SECRET", raising=False)
    resp = client.get(CONNECT, headers=gate())
    assert resp.status_code == 503
    assert "no Slack app configured" in resp.text
    # **It used to end by offering the other way in, and that went on
    # 2026-08-24.** The window stopped asking for a webhook URL that day, so a
    # page telling an operator to paste one would point at a field no screen
    # has. The owner had the field removed.
    assert "paste" not in resp.text
    assert "webhook" not in resp.text


def test_connect_redirects_to_slack_and_parks_a_state(client, monkeypatch):
    slack_configured(monkeypatch)
    resp = client.get(CONNECT, headers=gate(), follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith(
        "https://slack.com/oauth/v2/authorize?")
    cookie = resp.headers.get("set-cookie", "")
    assert "whichports_slack_state=" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=lax" in cookie.replace("samesite", "SameSite")


def test_the_redirect_never_carries_the_client_secret(client, monkeypatch):
    slack_configured(monkeypatch)
    resp = client.get(CONNECT, headers=gate(), follow_redirects=False)
    assert "SUPERSECRETCLIENTSECRET" not in resp.headers["location"]
    assert "SUPERSECRETCLIENTSECRET" not in resp.text


def test_a_callback_with_no_state_writes_nothing(client, monkeypatch):
    """**The forgery check, through the route.** A stranger's link lands here
    with a code and no cookie."""
    slack_configured(monkeypatch)
    monkeypatch.setattr(ingest.slack_oauth, "exchange_raw",
                        fake_exchange(slack_answer()))
    resp = client.get(f"{CALLBACK}?code=abc&state=whatever", headers=gate())
    assert resp.status_code == 400
    assert "did not come from here" in resp.text
    assert rows() == [], "a channel was written by a forged callback"


def test_a_callback_whose_state_does_not_match_writes_nothing(client, monkeypatch):
    slack_configured(monkeypatch)
    sign_in(client)
    monkeypatch.setattr(ingest.slack_oauth, "exchange_raw",
                        fake_exchange(slack_answer()))
    client.cookies.set("whichports_slack_state", "a" * 40)
    resp = client.get(f"{CALLBACK}?code=abc&state={'b' * 40}")
    assert resp.status_code == 400
    assert rows() == []


def test_a_good_callback_writes_the_channel_and_never_shows_the_url(client,
                                                                    monkeypatch):
    slack_configured(monkeypatch)
    sign_in(client)
    monkeypatch.setattr(ingest.slack_oauth, "exchange_raw",
                        fake_exchange(slack_answer()))
    state = "s" * 44
    client.cookies.set("whichports_slack_state", state)
    resp = client.get(f"{CALLBACK}?code=abc&state={state}")
    assert resp.status_code == 200
    assert "Slack is connected" in resp.text
    # **the whole point**: the operator never handles the URL
    assert "SUPERSECRETHOOKPATH" not in resp.text

    stored = rows()
    assert len(stored) == 1
    assert stored[0]["type"] == "slack"
    assert stored[0]["destination"] == SLACK_HOOK
    assert stored[0]["label"] == "ops"


def test_the_state_cookie_is_cleared_whatever_happens(client, monkeypatch):
    """A one-time value that survives its one use is not one."""
    slack_configured(monkeypatch)
    sign_in(client)
    monkeypatch.setattr(ingest.slack_oauth, "exchange_raw",
                        fake_exchange(slack_answer()))
    state = "s" * 44
    client.cookies.set("whichports_slack_state", state)
    resp = client.get(f"{CALLBACK}?code=abc&state={state}")
    assert 'whichports_slack_state=""' in resp.headers.get("set-cookie", "") \
        or "Max-Age=0" in resp.headers.get("set-cookie", "")


def test_connecting_the_same_channel_twice_does_not_fail_on_the_label(client,
                                                                      monkeypatch):
    """Labels are unique among live channels, and the operator did nothing
    wrong by connecting a second channel that happens to share a name."""
    slack_configured(monkeypatch)
    sign_in(client)
    monkeypatch.setattr(ingest.slack_oauth, "exchange_raw",
                        fake_exchange(slack_answer()))
    state = "s" * 44
    for hook in (SLACK_HOOK, SLACK_HOOK + "2"):
        monkeypatch.setattr(ingest.slack_oauth, "exchange_raw",
                            fake_exchange(json.dumps(
                                {"ok": True,
                                 "incoming_webhook": {"url": hook,
                                                      "channel": "#ops"}}).encode()))
        client.cookies.set("whichports_slack_state", state)
        resp = client.get(f"{CALLBACK}?code=abc&state={state}")
        assert resp.status_code == 200, resp.text
    assert sorted(r["label"] for r in rows()) == ["ops", "ops 2"]


def test_a_cancelled_connect_is_not_a_fault(client, monkeypatch):
    """access_denied is somebody clicking Cancel."""
    slack_configured(monkeypatch)
    resp = client.get(f"{CALLBACK}?error=access_denied", headers=gate())
    assert resp.status_code == 200
    assert "access_denied" in resp.text
    assert rows() == []


def test_an_error_parameter_is_bounded_because_anyone_can_send_one(client,
                                                                   monkeypatch):
    """Anybody can open the callback with any query string, so what lands in
    that field is not Slack's word for it."""
    slack_configured(monkeypatch)
    resp = client.get(f"{CALLBACK}?error=" + "SUPERSECRETCLIENTSECRET",
                      headers=gate())
    assert resp.status_code == 200
    assert "SUPERSECRETCLIENTSECRET" not in resp.text


def test_slack_refusing_the_exchange_writes_nothing(client, monkeypatch):
    slack_configured(monkeypatch)
    sign_in(client)

    def refuse(code, redirect_uri, env=None, opener=None):
        raise ingest.slack_oauth.SlackError("Slack refused the connect: invalid_code")

    monkeypatch.setattr(ingest.slack_oauth, "exchange_raw", refuse)
    state = "s" * 44
    client.cookies.set("whichports_slack_state", state)
    resp = client.get(f"{CALLBACK}?code=abc&state={state}")
    assert resp.status_code == 502
    assert "invalid_code" in resp.text
    assert rows() == []


def test_the_command_that_is_handed_over_is_one_that_sends(client):
    """**The property, not the string.** The answer says this process cannot
    send the test and names a line to run instead, so that line has to be a
    command that sends one message to one channel. `sweep_cli --dry-run` was
    named here and is documented in its own module as "sweep, print, send
    nothing", which made the answer a promise nothing could keep.

    Asserted against the CLI's own parser rather than by matching words, so a
    rename of the subcommand fails here instead of on the box.
    """
    from app import channels_cli
    add(client, type="email", label="ops", destination="ops@example.com")
    handed = client.post("/api/admin/channels/ops/test",
                         headers=gate()).json()["command"]
    assert handed.startswith("python -m app.channels_cli ")
    argv = shlex.split(handed)[3:]
    parsed = channels_cli.parse_args(argv)
    assert parsed.command == "test"
    assert parsed.label == "ops"


def test_the_handed_over_command_names_the_channel_it_is_for(client):
    """One channel, named, and quoted so a label with a space in it survives
    being pasted into a shell."""
    add(client, type="email", label="night rota", destination="ops@example.com")
    handed = client.post("/api/admin/channels/night%20rota/test",
                         headers=gate()).json()["command"]
    assert shlex.split(handed)[-1] == "night rota"


# ------------------------------------------------ one workspace's rows only

def signed_in_neighbour():
    """An operator in a second workspace, so the scoping has somebody to be
    scoped against."""
    con = db.connect()
    db.init(con)
    accounts.init(con)
    email = "neighbour@example.com"
    if accounts.get_user_by_email(con, email) is None:
        con.execute("INSERT OR IGNORE INTO workspaces (id, name, created_at)"
                    " VALUES (2, 'neighbour', '2026-08-29T12:00:00+00:00')")
        con.commit()
        an_account_with_no_channel(con, email, workspace_id=2)
    user = accounts.get_user_by_email(con, email)
    token, _ = accounts.issue_session(con, user["id"])
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def test_a_channel_lands_in_the_creators_workspace(client):
    op = signed_in_operator()
    answer = add(op, headers={}, type="webhook", label="ops",
                 env="WHICHPORTS_WEBHOOK_URL")
    assert answer.status_code == 201
    stored = rows()[0]
    assert stored["workspace_id"] == 1


def test_another_workspace_cannot_touch_the_row_and_learns_nothing(client):
    """404, the same answer a missing label gets, so a guessed label does not
    say whether it exists somewhere else."""
    op = signed_in_operator()
    add(op, headers={}, type="webhook", label="ops",
        env="WHICHPORTS_WEBHOOK_URL")
    other = signed_in_neighbour()
    for action in ("disable", "enable", "remove"):
        answer = act(other, "ops", action, headers={})
        assert answer.status_code == 404, action
    stored = rows()[0]
    assert stored["enabled"] == 1 and stored["removed_at"] is None


def test_each_workspace_may_call_its_channel_ops(client):
    op = signed_in_operator()
    assert add(op, headers={}, type="webhook", label="ops",
               env="WHICHPORTS_WEBHOOK_URL").status_code == 201
    other = signed_in_neighbour()
    assert add(other, headers={}, type="webhook", label="ops",
               env="WHICHPORTS_WEBHOOK_URL").status_code == 201
    stored = rows()
    assert sorted(r["workspace_id"] for r in stored) == [1, 2]


# ----------------------- a refusal names its field and its reason, as classes
#
# Found in a round of the test fleet (docs/RECORD.md 4.228): the
# bot token and the chat id were typed into each other's field, and the
# answer named no field. The answer still carries channels.py's sentence
# under `detail`. Beside it stand the field the refusal is about and why,
# each one of that module's fixed words, so a screen can say its own few
# words at the field and print none of ours.

BOT_TOKEN = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
# Not the chat id channels.py's own sentence gives as its example, so the
# check that an answer repeats nothing is not fooled by that example.
CHAT_ID = "-1009876543210"
PLAIN_HOOK = "https://hooks.example.com/services/T0/B0/abc"

REFUSED_CREATES = [
    # The bot token and the chat id in each other's field: first the one,
    # and with that put right the other.
    ({"type": "telegram", "destination": CHAT_ID, "chat_id": BOT_TOKEN},
     "destination", "shape"),
    ({"type": "telegram", "destination": BOT_TOKEN, "chat_id": BOT_TOKEN},
     "chat_id", "shape"),
    # Each field empty.
    ({"type": "telegram", "destination": "", "chat_id": CHAT_ID},
     "destination", "missing"),
    ({"type": "telegram", "destination": BOT_TOKEN, "chat_id": ""},
     "chat_id", "missing"),
    ({"type": "email", "destination": ""}, "destination", "missing"),
    ({"type": "webhook", "destination": ""}, "destination", "missing"),
    ({"type": "discord", "destination": "   "}, "destination", "missing"),
    # A URL where a token belongs, and a token where a URL belongs.
    ({"type": "telegram", "destination": PLAIN_HOOK, "chat_id": CHAT_ID},
     "destination", "shape"),
    ({"type": "discord", "destination": BOT_TOKEN}, "destination", "shape"),
    ({"type": "webhook", "destination": "hooks.example.com/SUPERSECRETVALUE"},
     "destination", "shape"),
    ({"type": "email", "destination": "ops@"}, "destination", "shape"),
    ({"type": "telegram", "destination": BOT_TOKEN,
      "chat_id": CHAT_ID + ":general"}, "chat_id", "shape"),
    # What only the server can know: an address no alert may be sent to.
    ({"type": "webhook", "destination": "https://10.0.0.5/hook"},
     "destination", "private"),
    ({"type": "webhook", "destination": "http://127.0.0.1:8065/hook"},
     "destination", "unsendable"),
    # And the fields no window of ours asks for.
    ({"type": "webhook", "destination": PLAIN_HOOK, "chat_id": CHAT_ID},
     "chat_id", "not_taken"),
    ({"type": "webhook", "destination": PLAIN_HOOK, "events": ["made up"]},
     "events", "unknown"),
    ({"type": "carrier pigeon", "destination": PLAIN_HOOK}, "type", "unknown"),
    ({"type": "webhook", "label": "<script>", "destination": PLAIN_HOOK},
     "label", "shape"),
    ({"type": "webhook", "env": "PATH"}, "env", "shape"),
    ({"type": "webhook", "env": "WHICHPORTS_A", "destination": PLAIN_HOOK},
     "env", "not_taken"),
]


def is_a_classed_refusal(resp, field, reason, sent=()):
    """A 400 whose body is the sentence, the field and the reason and nothing
    else, with none of what was sent in it."""
    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert set(body) == {"detail", "field", "reason"}
    assert (body["field"], body["reason"]) == (field, reason)
    assert body["field"] in channels.FIELDS
    assert body["reason"] in channels.REASONS
    assert isinstance(body["detail"], str) and body["detail"]
    for value in sent:
        if isinstance(value, str) and len(value.strip()) > 4:
            assert value not in resp.text, "the answer repeats what was sent"


@pytest.mark.parametrize("fields,field,reason", REFUSED_CREATES)
def test_a_refused_create_names_its_field_and_its_reason(client, monkeypatch,
                                                         fields, field, reason):
    from app import outbound
    monkeypatch.delenv(outbound.SETTING, raising=False)
    resp = add(client, **fields)
    is_a_classed_refusal(resp, field, reason,
                         sent=(fields.get("destination"), fields.get("chat_id")))
    assert state() == []


def test_the_fields_a_refusal_names_are_the_ones_a_request_carries():
    """The class is the request's own field name, so a caller finds the field
    without a table of ours."""
    assert set(channels.FIELDS) == set(ingest.CHANNEL_FIELDS) | {"events"}


def test_a_refused_replacement_names_its_field_and_its_reason(client):
    assert add(client, type="telegram", label="tg", destination=BOT_TOKEN,
               chat_id=CHAT_ID).status_code == 201
    for fields, field, reason in (
            ({"destination": CHAT_ID, "chat_id": BOT_TOKEN},
             "destination", "shape"),
            ({"destination": BOT_TOKEN, "chat_id": BOT_TOKEN},
             "chat_id", "shape"),
            ({"destination": "", "chat_id": CHAT_ID}, "destination", "missing"),
            ({"destination": BOT_TOKEN}, "chat_id", "missing"),
            ({"destination": PLAIN_HOOK, "chat_id": CHAT_ID},
             "destination", "shape")):
        resp = put_destination(client, "tg", **fields)
        is_a_classed_refusal(resp, field, reason)
    stored = rows()[0]
    assert stored["destination"] == BOT_TOKEN
    assert stored["destination_extra"] == CHAT_ID


def test_refused_kinds_and_a_refused_name_say_theirs(client):
    assert a_webhook(client, "ops").status_code == 201
    assert a_webhook(client, "two").status_code == 201
    kinds = put_events(client, "ops", events=["made up"])
    is_a_classed_refusal(kinds, "events", "unknown")
    for label, field, reason in (("<b>", "label", "shape"),
                                 ("ops", "label", "taken")):
        resp = client.post("/api/admin/channels/two/rename",
                           content=json.dumps({"label": label}),
                           headers=gate())
        is_a_classed_refusal(resp, field, reason)
    assert live_labels() == ["ops", "two"]


def test_a_create_with_no_label_left_names_the_label(client):
    """The window sends no label and the server makes one up. When it has
    none left to make up, the answer says the label is taken, by class."""
    for _ in range(99):
        assert add(client, type="webhook",
                   env="WHICHPORTS_A").status_code == 201
    resp = add(client, type="webhook", env="WHICHPORTS_A")
    is_a_classed_refusal(resp, "label", "taken")
    assert len(rows()) == 99
