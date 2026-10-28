"""Connect to Slack, and the parts of it that would be expensive to get wrong.

    python -m pytest tests/test_slack_oauth.py

**No test here reaches Slack.** The opener is an argument, the same rule
`tests/test_webhook.py` states, so the real logic runs against stand-ins.

The three that matter most:

  - **the forgery check**, because it is the only thing standing between a
    stranger's link and a webhook row written into this database
  - **nothing leaks**, because a client secret goes out and a webhook URL comes
    back, and both end up in a browser if anything prints them
  - **the shape Slack does not document**, because `incoming_webhook.url` is
    read from a position its v2 reference shows nowhere, so the failure has to
    be loud rather than a row holding None
"""

import json

import pytest

from app import slack_oauth

CLIENT_ID = "242341083157.1043470460085"
CLIENT_SECRET = "SUPERSECRETCLIENTSECRET"
HOOK = "https://hooks.slack.com/services/T00/B00/SUPERSECRETHOOKPATH"
ENV = {slack_oauth.CLIENT_ID_ENV: CLIENT_ID,
       slack_oauth.CLIENT_SECRET_ENV: CLIENT_SECRET}
REDIRECT = "https://app.whichports.com/api/admin/channels/slack/callback"


def body(**kw):
    base = {"ok": True, "incoming_webhook": {"url": HOOK, "channel": "#ops"}}
    base.update(kw)
    return json.dumps(base).encode()


class FakeOpener:
    def __init__(self, payload=None, status=200):
        self.payload = payload if payload is not None else body()
        self.status = status
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        outer = self

        class R:
            status = outer.status

            def read(self, n=None):
                return outer.payload if n is None else outer.payload[:n]

            def __enter__(self_inner):
                return self_inner

            def __exit__(self_inner, *a):
                return False

        return R()


# ------------------------------------------------- absent until configured

def test_the_feature_is_absent_without_both_halves():
    assert slack_oauth.is_configured({}) is False
    assert slack_oauth.is_configured({slack_oauth.CLIENT_ID_ENV: CLIENT_ID}) is False
    assert slack_oauth.is_configured(ENV) is True


def test_asking_for_an_authorize_url_without_an_app_says_so():
    with pytest.raises(slack_oauth.SlackError) as caught:
        slack_oauth.authorize_url(REDIRECT, slack_oauth.new_state(), {})
    assert slack_oauth.CLIENT_ID_ENV in str(caught.value)


# --------------------------------------------------------- the authorize leg

def test_the_authorize_url_is_the_v2_endpoint_with_the_one_scope():
    where = slack_oauth.authorize_url(REDIRECT, "s" * 40, ENV)
    assert where.startswith("https://slack.com/oauth/v2/authorize?")
    assert "scope=incoming-webhook" in where
    assert "client_id=242341083157" in where


def test_the_authorize_url_never_carries_the_client_secret():
    """The id is public and belongs in that URL. The secret is not and does
    not, and this is the request that lands in a browser's address bar."""
    where = slack_oauth.authorize_url(REDIRECT, "s" * 40, ENV)
    assert CLIENT_SECRET not in where


def test_a_state_is_long_enough_to_be_compared():
    for _ in range(20):
        assert len(slack_oauth.new_state()) >= slack_oauth.STATE_MIN_LENGTH


def test_two_states_are_never_the_same():
    assert len({slack_oauth.new_state() for _ in range(200)}) == 200


# ------------------------------------------------------- the forgery check

def test_a_matching_state_passes():
    state = slack_oauth.new_state()
    assert slack_oauth.state_matches(state, state) is True


def test_a_different_state_fails():
    assert slack_oauth.state_matches(slack_oauth.new_state(),
                                     slack_oauth.new_state()) is False


@pytest.mark.parametrize("expected,given", [
    ("", ""),                    # no cookie, no parameter
    ("", "x" * 40),              # no cookie
    ("x" * 40, ""),              # no parameter
    ("short", "short"),          # equal but too short to be one of ours
    ("x" * 31, "x" * 31),        # one below the floor
])
def test_nothing_short_or_absent_can_ever_match(expected, given):
    """**The one that would be expensive.** `hmac.compare_digest("", "") is
    True`, so without the floor a request carrying no state, from a browser
    holding no cookie, passes the check that exists to stop exactly that."""
    assert slack_oauth.state_matches(expected, given) is False


def test_the_floor_is_the_length_a_real_state_clears():
    assert len("x" * slack_oauth.STATE_MIN_LENGTH) == slack_oauth.STATE_MIN_LENGTH
    assert slack_oauth.state_matches("x" * slack_oauth.STATE_MIN_LENGTH,
                                     "x" * slack_oauth.STATE_MIN_LENGTH) is True


# ---------------------------------------------------------- the exchange leg

def test_the_secret_goes_in_a_basic_header_and_not_in_the_body():
    """Slack's own reference asks for this: "avoid sending client_id and
    client_secret as parameters in your request and instead supply the Client
    ID and Client Secret using the HTTP Basic authentication scheme"."""
    opener = FakeOpener()
    slack_oauth.exchange_raw("thecode", REDIRECT, ENV, opener)
    request = opener.requests[-1]
    assert request.headers["Authorization"].startswith("Basic ")
    sent = request.data.decode()
    assert CLIENT_SECRET not in sent
    assert "client_secret" not in sent


def test_the_exchange_posts_to_the_v2_access_endpoint():
    opener = FakeOpener()
    slack_oauth.exchange_raw("thecode", REDIRECT, ENV, opener)
    assert opener.requests[-1].full_url == "https://slack.com/api/oauth.v2.access"
    assert opener.requests[-1].method == "POST"


def test_no_code_is_refused_before_a_request_is_made():
    opener = FakeOpener()
    with pytest.raises(slack_oauth.SlackError):
        slack_oauth.exchange_raw("", REDIRECT, ENV, opener)
    assert opener.requests == [], "a request was made with no code"


# ----------------------------------------------- reading Slack's answer

def test_a_good_answer_gives_the_webhook_url():
    assert slack_oauth.webhook_url_from(body()) == HOOK


def test_the_channel_the_operator_picked_comes_back_too():
    assert slack_oauth.channel_name_from(body()) == "#ops"


def test_an_answer_with_no_incoming_webhook_fails_loudly(caplog):
    """**The shape Slack does not document for v2.** If it is not there, this
    has to say so rather than write a row holding nothing."""
    with pytest.raises(slack_oauth.SlackError) as caught:
        slack_oauth.webhook_url_from(json.dumps(
            {"ok": True, "access_token": "xoxb-SUPERSECRETTOKEN"}).encode())
    assert "incoming_webhook" in str(caught.value)
    # and the access token that was in that body is not in the message
    assert "SUPERSECRETTOKEN" not in str(caught.value)


def test_a_webhook_url_that_is_not_slacks_is_refused():
    """It arrives from a network call and lands in the database."""
    with pytest.raises(slack_oauth.SlackError) as caught:
        slack_oauth.webhook_url_from(body(
            incoming_webhook={"url": "https://evil.example/hook"}))
    assert "evil.example" not in str(caught.value)


def test_a_userinfo_trick_does_not_pass_the_prefix_check():
    """`https://hooks.slack.com@evil.example/` has hooks.slack.com in it and is
    not on it. The prefix ends with a slash, which is what stops this."""
    with pytest.raises(slack_oauth.SlackError):
        slack_oauth.webhook_url_from(body(
            incoming_webhook={"url": "https://hooks.slack.com@evil.example/x"}))


def test_slacks_own_error_code_is_passed_on():
    """A fixed vocabulary, not free text. Without it every failure reads the
    same and none is diagnosable."""
    out = json.dumps({"ok": False, "error": "invalid_code"}).encode()
    with pytest.raises(slack_oauth.SlackError) as caught:
        slack_oauth.webhook_url_from(out)
    assert "invalid_code" in str(caught.value)


def test_an_error_field_that_is_not_a_code_is_not_passed_on():
    """It reaches a page a person reads, so it is typed on the way in."""
    out = json.dumps({"ok": False, "error": "<script>alert(1)</script>"}).encode()
    with pytest.raises(slack_oauth.SlackError) as caught:
        slack_oauth.webhook_url_from(out)
    assert "<script>" not in str(caught.value)


@pytest.mark.parametrize("raw", [b"", b"not json", b"[1,2]", b"null", b"\xff\xfe"])
def test_an_answer_that_is_not_the_documented_shape_fails(raw):
    with pytest.raises(slack_oauth.SlackError):
        slack_oauth.webhook_url_from(raw)


def test_a_missing_channel_name_is_empty_and_not_a_crash():
    """The label falls back, because a connect that worked must not fail on the
    cosmetic half."""
    assert slack_oauth.channel_name_from(body(
        incoming_webhook={"url": HOOK})) == ""
    assert slack_oauth.channel_name_from(b"not json") == ""


# ------------------------------------------------------- nothing leaks

def test_no_failure_message_anywhere_carries_the_hook_or_the_secret():
    """Swept rather than listed. Every refusal in this module reaches a page in
    a browser, and two of the values in play are credentials."""
    attempts = [
        lambda: slack_oauth.webhook_url_from(body(
            incoming_webhook={"url": "https://evil.example/" + HOOK})),
        lambda: slack_oauth.webhook_url_from(json.dumps(
            {"ok": True, "incoming_webhook": {"url": None}}).encode()),
        lambda: slack_oauth.webhook_url_from(json.dumps(
            {"ok": False, "error": "bad_" + CLIENT_SECRET}).encode()),
        lambda: slack_oauth.exchange_raw("", REDIRECT, ENV, FakeOpener()),
    ]
    for attempt in attempts:
        with pytest.raises(slack_oauth.SlackError) as caught:
            attempt()
        message = str(caught.value)
        assert CLIENT_SECRET not in message, message
        assert "SUPERSECRETHOOKPATH" not in message, message


def test_the_opener_refuses_proxies_and_redirects():
    """The project this flow was reviewed from calls bare urlopen here, which
    reads https_proxy from the environment and follows redirects. What
    crosses this wire is a client
    secret going out and a webhook URL coming back."""
    opener = slack_oauth._opener()
    handlers = [type(h).__name__ for h in opener.handlers]
    assert "_NoRedirects" in handlers
    # An empty ProxyHandler defines no <scheme>_open method, so add_handler
    # never inserts it. tests/test_authz.py records the same thing, which is
    # why this asserts the redirect refusal and not the proxy one by name.
    assert "HTTPRedirectHandler" not in handlers
