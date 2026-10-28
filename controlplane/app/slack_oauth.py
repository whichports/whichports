"""Connect to Slack: the OAuth v2 flow that hands us an incoming webhook URL.

The owner asked for the Connect to Slack button on 2026-08-22, and was right that
it works: an earlier project of the author's runs this flow in production.
This is that flow, reviewed rather than pasted, with the two things that
project does that we do not.

## What this needs before it does anything

    WHICHPORTS_SLACK_CLIENT_ID       the app's client id
    WHICHPORTS_SLACK_CLIENT_SECRET   the app's client secret, a real secret

Both in the **ingest** unit's environment, which is a widening worth naming:
that unit has held no credential until now. It holds this one because the flow
cannot happen anywhere else, and it holds nothing else. With either unset the
feature is absent rather than broken, and the connect route says so in words.

**No Caddy change is needed.** The callback lives under `/api/admin/`, which is
already routed to this app and already behind basic auth, so the browser that
comes back from Slack is one that has already authenticated. That is not a
coincidence to rely on silently, so it is written here: move this route out of
`/api/admin/` and it stops being reachable.

## The flow, from Slack's own documentation

Read 2026-08-22 from docs.slack.dev/authentication/installing-with-oauth and
docs.slack.dev/reference/methods/oauth.v2.access:

  - authorize at `https://slack.com/oauth/v2/authorize` with `client_id`,
    a comma separated `scope`, and `redirect_uri`
  - the code "expires after ten minutes"
  - exchange at `https://slack.com/api/oauth.v2.access`
  - "Your `redirect_uri` must match or be a subdirectory of a Redirect URL
    configured under App Management", and "must use HTTPS"
  - on `state`: "Check the `state` parameter if you sent one along with your
    initial user redirect. If it doesn't match what you sent, consider the
    authorization a forgery."

One scope, `incoming-webhook`, which "triggers a user-facing channel picker in
the OAuth 2.0 installation sequence". No message history, no user identity, no
admin.

## Two things the earlier project does that this does not

**It sends the client id and secret in the request body.** Slack's own
reference says: "If possible, avoid sending `client_id` and `client_secret` as
parameters in your request and instead supply the Client ID and Client Secret
using the HTTP Basic authentication scheme." So this uses Basic.

**It calls bare `urllib.request.urlopen`**, which installs a proxy handler that
reads `https_proxy` from the environment and follows redirects. This module
takes `app/webhook.py`'s opener instead, for the reasons in that file's
docstring, and they apply harder here: the thing crossing the wire is a client
secret going out and a webhook URL coming back.

## One thing that is not verified, and must not be assumed

**Where `incoming_webhook.url` sits in a genuine v2 response.** Slack's
`oauth.v2.access` reference shows no `incoming_webhook` object in any of its
examples, even in the one whose scope string is `commands,incoming-webhook`.
The only place the object is shown is the webhooks guide, and that example is a
v1 body. So the field is read from where the earlier project reads it in
production and where the guide documents it, and **this module fails loudly
rather than
guessing** if it is not there. The first real connect either confirms the shape
or produces an error naming exactly what came back, and that answer belongs in
`docs/RECORD.md` rather than in a comment written before it happened.
"""

import hmac
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode

from . import authz, webhook

AUTHORIZE_URL = "https://slack.com/oauth/v2/authorize"
ACCESS_URL = "https://slack.com/api/oauth.v2.access"

# The one scope. It grants "Post messages to specific channels in Slack" and
# nothing else (docs.slack.dev/reference/scopes/incoming-webhook).
SCOPE = "incoming-webhook"

CLIENT_ID_ENV = "WHICHPORTS_SLACK_CLIENT_ID"
CLIENT_SECRET_ENV = "WHICHPORTS_SLACK_CLIENT_SECRET"

# The cookie the state lives in between the two legs. HttpOnly so no script can
# read it, SameSite=Lax so it survives Slack's top level redirect back, and
# short lived because the code Slack issues expires in ten minutes anyway.
STATE_COOKIE = "whichports_slack_state"
STATE_TTL_SECONDS = 600

# A state shorter than this is not compared at all. Without a floor, an absent
# cookie and an absent parameter compare equal and every forgery check passes.
# The earlier project has the same guard and it is the one worth copying
# exactly.
STATE_MIN_LENGTH = 32

# Every webhook URL Slack issues is on this host. Checked because the value
# arrives from a network call and lands in the database, and a prefix test on
# the full string cannot be fooled by a userinfo trick like
# `https://hooks.slack.com@evil.example/`.
WEBHOOK_PREFIX = "https://hooks.slack.com/"

# Slack's own error codes: short, lowercase, snake_case, from a fixed
# vocabulary. `invalid_code`, `access_denied`, `bad_client_secret`.
#
# **Bounded rather than trusted, and a test found why.** The first version
# accepted anything alphanumeric with underscores, so a value like
# `bad_SUPERSECRETCLIENTSECRET` passed and was printed onto a page. That field
# reaches a browser from two directions: Slack's answer body, and the callback's
# own query string, which anybody can put anything in. Lowercase only and a
# length cap makes it a code or nothing.
ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,40}$")


def safe_error_code(value) -> str:
    """A Slack error code, or "" if it does not look like one.

    Used on both the response body and the callback's query string, because
    the second is attacker supplied and the first is only as trustworthy as
    the connection.
    """
    if not isinstance(value, str):
        return ""
    return value if ERROR_CODE_RE.match(value) else ""

TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 65536


class SlackError(Exception):
    """A connect that cannot be completed, in words an operator can act on.

    **Never carries the client secret, the code, or the webhook URL.** Every
    one of those is reachable from this flow and every one of them ends up in a
    browser, so the message is about shape and never about value.
    """


def client_id(env=None) -> str:
    env = os.environ if env is None else env
    return (env.get(CLIENT_ID_ENV) or "").strip()


def client_secret(env=None) -> str:
    env = os.environ if env is None else env
    return (env.get(CLIENT_SECRET_ENV) or "").strip()


def is_configured(env=None) -> bool:
    """Both halves, or the feature is absent. Absent is a state this says out
    loud rather than a route that fails oddly."""
    return bool(client_id(env) and client_secret(env))


def new_state() -> str:
    return secrets.token_urlsafe(32)


def state_matches(expected: str, given: str) -> bool:
    """Constant time, and refusing anything too short to be one of ours.

    The floor is the point. `hmac.compare_digest("", "")` is True, so without
    it a request carrying no state, against a browser holding no cookie, would
    pass the forgery check that exists to stop exactly that.
    """
    if not expected or len(expected) < STATE_MIN_LENGTH:
        return False
    if not given or len(given) < STATE_MIN_LENGTH:
        return False
    return hmac.compare_digest(expected, given)


def authorize_url(redirect_uri: str, state: str, env=None) -> str:
    """Where to send the browser. Raises if this control plane has no app."""
    if not is_configured(env):
        raise SlackError(
            "this control plane has no Slack app configured, so there is"
            f" nothing to connect to. Set {CLIENT_ID_ENV} and"
            f" {CLIENT_SECRET_ENV} in the ingest unit's environment")
    query = urllib.parse.urlencode({
        "client_id": client_id(env),
        "scope": SCOPE,
        "redirect_uri": redirect_uri,
        "state": state,
    })
    return f"{AUTHORIZE_URL}?{query}"


def _opener():
    """`app/webhook.py`'s posture: no proxy, no redirect.

    A proxy here would take the client secret on the way out and the webhook
    URL on the way back. A redirect would let an answer move the request to an
    address nobody checked.
    """
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), authz._NoRedirects())


def exchange_raw(code: str, redirect_uri: str, env=None, opener=None) -> bytes:
    """Trade the code for Slack's answer, as bytes, or raise SlackError.

    Raw rather than parsed because the caller wants two things out of one
    exchange, the webhook URL and the channel the operator picked, and a code
    may only be exchanged once.

    The client id and secret go in an `Authorization: Basic` header rather than
    in the body, which is what Slack's reference asks for.
    """
    if not is_configured(env):
        raise SlackError("this control plane has no Slack app configured")
    if not code:
        raise SlackError("Slack sent no code back, so there is nothing to"
                         " exchange. Start the connect again")

    body = urllib.parse.urlencode({
        "code": code,
        "redirect_uri": redirect_uri,
    }).encode("utf-8")
    pair = f"{client_id(env)}:{client_secret(env)}".encode("utf-8")
    request = urllib.request.Request(
        ACCESS_URL, data=body, method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": "Basic " + b64encode(pair).decode("ascii"),
            "User-Agent": webhook.USER_AGENT,
        })

    opener = opener or _opener()
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        raise SlackError(f"Slack answered {exc.code} to the exchange") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # The class and never the message, the same rule every other outbound
        # call in this package follows.
        raise SlackError("Slack could not be reached:"
                         f" {type(exc).__name__}") from None

    return raw


def webhook_url_from(raw: bytes) -> str:
    """The webhook URL out of an `oauth.v2.access` body, or a SlackError.

    Separate from the call so the shape can be tested without a socket, which
    matters more here than usual: **this is the part Slack's own reference does
    not show for v2**, so it is the part most likely to be wrong on the first
    real connect.
    """
    try:
        answer = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise SlackError("Slack answered something that is not JSON") from None
    if not isinstance(answer, dict):
        raise SlackError("Slack answered something that is not JSON")

    if answer.get("ok") is not True:
        # `error` is Slack's own short code, like `invalid_code`. It is a fixed
        # vocabulary rather than free text, so it is worth passing on: without
        # it every failure reads the same and none is diagnosable.
        code = safe_error_code(answer.get("error"))
        if code:
            raise SlackError(f"Slack refused the connect: {code}")
        raise SlackError("Slack refused the connect and gave no reason we can"
                         " read")

    hook = answer.get("incoming_webhook")
    if not isinstance(hook, dict) or not isinstance(hook.get("url"), str):
        # Named precisely, because this is the shape that is unverified. An
        # operator hitting this should be able to say what was missing without
        # us printing the body, which carries an access token.
        raise SlackError(
            "Slack said yes but the answer carried no incoming_webhook.url,"
            " so there is no channel to post to. Check the app has the"
            " incoming-webhook scope")

    url = hook["url"]
    if not url.startswith(WEBHOOK_PREFIX):
        # Not repeated back. It is a credential whichever host it names.
        raise SlackError("Slack returned a webhook URL that is not on"
                         " hooks.slack.com, which is not a URL this stores")
    return url


def channel_name_from(raw: bytes) -> str:
    """The Slack channel the operator picked, for the row's label. "" if absent.

    A channel name is not a secret and it is the only readable thing in that
    answer, so it is what the row is called on the Integrations screen instead of a
    label they never chose.
    """
    try:
        answer = json.loads(raw.decode("utf-8"))
        name = answer.get("incoming_webhook", {}).get("channel")
    except (UnicodeDecodeError, ValueError, AttributeError):
        return ""
    return name if isinstance(name, str) else ""
