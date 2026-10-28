"""Alert delivery to a URL the operator chooses. Stdlib urllib only, and off
unless configured.

`docs/PRODUCT.md` section 7's frozen v1 list says "drift alerts by email and
webhook". `app/notify.py` is the mail half and this is the other one. Both are
best effort: a dead endpoint logs and returns rather than raising, because one
broken delivery path must never wedge the sweep that found the problem.

## The posture is copied from `app/authz.py`, deliberately and not by accident

There are two outbound HTTP call sites in this package already and they do not
agree with each other. `authz.fetch_token_file` hands `build_opener` an
explicit `ProxyHandler({})` and refuses redirects. `hetzner.build_opener` does
neither. This module copies the first one, because the reasoning in its
docstring is the reasoning that applies here too:

  - **no proxy, ever.** `urllib.request.build_opener` installs a bare
    `ProxyHandler()` unless it is handed one, and that reads `https_proxy`
    from the environment. So the hole opens with nobody touching the code,
    through one variable in the sweep unit's environment, and what would go
    through it is a URL that is frequently itself a secret.
  - **no redirect, ever.** A 3xx is a refusal. Following one would let the
    endpoint move the request to an address this module already decided not to
    send to, which throws away the check below.

## Where it may send, and exactly what that does and does not stop

The control plane runs beside the ingest on `127.0.0.1:8410`, Caddy, and the
only database in the project, so a URL an operator supplies is an outbound
request from inside that box to an address they choose.

**Every address the host name resolves to has to be globally routable**, using
`authz._is_probeable`, which is the same predicate that decides what the prober
may touch. That refuses loopback, private, link-local, reserved, multicast,
carrier-NAT and v4-mapped v6.

**One exception, and it is never ours.** An instance somebody runs themselves
may set `WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES=yes`, and then five named
private networks are sent to as well. `app/outbound.py` owns that rule, what
it lets through and what stays refused whatever it says. This box never sets
it.

**What it does not stop, said plainly rather than left to be discovered.** The
name is resolved here and resolved again by the connection, so a name that
answers with a public address now and a private one a moment later is not
caught. That is DNS rebinding, and `authz.py` already names it as the reason
the proof URL takes a literal address rather than a name. Closing it means
connecting to the address that was checked and carrying the name only in the
Host header, which changes certificate validation and is its own piece of work.
It is worth naming now because v1 is single tenant, where the operator supplying
the URL is the operator who owns the box, and the day that stops being true is
the day this has to be finished.

## What crosses the wire

**Never more than the mail already sends.** The mail is the ceiling, and the
payload carries the same strings `app/notify.py` puts in a message rather than
a decomposed version of them. That last part matters and is easy to get
backwards: `join.describe` can quote firewall rule text verbatim, and lifting
that text into its own `rule_text` field would make it easier to consume, which
is the same thing as disclosing more.

Configuration is environment only, never the database and never the repository,
which is `app/notify.py`'s rule and it applies here twice over: a webhook URL is
a destination and is very often a credential as well.

    WHICHPORTS_WEBHOOK_URL   where to post. Absent means send nothing.
"""

import ipaddress
import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import authz, outbound

log = logging.getLogger("whichports.webhook")

# Long enough for a slow endpoint, short enough that the five minute sweep
# timer cannot be held open by one. The same reasoning as notify's SMTP
# timeout, and the same order of magnitude.
TIMEOUT_SECONDS = 10.0

USER_AGENT = "whichports-alerts (+https://whichports.com)"

# The payload version, so a consumer can tell a shape change from a data
# change. It is in the body rather than only in a header, because a consumer
# that logs the body keeps the version with it.
PAYLOAD_VERSION = 1

# A bounded read of the response. Nothing here uses the body, so this exists
# only so a hostile endpoint cannot stream into this process for ever.
MAX_RESPONSE_BYTES = 4096

ALLOWED_SCHEMES = ("https", "http")


@dataclass(frozen=True)
class Config:
    url: str = ""
    # Which environment variable the URL came from. It is the delivery key
    # (`alerts.webhook_channel`), so two channels reading two variables are two
    # destinations and each is delivered to once.
    source_env: str = "WHICHPORTS_WEBHOOK_URL"

    @property
    def configured(self) -> bool:
        return bool(self.url)

    def __repr__(self) -> str:
        """`url=set`, never the URL.

        A webhook URL routinely carries its own secret in the path, and a
        dataclass prints every field by default. `app/hetzner.py` already does
        this for its token and `app/notify.py` did not do it for its relay
        password, which is fixed in the same change that added this.
        """
        return f"Config(url={'set' if self.url else 'unset'})"


def config_from_env(env=None) -> Config:
    env = os.environ if env is None else env
    return Config(url=(env.get("WHICHPORTS_WEBHOOK_URL") or "").strip())


def _addresses(host: str, resolver=None):
    """Every address this name answers with, as `ipaddress` objects.

    `resolver` is injected by the tests and by nothing else, so no test in this
    repository has to resolve a real name to prove the check works.
    """
    resolver = resolver or (lambda h: [info[4][0] for info in
                                       socket.getaddrinfo(h, None)])
    found = []
    for text in resolver(host):
        try:
            found.append(ipaddress.ip_address(str(text).split("%")[0]))
        except ValueError:
            continue
    return found


def check_url(url: str, resolver=None, guard=None) -> str:
    """"" when this URL may be posted to, or a sentence saying why not.

    A sentence rather than an exception, because the caller is a timer and
    every refusal here has to be printable beside the others.

    `guard` decides which addresses are sent to. Left out, it is the rule in
    force for this process (`app/outbound.py`): globally routable only, or on
    an instance whose operator set it so, the private networks as well.
    """
    allowed = guard or outbound.guard()
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return f"the webhook URL cannot be parsed: {type(exc).__name__}"
    if parts.scheme not in ALLOWED_SCHEMES:
        return (f"the webhook URL scheme is {parts.scheme!r} and only"
                f" {' and '.join(ALLOWED_SCHEMES)} are sent to")
    if not parts.hostname:
        return "the webhook URL names no host"

    try:
        addresses = _addresses(parts.hostname, resolver)
    except OSError as exc:
        return (f"the webhook host {parts.hostname} did not resolve:"
                f" {type(exc).__name__}")
    if not addresses:
        return f"the webhook host {parts.hostname} resolved to no address"

    # Every one of them, not the first. A name answering with one public
    # address and one private address is a name that reaches the private one.
    for ip in addresses:
        if not allowed(ip):
            return (f"the webhook host {parts.hostname} resolves to {ip}, "
                    + outbound.refusal(ip))
    return ""


def send(payload: dict, config: Config | None = None,
         resolver=None, opener=None, check_body=None,
         max_response_bytes: int = MAX_RESPONSE_BYTES) -> tuple[bool, str]:
    """Returns (sent, reason). Never raises: the caller is a timer.

    `resolver` and `opener` are arguments so the tests drive the real logic
    without a socket. Left alone they are the real ones.

    `check_body` exists for one endpoint and is None for the rest.
    **Telegram defines success in the body rather than in the status**: its
    documentation says the response "always has a Boolean field `ok`" and that
    "if `ok` equals True, the request was successful"
    (core.telegram.org/bots/api#making-requests, read 2026-08-22). Checking the
    signal the API documents is right whatever its status code does, so a
    caller that has one passes a function taking the bytes and returning "" or
    a complaint. Nothing else reads the body at all.

    `max_response_bytes` is the bound on that read. It is raised only by a
    caller that has to parse what came back, because a body cut in half parses
    as broken and would be reported as a failed delivery that in fact arrived.
    """
    config = config_from_env() if config is None else config
    if not config.configured:
        return False, "no webhook configured"

    complaint = check_url(config.url, resolver)
    if complaint:
        log.warning("webhook refused: %s", complaint)
        return False, complaint

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        config.url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": USER_AGENT})
    opener = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), authz._NoRedirects())
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            body_bytes = response.read(max_response_bytes)
            if not 200 <= response.status < 300:
                return False, f"the endpoint answered {response.status}"
            if check_body is not None:
                complaint = check_body(body_bytes)
                if complaint:
                    return False, complaint
    except urllib.error.HTTPError as exc:
        # A 3xx arrives here because redirects are refused, and it is a
        # refusal rather than a failure of ours.
        return False, f"the endpoint answered {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # The class and never the message. An endpoint's own error text is not
        # something to put in our log, and it is not something we can trust.
        return False, f"the endpoint could not be reached: {type(exc).__name__}"
    return True, "posted"


# ------------------------------------------------------------ the payloads
#
# One builder per kind the mail has a formatter for, so a kind that gains a
# mail and not a webhook is a visible gap rather than a silent one.
#
# The fields are the same facts the mail carries and no others. `detail` and
# `description` are the strings `app/notify.py` puts in a message, passed
# through rather than taken apart.


def _base(kind: str, host_name: str, display: str = "") -> dict:
    """`server` is the name the server is found by, always, because a program
    reads it. A server with a display name carries that beside it as
    `server_name`, and one without carries no such field, so what a consumer
    reading `server` gets is what it got before display names. An added field
    is not a new version of the payload."""
    base = {"version": PAYLOAD_VERSION, "kind": kind, "server": host_name}
    if display:
        base["server_name"] = display
    return base


def payload_for_alert(kind: str, host_name: str, detail: str,
                      raised_at: str, display: str = "") -> dict:
    """The one-line kinds: an agent gone quiet, an outside view gone stale."""
    return {**_base(kind, host_name, display), "detail": detail, "raised_at": raised_at}


def payload_for_changes(host_name: str, changes, display: str = "") -> dict:
    """The coalesced kind. One post for every finding on one server that
    changed, which is the same grouping the mail uses and therefore the same
    thing `docs/PRODUCT.md` 4c asked for."""
    return {**_base("finding changed", host_name, display),
            "changes": [{"where": c.where, "was": c.was, "now": c.now,
                         "description": c.description,
                         "vantage": c.vantage, "measured_at": c.measured_at}
                        for c in changes]}
