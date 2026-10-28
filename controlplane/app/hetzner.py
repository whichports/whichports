"""The Hetzner Cloud provider leg, read only, and off unless configured.

`docs/PRODUCT.md` section 8 item 3 wants three views of the same port side by
side: what the agent sees from inside the host, what the prober sees from
outside, and what the provider says its cloud firewall is doing. This module is
the third one. It fetches the server inventory and the firewalls, and it stores
what the provider said, verbatim. It draws no conclusion and it joins nothing
to a host document. That is a later PR.

## Where every fact below comes from

the accuracy rule and `docs/PRODUCT.md` section 4b: never state a provider
capability without reading it from that provider's own documentation or API.
Everything this module relies on was read on **2026-08-15** from:

  - the Hetzner Cloud OpenAPI description, `https://docs.hetzner.cloud/cloud.spec.json`,
    which is the document `https://docs.hetzner.cloud/reference/cloud` renders.
    openapi 3.1.2, info.title "Hetzner Cloud API"
  - `https://docs.hetzner.com/cloud/api/getting-started/using-api/`
  - `https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/`

The individual endpoint and field citations sit next to the code that uses
them, so a later reader can check one line without re-reading this header.

This is the Hetzner **Cloud** API. Hetzner Robot, which serves the dedicated
servers, is a separate web service on `https://robot-ws.your-server.de` with
its own documentation at `https://robot.hetzner.com/doc/webservice/en.html` and
HTTP Basic authentication rather than a bearer token, read 2026-08-15. Nothing
here speaks to it and dedicated servers are out of scope.

## Read only, by construction

Security invariants SI-3 and SI-5. Two independent things hold it:

  1. **Ours.** `_request` is the only function in this module that touches the
     network. It hardcodes `method="GET"` and never passes a body. There is no
     parameter anywhere that could make it send anything else, so making this
     module write would take a visible code change rather than a wrong argument.
     `tests/test_hetzner.py` asserts both the behaviour and the source.
  2. **Theirs.** Hetzner issues tokens with a permission of either "Read" or
     "Read & Write", and of the Read permission the token page says: "If you
     select Read, the token will only be allowed to perform GET requests." The
     API backs that with its own error, listed in the spec's error table as
     `401 token_readonly`, "The token is only allowed to perform GET requests."
     So a token created the way the docs describe cannot write even if this
     code were wrong. Use a Read token.

## The credential

One row per token, stored per workspace since 2026-09-14 (`docs/RECORD.md`
4.178) and one per Hetzner project since 2026-09-27 (4.206), the shape
`app/channels.py` settled on for a webhook: a row holds the token, and
nothing that renders a page reads that column. `token_for` is the one
function that returns the value, the sweep and the admin routes are its
callers, and `tokens` is what a screen gets: per token, a hint the row stored
beside it when it was set, the last four characters and nothing before them,
and when it was set. A test in `site/` fails if the renderer's
source names `token_for` or a stored token reaches the HTML.

Until 2026-09-14 the token was one environment variable on the box for the
whole fleet, `WHICHPORTS_HETZNER_TOKEN`, which cannot serve a second
workspace. It is not read any more. Nothing on the production box had it set
on the day it went, read by the owner (4.178), so nothing was migrated.

Encrypting the row at rest was weighed and not done: against someone holding
the database file and the process it buys nothing, because the process must
hold the key to use the token, and it would protect only a copy of the file
on its own, which today means the nightly backups. Said plainly so the trade
is known: a backup holds Read tokens, and a Read token is the customer's to
revoke in their provider's console.

**With no row this does nothing and says so.** Merging a branch never starts
talking to anybody's provider account, and `Config.__repr__` redacts the
token, so a config object landing in a log line or a traceback cannot leak it.

## v4 and v6 are kept apart

`docs/PRODUCT.md` 4b, rule 3: each family is measured or marked absent, never
inferred from the other. The provider hands both families back in one flat list
per rule, and flattening it further is exactly the mistake 4b was written
after. So `AddressSet` splits the list by family and keeps a rule that names
only one of them visibly one-sided. A rule with `0.0.0.0/0` and no v6 entry
says nothing at all about IPv6, and this model makes that readable rather than
guessable.

The other half of 4b: four servers on the owner's account had no cloud firewall
attached at all. The provider reports that as an empty `public_net.firewalls`
array, and an empty tuple here means the provider said none, which is a
different fact from never having fetched. Nothing is stored at all when a fetch
fails, so the two can never be confused.
"""

import ipaddress
import json
import sqlite3
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .workspace import DEFAULT_WORKSPACE_ID

# No logger here on purpose. Everything this module could usefully say either
# goes to the caller as a typed error or is printed by hetzner_cli, and a log
# call is one more place a config object could be handed a formatter.
PROVIDER = "hetzner"

# What a token may look like before it is stored. Hetzner's own tokens are 64
# characters of letters and digits (read from a token this project holds,
# 2026-08-15); the bound is generous rather than exact so a format change on
# their side does not refuse a real token, and the character rule keeps a
# pasted line with a newline, a space or a control character out of the row.
MAX_TOKEN_LEN = 256

# "https://api.hetzner.cloud/v1/{api-url-ending}", from the Using the API page,
# and the same value appears as the single entry in the spec's `servers` array.
# A constant rather than a setting: there is no reason for an operator to point
# this at another host, and a knob that could would be a way to send the token
# somewhere else.
API_BASE = "https://api.hetzner.cloud/v1"

# Endpoints. Both are GET-only here even though the API offers more on the same
# paths (spec: /servers has get and post, /firewalls has get and post).
PATH_SERVERS = "/servers"
PATH_FIREWALLS = "/firewalls"

# Pagination, from the spec's Pagination section: "A `page` parameter specifies
# the page to fetch. The number of the first page is 1." and "A `per_page`
# parameter specifies the number of items returned per page. The default value
# is 25, the maximum value is 50 except otherwise specified in the
# documentation." Neither endpoint above specifies otherwise.
PER_PAGE = 50
FIRST_PAGE = 1

# 50 per page, so this covers 2,000 servers or firewalls. A project past that
# is a real situation and a silent truncation would be the worst possible
# answer to it, so hitting this raises instead (see ERROR_TOO_MANY_PAGES).
MAX_PAGES = 40

# Long enough for a slow API, short enough that a person running the CLI is not
# left staring at a terminal. There is no timer running this yet.
REQUEST_TIMEOUT_SECONDS = 20

# Who we are, in the shape `app/authz.py` uses. A provider whose audit log
# shows an unnamed client is a provider whose owner cannot tell our reads from
# anyone else's.
USER_AGENT = "whichports-provider-read (+https://whichports.com)"

# A response bigger than this is not an inventory, it is a problem. The ingest
# caps the documents agents post for the same reason.
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Error kinds. Typed, in the spirit of SI-8: the provider's `message` field is
# free text written by them and it never enters an exception here, a log line
# or the database. Only these constants and the HTTP status travel.
ERROR_NOT_CONFIGURED = "not_configured"
ERROR_UNAUTHORIZED = "unauthorized"
ERROR_FORBIDDEN = "forbidden"
ERROR_RATE_LIMITED = "rate_limited"
ERROR_NETWORK = "network"
ERROR_MALFORMED = "malformed"
ERROR_REDIRECTED = "redirected"
ERROR_TOO_MANY_PAGES = "too_many_pages"
ERROR_HTTP = "http"


class ProviderError(Exception):
    """One class, one typed kind, no provider text.

    `str(exc)` is the kind and nothing else, so an operator pasting a traceback
    into a chat window cannot paste anything the provider wrote.
    """

    def __init__(self, kind: str, status: int | None = None,
                 rate_limit_reset_unix: int | None = None):
        super().__init__(kind)
        self.kind = kind
        self.status = status
        self.rate_limit_reset_unix = rate_limit_reset_unix


# ------------------------------------------------------------------- the token

@dataclass(frozen=True)
class Config:
    token: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.token)

    def __repr__(self) -> str:
        # The default dataclass repr would print the token. A Config can end up
        # in a log line or a traceback, so it is redacted at the source rather
        # than at every call site.
        return f"Config(token={'set' if self.token else 'unset'})"


class TokenError(ValueError):
    """A token that cannot be stored, said in words a screen can show and
    never echoing what was pasted."""


def check_token(token) -> str:
    """The token as it will be stored, or TokenError. Whitespace around it is
    the paste's and is dropped; anything else that is not printable ASCII is
    refused, because a real token has none of it and a control character in
    a bearer header is a request we do not want to send."""
    if not isinstance(token, str):
        raise TokenError("A token is needed.")
    token = token.strip()
    if not token:
        raise TokenError("A token is needed.")
    if len(token) > MAX_TOKEN_LEN:
        raise TokenError(f"A token is at most {MAX_TOKEN_LEN} characters.")
    if any(ch < "!" or ch > "~" for ch in token):
        raise TokenError("A token holds letters, digits and punctuation only.")
    return token


def token_hint(token: str) -> str:
    """What a screen may show of a token: its last four characters after an
    ellipsis, and nothing of a token too short to hide anything."""
    return "…" + token[-4:] if len(token) >= 12 else "…"


def client_for(token: str, opener=None) -> "ReadOnlyClient":
    return ReadOnlyClient(Config(token=token), opener=opener)


# --------------------------------------------------------------- the data model

@dataclass(frozen=True)
class AddressSet:
    """The CIDRs the provider listed for one rule, split by address family.

    Spec, `source_ips` on a firewall rule: "List of permitted IPv4/IPv6
    addresses for incoming traffic ... Use `0.0.0.0/0` to allow any IPv4
    addresses and `::/0` to allow any IPv6 addresses." So one flat list carries
    both families and the split has to be made here.

    `unparsed` holds any entry that is a string but not something
    `ipaddress` recognises. Keeping it verbatim rather than dropping it means a
    form we have not seen shows up as an entry we could not classify, instead
    of vanishing and making a rule look narrower than it is.
    """

    v4: tuple[str, ...] = ()
    v6: tuple[str, ...] = ()
    unparsed: tuple[str, ...] = ()

    @property
    def has_v4(self) -> bool:
        """The rule names at least one IPv4 CIDR. Not a claim about reach."""
        return bool(self.v4)

    @property
    def has_v6(self) -> bool:
        return bool(self.v6)

    @property
    def empty(self) -> bool:
        return not (self.v4 or self.v6 or self.unparsed)


@dataclass(frozen=True)
class FirewallRule:
    """One rule, as the provider wrote it.

    Field names and value sets are the spec's: `direction` is `in` or `out`,
    `protocol` is one of `tcp`, `udp`, `icmp`, `esp`, `gre`, and `port` is
    "Port or port range to apply the rule for. Only applicable for protocols
    `tcp` and `udp`", nullable, a string like `80` or `1024-5000`.

    `port` stays the string the provider sent. Expanding `1024-5000` into
    numbers here would be us reshaping evidence, and the range syntax is theirs
    to define.
    """

    direction: str
    protocol: str
    port: str | None
    description: str | None
    source_ips: AddressSet
    destination_ips: AddressSet


@dataclass(frozen=True)
class FirewallTarget:
    """One entry of a firewall's `applied_to` array.

    Spec: `type` is `server` or `label_selector`. `server` is set only for type
    `server`, `label_selector` only for type `label_selector`, and
    `applied_to_resources` holds the "Resources applied to via this Label
    Selector", which is how a selector-attached firewall names the servers it
    actually landed on.
    """

    type: str
    server_id: int | None = None
    label_selector: str | None = None
    resolved_server_ids: tuple[int, ...] = ()


@dataclass(frozen=True)
class Firewall:
    id: int
    name: str
    rules: tuple[FirewallRule, ...] = ()
    applied_to: tuple[FirewallTarget, ...] = ()


@dataclass(frozen=True)
class AttachedFirewall:
    """An entry of a server's `public_net.firewalls`.

    Spec: `status` is `applied` or `pending`. Pending is not applied, and the
    two are kept apart rather than both read as "has a firewall".
    """

    id: int
    status: str


@dataclass(frozen=True)
class Server:
    """One server, with the two address families kept apart.

    `ipv4` is `public_net.ipv4.ip`, "IP address (v4) of this Server". The whole
    `public_net.ipv4` object is nullable in the spec, so a server can have no
    primary IPv4 and this is then None, which means the provider said none.

    `ipv6_network` is `public_net.ipv6.ip`, and the name is deliberate. The
    spec calls that object "IPv6 network assigned to this Server" and its
    example value is `2001:db8::/64`. It is a network, not the address anything
    is bound to. Treating it as a host address is the kind of confident wrong
    mechanism sentence PRODUCT.md 4b exists to stop, so the field name says
    what it is and nothing downstream has to remember.

    `firewalls` is `public_net.firewalls`, "Firewalls applied to the public
    network interface of this Server". An empty tuple means the provider
    reported none attached, which is the finding recorded in PRODUCT.md 4b.
    """

    id: int
    name: str
    status: str
    ipv4: str | None
    ipv6_network: str | None
    firewalls: tuple[AttachedFirewall, ...] = ()


@dataclass(frozen=True)
class Inventory:
    servers: tuple[Server, ...] = ()
    firewalls: tuple[Firewall, ...] = ()

    def firewall_by_id(self, firewall_id: int) -> Firewall | None:
        for firewall in self.firewalls:
            if firewall.id == firewall_id:
                return firewall
        return None

    def firewalls_for_server(self, server_id: int) -> list[tuple[AttachedFirewall, Firewall | None]]:
        """The attachment, read from the server's own side.

        The pair is deliberate. The second half is None when the server names a
        firewall id that the firewalls fetch did not return, which is a real
        race: the two GETs are separate requests and somebody can create or
        delete a firewall between them. Reporting that as "no firewall" would
        be inventing a finding.
        """
        for server in self.servers:
            if server.id == server_id:
                return [(ref, self.firewall_by_id(ref.id)) for ref in server.firewalls]
        return []


@dataclass(frozen=True)
class Snapshot:
    """What the provider returned, before anything of ours touched it.

    The list bodies are kept exactly as they arrived, the same posture the host
    document takes (PRODUCT.md 4e): evidence, not verdicts. The response
    envelope around them is dropped, because `meta.pagination` describes our
    request rather than their state.
    """

    fetched_at: str
    servers: tuple[dict, ...] = ()
    firewalls: tuple[dict, ...] = ()


@dataclass
class RateLimit:
    """The three headers the spec's Rate Limiting section documents:
    `RateLimit-Limit` is "the total number of requests you can perform per
    hour", `RateLimit-Remaining` is what is left in the window, and
    `RateLimit-Reset` is "a UNIX timestamp of the point in time when your rate
    limit will have recovered". The default is 3,600 requests per hour per
    project, so this integration is nowhere near it, but a fetch that starts
    failing should be able to say whether that is why."""

    limit: int | None = None
    remaining: int | None = None
    reset_unix: int | None = None


# ------------------------------------------------------------------ the parsing

def _as_str(value) -> str | None:
    """None stays None. Anything else must already be a string: the spec types
    every field used here, and quietly stringifying a number would hide the
    fact that we are no longer talking to the API we read the docs for."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProviderError(ERROR_MALFORMED)
    return value


def _as_int(value) -> int:
    # bool is an int in Python and would slip through a bare isinstance check.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProviderError(ERROR_MALFORMED)
    return value


def _as_dict(value) -> dict:
    if not isinstance(value, dict):
        raise ProviderError(ERROR_MALFORMED)
    return value


def _as_list(value) -> list:
    if not isinstance(value, list):
        raise ProviderError(ERROR_MALFORMED)
    return value


def parse_address_set(values) -> AddressSet:
    """Split one `source_ips` or `destination_ips` list by address family.

    Order inside each family is the provider's order, and nothing is
    deduplicated. The rule PRODUCT.md 4b quotes lists `100.64.0.0/10` and
    `0.0.0.0/0` together, and which entries a rule carries alongside which is
    the whole finding.
    """
    if values is None:
        return AddressSet()
    v4: list[str] = []
    v6: list[str] = []
    unparsed: list[str] = []
    for entry in _as_list(values):
        if not isinstance(entry, str):
            # The spec types these as strings. A non-string means the shape
            # changed under us, and half-reading a firewall rule is worse than
            # saying we could not read it.
            raise ProviderError(ERROR_MALFORMED)
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            unparsed.append(entry)
            continue
        (v4 if network.version == 4 else v6).append(entry)
    return AddressSet(v4=tuple(v4), v6=tuple(v6), unparsed=tuple(unparsed))


def parse_rule(raw: dict) -> FirewallRule:
    raw = _as_dict(raw)
    return FirewallRule(
        direction=_as_str(raw.get("direction")) or "",
        protocol=_as_str(raw.get("protocol")) or "",
        port=_as_str(raw.get("port")),
        description=_as_str(raw.get("description")),
        source_ips=parse_address_set(raw.get("source_ips")),
        destination_ips=parse_address_set(raw.get("destination_ips")),
    )


def parse_target(raw: dict) -> FirewallTarget:
    raw = _as_dict(raw)
    server = raw.get("server")
    selector = raw.get("label_selector")
    resolved = []
    for applied in _as_list(raw.get("applied_to_resources") or []):
        applied_server = _as_dict(applied).get("server")
        if isinstance(applied_server, dict):
            resolved.append(_as_int(applied_server.get("id")))
    return FirewallTarget(
        type=_as_str(raw.get("type")) or "",
        server_id=_as_int(server.get("id")) if isinstance(server, dict) else None,
        label_selector=(_as_str(selector.get("selector"))
                        if isinstance(selector, dict) else None),
        resolved_server_ids=tuple(resolved),
    )


def parse_firewall(raw: dict) -> Firewall:
    raw = _as_dict(raw)
    return Firewall(
        id=_as_int(raw.get("id")),
        name=_as_str(raw.get("name")) or "",
        rules=tuple(parse_rule(rule) for rule in _as_list(raw.get("rules") or [])),
        applied_to=tuple(parse_target(target)
                         for target in _as_list(raw.get("applied_to") or [])),
    )


def parse_server(raw: dict) -> Server:
    raw = _as_dict(raw)
    public_net = raw.get("public_net")
    public_net = public_net if isinstance(public_net, dict) else {}
    ipv4 = public_net.get("ipv4")
    ipv6 = public_net.get("ipv6")
    attached = []
    for entry in _as_list(public_net.get("firewalls") or []):
        entry = _as_dict(entry)
        attached.append(AttachedFirewall(id=_as_int(entry.get("id")),
                                         status=_as_str(entry.get("status")) or ""))
    return Server(
        id=_as_int(raw.get("id")),
        name=_as_str(raw.get("name")) or "",
        status=_as_str(raw.get("status")) or "",
        # Each family read on its own. A missing object means the provider said
        # there is none, and neither answer is derived from the other.
        ipv4=_as_str(ipv4.get("ip")) if isinstance(ipv4, dict) else None,
        ipv6_network=_as_str(ipv6.get("ip")) if isinstance(ipv6, dict) else None,
        firewalls=tuple(attached),
    )


def _server_holds(server: Server, address) -> bool:
    """Whether one address is this server's: equal to its public IPv4, or
    inside its IPv6 network. Anything that does not parse, on either side, is
    no, and the two families never answer for each other."""
    try:
        ip = ipaddress.ip_address(address)
    except (ValueError, TypeError):
        return False
    try:
        if ip.version == 4:
            return (server.ipv4 is not None
                    and ipaddress.ip_address(server.ipv4) == ip)
        if server.ipv6_network is None:
            return False
        network = ipaddress.ip_network(server.ipv6_network, strict=False)
        return network.version == 6 and ip in network
    except (ValueError, TypeError):
        return False


def match_server(inventory: Inventory, hostname, addresses) -> Server | None:
    """Which of the provider's servers one host is, or None.

    **By proved address first, and by name only when no address names one.**
    `addresses` are the ones the host proved (`authz.live_addresses_for_host`),
    each observed on a completed connection and corroborated by the host's
    own document (docs/PRODUCT.md 5). The provider states the server's public
    IPv4 and its IPv6 network. A proved address that is the server's, or lies
    inside its network, names the server, whatever either side calls it.

    Until 2026-09-20 the name was the only rule, exact apart from case, in
    three places, so a Hetzner server not named like its whichports host was
    "server not found" and its firewall showed nowhere (docs/RECORD.md 4.190).
    The name stays as the fallback, because a host that has proved nothing
    yet still has one, and the snapshot is its own workspace's and nobody
    else's (record 4.178).

    **Two different servers named by one host's addresses is no match, and
    the name does not break the tie.** One machine cannot be two servers, so
    the data is wrong somewhere, and a firewall drawn on the wrong host is
    worse than none drawn.

    One project's case of `match_in_projects`, so the rule is written once.
    """
    found = match_in_projects((inventory,), hostname, addresses)
    return found[1] if found is not None else None


def match_in_projects(inventories, hostname, addresses) -> tuple[int, Server] | None:
    """Which project's server one host is, as (its place in `inventories`,
    the server), or None. `match_server`'s rule, across every token a
    workspace holds (since 2026-09-27, docs/RECORD.md 4.206).

    **A proved address in any project outranks a name in any project**, the
    same order as within one. Each project keeps its own inventory and nothing
    is merged, so a server's firewalls are always looked up in the project
    that listed it.

    **The same server read through two tokens is one server.** A project
    connected twice lists it twice, under the same id the provider gave it,
    and that is not the ambiguity the rule refuses. Two different ids holding
    one host's proved addresses is, and so is one name in two projects:
    neither the name nor the order of the tokens breaks that tie.
    """
    by_address = {}
    for place, inventory in enumerate(inventories):
        for server in inventory.servers:
            if any(_server_holds(server, address) for address in addresses or ()):
                by_address.setdefault(server.id, (place, server))
    if len(by_address) == 1:
        return next(iter(by_address.values()))
    if by_address:
        return None
    if not isinstance(hostname, str) or not hostname:
        return None
    by_name = {}
    for place, inventory in enumerate(inventories):
        # The first server of this name in one project, as `match_server`
        # has always taken it.
        named = next((s for s in inventory.servers
                      if s.name.lower() == hostname.lower()), None)
        if named is not None:
            by_name.setdefault(named.id, (place, named))
    if len(by_name) == 1:
        return next(iter(by_name.values()))
    return None


def parse_snapshot(snapshot: Snapshot) -> Inventory:
    return Inventory(
        servers=tuple(parse_server(raw) for raw in snapshot.servers),
        firewalls=tuple(parse_firewall(raw) for raw in snapshot.firewalls),
    )


# ------------------------------------------------------------------ the transport

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are never followed, for the reason the agent gives in
    PRODUCT.md 4f: following one would re-send the credential to wherever the
    response points. Returning None here leaves the response unhandled, so
    urllib raises the redirect as an HTTPError and `_request` turns it into a
    typed kind."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(context: ssl.SSLContext | None = None) -> urllib.request.OpenerDirector:
    """The one opener this module uses. `build_opener` drops its default
    redirect handler when it is handed a subclass of it, which is how
    `_NoRedirect` takes over.

    **And `ProxyHandler({})`, for the reason `app/authz.py` already gives.**
    `urllib.request.build_opener` installs a bare `ProxyHandler()` unless it is
    handed one, and a bare one reads `https_proxy` from the environment. This
    module's every request carries the API token in an `Authorization` header,
    so the hole opens without anybody touching this code: one variable in the
    sweep unit's environment and the token goes to whoever answers there.

    `docs/PRODUCT.md` section 5 already names this exact shape for the HTTP
    proof and says it "opens with nobody touching the code". `authz` was given
    the guard and this was not, which is `docs/RECORD.md` 4.83.

    The token is read only and the operator's to revoke, so what is at stake is
    disclosure rather than control. SI-5 is the reason that still matters: the
    token is theirs, and a credential of theirs is not ours to leak.
    """
    https = urllib.request.HTTPSHandler(context=context or ssl.create_default_context())
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), https, _NoRedirect())


def _header_int(headers, name: str) -> int | None:
    try:
        return int(headers.get(name))
    except (TypeError, ValueError):
        return None


class ReadOnlyClient:
    """GET against the Hetzner Cloud API, and nothing else.

    The opener is injectable so the tests can drive this without a network.
    Nothing else about the transport is configurable.
    """

    def __init__(self, config: Config | None = None, opener=None,
                 timeout: int = REQUEST_TIMEOUT_SECONDS):
        self.config = config or Config()
        self._opener = opener or build_opener()
        self._timeout = timeout
        self.rate_limit = RateLimit()

    # -- the only place in this module that speaks to the network --

    def _request(self, path: str, params: dict) -> dict:
        """One GET. There is no method parameter and no body parameter, on
        purpose: SI-3 and SI-5 hold here by construction rather than by
        promise, and tests/test_hetzner.py reads this function's source to
        check that nobody added one later."""
        if not self.config.configured:
            raise ProviderError(ERROR_NOT_CONFIGURED)

        url = API_BASE + path + "?" + urllib.parse.urlencode(params)
        if not url.startswith("https://"):
            # API_BASE is a constant so this cannot fire today. It is here so
            # that changing the constant to plain http fails loudly instead of
            # putting the token on the wire in clear.
            raise ProviderError(ERROR_MALFORMED)

        request = urllib.request.Request(
            url,
            headers={
                # "Include your secret API token in every request you send to
                # the API with the `Authorization` HTTP header", example
                # "Authorization: Bearer <token>". The spec's security scheme
                # is type http, scheme bearer, which says the same.
                "Authorization": f"Bearer {self.config.token}",
                "Accept": "application/json",
                # Named, so an operator reading their provider's audit log can
                # tell who called. `app/authz.py` and `app/webhook.py` both do
                # this and this did not.
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )

        try:
            response = self._opener.open(request, timeout=self._timeout)
        except urllib.error.HTTPError as exc:
            self._read_rate_limit(exc.headers)
            raise self._http_error(exc) from None
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
            # The class of failure, never the text. Same reason notify.send
            # reports a type name rather than what the relay said. All four are
            # OSError subclasses and the tuple is spelled out so a reader can
            # see which failures are meant.
            raise ProviderError(ERROR_NETWORK) from None

        try:
            with response:
                self._read_rate_limit(response.headers)
                # The connection can also die part way through the body, which
                # is the same class of failure as never connecting.
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError):
            raise ProviderError(ERROR_NETWORK) from None
        if len(body) > MAX_RESPONSE_BYTES:
            raise ProviderError(ERROR_MALFORMED)
        try:
            payload = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise ProviderError(ERROR_MALFORMED) from None
        return _as_dict(payload)

    def _read_rate_limit(self, headers) -> None:
        if headers is None:
            return
        self.rate_limit = RateLimit(
            limit=_header_int(headers, "RateLimit-Limit"),
            remaining=_header_int(headers, "RateLimit-Remaining"),
            reset_unix=_header_int(headers, "RateLimit-Reset"),
        )

    def _http_error(self, exc: urllib.error.HTTPError) -> ProviderError:
        """Status code to typed kind. The provider's `message` is free text and
        is not read at all, which is why this only looks at the number.

        Statuses from the spec's error table: 401 unauthorized ("Request was
        made with an invalid or unknown token"), 403 forbidden, 429
        rate_limit_exceeded ("Error when sending too many requests").
        """
        code = exc.code
        if code in (301, 302, 303, 307, 308):
            return ProviderError(ERROR_REDIRECTED, status=code)
        if code == 401:
            return ProviderError(ERROR_UNAUTHORIZED, status=code)
        if code == 403:
            return ProviderError(ERROR_FORBIDDEN, status=code)
        if code == 429:
            return ProviderError(ERROR_RATE_LIMITED, status=code,
                                 rate_limit_reset_unix=self.rate_limit.reset_unix)
        return ProviderError(ERROR_HTTP, status=code)

    # -- paging --

    def _fetch_all(self, path: str, key: str) -> list[dict]:
        """Every page of one list endpoint, concatenated in the order returned.

        Paging is driven by `meta.pagination.next_page`, which the spec says
        "Can be null if the current page is the last one". A next_page that
        does not move forward stops the loop, because a broken or hostile
        response must not be able to spin this forever.
        """
        items: list[dict] = []
        page = FIRST_PAGE
        for _ in range(MAX_PAGES):
            payload = self._request(path, {"page": page, "per_page": PER_PAGE})
            if key not in payload:
                # The documented envelope is {"<key>": [...], "meta": {...}}.
                # A body without it is not a response we know how to read.
                raise ProviderError(ERROR_MALFORMED)
            for item in _as_list(payload[key]):
                items.append(_as_dict(item))
            meta = payload.get("meta")
            pagination = meta.get("pagination") if isinstance(meta, dict) else None
            next_page = pagination.get("next_page") if isinstance(pagination, dict) else None
            if not isinstance(next_page, int) or isinstance(next_page, bool):
                return items
            if next_page <= page:
                return items
            page = next_page
        # Ran out of pages with more to come. Returning what we have would be a
        # silent truncation, and a partial inventory presented as a whole one is
        # exactly the failure mode PRODUCT.md 4b is about.
        raise ProviderError(ERROR_TOO_MANY_PAGES)

    # -- what callers use --

    def fetch_servers(self) -> list[dict]:
        """GET /servers. Spec: "Returns all Servers", response
        {"servers": [...], "meta": {...}}."""
        return self._fetch_all(PATH_SERVERS, "servers")

    def fetch_firewalls(self) -> list[dict]:
        """GET /firewalls. Spec: "Returns all Firewalls", response
        {"firewalls": [...], "meta": {...}}."""
        return self._fetch_all(PATH_FIREWALLS, "firewalls")

    def fetch_snapshot(self) -> Snapshot:
        """Both halves or nothing.

        If the servers fetch works and the firewalls fetch does not, there is
        no honest snapshot to keep: an empty firewall list would read as "no
        cloud firewalls exist", which is a finding nobody measured. The error
        propagates and nothing is stored.
        """
        servers = self.fetch_servers()
        firewalls = self.fetch_firewalls()
        return Snapshot(
            fetched_at=datetime.now(timezone.utc).isoformat(),
            servers=tuple(servers),
            firewalls=tuple(firewalls),
        )


# --------------------------------------------------------------------- storage

# The three tables' columns, named once, because `init` creates each table
# twice: here for a fresh database, and again inside a rebuild for an old
# one. Two copies of a column list are how a rebuild silently drops a column.

# **Several tokens per workspace and provider, since 2026-09-27.** Hetzner
# makes a token from inside a project ("please open your project and do the
# following", docs.hetzner.com/cloud/api/getting-started/generating-api-token/,
# read 2026-09-27), and the first outside workspace held one that listed six
# of its servers and not the seventh (docs/RECORD.md 4.203). Until then a
# second token replaced the first, so each project's servers took turns having
# a provider view. Each token is its own row and everything read with it
# carries its id.
#
# AUTOINCREMENT so an id is never handed out twice. Without it SQLite reuses
# the highest id after that row is deleted, and a page still open from before
# a Disconnect would then act on whichever token was connected next.
TOKENS_COLUMNS = """(
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_id INTEGER NOT NULL,
    provider     TEXT NOT NULL,
    token        TEXT NOT NULL,
    token_hint   TEXT NOT NULL,
    set_at       TEXT NOT NULL
)"""

FETCHES_COLUMNS = """(
    workspace_id INTEGER NOT NULL DEFAULT 1,
    provider     TEXT NOT NULL,
    token_id     INTEGER NOT NULL,
    tried_at     TEXT NOT NULL,
    error_kind   TEXT,
    error_status INTEGER,
    PRIMARY KEY (workspace_id, provider, token_id)
)"""

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS provider_snapshots (
    id             INTEGER PRIMARY KEY,
    provider       TEXT NOT NULL,
    fetched_at     TEXT NOT NULL,
    servers_json   TEXT NOT NULL,
    firewalls_json TEXT NOT NULL,
    workspace_id   INTEGER NOT NULL DEFAULT 1,
    token_id       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_provider_snapshots_fetched
    ON provider_snapshots(provider, fetched_at DESC);

-- What the last read with one token did. A snapshot is written only when both
-- endpoints answered, so a token that stopped working leaves the last good
-- snapshot in place and nothing said so on any screen. This row is that fact:
-- one per token, the time of the last attempt, and the typed kind and the
-- HTTP status when it failed. Never the provider's own text (SI-8).
CREATE TABLE IF NOT EXISTS provider_fetches {FETCHES_COLUMNS};

-- The credentials, one row per token. `token` is read by `token_for` and by
-- nothing that renders a page; `token_hint` is what a screen shows, written
-- here when the token is set so the renderer never has to look at the token
-- to describe it.
CREATE TABLE IF NOT EXISTS provider_tokens {TOKENS_COLUMNS};
"""

# Indexes on columns an older table only gains inside `init`, so they are made
# after it rather than in SCHEMA, where they would fail on that older table.
LATE_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_provider_snapshots_token
    ON provider_snapshots(workspace_id, provider, token_id, fetched_at DESC);
CREATE INDEX IF NOT EXISTS idx_provider_tokens_workspace
    ON provider_tokens(workspace_id, provider);
"""

# The slot for what was read or stored while no token was held: a database
# from before the store existed (2026-09-14), or a caller that names no token
# in a workspace that holds none. Real ids start at 1, so it never collides.
NO_TOKEN = 0


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init and alerts.init follow.

    Three older shapes are brought forward, each once:

      - snapshots from before 2026-09-14 have no workspace, and gain the
        column with every row in workspace 1, the backfill hosts and
        channels got.
      - tokens from before 2026-09-27 are keyed by workspace and provider,
        one each. SQLite cannot change a key in place, so the table is
        rebuilt and every row keeps its token and gets an id.
      - snapshots and fetch rows from before 2026-09-27 carry no token. There
        was at most one token per workspace and provider then, so each one is
        that token's, and one read while none was held goes to NO_TOKEN.

    Each rebuild runs under a write lock and checks again once it holds it,
    because the ingest and the sweep both call this, and after a deploy they
    can start at the same moment.
    """
    con.executescript(SCHEMA)
    if not _has_column(con, "provider_snapshots", "workspace_id"):
        con.execute("ALTER TABLE provider_snapshots ADD COLUMN"
                    " workspace_id INTEGER NOT NULL DEFAULT 1")
        con.commit()
    _migrate_once(con, lambda: _has_column(con, "provider_tokens", "id"),
                  _give_tokens_ids)
    _migrate_once(con, lambda: _has_column(con, "provider_snapshots", "token_id"),
                  _give_snapshots_tokens)
    _migrate_once(con, lambda: _has_column(con, "provider_fetches", "token_id"),
                  _give_fetches_tokens)
    con.executescript(LATE_INDEXES)
    con.commit()


def _migrate_once(con: sqlite3.Connection, done, steps) -> None:
    """Run `steps` in one write transaction, unless `done()` says it is done.

    BEGIN IMMEDIATE takes the write lock before the check, so of two processes
    starting together the second waits on the busy timeout and then finds the
    work done rather than doing it twice. A failure rolls the whole step back,
    so a table is never left half rebuilt.
    """
    if done():
        return
    con.commit()
    con.execute("BEGIN IMMEDIATE")
    try:
        if not done():
            steps(con)
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def _give_tokens_ids(con: sqlite3.Connection) -> None:
    con.execute("ALTER TABLE provider_tokens RENAME TO provider_tokens_old")
    con.execute(f"CREATE TABLE provider_tokens {TOKENS_COLUMNS}")
    con.execute(
        "INSERT INTO provider_tokens (workspace_id, provider, token, token_hint, set_at)"
        " SELECT workspace_id, provider, token, token_hint, set_at"
        " FROM provider_tokens_old ORDER BY workspace_id, provider")
    con.execute("DROP TABLE provider_tokens_old")


def _give_snapshots_tokens(con: sqlite3.Connection) -> None:
    con.execute("ALTER TABLE provider_snapshots ADD COLUMN"
                f" token_id INTEGER NOT NULL DEFAULT {NO_TOKEN}")
    con.execute(
        "UPDATE provider_snapshots SET token_id = (SELECT t.id FROM provider_tokens t"
        " WHERE t.workspace_id = provider_snapshots.workspace_id"
        " AND t.provider = provider_snapshots.provider)"
        " WHERE EXISTS (SELECT 1 FROM provider_tokens t"
        " WHERE t.workspace_id = provider_snapshots.workspace_id"
        " AND t.provider = provider_snapshots.provider)")


def _give_fetches_tokens(con: sqlite3.Connection) -> None:
    # The oldest shape has no workspace either, and its rows were workspace 1's.
    workspace = "o.workspace_id" if _has_column(con, "provider_fetches",
                                                "workspace_id") else "1"
    con.execute("ALTER TABLE provider_fetches RENAME TO provider_fetches_old")
    con.execute(f"CREATE TABLE provider_fetches {FETCHES_COLUMNS}")
    con.execute(
        "INSERT INTO provider_fetches (workspace_id, provider, token_id, tried_at,"
        " error_kind, error_status)"
        f" SELECT {workspace}, o.provider,"
        f" COALESCE((SELECT t.id FROM provider_tokens t WHERE t.workspace_id = {workspace}"
        f" AND t.provider = o.provider), {NO_TOKEN}),"
        " o.tried_at, o.error_kind, o.error_status FROM provider_fetches_old o")
    con.execute("DROP TABLE provider_fetches_old")


def _has_column(con: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in con.execute(f"PRAGMA table_info({table})"))


# ---------------------------------------------------------------- the tokens


def _first_token_id(con: sqlite3.Connection, workspace_id: int,
                    provider: str) -> int | None:
    if not _table_exists(con, "provider_tokens"):
        return None
    row = con.execute("SELECT id FROM provider_tokens WHERE workspace_id = ?"
                      " AND provider = ? ORDER BY id LIMIT 1",
                      (workspace_id, provider)).fetchone()
    return row[0] if row is not None else None


def _resolve(con: sqlite3.Connection, workspace_id: int, provider: str,
             token_id: int | None) -> int:
    """The token a call is about. A caller that names none means the
    workspace's first token, which is the one token it could hold until
    2026-09-27, and NO_TOKEN when it holds none."""
    if token_id is not None:
        return token_id
    first = _first_token_id(con, workspace_id, provider)
    return first if first is not None else NO_TOKEN


def holds_token(con: sqlite3.Connection, workspace_id: int, token_id: int,
                provider: str = PROVIDER) -> bool:
    """Whether this workspace holds this token. Another workspace's token is
    the same answer as no token at all, so a caller cannot tell them apart."""
    return con.execute("SELECT 1 FROM provider_tokens WHERE id = ? AND workspace_id = ?"
                       " AND provider = ?", (token_id, workspace_id, provider)
                       ).fetchone() is not None


def add_token(con: sqlite3.Connection, token: str, workspace_id: int,
              now: datetime | None = None, provider: str = PROVIDER) -> tuple[int, str]:
    """Hold one more token for this workspace. Returns its id and its hint,
    which is all a caller may show. A token the workspace already holds is not
    added twice: its own id comes back, so Connect with the same paste reads
    with it again. Raises TokenError on a token that cannot be stored, in
    words that never echo it."""
    token = check_token(token)
    held = con.execute("SELECT id, token_hint FROM provider_tokens WHERE workspace_id = ?"
                       " AND provider = ? AND token = ?",
                       (workspace_id, provider, token)).fetchone()
    if held is not None:
        return held[0], held[1]
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    hint = token_hint(token)
    cur = con.execute(
        "INSERT INTO provider_tokens (workspace_id, provider, token, token_hint, set_at)"
        " VALUES (?, ?, ?, ?, ?)", (workspace_id, provider, token, hint, stamp))
    con.commit()
    return cur.lastrowid, hint


def replace_token(con: sqlite3.Connection, token_id: int, token: str, workspace_id: int,
                  now: datetime | None = None, provider: str = PROVIDER) -> str | None:
    """Put a new value in one held token's place. Returns the hint, or None
    when this workspace holds no such token.

    Everything read with the old value goes with it. The new one may read
    another project, and a snapshot the old one took must never be drawn as
    this token's. The caller reads again at once. A value another of this
    workspace's tokens already holds is refused, because two rows reading one
    project would show its servers twice."""
    token = check_token(token)
    if not holds_token(con, workspace_id, token_id, provider):
        return None
    clash = con.execute("SELECT 1 FROM provider_tokens WHERE workspace_id = ?"
                        " AND provider = ? AND token = ? AND id != ?",
                        (workspace_id, provider, token, token_id)).fetchone()
    if clash is not None:
        raise TokenError("That token is already connected.")
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    hint = token_hint(token)
    con.execute("UPDATE provider_tokens SET token = ?, token_hint = ?, set_at = ?"
                " WHERE id = ? AND workspace_id = ? AND provider = ?",
                (token, hint, stamp, token_id, workspace_id, provider))
    _forget_reads(con, workspace_id, provider, token_id)
    con.commit()
    return hint


def token_for(con: sqlite3.Connection, workspace_id: int, token_id: int | None = None,
              provider: str = PROVIDER) -> str:
    """The stored token, or "". **The one reader of the value.** Its callers
    are the sweep and the admin routes that read the provider; a renderer
    never calls it, and `site/app/test_integrations_live.py` reads the
    renderer's source to hold that. Naming no token means the first."""
    if not _table_exists(con, "provider_tokens"):
        return ""
    token_id = _resolve(con, workspace_id, provider, token_id)
    row = con.execute("SELECT token FROM provider_tokens WHERE id = ? AND workspace_id = ?"
                      " AND provider = ?", (token_id, workspace_id, provider)).fetchone()
    return row[0] if row is not None else ""


def tokens(con: sqlite3.Connection, workspace_id: int,
           provider: str = PROVIDER) -> list[dict]:
    """What a screen may know about each token this workspace holds, in the
    order they were connected: its id, its hint and when it was set. No token
    on any of them."""
    if not _table_exists(con, "provider_tokens"):
        return []
    return [{"id": row[0], "hint": row[1], "set_at": row[2]} for row in con.execute(
        "SELECT id, token_hint, set_at FROM provider_tokens WHERE workspace_id = ?"
        " AND provider = ? ORDER BY id", (workspace_id, provider))]


def token_status(con: sqlite3.Connection, workspace_id: int,
                 provider: str = PROVIDER) -> dict | None:
    """The first token's hint and when it was set, or None when the workspace
    holds none. The one-row Integrations screen read this until it listed
    every token (2026-09-29, record 4.206), and nothing that renders a page
    reads it now: `tokens` is what the screen reads."""
    held = tokens(con, workspace_id, provider)
    if not held:
        return None
    return {"hint": held[0]["hint"], "set_at": held[0]["set_at"]}


def tokens_to_read(con: sqlite3.Connection, provider: str = PROVIDER) -> list[tuple[int, int]]:
    """Every held token as (workspace, token id), in that order, for the sweep."""
    if not _table_exists(con, "provider_tokens"):
        return []
    return [(row[0], row[1]) for row in con.execute(
        "SELECT workspace_id, id FROM provider_tokens WHERE provider = ?"
        " ORDER BY workspace_id, id", (provider,))]


def _forget_reads(con: sqlite3.Connection, workspace_id: int, provider: str,
                  token_id: int) -> None:
    con.execute("DELETE FROM provider_snapshots WHERE workspace_id = ? AND provider = ?"
                " AND token_id = ?", (workspace_id, provider, token_id))
    con.execute("DELETE FROM provider_fetches WHERE workspace_id = ? AND provider = ?"
                " AND token_id = ?", (workspace_id, provider, token_id))


def disconnect(con: sqlite3.Connection, workspace_id: int, token_id: int | None = None,
               provider: str = PROVIDER) -> bool:
    """Drop one token and everything read with it: its snapshots and its
    fetch row. Naming no token means the first. The workspace's other tokens
    and every other workspace are untouched. Once the workspace holds none,
    whatever sits under NO_TOKEN goes too, so nothing read stays on a screen
    with nothing connected. Returns whether there was a token to drop."""
    token_id = _resolve(con, workspace_id, provider, token_id)
    had = con.execute("DELETE FROM provider_tokens WHERE id = ? AND workspace_id = ?"
                      " AND provider = ?", (token_id, workspace_id, provider)).rowcount
    if had:
        _forget_reads(con, workspace_id, provider, token_id)
        if _first_token_id(con, workspace_id, provider) is None:
            _forget_reads(con, workspace_id, provider, NO_TOKEN)
    con.commit()
    return had == 1


# ------------------------------------------------------- what the reads left


def store_snapshot(con: sqlite3.Connection, snapshot: Snapshot,
                   provider: str = PROVIDER,
                   workspace_id: int = DEFAULT_WORKSPACE_ID,
                   token_id: int | None = None) -> int:
    """Write one snapshot, read with one token. Only a complete fetch ever
    gets here, so a row in this table always means both endpoints answered.

    Nothing derived is stored. The lists go in as JSON exactly as they came
    back, so a later reader can see what the provider said rather than what we
    made of it, and a change to the parsing above cannot rewrite history."""
    token_id = _resolve(con, workspace_id, provider, token_id)
    # One transaction for the insert and the pruning: either the new snapshot
    # is stored and the old ones beyond a day are gone, or nothing changed.
    try:
        cur = con.execute(
            "INSERT INTO provider_snapshots (provider, fetched_at, servers_json,"
            " firewalls_json, workspace_id, token_id) VALUES (?, ?, ?, ?, ?, ?)",
            (provider, snapshot.fetched_at,
             json.dumps(list(snapshot.servers)), json.dumps(list(snapshot.firewalls)),
             workspace_id, token_id),
        )
        _prune_snapshots(con, snapshot, provider, workspace_id, token_id)
        con.commit()
    except sqlite3.Error:
        con.rollback()
        raise
    return cur.lastrowid


def _stamp(value) -> datetime | None:
    """A snapshot's `fetched_at` as a time, or None when it will not read or
    carries no timezone. The same two refusals as `snapshot_age_seconds`."""
    try:
        stamped = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return stamped if stamped.tzinfo is not None else None


def _prune_snapshots(con: sqlite3.Connection, stored: Snapshot, provider: str,
                     workspace_id: int, token_id: int) -> None:
    """Delete one token's snapshots that are more than a day older than the
    one just stored. The caller owns the transaction.

    Narrow on purpose:

      - only rows of this workspace, this provider and this token. Another
        token's rows and another workspace's are never looked at
      - never the row just stored: nothing is a day older than itself
      - only a row whose own stamp reads and is provably older. A stamp that
        will not read is left where it is, the same refusal to guess that
        `snapshot_age_seconds` makes
      - and when the new snapshot's own stamp will not read, nothing is
        deleted at all, since there is nothing to measure a day from
    """
    newest = _stamp(stored.fetched_at)
    if newest is None:
        return
    cutoff = newest - timedelta(seconds=SNAPSHOT_KEEP_SECONDS)
    rows = con.execute(
        "SELECT id, fetched_at FROM provider_snapshots WHERE workspace_id = ?"
        " AND provider = ? AND token_id = ?",
        (workspace_id, provider, token_id)).fetchall()
    # Read by position and not by name: a caller's connection may hand back
    # plain tuples, and `store_snapshot` has always worked on one that does.
    for row_id, fetched_at in rows:
        stamped = _stamp(fetched_at)
        if stamped is not None and stamped < cutoff:
            con.execute("DELETE FROM provider_snapshots WHERE id = ?", (row_id,))


def record_fetch(con: sqlite3.Connection, now: datetime,
                 error: "ProviderError | None" = None, provider: str = PROVIDER,
                 workspace_id: int = DEFAULT_WORKSPACE_ID,
                 token_id: int | None = None) -> None:
    """Write what the read just done with one token did: a success clears the
    error, a failure records its typed kind and status. One row per token."""
    token_id = _resolve(con, workspace_id, provider, token_id)
    con.execute(
        "INSERT INTO provider_fetches (workspace_id, provider, token_id, tried_at,"
        " error_kind, error_status) VALUES (?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(workspace_id, provider, token_id)"
        " DO UPDATE SET tried_at = excluded.tried_at, error_kind = excluded.error_kind,"
        " error_status = excluded.error_status",
        (workspace_id, provider, token_id, now.isoformat(),
         error.kind if error is not None else None,
         error.status if error is not None else None))
    con.commit()


def latest_fetch(con: sqlite3.Connection, provider: str = PROVIDER,
                 workspace_id: int = DEFAULT_WORKSPACE_ID,
                 token_id: int | None = None) -> dict | None:
    """The last read's outcome for one token as a plain dict, or None when
    nothing was ever tried or the table is from before this existed. Naming no
    token means the first."""
    if not _table_exists(con, "provider_fetches"):
        return None
    token_id = _resolve(con, workspace_id, provider, token_id)
    row = con.execute("SELECT * FROM provider_fetches WHERE provider = ?"
                      " AND workspace_id = ? AND token_id = ?",
                      (provider, workspace_id, token_id)).fetchone()
    if row is None:
        return None
    return {"tried_at": row["tried_at"], "error_kind": row["error_kind"],
            "error_status": row["error_status"]}


# How old a stored snapshot may be before the sweep reads another.
#
# A minute, which means every sweep reads: the sweep runs every five minutes
# (`ops/whichports-sweep.timer`), and the minute is only there so that a sweep
# run by hand right after a timed one does not read twice.
#
# Not five minutes, though that is the number a reader expects here. The
# client stamps a snapshot when the provider's answer arrives, a few seconds
# after the sweep began, so the next sweep finds it a little less than five
# minutes old. A gate of five minutes would call that fresh and skip every
# second sweep.
#
# Until 2026-10-03 this was an hour, on the reasoning that a cloud firewall is
# an inventory and not a measurement (`docs/RECORD.md` 4.90). Then a firewall
# deleted at the provider was still quoted seven minutes later as the reason a
# port answers, from a snapshot twenty-five minutes old (4.330). What a screen
# quotes as a cause has to be current, so the hour went (4.340).
#
# The cost, counted against Hetzner's own specification: "The default limit
# is 3600 requests per hour and per Project." One read is one request for the
# servers and one for the firewalls while a project has at most `PER_PAGE` of
# each, so twelve reads an hour are 24 requests. A read can never take more
# than `MAX_PAGES` requests for each list, so 960 an hour at the very most.
# The sweep still prints what the provider says is left.
SNAPSHOT_MAX_AGE_SECONDS = 60

# How long a token's snapshots are kept. Only the newest is ever read, by the
# engine and by every screen, and until 2026-10-03 nothing deleted the rest.
# At a read every five minutes that is 288 rows a day for each token, each
# holding the whole inventory, so a day's worth is kept and the rest goes when
# a new one is stored.
SNAPSHOT_KEEP_SECONDS = 24 * 60 * 60


def snapshot_age_seconds(snapshot: "Snapshot", now: datetime) -> float | None:
    """How old a snapshot is, or None when its stamp will not read.

    None is its own answer and never silently becomes old or fresh. A stamp we
    cannot read is a snapshot we cannot age, and the caller refetches rather
    than guessing, because refetching costs one GET and guessing wrong costs a
    wrong answer on a screen.
    """
    try:
        stamped = datetime.fromisoformat(snapshot.fetched_at)
    except (TypeError, ValueError):
        return None
    if stamped.tzinfo is None:
        return None
    return (now - stamped).total_seconds()


def needs_refresh(con: sqlite3.Connection, now: datetime,
                  max_age: float = SNAPSHOT_MAX_AGE_SECONDS,
                  workspace_id: int = DEFAULT_WORKSPACE_ID,
                  token_id: int | None = None) -> bool:
    """Whether the sweep should fetch a new snapshot with this token on this
    tick.

    True when there is none, when the newest one cannot be aged, and when it is
    older than `max_age`. This asks nothing about whether a token is set: that
    is the caller's question and the answer differs, because no token is a
    provider nobody connected and a stale snapshot is a provider we should ask
    again.
    """
    if not _table_exists(con, "provider_snapshots"):
        return True
    snapshot = latest_snapshot(con, workspace_id=workspace_id, token_id=token_id)
    if snapshot is None:
        return True
    age = snapshot_age_seconds(snapshot, now)
    return age is None or age >= max_age


def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    return con.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,)).fetchone() is not None


def _snapshot_from(row) -> Snapshot:
    return Snapshot(
        fetched_at=row["fetched_at"],
        servers=tuple(json.loads(row["servers_json"])),
        firewalls=tuple(json.loads(row["firewalls_json"])),
    )


def latest_snapshot(con: sqlite3.Connection, provider: str = PROVIDER,
                    workspace_id: int = DEFAULT_WORKSPACE_ID,
                    token_id: int | None = None) -> Snapshot | None:
    """One token's newest snapshot, or None. Naming no token means the first,
    and a workspace holding none reads what sits under NO_TOKEN. A database
    from before the workspace column reads as workspace 1's, which is where
    its rows were backfilled, and one from before the token column as the
    workspace's own."""
    if not _has_column(con, "provider_snapshots", "workspace_id"):
        if workspace_id != DEFAULT_WORKSPACE_ID:
            return None
        row = con.execute(
            "SELECT * FROM provider_snapshots WHERE provider = ?"
            " ORDER BY fetched_at DESC, id DESC LIMIT 1", (provider,)).fetchone()
    elif not _has_column(con, "provider_snapshots", "token_id"):
        row = con.execute(
            "SELECT * FROM provider_snapshots WHERE provider = ? AND workspace_id = ?"
            " ORDER BY fetched_at DESC, id DESC LIMIT 1", (provider, workspace_id)).fetchone()
    else:
        token_id = _resolve(con, workspace_id, provider, token_id)
        row = con.execute(
            "SELECT * FROM provider_snapshots WHERE provider = ? AND workspace_id = ?"
            " AND token_id = ? ORDER BY fetched_at DESC, id DESC LIMIT 1",
            (provider, workspace_id, token_id)).fetchone()
    if row is None:
        return None
    return _snapshot_from(row)


def latest_snapshots(con: sqlite3.Connection, workspace_id: int,
                     provider: str = PROVIDER) -> list[tuple[int, Snapshot | None]]:
    """Each held token's newest snapshot, as (token id, snapshot or None), in
    the order the tokens were connected. A workspace holding no token gets
    what sits under NO_TOKEN, if anything does, so a database from before the
    store still shows what it read."""
    held = [token["id"] for token in tokens(con, workspace_id, provider)]
    if not held:
        snapshot = latest_snapshot(con, provider, workspace_id, NO_TOKEN)
        return [(NO_TOKEN, snapshot)] if snapshot is not None else []
    return [(token_id, latest_snapshot(con, provider, workspace_id, token_id))
            for token_id in held]
