"""The join engine: three views of one port, and which layer decided.

`docs/PRODUCT.md` section 1 is the product in one sentence and this module is
the place it becomes code. For every port, on every address family, it puts
three views next to each other:

  - **what the host thinks**, from the agent document (`app/ingest.py` stores
    it, `docs/PRODUCT.md` 4e is its design)
  - **what the internet can reach**, from the prober (`app/prober.py`, and the
    tables it owns)
  - **what the provider says**, from the cloud firewall API (`app/hetzner.py`)

and where they disagree it names the layer and quotes the rule it is talking
about. The renderer turns a finding into a sentence. `describe()` at the bottom
is the plain-text form, and it exists so the vocabulary can be tested.

Pure functions over data. The only I/O is reading the SQLite file, nothing here
opens a socket or writes a row, so the whole engine can be pointed at a
read-only copy of production and at a hostile document alike.

## The rule that outranks everything else here

**The outside view is never inferred from the inside view.** A host saying it
is listening is not a measurement of what the internet can reach, and a
firewall rule that names a port is not one either. With no probe result the
outside view is `not tested`, in those words, and four of the five states
cannot be reached at all. `docs/PRODUCT.md` 4b is the retraction this project
already had to publish for making exactly that inference, and `docs/RECORD.md`
4.48 is the same mistake found inside the prober, where a mutation replaced
`not_tested` with `no_response` on a path nothing had measured and all 112
tests stayed green.

There is one vocabulary for the outside view and it is the prober's own, so
`STATE_NOT_TESTED` here is `prober.STATE_NOT_TESTED` and not a second spelling.
The word on screen is `not tested`, which is `OutsideView.word`.

**A probe result is a TCP answer and only a TCP answer.** `probe_results` has
no protocol column and `app/prober.py` opens `SOCK_STREAM` sockets, so a row
in that table says nothing whatever about the UDP port with the same number.
A UDP port is therefore always `not tested` today, and `docs/PRODUCT.md`
section 5 already says UDP probing needs a valid payload before it can say
anything.

## The five states, and where intent comes from

`docs/DESIGN.md` section 3 owns the words and how they are shown. This owns
what they mean:

  - `conflict`     the outside view connected, and you declared this closed
  - `unreviewed`   the outside view connected, and nobody has declared anything
  - `intended`     the outside view connected, and you declared this open
  - `stale rule`   a rule permits this port and nothing is behind it
  - `unexplained`  the outside view connected and no part of the host owns it

Four of the five need a completed connect from outside. **`stale rule` is the
one that does not**, because both halves of it are things a view states rather
than concludes: a rule that permits the port, and no listening socket and no
container publication behind it. That is why this engine produces findings
today, before the prober runs anywhere.

**Intent comes from `app/intent.py`.** `host_findings` still takes an `intent`
argument and it still means exactly what it meant: a mapping or a callable the
caller supplies. Left alone it now reads that host's declarations from the
`port_intents` table instead of being empty, which is what makes `conflict` and
`intended` reachable outside a test. Passing an empty mapping still means no
declarations, so a caller asking a what-if question gets its own answer. A port
with no declaration is `unreviewed`, unchanged, and that is still the honest
default.

**An acknowledgement is not an intent and does not touch the state.** It says a
finding has been read and is not being acted on, so it is stored against the
state it was given for and `Finding.acknowledged` carries it only while that
state still holds. Nothing in `_decide` sees it. `app/intent.py` argues why the
two are separate tables.

**There is no sixth state, and there is no state for "we do not know".** A
finding whose evidence supports none of the five carries `state = None`. That
is the absence of a claim rather than a new word, and today it is what almost
every port on the fleet gets, because two of the three views are not running.
Forcing `unreviewed` onto those ports would be claiming a measurement nobody
took, which is the one thing this module exists to prevent.

## What this engine may not conclude

  - **That a rule getting through means the packet does.** `docs/PRODUCT.md`
    4g is the packet path's version of the same restraint, and `docs/RECORD.md`
    4.36 is why: a rate limit makes the same port reachable and unreachable at
    once depending on who is asking, and no ruleset can see that. So an
    `accept` rule is quoted, and a `stale rule` says the rule has nothing
    behind it. Neither says anything gets through.
  - **That the absence of a provider rule blocks anything.** The Hetzner spec
    calls `source_ips` the "List of permitted IPv4/IPv6 addresses for incoming
    traffic", so an inbound rule is a permit in the provider's own words, and
    that is what is quoted. Whether the absence of a rule denies is a
    default-deny claim, no source has been read for it, and the accuracy rule
    does not accept "this is well known".
  - **Anything about the other address family.** A v4 rule, a v4 socket and a
    v4 probe result each answer for v4 only.

## A rate limit is named as one, and it is never a cause

`docs/RECORD.md` 4.36 is the measurement this rests on. The production box
dropped tcp/22 for a burst of connections while 443 stayed up, and it cleared
after 75 quiet seconds. That is ufw's `limit`. The rule text says the port is
allowed and says nothing about the window just used up, and the drop happens to
whoever is currently over the threshold rather than to everyone, so the same
port is reachable and unreachable at the same moment depending on who is asking.

Two halves, and only the first of them is built here.

**A rule that decides on connection history is named as one.**
`_limit_module` recognises the three modules a host document can carry one in,
`InsideView.rate_limit_rules` holds the ones that name this port, and
`describe()` says which module it is rather than summarising it. The module is
named because what a module does is in its own manual page and what its
parameters are is not in the document at all: the agent stores an x_tables
match by name only (`docs/PRODUCT.md` 4g), so ufw's own `--seconds 30
--hitcount 6` is not there to read.

**It is never the cause and it never explains a silence.** `_decide` does not
see these rules, so no state moves because of one and no layer is named from
one. The agent cannot see the window and the prober cannot know whether it hit
it, so attributing a measured silence to a rate limit would be stating a
finding nobody made. Whether the product grows a conditional-reachability
concept is a decision for the owner and it is not taken here.

**The permit beside a rate limit is an answer, and the limit is still blamed
for nothing** (`docs/PRODUCT.md` 8d, `docs/RECORD.md` 4.209). ufw's `limit`
permits through a jump to a chain that only accepts, and nftables' own limit
sits in the rule that accepts. For a port that answers, both count as the rule
the operator wrote, exactly as `ufw allow` does, and the limit stays the mark
beside the state. A measured silence is never attributed to either.

## Where the rule reading comes from

`site/app/packetpath.py` already walks a host document in kernel order and
already decides whether a rule names a port. This module needs the same
answer, and `controlplane` and `site` are separate Python projects with no
import path between them, so the port-matching half is **reimplemented here
rather than imported**. It is a faithful copy: the regexes, the raw-payload
bound, the comment-match exception and the jump-following walk all behave the
same, and `tests/test_join.py` loads the site module by path and asserts the
two agree on every rule shape the fleet actually carries, including the ones
that cost this project a correction.

That is more copying than is comfortable and the pull request says so. The
proposal, which is its own change and not this one: a small `ruletext` module
that both sides import, holding `classify_rule` and the constants it needs.
A broad refactor does not belong inside a feature, so it is a
proposal here and a separate card.
"""

import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass, replace
from datetime import datetime, timezone

from . import authz, db, hetzner, prober, vantages
from . import intent as intent_store

# ------------------------------------------------------------------ the states
#
# `docs/DESIGN.md` section 3 owns these words and `docs/RECORD.md` 4.50 records
# why the previous set was retired: each word had to be readable by somebody
# who has never been told what it means, and the old set named who decided
# instead of what is wrong.

STATE_CONFLICT = "conflict"
STATE_UNREVIEWED = "unreviewed"
STATE_INTENDED = "intended"
STATE_STALE_RULE = "stale rule"
STATE_UNEXPLAINED = "unexplained"
# Measured, it did not answer, and nobody declared anything about it. Added
# 2026-08-28 (`docs/RECORD.md` 4.112) and it is the inverse of `unreviewed`
# rather than a new kind of thing.
#
# **Why this had to be its own word.** `unreviewed` is defined in
# `docs/DESIGN.md` section 3 as "reachable, nobody has said whether that is
# intended". Until this word existed a measured silence with no declaration
# returned `unreviewed` too, so one word meant a port answering the internet
# and a port that is shut, and the tone system painted both amber. Two things
# followed from that and both were faults:
#
#   - the state word could not answer the product's own question, so a reader
#     had to go and read the outside column to learn whether a port was
#     reachable at all
#   - `app/finding_alerts.py` compares state words to find a transition, so a
#     port going from shut to answering the internet was not a change and
#     mailed nothing, which is the one alert this product exists to send
#
# `docs/RECORD.md` 4.55 decided that a measured silence "earns the same three
# rules as a measured answer, with reality inverted rather than a sixth word".
# The first half stands and the two declared rules still invert. What did not
# invert is this one, because the inverse of "reachable and nobody said" is a
# different fact and not the same fact upside down.
STATE_NOT_REACHABLE = "not reachable"

STATES = (STATE_CONFLICT, STATE_UNREVIEWED, STATE_INTENDED, STATE_STALE_RULE,
          STATE_UNEXPLAINED, STATE_NOT_REACHABLE)

# The states that assert the internet reached this port. Every one of them may
# only ever appear beside a completed connect, and a test asserts that across
# the whole set at once rather than one path at a time, which is the shape
# `docs/RECORD.md` 4.48 says the prober's suite was missing.
# The four that compare reality against a declaration, so every one of them
# needs the outside view to have MEASURED something. Not to have connected:
# a measured silence earns one of them too since 2026-08-16 (RECORD 4.55).
# What none of them may ever sit beside is `not_tested`.
STATES_NEEDING_A_MEASUREMENT = (STATE_CONFLICT, STATE_UNREVIEWED, STATE_INTENDED,
                            STATE_UNEXPLAINED, STATE_NOT_REACHABLE)

# The states `_decide` reaches by comparing what was measured against what was
# declared, so each of them is a place where "and here is what you said about
# it" is worth adding. `stale rule` and `unexplained` are not here: neither
# reads a declaration at all. Named once because two copies of this tuple had
# to be edited together when `not reachable` was added, which is how one
# fact drifts into two.
STATES_FROM_A_DECLARATION = (STATE_CONFLICT, STATE_UNREVIEWED, STATE_INTENDED,
                             STATE_NOT_REACHABLE)

# ------------------------------------------------------------------ the intent
#
# Two words, because a declaration has two answers. Absent is not a third
# value, it is the absence of a declaration, and it is spelled None. The words
# come from `app/intent.py`, which owns the storage, so there is one spelling
# rather than two that could drift.
INTENT_OPEN = intent_store.INTENT_OPEN
INTENT_CLOSED = intent_store.INTENT_CLOSED
INTENTS = (INTENT_OPEN, INTENT_CLOSED)

# ------------------------------------------------------------------ the layers
#
# Which layer decided, in the order an inbound packet meets them. `service` is
# not a filtering layer, it is the thing at the end of the path, and it is
# named because "nothing is listening" is as much an answer as a rule is.
LAYER_PROVIDER = "provider firewall"
LAYER_HOST_FIREWALL = "host firewall"
LAYER_SERVICE = "service"
LAYER_NOT_DETERMINED = "not determined"

LAYERS = (LAYER_PROVIDER, LAYER_HOST_FIREWALL, LAYER_SERVICE,
          LAYER_NOT_DETERMINED)

# ------------------------------------------------------------------- the notes
#
# Typed, a closed set, never free text. Same posture as the prober's reasons
# and for the same reason (SI-8): a caveat that arrives as a sentence somebody
# typed cannot be counted, cannot be tested and cannot be translated.
NOTE_OUTSIDE_NOT_MEASURED = "outside_view_not_measured"
NOTE_OUTSIDE_PRECEDES_DOCUMENT = "outside_view_older_than_the_document"
NOTE_OUTSIDE_AGE_UNREADABLE = "outside_view_age_unreadable"
NOTE_NO_INTENT_DECLARED = "no_intent_declared"
NOTE_NOTHING_ON_THE_HOST_OWNS_IT = "nothing_on_the_host_owns_this_port"
NOTE_V6_WILDCARD_MAY_SERVE_V4 = "v6_wildcard_bind_may_also_serve_v4"
NOTE_SOCKETS_NOT_READ = "sockets_were_not_read"
NOTE_HOST_FIREWALL_NOT_READ = "host_ruleset_was_not_read"
NOTE_RULES_NOT_FULLY_READABLE = "rules_not_fully_readable"
NOTE_RULE_IS_NARROWED = "rule_narrowed_beyond_the_port"
NOTE_RULE_LIMITS_THE_RATE = "rule_matches_on_how_often_a_connection_was_made"
NOTE_LEGACY_RULES_NOT_PLACED = "legacy_rules_not_placed"
NOTE_PROVIDER_ABSENT = "provider_view_absent"
NOTE_PROVIDER_NO_MATCH = "provider_view_has_no_matching_server"
NOTE_PROVIDER_UNREADABLE = "provider_view_unreadable"
NOTE_PROVIDER_FIREWALL_PENDING = "provider_firewall_pending"
NOTE_PROVIDER_FIREWALL_MISSING = "provider_firewall_not_in_snapshot"
NOTE_PROVIDER_RANGE_NOT_ENUMERATED = "provider_rule_covers_a_port_range"
NOTE_HOST_REVOKED = "host_credential_revoked"
# The host has no agent, so no inside view exists to name a layer or quote a
# rule. The outside view and the declaration are the whole finding.
NOTE_NO_AGENT = "no_agent_on_this_host"

NOTES = frozenset({
    NOTE_OUTSIDE_NOT_MEASURED, NOTE_OUTSIDE_PRECEDES_DOCUMENT,
    NOTE_OUTSIDE_AGE_UNREADABLE, NOTE_NO_INTENT_DECLARED,
    NOTE_NOTHING_ON_THE_HOST_OWNS_IT, NOTE_V6_WILDCARD_MAY_SERVE_V4,
    NOTE_SOCKETS_NOT_READ,
    NOTE_HOST_FIREWALL_NOT_READ, NOTE_RULES_NOT_FULLY_READABLE,
    NOTE_RULE_IS_NARROWED, NOTE_RULE_LIMITS_THE_RATE,
    NOTE_LEGACY_RULES_NOT_PLACED, NOTE_PROVIDER_ABSENT,
    NOTE_PROVIDER_NO_MATCH, NOTE_PROVIDER_UNREADABLE,
    NOTE_PROVIDER_FIREWALL_PENDING, NOTE_PROVIDER_FIREWALL_MISSING,
    NOTE_PROVIDER_RANGE_NOT_ENUMERATED, NOTE_HOST_REVOKED,
})

# The outside view's own vocabulary is the prober's, imported rather than
# retyped. One extra reason, for the case the prober cannot produce because it
# never ran: there is no row at all.
REASON_NOT_PROBED = "no_probe_result"

# The word for `not_tested` on a screen. The constant keeps the prober's
# spelling so the two can never drift, and this is the only place the spaced
# form is written.
_OUTSIDE_WORDS = {
    prober.STATE_CONNECTED: "connect succeeded",
    prober.STATE_REFUSED: "connect refused",
    prober.STATE_NO_RESPONSE: "no response",
    prober.STATE_NOT_TESTED: "not tested",
}

# The families this engine answers for, from the prober so there is one list.
FAMILIES = prober.FAMILIES

# The protocols a port can be. Anything else in a document is carried through
# as a finding with no outside view, never dropped.
PROTOCOL_TCP = "tcp"
PROTOCOL_UDP = "udp"

# The IPv6 wildcard bind address. A socket on it may or may not also take IPv4
# traffic: that is decided by IPV6_V6ONLY, **and the host document does not
# carry it**. So a `::` socket is not evidence that nothing is listening on v4,
# and this engine will not say it is. `site/app/packetpath.sockets_on` already
# says the same about the same missing field. The ambiguity runs one way only:
# a socket on `0.0.0.0` accepts nothing on v6 and is not evidence about it.
#
# Found by running this engine against a copy of production on 2026-08-16,
# where the first version called `app-01` tcp/80 a stale rule on v4
# while caddy was bound to `::`.
V6_WILDCARD = ipaddress.IPv6Address("::")
FAMILY_V4 = prober.FAMILY_V4
FAMILY_V6 = prober.FAMILY_V6

# The one protocol the prober measures, because `app/prober.py` opens
# SOCK_STREAM. A probe row may only ever be attached to this protocol.
PROBED_PROTOCOL = PROTOCOL_TCP


# ============================================================================
# Reading rule text.
#
# COPIED, deliberately and with the copy declared, from site/app/packetpath.py.
# See the module docstring for why it is a copy and where the shared home
# should be. Change one of the two and change the other, and the agreement test
# in tests/test_join.py is what makes that impossible to forget.
# ============================================================================

_DPORT = re.compile(r"\b(?:tcp|udp|sctp|dccp|th) dport (!=|>=|<=|>|<)?\s*(\d+)\b")
_DPORT_MENTION = re.compile(r"\bdport\b")
_L4PROTO = re.compile(r"\b(?:ip protocol|ip6 nexthdr|meta l4proto) (\w+)\b")
_RAWPAYLOAD = re.compile(r"@(th|nh|ll),(\d+),(\d+)")
_COMMENT_MATCH = re.compile(r"\s*\[xt match comment\]")
_JUMP = re.compile(r"\b(jump|goto) (\S+)$")

# A network-header load ending at or before bit 160 is inside the IPv4 fixed
# header (RFC 791 section 3.1, five 32-bit words minimum) and inside the first
# 160 bits of the IPv6 header (RFC 8200 section 3, a fixed 40 octets). Neither
# carries a transport port. 160 and not 320 because an `inet` table sees both
# families and nothing here infers one from the other. `docs/RECORD.md` 4.51 is
# the measurement that produced this bound.
_NETWORK_HEADER_BITS = 160

NAMES_PORT = "names this port"
EVERY_PORT = "carries no port match"
UNREADABLE = "not fully readable"
OTHER_PORT = "names a different port"

# nftables table families and the IP families their chains see.
_FAMILY_SEES = {"ip": ("v4",), "ip6": ("v6",), "inet": ("v4", "v6")}

# The hooks an inbound packet destined for a local port meets, in the order the
# kernel evaluates them. Sourced in site/app/packetpath.py's docstring from the
# kernel tree and repeated here rather than re-derived.
LOCAL_HOOKS = ("ingress", "prerouting", "input")

# The hooks on which an `accept` is a filtering decision. A nat chain's accept
# is not a permit, it is the absence of a translation.
_PERMIT_HOOKS = ("prerouting", "input")
_PERMIT_CHAIN_TYPE = "filter"

_MAX_DEPTH = 12

# How many rules one walk may examine before it stops and says so.
#
# **Depth and the loop guard do not bound the work, and that was measured
# rather than argued.** `seen` is per path, not per walk, which is correct:
# nftables refuses a ruleset with a jump loop but a chain reached down two
# different paths really is evaluated twice, so a walk that visited each chain
# once would under-report a real ruleset. The cost is that a dense jump graph
# has a number of distinct paths that grows like a factorial under the depth
# cap. One table of eight chains, each rule jumping to each other chain,
# produced 767,208 rule hits in 4.2 seconds on a laptop; nine chains is roughly
# eight million and ten is memory. The document is written by the host, the
# dashboard walks it per port per family on every request, and a host
# document is treated as hostile input, so an unbounded walk is a
# way to hang the screen from a machine somebody else owns.
#
# The number is enormous beside anything real. The busiest host in the fleet
# carries 341 nftables rules in total, and a walk for one port on the live box
# examines a few hundred. Twenty thousand is two orders of magnitude of
# headroom and still finishes in milliseconds.
#
# **When it bites it says so rather than returning a short answer.** The rules
# left unexamined in the chain being walked are counted as UNREADABLE, which is
# the count already behind "not fully readable" on the screen, so a truncated
# walk reads as a path we could not fully read. That count is a lower bound:
# chains never reached are not in it, and a lower bound on a hedge is the safe
# direction.
MAX_RULES_WALKED = 20_000


def _raw_load_can_hide_a_port(base: str, offset: int, length: int) -> bool:
    if base == "nh":
        return offset + length > _NETWORK_HEADER_BITS
    return True


def _has_unreadable_payload(text: str) -> bool:
    return any(_raw_load_can_hide_a_port(base, int(offset), int(length))
               for base, offset, length in _RAWPAYLOAD.findall(text))


def classify_rule(text, rendered, protocol, port):
    """How rule `text` relates to `protocol`/`port`, using only what the text
    says. One of NAMES_PORT, EVERY_PORT, UNREADABLE, OTHER_PORT.

    A copy of `site/app/packetpath.classify_rule`, kept identical on purpose.
    """
    text = text or ""
    readable = _COMMENT_MATCH.sub("", text)

    if "[" in readable or _has_unreadable_payload(readable) or not readable.strip():
        return UNREADABLE
    if rendered != "full" and readable == text:
        return UNREADABLE
    text = readable

    proto_match = _L4PROTO.search(text)
    if proto_match and protocol and proto_match.group(1) != protocol:
        return OTHER_PORT

    ports = _DPORT.findall(text)
    if len(_DPORT_MENTION.findall(text)) != len(ports):
        return UNREADABLE
    if not ports:
        return EVERY_PORT

    verdicts = {_dport_selects(op, int(value), port) for op, value in ports}
    if verdicts == {True}:
        return NAMES_PORT
    if verdicts == {False}:
        return OTHER_PORT
    return UNREADABLE


def _dport_selects(op, value, port):
    if op in (None, ""):
        return port == value
    if op == "!=":
        return port != value
    if op == ">":
        return port > value
    if op == ">=":
        return port >= value
    if op == "<":
        return port < value
    if op == "<=":
        return port <= value
    return None  # never reached: the regex only matches the operators above


# ============================================================================
# End of the copied half.
# ============================================================================


def _dicts(value):
    """The dicts in `value`, and nothing else.

    A host document is hostile input (`docs/RECORD.md` 4.14). A `chains` key
    holding the string "no" iterates into characters, and the first `.get` on a
    character raises, which on a render timer takes the dashboard down. So
    every list walked here goes through this.
    """
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _priority(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


@dataclass(frozen=True)
class RuleHit:
    """One rule the walk reached, with where it was found.

    `base_hook` and `base_type` are the base chain's, not the chain the rule
    sits in, because a jumped-to chain has neither and the hook is what decides
    whether an `accept` in it is a filtering decision.
    """
    table_family: str
    table_name: str
    chain: str
    text: str
    rendered: str
    verdict: str | None
    depth: int
    base_hook: str
    base_type: str
    # True when the rule ends in a jump or goto to a chain that holds nothing
    # but a bare accept. See `_holds_only_accepts`.
    jumps_to_bare_accept: bool = False
    # The text of every jump or goto rule the walk followed to reach this
    # rule's chain, outermost first. A packet meets this rule only when it
    # met every one of them, so their conditions are this rule's conditions
    # too. See `_path_shape`.
    path: tuple[str, ...] = ()

    @property
    def source(self) -> str:
        return f"{self.table_family} {self.table_name} {self.chain}"


def _chain_index(table):
    return {c.get("name"): c for c in _dicts(table.get("chains"))
            if c.get("name")}


def _walk(table, chain, protocol, port, base_hook, base_type,
          depth=0, seen=None, index=None, budget=None, path=()):
    """Every rule reached from `chain`, jumps and gotos followed, depth first.

    `port` of None walks everything and classifies nothing, which is the pass
    that proposes candidate ports. With a port it behaves exactly as
    `site/app/packetpath.walk_chain` does, including skipping a rule that names
    a different port and not following that rule's jump, because the packet
    being traced never reaches what it jumps to.
    """
    seen = set() if seen is None else seen
    # A one-element list rather than an integer, because the count has to be
    # shared with every nested call and an integer would be copied.
    budget = [MAX_RULES_WALKED] if budget is None else budget
    counts = {NAMES_PORT: 0, EVERY_PORT: 0, UNREADABLE: 0, OTHER_PORT: 0}
    hits = []
    key = chain.get("name")
    if depth > _MAX_DEPTH or key in seen:
        return hits, counts
    seen = seen | {key}
    index = _chain_index(table) if index is None else index

    rules = _dicts(chain.get("rules"))
    for position, rule in enumerate(rules):
        if budget[0] <= 0:
            counts[UNREADABLE] += len(rules) - position
            break
        budget[0] -= 1
        text = rule.get("text")
        text = text if isinstance(text, str) else ""
        rendered = rule.get("rendered")
        rendered = rendered if isinstance(rendered, str) else ""
        verdict = None
        if port is not None:
            verdict = classify_rule(text, rendered, protocol, port)
            counts[verdict] += 1
            if verdict == OTHER_PORT:
                continue
        jump = _JUMP.search(text)
        target = index.get(jump.group(2)) if jump else None
        hits.append(RuleHit(
            table_family=str(table.get("family") or ""),
            table_name=str(table.get("name") or ""),
            chain=str(key or ""), text=text, rendered=rendered,
            verdict=verdict, depth=depth,
            base_hook=base_hook, base_type=base_type,
            jumps_to_bare_accept=_holds_only_accepts(target), path=path))
        if target is None:
            continue
        sub_hits, sub_counts = _walk(table, target, protocol, port, base_hook,
                                     base_type, depth + 1, seen, index, budget,
                                     path + (text,))
        hits.extend(sub_hits)
        for name, value in sub_counts.items():
            counts[name] += value
    return hits, counts


def _base_chains(doc, family, hooks):
    """Every nftables base chain on one of `hooks` that a packet of this family
    meets, in the priority order the kernel reported.

    Priority order is not load bearing here the way it is on the packet path
    screen, because this engine counts and quotes rather than narrating an
    order. It is kept anyway so the quotes come out in the same order the
    screen shows them.
    """
    found = []
    for table in _dicts(_mapping(doc.get("nftables")).get("tables")):
        if family not in _FAMILY_SEES.get(table.get("family"), ()):
            continue
        for chain in _dicts(table.get("chains")):
            if chain.get("hook") not in hooks:
                continue
            found.append((_priority(chain.get("priority")), table, chain))
    found.sort(key=lambda item: (
        item[0] is None, item[0] if item[0] is not None else 0,
        str(item[1].get("family") or ""), str(item[1].get("name") or ""),
        str(item[2].get("name") or "")))
    return found


def _rules_for_port(doc, family, protocol, port):
    """Every rule on the local-delivery path that this port's packet is
    evaluated against, plus the counts by readability."""
    hits = []
    counts = {NAMES_PORT: 0, EVERY_PORT: 0, UNREADABLE: 0, OTHER_PORT: 0}
    # One budget for the whole port, not one per base chain, so a document
    # carrying a thousand base chains cannot spend it a thousand times.
    budget = [MAX_RULES_WALKED]
    for _, table, chain in _base_chains(doc, family, LOCAL_HOOKS):
        chain_hits, chain_counts = _walk(
            table, chain, protocol, port,
            base_hook=str(chain.get("hook") or ""),
            base_type=str(chain.get("type") or ""), budget=budget)
        hits.extend(chain_hits)
        for name, value in chain_counts.items():
            counts[name] += value
    return hits, counts


# ----------------------------------------------------- what counts as a permit

def _is_accept(text: str) -> bool:
    """Whether the rule's verdict is a bare accept.

    Token based rather than a regex on the tail, because `jump ufw-user-accept`
    ends in the letters of accept and a word-boundary match would read it as
    one. That chain exists on ufw hosts.
    """
    tokens = (text or "").split()
    if not tokens or tokens[-1] != "accept":
        return False
    return not (len(tokens) >= 2 and tokens[-2] in ("jump", "goto"))


def _holds_only_accepts(chain) -> bool:
    """Whether `chain` holds at least one rule and every rule in it is a bare
    accept, a counter aside.

    This is the chain ufw's `limit` permits through. `ufw limit 3020/tcp`
    writes `-p tcp --dport 3020 -j ufw-user-limit-accept`, and that chain is
    one `-j ACCEPT` (ufw 0.36.2 `backend_iptables.py` lines 650 to 659 and
    `/etc/ufw/user.rules`, read on 2026-09-29, `docs/RECORD.md` 4.209). The
    agent writes the chain as `counter accept`. `docs/PRODUCT.md` 8d: a permit
    that names the port and jumps to a chain holding nothing but an
    unconditional accept counts as that accept.

    Strict on purpose. A chain with a `return`, a `log`, a match of any kind
    or a rule the agent could not fully read is not this chain, and an empty
    chain accepts nothing.
    """
    rules = _dicts(_mapping(chain).get("rules"))
    if not rules:
        return False
    for rule in rules:
        text = rule.get("text")
        tokens = [token for token in (text if isinstance(text, str) else "").split()
                  if token != "counter"]
        if tokens != ["accept"] or rule.get("rendered") != "full":
            return False
    return True


def _jump_as_accept(text: str) -> str:
    """The rule's text with its final `jump X` or `goto X` read as `accept`.
    Only ever called for a hit whose target `_holds_only_accepts`."""
    return " ".join((text or "").split()[:-2] + ["accept"])


def _limit_set_aside(text: str, rendered: str):
    """The rule's text and grade with nftables' own rate limit taken out, for
    asking whether what is left is a plain permit.

    The agent writes a limit expression as the bare token `[limit]`
    (`LIMIT_MODULE_TOKENS` below), so `tcp dport 4050 limit rate 10/second
    burst 5 packets accept` arrives as `meta l4proto tcp tcp dport 4050
    [limit] accept`, graded partial (measured on 2026-10-02, nftables 1.1.3,
    `docs/RECORD.md` 4.244). Every part the agent could not read is a
    bracketed token, so when no bracket is left after this one is removed,
    the rest was read in full and is graded so.
    """
    tokens = (text or "").split()
    if "[limit]" not in tokens:
        return text, rendered
    left = " ".join(token for token in tokens if token != "[limit]")
    return left, ("full" if "[" not in left else rendered)


# A conntrack state match, in the two forms nft prints and the agent writes:
# the comma list, `ct state new,untracked`, and the set, `ct state { new,
# untracked }` (the agent writes the set form since 0.1.12, before that such a
# rule arrived as a `[lookup @...]` and was not readable at all,
# `docs/RECORD.md` 4.244). An inverted match, `ct state != ...`, is not one of
# them and is left alone.
_CT_STATE = re.compile(r"\bct state (\{ [a-z]+(?:, [a-z]+)* \}|[a-z]+(?:,[a-z]+)*)(?= |$)")
_CT_STATES = frozenset({"invalid", "established", "related", "new", "untracked"})


def _without_new_connection_match(body: str) -> str:
    """`body` with a conntrack state match that includes `new` taken out.

    **A rule that accepts new connections is an answer** (`docs/PRODUCT.md`
    8d, decided 2026-10-02, `docs/RECORD.md` 4.244). firewalld 0.9.11 on the
    RHEL 8 family opens every port as `tcp dport 6000 ct state { new,
    untracked } accept`. The nftables wiki (Matching connection tracking
    stateful metainformation, read 2026-10-02) defines new as "Netfilter has so
    far seen packets between this pair of hosts in only one direction", so the
    match is met by the first packet of a connection from every address. It
    narrows no address and no port.

    Only a match that includes `new` and names nothing but the five states
    goes. `ct state established` alone opens nothing to a first packet, and a
    state this function does not know is not one it may reason about. Both
    stay, and what stays makes the rule narrowed.
    """
    def replace(match):
        names = set(re.findall(r"[a-z]+", match.group(1)))
        if "new" in names and names <= _CT_STATES:
            return " "
        return match.group(0)
    return _CT_STATE.sub(replace, body)


def _accept_shape(text: str, protocol: str, port: int, family: str) -> str | None:
    """`unconditional`, `narrowed`, or None when this is not an accept for a
    packet of `family`.

    Unconditional means that after removing the matched protocol, this exact
    destination port, the counter and the verdict, **nothing is left**. That is
    a deliberately strict test and it is what keeps the vocabulary usable:

      - `ip daddr 239.255.255.250 ip protocol udp udp dport 1900 counter
        accept` is ufw's own boilerplate, present on every host it is installed
        on, and it is scoped to a multicast destination. Narrowed.
      - `ip protocol tcp tcp dport 80 counter accept` is what `ufw allow 80`
        writes. Unconditional.

    **A rule pinned to one address family is that family's rule and nobody
    else's** (`docs/PRODUCT.md` 8d, `docs/RECORD.md` 4.216). `meta nfproto ipv4
    meta l4proto tcp tcp dport 4040 accept` in an `inet` table applies to every
    IPv4 packet for the port, exactly as `tcp dport 4040 accept` in an `ip`
    table does, so for v4 the pin is set aside and the rule is unconditional.
    For v6 the rule cannot match at all, and it is not an accept: None.
    Until 2026-10-02 the pin was left over and the rule read narrowed on both
    families, which called a port opened on purpose `unreviewed` on the family
    it was opened for, and put a v4 rule beside a v6 finding. Nothing about v4
    answers v6 (`docs/PRODUCT.md` 4b), in either direction.

    Anything this function cannot take apart stays narrowed, which is the
    answer that claims less.
    """
    left = _left_over(text, protocol, port, family)
    if left is None:
        return None
    return "narrowed" if left else "unconditional"


def _left_over(text: str, protocol: str, port: int, family: str) -> str | None:
    """What is left of an accept once everything `_accept_shape` sets aside
    is gone, or None when this is not an accept for a packet of `family`.
    Nothing left is the unconditional accept.

    Kept apart from `_accept_shape` because one thing more is read from it:
    whether what is left is one source address and nothing else
    (`_plain_source`)."""
    if not _is_accept(text):
        return None
    pinned = _rule_family(text)
    if pinned is not None and pinned != family:
        return None
    body = " ".join(text.split()[:-1])
    body = _COMMENT_MATCH.sub(" ", body)
    if pinned == family:
        # Only the bare pin goes. An `ip saddr` or an `ip6 daddr` pins the
        # family as well and is a real narrowing, so it stays and is counted
        # below.
        body = re.sub(r"\bmeta nfproto ipv[46]\b", " ", body)
    body = re.sub(r"\b(?:ip protocol|ip6 nexthdr|meta l4proto) "
                  + re.escape(str(protocol)) + r"\b", " ", body)
    body = re.sub(r"\b(?:tcp|udp|sctp|dccp|th) dport " + str(int(port)) + r"\b",
                  " ", body)
    body = re.sub(r"\bcounter\b", " ", body)
    body = _without_new_connection_match(body)
    return " ".join(body.split())


# One source address or one prefix, and nothing else, in the family's own
# spelling. The prefix length is digits: a mask written out, a range, a set,
# a negation and a name all fail to match or fail to parse below.
_PLAIN_SOURCE = {"v4": re.compile(r"^ip saddr ([0-9.]+(?:/[0-9]{1,2})?)$"),
                 "v6": re.compile(r"^ip6 saddr ([0-9A-Fa-f:.]+(?:/[0-9]{1,3})?)$")}


def _plain_source(left: str, family: str) -> str | None:
    """The network a narrowed accept permits, when what is left of it
    (`_left_over`) is one source address or one prefix of `family` and
    nothing else. None for every other narrowing: an interface, a destination,
    a set, a negation, a range, a second condition beside the source, and
    anything that does not read as an address.

    This is the one narrowing the engine reads as what it is, for one
    question only: whether a prober that connected was outside it
    (`docs/PRODUCT.md` 8d, `docs/RECORD.md` 4.358). Every other narrowing
    stays "narrowed" and nothing more is said about it."""
    found = _PLAIN_SOURCE[family].match(left)
    if found is None:
        return None
    try:
        network = ipaddress.ip_network(found.group(1), strict=False)
    except ValueError:
        return None
    return str(network)


# An interface match on a jump, the way firewalld enters a zone: `iifname
# "eno1" jump filter_IN_public`. Only the plain form, an interface that is
# named and matched for equality.
_ON_INTERFACE = re.compile(r'\b(?:iifname|iif) "?([^"\s]+)"?(?= |$)')


def _path_shape(path, protocol: str, port: int, family: str) -> str | None:
    """How the jumps that lead to a rule restrict it: `unconditional`,
    `narrowed`, or None when a packet of `family` never takes them.

    **A jump's own condition is read, never assumed.** Until 2026-10-02 the
    walk followed every jump and looked only at the rule it arrived at, so a
    permit behind `ip saddr 192.0.2.0/24 jump filter_IN_internal` read as open
    to everyone, on v6 too although an `ip saddr` match cannot be met by a v6
    packet. That is firewalld's own trap, a port opened in a zone that does
    not face the internet, measured on 2026-09-30 on a server
    (`docs/RECORD.md` 4.213, test fleet case 12).

    Each jump is read as `_accept_shape` reads an accept: the protocol, this
    port, the counter, a family pin for this family and a new-connection
    match are no condition, anything else left over narrows, and a jump
    pinned to the other family is never taken.

    **One more thing is no condition on a jump: the interface it comes in
    on.** firewalld enters the zone that applies through `iifname "eno1"
    jump filter_IN_public`, and that is how every firewalld permit on the
    fleet reaches its port, so it has to go on counting. `lo` is the
    exception, because nothing from outside arrives on it.

    What this does not decide, and it is said rather than guessed: whether
    the named interface is the one that faces the internet. A zone bound to
    an interface that does not, a VPN or a private network, still reads as
    it did before. The document holds each interface's addresses and not
    which of them the provider routes, so an interface with only a private
    address may still be the public one.
    """
    worst = "unconditional"
    for jump_text in path:
        text = jump_text
        interface = _ON_INTERFACE.search(text)
        if interface and interface.group(1) != "lo":
            text = _ON_INTERFACE.sub(" ", text, count=1)
        shape = _accept_shape(_jump_as_accept(text), protocol, port, family)
        if shape is None:
            return None
        if shape == "narrowed":
            worst = "narrowed"
    return worst


def _is_permit_chain(hit: RuleHit) -> bool:
    return hit.base_type == _PERMIT_CHAIN_TYPE and hit.base_hook in _PERMIT_HOOKS


# -------------------------------------------------- what counts as a rate limit
#
# The modules a rule can decide on connection history with, and the token the
# agent writes each one as. Read from the agent's own renderer,
# `agent/internal/collect/nftrender_linux.go`, where `*expr.Match` becomes
# `[xt match <name>]` and `*expr.Limit` becomes a bare `[limit]`. Both go
# through the same `fall` helper, so **every one of these tokens is a bracketed
# fallback**, which means a rule carrying one is always `UNREADABLE` to
# `classify_rule` above. Nothing in this section changes that and nothing here
# moves a rule into or out of `permit_rules` or `narrowed_rules`.
#
# What each module does, from `man iptables-extensions` read on the fleet on
# 2026-08-19:
#
#   limit      "Matches at a limited rate using a token bucket filter."
#   hashlimit  "hashlimit uses hash buckets to express a rate limiting match
#              (like the limit match) for a group of connections using a single
#              iptables rule."
#   recent     a list of addresses, matched on `--seconds` and `--hitcount`.
#              This is what ufw's `limit` is built from: ufw 0.36.2
#              `backend_iptables.py` substitutes ` -j LIMIT` for
#              `-m conntrack --ctstate NEW -m recent --set` and
#              `-m recent --update --seconds 30 --hitcount 6`, and `man ufw`
#              calls that "connection rate limiting".
#
# `[limit]` and `[xt match recent]` were both read out of the app-01
# host document on 2026-08-19. `hashlimit` is on no host in this fleet, so its
# token shape comes from the renderer above plus the module's own name, and it
# is here rather than left out because it is a rate limiter and leaving it out
# would file one under nothing.
#
# **If the agent's renderer ever writes an nftables limit as understood text**,
# a `limit rate 6/minute` form appears that none of these tokens match, and
# this table is the place that has to learn it.
LIMIT_MODULE_TOKENS = {
    "[limit]": "limit",
    # nftables' `limit rate over N`, which the agent tells apart from a plain
    # limit since 0.1.12. It matches only what is above the rate, so it is a
    # rate limit to name and never a permit: `_limit_set_aside` takes out the
    # plain token alone, and a rule carrying this one stays unreadable.
    "[limit over]": "limit",
    "[xt match hashlimit]": "hashlimit",
    "[xt match recent]": "recent",
}


def _states_this_port(text: str, protocol: str, port: int) -> bool:
    """Whether the rule's own text plainly states this protocol and this exact
    destination port.

    **This is not `classify_rule` and it does not replace it.** That function
    answers whether a rule may be quoted as naming a port, and it answers no as
    soon as any part of the rule is a bracketed fallback, because a set or an
    x_tables match can select a port the text never mentions
    (`docs/PRODUCT.md` 4g). This one answers a narrower question: does the text
    say `tcp dport 22` in plain words.

    It is used only to attach a fact about a rule to the port that rule's own
    text names. It never widens what a rule covers and it never feeds a state.
    nftables matches are conjunctive, so whatever the bracketed part of such a
    rule turns out to be, it can only narrow what the rule applies to. It
    cannot make the rule apply to a different port.

    Deliberately strict, because the answer that claims less is the right one:
    the protocol has to be stated and has to be this one, every destination
    port in the rule is a plain equality against this port so a range and a
    `!=` and every comparison answer no, and a bare `dport` the regex could not
    parse answers no.
    """
    text = _COMMENT_MATCH.sub("", text or "")
    proto_match = _L4PROTO.search(text)
    if proto_match is None or proto_match.group(1) != protocol:
        return False
    ports = _DPORT.findall(text)
    if not ports or len(_DPORT_MENTION.findall(text)) != len(ports):
        return False
    return all(op in (None, "") and int(value) == port for op, value in ports)


# The expressions that pin a rule to one address family, and nothing else does.
#
# They only matter inside an `inet` table. An `ip` or `ip6` table is already
# filtered by family in `_base_chains` through `_FAMILY_SEES`, and an `inet`
# table is seen by both, so a rule in one that restricts itself has to be read
# from its own text or not at all.
#
# `meta nfproto ipv4` is already sourced in `_accept_shape`'s docstring above,
# which says in as many words that such a rule "in an `inet` table applies to
# v4 only". `ip` and `ip6` are the payload expression bases for the two
# protocols and the same argument applies to them: an `ip daddr` match can only
# be evaluated against an IPv4 header. The set is deliberately small. An
# expression not listed here leaves the rule unpinned, which is the answer that
# claims less.
_FAMILY_EXPRESSIONS = (
    (FAMILY_V4, re.compile(r"\bmeta nfproto ipv4\b|\bip (?:saddr|daddr|protocol)\b")),
    (FAMILY_V6, re.compile(r"\bmeta nfproto ipv6\b|\bip6 (?:saddr|daddr|nexthdr)\b")),
)


def _rule_family(text: str) -> str | None:
    """The one family this rule pins itself to, or None for neither and both.

    None is the honest answer twice over. A rule naming no family applies to
    whatever its table carries, and a rule naming both is something this
    function does not understand, so neither may be read as being about one
    family.
    """
    named = [family for family, pattern in _FAMILY_EXPRESSIONS
             if pattern.search(text or "")]
    return named[0] if len(named) == 1 else None


def _limit_module(text: str, protocol: str, port: int, family: str) -> str | None:
    """The module this rule decides on connection history with, or None.

    Conservative in both directions, and both directions were measured.

    A rule carrying one of the tokens that does **not** plainly state this port
    answers None, and that is what keeps ufw's logging rate limiters out of
    this. `[limit] counter [xt target LOG]` sits in `ufw-logging-deny` and in
    `ufw-after-logging-input`, it is on the walked path of every port on every
    ufw host, and it limits the log rather than the connection. Counting it
    would mark every port on the fleet as rate limited.

    A rule that plainly states this port and carries none of the tokens also
    answers None. `meta l4proto tcp tcp dport 22 meta nfproto ipv4 [lookup
    @addr-set-sshd] [reject]` is fail2ban on the production box, read on
    2026-08-19. It is a list of banned addresses and not a rate limit, and
    calling it one would be naming the wrong mechanism.

    **And it answers None for the other family's rule.** Measured on
    2026-08-21: inside an `inet` table, which both families are shown, a rule
    reading `meta nfproto ipv4 meta l4proto tcp tcp dport 22 [xt match
    hashlimit] ...` was counted as a rate limit on the **v6** finding as well.
    The rule's own text says v4. `docs/PRODUCT.md` 4b with the families
    swapped, and `docs/RECORD.md` 4.79 has the reproduction.

    `_accept_shape` never had this because it demotes anything with a leftover
    expression to `narrowed`, which makes no claim on either family. This path
    returns before reaching it, so the check has to be its own.
    """
    if _rule_family(text) not in (None, family):
        return None
    if not _states_this_port(text, protocol, port):
        return None
    for token, module in LIMIT_MODULE_TOKENS.items():
        if token in (text or ""):
            return module
    return None


# ------------------------------------------------------------------- the views

@dataclass(frozen=True)
class Quote:
    """One piece of evidence, quoted rather than summarised.

    `text` is verbatim for a host rule, because the agent already rendered it
    in the syntax the host itself uses (`docs/PRODUCT.md` 4e principle 5). A
    provider rule has no text form at all, so its fields are rendered in a
    fixed order and only its description is the provider's own words.
    """
    layer: str
    source: str
    text: str
    rendered: str = ""
    note: str = ""
    # The module this rule decides on connection history with, when it is one
    # of `LIMIT_MODULE_TOKENS`, and empty otherwise. Carried on the quote
    # because the sentence names the module, and worked out where the rule was
    # read rather than a second time where it is written out.
    limit_module: str = ""


@dataclass(frozen=True)
class ListeningSocket:
    process_name: str
    bind_address: str
    pid: int | None
    # What the kernel said about the socket, which is all agent 0.1.10 sends
    # about who holds it: the systemd unit, verbatim, and the owner
    # (docs/RECORD.md 4.169). Carried so that every reader of a finding can
    # name the socket from the same facts the Services tab names it from.
    # Empty and None when the document gave none, or gave the wrong type.
    unit: str = ""
    owner_name: str = ""
    owner_uid: int | None = None

    @property
    def name(self) -> str:
        # The unit verbatim, as the kernel named it. Whether a unit is a
        # fair name for a service is the screen's question
        # (`site/app/render_live.py`, `socket_holder`), not the engine's.
        return self.process_name or self.unit or "an unnamed process"

    @property
    def text(self) -> str:
        return f"{self.name} on {self.bind_address}" if self.bind_address else self.name


@dataclass(frozen=True)
class Publication:
    runtime: str
    container: str
    host_ip: str
    family: str | None


@dataclass(frozen=True)
class InsideView:
    """What the host says. Facts and quotes, never an outcome."""
    sockets_status: str
    nftables_status: str
    sockets: tuple[ListeningSocket, ...] = ()
    publications: tuple[Publication, ...] = ()
    ambiguous_binds: tuple[Quote, ...] = ()
    # The sockets behind `ambiguous_binds`: on v4, what listens on the IPv6
    # wildcard and may be taking v4 connections. Kept as sockets so a reader
    # that has to name the program, the finding alerts, reads the unit and
    # the process the way it does for `sockets`, and not a quote's text.
    wildcard_sockets: tuple[ListeningSocket, ...] = ()
    permit_rules: tuple[Quote, ...] = ()
    narrowed_rules: tuple[Quote, ...] = ()
    # The network each narrowed rule permits, when every narrowed rule for
    # this port is a plain narrowing by source address on the input hook
    # (`_plain_source`), and empty otherwise. One rule narrowed any other way
    # empties it: what that rule permits is not known, so nothing is said
    # about the others either. Read by `_answered_outside_the_rules_source`
    # and by nothing else.
    narrowed_to_sources: tuple[str, ...] = ()
    # Rules on this port's path that decide on how recently and how often a
    # connection was made. They are facts about the ruleset and never evidence
    # about reachability, so `_decide` cannot see them and `owns_the_port`
    # below does not count them.
    rate_limit_rules: tuple[Quote, ...] = ()
    # Rules on this port's path that name the port and turn the packet away,
    # with drop or reject, for a packet of this family. A fact about the
    # ruleset, quoted the way a permit is: a card said "no rule names 5432"
    # on a server whose ufw denies 5432 (`docs/RECORD.md` 4.454). `_decide`
    # cannot see them, since a measured silence names no layer
    # (`docs/PRODUCT.md` 8b), and `owns_the_port` does not count them.
    deny_rules: tuple[Quote, ...] = ()
    rules_naming_port: int = 0
    unreadable_rule_count: int = 0
    legacy_rule_count: int = 0
    # True on a host that has no agent by the operator's choice, an address
    # host (docs/PRODUCT.md 3a, tier 1). Nothing was read because nothing
    # runs there to read, which is a different fact from a section that
    # failed to read, and `_decide` and `_notes_for` treat the two apart.
    absent: bool = False

    @property
    def owns_the_port(self) -> bool:
        """Whether anything on this host could be serving this port.

        `ambiguous_binds` counts, and that is the point of it. A socket on the
        IPv6 wildcard may be answering v4 connections and the document cannot
        say, so on v4 it is neither an owner nor an absence. Counting it as an
        owner is the answer that claims less: it stops `stale rule`, which
        would assert that nothing is behind the rule, and it stops
        `unexplained`, which would assert that no agent can attribute the port.
        """
        return bool(self.sockets or self.publications or self.ambiguous_binds)


@dataclass(frozen=True)
class VantageView:
    """What one vantage's newest measurement of one port on one address said.

    Kept beside the resolved answer rather than folded into it, because with
    two vantages the resolved answer is a conclusion and this is the evidence:
    a screen that shows the port as reachable can also show that London saw
    nothing, and a reader can check the conclusion against what each box
    measured (`docs/PRODUCT.md` 8e).
    """
    vantage: str
    target: str | None
    state: str
    reason: str | None = None
    measured_at: str | None = None
    # The addresses of this family the registry holds for this vantage
    # (`app/vantages.py`), which are the addresses it probes from. Empty when
    # the registry does not hold the vantage, or holds none of this family.
    # They are the registry's of now, not of the moment of the measurement.
    probes_from: tuple[str, ...] = ()

    @property
    def word(self) -> str:
        """The same word OutsideView gives its state, so a screen listing
        what each vantage said spells it the way the resolved answer is
        spelt."""
        return _OUTSIDE_WORDS.get(self.state, self.state)

    @property
    def measured(self) -> bool:
        return self.state in prober.MEASURED_STATES


@dataclass(frozen=True)
class OutsideView:
    """What the prober measured, or that it measured nothing.

    `disagree` is True when two vantages' newest measurements of this port do
    not agree, and it is a mark beside the state, never a sixth state
    (`docs/PRODUCT.md` 8e, the same shape as 8c's `rate_limited`). `views` is
    what each vantage said, so the mark can be read rather than trusted. A
    vantage that measured nothing is absent from the comparison: silence from
    a box is not a second opinion.

    `state` is the prober's own constant, never a second spelling of it.
    `precedes_document` is True when this port's own measurement was taken
    before the document we are comparing it against arrived, False when it was
    not, and None when one of the two timestamps could not be read. It is
    computed from this cell's `measured_at`, not from a run start, because the
    engine reads a measurement per port across runs and each may have been taken
    at a different time. None is its own answer and never silently becomes
    False, which is `docs/RECORD.md` 4.51's correction about a fallback that put
    a number nobody observed into a sentence.
    """
    state: str
    reason: str | None = None
    run_id: int | None = None
    vantage: str | None = None
    measured_at: str | None = None
    targets: tuple[str, ...] = ()
    precedes_document: bool | None = None
    disagree: bool = False
    views: tuple[VantageView, ...] = ()

    @property
    def word(self) -> str:
        return _OUTSIDE_WORDS.get(self.state, self.state)

    @property
    def connected(self) -> bool:
        return self.state == prober.STATE_CONNECTED

    @property
    def measured(self) -> bool:
        return self.state in prober.MEASURED_STATES


@dataclass(frozen=True)
class ProviderView:
    """What the provider says, or that it says nothing.

    `configured` is whether a snapshot exists at all, `matched` is whether one
    of its servers is this host. The two are separate because "we never asked"
    and "we asked and this host is not there" are different facts and only one
    of them is a problem.
    """
    configured: bool = False
    matched: bool = False
    provider: str = hetzner.PROVIDER
    server_name: str | None = None
    rules: tuple[Quote, ...] = ()
    # Rules that permit this port from some addresses only, never from the
    # whole family. They are quoted and never counted as a permit, the same
    # rule docs/PRODUCT.md 8d applies to a narrowed host rule: a port the
    # world cannot reach through them is not a port somebody opened.
    narrowed: tuple[Quote, ...] = ()


@dataclass(frozen=True)
class Cause:
    """Which layer decided, and the evidence for saying so."""
    layer: str = LAYER_NOT_DETERMINED
    quotes: tuple[Quote, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """One port, one address family, three views and a cause."""
    protocol: str
    port: int
    family: str
    state: str | None
    intent: str | None
    inside: InsideView
    outside: OutsideView
    provider: ProviderView
    cause: Cause
    # When somebody said they had read this finding and were not acting on it,
    # and None otherwise. It is set only while the acknowledged state is still
    # the state below, so a finding that changed comes back on the list. It is
    # not a state and it is not evidence, which is why it sits beside the
    # state rather than inside it.
    acknowledged: str | None = None
    # What the operator calls the service on this port, from `app/intent.py`,
    # and None when nothing was declared. One name for both families, because
    # it names the service and not an address. It is a thing a person typed:
    # `_decide` never sees it, it changes no state and no quote, and a
    # renderer that shows it says it was declared.
    declared_name: str | None = None
    # Whether a rule on this port's path, in this address family, decides on
    # how recently and how often a connection was made. The owner's decision,
    # 2026-08-21, `docs/RECORD.md` 4.81.
    #
    # **A flag beside the state, never a state and never part of one.** The
    # five words keep their meanings, `_decide` does not see this, and no layer
    # is named from it. `docs/PRODUCT.md` 8c is the rule it obeys: a rate limit
    # is named as a rate limit and blamed for nothing.
    #
    # What it is for. A port behind such a rule is reachable and unreachable at
    # the same moment depending on who is asking and how recently, so two
    # probes minutes apart can legitimately disagree about it. Nothing could
    # see that the disagreement was expected there, and this is the thing that
    # can (`app/finding_alerts.py`).
    #
    # It restates `bool(inside.rate_limit_rules)` and it is worth the second
    # copy: every reader of a finding would otherwise have to know that a
    # non-empty quote list on one view is the answer to a question about the
    # finding as a whole.
    rate_limited: bool = False
    # True in one case and in no other: a Docker port that answered an address
    # its host rule does not permit, while the provider's firewall permits
    # everyone (`_answered_outside_the_rules_source`, `docs/PRODUCT.md` 8d).
    # The state is `unreviewed` then, and this is how a screen or a message
    # tells that `unreviewed` from the one where no rule permits the port.
    # Nothing outside the engine works the case out a second time.
    answered_outside_the_rules_source: bool = False
    # What the provider says about this port in the other address family,
    # set only when the engine raised no finding there. None otherwise.
    #
    # **Read by a screen, never by `_decide`.** It raises no finding, changes
    # no state and no count. It exists because a server's page draws both
    # families of a port, and the card for the family with no finding hard-
    # coded "provider: not connected" beside a connected provider (Sweep 2,
    # C5, `docs/RECORD.md` 4.199). Whether a provider rule covers a port is
    # `_provider_view`'s question, ranges included, so the answer is taken
    # from there and not worked out a second time on the page.
    other_family_provider: ProviderView | None = None


@dataclass(frozen=True)
class HostFindings:
    host_id: int
    host_name: str
    hostname: str | None
    revoked_at: str | None
    paused: bool
    document_readable: bool
    received_at: str | None
    collected_at_unix: int | None
    findings: tuple[Finding, ...] = ()
    # There is deliberately no host-level probe run, vantage or run time here.
    # The engine now reads the newest measurement per port across every run
    # (`_probe_index`), so no single run is behind a host's findings any more:
    # a fast-lane run and a broad-sweep run can each own some of them. Naming
    # one run at the host level would claim every port came from it, which is
    # exactly the mis-attribution this change removed. Provenance lives per
    # cell instead, on `OutsideView.run_id`, `.vantage` and `.measured_at`,
    # each set to the run that took that port's newest measurement.
    provider_configured: bool = False
    provider_matched: bool = False
    # "agent" or "address" (db.HOST_KINDS). An address host has no document
    # by design, so received_at is None while document_readable stays True:
    # nothing failed to read, there was never anything to read.
    kind: str = "agent"


# --------------------------------------------------------------- reading the db

def _table_exists(con: sqlite3.Connection, name: str) -> bool:
    """Whether a table is there at all.

    Asked rather than caught. The production database on 2026-08-16 has no
    `probe_results` table, because nothing has run the prober against it, and
    an engine that answered that with a traceback would be unusable exactly
    where it has to work. Catching OperationalError instead would also swallow
    a corrupt file, which is not the same thing and should be loud.
    """
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        (name,)).fetchone()
    return row is not None


def _latest_report(con: sqlite3.Connection, host_id: int):
    return con.execute(
        "SELECT * FROM reports WHERE host_id = ?"
        " ORDER BY received_at DESC, id DESC LIMIT 1", (host_id,)).fetchone()


def _parse_time(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


# The oldest possible instant, tz-aware, used only as a sort placeholder for a
# measurement whose timestamp will not parse. It is aware so it never has to be
# compared against a naive value, which would raise.
_UNDATED = datetime.min.replace(tzinfo=timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """A parsed timestamp normalised to UTC, so any two are safe to compare.

    Every timestamp the prober writes is UTC already. This exists so that a
    naive one, which could only arrive from a hand-edited row, cannot raise a
    TypeError against an aware one mid-comparison and take down a host's whole
    render (`docs/RECORD.md` 4.80 is the same lesson about one bad row).
    """
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _measured_sort_key(row):
    """Newest-measurement ordering for one probe result row.

    By `measured_at`. A timestamp that will not parse sorts oldest rather than
    crashing the comparison, so a readable newer measurement always wins over an
    unreadable one, which is `docs/RECORD.md` 4.51: an unreadable time is its
    own answer and is never silently treated as now. The row id breaks a tie and
    rises with insert order, so the later-stored of two equal times wins.
    """
    parsed = _parse_time(row["measured_at"])
    return (parsed is not None, _as_utc(parsed) if parsed else _UNDATED, row["id"])


def _watched_vantages(con) -> frozenset:
    """The names of the enabled vantages in the registry, or nothing on a
    database from before the registry existed. Nothing means every vantage
    name in the stored runs counts, which is what the engine did until
    2026-09-08 and what a laptop's runs still need."""
    if not vantages.table_exists(con):
        return frozenset()
    return frozenset(v.name for v in vantages.enabled(con))


def _vantage_sources(con) -> dict:
    """(vantage name, family) to the addresses the registry holds for it,
    or nothing on a database from before the registry existed."""
    if not vantages.table_exists(con):
        return {}
    held: dict = {}
    for vantage in vantages.list_all(con):
        for address in vantage.addresses:
            family = "v6" if ipaddress.ip_address(address).version == 6 else "v4"
            held.setdefault((vantage.name, family), []).append(address)
    return {key: tuple(addresses) for key, addresses in held.items()}


def _resolve_target(rows_by_vantage: dict, watched: frozenset,
                    sources: dict | None = None) -> dict:
    """One address's answer from each vantage's newest measurement of it.

    **A completed connect from any vantage is a completed connect.** The
    question is whether the internet reached this port, and a box in London
    reaching it answers that whatever a box in Amsterdam saw. Otherwise the
    newest measurement wins, as it always has for one vantage.

    **Disagreement is recorded, never averaged and never resolved by
    recency.** Two vantages whose newest measurements are both measurements
    and differ, a connect against a silence, a refusal against a silence, mark
    the answer `disagree`, and the views are kept so a reader sees which box
    said what. A vantage whose newest row is `not_tested` said nothing, and
    nothing is not a second opinion.

    Only the enabled vantages of the registry are compared when the registry
    has any and one of them has measured this address. A vantage switched off
    keeps its old rows in the database and they must not stand against a
    live box's answer forever. When no enabled vantage has measured the
    address, every row counts, which is the pre-registry reading and keeps a
    laptop's run or an older name from disappearing.
    """
    rows = list(rows_by_vantage.values())
    if watched and any(r["vantage"] in watched for r in rows):
        rows = [r for r in rows if r["vantage"] in watched]
    connected = [r for r in rows if r["state"] == prober.STATE_CONNECTED]
    chosen = max(connected or rows, key=_measured_sort_key)
    measured_states = {r["state"] for r in rows
                       if r["state"] in prober.MEASURED_STATES}
    views = [VantageView(vantage=r["vantage"], target=r["target"],
                         state=r["state"], reason=r["reason"],
                         measured_at=r["measured_at"],
                         probes_from=(sources or {}).get(
                             (r["vantage"], r["family"]), ()))
             for r in sorted(rows, key=lambda r: r["vantage"] or "")]
    return {"row": chosen, "disagree": len(measured_states) > 1,
            "views": views}


def _resolve_cell(rows_by_target: dict) -> dict:
    """One (family, port) cell from each address's newest measurement.

    `rows_by_target` holds, per target address, that address's newest row. Two
    rules turn them into one answer, and they are the two `_probe_index` has
    always applied within a run, now applied across runs as well:

    - **A completed connect on any address is a completed connect for the
      family.** The question is whether the internet reached this host on this
      port, so the newest such connect names the cell. An address that stayed
      silent later does not undo a different address that answered.
    - **Otherwise the newest measurement across the addresses wins.** This is
      what lets a port stop answering: an address's own later silence supersedes
      its own earlier connect, because that later row is this address's newest.

    Every address ever seen is kept in `targets`, sorted for a stable render, so
    the renderer can name where the port was probed.

    Since 2026-09-08 each address's row is itself the answer across the
    vantages that measured it (`_resolve_target`), and the cell carries whether
    any address's vantages disagreed, plus every vantage's view of every
    address, in address order then vantage order.
    """
    resolved = list(rows_by_target.values())
    rows = [entry["row"] for entry in resolved]
    connected = [r for r in rows if r["state"] == prober.STATE_CONNECTED]
    chosen = max(connected or rows, key=_measured_sort_key)
    targets = sorted({r["target"] for r in rows if r["target"]})
    views = []
    for entry in sorted(resolved, key=lambda e: e["row"]["target"] or ""):
        views.extend(entry["views"])
    return {"state": chosen["state"], "reason": chosen["reason"],
            "measured_at": chosen["measured_at"], "run_id": chosen["run_id"],
            "vantage": chosen["vantage"], "targets": targets,
            "disagree": any(entry["disagree"] for entry in resolved),
            "views": tuple(views)}


def _probe_index(con: sqlite3.Connection, host_id: int,
                 every_row: bool = False) -> dict:
    """The newest measurement for each (family, port), merged across every run.

    **Why every run and not the newest one.** Two probing lanes are planned
    (`docs/PRODUCT.md` section 5): a fast lane over the joined port set, and a
    broad sweep of ports nothing reports, each stored as its own run over its
    own port set. Reading only `prober.latest_run` made a port that only the
    broad sweep covers read `not tested` the moment any other lane's run became
    newest, because that newest run never measured it. Reading the newest
    measurement per port instead lets the two lanes coexist: a port the broad
    sweep measured an hour ago and the fast lane never covers keeps its hour-old
    answer, and a port both cover shows whichever was measured last.

    **Staleness is a separate axis and is deliberately not handled here.** How
    old a measurement may be before it should not be trusted is watched
    elsewhere (the outside-view-stale sweep in `ops/RUNBOOK.md`), and every cell
    carries its own `measured_at` so a screen can show its age. This function
    only decides which measurement is the current one, never whether it is too
    old to use, so it applies no freshness window.

    A cell keyed `(family, port)` absent from every run stays absent, so
    `_outside_view` reads it as `not tested`. A port measured nowhere never
    borrows a neighbour's answer, which is `docs/PRODUCT.md` 4b's not-tested
    rule.
    """
    if not (_table_exists(con, "probe_runs") and _table_exists(con, "probe_results")):
        return {}
    # Per (family, port), keep each target address's newest row. Grouping by
    # target is what makes the family merge honest across runs: each address
    # contributes its own latest answer, so the same address answering then
    # falling silent is read as silence, while two different addresses are read
    # per the connect-on-any-address rule in _resolve_cell.
    #
    # Within a target, one slot per vantage, so two boxes each keep their own
    # newest answer and neither overwrites the other's. Which of them names
    # the cell is `_resolve_target`'s decision, made from both rather than
    # from whichever ran last.
    #
    # The rows come from `probe_latest`, which the database keeps as the
    # newest result per slot, so this reads a few dozen rows and not every one
    # the host ever had (`prober.LATEST_SCHEMA`, docs/RECORD.md 4.192). The
    # loop below is unchanged and still decides what newest means among what
    # it is handed. `every_row` reads the whole history the old way, for a
    # database with no such table and for the test that holds the two equal.
    watched = _watched_vantages(con)
    sources = _vantage_sources(con)
    per_key: dict[tuple[str, int], dict] = {}
    if every_row or not prober.has_latest(con):
        rows = prober.host_results(con, host_id)
    else:
        rows = prober.host_latest_results(con, host_id)
    for row in rows:
        port = row["port"]
        family = row["family"]
        if port is None or family is None:
            continue
        by_target = per_key.setdefault((family, port), {})
        # A row with no target names no address, for instance a family this
        # host has no address in. They share one slot because there is no
        # address to tell them apart, and the newest of them wins like any slot.
        target = row["target"]
        by_vantage = by_target.setdefault(target, {})
        current = by_vantage.get(row["vantage"])
        if current is None or _measured_sort_key(row) > _measured_sort_key(current):
            by_vantage[row["vantage"]] = row
    return {
        key: _resolve_cell({target: _resolve_target(by_vantage, watched, sources)
                            for target, by_vantage in by_target.items()})
        for key, by_target in per_key.items()}


# ------------------------------------------------------------- the inside view

def _listening(doc, protocol, port, family):
    out = []
    for entry in _dicts(_mapping(doc.get("sockets")).get("listening")):
        if entry.get("protocol") != protocol or entry.get("port") != port:
            continue
        if entry.get("family") != family:
            continue
        out.append(_socket(entry))
    return tuple(out)


def _socket(entry) -> ListeningSocket:
    """One listening socket from the document, every field type-checked."""
    pid = entry.get("pid")
    unit, owner_name, owner_uid = (entry.get("unit"), entry.get("owner_name"),
                                   entry.get("owner_uid"))
    return ListeningSocket(
        process_name=str(entry.get("process_name") or ""),
        bind_address=str(entry.get("bind_address") or ""),
        pid=pid if isinstance(pid, int) and not isinstance(pid, bool) else None,
        unit=unit if isinstance(unit, str) else "",
        owner_name=owner_name if isinstance(owner_name, str) else "",
        owner_uid=(owner_uid if isinstance(owner_uid, int)
                   and not isinstance(owner_uid, bool) else None))


def _publication_family(host_ip):
    """The family a published host port was bound in, or None when it cannot be
    read. `0.0.0.0` is the v4 wildcard and `::` the v6 one, and neither is
    evidence about the other family, so nothing here maps one onto both.
    """
    if not isinstance(host_ip, str) or not host_ip:
        return None
    try:
        return "v6" if ipaddress.ip_address(host_ip).version == 6 else "v4"
    except ValueError:
        return None


def _publications(doc, protocol, port):
    found = []
    containers = _mapping(doc.get("containers"))
    for runtime in ("docker", "podman"):
        for container in _dicts(containers.get(runtime)):
            for published in _dicts(container.get("ports")):
                if published.get("host_port") != port:
                    continue
                if published.get("protocol") != protocol:
                    continue
                host_ip = published.get("host_ip")
                found.append(Publication(
                    runtime=runtime,
                    container=str(container.get("name") or container.get("id") or ""),
                    host_ip=str(host_ip or ""),
                    family=_publication_family(host_ip)))
    return tuple(found)


def _publications_in_family(publications, family):
    """Publications that could be serving this family.

    A publication whose bind address could not be read counts for both, because
    the claim being tested is "nothing is behind this rule" and an unreadable
    bind address is not evidence that nothing is.
    """
    return tuple(p for p in publications if p.family in (family, None))


def _is_v6_wildcard(address) -> bool:
    if not isinstance(address, str) or not address:
        return False
    try:
        return ipaddress.ip_address(address) == V6_WILDCARD
    except ValueError:
        return False


def _wildcard_sockets(doc, protocol, port, family):
    """The sockets on the IPv6 wildcard that may be serving this port on v4.
    Empty for v6, for the reason `_ambiguous_binds` gives."""
    if family != FAMILY_V4:
        return ()
    return tuple(
        _socket(entry)
        for entry in _dicts(_mapping(doc.get("sockets")).get("listening"))
        if entry.get("protocol") == protocol and entry.get("port") == port
        and entry.get("family") == FAMILY_V6
        and _is_v6_wildcard(entry.get("bind_address")))


def _ambiguous_binds(doc, protocol, port, family):
    """Things bound on the IPv6 wildcard, when the family being answered is v4.

    See V6_WILDCARD for why. Empty for v6, always, because the ambiguity has a
    direction: a v4 socket cannot take a v6 connection.
    """
    if family != FAMILY_V4:
        return ()
    # Named the way every other socket is, the process, else the unit the
    # kernel named. It read the process name alone until 2026-09-27, so under
    # agent 0.1.10, which sends none, every such v4 port was quoted as "an
    # unnamed process on ::" beside a Services tab that named it (record 4.200).
    found = [Quote(layer=LAYER_SERVICE, source="listening socket",
                   text=f"{socket.name} on ::", note=NOTE_V6_WILDCARD_MAY_SERVE_V4)
             for socket in _wildcard_sockets(doc, protocol, port, family)]
    for publication in _publications(doc, protocol, port):
        if publication.family != FAMILY_V6 or not _is_v6_wildcard(publication.host_ip):
            continue
        found.append(Quote(
            layer=LAYER_SERVICE,
            source=f"{publication.runtime} container {publication.container}",
            text=f"publishes this port on {publication.host_ip}",
            note=NOTE_V6_WILDCARD_MAY_SERVE_V4))
    return tuple(found)


def _legacy_rule_count(doc):
    total = 0
    for key in ("iptables", "ip6tables"):
        for table in _dicts(_mapping(doc.get(key)).get("tables")):
            for chain in _dicts(table.get("chains")):
                total += len(_dicts(chain.get("rules")))
    return total


def _dedupe(quotes):
    """One quote per (source, text).

    The walk follows every branch, so a chain reached down two different paths
    has its rules read twice. On the packet path screen that is correct,
    because both branches are shown. Here it produced the same accept rule as
    two identical quotes on the production copy, which tells a reader nothing.
    The counts below are not deduplicated, so nothing about how many rules were
    walked changes.
    """
    seen, out = set(), []
    for quote in quotes:
        key = (quote.source, quote.text)
        if key in seen:
            continue
        seen.add(key)
        out.append(quote)
    return tuple(out)


# The token the agent writes a reject as, last in the rule, when it does not
# spell out what the reject answers with (`fall("reject")` in
# `agent/internal/collect/nftrender_linux.go`).
_REJECT_TOKEN = "[reject]"


def _turns_away(text: str) -> bool:
    """Whether the rule's own verdict is drop or reject.

    Token based, as `_is_accept` is and for its reason: a jump to a chain
    whose name ends like a verdict is a jump.
    """
    tokens = (text or "").split()
    if not tokens or tokens[-1] not in ("drop", "reject", _REJECT_TOKEN):
        return False
    return not (len(tokens) >= 2 and tokens[-2] in ("jump", "goto"))


def _reject_read_as_written(text: str, rendered: str):
    """The rule's text and grade with the agent's reject token read as the
    verdict it is, for asking whether the rest names the port.

    Every part the agent could not read is a bracketed token, so when no
    bracket is left once this one is read, the rest was read in full and is
    graded so. The same reading `_limit_set_aside` gives a rate limit.
    """
    tokens = (text or "").split()
    if not tokens or tokens[-1] != _REJECT_TOKEN:
        return text, rendered
    left = " ".join(tokens[:-1] + ["reject"])
    return left, ("full" if "[" not in left else rendered)


def _deny_rules(hits, protocol, port, family):
    """The rules among `hits` that name this port and turn the packet away,
    for a packet of `family`, as quotes in the order the walk met them.

    Held to what a permit is held to: a filter chain on a hook an incoming
    packet passes, a rule readable in full that names this port, not pinned
    to the other family, and reached by jumps a packet of this family
    takes. Its own conditions are not judged. The quote carries them as
    written.
    """
    quotes = []
    for hit in hits:
        if not _is_permit_chain(hit) or not _turns_away(hit.text):
            continue
        text, rendered = _reject_read_as_written(hit.text, hit.rendered)
        if classify_rule(text, rendered, protocol, port) != NAMES_PORT:
            continue
        pinned = _rule_family(text)
        if pinned is not None and pinned != family:
            continue
        if _path_shape(hit.path, protocol, port, family) is None:
            continue
        quotes.append(Quote(layer=LAYER_HOST_FIREWALL, source=hit.source,
                            text=hit.text, rendered=hit.rendered))
    return quotes


def _inside_view(doc, protocol, port, family, legacy_count):
    hits, counts = _rules_for_port(doc, family, protocol, port)
    permits, narrowed, rate_limits = [], [], []
    # (source, text) of a narrowed rule to the network it permits, or to None
    # when it is narrowed any other way. See `InsideView.narrowed_to_sources`.
    plain: dict = {}
    for hit in hits:
        # Asked before the verdict check below, because every token a rate
        # limit can arrive in is a bracketed fallback and `classify_rule`
        # therefore calls such a rule UNREADABLE rather than NAMES_PORT. See
        # LIMIT_MODULE_TOKENS. Nothing is taken out of the two buckets below by
        # this: a rule carrying one of those tokens could never have reached
        # `_accept_shape` in the first place.
        module = (_limit_module(hit.text, protocol, port, family)
                  if _is_permit_chain(hit) else None)
        text, verdict = hit.text, hit.verdict
        if module:
            rate_limits.append(Quote(layer=LAYER_HOST_FIREWALL, source=hit.source,
                                     text=hit.text, rendered=hit.rendered,
                                     note=NOTE_RULE_LIMITS_THE_RATE,
                                     limit_module=module))
            # **A rate-limited permit is an answer too** (`docs/PRODUCT.md`
            # 8d, 4.209). nftables' own limit sits in the rule that accepts,
            # so that one rule is the mark above and may be the permit below,
            # read with its limit set aside. `recent` and `hashlimit` are
            # marks only. `recent` is how ufw counts connections and its
            # rules accept nothing themselves, and it is also how a list of
            # addresses seen before is matched, which is a narrowing. No
            # host in the fleet carries `hashlimit`.
            if module != "limit":
                continue
            text, rendered = _limit_set_aside(hit.text, hit.rendered)
            verdict = classify_rule(text, rendered, protocol, port)
        if verdict != NAMES_PORT or not _is_permit_chain(hit):
            continue
        left = _left_over(text, protocol, port, family)
        shape = None if left is None else ("narrowed" if left else "unconditional")
        if shape is None and hit.jumps_to_bare_accept:
            # ufw's `limit`, and anything else shaped like it: the rule
            # names the port and hands the packet to a chain that only
            # accepts. Read as the accept it leads to.
            shape = _accept_shape(_jump_as_accept(text), protocol, port, family)
        if shape is None:
            continue
        # The jumps that led here count with the rule itself. A permit
        # reached only for some source addresses is narrowed, and one behind
        # a jump the other family takes is not this family's rule at all.
        reached = _path_shape(hit.path, protocol, port, family)
        if reached is None:
            continue
        if reached == "narrowed":
            shape = "narrowed"
        quote = Quote(layer=LAYER_HOST_FIREWALL, source=hit.source,
                      text=hit.text, rendered=hit.rendered)
        (permits if shape == "unconditional" else narrowed).append(quote)
        if shape == "narrowed":
            # A plain narrowing by source address is the rule's own accept, on
            # the input hook, behind jumps that leave no condition, with no
            # rate limit set aside. A forwarded packet passes prerouting, so
            # a rule there was on its way and is not this.
            network = None
            if left and not module and hit.base_hook == "input" \
                    and reached == "unconditional":
                network = _plain_source(left, family)
            key = (quote.source, quote.text)
            # A rule reached down two paths is plain only when both say so.
            plain[key] = network if plain.get(key, network) == network else None
    # One rule can be reached down two paths, firewalld's public zone is: once
    # on the interface and once as the default. Where one path is open the
    # rule is a permit, and it is not also listed as narrowed.
    permitted = {(quote.source, quote.text) for quote in permits}
    narrowed = [quote for quote in narrowed
                if (quote.source, quote.text) not in permitted]
    networks = [plain.get((quote.source, quote.text)) for quote in _dedupe(narrowed)]
    return InsideView(
        sockets_status=str(_mapping(doc.get("sockets")).get("status") or "not collected"),
        nftables_status=str(_mapping(doc.get("nftables")).get("status") or "not collected"),
        sockets=_listening(doc, protocol, port, family),
        publications=_publications_in_family(_publications(doc, protocol, port), family),
        ambiguous_binds=_ambiguous_binds(doc, protocol, port, family),
        wildcard_sockets=_wildcard_sockets(doc, protocol, port, family),
        permit_rules=_dedupe(permits),
        narrowed_rules=_dedupe(narrowed),
        narrowed_to_sources=tuple(networks) if networks and all(networks) else (),
        rate_limit_rules=_dedupe(rate_limits),
        deny_rules=_dedupe(_deny_rules(hits, protocol, port, family)),
        rules_naming_port=counts[NAMES_PORT],
        unreadable_rule_count=counts[UNREADABLE],
        legacy_rule_count=legacy_count)


def inside_view(doc, protocol: str, port: int, family: str) -> InsideView:
    """What a host's document says of one port on one address family.

    For a reader that holds the document and no finding for that family.
    Nothing listens there and nothing was measured, so no finding was made,
    and the rules of that family may still name the port: the card of such a
    family said "no rule names 5432" without anybody having looked
    (`docs/RECORD.md` 4.454). This is the function the findings themselves
    are built with, so the two cannot say different things of one family.
    """
    return _inside_view(doc, protocol, port, family, _legacy_rule_count(doc))


def _no_agent_view() -> InsideView:
    """The inside view of a host that has no agent. Nothing collected, and
    `absent` says why, so nobody downstream reads this as a document that
    failed."""
    return InsideView(sockets_status="not collected", nftables_status="not collected",
                      absent=True)


# ----------------------------------------------------------- the provider view

@dataclass
class _Provider:
    """The provider snapshot resolved to one host, worked out once per host
    rather than once per port.

    `configured` and `readable` are separate on purpose. Nobody has connected a
    token, a token is connected and the snapshot is unparseable, and a snapshot
    that simply does not hold this host are three different facts, and only two
    of them are somebody's problem.
    """
    configured: bool = False
    readable: bool = True
    server: object | None = None
    inventory: object | None = None
    notes: tuple = ()


def _workspace_of(host) -> int:
    """The host row's workspace, and workspace 1 for a row from before the
    column, which is where every such row was backfilled."""
    try:
        value = host["workspace_id"]
    except (KeyError, IndexError):
        return db.DEFAULT_WORKSPACE_ID
    return value if isinstance(value, int) else db.DEFAULT_WORKSPACE_ID


def _proved_addresses(con: sqlite3.Connection, host_id) -> list:
    """The addresses this host has proved and may be probed on right now,
    which is what names its server at the provider (`hetzner.match_in_projects`).
    Empty when the registry does not exist yet or the host is not given."""
    if host_id is None or not _table_exists(con, "authorizations"):
        return []
    return [row["target"] for row in authz.live_addresses_for_host(con, host_id)]


def _provider_for_host(con: sqlite3.Connection, hostname: str | None,
                       workspace_id: int = db.DEFAULT_WORKSPACE_ID,
                       host_id: int | None = None) -> _Provider:
    """The provider view for one host, from its own workspace's snapshots and
    no other's: a customer's cloud firewall is read with their token and
    can only ever be attached to their hosts (record 4.178).

    **Every project the workspace holds a token for** (record 4.206). Until
    2026-09-29 this read the first token's snapshot only, so a server in a
    second project was "no matching server" however plainly it was listed."""
    if not _table_exists(con, "provider_snapshots"):
        return _Provider(configured=False, notes=(NOTE_PROVIDER_ABSENT,))
    snapshots = [snapshot for _token_id, snapshot
                 in hetzner.latest_snapshots(con, workspace_id)
                 if snapshot is not None]
    if not snapshots:
        return _Provider(configured=False, notes=(NOTE_PROVIDER_ABSENT,))
    inventories, unreadable = [], False
    for snapshot in snapshots:
        try:
            inventories.append(hetzner.parse_snapshot(snapshot))
        except hetzner.ProviderError:
            # A snapshot we cannot parse is not a provider that says nothing.
            # The two are different and only one of them is our problem.
            unreadable = True
    # By the addresses the host proved, and by the name its document carries
    # only when no address names a server, across every project. One rule, in
    # `hetzner.match_in_projects`, which says why. The name match is exact
    # apart from case: the production fleet's own documents carry `Almabox`
    # while the control plane knows the host as `almabox`.
    found = hetzner.match_in_projects(
        inventories, hostname, _proved_addresses(con, host_id))
    if found is None:
        # A project we could not read might be the one that lists this host,
        # so that is what is said, rather than that no project lists it.
        if unreadable:
            return _Provider(configured=True, readable=False,
                             notes=(NOTE_PROVIDER_UNREADABLE,))
        return _Provider(configured=True, notes=(NOTE_PROVIDER_NO_MATCH,))
    place, server = found
    result = _Provider(configured=True)
    # The inventory of the project that listed the server, never another's:
    # firewall ids are the provider's per project, so another project's
    # firewall 3 is a different firewall.
    result.inventory = inventories[place]
    result.server = server
    return result


def _port_in_provider_range(port_text, port):
    """Whether the provider's `port` field covers `port`, and whether it names
    it exactly.

    The field is "Port or port range to apply the rule for", a string like `80`
    or `1024-5000`, and it stays a string in `app/hetzner.py` because expanding
    a range would be us reshaping their evidence. Returns (covers, exact).
    """
    if not isinstance(port_text, str) or not port_text.strip():
        return False, False
    text = port_text.strip()
    if text.isdigit():
        return int(text) == port, int(text) == port
    if "-" in text:
        low, _, high = text.partition("-")
        if low.strip().isdigit() and high.strip().isdigit():
            return int(low) <= port <= int(high), False
    return False, False


def _render_provider_rule(rule) -> str:
    """The provider gives structured fields and no rule text, so this renders
    them in one fixed order. Only `description` is the provider's own words."""
    sources = ", ".join(rule.source_ips.v4 + rule.source_ips.v6
                        + rule.source_ips.unparsed) or "no source listed"
    text = f"{rule.direction} {rule.protocol} {rule.port or 'any port'} from {sources}"
    if rule.description:
        text += f" ({rule.description})"
    return text


# The provider's own spelling for any address of a family, per its firewall
# spec: "Use `0.0.0.0/0` to allow any IPv4 addresses and `::/0` to allow any
# IPv6 addresses" (app/hetzner.py).
ANY_V4, ANY_V6 = "0.0.0.0/0", "::/0"


def _provider_view(provider: _Provider, protocol, port, family):
    """The provider rules that permit this port in this family, and the notes
    that go with them."""
    notes = list(provider.notes)
    if not provider.configured or provider.server is None:
        return ProviderView(configured=provider.configured, matched=False), notes, False

    quotes, narrowed = [], []
    exact_named = False
    for attached, firewall in provider.inventory.firewalls_for_server(provider.server.id):
        if firewall is None:
            # The server names a firewall the firewalls fetch did not return,
            # which is a real race between two GETs. Reporting that as "no
            # firewall" would be inventing a finding.
            if NOTE_PROVIDER_FIREWALL_MISSING not in notes:
                notes.append(NOTE_PROVIDER_FIREWALL_MISSING)
            continue
        if attached.status != "applied":
            # The spec's own values are `applied` and `pending`. Pending is not
            # applied, so it is never read as a permit.
            if NOTE_PROVIDER_FIREWALL_PENDING not in notes:
                notes.append(NOTE_PROVIDER_FIREWALL_PENDING)
            continue
        for rule in firewall.rules:
            if rule.direction != "in" or rule.protocol != protocol:
                continue
            covers, exact = _port_in_provider_range(rule.port, port)
            if not covers:
                continue
            addresses = rule.source_ips.v4 if family == "v4" else rule.source_ips.v6
            if not addresses:
                # A rule listing only `0.0.0.0/0` says nothing at all about
                # IPv6 (PRODUCT.md 4b), so it is not this family's evidence.
                continue
            exact_named = exact_named or exact
            if not exact and NOTE_PROVIDER_RANGE_NOT_ENUMERATED not in notes:
                notes.append(NOTE_PROVIDER_RANGE_NOT_ENUMERATED)
            quote = Quote(layer=LAYER_PROVIDER,
                          source=f"{hetzner.PROVIDER} firewall {firewall.name}",
                          text=_render_provider_rule(rule))
            # The whole family is the provider's own spelling for "any
            # address" (`0.0.0.0/0`, `::/0`). Anything else permits from
            # some addresses only.
            whole = ANY_V4 if family == "v4" else ANY_V6
            (quotes if whole in addresses else narrowed).append(quote)
    view = ProviderView(configured=True, matched=True,
                        server_name=provider.server.name, rules=tuple(quotes),
                        narrowed=tuple(narrowed))
    return view, notes, exact_named


# ------------------------------------------------------------- port enumeration

def _ports_from_sockets(doc):
    found = set()
    for entry in _dicts(_mapping(doc.get("sockets")).get("listening")):
        protocol, port, family = (entry.get("protocol"), entry.get("port"),
                                  entry.get("family"))
        if not isinstance(port, int) or isinstance(port, bool):
            continue
        if not isinstance(protocol, str) or family not in FAMILIES:
            continue
        found.add((protocol, port, family))
    return found


def _ports_from_publications(doc):
    """A published port is a port worth answering for in whichever family it
    was bound. An unreadable bind address answers for both, because dropping it
    would leave the port off the page entirely."""
    found = set()
    containers = _mapping(doc.get("containers"))
    for runtime in ("docker", "podman"):
        for container in _dicts(containers.get(runtime)):
            for published in _dicts(container.get("ports")):
                protocol, port = published.get("protocol"), published.get("host_port")
                if not isinstance(port, int) or isinstance(port, bool):
                    continue
                if not isinstance(protocol, str):
                    continue
                family = _publication_family(published.get("host_ip"))
                for one in ((family,) if family else FAMILIES):
                    found.add((protocol, port, one))
    return found


def _ports_from_accept_rules(doc):
    """Ports that some readable accept rule names on the local-delivery path.

    This is the pass that lets `stale rule` exist at all: a port nothing is
    listening on is not in the document's socket list, so without this it would
    never be asked about. It proposes only, and the per-port walk below decides
    everything.

    An accept whose protocol or port cannot be read proposes nothing, because a
    proposal we cannot classify becomes a row that says nothing.
    """
    found = set()
    for family in FAMILIES:
        for _, table, chain in _base_chains(doc, family, LOCAL_HOOKS):
            if str(chain.get("type") or "") != _PERMIT_CHAIN_TYPE:
                continue
            if str(chain.get("hook") or "") not in _PERMIT_HOOKS:
                continue
            hits, _ = _walk(table, chain, None, None,
                            base_hook=str(chain.get("hook") or ""),
                            base_type=str(chain.get("type") or ""))
            for hit in hits:
                # The two rate-limited permits of `docs/PRODUCT.md` 8d
                # propose a port the way a plain accept does, so a limit
                # rule with nothing behind it can read as a stale rule.
                text, rendered = _limit_set_aside(hit.text, hit.rendered)
                if not _is_accept(text) and not hit.jumps_to_bare_accept:
                    continue
                readable = _COMMENT_MATCH.sub("", text)
                if "[" in readable or _has_unreadable_payload(readable):
                    continue
                # An `inet` table is walked for both families. A rule in it
                # that pins itself to one proposes a row for that one only.
                if _rule_family(readable) not in (None, family):
                    continue
                proto_match = _L4PROTO.search(readable)
                if proto_match is None:
                    continue
                protocol = proto_match.group(1)
                if protocol not in (PROTOCOL_TCP, PROTOCOL_UDP):
                    continue
                ports = _DPORT.findall(readable)
                # One destination port, compared for equality. A range or a
                # negation names no single port to propose.
                if len(ports) != 1 or ports[0][0]:
                    continue
                port = int(ports[0][1])
                # The proposal is confirmed by the same function that will
                # classify it later, so a rule cannot be proposed here and
                # then read differently below. The `rendered` grade is checked
                # inside it, which matters for the commonest rule ufw writes:
                # the agent grades it partial and it becomes readable only
                # once the comment match is dropped.
                if classify_rule(text, rendered, protocol, port) != NAMES_PORT:
                    continue
                # A permit behind a jump that narrows it, or that this family
                # never takes, proposes nothing: no rule opens this port to
                # everyone, so there is no rule for it to be stale.
                if _path_shape(hit.path, protocol, port, family) != "unconditional":
                    continue
                found.add((protocol, port, family))
    return found


def _ports_from_provider(provider: _Provider):
    """Ports a provider rule names exactly.

    A range never enumerates. `1024-5000` would put 3,977 rows on a screen and
    every one of them would be a port nobody mentioned. A range still annotates
    a port some other view already raised, which is where it belongs.
    """
    found = set()
    if provider.server is None:
        return found
    for attached, firewall in provider.inventory.firewalls_for_server(provider.server.id):
        if firewall is None or attached.status != "applied":
            continue
        for rule in firewall.rules:
            if rule.direction != "in" or rule.protocol not in (PROTOCOL_TCP, PROTOCOL_UDP):
                continue
            if not isinstance(rule.port, str) or not rule.port.strip().isdigit():
                continue
            port = int(rule.port.strip())
            if rule.source_ips.v4:
                found.add((rule.protocol, port, "v4"))
            if rule.source_ips.v6:
                found.add((rule.protocol, port, "v6"))
    return found


def _ports_from_declarations(intent):
    """Every port the operator declared, so a port added under Probing on
    the server's settings is on its Overview at once, reading not tested
    until the prober measures it (the owner, 2026-09-08, `docs/RECORD.md`
    4.155). Only a mapping
    can be walked; a callable intent declares nothing here."""
    if not isinstance(intent, dict):
        return set()
    return {(protocol, port, family) for (protocol, port, family) in intent
            if isinstance(port, int)}


# How long a port nothing names stays a row after its newest measurement,
# and in the fast lane after its state went to nothing (`app/dispatch.py`).
# The owner, 2026-09-27 (docs/RECORD.md 4.207). THIS IS THE OWNING DEFINITION.
FORGOTTEN_AFTER_SECONDS = 24 * 60 * 60


def _forgotten(index, key, document_time) -> bool:
    """Whether a port only the probe history names has stopped being a row.

    It has when its newest measurement is a silence taken more than a day
    before the newest document. The fast lane stops probing such a port after
    a day with no state, so its measurement then ages while the reports keep
    arriving, and "nothing listening" beside a day-old silence says nothing
    anybody can use. A connect is never forgotten: a port that answered with
    nothing on the host owning it is `unexplained`, which is a finding. The
    document is the clock rather than the wall, so the answer is the same on
    every render of the same data.
    """
    _protocol, port, family = key
    cell = index.get((family, port))
    if cell is None or cell["state"] == prober.STATE_CONNECTED:
        return False
    if cell["state"] not in prober.MEASURED_STATES:
        return False
    measured = _parse_time(cell["measured_at"])
    if measured is None or document_time is None:
        return False
    age = (_as_utc(document_time) - _as_utc(measured)).total_seconds()
    return age > FORGOTTEN_AFTER_SECONDS


def _ports_from_probe(index):
    """Every (family, port) with a measurement, unioned across every run.

    This is what lets `unexplained` exist: a port the outside view connected to
    that the document does not list. It is the union across runs by
    construction, because `_probe_index` already merged every run into one cell
    per key, so a port only the broad sweep measured is here even when a later
    fast-lane run never covered it. A key absent from every run is absent here
    too and reads `not tested`, never a state. Only TCP, because that is all the
    prober measures.
    """
    return {(PROBED_PROTOCOL, port, family) for (family, port) in index}


# --------------------------------------------------------------- the join

def _intent_for(intent, protocol, port, family):
    """Intent is a mapping or a callable.

    `host_findings` resolves `None` into this host's stored declarations before
    calling here, so `None` arriving at this point means a caller asked for no
    declarations at all. Anything that is not one of the two words is read as no
    declaration, because a value we do not understand is not a declaration we
    can act on.
    """
    if intent is None:
        return None
    key = (protocol, port, family)
    value = intent(*key) if callable(intent) else intent.get(key)
    return value if value in INTENTS else None


def _acknowledgement_for(acknowledgements, protocol, port, family, state):
    """When this exact finding was acknowledged, or None.

    The stored state has to equal the state just decided. An acknowledgement is
    about a finding rather than about a port, so a port whose state changed
    carries a different finding and the acknowledgement no longer applies to
    it. `state` of None never matches, because the stored value is always one
    of the five words.
    """
    seen = acknowledgements.get((protocol, port, family))
    if seen is None or seen[0] != state:
        return None
    return seen[1]


def _decide(inside: InsideView, outside: OutsideView, provider: ProviderView,
            declared: str | None):
    """The state, the layer and the quotes. The whole decision, in one place.

    Read it as two branches. Above the line, the outside view completed a
    connection and the question is who owns the port and what was declared
    about it. Below the line, nothing reached this port from outside, or
    nothing tried, and the only thing that can still be said is that a rule
    permits a port with nothing behind it.
    """
    quotes: list[Quote] = []

    if inside.absent:
        return _decide_without_an_agent(outside, declared)

    if outside.connected:
        if inside.owns_the_port:
            quotes.extend(Quote(layer=LAYER_SERVICE, source="listening socket",
                                text=socket.text) for socket in inside.sockets)
            quotes.extend(
                Quote(layer=LAYER_SERVICE,
                      source=f"{p.runtime} container {p.container}",
                      text=f"publishes this port on {p.host_ip}")
                for p in inside.publications)
            quotes.extend(inside.ambiguous_binds)
            if declared == INTENT_CLOSED:
                return STATE_CONFLICT, LAYER_SERVICE, quotes
            if declared == INTENT_OPEN:
                return STATE_INTENDED, LAYER_SERVICE, quotes
            # The owner's decision, 2026-09-04 (docs/PRODUCT.md 8d): a rule the owner
            # wrote is the answer. A reachable port that an unconditional
            # permit rule in the host firewall or the provider firewall names
            # is `intended` without anyone clicking, and the rule is the layer
            # that decided. `unreviewed` is then what it should be: reachable
            # and no rule permits it. A declaration still wins over the rule,
            # which is why the two branches above come first, and a narrowed
            # rule is not an answer, which `_permits` already decides for the
            # stale rule below.
            permits = _permits(inside, provider)
            if _answered_outside_the_rules_source(inside, outside, provider, declared):
                # The one case where a provider's permit is not taken for the
                # answer. Both rules are quoted, the host's first.
                return (STATE_UNREVIEWED, LAYER_SERVICE,
                        quotes + list(inside.narrowed_rules) + list(provider.rules))
            if permits:
                return STATE_INTENDED, _permit_layer(provider), quotes + permits
            return STATE_UNREVIEWED, LAYER_SERVICE, quotes
        # Reachable and no part of this host owns it. Something else is
        # forwarding, or the agent could not see it. Naming a layer here would
        # be picking one, and the whole point of the state is that we cannot.
        return STATE_UNEXPLAINED, LAYER_NOT_DETERMINED, quotes

    # ------------------------------------------------------------------------
    # Nothing connected from outside, or nothing tried. Those are two different
    # facts and the line below is where they part.

    if inside.owns_the_port:
        if not outside.measured:
            # Nothing was tried, so there is nothing to compare a declaration
            # against. Naming a state here would state a finding nobody made,
            # which is the accuracy rule and the reason this branch exists.
            return None, LAYER_NOT_DETERMINED, quotes

        # Measured, and it did not answer. That is a finding, and the owner
        # decided on 2026-08-16 (RECORD 4.55) that it earns the same rules as
        # one that did answer, with reality inverted. It held up against
        # evidence: three passes from one vantage produced eight identical
        # results out of eight, so this is not one timeout being read as a
        # fact.
        #
        # **The two declared rules invert and the undeclared one does not.**
        # 4.55 said a sixth word was not needed and that was right about the
        # two declarations and wrong about the third case, which is why
        # `not reachable` exists (2026-08-28, RECORD 4.112). A port answering
        # the internet that nobody has declared is a queue entry. A port that
        # is shut and that nobody has declared is not, and calling both
        # `unreviewed` made the word unable to say which.
        #
        # The layer stays undetermined on purpose. Something between the
        # internet and this socket dropped the packet and the document does
        # not say which, so the quotes show that the host owns the port and
        # nothing here claims to know what stopped it.
        quotes.extend(Quote(layer=LAYER_SERVICE, source="listening socket",
                            text=socket.text) for socket in inside.sockets)
        quotes.extend(
            Quote(layer=LAYER_SERVICE,
                  source=f"{p.runtime} container {p.container}",
                  text=f"publishes this port on {p.host_ip}")
            for p in inside.publications)
        quotes.extend(inside.ambiguous_binds)
        if declared == INTENT_OPEN:
            return STATE_CONFLICT, LAYER_NOT_DETERMINED, quotes
        if declared == INTENT_CLOSED:
            return STATE_INTENDED, LAYER_NOT_DETERMINED, quotes
        return STATE_NOT_REACHABLE, LAYER_NOT_DETERMINED, quotes
    if inside.sockets_status != "collected":
        # "Nothing is listening" is half of a stale rule and this document
        # cannot say it.
        return None, LAYER_NOT_DETERMINED, quotes

    permits = _permits(inside, provider)
    if not permits:
        return None, LAYER_NOT_DETERMINED, quotes
    return STATE_STALE_RULE, _permit_layer(provider), permits


def _answered_outside_the_rules_source(inside: InsideView, outside: OutsideView,
                                       provider: ProviderView,
                                       declared: str | None) -> bool:
    """Whether a Docker port answered an address its host rule does not
    permit, while the provider's firewall permits everyone.

    A delegated decision of 2026-10-04 (`docs/PRODUCT.md` 8d,
    `docs/RECORD.md` 4.358, 4.365). Measured on a real server (4.309): the
    provider open to every address on a port, ufw permitting that port from
    one address, Docker publishing it, and both probers connected from
    addresses of their own. Docker carries a published port past ufw's input
    chain (`docs/PRODUCT.md` 4d), so the person had said who may reach the
    port and somebody else got an answer. The provider's permit is then not
    their answer, and the port asks.

    Every condition is read or measured, and each one missing leaves the port
    as it was:

    - the port answered, the host owns it, and nobody declared anything,
    - the provider holds an unconditional permit, the one not taken,
    - Docker publishes the port in this family, with a bind address that was
      read. Rootful Podman is not that bypass (4d), and a port a process of
      the host serves is out until a real server has shown that case,
    - the host's ruleset was read and no rule read in it permits everyone.
      A rule that was not fully read is never a permit, here as everywhere,
    - every narrowed host rule for the port is a plain narrowing by source
      address (`InsideView.narrowed_to_sources`),
    - a vantage that connected probes from addresses the registry holds, and
      every one of them is outside every one of those sources. A vantage
      whose addresses are not known is not compared, and neither is one with
      an address on each side.

    What this does not say: that the packet went round the rule. The engine
    does not walk the forward hook. It says a rule permits one source and an
    address outside that source got an answer.
    """
    if not (outside.connected and inside.owns_the_port and declared is None):
        return False
    if not provider.rules:
        return False
    if not any(p.runtime == "docker" and p.family is not None
               for p in inside.publications):
        return False
    if inside.nftables_status != "collected" or inside.permit_rules:
        return False
    if not inside.narrowed_to_sources:
        return False
    sources = [ipaddress.ip_network(source) for source in inside.narrowed_to_sources]
    for view in outside.views:
        if view.state != prober.STATE_CONNECTED or not view.probes_from:
            continue
        held = [ipaddress.ip_address(address) for address in view.probes_from]
        if not any(address in source for address in held for source in sources):
            return True
    return False


def _permits(inside: InsideView, provider: ProviderView) -> list:
    """Every unconditional permit for this port and family, provider rules
    first. The host firewall's rules count only when the ruleset was read,
    because a permit in a ruleset the agent could not read is not a rule
    anyone can be said to have written for this port."""
    return list(provider.rules) + list(
        inside.permit_rules if inside.nftables_status == "collected" else [])


def _permit_layer(provider: ProviderView) -> str:
    """The provider firewall is the outer layer and the one an operator
    manages somewhere else entirely, so when both hold a permit it is the one
    named. Both sets are quoted either way."""
    return LAYER_PROVIDER if provider.rules else LAYER_HOST_FIREWALL


def _decide_without_an_agent(outside: OutsideView, declared: str | None):
    """The state for a port on a host with no agent.

    The inside view abstains. Nothing on the host can say who owns the port
    or which layer let a packet through, so no layer is ever named and no
    rule is ever quoted: that is the honest half of tier 1 in
    docs/PRODUCT.md 3a, written as code. What remains is the outside
    measurement against the declaration, and those are the same rules an
    agent host gets (RECORD 4.55), for an answer and for a measured silence
    alike. That includes the undeclared pair: `unreviewed` when it answered
    and `not reachable` when it did not, exactly as on an agent host, because
    the question the word answers is about the measurement and not about how
    much of the host we could read. `stale rule` and `unexplained` can never
    arise here, since both assert something about the inside of the host.
    """
    if not outside.measured:
        return None, LAYER_NOT_DETERMINED, []
    if declared == INTENT_CLOSED:
        state = STATE_CONFLICT if outside.connected else STATE_INTENDED
    elif declared == INTENT_OPEN:
        state = STATE_INTENDED if outside.connected else STATE_CONFLICT
    else:
        state = STATE_UNREVIEWED if outside.connected else STATE_NOT_REACHABLE
    return state, LAYER_NOT_DETERMINED, []


def state_if_declared(finding: Finding, declared: str | None) -> str | None:
    """The state this exact port would carry if it were declared `declared`.

    `_decide` run again over the three views this finding already holds, so
    the answer is the engine's own rather than a second copy of its rules
    written somewhere else. A screen that offers `open` and `closed` on a row
    has to say what each of them would do to the row, and deriving that from
    the state and the outside word would be exactly the second spelling this
    module refuses everywhere else.

    `declared` is `open`, `closed`, or None for no declaration at all. No
    database and no I/O: the views were read when the finding was built, and
    a declaration changes none of them.

    **It answers for one port and one address family only**, the way every
    other answer here does, and a caller showing one word for a port asks it
    once per family and reconciles the answers itself.
    """
    if declared is not None and declared not in INTENTS:
        raise ValueError(f"unknown declaration {declared!r}")
    state, _layer, _quotes = _decide(finding.inside, finding.outside,
                                     finding.provider, declared)
    return state


def _notes_for(inside, outside, provider_notes, state, declared, revoked_at):
    notes = []
    if outside.state == prober.STATE_NOT_TESTED:
        notes.append(NOTE_OUTSIDE_NOT_MEASURED)
    if outside.precedes_document is True:
        notes.append(NOTE_OUTSIDE_PRECEDES_DOCUMENT)
    # With no document there is nothing for a measurement to precede, so the
    # unreadable-age note is about agent hosts only.
    if (outside.precedes_document is None and outside.reason != REASON_NOT_PROBED
            and not inside.absent):
        notes.append(NOTE_OUTSIDE_AGE_UNREADABLE)
    if state in STATES_FROM_A_DECLARATION and declared is None:
        notes.append(NOTE_NO_INTENT_DECLARED)
    if state == STATE_UNEXPLAINED:
        notes.append(NOTE_NOTHING_ON_THE_HOST_OWNS_IT)
    if inside.ambiguous_binds:
        notes.append(NOTE_V6_WILDCARD_MAY_SERVE_V4)
    if inside.absent:
        notes.append(NOTE_NO_AGENT)
    else:
        if inside.sockets_status != "collected":
            notes.append(NOTE_SOCKETS_NOT_READ)
        if inside.nftables_status != "collected":
            notes.append(NOTE_HOST_FIREWALL_NOT_READ)
    if inside.unreadable_rule_count:
        notes.append(NOTE_RULES_NOT_FULLY_READABLE)
    if inside.narrowed_rules and not inside.permit_rules:
        notes.append(NOTE_RULE_IS_NARROWED)
    if inside.rate_limit_rules:
        notes.append(NOTE_RULE_LIMITS_THE_RATE)
    if inside.legacy_rule_count:
        notes.append(NOTE_LEGACY_RULES_NOT_PLACED)
    if revoked_at:
        notes.append(NOTE_HOST_REVOKED)
    notes.extend(note for note in provider_notes if note not in notes)
    return tuple(notes)


def host_findings(con: sqlite3.Connection, host_id: int, *, intent=None,
                  provider=None) -> HostFindings | None:
    """Every finding for one host, or None when there is no such host.

    `intent` is a mapping of `(protocol, port, family)` to `open` or `closed`,
    or a callable of the same three arguments. Left alone it is this host's
    declarations from `app/intent.py`. An empty mapping is not the same as
    leaving it alone: it means no declarations, which is how a caller asks what
    the fleet would look like without them.

    `provider` is the resolved provider view and exists so a caller with many
    hosts resolves the snapshot once. Left alone it is read from the database.
    """
    host = con.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if host is None:
        return None

    if _host_kind(host) == db.HOST_KIND_ADDRESS:
        return _address_host_findings(con, host, intent=intent, provider=provider)

    report = _latest_report(con, host_id)
    if report is None:
        return HostFindings(
            host_id=host_id, host_name=host["name"], hostname=None,
            revoked_at=host["revoked_at"], paused=bool(host["paused"]),
            document_readable=False, received_at=None, collected_at_unix=None)

    try:
        doc = json.loads(report["document"])
    except (ValueError, TypeError):
        doc = None
    if not isinstance(doc, dict):
        return HostFindings(
            host_id=host_id, host_name=host["name"], hostname=None,
            revoked_at=host["revoked_at"], paused=bool(host["paused"]),
            document_readable=False, received_at=report["received_at"],
            collected_at_unix=report["collected_at_unix"])

    hostname = doc.get("hostname")
    hostname = hostname if isinstance(hostname, str) else None
    resolved = provider if provider is not None else _provider_for_host(
        con, hostname, _workspace_of(host), host_id=host_id)

    index = _probe_index(con, host_id)
    document_time = _parse_time(report["received_at"])

    legacy_count = _legacy_rule_count(doc)

    # Read here rather than above the early returns, because a host that has
    # never reported produces no findings and needs none of them.
    if intent is None:
        intent = intent_store.intents_for_host(con, host_id)
    acknowledgements = intent_store.acknowledgements_for_host(con, host_id)
    declared_names = intent_store.names_for_host(con, host_id)

    named = set()
    named |= _ports_from_sockets(doc)
    named |= _ports_from_publications(doc)
    named |= _ports_from_accept_rules(doc)
    named |= _ports_from_provider(resolved)
    named |= _ports_from_declarations(intent)
    candidates = named | {key for key in _ports_from_probe(index)
                          if key in named
                          or not _forgotten(index, key, document_time)}

    findings = []
    for protocol, port, family in sorted(candidates, key=lambda c: (c[1], c[0], c[2])):
        inside = _inside_view(doc, protocol, port, family, legacy_count)
        outside = _outside_view(protocol, port, family, index, document_time)
        provider_view, provider_notes, _ = _provider_view(resolved, protocol, port, family)
        declared = _intent_for(intent, protocol, port, family)
        state, layer, quotes = _decide(inside, outside, provider_view, declared)
        notes = _notes_for(inside, outside, provider_notes, state, declared,
                           host["revoked_at"])
        findings.append(Finding(
            protocol=protocol, port=port, family=family, state=state,
            intent=declared, inside=inside, outside=outside,
            provider=provider_view,
            cause=Cause(layer=layer, quotes=tuple(quotes), notes=notes),
            acknowledged=_acknowledgement_for(acknowledgements, protocol, port,
                                              family, state),
            declared_name=declared_names.get((protocol, port)),
            rate_limited=bool(inside.rate_limit_rules),
            answered_outside_the_rules_source=_answered_outside_the_rules_source(
                inside, outside, provider_view, declared)))

    return HostFindings(
        host_id=host_id, host_name=host["name"], hostname=hostname,
        revoked_at=host["revoked_at"], paused=bool(host["paused"]),
        document_readable=True, received_at=report["received_at"],
        collected_at_unix=report["collected_at_unix"],
        findings=_with_other_family_provider(findings, resolved),
        provider_configured=resolved.configured,
        provider_matched=resolved.server is not None)


def _with_other_family_provider(findings, resolved):
    """The findings, each port that has one family only carrying the
    provider's view of the other (`Finding.other_family_provider`).

    Nothing is added to the list and no state moves: the view rides on the
    finding that exists, for a screen to read."""
    present = {(f.protocol, f.port, f.family) for f in findings}
    out = []
    for finding in findings:
        others = [family for family in FAMILIES if family != finding.family
                  and (finding.protocol, finding.port, family) not in present]
        if len(others) == 1:
            view, _notes, _ = _provider_view(resolved, finding.protocol,
                                             finding.port, others[0])
            finding = replace(finding, other_family_provider=view)
        out.append(finding)
    return tuple(out)


def _host_kind(host) -> str:
    """The kind of a host row, agent for a row from before kinds existed."""
    return host["kind"] if "kind" in host.keys() else db.HOST_KIND_AGENT


def _address_host_findings(con: sqlite3.Connection, host, *, intent=None,
                           provider=None) -> HostFindings:
    """Every finding for a host that has no agent.

    The same loop as an agent host with the inside half removed: the ports
    are the ones the prober measured and the ones the provider names, the
    inside view is the abstaining one, and the outside view has no document
    to be older than. Declarations, acknowledgements and names read exactly
    as they do for any host, because those are the operator's and not the
    agent's.
    """
    host_id = host["id"]
    # An address host has no document and so no name of its own to match on.
    # Its proved addresses are all it has, and they are enough.
    resolved = provider if provider is not None else _provider_for_host(
        con, None, _workspace_of(host), host_id=host_id)
    index = _probe_index(con, host_id)
    if intent is None:
        intent = intent_store.intents_for_host(con, host_id)
    acknowledgements = intent_store.acknowledgements_for_host(con, host_id)
    declared_names = intent_store.names_for_host(con, host_id)

    candidates = set()
    candidates |= _ports_from_provider(resolved)
    candidates |= _ports_from_probe(index)
    candidates |= _ports_from_declarations(intent)

    findings = []
    for protocol, port, family in sorted(candidates, key=lambda c: (c[1], c[0], c[2])):
        inside = _no_agent_view()
        outside = _outside_view(protocol, port, family, index, None)
        provider_view, provider_notes, _ = _provider_view(resolved, protocol, port, family)
        declared = _intent_for(intent, protocol, port, family)
        state, layer, quotes = _decide(inside, outside, provider_view, declared)
        notes = _notes_for(inside, outside, provider_notes, state, declared,
                           host["revoked_at"])
        findings.append(Finding(
            protocol=protocol, port=port, family=family, state=state,
            intent=declared, inside=inside, outside=outside,
            provider=provider_view,
            cause=Cause(layer=layer, quotes=tuple(quotes), notes=notes),
            acknowledged=_acknowledgement_for(acknowledgements, protocol, port,
                                              family, state),
            declared_name=declared_names.get((protocol, port)),
            rate_limited=False))

    return HostFindings(
        host_id=host_id, host_name=host["name"], hostname=None,
        revoked_at=host["revoked_at"], paused=bool(host["paused"]),
        document_readable=True, received_at=None, collected_at_unix=None,
        findings=_with_other_family_provider(findings, resolved),
        provider_configured=resolved.configured,
        provider_matched=resolved.server is not None,
        kind=db.HOST_KIND_ADDRESS)


def _outside_view(protocol, port, family, index, document_time):
    """The outside view for one port, and the one place the absence of a
    measurement is turned into an answer.

    A UDP port never reads a row from this index. `probe_results` has no
    protocol column and `app/prober.py` connects with SOCK_STREAM, so every row
    is a TCP answer and attaching one to UDP would be reporting a measurement
    of a different protocol.

    The run id and vantage come from this port's own cell, which `_probe_index`
    filled from the run that took its newest measurement. Two ports on one host
    can therefore name two different runs, which is the point: they may have
    been measured by two different lanes.
    """
    if protocol != PROBED_PROTOCOL:
        return OutsideView(state=prober.STATE_NOT_TESTED, reason=REASON_NOT_PROBED)
    cell = index.get((family, port))
    if cell is None:
        return OutsideView(state=prober.STATE_NOT_TESTED, reason=REASON_NOT_PROBED)
    # Precedence is per cell, from when this port was measured, because across
    # runs each port carries its own measured_at. None stays None, never False.
    measured_time = _parse_time(cell["measured_at"])
    precedes = None
    if document_time is not None and measured_time is not None:
        precedes = _as_utc(measured_time) < _as_utc(document_time)
    return OutsideView(
        state=cell["state"], reason=cell["reason"],
        run_id=cell["run_id"], vantage=cell["vantage"],
        measured_at=cell["measured_at"], targets=tuple(cell["targets"]),
        precedes_document=precedes, disagree=cell["disagree"],
        views=cell["views"])


def fleet_findings(con: sqlite3.Connection, *, intent=None) -> list[HostFindings]:
    """Every host, in name order. The provider snapshot is resolved per host
    because the match is by the host's own hostname, and parsing it once per
    host is one JSON decode against a snapshot that is a few kilobytes.

    `intent` left alone means each host reads its own declarations, which is
    what one mapping across a whole fleet could never do: the same port number
    on two hosts is two different declarations.
    """
    out = []
    for host in con.execute("SELECT id FROM hosts ORDER BY name").fetchall():
        result = host_findings(con, host["id"], intent=intent)
        if result is not None:
            out.append(result)
    return out


# ------------------------------------------------------------- the description

def _held_by_docker(socket: ListeningSocket) -> bool:
    return socket.unit == "docker.service" or socket.process_name == "docker-proxy"


def describe(finding: Finding) -> str:
    """One plain sentence for one finding.

    The HTML renderer builds from the structured fields above rather than from
    this string. This exists because the vocabulary has to be testable, and
    `tests/test_join.py` asserts that nothing here ever says any of the words
    the writing rules forbids about our own output. It reports what each
    view said and which layer decided, and then it stops. It does not explain
    that posture either, because saying it out loud reads as covering
    ourselves.
    """
    where = f"{finding.protocol}/{finding.port} on {finding.family}"
    parts = [f"{where}:"]
    if finding.state:
        parts.append(f"{finding.state}.")

    if finding.outside.connected:
        parts.append("The outside view completed a connection.")
    elif finding.outside.measured:
        parts.append(f"The outside view answered {finding.outside.word}.")
    else:
        parts.append("The outside view is not tested.")

    # A container that publishes the port is named first, and the host socket
    # Docker holds for it is left out. That socket is named `docker.service`
    # by the kernel, or `docker-proxy` by its process, measured on a Docker host
    # (docs/AGENT-PRIVILEGE.md), and both name the runtime rather than what
    # answers. The Services tab names the container (docs/RECORD.md 4.184),
    # and until 2026-09-27 every mail about such a port said docker.service
    # instead (4.200).
    sockets = [s for s in finding.inside.sockets
               if not (finding.inside.publications and _held_by_docker(s))]
    if finding.inside.publications:
        published = ", ".join(
            f"{p.runtime} container {p.container} on {p.host_ip}"
            for p in finding.inside.publications)
        parts.append(f"The host publishes this port: {published}.")
        if sockets:
            listening = ", ".join(socket.text for socket in sockets)
            parts.append(f"The host is listening: {listening}.")
    elif sockets:
        listening = ", ".join(socket.text for socket in sockets)
        parts.append(f"The host is listening: {listening}.")
    elif finding.inside.ambiguous_binds:
        parts.append(f"The host is listening on the IPv6 wildcard: "
                     f"{finding.inside.ambiguous_binds[0].text}. The document "
                     "does not record whether that socket also takes IPv4.")
    elif finding.inside.sockets_status == "collected":
        parts.append("Nothing on this host is listening on it and no container "
                     "publishes it.")
    else:
        parts.append("The host could not read its own listening sockets.")

    if finding.cause.quotes and finding.cause.layer != LAYER_SERVICE:
        quote = finding.cause.quotes[0]
        verb = ("permits it" if finding.state in (STATE_STALE_RULE, STATE_INTENDED)
                else "names this port")
        parts.append(f"{finding.cause.layer} {verb}: {quote.text} in {quote.source}.")
    elif finding.inside.narrowed_rules:
        quote = finding.inside.narrowed_rules[0]
        parts.append(f"{LAYER_HOST_FIREWALL} names this port in a rule that is "
                     f"narrowed beyond the port: {quote.text} in {quote.source}.")
        if finding.answered_outside_the_rules_source:
            quote = finding.provider.rules[0]
            parts.append(f"{LAYER_PROVIDER} permits it: {quote.text} in "
                         f"{quote.source}.")

    # Its own sentence, never folded into the cause above. It says what the rule
    # does and it states no outcome, so it cannot read as the thing that
    # stopped a connection. The module is named because the parameters are not
    # in the document, and the rule is quoted verbatim like every other one.
    # It sits with the rule sentences above rather than with the operator's own
    # statements below, because it is a fact read off the host.
    if finding.inside.rate_limit_rules:
        quote = finding.inside.rate_limit_rules[0]
        parts.append(f"{LAYER_HOST_FIREWALL} matches this port on how recently "
                     f"and how often a connection was made, through the "
                     f"{quote.limit_module} module: {quote.text} in "
                     f"{quote.source}.")

    if finding.declared_name:
        # "You named" is the provenance: the sentence says a person typed it,
        # so it can never read as something the agent measured. It leads the
        # operator's own statements, the declared intent below being the rest.
        parts.append(f"You named this port {finding.declared_name}.")

    if finding.state in STATES_FROM_A_DECLARATION:
        if finding.intent == INTENT_CLOSED:
            parts.append("You declared this port closed.")
        elif finding.intent == INTENT_OPEN:
            parts.append("You declared this port open.")
        else:
            parts.append("Nobody has declared whether this port is meant to be "
                         "reachable.")

    if finding.acknowledged:
        parts.append("You have read this and said you are not acting on it.")

    if NOTE_OUTSIDE_PRECEDES_DOCUMENT in finding.cause.notes:
        parts.append("That measurement was taken before this document arrived.")
    if NOTE_RULES_NOT_FULLY_READABLE in finding.cause.notes:
        parts.append(f"{finding.inside.unreadable_rule_count} rules on this "
                     "path are not fully readable and may select this port.")
    if NOTE_LEGACY_RULES_NOT_PLACED in finding.cause.notes:
        parts.append(f"{finding.inside.legacy_rule_count} legacy iptables rules "
                     "on this host cannot be placed on the path.")
    return " ".join(parts)
