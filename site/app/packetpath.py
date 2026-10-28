#!/usr/bin/env python3
"""The packet path, inside view: every checkpoint an inbound packet meets on
its way to one port, in the order the kernel evaluates them.

This is half of `docs/PRODUCT.md` section 8 item 1. The other half, why a port
is *not* reachable, needed the prober, and since 2026-08-22 it is at the bottom
of this file under "the outward half" (`docs/RECORD.md` 4.91). It narrows where
to look and it names no cause. So nothing here concludes anything. It says which chains the packet is evaluated against, in
which order, and quotes the rules verbatim. The words reachable, allowed,
blocked and accepted do not appear in any string this module produces, and a
test pins that.

Pure functions over a host document, no HTML and no I/O, so the ordering and
the rule matching can be tested against real documents and against hostile
ones.

## Where the order comes from, and it is not from memory

Read from the kernel's own source at the torvalds/linux master tree on
2026-08-14, because the accuracy rule does not accept
"this is well known" for something this load-bearing:

  - `net/ipv4/ip_input.c`: `ip_rcv` calls
    `NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING, ..., ip_rcv_finish)`.
    `ip_rcv_finish` runs `ip_rcv_finish_core`, which calls
    `ip_route_input_noref` (the routing decision), then `dst_input`.
    `ip_local_deliver` calls `NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN, ...)`.
    So: prerouting, then the routing decision, then input.
  - `net/ipv4/ip_forward.c`: `ip_forward` calls
    `NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD, ...)`, which is the branch a
    packet takes when the routing decision did not choose local delivery.
  - `net/ipv6/ip6_input.c` carries the same two hooks for IPv6, at
    `NF_INET_PRE_ROUTING` and `NF_INET_LOCAL_IN`.
  - `net/netfilter/core.c`, in the hook-insert walk:
    `if (inserted || reg->priority > orig_ops[i]->priority)` keeps the array
    sorted by ascending priority, so **a lower priority number is evaluated
    first**. Equal priorities keep registration order, which a host document
    does not record, and this module says so rather than guessing.

Base-chain priorities are never assumed here. Every one of them is read from
the document, where the agent put what the kernel reported over netlink.

## What this cannot see, all of it said out loud on screen

  - **Legacy iptables rules are not placed on the path.** The agent stores an
    x_tables rule's match extensions by name only, so `--dport 22` arrives as
    `[xt match tcp]` with the port inside an undecoded payload. A legacy rule
    can therefore never be shown as naming a port, and pretending otherwise is
    exactly the failure section 4b exists to prevent. A host with legacy rules
    gets told they exist and are on the Rules tab.
  - **A port match this agent could not decode.** Sets (`[lookup @...]`),
    x_tables matches, raw header offsets that could reach a transport port
    (`@th,0,32`) and any rule graded below "full" may select this port without
    saying so in text. Those rules are shown, and labelled as not fully
    readable, never dropped.

    A raw load that provably cannot reach a port is not in that pile. A
    network-header load ending inside the fixed header, `@nh,96,16`, is part
    of an address, and calling it unreadable said less than the text shows.
    The bound is in `_raw_load_can_hide_a_port`.
  - **What a raw load actually matches is not this module's to work out.** The
    agent names an address prefix itself now, so `@nh,96,16 0x0a58` arrives as
    `ip saddr 10.88.0.0/16` from an agent carrying that change. Older documents
    still carry the hex, because the agent reaches a host only when a new signed
    package is published, so this module still has to reason about a raw load
    and all it asks of one is whether a port could be hiding in it.
  - **Runtime state.** `ct state established` is quoted as written. Whether it
    matches depends on a connection that may not exist. That is the reader's
    call, not this module's.
"""

import re

# Rule text this agent produces for a transport destination port, in the
# vocabulary of agent/internal/collect/nftrender_linux.go: the prefix is the
# matched l4 protocol or the anonymous "th", equality renders the operator as
# nothing, and everything else renders it explicitly.
_DPORT = re.compile(r"\b(?:tcp|udp|sctp|dccp|th) dport (!=|>=|<=|>|<)?\s*(\d+)\b")

# Every mention of a destination port, readable or not. The renderer also emits
# masked comparisons, `tcp dport & 0xff == 0x16`, which select a port without
# ever writing it as a decimal. Counting mentions against the ones _DPORT could
# read is what stops one of those being filed as "carries no port match", which
# is the most dangerous mistake this module could make: it would put a rule that
# does select the port into the pile the reader is told to ignore.
_DPORT_MENTION = re.compile(r"\bdport\b")

# A matched transport protocol, from the same renderer: "ip protocol tcp",
# "ip6 nexthdr tcp", "meta l4proto tcp".
_L4PROTO = re.compile(r"\b(?:ip protocol|ip6 nexthdr|meta l4proto) (\w+)\b")

# A raw payload load the renderer named by offset rather than by field, in
# nft's own `@base,offset,length` form with both numbers in bits.
_RAWPAYLOAD = re.compile(r"@(th|nh|ll),(\d+),(\d+)")

# Where a transport port can be hiding behind one of those loads, which is the
# only question this module asks of them.
#
# The IPv4 header is a minimum of five 32-bit words, which is what the IHL
# field counts (RFC 791 section 3.1), so 160 bits. The IPv6 header is a fixed
# 40 octets (RFC 8200 section 3), so 320 bits. A load from the network-header
# base that ends at or before bit 160 therefore lies inside the fixed header
# under either address family, and neither fixed header carries a transport
# port: they carry lengths, addresses, hop limits and the next protocol.
#
# 160 rather than 320 because an `inet` table sees both families and this
# module does not infer one from the other (PRODUCT.md 4b). So a load past bit
# 160 stays not fully readable even where it looks like an IPv6 address match.
# Bounding it needs the family, and guessing the family is the mistake this
# project has already made once. A load nft wrote from `ip6 saddr` or
# `ip6 daddr` never arrives here anyway: it carries a `meta nfproto`
# dependency, so the agent has the family and names the field itself.
_NETWORK_HEADER_BITS = 160


def _raw_load_can_hide_a_port(base: str, offset: int, length: int) -> bool:
    """Whether a raw payload load could be selecting a transport port.

    True is the safe answer: it makes the rule not fully readable, which is
    the honest label for a rule this module cannot reason about.

      - `th`, the transport header, is where ports live. Always true. The
        agent already renders the two port fields by name, so a `@th` load
        that survives to here is some other transport field, and this module
        has no reason to trust its own arithmetic over the renderer's.
      - `nh`, the network header, per the bound above.
      - `ll`, the link layer, is always true and deliberately not narrowed.
        The equivalent bound would be the link header's size, and that varies
        by link type in ways this session could not source. No host on the
        fleet carries one, so the narrowing would buy nothing and would be a
        claim with nothing behind it.
    """
    if base == "nh":
        return offset + length > _NETWORK_HEADER_BITS
    return True


def _has_unreadable_payload(text: str) -> bool:
    return any(_raw_load_can_hide_a_port(base, int(offset), int(length))
               for base, offset, length in _RAWPAYLOAD.findall(text))

# The verdict that leaves this chain for another one, always last in the text.
_JUMP = re.compile(r"\b(jump|goto) (\S+)$")

# The one x_tables match this module is willing to look past, and the only one
# it ever should be.
#
# `xt match comment` is a no-op. From net/netfilter/xt_comment.c at the
# torvalds/linux master tree, read 2026-08-14: the module describes itself as
# "No-op match which can be tagged with a comment" and its match function is
#
#     static bool comment_mt(const struct sk_buff *skb, struct xt_action_param *par)
#     {
#         /* We always match */
#         return true;
#     }
#
# so it cannot change which packets a rule selects. Without this exception the
# most common rule ufw writes, `-p tcp --dport 22 -m comment --comment ... -j
# ACCEPT`, is graded partial by the agent and would be filed here as a rule
# whose port cannot be read, which is wrong in the direction of saying less
# than we know. Every other bracketed match stays unreadable, because every
# other one can select.
_COMMENT_MATCH = re.compile(r"\s*\[xt match comment\]")

# How a rule relates to the port being traced. The order matters: it is the
# order they are shown in, and it is worst-readability-last on purpose, so a
# rule this module could not decode is never buried under ones it could.
NAMES_PORT = "names this port"
EVERY_PORT = "carries no port match"
UNREADABLE = "not fully readable"
OTHER_PORT = "names a different port"

# nftables table families and the IP families their chains see. arp, bridge
# and netdev do not sit on the ip prerouting-to-input path a connection to a
# host port takes, so they are not walked, and hosts that have them are told.
_FAMILY_SEES = {"ip": ("v4",), "ip6": ("v6",), "inet": ("v4", "v6")}

# Hooks in kernel traversal order, sourced in this module's docstring. ingress
# runs ahead of prerouting and is included because the agent can report it.
LOCAL_HOOKS = ("ingress", "prerouting", "input")
FORWARD_HOOKS = ("ingress", "prerouting", "forward", "postrouting")

# A jump chain that jumps to a chain that jumps ... nftables rejects loops, but
# this walks a document that may not have come from a healthy kernel.
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
# document is hostile input, so an unbounded walk is a
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


def _mapping(value):
    """`value` if it is a dict, otherwise an empty one.

    The whole module used `x or {}` and `x or []`, which catches None and
    nothing else. A host document is stored verbatim on purpose (PRODUCT.md 4e)
    and the ingest validates only the envelope, so a section holding a string
    where an object belongs reaches here intact. On 2026-08-16 that raised
    AttributeError out of the walk and took the render down for the whole
    fleet, not only for the host that sent it.
    """
    return value if isinstance(value, dict) else {}


def _dicts(value):
    """The dict entries of `value` if it is a list, otherwise nothing.

    Entries that are not dicts are dropped rather than skipped over one field
    at a time, because a socket that is not an object is not a socket. What is
    deliberately *not* done here is pretending the document was fine: the
    caller that reports counts still reports what it could read, and
    `render_live` names a host whose document would not walk.
    """
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, dict)]


def _int_or_none(value):
    """Priorities arrive as JSON numbers. A hostile document may put anything
    there, and sorting a string against an int raises, so it is normalised
    here and an unreadable priority sorts last rather than crashing the page.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return int(value)


# A meta match the agent had no name for. It writes the key as its number and
# the value as raw bytes, `meta 4 0x01000000` where the rule said `iif lo`
# (the default of the meta keys in agent/internal/collect/nftrender_linux.go),
# and grades the rule full, because it did decode the comparison. Nothing
# here knows what key 4 selects. The keys the agent names keep their words:
# `meta l4proto`, `meta nfproto`, `meta mark`.
_UNNAMED_META = re.compile(r"(?:^|\s)meta \d+(?:\s|$)")


def readable_tokens(text, rendered):
    """The rule text with the no-op comment match dropped, or None when a
    port-selecting token in it was not decoded.

    `classify_rule` and `rule_port_claim` both start here, so the Packet path
    tab and the Rules tab can never disagree about whether a rule is readable.
    They ask different questions of the same answer: one asks how the rule
    relates to a port being traced, the other asks which port the rule's own
    text names.
    """
    text = text or ""
    # The comment match is dropped first, with its licence in _COMMENT_MATCH.
    readable = _COMMENT_MATCH.sub("", text)
    # Any other placeholder, or a raw header offset, means a token that can
    # select packets was not decoded, so the rule cannot be reasoned about.
    if "[" in readable or _has_unreadable_payload(readable) or not readable.strip():
        return None
    # A match written as a number selects packets by something this module
    # has no word for. The Rules tab read `accept, any port` off the loopback
    # rule of a server with nftables by hand (docs/RECORD.md 4.220, 4.454).
    if _UNNAMED_META.search(readable):
        return None
    # A grade below full with no comment match to explain it means the renderer
    # fell back on something this text does not show. Trust the grade.
    if rendered != "full" and readable == text:
        return None
    return readable


def dports_readable(text):
    """Whether every destination port this text mentions is one `_DPORT` could
    read. A masked comparison, `tcp dport & 0xff == 0x16`, selects a port
    without ever writing it as a decimal.

    Kept out of `readable_tokens` on purpose, and the order is the point. A
    rule pinned to a different transport protocol is answered by the protocol
    alone and its port never has to be read, so this is asked after that check
    and not before it. Asking it first turns "names a different port" into
    "not fully readable", which is weaker than what the text supports, and the
    control plane's own classifier is the thing that caught that.
    """
    return len(_DPORT_MENTION.findall(text)) == len(_DPORT.findall(text))


def rule_port_claim(text, rendered):
    """Which transport port this rule's own text names, and whether every
    port-selecting token in it was readable.

    Returns `(label, readable)`. `label` is `"tcp/5432"`, or `"5432"` where the
    rule names a port without pinning a transport protocol, or `""` where the
    rule names no single port. `readable` is False for a rule carrying a token
    this module could not decode.

    **Only a plain equality earns a label.** A rule matching `dport >= 1024` or
    `dport != 22` does carry a port match and does not name a port, so it gets
    no label rather than a label that would read as a claim about one port.
    The rule text itself is on the screen either way, which is the product.

    This is the Rules tab's question and it is deliberately not
    `classify_rule`'s: that one is asked about a port the reader named, this
    one is asked with no port in mind at all.
    """
    readable = readable_tokens(text, rendered)
    if readable is None or not dports_readable(readable):
        return "", False
    ports = _DPORT.findall(readable)
    if not ports:
        return "", True
    # Every comparison has to be a plain equality on the same port. Several
    # dport comparisons in one rule is not something the renderer produces
    # today, and guessing how they combine would be inventing.
    values = {value for op, value in ports if op in (None, "")}
    if len(values) != 1 or len(ports) != len(values):
        return "", True
    port = values.pop()
    proto = _L4PROTO.search(readable)
    return (f"{proto.group(1)}/{port}" if proto else port), True


# One destination port compared by plain equality, with nothing after the
# number that could make it a range or a list.
_ONE_DPORT = re.compile(r"\b(tcp|udp|sctp|dccp|th) dport (\d+)(?=\s|$)")


def named_dport(text):
    """The one destination port this rule's text names, as `(protocol,
    port)`, or None when it names no single port this can read.

    **This reads a rule the agent rendered only in part**, which
    `classify_rule` and `rule_port_claim` refuse to do, and it may because it
    answers less: which port a rule is about, never what the rule does. The
    kernel evaluates a rule's expressions in turn and leaves the rule at the
    first one that does not hold. Read from the torvalds/linux master tree on
    2026-10-11: in `net/netfilter/nf_tables_core.c`, `nft_do_chain` runs each
    expression and stops at `if (regs.verdict.code != NFT_CONTINUE) break;`,
    then takes the next rule on `NFT_BREAK`, and in `net/netfilter/nft_cmp.c`
    a comparison that does not hold sets `NFT_BREAK`. So a rule that says
    `tcp dport 7000` is left by a packet for any other port, whatever stands
    beside that comparison in the rule.

    Who needs it: the rule Docker writes for a published port arrives as
    `... tcp dport 7000 counter [xt target DNAT]`, because the agent does not
    render that target. The walk files it as not fully readable for every
    port, which is right for the walk and says nothing of which port Docker
    published.

    None for everything else, and None is the answer that claims nothing: no
    port at all, a comparison that is not an equality, a masked one, a range,
    more than one, and anything that is not text. `protocol` is "" where the
    rule pins none.
    """
    if not isinstance(text, str):
        return None
    if len(_DPORT_MENTION.findall(text)) != 1:
        return None
    found = _ONE_DPORT.search(text)
    if found is None:
        return None
    protocol = found.group(1)
    if protocol == "th":
        pinned = _L4PROTO.search(text)
        protocol = pinned.group(1) if pinned else ""
    return protocol, int(found.group(2))


def classify_rule(text, rendered, protocol, port):
    """How rule `text` relates to `protocol`/`port`, using only what the text
    actually says. Returns one of the four constants above.

    The honesty rule lives here. A rule is called NAMES_PORT or EVERY_PORT
    only when the renderer graded it "full" and this function understood every
    port-selecting token in it. Anything else is UNREADABLE, which on screen
    reads "not fully readable" and is shown rather than hidden.
    """
    text = readable_tokens(text, rendered)
    if text is None:
        return UNREADABLE

    # A rule pinned to a different transport protocol does not select this one.
    proto_match = _L4PROTO.search(text)
    if proto_match and protocol and proto_match.group(1) != protocol:
        return OTHER_PORT

    # A destination port mentioned in a form this module could not read leaves
    # the rule unreadable rather than portless.
    if not dports_readable(text):
        return UNREADABLE
    ports = _DPORT.findall(text)
    if not ports:
        return EVERY_PORT

    # Several dport comparisons in one rule is not something the renderer
    # produces today, and guessing how they combine would be inventing. Every
    # comparison has to agree, or the rule is not readable here.
    verdicts = {_dport_selects(op, int(value), port) for op, value in ports}
    if verdicts == {True}:
        return NAMES_PORT
    if verdicts == {False}:
        return OTHER_PORT
    return UNREADABLE


def _dport_selects(op, value, port):
    """Whether one `dport` comparison selects `port`."""
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


def _chain_index(table):
    return {c.get("name"): c for c in _dicts(table.get("chains")) if c.get("name")}


def walk_chain(table, chain, protocol, port, depth=0, seen=None, budget=None):
    """Every rule the packet is evaluated against from `chain` onward, jumps
    followed, in evaluation order.

    Returns (steps, counts). A step is
    (chain_name, text, rendered, comment, verdict, depth). Rules that name a
    different port are counted and not returned, because showing every port on
    every port's page would bury the ones that matter. The count is printed on
    screen so the omission is visible rather than silent.
    """
    seen = set() if seen is None else seen
    # A one-element list rather than an integer, because the count has to be
    # shared with every nested call and an integer would be copied.
    budget = [MAX_RULES_WALKED] if budget is None else budget
    counts = {NAMES_PORT: 0, EVERY_PORT: 0, UNREADABLE: 0, OTHER_PORT: 0}
    steps = []
    key = chain.get("name")
    if depth > _MAX_DEPTH or key in seen:
        return steps, counts
    seen = seen | {key}
    index = _chain_index(table)

    rules = _dicts(chain.get("rules"))
    for position, rule in enumerate(rules):
        if budget[0] <= 0:
            counts[UNREADABLE] += len(rules) - position
            break
        budget[0] -= 1
        text = rule.get("text") or ""
        verdict = classify_rule(text, rule.get("rendered"), protocol, port)
        counts[verdict] += 1
        if verdict == OTHER_PORT:
            continue
        steps.append((key, text, rule.get("rendered") or "", rule.get("comment") or "",
                      verdict, depth))
        # Follow the jump unless this rule selected a different port, which
        # the continue above already handled. A rule that is not fully
        # readable is followed too: it may well be the one that matters.
        jump = _JUMP.search(text)
        if not jump:
            continue
        target = index.get(jump.group(2))
        if target is None:
            continue
        sub_steps, sub_counts = walk_chain(table, target, protocol, port,
                                           depth + 1, seen, budget)
        steps.extend(sub_steps)
        for name, value in sub_counts.items():
            counts[name] += value
    return steps, counts


def base_chains(doc, family, hook):
    """Every nftables base chain on `hook` that a packet of IP family `family`
    meets, ordered by the priority the kernel reported.

    Chains are returned grouped by priority, because two base chains
    registered at the same priority are traversed in registration order and a
    host document does not record registration order. Guessing which of them
    runs first would be exactly the kind of confident wrong sentence this
    project has already had to retract, so the group is returned intact and
    the caller says the order inside it is not readable.
    """
    found = []
    for table in _dicts(_mapping(doc.get("nftables")).get("tables")):
        if family not in _FAMILY_SEES.get(table.get("family"), ()):
            continue
        for chain in _dicts(table.get("chains")):
            if chain.get("hook") != hook:
                continue
            found.append((_int_or_none(chain.get("priority")), table, chain))

    # None sorts last: an unreadable priority is placed after everything with
    # a readable one rather than silently treated as zero.
    found.sort(key=lambda item: (item[0] is None, item[0] if item[0] is not None else 0,
                                 (item[1].get("family") or "", item[1].get("name") or "",
                                  item[2].get("name") or "")))
    groups = []
    for priority, table, chain in found:
        if groups and groups[-1][0] == priority:
            groups[-1][1].append((table, chain))
        else:
            groups.append((priority, [(table, chain)]))
    return groups


def excluded_families(doc):
    """Table families present on the host that this walk does not follow, so
    the screen can name them instead of quietly leaving them out."""
    names = set()
    for table in _dicts(_mapping(doc.get("nftables")).get("tables")):
        family = table.get("family")
        if family not in _FAMILY_SEES:
            names.add(f"{family} {table.get('name')}")
    return sorted(names)


def legacy_rule_count(doc):
    """How many legacy x_tables rules the host has, v4 and v6 together. The
    packet path cannot place them (see the module docstring), so the number is
    shown with the reason rather than the rules being silently absent."""
    total = 0
    for key in ("iptables", "ip6tables"):
        section = _mapping(doc.get(key))
        for table in _dicts(section.get("tables")):
            for chain in _dicts(table.get("chains")):
                total += len(_dicts(chain.get("rules")))
    return total


def sockets_on(doc, protocol, port):
    """The listening sockets on this protocol and port, by IP family. A v6
    socket on :: may or may not also take v4 traffic depending on
    IPV6_V6ONLY, which the document does not carry, so nothing here infers one
    family from the other (PRODUCT.md 4b)."""
    out = {"v4": [], "v6": []}
    for socket in _dicts(_mapping(doc.get("sockets")).get("listening")):
        if socket.get("protocol") != protocol or socket.get("port") != port:
            continue
        if socket.get("family") in out:
            out[socket["family"]].append(socket)
    return out


def publications_on(doc, protocol, port):
    """Container publications of this host port, with the runtime that made
    them. Docker and Podman stay apart because they publish through different
    mechanisms (PRODUCT.md 4d)."""
    found = []
    containers = _mapping(doc.get("containers"))
    for runtime in ("docker", "podman"):
        for container in _dicts(containers.get(runtime)):
            for published in _dicts(container.get("ports")):
                if published.get("host_port") == port and published.get("protocol") == protocol:
                    found.append((runtime, container, published))
    return found


def traced_ports(doc):
    """Which ports get a path, newest question first: everything the host is
    listening on, plus everything a container publishes. Sorted by port so the
    page is stable between runs."""
    found = {}
    for socket in _dicts(_mapping(doc.get("sockets")).get("listening")):
        protocol, port = socket.get("protocol"), socket.get("port")
        if isinstance(port, int) and protocol:
            found.setdefault((protocol, port), set()).add("socket")
    containers = _mapping(doc.get("containers"))
    for runtime in ("docker", "podman"):
        for container in _dicts(containers.get(runtime)):
            for published in _dicts(container.get("ports")):
                protocol, port = published.get("protocol"), published.get("host_port")
                if isinstance(port, int) and protocol:
                    found.setdefault((protocol, port), set()).add("published")
    return sorted(found.items(), key=lambda item: (item[0][1], item[0][0]))


def path_for(doc, protocol, port, family):
    """The whole inside view for one port on one IP family.

    Returns a dict the renderer turns into HTML. It holds facts and quotes and
    no verdict: there is no field here saying whether anything gets through,
    because measuring that is the prober's job and the prober does not exist.
    """
    sockets = sockets_on(doc, protocol, port)[family]
    publications = publications_on(doc, protocol, port)
    # Local delivery and forwarding are not exclusive. Docker's userland proxy
    # holds a real socket while a DNAT rule also exists for the same port, and
    # a page that showed only one of the two would hide the more interesting
    # half. Both are shown when both are present.
    hooks = list(LOCAL_HOOKS) if sockets else []
    if publications:
        for hook in FORWARD_HOOKS:
            if hook not in hooks:
                hooks.append(hook)
    if not hooks:
        hooks = list(LOCAL_HOOKS)

    stages = []
    # One budget for the whole page, not one per base chain, so a document
    # carrying a thousand base chains cannot spend it a thousand times.
    budget = [MAX_RULES_WALKED]
    for hook in (h for h in ("ingress", "prerouting", "forward", "input", "postrouting")
                 if h in hooks):
        groups = []
        for priority, members in base_chains(doc, family, hook):
            entries = []
            for table, chain in members:
                steps, counts = walk_chain(table, chain, protocol, port,
                                           budget=budget)
                entries.append({
                    "table": f"{table.get('family')} {table.get('name')}",
                    "chain": chain.get("name"),
                    "policy": chain.get("policy") or "",
                    "type": chain.get("type") or "",
                    "steps": steps,
                    "counts": counts,
                    # Carried so a later reader of this entry can tell an
                    # accept that certainly reaches this packet from one that
                    # only might. `rule_lets_it_pass` is the reader.
                    "protocol": protocol,
                    "port": port,
                })
            groups.append({"priority": priority, "entries": entries})
        stages.append({"hook": hook, "groups": groups})

    return {
        "protocol": protocol,
        "port": port,
        "family": family,
        "sockets": sockets,
        "publications": publications,
        "stages": stages,
        "delivery_local": bool(sockets),
        "delivery_forwarded": bool(publications),
        # False when the walk spent its whole budget, so rules may stand in
        # these chains that no step here shows. A reader that concludes
        # something from a rule being absent asks this first.
        "walked_all": budget[0] > 0,
        "legacy_rules": legacy_rule_count(doc),
        "excluded_tables": excluded_families(doc),
        "nftables_status": _mapping(doc.get("nftables")).get("status") or "not collected",
    }


# ===================================== the outward half, added 2026-08-22
#
# `docs/PRODUCT.md` section 8 item 1 promises the path in both directions:
# why this is reachable, and why that one is not. The docstring at the top of
# this file said the second half needed the prober and the prober did not
# exist. It does now, it runs on two timers, and its answers reach the join
# engine.
#
# **This narrows where to look. It does not answer the question**, and the
# difference is the whole design. 4g's last paragraph stands unchanged: the
# view states no outcome, not reachable, not allowed, not blocked, not
# accepted. What is added here is one measurement, which the prober owns and
# is entitled to state, and then a per-checkpoint reading of what the document
# says, from which a reader draws their own conclusion.
#
# Why it cannot do better, and this is not caution for its own sake. Nothing
# came back. A packet that is not answered leaves no evidence of where it
# stopped, so any single checkpoint named as the cause would be a guess wearing
# a fact's clothes. `controlplane/app/join.py:_decide` reaches the same wall
# from the other side and returns `LAYER_NOT_DETERMINED` for exactly this case.
#
# **This emits keys and quotes, never sentences.** The words this module is
# forbidden to produce are pinned by a test, and the way to keep that true
# while saying something useful is to hand the renderer facts and let the copy
# live where copy is reviewed.

# nft puts a rule's verdict at its end, which `_JUMP` above already relies on.
# Anchoring matters more than it looks: `counter jump ufw-user-limit-accept`
# ends with the letters of a verdict and is a jump to a chain, so a pattern
# that is not anchored to a word boundary preceded by whitespace reads ufw's
# commonest rule as an accept.
_VERDICT_ACCEPT = re.compile(r"(?:^|\s)accept$")
# `reject` takes arguments, `reject with icmpx port-unreachable`, so it is not
# always last. `drop` never takes one.
_VERDICT_DROP = re.compile(r"(?:^|\s)drop$")
_VERDICT_REJECT = re.compile(r"(?:^|\s)reject\b")

# Why one checkpoint is worth a reader's attention. Keys, not prose.
ENDS_ON_THIS_PORT = "a rule here names this port and ends its journey"
POLICY_ENDS = "nothing here names this port and the chain's policy ends it"
CANNOT_RULE_OUT = "rules here could not be fully read"


# The three verdicts in the order a reader meets them. `reject` is checked
# before `drop` only for tidiness: a rule carries one verdict.
_VERDICTS = (("accept", _VERDICT_ACCEPT), ("reject", _VERDICT_REJECT),
             ("drop", _VERDICT_DROP))


def rule_verdict(text: str) -> str:
    """The verdict word this rule ends on, or "" for one that ends on none.

    **This is what the rule says, not what happens to any packet.** A rule can
    say accept and still match nothing a reader cares about, which is why
    `rule_lets_it_pass` below asks a much harder question and answers it far
    less often. The Rules tab asks this one, because it lists rules rather
    than walking one packet through them.

    Anchored the same way, so `counter jump ufw-user-limit-accept` is a jump
    and not an accept.
    """
    for word, pattern in _VERDICTS:
        if pattern.search(text or ""):
            return word
    return ""


def rule_ends_the_journey(text: str) -> bool:
    """Whether this rule's own verdict stops a packet.

    `drop` and `reject` and nothing else. A `jump` does not stop anything, it
    moves, and the walk follows it. A `return` leaves a chain and the packet
    carries on. `queue` hands the packet to userspace, which may do anything at
    all, and calling that stopped would be stating an outcome this module
    cannot see.
    """
    return bool(_VERDICT_DROP.search(text or "")
                or _VERDICT_REJECT.search(text or ""))


def rule_lets_it_pass(text: str, protocol=None, port=None) -> bool:
    """Whether this rule certainly ends the walk without stopping the packet.

    An `accept` verdict, and **only when nothing else in the rule could stop it
    matching**. That second half is the whole of it, and reading the rendered
    page is what found it: `ct state established accept` carries no port match,
    so it is evaluated for every port, and treating it as an accept said a
    chain's drop policy was never reached. A new inbound connection is not
    established, so for the packet this page is about, that rule matches
    nothing.

    The same is true of `iifname "lo" accept` and of every other condition the
    walk cannot evaluate. So the test is the one
    `controlplane/app/join.py:_accept_shape` already applies for the same
    reason: after removing the protocol, this exact port, the counter and the
    verdict, an accept that certainly reaches this packet has nothing left.
    Anything left over and the answer is no, which is the answer that claims
    less.
    """
    text = text or ""
    if not _VERDICT_ACCEPT.search(text):
        return False
    body = " ".join(text.split()[:-1])
    body = _COMMENT_MATCH.sub(" ", body)
    if protocol:
        body = re.sub(r"\b(?:ip protocol|ip6 nexthdr|meta l4proto) "
                      + re.escape(str(protocol)) + r"\b", " ", body)
    if port is not None:
        body = re.sub(r"\b(?:tcp|udp|sctp|dccp|th) dport " + str(int(port)) + r"\b",
                      " ", body)
    body = re.sub(r"\bcounter\b", " ", body)
    return not body.strip()


def checkpoint_notes(entry) -> list:
    """Why this base chain is worth looking at, given the port did not answer.

    Returns a list of (key, quote) with the quote empty where the fact is
    about the chain rather than about one rule. An empty list means the
    document says nothing here that could account for a silence, which is not
    the same as saying the packet got through: something the agent could not
    read, or something no ruleset can see, is still possible and the screen
    says so once rather than on every row.
    """
    notes = []
    steps = entry.get("steps") or []
    counts = entry.get("counts") or {}

    for _chain, text, _rendered, _comment, verdict, _depth in steps:
        if verdict == NAMES_PORT and rule_ends_the_journey(text):
            notes.append((ENDS_ON_THIS_PORT, text))

    # A policy only decides when nothing before it did. `accept` on this port
    # ends the walk in this chain, so a policy after one is not reached.
    accepted = any(
        verdict in (NAMES_PORT, EVERY_PORT)
        and rule_lets_it_pass(text, entry.get("protocol"), entry.get("port"))
        for _c, text, _r, _cm, verdict, _d in steps)
    if not accepted and str(entry.get("policy") or "").lower() == "drop":
        notes.append((POLICY_ENDS, ""))

    if counts.get(UNREADABLE):
        notes.append((CANNOT_RULE_OUT, ""))
    return notes


def outward_path(path, outside_state, measured=True):
    """The outward reading of an inside path, or None when there is nothing to
    read it against.

    `outside_state` is the prober's own word for what happened. `measured` is
    whether it measured at all, which is the one question that decides whether
    this view exists: a port nobody probed gets no outward view, ever, because
    the alternative is a page that reasons about a silence nobody observed
    (`docs/PRODUCT.md` 4b).

    A port that answered gets a view with no checkpoints marked. Something on
    this path let it through and the document cannot say which, so marking any
    of them would be the same guess in the opposite direction.
    """
    if not measured:
        return None
    answered = outside_state == "connect_succeeded"
    marked = []
    if not answered:
        for stage in path.get("stages") or []:
            for group in stage.get("groups") or []:
                for entry in group.get("entries") or []:
                    notes = checkpoint_notes(entry)
                    if notes:
                        marked.append({
                            "hook": stage.get("hook"),
                            "table": entry.get("table"),
                            "chain": entry.get("chain"),
                            "notes": notes,
                        })
    return {
        "state": outside_state,
        "answered": answered,
        "checkpoints": marked,
        # Said once rather than on every row, and it is the honest ceiling on
        # everything above: legacy rules are not on the path at all, and a
        # ruleset cannot see a rate limit's window or anything upstream of this
        # host.
        "legacy_rules": path.get("legacy_rules", 0),
    }
