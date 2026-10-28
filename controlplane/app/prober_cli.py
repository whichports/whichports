"""Drive the connect engine from the terminal.

    python -m app.prober_cli probe --dry-run          # print, send nothing
    python -m app.prober_cli probe --host almabox   # one host, for real
    python -m app.prober_cli probe                    # every host we hold
    python -m app.prober_cli probe --tls-port 443     # and read 443's certificate
    python -m app.prober_cli probe --tls-known        # certificates on the known TLS ports
    python -m app.prober_cli probe --joined           # the joined port set
    python -m app.prober_cli probe --joined --registry   # from every vantage
    python -m app.prober_cli last                     # the run that was stored

`app/prober.py` is the engine and `docs/PRODUCT.md` section 5 is the
specification. This file is the part that decides **which** addresses and
**which** ports the engine is handed, and it is deliberately thin: it derives
that from the documents the agents already sent, and it does nothing else.

## Run the dry run first

`--dry-run` lists every target, every port and what the gate answers for each,
and sends nothing. It is the mode a person runs before the other one, so it is
the mode that had to be right first. Nothing in that path constructs a socket,
and `tests/test_prober_cli.py` proves it by handing the command a connect
primitive that fails the test if it is called at all.

## Where the targets come from

The addresses are the bind addresses of the listening sockets in the host's
most recent document, keeping only the ones that can be a probe target at all.
Nothing is probed without `authz.may_probe` saying yes, so this list decides
what is offered and never what is allowed.

**It reads bind addresses and interface addresses, and it took two goes to
get there.** The agent-derived proof was widened to interface addresses on
2026-08-17 (`docs/RECORD.md` 4.55) and this derivation was left reading bind
addresses only, deliberately, as its own change. What that cost was measured
on the live fleet on 2026-08-27 and it was the whole IPv6 half of the product:

  - every service on an ordinary host binds the wildcard, `0.0.0.0` or `::`,
    which names no address. On all three fleet hosts the **only** globally
    routable bind address was the DHCP client's, on udp/68. So v4 was probed
    by the accident of DHCP, and a statically addressed server, which is most
    production boxes, yielded no targets at all.
  - **not one host offered a v6 target**, because nothing binds a specific v6
    address, so every v6 port on the fleet read `not_tested` with the reason
    `no_address_in_family`. Two of those hosts hold a global v6 address, say
    so in their own documents, and answer on 22, 80 and 443 from the internet.

The reason string is why this is a correctness fix rather than a widening.
`no_address_in_family` states that the host has no address in that family, and
the document said the opposite. A field may say it did not measure something;
it may not state a fact about the host that the host contradicts (the accuracy
rule).

**It offers more and allows nothing new.** `authz.may_probe` is still the only
gate and it is unchanged, so an address nobody proved is refused exactly as
before. What changes is which refusal: `no_authorization`, which is true,
instead of `no_address_in_family`, which was not.

The ports are every TCP port the document reports listening, plus every TCP
port a container publishes, which is the same question
`site/app/packetpath.py:traced_ports` answers for the inside view. The two
agree and share no code, because the control plane and the site renderer are
separate programs.

**`--joined` widens that set and is what both timers pass.** It adds every
port with a declaration against it and every port the newest stored run
measured, which is the owner's decision of 2026-08-21 in `docs/RECORD.md` 4.78.
`app/dispatch.py:joined_ports` owns the set and the cap on it. The plain form
is left as it was so a person can still ask what the document alone offers.

**A port bound to a loopback address is still probed.** The whole product
exists because a rule and a bind address do not tell you what is reachable
from outside, so the measurement decides that and the document does not.

## Where the packets leave from, since 2026-09-08

`--registry` drives every enabled vantage in `app/vantages.py`, one after
another, and it is what both timers pass. It refuses, exit 2, when the
registry holds no enabled vantage, because the alternative is silently
probing from the machine the command runs on, which in production is the
control plane and must never probe. `--vantage NAME` beside it narrows the
pass to that one registered vantage, which is how a new box is tried alone
before it joins the others.

`--via DESTINATION` is the older explicit form, one vantage named by hand.
Since the finer locks it names a vantage of the registry, `--vantage` its name
and `--via` its destination, because the lock a batch takes is that row's
(`registry_row_for_via`). Without either flag the connects come from this
machine, as they always have, which is a laptop's mode and nothing else.

Whatever the path, **no vantage address is ever a target.** Every address in
the registry is taken out of every plan, and the dry run says so per address
(`app/dispatch.py`, the module docstring).

## Reading a certificate is asked for, never assumed

`--tls-port` names a port a certificate is read from, and it can be given more
than once. Nothing is read without it.

A certificate read is a **second connection** to that port, so handshaking
every port that answered would double what the fleet sends to find out
something nobody asked for. There is also no way to tell from outside which
ports speak TLS without trying, and trying everything is what a scanner does.

The named port is only read when the document already reports it, because the
ports come from the documents and this command does not invent one. A port that
was named and is not in the document is said out loud by the dry run rather
than quietly doing nothing.

**`--tls-known` is what the timers pass, since 2026-09-10.** Until then no
unit ever named a port, so no certificate was ever read in production
(`docs/RECORD.md` 4.158). The owner's decision that day: the timers name the
ports in `KNOWN_TLS_PORTS`, the IANA-registered TLS services plus 8443 by
convention, and a certificate is read on each of those the plan already
carries. A port not in the plan is not read and not mentioned. `--tls-port`
still names any other port by hand, beside it.

## What it may not do, and how that is held

  - **it asks `authz.may_probe` and nothing else.** The dry run asks it once
    per target to print an answer. The real run does not ask it at all: the
    engine asks it again immediately before every single connect, which is
    what makes a revocation mid-run stop the packets. A test revokes an
    authorisation from inside the first connect and asserts every remaining
    port was recorded not tested
  - **it writes no SQL.** Runs are stored by the engine, through the one path
    that already exists. A test fails if a query appears in this file
  - **an address that is refused leaves a record.** A target the gate says no
    to is stored as not tested with the engine's own typed reason, never left
    out of the output. A target nobody can see was not measured is the shape
    `docs/RECORD.md` 4.45 keeps finding

## Exit codes are for a timer, not for a person

Zero unless the run itself could not happen, which is the database being
unusable or a named host not existing. **Never because a port did not answer,
and never because the gate refused a target.** `app/sweep_cli.py` states the
reasoning: a unit that goes red every time a server is down teaches everyone
to ignore it, and here a refusal is the authorisation rule working rather than
failing.
"""

import argparse
import asyncio
import json
import sqlite3
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, replace

from . import authz, cli, db, dispatch, probelock, prober, store, vantages

# This is a TCP connect prober (SI-7 and `docs/PRODUCT.md` 5a). A UDP port in
# a document is not a TCP port, and answering about it would be inventing a
# measurement: PRODUCT.md section 5a says UDP is weak and we say so, which
# starts with not pretending we probed it.
PROTOCOL = "tcp"

# Docker and Podman publish through different mechanisms (PRODUCT.md 4d), so
# they are read separately even though the ports go into one list.
CONTAINER_RUNTIMES = ("docker", "podman")

# Why a host is in the listing with nothing derived from it. Each one is a
# statement about our evidence, never about the host.
NOTE_NEVER_REPORTED = "has never reported, so there is nothing to derive"
NOTE_UNREADABLE = "its latest document cannot be read, so there is nothing to derive"
NOTE_REVOKED = "revoked, so it is not probed"
# The two notes an address host can carry. It has no document by design, so
# what it is probed on is what its operator proved and declared, and until
# both exist there is nothing to send (docs/PRODUCT.md 3a, tier 1).
NOTE_NO_PROVED_ADDRESS = "has no address proved for it, so there is nothing to probe"
NOTE_NO_PORT_DECLARED = ("has no port declared for it and none measured before,"
                         " so there is nothing to probe")

# A run against every port would otherwise print 65,535 numbers on one line.
MAX_PORTS_LISTED = 24

# The ports a timer reads a certificate on when the plan carries them, decided
# by the owner on 2026-09-10 (docs/PRODUCT.md 5b). Six are TLS services in the
# IANA Service Name and Transport Protocol Port Number Registry, read on
# 2026-09-10: 443 https, 465 submissions, 636 ldaps, 853 domain-s, 993 imaps,
# 995 pop3s. 8443 is registered there as pcsync-https and is on this list by
# convention, because it is where a second HTTPS service usually sits. Nothing
# here decides that a port speaks TLS: a port on this list that does not is
# recorded as a certificate not read, with the typed reason, and never as a
# finding about the server (docs/PRODUCT.md 5b).
KNOWN_TLS_PORTS = (443, 465, 636, 853, 993, 995, 8443)


# ------------------------------------------------------- reading the document

def _listening(document) -> list:
    """The listening sockets, defensively. Anything that is not the shape we
    expect yields nothing, because a malformed document is a document that
    says nothing, never an exception. The same posture `authz._bind_addresses`
    takes for the same field."""
    if not isinstance(document, dict):
        return []
    sockets = document.get("sockets")
    if not isinstance(sockets, dict):
        return []
    listening = sockets.get("listening")
    if not isinstance(listening, list):
        return []
    return [entry for entry in listening if isinstance(entry, dict)]


def _publications(document) -> list:
    """Every port a container publishes on the host, from both runtimes."""
    if not isinstance(document, dict):
        return []
    containers = document.get("containers")
    if not isinstance(containers, dict):
        return []
    found = []
    for runtime in CONTAINER_RUNTIMES:
        entries = containers.get(runtime)
        if not isinstance(entries, list):
            continue
        for container in entries:
            if not isinstance(container, dict):
                continue
            ports = container.get("ports")
            if not isinstance(ports, list):
                continue
            found.extend(port for port in ports if isinstance(port, dict))
    return found


def candidate_ports(document) -> list:
    """Every TCP port this document reports, deduplicated and ordered.

    **Nothing is dropped for being the wrong shape.** A port the document
    reports as text, or outside the range a port can be, is passed through
    exactly as it arrived so that the engine records it as not tested with its
    own typed reason. Dropping it here would make it disappear between the
    document and the answer, which is a port nobody can see was not measured.

    The probeable ports come first in ascending order, then anything the
    engine will refuse, in the order the document listed it. Deterministic,
    because one run's output is compared with the last one.
    """
    numbered: set = set()
    odd: list = []
    odd_seen: set = set()

    def offer(protocol, port) -> None:
        if protocol != PROTOCOL:
            return
        # bool is an int in Python and True would silently become port 1.
        if isinstance(port, int) and not isinstance(port, bool):
            numbered.add(port)
            return
        key = repr(port)[:prober.MAX_TARGET_TEXT]
        if key not in odd_seen:
            odd_seen.add(key)
            odd.append(port)

    for entry in _listening(document):
        offer(entry.get("protocol"), entry.get("port"))
    for entry in _publications(document):
        offer(entry.get("protocol"), entry.get("host_port"))
    return sorted(numbered) + odd


def _interface_addresses(document) -> list:
    """The interface addresses, defensively, read with the same posture
    `_listening` takes for the sockets and `authz._interface_addresses` takes
    for the same field. One unreadable half never loses the other, and a host
    running a build from before this section existed simply has none."""
    if not isinstance(document, dict):
        return []
    section = document.get("interface_addresses")
    if not isinstance(section, dict):
        return []
    addresses = section.get("addresses")
    if not isinstance(addresses, list):
        return []
    return [entry for entry in addresses if isinstance(entry, dict)]


def candidate_targets(document):
    """(targets, not targets). The addresses this host reports holding, split
    by whether they can be probed at all.

    Both halves of what a host says it holds: the bind addresses of its
    listening sockets, and the addresses on its interfaces. The module
    docstring holds what reading only the first half cost, measured.

    Bind addresses come first so an address a service really binds is offered
    ahead of one that is only on an interface, which changes nothing about
    what is allowed and keeps the order a run's output is compared in.

    The spelling comes back from `authz.normalise_target`, which is the gate's
    own function, so the address handed to the engine is the address the
    registry holds. Two spellings of one address is how a revocation misses
    one of them.

    **An address that cannot be a target is recorded once.** A wildcard bind
    and a link-local interface address are both refused, and both are worth
    showing in the dry run, but the same text refused twice would read as two
    problems.
    """
    targets: list = []
    not_targets: list = []
    seen: set = set()

    def offer(value) -> None:
        text = value if isinstance(value, str) else repr(value)
        if text in seen:
            return
        seen.add(text)
        try:
            target, _family = authz.normalise_target(value)
        except authz.TargetError as exc:
            not_targets.append((text[:prober.MAX_TARGET_TEXT], str(exc)))
            return
        if target not in targets:
            targets.append(target)

    for entry in _listening(document):
        offer(entry.get("bind_address"))
    for entry in _interface_addresses(document):
        offer(entry.get("address"))
    return targets, not_targets


# ------------------------------------------------------------------- planning

@dataclass(frozen=True)
class Plan:
    """What one host's run would consist of. `note` is set when there was
    nothing to derive, and a plan carrying one is never handed to the engine:
    we know nothing about that host, so we say nothing about it."""
    host_id: int
    name: str
    targets: tuple = ()
    ports: tuple = ()
    not_targets: tuple = ()
    note: str = ""
    # The gate's account for this host's workspace. It travels on the plan
    # because the plan is the only thing that reaches both the dry run and the
    # dispatch, and because deriving it once from the host row is one place to
    # be right rather than three.
    account: str = authz.DEFAULT_ACCOUNT
    # An address host's plan is built from its proofs and declarations rather
    # than from a document. `joined` says its port set is already the joined
    # set, so widening it again would only repeat the cap's sentence.
    agentless: bool = False
    joined: bool = False

    @property
    def derived(self) -> bool:
        return not self.note


def plan_for(con, host) -> Plan:
    """One host's plan, from its most recent document. Documents are stored
    verbatim and never edited, so the newest one is the only one that says
    what the host is listening on now."""
    account = authz.account_for_host(host)
    if _host_kind(host) == db.HOST_KIND_ADDRESS:
        return _address_plan(con, host, account)
    report = store.latest_report(con, host["id"])
    if report is None:
        return Plan(host["id"], host["name"], note=NOTE_NEVER_REPORTED,
                    account=account)
    try:
        document = json.loads(report["document"])
    except (ValueError, TypeError):
        document = None
    if not isinstance(document, dict):
        return Plan(host["id"], host["name"], note=NOTE_UNREADABLE,
                    account=account)
    targets, not_targets = candidate_targets(document)
    return Plan(host["id"], host["name"], tuple(targets),
                tuple(candidate_ports(document)), tuple(not_targets),
                account=account)


def _host_kind(host) -> str:
    """The kind of a host row, agent for a row from before kinds existed."""
    return host["kind"] if "kind" in host.keys() else db.HOST_KIND_AGENT


def _address_plan(con, host, account) -> Plan:
    """The plan for a host that has no agent.

    Its targets are the addresses its operator proved control of and that are
    live right now, read through the registry's own reader so the plan and
    the gate cannot disagree about which those are. Its ports are the joined
    set with nothing to join onto: what the operator declared, and what a
    previous pass measured. There is no document, by design, so nothing here
    reads one, and a plan missing either half carries a note and is never
    handed to the engine, the same way a host that never reported is not.
    """
    targets = tuple(row["target"]
                    for row in authz.live_addresses_for_host(con, host["id"]))
    if not targets:
        return Plan(host["id"], host["name"], note=NOTE_NO_PROVED_ADDRESS,
                    account=account, agentless=True)
    bare = Plan(host["id"], host["name"], targets, account=account, agentless=True)
    ports, note = dispatch.joined_ports(con, bare)
    if note:
        print(f"{host['name']}: {note}", file=sys.stderr)
    if not ports:
        return Plan(host["id"], host["name"], targets, note=NOTE_NO_PORT_DECLARED,
                    account=account, agentless=True)
    return replace(bare, ports=ports, joined=True)


def _with_joined_ports(con, plan) -> Plan:
    """One plan, with the joined port set in place of the document's ports.

    A plan with a note is left alone. We derived nothing about that host, so
    there is nothing to widen and widening it would invent a set.

    The cap, when it bites, is printed here rather than returned quietly. This
    file is what a person and a timer both run, and a pass that covered less
    than it was asked to has to say so where the output is read.
    """
    if not plan.derived or plan.joined:
        return plan
    ports, note = dispatch.joined_ports(con, plan)
    if note:
        print(f"{plan.name}: {note}", file=sys.stderr)
    return replace(plan, ports=ports)


def _selected(con, host_name=None):
    """(the hosts this covers, the hosts it leaves out and why).

    A revoked host is left out. We have been told to stop accepting what it
    says, so probing on the strength of a document it sent before that is
    probing on evidence we already withdrew. This only ever narrows what is
    probed, so it is not a second gate on a packet: the gate is still the only
    thing that lets one leave.
    """
    hosts = store.list_hosts(con)
    if host_name is not None:
        hosts = [host for host in hosts if host["name"] == host_name]
    covered = [host for host in hosts if not host["revoked_at"]]
    left_out = [(host["name"], NOTE_REVOKED) for host in hosts if host["revoked_at"]]
    return covered, left_out


def _by_family(targets) -> dict:
    """The targets grouped the way the engine answers, which is one answer per
    family always. The family comes from the address through the gate's own
    function, never from a field beside it."""
    grouped = {family: [] for family in prober.FAMILIES}
    for target in targets:
        _text, family = authz.normalise_target(target)
        grouped[family].append(target)
    return grouped


def _port_list(ports) -> str:
    """Ports as a person reads them, bounded. A whole range run is 65,535
    numbers and nobody reads that on one line."""
    shown = [str(port) for port in ports[:MAX_PORTS_LISTED]]
    if len(ports) > MAX_PORTS_LISTED:
        shown.append(f"and {len(ports) - MAX_PORTS_LISTED} more")
    return ", ".join(shown)


# -------------------------------------------------------------------- dry run

def _dry_run(con, host_plans, tls_ports=(), exclude=frozenset(), named=None) -> int:
    """What a real run would do, and what the gate says about each target.

    The gate is asked once per target here because this prints a line per
    target. A real run asks it again before every single connect, and this
    says so out loud rather than leaving the difference to be assumed.
    """
    print("dry run, nothing is sent.")
    print("A real run asks the gate again before every single connect.")
    allowed = refused = connects = handshakes = 0
    for plan in host_plans:
        print()
        print(plan.name)
        if not plan.derived:
            print(f"  {plan.note}")
            continue
        kept, ours = dispatch.split_targets(plan.targets, exclude)
        for address in ours:
            print(f"  {address} is one of our own vantage addresses, so"
                  f" {len(plan.ports)} results would be"
                  f" {prober.STATE_NOT_TESTED}"
                  f" ({prober.REASON_VANTAGE_ADDRESS})")
        plan = replace(plan, targets=tuple(kept))
        probeable = [entry.port for entry in prober.normalise_ports(list(plan.ports))
                     if entry.reason is None]
        readable = [port for port in tls_ports if port in probeable]
        # Only a port somebody named by hand is worth a line when the plan
        # lacks it. The known list is a list, not a claim about this host.
        named_here = tls_ports if named is None else named
        missing = [port for port in named_here if port not in probeable]
        if tls_ports:
            if readable:
                print(f"  a certificate would be read from {_port_list(readable)},"
                      " which is one more connection per port and per family")
            for port in missing:
                print(f"  port {port} was named for a certificate read and the"
                      " document does not report it, so nothing is read there")
        if plan.ports:
            print(f"  tcp ports ({len(plan.ports)}): {_port_list(plan.ports)}")
        else:
            print("  the document reports no tcp port")
        source = "proved" if plan.agentless else "in the document"
        grouped = _by_family(plan.targets)
        for family in prober.FAMILIES:
            if not grouped[family]:
                print(f"  {family} no address {source}, so"
                      f" {len(plan.ports)} results would be"
                      f" {prober.STATE_NOT_TESTED}"
                      f" ({prober.REASON_NO_ADDRESS_IN_FAMILY})")
                continue
            for target in grouped[family]:
                decision = authz.may_probe(con, target, account=plan.account)
                if decision.allowed:
                    allowed += 1
                    connects += len(probeable)
                    handshakes += len(readable)
                    print(f"  {family} {target}  yes: {decision.reason}")
                else:
                    refused += 1
                    print(f"  {family} {target}  no: {decision.reason}")
                    print(f"     {len(plan.ports)} results would be"
                          f" {prober.STATE_NOT_TESTED}"
                          f" ({prober.REASON_NO_AUTHORIZATION})")
        if plan.not_targets:
            print(f"  {len(plan.not_targets)} addresses in the document cannot be"
                  " probe targets: "
                  + ", ".join(text for text, _reason in plan.not_targets))
    print()
    print(f"{len(host_plans)} hosts, {allowed + refused} targets, {allowed} the gate"
          f" allows, {refused} it refuses, {connects} connects plus"
          f" {handshakes} handshakes in a real run, {connects + handshakes}"
          " connections in total, nothing was sent")
    return 0


# ------------------------------------------------------------------- real run

async def _probe_all(con, host_plans, connect, tls_read=None, tls_ports=(),
                     vantage=None, exclude=frozenset(), locks=None):
    """One Prober for the whole fleet, one run per host, in turn. Returns
    (the hosts measured with their runs, the names of those that were not).

    The engine's own docstring says anything probing repeatedly should hold a
    Prober, because the pace lives in it and a fresh one starts with a full
    bucket. The hosts go one after another rather than at once, so the
    engine's concurrency bound stays a bound on this process too.

    A vantage address is dropped from the targets here and named on stderr.
    This is the laptop's path and it stores the engine's own rows only, so the
    typed row `dispatch.run_host` writes for one of ours is not written here.

    `locks` gives each host the stripes of its addresses while it is probed
    (`probelock.BatchLocks`, with no prober: the packets leave this machine).
    A host whose addresses stayed busy for the whole wait is not measured,
    and the next host is tried.
    """
    injected = {}
    if connect:
        injected["connect"] = connect
    if tls_read:
        injected["tls_read"] = tls_read
    if vantage is not None:
        injected["vantage"] = vantage
    engine = prober.Prober(**injected)
    done = []
    failed = []
    for plan in host_plans:
        kept, ours = dispatch.split_targets(plan.targets, exclude)
        for address in ours:
            print(f"{plan.name}: {address} is one of our own vantage addresses"
                  " and is not probed", file=sys.stderr)
        held = None if locks is None else locks.taking(kept)
        if held is not None:
            try:
                held.acquire()
            except probelock.ProbeLockHeld as exc:
                print(probelock.held_line(exc, vantage, plan.host_id),
                      file=sys.stderr)
                print(f"{plan.name}: not measured: {exc}", file=sys.stderr)
                failed.append(plan.name)
                continue
        try:
            done.append((plan, await engine.run(con, list(kept),
                                                list(plan.ports),
                                                host_id=plan.host_id,
                                                account=plan.account,
                                                tls_ports=tls_ports)))
        except prober.HostGone:
            # Deleted after the list was made: left out, and the next server
            # is probed (docs/RECORD.md 4.312).
            print(f"{plan.name}: not measured: {dispatch.SERVER_DELETED}")
        finally:
            if held is not None:
                held.release()
    return done, failed


def _print_results(results) -> None:
    """One block per family and per target, with the states as the engine
    named them. There is no other vocabulary here on purpose: every one of
    those four words says what was observed rather than what it means."""
    groups: dict = {}
    for result in results:
        groups.setdefault((result.family, result.target), []).append(result)
    for (family, target), rows in sorted(
            groups.items(), key=lambda item: (item[0][0], item[0][1] or "")):
        print(f"  {family} {target or 'no address in the document'}")
        by_state: dict = {}
        for row in rows:
            by_state.setdefault(row.state, []).append(row)
        for state in prober.STATES:
            found = by_state.get(state)
            if not found:
                continue
            ports = [row.port for row in found if row.port is not None]
            detail = _port_list(ports) if ports else ""
            if state == prober.STATE_NOT_TESTED:
                # The reason is the whole content of a not tested row, so it
                # is what gets counted rather than the port numbers.
                counted = Counter(row.reason for row in found)
                detail = ", ".join(f"{reason} {count}"
                                   for reason, count in sorted(counted.items()))
            print(f"     {state}: {len(found)}  {detail}".rstrip())


def _print_certificates(certificates) -> None:
    """One line per certificate row, and the fields as the certificate carried
    them.

    There is no word here about whether a certificate is valid, trusted or
    expired, because none of those was measured. The dates are printed and the
    reader draws the conclusion (the writing rules).
    """
    if not certificates:
        return
    for row in sorted(certificates,
                      key=lambda r: (r.family, r.target or "", r.port or 0)):
        where = f"  {row.family} {row.target or 'no address in the document'}"
        if row.state != prober.TLS_STATE_READ:
            print(f"{where} port {row.port}: {row.state} ({row.reason})")
            continue
        certificate = row.certificate
        print(f"{where} port {row.port}: {row.state}")
        print(f"     subject     {certificate.subject}")
        print(f"     issuer      {certificate.issuer}"
              + ("  (the same as the subject)" if certificate.self_issued else ""))
        print(f"     not before  {certificate.not_before or 'could not be read'}")
        print(f"     not after   {certificate.not_after or 'could not be read'}")
        if certificate.names:
            print(f"     names       {', '.join(certificate.names)}")
        print(f"     sha256      {certificate.fingerprint_sha256}")


def _probe_via(con, host_plans, destination, tls_ports=(), vantage=None,
               transport=None, exclude=frozenset(), locks=None) -> int:
    """Probe from a vantage host instead of from this machine.

    The engine runs there, the packets leave there, and the gate travels with
    each batch. `app/dispatch.py` owns how, and this only reports.

    **A host whose pass fails does not stop the others.** One unreachable
    vantage or one unreadable answer is a fact about that pass, and turning it
    into a fleet-wide failure would lose the hosts that did measure. The failure
    is printed and counted rather than swallowed.

    `locks` is set on the vantage's registry row by the caller
    (`registry_row_for_via`), so each batch takes that prober's lock.
    """
    derived = [plan for plan in host_plans if plan.derived]
    for plan in host_plans:
        if not plan.derived:
            print(f"{plan.name}: {plan.note}")
    if not derived:
        print("nothing to probe")
        return 0

    transport = transport or dispatch.SshTransport(destination)
    tally = Counter()
    failed = []
    deleted = []
    for plan in derived:
        print()
        print(plan.name)
        try:
            result = dispatch.run_host(con, plan, transport, vantage,
                                       tls_ports=tls_ports, exclude=exclude,
                                       locks=locks)
        except dispatch.DispatchFailed as exc:
            # Typed, and printed rather than downgraded. A pass that did not
            # happen must not read like a pass that found nothing.
            print(f"  not measured: {exc}", file=sys.stderr)
            failed.append(plan.name)
            continue
        except prober.HostGone:
            # Deleted after the list was made: left out, and no failure.
            print(f"  not measured: {dispatch.SERVER_DELETED}")
            deleted.append(plan.name)
            continue
        _print_results(result.results)
        _print_certificates(result.certificates)
        for row in result.results:
            tally[row.state] += 1
        print(f"  run {result.id} stored from {result.vantage},"
              f" {len(result.results)} results")

    print()
    still_there = len(derived) - len(deleted)
    print(f"{still_there - len(failed)} of {still_there} hosts measured"
          f" from {vantage} via {destination}")
    for state, count in sorted(tally.items()):
        print(f"  {state}: {count}")
    _print_deleted(deleted)
    if failed:
        print(f"  not measured: {', '.join(failed)}")
        return 1
    return 0


def _print_deleted(names) -> None:
    """The servers a pass left out because they were deleted under it. Said
    in the summary as well as on each server's own line, so a pass that
    measured fewer servers than its list held says why."""
    if names:
        word = "server" if len(names) == 1 else "servers"
        print(f"  {len(names)} {word} deleted during the pass: {', '.join(names)}")


def _probe_registry(con, host_plans, tls_ports=(), only=None,
                    transport_factory=None, exclude=frozenset(),
                    locks=None) -> int:
    """Probe every host from every enabled vantage in the registry.

    `only` narrows the pass to one registered vantage by name. The exit code
    is 1 when any host was not measured from any vantage it should have been,
    which is the same rule `_probe_via` has always applied to one vantage: a
    pass that did not happen is not a success, however many others did.
    """
    derived = [plan for plan in host_plans if plan.derived]
    for plan in host_plans:
        if not plan.derived:
            print(f"{plan.name}: {plan.note}")

    chosen = vantages.enabled(con)
    if only is not None:
        chosen = [v for v in chosen if v.name == only]
        if not chosen:
            print(f"no enabled vantage called {only!r} in the registry",
                  file=sys.stderr)
            return 2
    if not chosen:
        print("no enabled vantage in the registry, so nothing is probed. Add"
              " one with python -m app.vantages_cli add", file=sys.stderr)
        return 2
    # ssh, or our prober API on a self-hosted instance
    # (dispatch.default_transport_factory). Asked before anything else, so a
    # half-configured instance says so on every pass, not only on one with
    # something to probe.
    try:
        factory = transport_factory or dispatch.default_transport_factory()
    except dispatch.TransportConfigError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not derived:
        print("nothing to probe")
        return 0

    outcomes = dispatch.run_pass(con, derived, chosen, tls_ports=tls_ports,
                                 transport_factory=factory, exclude=exclude,
                                 locks=locks)

    tally = Counter()
    failed = []
    deleted = []
    for outcome in outcomes:
        print()
        print(f"{outcome.host_name} from {outcome.vantage}")
        if outcome.gone:
            # Deleted after the list was made: left out, and no failure.
            print(f"  not measured: {outcome.failure}")
            deleted.append(outcome.host_name)
            continue
        if outcome.run is None:
            word = "not tried" if outcome.skipped else "not measured"
            print(f"  {word}: {outcome.failure}", file=sys.stderr)
            failed.append(f"{outcome.host_name} from {outcome.vantage}")
            continue
        _print_results(outcome.run.results)
        _print_certificates(outcome.run.certificates)
        for row in outcome.run.results:
            tally[row.state] += 1
        print(f"  run {outcome.run.id} stored from {outcome.run.vantage},"
              f" {len(outcome.run.results)} results")

    print()
    measured = sum(1 for o in outcomes if o.measured)
    owed = sum(1 for o in outcomes if not o.gone)
    # The hosts this line counts are the ones that were there to measure. A
    # server deleted during the pass is named on its own line below, and
    # counting it here as well made the summary disagree with itself, seen on
    # the box on 2026-10-03 (docs/RECORD.md 4.328).
    hosts = len(derived) - len(set(deleted))
    print(f"{measured} of {owed} host passes measured, {hosts}"
          f" hosts from {', '.join(v.name for v in chosen)}")
    for state, count in sorted(tally.items()):
        print(f"  {state}: {count}")
    _print_deleted(deleted)
    if failed:
        print(f"  not measured: {', '.join(failed)}")
        return 1
    return 0


def _probe(con, host_plans, connect, tls_read=None, tls_ports=(), vantage=None,
           exclude=frozenset(), locks=None) -> int:
    derived = [plan for plan in host_plans if plan.derived]
    for plan in host_plans:
        if not plan.derived:
            print(f"{plan.name}: {plan.note}")
    if not derived:
        print("nothing to probe")
        return 0

    done, failed = asyncio.run(_probe_all(con, derived, connect, tls_read,
                                          tls_ports, vantage, exclude, locks))

    tally = Counter()
    read = 0
    for plan, result in done:
        print()
        print(plan.name)
        _print_results(result.results)
        _print_certificates(result.certificates)
        read += sum(1 for row in result.certificates
                    if row.state == prober.TLS_STATE_READ)
        print(f"  run {result.id} stored from {result.vantage},"
              f" {len(result.results)} results")
        tally.update(row.state for row in result.results)
    print()
    # Every state, including the ones that did not happen, because a state
    # missing from a summary reads as a state nobody looked at.
    counts = ", ".join(f"{state} {tally[state]}" for state in prober.STATES)
    print(f"{len(done)} hosts probed, {counts}")
    if tls_ports:
        print(f"{read} certificates read")
    if failed:
        print(f"  not measured: {', '.join(failed)}")
        return 1
    return 0


# ------------------------------------------------------------- the stored run

def _print_last(con, hosts) -> int:
    for host in hosts:
        row = prober.latest_run(con, host["id"])
        if row is None:
            print(f"{host['name']}: no run stored")
            continue
        finished = row["finished_at"] or "it did not finish"
        print(f"{host['name']}  run {row['id']} from {row['vantage']},"
              f" started {row['started_at']}, finished {finished}")
        _print_results([prober.Result(
            family=result["family"], target=result["target"],
            port=result["port"], state=result["state"], reason=result["reason"],
            connect_ms=result["connect_ms"], os_errno=result["os_errno"],
            measured_at=result["measured_at"])
            for result in prober.run_results(con, row["id"])])
        _print_certificates([_stored_certificate(stored)
                             for stored in prober.run_certificates(con, row["id"])])
    return 0


def _stored_certificate(stored) -> "prober.TlsResult":
    """One stored certificate row, back in the engine's own shape, so the
    printing above has one code path rather than two that can drift."""
    certificate = None
    if stored["state"] == prober.TLS_STATE_READ:
        certificate = prober.Certificate(
            subject=stored["subject"] or "", issuer=stored["issuer"] or "",
            not_before=stored["not_before"], not_after=stored["not_after"],
            serial=stored["serial"], self_issued=bool(stored["self_issued"]),
            names=tuple((stored["names"] or "").split()),
            fingerprint_sha256=stored["fingerprint"] or "")
    return prober.TlsResult(
        family=stored["family"], target=stored["target"], port=stored["port"],
        state=stored["state"], reason=stored["reason"], certificate=certificate,
        read_at=stored["read_at"])


# ----------------------------------------------------------------- the command

def parse_args(argv=None):
    # The usage block at the top of this file, and not the rest of it. The
    # reasoning below it is for somebody reading the source, and forty lines of
    # it on a terminal buries the two commands a person came for.
    usage = __doc__.split("\n## ")[0]
    parser = argparse.ArgumentParser(
        prog="prober", description=usage,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_probe = sub.add_parser(
        "probe", help="probe what the documents say, every host or one of them")
    p_probe.add_argument("--host", help="one host by name, rather than all of them")
    p_probe.add_argument("--dry-run", action="store_true",
                         help="print the targets, the ports and the gate's"
                              " answer, and send nothing")
    p_probe.add_argument("--vantage", metavar="NAME",
                         help="where this run is being taken from, which is"
                              " stored with every result. Required for a real"
                              " run, not for a dry run. "
                              + prober.VANTAGE_ENV + " sets it too, and this"
                              " flag wins when both are set")
    p_probe.add_argument("--joined", action="store_true",
                         help="probe the joined port set rather than the"
                              " document's ports alone: every port with a"
                              " listener, a declaration, or a result in the"
                              " newest stored run. This is what both timers"
                              " pass")
    p_probe.add_argument("--changed", action="store_true",
                         help="only hosts where what we would probe has moved"
                              " since the last pass covered it: a new port, a"
                              " port gone, a different address. Nothing else"
                              " is touched, so this can run often without"
                              " putting more connections in anybody's log")
    p_probe.add_argument("--via", metavar="DESTINATION",
                         help="probe from a vantage host over ssh, as"
                              " user@address, the destination of the vantage"
                              " --vantage names in the registry. The packets"
                              " leave that machine and never this one. Without"
                              " it the connects come from wherever this"
                              " command is run, which must never be the"
                              " control plane in production")
    p_probe.add_argument("--registry", action="store_true",
                         help="probe from every enabled vantage in the"
                              " registry, one after another. This is what"
                              " both timers pass. With --vantage NAME, only"
                              " that registered vantage. Refuses when the"
                              " registry holds no enabled vantage")
    p_probe.add_argument("--tls-port", type=int, action="append",
                         dest="tls_ports", metavar="PORT",
                         help="read the certificate this port presents, which"
                              " is one more connection to it. Repeatable, and"
                              " nothing is read without it")
    p_probe.add_argument("--tls-known", action="store_true",
                         help="read the certificate on every port of the plan"
                              " that is a known TLS service: "
                              + ", ".join(str(p) for p in KNOWN_TLS_PORTS)
                              + ". This is what both timers pass")

    p_last = sub.add_parser("last", help="the most recent run that was stored")
    p_last.add_argument("--host", help="one host by name, rather than all of them")

    return parser.parse_args(argv)


# A vantage name is stored with every result, printed, and will appear on the
# published list of addresses we probe from. So it is restricted at the door
# rather than escaped in three places later, which is what store.NAME_RE does
# for a host name and for the same reasons.
VANTAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def chosen_vantage(args):
    """The vantage for this run, or a sentence saying why there is not one.

    Returns (name, complaint). Exactly one of the two is None.

    **A stored measurement has to say where it was taken from.** The same port
    answers from one network and not from another, which is the whole reason
    PRODUCT.md 5c prices a second vantage point, so a result without a vantage
    cannot be read at all. `prober.default_vantage` falls back to the string
    "unnamed" when nothing says otherwise, and on 2026-08-16 that is exactly
    what the first real run in this project's history stored (RECORD 4.53).
    Refusing is the honest answer, because the alternative is a row that reads
    like a measurement and is not one.

    The placeholder is refused by name as well as by shape, so setting the
    environment variable to "unnamed" does not buy its way past this.
    """
    name = getattr(args, "vantage", None)
    if name is None:
        name = os.environ.get(prober.VANTAGE_ENV)
    if name is None or not name.strip():
        return None, (
            "this run would be stored and nothing says where it is being taken"
            " from. Pass --vantage NAME, or set " + prober.VANTAGE_ENV + ". A"
            " result without a vantage cannot be read: the same port answers"
            " from one network and not another. --dry-run needs no vantage.")
    name = name.strip()
    if name == prober.UNNAMED_VANTAGE:
        return None, (
            f"{name!r} is the placeholder this check exists to stop, so it is"
            " not a vantage name. Name the network or the machine this runs"
            " from.")
    if not VANTAGE_RE.match(name):
        return None, (
            "a vantage name is lowercase letters, digits, dot, dash and"
            " underscore, starting with a letter or digit, at most 64"
            f" characters. {name!r} is not.")
    return name, None


def run(con, args, connect=None, tls_read=None) -> int:
    """The commands themselves, with the connection passed in so the tests can
    drive them against a temporary database.

    `connect` and `tls_read` are the two primitives the engine puts on the
    wire, and they are arguments for one reason: the tests hand them stand-ins
    that fail if they are called, which is how "the dry run sends nothing" is
    proved rather than asserted. Left alone they are the engine's own.
    """
    host_name = getattr(args, "host", None)
    # getattr rather than a plain read, because a caller building a Namespace by
    # hand predates this flag and must not start raising.
    named_tls = tuple(getattr(args, "tls_ports", None) or ())
    tls_ports = tls_ports_for(named_tls, getattr(args, "tls_known", False))
    covered, left_out = _selected(con, host_name)
    if host_name is not None and not covered:
        print(f"no host named {host_name!r} that we still accept reports from",
              file=sys.stderr)
        return 1

    if args.command == "last":
        for name, note in left_out:
            print(f"{name}: {note}")
        if not covered:
            print("no hosts enrolled")
            return 0
        return _print_last(con, covered)

    if args.command == "probe":
        for name, note in left_out:
            print(f"{name}: {note}")
        if not covered:
            print("no hosts to probe")
            return 0
        host_plans = [plan_for(con, host) for host in covered]
        if getattr(args, "joined", False):
            # Before the dry run, so the dry run prints the set a real run
            # would actually send rather than a narrower one.
            host_plans = [_with_joined_ports(con, plan) for plan in host_plans]
        # Every vantage address, enabled or not. Read once per pass and
        # handed down, so the three paths below cannot disagree about it.
        exclude = _vantage_addresses(con)
        if args.dry_run:
            return _dry_run(con, host_plans, tls_ports, exclude, named=named_tls)
        # The locks, app/probelock.py. Taken here, after the dry run, so
        # nothing that sends a packet runs outside them and a dry run never
        # waits behind a real pass.
        wait = getattr(args, "lock_wait_seconds", probelock.WAIT_SECONDS)
        try:
            with probelock.OurPass.for_connection(con):
                if dispatch.uses_prober_api():
                    # A self-hosted instance: one pass at a time, whole
                    # (dispatch.uses_prober_api says why).
                    with probelock.ProbeLock.for_connection(con, wait_seconds=wait):
                        return _probe_paths(con, args, host_plans, connect,
                                            tls_read, tls_ports, exclude, None)
                # Our box: each batch takes its prober's lock and its
                # addresses', and the passes run beside each other.
                locks = probelock.BatchLocks.for_connection(con, wait_seconds=wait)
                return _probe_paths(con, args, host_plans, connect, tls_read,
                                    tls_ports, exclude, locks)
        except probelock.ProbeLockHeld as exc:
            print(exc, file=sys.stderr)
            return probelock.EXIT_HELD

    return 1


def _probe_paths(con, args, host_plans, connect, tls_read, tls_ports,
                 exclude, locks) -> int:
    """The three ways packets leave: every vantage in the registry, one named
    vantage over ssh, or this machine. `run` takes the locks for all three,
    `probe.lock` whole or `locks` handed to every batch, and nothing that
    reaches the wire is called from anywhere else."""
    if getattr(args, "registry", False):
        if getattr(args, "via", None):
            print("--registry and --via are two different answers to where"
                  " the packets leave from, give one", file=sys.stderr)
            return 2
        only = getattr(args, "vantage", None)
        if getattr(args, "changed", False):
            host_plans = _moved(con, host_plans)
            if host_plans is None:
                return 0
        return _probe_registry(con, host_plans, tls_ports, only=only,
                               transport_factory=getattr(
                                   args, "transport_factory", None),
                               exclude=exclude, locks=locks)
    vantage, complaint = chosen_vantage(args)
    if vantage is None:
        print(complaint, file=sys.stderr)
        return 2
    if getattr(args, "changed", False):
        host_plans = _moved(con, host_plans)
        if host_plans is None:
            return 0

    via = getattr(args, "via", None)
    if via:
        row, complaint = registry_row_for_via(con, vantage, via)
        if row is None:
            print(complaint, file=sys.stderr)
            return 2
        factory = getattr(args, "transport_factory", None) or dispatch.SshTransport
        return _probe_via(con, host_plans, via, tls_ports, vantage,
                          transport=factory(via), exclude=exclude,
                          locks=None if locks is None else locks.on_prober(row.id))
    return _probe(con, host_plans, connect, tls_read, tls_ports, vantage,
                  exclude=exclude, locks=locks)


def registry_row_for_via(con, vantage: str, destination: str):
    """(the registry's row for a pass named by hand, a sentence) with
    exactly one of the two None.

    A pass `--via` a destination takes the lock of the prober it reaches,
    and that lock is keyed on the vantage's row in the registry, never on a
    name the command typed. So `--vantage` has to name a vantage of the
    registry and `--via` has to be its destination. Otherwise one box could
    be reached under two names and take two locks, and nothing would keep
    its batches one at a time (docs/SPEC-probe-locks.md, point 6). A vantage
    switched off is still a row, so a box can be tried by hand before it is
    switched on.
    """
    row = vantages.by_name(con, vantage) if vantages.table_exists(con) else None
    if row is None:
        return None, (
            f"{vantage!r} is not a vantage in the registry. A pass --via a"
            " destination names a registered vantage with --vantage, and it"
            " is its destination. Add one with python -m app.vantages_cli add")
    if row.destination != destination:
        return None, (
            f"{destination!r} is not the destination of {vantage!r} in the"
            f" registry, which is {row.destination!r}")
    return row, None


def tls_ports_for(named, known: bool) -> tuple:
    """The ports a certificate is read on: the ones named by hand, plus the
    known TLS services when asked. Sorted and without duplicates, so the batch
    a vantage receives is the same whichever way a port got on the list. The
    engine reads only the ports a plan actually probed, so a known port absent
    from a host's plan costs that host nothing."""
    ports = set(named)
    if known:
        ports |= set(KNOWN_TLS_PORTS)
    return tuple(sorted(ports))


def _moved(con, host_plans):
    """The plans whose port set or address set moved since the last pass, or
    None when nothing did, printed either way.

    The ports this pass would cover, not the document's, because the joined
    set is wider and comparing against the document would report every host
    as moved on every tick.
    """
    moved = [plan for plan in host_plans
             if plan.derived
             and dispatch.needs_reprobe(con, plan, set(plan.ports))]
    if not moved:
        print("nothing has moved since the last pass")
        return None
    print(f"{len(moved)} of {len(host_plans)} hosts have moved")
    return moved


def _vantage_addresses(con) -> frozenset:
    """Every address in the registry, or nothing on a database from before
    the registry existed. A test hands `run` a connection that never ran
    `vantages.init`, and that must keep meaning no vantages rather than a
    crash."""
    if not vantages.table_exists(con):
        return frozenset()
    return vantages.all_addresses(con)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        con = cli.open_database(args)
    except sqlite3.Error as exc:
        print(f"the database could not be used: {exc}", file=sys.stderr)
        return 1
    try:
        # Additive and idempotent, the same as every other command here. On a
        # database where the registry has never been created this makes an
        # empty one, which changes no answer: the gate's default is no.
        db.init(con)
        authz.init(con)
        prober.init(con)
        vantages.init(con)
        return run(con, args)
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
