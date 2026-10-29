"""Authorisation to probe an address: proof, a record of it, and expiry.

`docs/PRODUCT.md` section 5 opens with it and SI-6 states it as an
invariant. Probing an address you do not control is computer trespass under
art. 550bis of the Belgian criminal code and the equivalents elsewhere, so
this module is what makes the prober lawful. It is built before anything can
send a packet, on purpose.

Nothing here probes. The only two remote reads in this file fetch evidence the
operator themself published, at a name or an address they nominated, and
neither records or reports a port state. That boundary is the point: a token
file fetched from a web server somebody asked us to read is proof, and it is
never a measurement.

## The gate

`may_probe` is the only way anything may ask whether an address can be
probed. It is not a hint and there is no second path:

  - it takes the address as text and normalises it itself, so no caller can
    hand it a pre-cooked value that skips a check
  - **the default is no.** A malformed address, an address nobody proved, an
    expired proof, a revoked proof and a proof belonging to a revoked host
    all return the same refusal
  - **expiry is decided when the question is asked**, by comparing the stored
    expiry with the clock. `sweep` only writes down what has lapsed, so a
    sweep that never runs cannot leave a lapsed authorisation usable. A row
    the sweep has already written off stays off, so a clock that steps
    backwards cannot make the gate disagree with the listing
  - **a revocation cannot be lost.** Reading published evidence takes a
    network timeout, and a revoke landing inside that window used to be
    overwritten by the verification that was already in flight. The
    verification now takes the write lock before it records, so the two
    orderings are the only two outcomes and both end revoked
  - `require_probe_authorization` is the raising form, so a caller that
    forgets to look at the answer crashes instead of probing

A test in `tests/test_authz.py` fails if the `authorizations` table is named
in any Python file outside this one. That is the part with teeth: a future
prober cannot quietly write its own query without turning the suite red.

## The three proofs, and why each one is proof

**Agent-derived.** Two halves that have to agree. We observe the address a
report arrived from, which the host cannot forge because the connection
completed and the credential authenticated it. The host document separately
lists the addresses the host says it holds: the addresses its sockets are
bound to, and the addresses on its interfaces. An authorisation is recorded
only when the observed source address is also one of those, in the same
family.

Neither half is proof alone, and that is the whole design:

  - the host-side list is **asserted by the host**. A document can claim
    anything, so trusting it by itself would let a target authorise itself by
    saying so
  - the observed source address is **observed by us**, but behind NAT it is
    the gateway's address rather than the host's, and behind carrier-grade
    NAT it is shared with strangers. Probing it would probe somebody else

Requiring both means a host behind NAT simply fails to auto-authorise, which
is the correct answer, and it then uses one of the published proofs below.

**Interface addresses were added on 2026-08-17** (the owner, `docs/RECORD.md`
4.55 item 3) because bind addresses alone did not work. Measured across the
fleet on 2026-08-16: the only socket on either working host bound to that
host's own public address was the DHCP client on udp/68. Every ordinary
service binds the wildcard, which names no address, so a statically addressed
server, which is most production boxes, could never auto-authorise. It worked
on two hosts of three by accident of DHCP.

**Widening the host-side list does not move the anchor, and that is why this
does not weaken SI-6.** An interface address is asserted by the host exactly
as a bind address is, so both are the same kind of claim and neither is
trusted on its own. The security is entirely in the address **we observed**
the report arriving from (`app/ingest.py`, `observed_source_address`). The
host-side list only corroborates that the host knows it holds the address we
already saw. A host that lists a thousand addresses still authorises at most
the one we saw its report come from, and a test pins that bound.

The section's own status is not consulted, on purpose. It is a label the host
writes, and letting it gate anything would give the host a switch. The
addresses in it are claims either way and the anchor decides.

**DNS TXT.** The token is published at the **reverse-DNS name of the address**
(`4.3.2.1.in-addr.arpa`, or the nibble form under `ip6.arpa`). That name is
the one DNS fact only the holder of the address delegation can write, which is
why it is the name we specify. A forward name would prove nothing: anybody can
point `foo.example.com` at an address they do not own. Nothing in this file
turns a name into an address, and a test asserts that.

**HTTP token file.** The token is served at a well-known path on the address
itself. Serving content from an address is control of that address. Three
restrictions make it evidence rather than a rumour: the URL is built by us
from the literal address so there is no name to resolve and nothing to rebind,
**no redirect is ever followed** because a redirect means the bytes came from
somewhere other than the address being proved (the agent's client refuses
redirects for the neighbouring reason, `agent/internal/report/client.go`), and
the body is capped.

Both published proofs derive the name or the URL from the target again at
verification time and refuse if it disagrees with what the challenge row
stored. The place evidence is read from is a derived fact, never a string a
column happens to hold.

## The token

`secrets`, 64 hex characters, its own prefix so it can never be confused with
a host credential, and **only its SHA-256 is stored** while it is pending, the
same posture as `app/store.py`. A challenge row binds it to one target and one
method, so it proves nothing a challenge was not started for.

**A server has one token for its token file, since 2026-10-03**
(`docs/RECORD.md` 4.329). A machine serves one file at the well-known path,
and the file holds one token, so a second address of the same machine could
only be proved by overwriting the token the first one is read against, which
then failed its next reading (4.297, measured). A token file proof started
for a server that already holds a live token file proof is therefore given
that proof's token (`_server_token`). Nothing about what proves an address
moved: every address is still fetched at its own URL and compared with its
own challenge's hash. Only where the token comes from did. DNS TXT keeps a
token for each address, because each address has a name of its own there.

After a successful verification the evidence row holds the string that was
read, verbatim, token included. That is deliberate and it is not a stored
secret: by then the operator has published that exact string in public DNS or
on a public web server, so the only thing it was ever protecting is the moment
before publication, and the hash covers that.

## Expiry and re-proof

An authorisation lapses. Agent-derived lapses in a week, and a running agent
re-proves it every quarter of an hour, so in practice it lapses when the agent
stops reporting from that address, which is exactly when the evidence went
away. A published proof lasts thirty days and is re-proved by verifying the
same challenge again, which re-reads the record or the file and checks the
operator still controls the address. Nothing has to be published twice.

**A published proof is read again every day, since 2026-10-20**, and a read
that finds other content or no file ends it (`renew_published`). Read only
in its last week, a token file proof of a released cloud address outlived
its file by up to thirty days, kept our probers on the next owner's server,
and held the next owner out of the address.

**Every agent proof but workspace 1's lapses in an hour, since 2026-10-20**
(`docs/PRODUCT.md` 5, the clauses of that day). The anchor is an address we
observed and the list beside it is the host's own claim, so a request or a
report sent by hand from a shared address, behind a carrier NAT, an office
NAT or a VPN, with a list naming that address, proves it. That holds for an
instance's presence and for a report to this control plane alike, since any
workspace's host credential can send one. An hour bounds how long such a
proof, or a released cloud address, stays probed. Workspace 1 is our own
fleet and keeps its week. The same clauses give one address to one holder
among every account but workspace 1 (`_held_by_another`), keep presence for
invited instances (`proves_by_presence`), and add the exclusion list below.

An expired authorisation is indistinguishable from one that never existed:
`may_probe` gives the same refusal, in the same words, for never proved,
expired, revoked, belonging to a revoked host, and proved by a different
account. The dates are in the CLI listing, which is where a person looks.

## The exclusion list

An address on it is never proved and never probed, for any account, new ones
included. A revoke ends the proofs that exist, and the next presence or
report proves the address again, which is right for a revoke and wrong after
an abuse report. `exclude` is the stop that stays: it closes every proof of
the address in the same transaction that lists it, and every way to prove
one, and the gate itself, refuse a listed address from then on. Taking an
address off restores nothing.

## Addresses

v4 and v6 are separate targets throughout (`docs/PRODUCT.md` 4b rule 3).
Authorising the v4 address of a host authorises nothing about its v6 address,
because they are literally different rows.

Only globally routable unicast addresses can be registered at all. A private,
loopback, link-local, multicast or carrier-NAT address cannot be probed from
outside in any meaningful way, and refusing them at the door also means the
HTTP proof can never be aimed at this control plane's own network. An address
carrying a zone index is refused too: it names an interface on one machine,
and leaving it in would make one address two rows.
"""

import dataclasses
import errno
import hashlib
import ipaddress
import json
import re
import secrets
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from . import dnstxt, workspace

# The account every authorisation written before workspaces existed carries.
# It is workspace 1's account and `account_for_workspace` below is the only
# thing that decides that, so the mapping lives in one place.
DEFAULT_ACCOUNT = "default"

METHOD_AGENT = "agent"
METHOD_DNS_TXT = "dns_txt"
METHOD_HTTP_TOKEN = "http_token"
METHODS = (METHOD_AGENT, METHOD_DNS_TXT, METHOD_HTTP_TOKEN)

# The agent document names families exactly this way
# (agent/internal/hostdoc.ListeningSocket), so the registry uses the same two
# words rather than inventing a second vocabulary for the same fact.
FAMILY_V4 = "v4"
FAMILY_V6 = "v6"

# A running agent re-proves this every fifteen minutes, so a week means "the
# agent stopped reporting from this address" rather than "a timer went off".
AGENT_TTL_SECONDS = 7 * 24 * 60 * 60

# Every agent proof but workspace 1's, since 2026-10-20 (docs/PRODUCT.md 5):
# an instance's presence, and a report or presence to this control plane from
# any other workspace. The agent's packaged timer runs every quarter hour with
# up to two minutes of delay and every run proves, so two runs in a row can
# fail and the proof still holds. A test reads the timer and holds the two
# together.
HOUR_TTL_SECONDS = 60 * 60

# How an instance was made, which decides whether its agents may prove by
# presence. Invited is `instances_cli add`, by hand. Signup is an instance a
# stranger made for themself, which proves by DNS TXT or a token file only,
# because presence proves a shared address for whoever sends from it.
ORIGIN_INVITED = "invited"
ORIGIN_SIGNUP = "signup"
ORIGINS = (ORIGIN_INVITED, ORIGIN_SIGNUP)

# How long an authorisation snapshot carried to a prober stays usable. Fifteen
# minutes, which is the agent's report interval and the finding debounce, so it
# is a number this project already reasons in rather than a new one. It bounds
# how long a revoked target can still be probed by a prober that has not been
# handed a newer snapshot. THIS IS THE OWNING DEFINITION.
SNAPSHOT_TTL_SECONDS = 15 * 60

# A published proof is re-read rather than re-published, so thirty days costs
# the operator nothing and keeps the evidence recent.
PUBLISHED_TTL_SECONDS = 30 * 24 * 60 * 60

# A challenge that is never completed must not leave a live token lying at a
# name forever. Once it has been verified it becomes the standing re-proof
# record and this no longer applies.
CHALLENGE_TTL_SECONDS = 24 * 60 * 60

# Renewal of a published proof, run from the five-minute sweep since
# 2026-08-26 (docs/RECORD.md 4.104, part 3). SI-6 says an authorisation
# expires when the evidence goes away, and evidence left in place keeps it
# alive without anybody editing DNS again.
#
# Since 2026-10-20 every published proof is read again once a day, no longer
# only in its last week, and a read that finds other content, or an address
# that answers without the file, ends the proof (docs/PRODUCT.md 5). A read
# that gets no answer at all, a timeout or a resolver that does not answer, is
# tried again no sooner than an hour later, because a five-minute timer
# against somebody's server is 288 fetches a day into their log. Two days with
# no good read end the proof too, so a released address that answers nothing
# is not probed past them.
RENEWAL_EVERY_SECONDS = 24 * 60 * 60
RENEWAL_RETRY_SECONDS = 60 * 60
RENEWAL_GIVE_UP_SECONDS = 2 * 24 * 60 * 60

TOKEN_PREFIX = "whpa_"

HTTP_WELL_KNOWN_PATH = "/.well-known/whichports-authorization"
HTTP_PORT = 80
HTTP_TIMEOUT_SECONDS = 10.0
MAX_TOKEN_BYTES = 4096
USER_AGENT = "whichports-authorization-check (+https://whichports.com)"

# 100.64.0.0/10 is shared between a carrier's customers by definition, so no
# single operator controls one of its addresses. Named explicitly rather than
# leaned on ipaddress.is_private, which has covered it differently across
# Python versions.
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")

# One refusal, used for every state that is not a live proof. Never proved,
# expired, revoked and belonging to a revoked host read identically, which is
# what "an expired authorisation is indistinguishable from one that never
# existed" means in practice. It is the same posture ingest.py takes when it
# refuses to say whether a credential ever existed.
NO_PROOF = "no current proof of control"

SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
    id          INTEGER PRIMARY KEY,
    target      TEXT NOT NULL,
    family      TEXT NOT NULL,
    method      TEXT NOT NULL,
    evidence    TEXT NOT NULL,
    account     TEXT NOT NULL,
    host_id     INTEGER REFERENCES hosts(id),
    verified_at TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    revoked_at  TEXT,
    expired_at  TEXT
);

CREATE INDEX IF NOT EXISTS idx_authorizations_target
    ON authorizations(target, family, revoked_at);

CREATE TABLE IF NOT EXISTS authz_challenges (
    id           INTEGER PRIMARY KEY,
    target       TEXT NOT NULL,
    family       TEXT NOT NULL,
    method       TEXT NOT NULL,
    token_hash   TEXT NOT NULL,
    publish_at   TEXT NOT NULL,
    account      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    verified_at  TEXT,
    cancelled_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_authz_challenges_target
    ON authz_challenges(target, family, cancelled_at);

-- The exclusion list, 2026-10-20. One live entry per address: the index
-- refuses a second one with no removed_at, and an address taken off and put
-- back is a second row, so the list keeps what was stopped and when.
CREATE TABLE IF NOT EXISTS authz_exclusions (
    id          INTEGER PRIMARY KEY,
    target      TEXT NOT NULL,
    family      TEXT NOT NULL,
    added_at    TEXT NOT NULL,
    removed_at  TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_authz_exclusions_live
    ON authz_exclusions(target, family) WHERE removed_at IS NULL;
"""


class TargetError(ValueError):
    """The address cannot be a probe target at all."""


class AddressExcluded(TargetError):
    """The address is on the exclusion list. A kind of TargetError on
    purpose: every caller that already refuses an address that can never be
    a target refuses this one the same way."""


class ProofError(Exception):
    """The evidence could not be read. Never "probably fine".

    `answered` is True when the address answered and the answer was not a
    file: a status, or a redirect. That is no file, which ends a proof at its
    next reading. False is no answer at all, which is tried again."""

    def __init__(self, message: str, answered: bool = False):
        super().__init__(message)
        self.answered = answered


class SnapshotUnreadable(ValueError):
    """A snapshot that cannot be read. Deliberately not a subclass of
    `NotAuthorized`, because "I could not read my instructions" and "you may
    not probe that" are different facts and a prober must not report the first
    as the second."""


class NotAuthorized(Exception):
    """Raised by require_probe_authorization. A caller that ignores an answer
    it did not ask for cannot exist, because there is no answer to ignore."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init and alerts.init follow.

    `host_id` on a challenge is the 2026-08-26 addition: a published proof
    started for an address host is that host's, so the authorisation it earns
    carries the host and the probe plan can find it. Older challenges carry
    NULL, which is what they always meant, a proof for the account alone.

    Nothing here rewrites a stored row. A proof by presence written under
    the week, before 2026-10-20 or by the old build in the minutes between a
    deploy's copy and its restart, is read with its hour anyway
    (`_live_until`).
    """
    con.executescript(SCHEMA)
    for table, column in (("authz_challenges", "host_id INTEGER"),
                          ("authorizations", "renewal_attempted_at TEXT"),
                          ("authorizations", "renewal_failure TEXT")):
        try:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    con.commit()


def _begin_writing(con: sqlite3.Connection) -> bool:
    """Take the write lock now, before a check whose answer a write depends
    on. Returns whether this call began the transaction, so a refusal can end
    it without ending anything a caller had open.

    Two requests checking "is this address free" and then writing would both
    find it free. Taken here, the second waits for the first's write and then
    reads it, the same `BEGIN IMMEDIATE` that `proberapi.submit` uses for its
    queue. A transaction that is already open was opened by a write, which
    holds the lock already.
    """
    if con.in_transaction:
        return False
    con.execute("BEGIN IMMEDIATE")
    return True


def _is_our_fleet(account) -> bool:
    """Workspace 1, our own fleet. The one account the clauses of 2026-10-20
    leave as they were: its agents keep their week, and it neither holds an
    address against anybody nor is held out of one."""
    return account == DEFAULT_ACCOUNT


def _lasts_an_hour(account, method) -> bool:
    """Whether a proof of this account and method lasts an hour after its
    last renewal: an agent proof of any account but our own fleet's
    (docs/PRODUCT.md 5, the clauses of 2026-10-20)."""
    return method == METHOD_AGENT and not _is_our_fleet(account)


def agent_ttl_seconds(account) -> int:
    """How long an agent proof recorded now for this account lasts."""
    return AGENT_TTL_SECONDS if _is_our_fleet(account) else HOUR_TTL_SECONDS


def live_until(row) -> datetime | None:
    """When this authorisation stops being live, read the way the gate reads
    it. None when that cannot be read, which is never live.

    The stored expiry, except that a proof which lasts an hour is never read
    past an hour after its last renewal, whatever expiry it carries. A row
    written under the week, before the hour existed or by the old build
    while a deploy is between its copy and its restart, is read with its
    hour all the same, and no stored row has to be rewritten for it. A row
    whose last renewal cannot be read is never live.

    Every reader of "live" in this module asks this, so the gate, the
    listings, the sweep and a snapshot cannot disagree.
    """
    expires = _parse(row["expires_at"])
    if expires is None or not _lasts_an_hour(row["account"], row["method"]):
        return expires
    verified = _parse(row["verified_at"])
    if verified is None:
        return None
    return min(expires, verified + timedelta(seconds=HOUR_TTL_SECONDS))


def _excluded(con: sqlite3.Connection, target: str, family: str) -> bool:
    """Whether this canonical address is on the exclusion list now."""
    return con.execute(
        "SELECT 1 FROM authz_exclusions WHERE target = ? AND family = ?"
        " AND removed_at IS NULL LIMIT 1", (target, family)).fetchone() is not None


def _held_by_another(con: sqlite3.Connection, target: str, family: str,
                     account: str, now: datetime) -> bool:
    """Whether another account holds a live proof of this address, by any of
    the three ways. One address belongs to one holder among every instance
    and every workspace but workspace 1 (docs/PRODUCT.md 5, the clauses of
    2026-10-20). Our own fleet is outside the rule both ways.

    "Live" is read the way `_active_authorization` reads it.

    Two holders of one address can only come from a database written before
    the rule. Then the one whose live proof is older, the lower row, keeps
    the address and the other is refused, so the first never goes dark and
    the second lapses at the end of its own expiry.
    """
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.target = ? AND a.family = ?"
        "   AND a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR h.revoked_at IS NULL)",
        (target, family)).fetchall()
    mine, others = [], []
    for row in rows:
        expires = live_until(row)
        if expires is None or expires <= now or _is_our_fleet(row["account"]):
            continue
        if row["account"] == account:
            mine.append(row["id"])
        else:
            others.append(row["id"])
    if not others:
        return False
    return not mine or min(others) < min(mine)


def _close_agent_proofs_of_others(con: sqlite3.Connection, target: str,
                                  family: str, account: str, now: datetime) -> int:
    """Close every live agent proof another holder has of this address, for
    a published proof about to be recorded. Returns how many.

    A DNS TXT record in the address's reverse zone, or a token file served
    from the address, is evidence of control. An agent proof is an address
    we saw a request come from and a list the host wrote, which a request
    made by hand from a shared address also gives. So the published proof
    wins (docs/PRODUCT.md 5, decided on the second challenge of 2026-10-20),
    and the other holder's next presence or report is refused as held.

    Closed the way a revoke closes, so the row stays as the record. Our own
    fleet is outside the rule both ways: its proofs close nothing and are
    never closed here. Called with the write lock held.
    """
    if _is_our_fleet(account):
        return 0
    rows = con.execute(
        "SELECT * FROM authorizations WHERE target = ? AND family = ?"
        " AND method = ? AND account != ?"
        " AND revoked_at IS NULL AND expired_at IS NULL",
        (target, family, METHOD_AGENT, account)).fetchall()
    closed = 0
    for row in rows:
        if _is_our_fleet(row["account"]):
            continue
        ends = live_until(row)
        if ends is None or ends <= now:
            continue
        con.execute("UPDATE authorizations SET revoked_at = ? WHERE id = ?",
                    (now.isoformat(), row["id"]))
        closed += 1
    return closed


def _claim_refused(con: sqlite3.Connection, target: str, family: str,
                   account: str, now: datetime):
    """The refusal a proof about to be recorded gets, or None. Asked with
    the write lock held, so nothing can change the answer before the write.

    An excluded address answers `target_refused`, the class an address that
    can never be a target gets. A held address answers `address_held`.
    Neither sentence names an account."""
    if _excluded(con, target, family):
        return ProofResult(False, f"{target} is excluded, so it is never proved",
                           code="target_refused")
    if not _is_our_fleet(account) and _held_by_another(
            con, target, family, account, now):
        return ProofResult(False, f"another account holds a live proof of {target}",
                           code="address_held")
    return None


# ------------------------------------------------------------------- clock

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(now: datetime | None) -> datetime:
    """Every entry point takes its clock through here.

    Comparing a naive datetime with an aware one raises, and a TypeError
    escaping the gate in the middle of a prober run is a worse outcome than
    reading a naive stamp as UTC. Reading it as UTC is also what `_parse`
    already does for stored values, so the two halves of a comparison agree.
    """
    if now is None:
        return _now()
    return now if now.tzinfo else now.replace(tzinfo=timezone.utc)


def _parse(value):
    """Timestamps are ISO strings in UTC in this database. A row written by an
    older build, or by hand, must not take a decision down.

    The same shape as `alerts._parse`, duplicated rather than moved to a
    shared module because lifting a helper out is its own PR. A test pins that the two agree.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ------------------------------------------------------------------ targets

def _is_probeable(ip) -> bool:
    """Globally routable unicast only. Everything else either cannot be
    reached from a prober outside, or is not one operator's address to
    authorise."""
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return False
    if ip.is_link_local or ip.is_private or ip.is_reserved:
        return False
    if ip.version == 4:
        return ip not in SHARED_ADDRESS_SPACE
    # A v4-mapped v6 address is a v4 address in a v6 costume, and letting one
    # in would break "v4 and v6 are separate targets" at the first hurdle.
    return ip.ipv4_mapped is None and not ip.is_site_local


def normalise_target(address: str) -> tuple[str, str]:
    """Return (canonical text, family) for an address we are allowed to hold
    an authorisation for. Raises TargetError otherwise.

    Canonicalising here is what stops `2001:db8::1` and its expanded spelling
    being two different rows for one address.
    """
    if not isinstance(address, str):
        raise TargetError("address must be text")
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        raise TargetError(f"{address!r} is not an IP address") from None
    # A zone index (the `%eth0` in `fe80::1%eth0`) names a local interface, and
    # `ipaddress` keeps it in the canonical text. Left in, a global address
    # with `%eth0` appended and the same address without it are two rows for
    # one address, so revoking one would leave the other live, which is the
    # split this function exists to stop. A target is remote by definition, so
    # a zone index on one can only be wrong.
    if getattr(ip, "scope_id", None):
        raise TargetError(
            f"{address!r} carries a zone index, which names an interface on one"
            " machine rather than an address anyone can reach")
    if not _is_probeable(ip):
        raise TargetError(f"{ip} is not a globally routable unicast address")
    return str(ip), FAMILY_V4 if ip.version == 4 else FAMILY_V6


# ------------------------------------------------------------------- tokens

# What `new_token` makes, and nothing else. `start_proof` holds a token it
# is handed to this shape.
TOKEN_SHAPE = re.compile(r"^" + TOKEN_PREFIX + r"[0-9a-f]{64}$")


def new_token() -> str:
    """Its own prefix, so a leaked token is recognisable and can never be
    mistaken for a host credential (`whp_`, app/store.py)."""
    return TOKEN_PREFIX + secrets.token_hex(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _token_matches(candidate: str, stored_hash: str) -> bool:
    return secrets.compare_digest(token_hash(candidate.strip()), stored_hash)


# ------------------------------------------------------- account and workspace

def account_for_workspace(workspace_id: int) -> str:
    """The account string one workspace's authorisations are recorded under.

    **This is what keeps SI-6 as strict as it was, with a second workspace in
    the picture.** Every row here already carries an account and
    `_active_authorization` already filters on it, so making the account the
    workspace means a host in workspace 2 proving an address authorises it for
    workspace 2 and for nobody else. It is the gate that already existed
    answering a narrower question, rather than a second gate beside it.

    **Workspace 1 maps back to the pre-workspace string, deliberately.** Every
    authorisation on the production box was written with `account = 'default'`.
    A mapping that spelled workspace 1 anything else would make every one of
    those rows stop matching the moment this deploys, and a gate that suddenly
    says no is the prober quietly refusing to probe the owner's three hosts. This
    keeps them live and rewrites no data.
    """
    if workspace_id == workspace.DEFAULT_WORKSPACE_ID:
        return DEFAULT_ACCOUNT
    return f"w{int(workspace_id)}"


INSTANCE_ACCOUNT_PREFIX = "i"


def account_for_instance(instance_id: int) -> str:
    """The account a self-hosted instance's proofs are recorded under.

    Since 2026-09-30 (the prober API, `app/proberapi.py`) a self-hosted
    whichports proves addresses to this registry so our probers may probe
    them. Each instance is one account, which is the same property
    `account_for_workspace` gives a workspace: the gate already answers "did
    *this* account prove it", so one instance proving an address authorises it
    for that instance and nobody else.

    `i` rather than `w`, so an instance account can never be spelled like a
    workspace's, and neither can ever be `default`. A test holds all three
    apart.
    """
    if isinstance(instance_id, bool) or not isinstance(instance_id, int) \
            or instance_id < 1:
        raise ValueError(f"{instance_id!r} is not an instance id")
    return f"{INSTANCE_ACCOUNT_PREFIX}{instance_id}"


def is_instance_account(account) -> bool:
    """Whether an account string is one `account_for_instance` makes."""
    if not isinstance(account, str) or not account.startswith(
            INSTANCE_ACCOUNT_PREFIX):
        return False
    digits = account[len(INSTANCE_ACCOUNT_PREFIX):]
    return digits.isascii() and digits.isdigit() and not digits.startswith("0")


def account_for_host(host) -> str:
    """The account for a host row, read from the row itself.

    Derived from the row rather than passed in by a caller, because an account
    a caller can pass is an account a caller can pass wrongly, and passing
    another workspace's is exactly the cross-workspace authorisation SI-6
    forbids. A row from a database that has not run `db.init` yet carries no
    column, and that answers workspace 1, which is where the migration puts
    everything.
    """
    keys = host.keys() if hasattr(host, "keys") else ()
    if "workspace_id" not in keys:
        return DEFAULT_ACCOUNT
    value = host["workspace_id"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return DEFAULT_ACCOUNT
    return account_for_workspace(value)


# -------------------------------------------------------------- the gate

@dataclasses.dataclass(frozen=True)
class Decision:
    """The answer to "may I probe this address". `allowed` is the only field
    anything is permitted to branch on. `reason` is for a person, and `target`
    is the canonical spelling of the address that was allowed, so a caller
    probes what was authorised rather than the text it was handed."""
    allowed: bool
    reason: str
    target: str | None = None


def _active_authorization(con: sqlite3.Connection, target: str, family: str,
                          now: datetime, account: str = DEFAULT_ACCOUNT):
    """The one query that decides currency. Everything about "is this
    address authorised" is in these few lines and nowhere else.

    **The account is part of the question, not decoration.** Every row already
    carries one, and without this filter the gate answered "somebody proved
    this address" when the question is "did *this* account prove it". v1 has
    one account, so the filter changes no answer today, which is exactly when
    it is cheap to add: on the day a second account exists the gate is already
    right, rather than needing to be made right under pressure.

    A row whose expiry cannot be read counts as no row. Refusing to probe
    because a timestamp is unreadable is the only safe way round.

    `expired_at` is checked as well as the clock. Expiry is still decided
    against the clock, so an unrun sweep cannot leave a lapsed row usable, but
    once the sweep has written a row off the listing shows it as expired and a
    person acts on that. A clock that steps backwards, which is one NTP
    correction, must not make the gate say yes to a row the listing calls
    dead.
    """
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.target = ? AND a.family = ? AND a.account = ?"
        "   AND a.revoked_at IS NULL"
        "   AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR h.revoked_at IS NULL)"
        " ORDER BY a.id DESC",
        (target, family, account),
    ).fetchall()
    for row in rows:
        expires = live_until(row)
        if expires is not None and expires > now:
            return row
    return None


def may_probe(con: sqlite3.Connection, address: str,
              now: datetime | None = None,
              account: str = DEFAULT_ACCOUNT) -> Decision:
    """**The only way anything may ask whether an address can be probed.**

    When the prober exists it calls this and nothing else. It never reads the
    table, never caches an answer across a run, and never treats a refusal as
    a warning.

    The refusal for "another account proved this" is the same sentence as for
    never proved, which is the rule the whole module follows: an address the
    caller may not probe reveals nothing about why.
    """
    now = _as_utc(now)
    try:
        target, family = normalise_target(address)
    except TargetError as exc:
        return Decision(False, str(exc))
    # An excluded address has no live proof, because `exclude` closed them
    # all and nothing records a new one. Asked here as well, so that rule
    # does not rest on every writer, and refused in the same words.
    if _excluded(con, target, family):
        return Decision(False, f"{NO_PROOF}: {target}")
    row = _active_authorization(con, target, family, now, account)
    if row is None:
        return Decision(False, f"{NO_PROOF}: {target}")
    return Decision(
        True,
        f"{target} proved by {row['method']}, verified {row['verified_at']},"
        f" expires {row['expires_at']}",
        target,
    )


def require_probe_authorization(con: sqlite3.Connection, address: str,
                                now: datetime | None = None,
                                account: str = DEFAULT_ACCOUNT) -> str:
    """The raising form, and the one a prober should call. Returns the
    canonical target text. A caller that forgets to check gets an exception
    rather than a value it can accidentally treat as permission."""
    decision = may_probe(con, address, now=now, account=account)
    if not decision.allowed or decision.target is None:
        raise NotAuthorized(decision.reason)
    return decision.target


# ------------------------------------------------------------- recording

@dataclasses.dataclass(frozen=True)
class ProofResult:
    """`reason` is a sentence for a person on this box. `code` is the same
    outcome as one word from a closed set, for anything that crosses the wire:
    the prober API answers a self-hosted instance with the code and never the
    sentence (SI-8), because the sentence names addresses and paths."""
    recorded: bool
    reason: str
    authorization_id: int | None = None
    code: str = ""


# The codes `verify_proof` and `record_presence_claim` give. Closed, so a
# caller can map each one and a test can hold the set. `address_held` is the
# 2026-10-20 addition: another account holds a live proof of the address.
PROOF_CODES = frozenset({
    "proved", "no_such_challenge", "challenge_cancelled", "challenge_expired",
    "not_a_published_method", "target_refused", "challenge_mismatch",
    "evidence_unreadable", "token_not_found", "not_held", "address_held",
})


def _record(con: sqlite3.Connection, target: str, family: str, method: str,
            evidence: dict, account: str, host_id: int | None,
            ttl_seconds: int, now: datetime) -> int:
    """Write one authorisation. Every successful proof lands here, so there is
    one place where a row is created and one place where an expiry is set.

    Re-proving something that is still live refreshes that row rather than
    adding a second one. A reporting agent re-proves every fifteen minutes and
    a row per quarter of an hour would bury the history instead of being it.
    Re-proving something that lapsed or was revoked writes a new row, so the
    old one stays visible as the record of what went away and when.

    **The row it refreshes has to be this account's, and until 2026-08-27 the
    account was left off this one call.** `_active_authorization` filters on
    the account, so with the argument missing every write here asked about
    workspace 1 whatever workspace it was writing for. Two things came of that,
    both measured rather than feared:

      - a published proof in workspace 2, for an address workspace 1 had
        already proved by the same method with no host attached, found
        workspace 1's live row and **updated it**. Workspace 2 got no
        authorisation at all and was told it had one, and workspace 1's expiry
        was pushed out thirty days on a stranger's evidence.
      - an agent in any workspace but 1 never found its own live row, so every
        report inserted a new one. Ninety-six rows a day per host, which is the
        history this function exists to keep readable.
    """
    expires_at = (now + timedelta(seconds=ttl_seconds)).isoformat()
    payload = json.dumps(evidence, sort_keys=True)
    live = _active_authorization(con, target, family, now, account)
    if live is not None and live["method"] == method and live["host_id"] == host_id:
        con.execute(
            "UPDATE authorizations SET evidence = ?, verified_at = ?, expires_at = ?"
            " WHERE id = ?", (payload, now.isoformat(), expires_at, live["id"]))
        con.commit()
        return live["id"]
    cur = con.execute(
        "INSERT INTO authorizations (target, family, method, evidence, account,"
        " host_id, verified_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (target, family, method, payload, account, host_id, now.isoformat(),
         expires_at),
    )
    con.commit()
    return cur.lastrowid


# -------------------------------------------------------- agent-derived proof

def _document_object(document) -> dict:
    """A host document as a mapping, defensively. Anything that is not the
    shape we expect yields an empty mapping, because a malformed document is a
    document that proves nothing, never an exception."""
    if isinstance(document, (str, bytes)):
        try:
            document = json.loads(document)
        except (ValueError, TypeError):
            return {}
    return document if isinstance(document, dict) else {}


def _bind_addresses(document) -> list[dict]:
    """The listening sockets in a host document, defensively."""
    sockets = _document_object(document).get("sockets")
    if not isinstance(sockets, dict):
        return []
    listening = sockets.get("listening")
    if not isinstance(listening, list):
        return []
    return [entry for entry in listening if isinstance(entry, dict)]


def _interface_addresses(document) -> list[dict]:
    """The interface addresses in a host document, defensively, read with the
    same posture as the sockets above.

    The two sections are read independently for the same reason the agent
    collects them independently: one unreadable half must never lose the other.
    A host running a build from before this section existed simply has none of
    them, which is the everyday case until a package is published, and it
    changes nothing about what its sockets prove.
    """
    section = _document_object(document).get("interface_addresses")
    if not isinstance(section, dict):
        return []
    addresses = section.get("addresses")
    if not isinstance(addresses, list):
        return []
    return [entry for entry in addresses if isinstance(entry, dict)]


def _entry_claims_address(entry: dict, key: str, wanted, family: str) -> bool:
    """Does this document entry assert the address we observed, in the family
    we observed it in?

    **Every step is a refusal by default**, because the entry is text the host
    wrote. The address has to be a string, it has to parse, it has to carry no
    zone index, the entry's own family field has to agree with the family the
    observed address is in, and only then do the two addresses get compared.

    The zone-index check is the one worth spelling out. `normalise_target`
    refuses a target carrying one, because a zone index names an interface on
    one machine and leaving it in would make one address two rows. So an entry
    carrying one must not match the same address without one. Python's
    IPv6Address compares scope ids in `__eq__` as of 3.9, so this check is
    belt and braces rather than the only thing standing there, and it is
    written out because relying on that subtlety is not something a reviewer
    should have to know.
    """
    claimed = entry.get(key)
    if not isinstance(claimed, str):
        return False
    try:
        parsed = ipaddress.ip_address(claimed.strip())
    except ValueError:
        return False
    if getattr(parsed, "scope_id", None):
        return False
    # The document's own family field has to agree with the address it
    # carries. Both halves or neither, the same rule as everywhere else.
    if entry.get("family") != family:
        return False
    return parsed == wanted


def record_agent_proof(con: sqlite3.Connection, host_id: int,
                       observed_address: str, document,
                       account: str | None = None,
                       now: datetime | None = None) -> ProofResult:
    """Authorise the address a host's own report arrived from, but only when
    the host also reports holding it.

    `observed_address` is the source address of the report as this control
    plane saw it. It must be an address we observed, never one a request
    asserted in a header, or the whole proof is worth nothing.

    **This function's only decision is whether the host corroborates the
    address we already observed.** It never reads an address out of the
    document and authorises it. Everything below either matches against
    `target` or refuses, so the set of addresses this can ever authorise has
    exactly one member no matter what the document says.

    **The document is the host's own claim, as a presence body is**, and any
    workspace's host credential can send a report by hand from a shared
    address with a document naming it. So since 2026-10-20 a proof of any
    workspace but workspace 1, our own fleet, lasts an hour
    (`agent_ttl_seconds`) and is refused for an address another account
    holds, the rules an instance's presence follows (docs/PRODUCT.md 5).
    """
    now = _as_utc(now)
    try:
        target, family = normalise_target(observed_address)
    except TargetError as exc:
        return ProofResult(False, str(exc))

    host = con.execute("SELECT * FROM hosts WHERE id = ?", (host_id,)).fetchone()
    if host is None:
        return ProofResult(False, "no such host")
    if host["revoked_at"]:
        return ProofResult(False, "the host is revoked")

    # The account is this host's own workspace, read off the row that was just
    # loaded. A caller may still name one, which is what the tests and the
    # command line do, but the ingest passes nothing and therefore cannot
    # record a proof under a workspace that is not the reporting host's.
    if account is None:
        account = account_for_host(host)

    wanted = ipaddress.ip_address(target)
    # The two halves of the host's own account of which addresses it holds. A
    # bound socket names an address only when the service did not bind the
    # wildcard, which on an ordinary server it always does, so the interface
    # list is the half that usually answers.
    matching_sockets = [
        entry for entry in _bind_addresses(document)
        if _entry_claims_address(entry, "bind_address", wanted, family)]
    matching_interfaces = [
        entry for entry in _interface_addresses(document)
        if _entry_claims_address(entry, "address", wanted, family)]

    if not matching_sockets and not matching_interfaces:
        return ProofResult(
            False,
            f"the report arrived from {target} but {host['name']} does not report"
            " holding it, on an interface or as a bind address, which is what a"
            " host behind NAT looks like. Use a DNS TXT or HTTP token proof for"
            " this address",
        )

    began = _begin_writing(con)
    refused = _claim_refused(con, target, family, account, now)
    if refused is not None:
        if began:
            con.rollback()
        return refused

    evidence = {
        "observed_source": target,
        "matching_sockets": matching_sockets,
        "matching_interface_addresses": matching_interfaces,
    }
    authorization_id = _record(con, target, family, METHOD_AGENT, evidence,
                               account, host_id, agent_ttl_seconds(account), now)
    return ProofResult(True, f"{target} authorised from {host['name']}'s own report",
                       authorization_id)


# ------------------------------------- a self-hosted instance's own agents

# More addresses than one server holds on its interfaces is not a claim, it is
# a list somebody is fishing with. Bounded so a claim is never a large read.
MAX_CLAIMED_ADDRESSES = 64


def proves_by_presence(origin) -> bool:
    """Whether an instance made this way may prove by presence. Only an
    invited one, and anything that is not exactly that word is not."""
    return origin == ORIGIN_INVITED


def record_presence_claim(con: sqlite3.Connection, account: str,
                          observed_address: str, claimed,
                          now: datetime | None = None, *,
                          origin) -> ProofResult:
    """Authorise the address a self-hosted agent's request arrived from, but
    only when the same request says the host holds it on an interface.

    **The same two halves as `record_agent_proof`, and the same anchor.** A
    self-hosted agent reports to its own control plane, so this one never
    sees its document. Instead the agent sends its presence straight to the
    prober API (`app/proberapi_routes.py`), over each family, carrying the
    addresses on its own interfaces and nothing else. The address we observed
    the request arriving from is the half the host cannot forge. The list is
    the host's assertion and only corroborates, exactly as the interface
    section of a document does, so:

      - an address the request did not arrive from proves nothing, however
        many times the list names it
      - an address the request arrived from that the list does not name
        proves nothing, which is a host behind NAT, whose request arrives
        from a gateway it does not hold

    Decided 2026-09-30 (`docs/RECORD.md` 4.217), keeping both halves of
    `docs/RECORD.md` 4.185.

    **Only an instance account.** A hosted workspace proves its addresses from
    the documents its agents send, and a bare claim must never become a way
    into one. `account` is derived by the caller from the proof key that
    authenticated the request, never read from the request.

    **Only an invited instance, since 2026-10-20.** Both halves hold for a
    request sent by hand from a shared address, a carrier or office NAT or a
    VPN, so presence proves that address for whoever sends from it. An
    instance a stranger made for themself proves by DNS TXT or a token file
    instead. `origin` is how the instance was made, read by the caller off
    the same row as the account, and it has no default, so no caller can
    leave it out. The route checks first, so a refusal here is a mistake and
    it is loud, the same as for a workspace account.

    **One hour, one instance, and never an excluded address.** The proof
    lapses `HOUR_TTL_SECONDS` after the last presence, and the address
    is refused when another account holds it or it is on the exclusion
    list. Both are asked with the write lock held (`_begin_writing`), so two
    instances racing for one address end with one holder.
    """
    if not is_instance_account(account):
        raise ValueError(f"{account!r} is not an instance account")
    if not proves_by_presence(origin):
        raise ValueError(f"an instance made by {origin!r} does not prove by presence")
    now = _as_utc(now)
    try:
        target, family = normalise_target(observed_address)
    except TargetError as exc:
        return ProofResult(False, str(exc), code="target_refused")

    wanted = ipaddress.ip_address(target)
    held = False
    if isinstance(claimed, list) and len(claimed) <= MAX_CLAIMED_ADDRESSES:
        for entry in claimed:
            if not isinstance(entry, str):
                continue
            try:
                parsed = ipaddress.ip_address(entry.strip())
            except ValueError:
                continue
            # A zone index names an interface on one machine, and the same
            # address with one and without one must not be one claim. The
            # reason is written out at `_entry_claims_address`.
            if getattr(parsed, "scope_id", None):
                continue
            if parsed == wanted:
                held = True
                break
    if not held:
        return ProofResult(
            False,
            f"the request arrived from {target} and the host does not say it"
            " holds it on an interface, which is what a host behind NAT looks"
            " like. Use a DNS TXT or HTTP token proof for this address",
            code="not_held")

    began = _begin_writing(con)
    refused = _claim_refused(con, target, family, account, now)
    if refused is not None:
        if began:
            con.rollback()
        return refused

    evidence = {"observed_source": target, "held_on_interface": target}
    authorization_id = _record(con, target, family, METHOD_AGENT, evidence,
                               account, None, HOUR_TTL_SECONDS, now)
    return ProofResult(True, f"{target} authorised from its own agent's presence",
                       authorization_id, code="proved")


# ------------------------------------------------------- published proofs

@dataclasses.dataclass(frozen=True)
class Challenge:
    """What the operator needs to publish. The token is in memory here and on
    their screen, and the challenge row holds only its hash."""
    id: int
    target: str
    family: str
    method: str
    token: str
    publish_at: str
    expires_at: str


def _publish_at(target: str, family: str, method: str) -> str:
    if method == METHOD_DNS_TXT:
        return ipaddress.ip_address(target).reverse_pointer
    host = f"[{target}]" if family == FAMILY_V6 else target
    return f"http://{host}:{HTTP_PORT}{HTTP_WELL_KNOWN_PATH}"


def _server_token(con: sqlite3.Connection, account: str, host_id: int,
                  now: datetime) -> str | None:
    """The token this server's token file is read against today, or None.

    One machine serves one file, so every address of one server has to be
    proved by the same token (`docs/RECORD.md` 4.329, and 4.297 for what
    happened when each address got its own). This finds the token to give a
    new challenge, and it is deliberately narrow:

      - only a **live** token file proof lends its token: not revoked, not
        lapsed, its expiry still ahead of the clock, its server not revoked.
        The same reading of "live" as `_active_authorization`
      - only a proof of **this server and this account**. Another server's
        token is never looked at, in this workspace or any other
      - only a token the registry **still expects**: the proof's standing
        challenge has to carry the hash of exactly this string. A proof whose
        challenge was cancelled, or an evidence row that holds anything but
        the token, lends nothing. This is also what makes it safe to show:
        the evidence row is text, and only text that hashes to what we minted
        ever leaves here
      - a challenge that was never verified lends nothing either. Its token
        exists here as a hash alone and cannot be shown a second time

    The token comes out of the proof's evidence row, which has held the string
    that was read since the registry was built (see "The token" at the top).
    Nothing new is stored for this. With several live proofs the newest
    reading wins, because that is the one the file is known to have held last.

    None means there is nothing to share, and the caller mints a new token.
    """
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " JOIN hosts h ON h.id = a.host_id"
        " WHERE a.host_id = ? AND a.account = ? AND a.method = ?"
        "   AND a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND h.revoked_at IS NULL"
        " ORDER BY a.verified_at DESC, a.id DESC",
        (host_id, account, METHOD_HTTP_TOKEN)).fetchall()
    for row in rows:
        expires = _parse(row["expires_at"])
        if expires is None or expires <= now:
            continue
        try:
            evidence = json.loads(row["evidence"])
        except (ValueError, TypeError):
            continue
        read = evidence.get("read") if isinstance(evidence, dict) else None
        if not isinstance(read, str):
            continue
        challenge = _standing_challenge(con, row)
        if challenge is None:
            continue
        # The string as it is stored, with nothing trimmed. Its hash goes on
        # the new challenge row, so it has to be the token itself and not the
        # token with a space beside it.
        if not secrets.compare_digest(token_hash(read), challenge["token_hash"]):
            continue
        return read
    return None


def server_token(con: sqlite3.Connection, host, now: datetime | None = None) -> str | None:
    """The token this server's token file is read against today, or None
    (`_server_token`). For an instance that names it to our prober API when
    it starts a token file proof of another address of the same server
    (`app/proberproofs.py`)."""
    return _server_token(con, account_for_host(host), host["id"], _as_utc(now))


def _account_token(con: sqlite3.Connection, account: str, wanted: str,
                   now: datetime) -> str | None:
    """`wanted`, when it is the token one of this account's live token file
    proofs is read against, or None.

    For our prober API (docs/PRODUCT.md 5, the clause of 2026-10-03, and 5g).
    An instance's proofs carry no server on our side, so `_server_token`
    cannot find a server's token, and an instance names it instead. It is
    honoured as narrowly as `_server_token` is: only a live proof, not
    revoked, not lapsed, not ended by a reading, of this account and no
    other, whose standing challenge still holds the hash of exactly this
    string. Another account's token, a DNS proof's token and a token nobody
    made lend nothing, and the caller makes a new one.
    """
    wanted_hash = token_hash(wanted)
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.account = ? AND a.method = ?"
        "   AND a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR h.revoked_at IS NULL)"
        " ORDER BY a.id DESC",
        (account, METHOD_HTTP_TOKEN)).fetchall()
    for row in rows:
        ends = live_until(row)
        if ends is None or ends <= now:
            continue
        challenge = _standing_challenge(con, row)
        if challenge is None:
            continue
        if secrets.compare_digest(challenge["token_hash"], wanted_hash):
            return wanted
    return None


def start_proof(con: sqlite3.Connection, address: str, method: str,
                account: str = DEFAULT_ACCOUNT,
                now: datetime | None = None,
                host_id: int | None = None,
                adopt_token: str | None = None,
                same_token_as: str | None = None) -> Challenge:
    """Mint a challenge for one address and one method. Raises TargetError for
    an address that can never be a target and ValueError for a method that is
    not published proof. `host_id` names the host this proof is for, so the
    authorisation it earns belongs to that host; None is a proof for the
    account alone, which is what every challenge before 2026-08-26 was.

    A token file proof for a server that already holds a live one is given
    that server's token and no new one, see `_server_token`. A proof for the
    account alone names no server, so it gets a token of its own every time.

    `adopt_token` is for an instance that uses our prober API, and nothing
    else: the token our API made for the same proof, which this registry takes
    as it is, so one published token proves the address to both registries
    (docs/PRODUCT.md 5g, 2026-10-24, `app/proberproofs.py`). **It is refused
    for an instance's account**, which is what our own API proves under: on
    our side the token is always ours to make. An instance that could name it
    could name the token another instance's file already serves, and prove an
    address it does not control (SI-6). Anything not shaped like a token we
    make is refused too.

    `same_token_as` is the other way round, for our prober API: the token an
    instance names for a token file proof, because the server's file already
    holds it. It is given again only when it is the token of one of this
    account's own live token file proofs (`_account_token`), the rule
    `_server_token` follows for a server, and a new one is made otherwise. So
    the token stays ours to make, and an instance can only ask again for one
    we made for it. Only for a token file proof with no server, which is what
    an instance's proofs are on our side."""
    if method not in (METHOD_DNS_TXT, METHOD_HTTP_TOKEN):
        raise ValueError(f"{method!r} is not a published proof method")
    if same_token_as is not None:
        if adopt_token is not None:
            raise ValueError("a token is either taken or asked for, never both")
        if method != METHOD_HTTP_TOKEN or host_id is not None:
            raise ValueError("a token is asked for only for a token file proof"
                             " with no server")
        if not isinstance(same_token_as, str) or not TOKEN_SHAPE.fullmatch(same_token_as):
            raise ValueError("that is not a token this registry makes")
    if adopt_token is not None:
        if is_instance_account(account):
            raise ValueError("a token is never taken for an instance's proof")
        if not isinstance(adopt_token, str) or not TOKEN_SHAPE.fullmatch(adopt_token):
            raise ValueError("that is not a token this registry makes")
    now = _as_utc(now)
    target, family = normalise_target(address)
    # Refused for an excluded address, which is the stop an abuse report asks
    # for. Not refused for an address another account holds: a start shows
    # no evidence, so it is not where holding is decided, and verify refuses
    # it once the evidence was read.
    if _excluded(con, target, family):
        raise AddressExcluded(f"{target} is excluded, so it is never proved")
    token = adopt_token
    if token is None and same_token_as is not None:
        token = _account_token(con, account, same_token_as, now)
    if token is None and method == METHOD_HTTP_TOKEN and host_id is not None:
        token = _server_token(con, account, host_id, now)
    if token is None:
        token = new_token()
    publish_at = _publish_at(target, family, method)
    expires_at = (now + timedelta(seconds=CHALLENGE_TTL_SECONDS)).isoformat()
    cur = con.execute(
        "INSERT INTO authz_challenges (target, family, method, token_hash,"
        " publish_at, account, created_at, expires_at, host_id)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (target, family, method, token_hash(token), publish_at, account,
         now.isoformat(), expires_at, host_id),
    )
    con.commit()
    return Challenge(cur.lastrowid, target, family, method, token, publish_at,
                     expires_at)


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Any 3xx is a refusal, never a hop.

    Following one would mean the token file came from somewhere other than the
    address being proved, and the whole value of this check is that the bytes
    came from that address. Returning None here leaves urllib to raise the
    3xx as an HTTPError, which is exactly the outcome we want.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


REDIRECT_CODES = (301, 302, 303, 307, 308)


def fetch_token_file(url: str, timeout: float = HTTP_TIMEOUT_SECONDS) -> str:
    """Read the token file. The URL is built by this module from a validated
    literal address, never supplied by anyone, so there is no name to resolve,
    no scheme but http, and no port but 80.

    **Proxies are turned off here, and that is a security property rather than
    a preference.** This check is worth something only because the bytes came
    from the address being proved. A proxy in the way means they came from the
    proxy, and it is the same hole `_NoRedirects` closes for a 3xx.

    `urllib.request.build_opener` installs a bare `ProxyHandler()` unless it is
    handed one, and a bare one reads `http_proxy` from the environment
    (Python 3.14 `Lib/urllib/request.py`, the `default_classes` loop). So an
    `http_proxy` in the sweep unit's environment, or exported in a shell that
    runs the CLI, would silently reroute every proof fetch. An empty mapping
    registers no proxy for any scheme.
    """
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirects())
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT},
                                     method="GET")
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ProofError(f"the address answered {response.status}",
                                 answered=True)
            body = response.read(MAX_TOKEN_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.code in REDIRECT_CODES:
            raise ProofError(
                f"the address answered {exc.code} and redirected, so the file"
                " would have come from somewhere other than the address being"
                " proved", answered=True) from None
        raise ProofError(f"the address answered {exc.code}", answered=True) from None
    except (OSError, ValueError) as exc:
        raise ProofError(unread_token_file(exc)) from None
    if len(body) > MAX_TOKEN_BYTES:
        raise ProofError("the token file is larger than a token")
    return body.decode("utf-8", "replace")


UNREAD_TOKEN_FILE = "the token file could not be read"
_UNREACHABLE = (errno.EHOSTUNREACH, errno.ENETUNREACH)


def unread_token_file(exc: BaseException) -> str:
    """What a read of the token file that got no file says, in words.

    The address window shows this sentence in the fail tone. It said
    "could not read the token file: URLError", a class name, and a person
    with a firewall in the way could not tell it from a server that is down
    (the second big test, 2026-10-25, case D13). Three cases are told
    apart, by the exception's class and errno and never by its text (SI-8):
    no answer before the timeout, a refused connection, and no route.
    Anything else is said as not read and no more.
    """
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, TimeoutError):
        return f"{UNREAD_TOKEN_FILE}: no answer on port 80"
    if isinstance(reason, ConnectionRefusedError):
        return f"{UNREAD_TOKEN_FILE}: port 80 refused the connection"
    if isinstance(reason, OSError) and reason.errno in _UNREACHABLE:
        return f"{UNREAD_TOKEN_FILE}: no route to the address"
    return UNREAD_TOKEN_FILE


def verify_proof(con: sqlite3.Connection, challenge_id: int,
                 now: datetime | None = None,
                 resolver=None, fetcher=None) -> ProofResult:
    """Read the evidence and, if it is the token we minted, record an
    authorisation.

    `resolver` and `fetcher` exist so the tests never touch a real resolver or
    a real web server. In production they are the two functions above.
    """
    now = _as_utc(now)
    resolver = resolver or dnstxt.query_txt
    fetcher = fetcher or fetch_token_file

    row = con.execute("SELECT * FROM authz_challenges WHERE id = ?",
                      (challenge_id,)).fetchone()
    if row is None:
        return ProofResult(False, "no such challenge", code="no_such_challenge")
    closed = challenge_closed(row, now)
    if closed is not None:
        return closed

    if row["method"] not in (METHOD_DNS_TXT, METHOD_HTTP_TOKEN):
        return ProofResult(False,
                           f"{row['method']!r} is not a published proof method",
                           code="not_a_published_method")

    # Where the evidence is read from is derived from the target again here
    # rather than taken from the row. `publish_at` is a stored string, and a
    # stored string that does not match the address it claims to prove would
    # point this fetch at a name or a URL of somebody else's choosing. It also
    # means a row whose target today's rules refuse cannot be re-proved.
    try:
        target, family = normalise_target(row["target"])
    except TargetError as exc:
        return ProofResult(False, str(exc), code="target_refused")
    if family != row["family"] or _publish_at(target, family, row["method"]) \
            != row["publish_at"]:
        return ProofResult(
            False,
            "this proof does not match the address it names, start a new one",
            code="challenge_mismatch")

    # Before the read, so nothing is fetched from an excluded address, and
    # asked again under the write lock below, for an exclusion that lands
    # while the read is in flight.
    if _excluded(con, target, family):
        return ProofResult(False, f"{target} is excluded, so it is never proved",
                           code="target_refused")

    try:
        read = _read_evidence(row, resolver, fetcher)
    except ProofError as exc:
        # An address that answered without the file holds no token, which
        # is the same no as other content. Getting no answer at all is not
        # the same as reading the wrong thing. Both are a no, and each says
        # which in its own sentence.
        code = "token_not_found" if exc.answered else "evidence_unreadable"
        return ProofResult(False, str(exc), code=code)
    if read is None:
        return ProofResult(False, f"the token was not found at {row['publish_at']}",
                           code="token_not_found")

    # Another holder's published proof whose evidence is gone from where it
    # was published, read again now rather than at its next daily reading,
    # so the next owner of a released address is not held out by it.
    gone = _published_proofs_gone(con, target, family, row["account"], now,
                                  resolver, fetcher)

    # Reading the evidence above took a DNS timeout or an HTTP timeout to
    # finish, and a revocation can land inside that window. So the challenge is
    # stamped here rather than after recording, and only while it is still
    # open. Being a write, this takes the database's write lock and starts the
    # transaction that `_record` commits, so a concurrent revoke either got
    # there first and this updates nothing, or it waits and then closes the row
    # written below. Without it a revoke during the read is simply lost, and
    # the person who ran it is told nothing.
    stamped = con.execute(
        "UPDATE authz_challenges SET verified_at = ?"
        " WHERE id = ? AND cancelled_at IS NULL",
        (now.isoformat(), row["id"]))
    if stamped.rowcount != 1:
        con.rollback()
        return ProofResult(False, "the challenge was cancelled, start a new one",
                           code="challenge_cancelled")
    # The write lock is held from the stamp on, so these answers stand until
    # `_record` commits. Evidence just read in the address's own reverse zone
    # or from the address itself outranks another holder's agent proof, so
    # that one is closed first. A refusal after it takes the stamp and the
    # closing back with it: the challenge stays open, and verifying it again
    # works once the address is free.
    for authorization_id, reason in gone:
        _end_proof(con, authorization_id, now, reason)
    _close_agent_proofs_of_others(con, target, family, row["account"], now)
    refused = _claim_refused(con, target, family, row["account"], now)
    if refused is not None:
        con.rollback()
        return refused

    evidence = {"read_from": row["publish_at"], "read": read}
    # Verified rather than consumed: the same published record is what re-proof
    # reads, so nobody has to edit DNS again in thirty days.
    authorization_id = _record(con, target, family, row["method"],
                               evidence, row["account"], _challenge_host(row),
                               PUBLISHED_TTL_SECONDS, now)
    return ProofResult(True, f"{target} authorised by {row['method']}",
                       authorization_id, code="proved")


def challenge_closed(row, now: datetime | None = None) -> ProofResult | None:
    """The answer a verify of this challenge row ends on before any evidence
    is read, because the challenge was cancelled or its day is over, or None
    when it is open. `verify_proof` asks it first, and so does an instance
    before it asks our prober API to read anything (`app/proberproofs.py`).

    A challenge that has already been verified is the standing re-proof
    record, and its day no longer applies to it."""
    now = _as_utc(now)
    if row["cancelled_at"]:
        return ProofResult(False, "the challenge was cancelled, start a new one",
                           code="challenge_cancelled")
    if not row["verified_at"]:
        expires = _parse(row["expires_at"])
        # An unreadable expiry counts as expired, the same way round as the
        # gate.
        if expires is None or expires <= now:
            return ProofResult(False, "the challenge expired, start a new one",
                               code="challenge_expired")
    return None


def _read_evidence(row, resolver, fetcher) -> str | None:
    """The token as it was read for this challenge row, or None when what is
    there is not it. Raises ProofError when it could not be read."""
    if row["method"] == METHOD_DNS_TXT:
        return _verify_dns(row, resolver)
    return _verify_http(row, fetcher)


def _published_proofs_gone(con: sqlite3.Connection, target: str, family: str,
                           account: str, now: datetime, resolver,
                           fetcher) -> list[tuple[int, str]]:
    """Another holder's live published proofs of this address whose token is
    no longer where it was published, read again now. Returns (row id, why)
    for each, for `verify_proof` to end once it holds the write lock.

    A token file holds one token, so when the next owner of an address serves
    theirs, the last owner's is gone, and a reverse zone's new keeper decides
    what its TXT records hold. A read that gets no answer leaves the proof as
    it is, for its daily reading to decide. Our own fleet is outside the
    one-holder rule both ways, so nothing is read for it or of it here.
    """
    if _is_our_fleet(account):
        return []
    rows = con.execute(
        "SELECT * FROM authorizations WHERE target = ? AND family = ?"
        " AND method IN (?, ?) AND account != ?"
        " AND revoked_at IS NULL AND expired_at IS NULL",
        (target, family, METHOD_DNS_TXT, METHOD_HTTP_TOKEN, account)).fetchall()
    gone = []
    for row in rows:
        if _is_our_fleet(row["account"]):
            continue
        ends = live_until(row)
        if ends is None or ends <= now:
            continue
        challenge = _standing_challenge(con, row)
        if challenge is None:
            gone.append((row["id"], "no verified challenge to read again"))
            continue
        try:
            found = _read_evidence(challenge, resolver, fetcher)
        except ProofError as exc:
            if not exc.answered:
                continue
            found = None
        if found is None:
            gone.append((row["id"],
                         f"the token was not found at {challenge['publish_at']}"))
    return gone


def _end_proof(con: sqlite3.Connection, authorization_id: int, now: datetime,
               reason: str) -> bool:
    """End a published proof whose evidence is gone: written off the way the
    sweep writes off a lapse, with why. Only a row still live is touched.
    The caller commits. Its standing challenge stays, so publishing the token
    again and verifying it again proves the address again."""
    stamp = now.isoformat()
    cur = con.execute(
        "UPDATE authorizations SET expired_at = ?, renewal_attempted_at = ?,"
        " renewal_failure = ? WHERE id = ? AND revoked_at IS NULL"
        " AND expired_at IS NULL", (stamp, stamp, reason, authorization_id))
    return cur.rowcount == 1


def _verify_dns(row, resolver) -> str | None:
    """The matching TXT string, or None if the name holds no such string.
    Raises ProofError when the name could not be read at all."""
    try:
        strings = resolver(row["publish_at"])
    except dnstxt.DnsError as exc:
        raise ProofError(f"could not read TXT at {row['publish_at']}: {exc}") from None
    for text in strings:
        if isinstance(text, str) and _token_matches(text, row["token_hash"]):
            return text
    return None


def _verify_http(row, fetcher) -> str | None:
    """The token file's contents if they are the token, None if they are not.
    `fetcher` raises ProofError when the file could not be read."""
    body = fetcher(row["publish_at"])
    return body.strip() if _token_matches(body, row["token_hash"]) else None


# ------------------------------------------------------------- revocation

def revoke(con: sqlite3.Connection, address: str,
           now: datetime | None = None, account: str | None = None) -> int:
    """Stop probing this address now. Returns how many live authorisations
    were closed.

    Outstanding challenges for the address are cancelled in the same
    transaction. Leaving one open would let the next verification re-authorise
    the address a second after somebody revoked it, which is not a revocation.

    With `account` given, only that account's rows are touched. The dashboard
    passes the operator's workspace, because one workspace revoking an address
    another workspace proved would be the cross-workspace reach SI-6 forbids
    in the other direction. The CLI passes nothing and keeps its fleet-wide
    reach, which is what an operator on the box means by revoke.

    A revoke ends what exists. An agent still sending from the address proves
    it again with its next report or presence, as a new row. `exclude` below
    is the stop that stays.
    """
    now = _as_utc(now)
    target, family = normalise_target(address)
    stamp = now.isoformat()
    scope, params = ("", ()) if account is None else (" AND account = ?", (account,))
    cur = con.execute(
        "UPDATE authorizations SET revoked_at = ? WHERE target = ? AND family = ?"
        " AND revoked_at IS NULL" + scope, (stamp, target, family) + params)
    con.execute(
        "UPDATE authz_challenges SET cancelled_at = ? WHERE target = ? AND family = ?"
        " AND cancelled_at IS NULL" + scope, (stamp, target, family) + params)
    con.commit()
    return cur.rowcount


def revoke_account(con: sqlite3.Connection, account: str,
                   now: datetime | None = None) -> int:
    """Stop probing everything one account proved. Returns how many live
    authorisations were closed.

    For a self-hosted instance that is revoked (`app/instances.py`): its key
    stops working at once, and this makes sure nothing it proved can be probed
    on its behalf afterwards either. Open challenges are cancelled in the same
    transaction, for the reason `revoke` gives.

    **Only instance accounts.** A workspace is never ended this way, and
    refusing anything else means a slip in a caller cannot close every proof
    in workspace 1.
    """
    if not is_instance_account(account):
        raise ValueError(f"{account!r} is not an instance account")
    stamp = _as_utc(now).isoformat()
    cur = con.execute(
        "UPDATE authorizations SET revoked_at = ?"
        " WHERE account = ? AND revoked_at IS NULL", (stamp, account))
    con.execute(
        "UPDATE authz_challenges SET cancelled_at = ?"
        " WHERE account = ? AND cancelled_at IS NULL", (stamp, account))
    con.commit()
    return cur.rowcount


# ------------------------------------------------------ erasing a workspace
#
# For `app/erase.py`, which deletes an account with its workspace and every
# row about them, when the person asks for it. Everywhere else a proof ends
# by `revoke`, which keeps the row as the history. Here the history is what
# goes. The deletes are here and nowhere else because this module is the only
# one that may touch these tables.

# The two tables a workspace's proofs are in. The exclusion list is not one:
# it names no account, and it is the record of what we were asked to stop.
WORKSPACE_PROOF_TABLES = ("authorizations", "authz_challenges")

# A workspace's rows: recorded under its account, or bound to one of its
# servers. Both, because a challenge started before 2026-08-26 carries no
# server, and a proof for the account alone carries none either.
_OF_WORKSPACE = ("account = ? OR host_id IN"
                 " (SELECT id FROM hosts WHERE workspace_id = ?)")


def _workspace_account(workspace_id: int) -> str:
    """The account string of a workspace that may be erased. Workspace 1 may
    not: its account is `default`, which every proof written before
    workspaces existed carries."""
    if isinstance(workspace_id, bool) or not isinstance(workspace_id, int) \
            or workspace_id <= workspace.DEFAULT_WORKSPACE_ID:
        raise ValueError(f"workspace {workspace_id!r} is not one that is erased")
    return account_for_workspace(workspace_id)


def workspace_challenge_ids(con: sqlite3.Connection, workspace_id: int) -> list[int]:
    """The number of every challenge one workspace started, so a row kept
    beside a challenge (`prober_challenges`) can go with it. Read before
    `erase_workspace_proofs`, which deletes them."""
    account = _workspace_account(workspace_id)
    return [row[0] for row in con.execute(
        f"SELECT id FROM authz_challenges WHERE {_OF_WORKSPACE} ORDER BY id",
        (account, workspace_id))]


def erase_workspace_proofs(con: sqlite3.Connection, workspace_id: int) -> dict:
    """Delete every proof and every challenge of one workspace, lapsed and
    revoked ones included, and say per table how many went.

    In the caller's transaction, and never committed here: an erase is all
    or nothing, and its dry run is the same deletes rolled back.
    """
    account = _workspace_account(workspace_id)
    went = {}
    for table in WORKSPACE_PROOF_TABLES:
        went[table] = con.execute(f"DELETE FROM {table} WHERE {_OF_WORKSPACE}",
                                  (account, workspace_id)).rowcount
    return went


# --------------------------------------------------------- the exclusion list

def exclude(con: sqlite3.Connection, address: str,
            now: datetime | None = None) -> tuple[bool, int]:
    """Put an address on the exclusion list and close every proof of it, for
    every account, in one transaction. Returns (whether it was added now,
    how many proofs were closed).

    Run by hand on the box after an abuse report (`ops/RUNBOOK.md`). From the
    commit on, no presence, report, start or verify proves the address, for
    any instance or workspace, and the gate refuses it. An address already
    on the list is not added twice, and any proof of it is closed again all
    the same. Raises TargetError for what can never be a target, which is
    never probed anyway.
    """
    now = _as_utc(now)
    target, family = normalise_target(address)
    stamp = now.isoformat()
    began = _begin_writing(con)
    try:
        added = not _excluded(con, target, family)
        if added:
            con.execute(
                "INSERT INTO authz_exclusions (target, family, added_at)"
                " VALUES (?, ?, ?)", (target, family, stamp))
        closed = con.execute(
            "UPDATE authorizations SET revoked_at = ? WHERE target = ?"
            " AND family = ? AND revoked_at IS NULL", (stamp, target, family)).rowcount
        con.execute(
            "UPDATE authz_challenges SET cancelled_at = ? WHERE target = ?"
            " AND family = ? AND cancelled_at IS NULL", (stamp, target, family))
    except BaseException:
        if began:
            con.rollback()
        raise
    con.commit()
    return added, closed


def unexclude(con: sqlite3.Connection, address: str,
              now: datetime | None = None) -> bool:
    """Take an address off the exclusion list. Returns whether it was on it.

    **Nothing is restored.** The proofs `exclude` closed stay closed, and
    the address is probed again only after somebody proves it again. The
    entry stays as the record, with when it was taken off.
    """
    target, family = normalise_target(address)
    cur = con.execute(
        "UPDATE authz_exclusions SET removed_at = ? WHERE target = ?"
        " AND family = ? AND removed_at IS NULL",
        (_as_utc(now).isoformat(), target, family))
    con.commit()
    return cur.rowcount == 1


def active_exclusion(con: sqlite3.Connection, address: str):
    """The live entry for this address, or None. Raises TargetError for what
    can never be a target."""
    target, family = normalise_target(address)
    return con.execute(
        "SELECT * FROM authz_exclusions WHERE target = ? AND family = ?"
        " AND removed_at IS NULL", (target, family)).fetchone()


def list_exclusions(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every address ever put on the list, newest first, the ones taken off
    included."""
    return con.execute(
        "SELECT * FROM authz_exclusions ORDER BY id DESC").fetchall()


# ---------------------------------------------------------------- renewal

def _standing_challenge(con, row):
    """The verified challenge this authorisation rests on, or None. Verified
    rather than consumed is the design (`verify_proof`): the same challenge is
    what re-proof reads, so nobody publishes twice.

    **It matches the host as well as the address.** Two host rows in one
    workspace can both prove the same address, and without this clause the
    newest challenge answered for every authorisation of that address. The
    row belonging to the other host was then read against a token that is not
    its own: `_record` correctly refuses to move a live row between hosts, so
    nothing was corrupted, but the caller counted the attempt as a success and
    the row it was actually looking at was never extended. It lapsed on its
    own a week later with `renewal_failure` reading NULL, which is the sweep
    reporting a renewal it did not perform.

    `IS` rather than `=` because an account-level proof carries `host_id
    NULL`, and NULL never equals anything. It has to match itself.
    """
    return con.execute(
        "SELECT * FROM authz_challenges WHERE target = ? AND family = ? AND method = ?"
        " AND account = ? AND host_id IS ? AND verified_at IS NOT NULL"
        " AND cancelled_at IS NULL ORDER BY id DESC LIMIT 1",
        (row["target"], row["family"], row["method"], row["account"],
         row["host_id"])).fetchone()


def renew_published(con: sqlite3.Connection, now: datetime | None = None,
                    resolver=None, fetcher=None) -> dict:
    """Read the evidence again for every published proof last read a day ago
    or more.

    Only the two published methods are here. An agent-derived proof renews
    itself with every report the agent sends, and nothing here should ever
    outlive an agent that stopped reporting.

    A successful read refreshes the authorisation through `_record`, the
    same way a hand-run verify does, so its thirty days start again. A read
    that finds other content, or an address that answers without the file,
    ends the proof at once (`_end_proof`). A read that gets no answer is
    written on the row with its reason and the time, tried again no sooner
    than an hour later, and ends the proof once no read has been good for
    `RENEWAL_GIVE_UP_SECONDS`. A proof with no standing challenge can never
    be read again and ends too.

    Returns, by target: what was renewed, every read that did not renew
    with why, which of those ended their proof, and what was left for the
    hour. `resolver` and `fetcher` exist for the tests, as on `verify_proof`.
    """
    now = _as_utc(now)
    renewed, failed, ended, skipped = [], [], [], []
    rows = con.execute(
        "SELECT * FROM authorizations WHERE method IN (?, ?)"
        " AND revoked_at IS NULL AND expired_at IS NULL ORDER BY verified_at",
        (METHOD_DNS_TXT, METHOD_HTTP_TOKEN)).fetchall()
    for row in rows:
        expires = _parse(row["expires_at"])
        if expires is None or expires <= now:
            continue  # lapsed already, sweep() writes that down
        verified = _parse(row["verified_at"])
        since_good = None if verified is None else (now - verified).total_seconds()
        if since_good is not None and since_good < RENEWAL_EVERY_SECONDS:
            continue
        attempted = _parse(row["renewal_attempted_at"]) if "renewal_attempted_at" in row.keys() else None
        if attempted is not None and (now - attempted).total_seconds() < RENEWAL_RETRY_SECONDS:
            skipped.append(row["target"])
            continue
        challenge = _standing_challenge(con, row)
        if challenge is None:
            reason = "no verified challenge to read again, start a new proof"
            _end_proof(con, row["id"], now, reason)
            con.commit()
            failed.append((row["target"], reason))
            ended.append(row["target"])
            continue
        result = verify_proof(con, challenge["id"], now=now,
                              resolver=resolver, fetcher=fetcher)
        if result.recorded:
            _note_renewal(con, row["id"], now, None)
            renewed.append(row["target"])
            continue
        failed.append((row["target"], result.reason))
        no_answer = result.code == "evidence_unreadable"
        if no_answer and since_good is not None and since_good < RENEWAL_GIVE_UP_SECONDS:
            _note_renewal(con, row["id"], now, result.reason)
        else:
            _end_proof(con, row["id"], now, result.reason)
            con.commit()
            ended.append(row["target"])
    return {"checked": len(rows), "renewed": renewed, "failed": failed,
            "ended": ended, "skipped": skipped}


def _note_renewal(con, authorization_id: int, now: datetime, failure: str | None) -> None:
    con.execute(
        "UPDATE authorizations SET renewal_attempted_at = ?, renewal_failure = ?"
        " WHERE id = ?", (now.isoformat(), failure, authorization_id))
    con.commit()


# ------------------------------------------------------------------ sweep

def sweep(con: sqlite3.Connection, now: datetime | None = None) -> dict:
    """Write down what has lapsed.

    Bookkeeping only. `may_probe` compares the stored expiry with the clock
    every time it is asked, so a sweep that never runs cannot leave a lapsed
    authorisation usable. This exists so a listing reads honestly and so an
    operator can see what went away and when.
    """
    now = _as_utc(now)
    expired = []
    rows = con.execute(
        "SELECT * FROM authorizations WHERE revoked_at IS NULL AND expired_at IS NULL"
    ).fetchall()
    for row in rows:
        expires = live_until(row)
        if expires is None or expires <= now:
            con.execute("UPDATE authorizations SET expired_at = ? WHERE id = ?",
                        (now.isoformat(), row["id"]))
            expired.append(row["target"])
    con.commit()
    return {"checked": len(rows), "expired": expired}


def last_proof_made(con: sqlite3.Connection, account: str) -> str | None:
    """When a verify last proved an address for this account, as stored, or
    None. A proof's daily reading by the sweep is not a proof made: it
    refreshes the authorisation and leaves the challenge alone, so the
    challenge's own time is read. For `instancesignup.end_unused`."""
    return con.execute(
        "SELECT MAX(verified_at) FROM authz_challenges WHERE account = ?",
        (account,)).fetchone()[0]


def forget_unproved_challenges(con: sqlite3.Connection,
                               now: datetime | None = None) -> int:
    """Delete every instance's challenge that never proved its address once
    its day is over. Returns how many.

    A start keeps the address an instance named, and since the open signup a
    stranger's instance can start one for any public address. One that
    proved nothing is evidence of nothing, so it is kept for its day and no
    longer. A proved one stays, as the record of the proof. Our own control
    plane's challenges are not touched: they belong to a server and go with
    it (`store.py`). The connection overwrites what it deletes
    (`db.forget_what_is_deleted`).
    """
    now = _as_utc(now)
    due = []
    for row in con.execute(
            "SELECT id, account, expires_at FROM authz_challenges"
            " WHERE verified_at IS NULL"):
        if not is_instance_account(row[1]):
            continue
        # Compared as times, not as text, the way the gate reads an expiry.
        # An expiry nothing can read counts as over.
        expires = _parse(row[2])
        if expires is None or expires <= now:
            due.append(row[0])
    for challenge_id in due:
        con.execute("DELETE FROM authz_challenges WHERE id = ?", (challenge_id,))
    con.commit()
    return len(due)


# ----------------------------------------------------------------- listing

def list_authorizations(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every authorisation ever recorded, newest first. Lapsed and revoked
    rows stay: they are the history of what we were allowed to do and when."""
    return con.execute(
        "SELECT a.*, h.name AS host_name FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id ORDER BY a.id DESC").fetchall()


def list_challenges(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute(
        "SELECT * FROM authz_challenges ORDER BY id DESC").fetchall()


def _challenge_host(row) -> int | None:
    """The host a challenge row names, or None for a row from before the
    column existed or a proof started for the account alone."""
    return row["host_id"] if "host_id" in row.keys() else None


def challenge_for_host(con: sqlite3.Connection, challenge_id: int,
                       host_id: int, account: str) -> sqlite3.Row | None:
    """One challenge, only if it is this host's and this account's. Anything
    else is None, the same posture `active_host_by_name` takes: a challenge
    that is somebody else's reads exactly like one that does not exist."""
    return con.execute(
        "SELECT * FROM authz_challenges WHERE id = ? AND host_id = ? AND account = ?",
        (challenge_id, host_id, account)).fetchone()


def challenge_for_account(con: sqlite3.Connection, challenge_id,
                          account: str) -> sqlite3.Row | None:
    """One challenge, only if this account started it. Another account's reads
    exactly like one that does not exist, the posture `challenge_for_host`
    takes, so an instance cannot learn that a number belongs to somebody."""
    if isinstance(challenge_id, bool) or not isinstance(challenge_id, int):
        return None
    return con.execute(
        "SELECT * FROM authz_challenges WHERE id = ? AND account = ?",
        (challenge_id, account)).fetchone()


def live_for_account(con: sqlite3.Connection, account: str,
                     now: datetime | None = None) -> list[sqlite3.Row]:
    """Every authorisation this account holds that the gate would honour right
    now, decided the way `_active_authorization` decides it. What the prober
    API shows an instance about its own proofs, and nothing about anyone
    else's."""
    now = _as_utc(now)
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.account = ? AND a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR h.revoked_at IS NULL)"
        " ORDER BY a.family, a.target, a.id DESC", (account,)).fetchall()
    live = []
    for row in rows:
        expires = live_until(row)
        if expires is not None and expires > now:
            live.append(row)
    return live


def live_proof_counts(con: sqlite3.Connection,
                      now: datetime | None = None) -> dict[str, int]:
    """How many authorisations each account holds that the gate would honour
    right now, in one query over every account, decided the way
    `live_for_account` decides it for one. The admin console reads this for
    every instance at once (docs/screens/admin/SPEC.md), and this module is
    the one door to these tables, so the query lives here and not there."""
    now = _as_utc(now)
    rows = con.execute(
        "SELECT a.account, a.method, a.verified_at, a.expires_at"
        " FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR h.revoked_at IS NULL)").fetchall()
    counts: dict[str, int] = {}
    for row in rows:
        expires = live_until(row)
        if expires is not None and expires > now:
            counts[row["account"]] = counts.get(row["account"], 0) + 1
    return counts


def live_addresses_for_host(con: sqlite3.Connection, host_id: int,
                            now: datetime | None = None) -> list[sqlite3.Row]:
    """Every authorisation that lets this host be probed right now, decided
    the way the gate decides it: live rows whose expiry is still ahead of
    the clock. This is what a probe plan for an address host is built from.
    """
    now = _as_utc(now)
    rows = con.execute(
        "SELECT * FROM authorizations WHERE host_id = ? AND revoked_at IS NULL"
        " AND expired_at IS NULL ORDER BY family, target", (host_id,)).fetchall()
    live = []
    for row in rows:
        expires = live_until(row)
        if expires is not None and expires > now:
            live.append(row)
    return live


def addresses_for_host(con: sqlite3.Connection, host_id: int) -> dict:
    """What the settings screen shows for one host: its authorisations, live
    and lapsed, and the challenges still waiting to be verified."""
    return {
        "authorizations": con.execute(
            "SELECT * FROM authorizations WHERE host_id = ? ORDER BY id DESC",
            (host_id,)).fetchall(),
        "open_challenges": con.execute(
            "SELECT * FROM authz_challenges WHERE host_id = ? AND verified_at IS NULL"
            " AND cancelled_at IS NULL ORDER BY id DESC", (host_id,)).fetchall(),
    }


# ====================================================== carrying the gate away
#
# `require_probe_authorization` above is the authority and stays the authority.
# What follows lets the same decision be asked on a machine that does not hold
# the database, which is what a prober on its own box is.
#
# **Why this exists at all.** The prober asks the gate before every single
# connect, not once per run, and `prober.Prober._probe_one_port` puts nothing
# between the answer and the packet on purpose. Moving the engine to a vantage
# host without moving that per-connect question would quietly turn an invariant
# into a start-of-run formality. So the question travels instead.
#
# **Why a snapshot is not a second authority.** It cannot say yes to anything
# the database did not already say yes to, because only the control plane
# builds one and it builds it by asking the database. It can only say no more
# often, as it ages. Everything below is written so that every unexpected shape
# is a refusal.
#
# **The cost, which is real and bounded rather than hidden.** A target revoked
# after a snapshot is built stays probeable until that snapshot is replaced.
# Two things bound it: the snapshot carries its own expiry and refuses
# everything once stale, and the control plane ships work in batches with a
# fresh snapshot per batch, so the window is one batch rather than one run.


class ProbeAuthority:
    """What `prober.Prober` asks before each connect.

    One method, the same contract as `require_probe_authorization`: return the
    canonical target text, or raise `NotAuthorized`. Returning the canonical
    text rather than a boolean is deliberate and is not a convenience. It means
    the address that gets connected to is the one the gate approved, rather
    than the one the caller happened to be holding.
    """

    def require(self, address: str, now: datetime | None = None) -> str:
        raise NotImplementedError


class DatabaseAuthority(ProbeAuthority):
    """The gate as it has always been, asked against the live registry.

    This is what the control plane uses and the behaviour is unchanged: one
    indexed read per connect against the database that holds the truth.
    """

    def __init__(self, con: sqlite3.Connection, account: str = DEFAULT_ACCOUNT):
        self._con = con
        self._account = account

    def require(self, address: str, now: datetime | None = None) -> str:
        return require_probe_authorization(self._con, address, now=now,
                                           account=self._account)


class SnapshotAuthority(ProbeAuthority):
    """The gate as a fact that can be carried to another machine.

    Built only by `build_snapshot` below, which asks the database. Holds
    canonical targets and the instant each one stops being authorised, plus an
    instant the whole snapshot stops being usable.

    **Every refusal path is explicit and there is no path that raises anything
    other than NotAuthorized.** A prober that crashes on a malformed snapshot
    is a prober that stops measuring, which is safe, but a prober that treats a
    malformed snapshot as permission is the failure this class exists to make
    impossible.
    """

    def __init__(self, targets: dict, expires_at: datetime):
        self._targets = dict(targets)
        self._expires_at = _as_utc(expires_at)

    @property
    def expires_at(self) -> datetime:
        return self._expires_at

    @property
    def targets(self) -> dict:
        """A copy, so nothing can widen a snapshot after it was built."""
        return dict(self._targets)

    def require(self, address: str, now: datetime | None = None) -> str:
        moment = _as_utc(now) if now is not None else _as_utc(None)

        # The whole snapshot first. A stale one authorises nothing at all,
        # which is what bounds how long a revoked target stays probeable.
        if moment >= self._expires_at:
            raise NotAuthorized(
                "the authorisation snapshot expired at "
                f"{self._expires_at.isoformat()}, so nothing is authorised from"
                " it. The control plane builds a new one per batch")

        # The address goes through the same door every candidate target does,
        # so `2001:db8::1` and its expanded spelling cannot be two answers, and
        # a private or zone-indexed address is refused here exactly as the
        # database would refuse it.
        try:
            target, _family = normalise_target(address)
        except TargetError as exc:
            raise NotAuthorized(str(exc)) from None

        until = self._targets.get(target)
        if until is None:
            raise NotAuthorized(
                f"{target} is not in the authorisation snapshot this prober was"
                " given, so nothing here says anybody proved they control it")

        # A per-target expiry the control plane copied from the registry. The
        # snapshot being fresh does not make an authorisation inside it fresh.
        #
        # None is refused before `_as_utc` sees it, and that is not tidiness.
        # `_as_utc(None)` answers with the current time, so a None expiry would
        # read as "expires now", and a caller passing an earlier clock would
        # then be told yes. An absent expiry is not an expiry.
        if until is None:
            raise NotAuthorized(
                f"{target} carries no expiry in the snapshot, which is not"
                " permission")
        try:
            until = _as_utc(until)
        except (TypeError, ValueError, AttributeError):
            raise NotAuthorized(
                f"{target} carries an expiry this build cannot read, which is"
                " not permission") from None
        if moment >= until:
            raise NotAuthorized(
                f"the authorisation for {target} expired at {until.isoformat()}")
        return target


def build_snapshot(con: sqlite3.Connection, addresses, *,
                   valid_for_seconds: int = SNAPSHOT_TTL_SECONDS,
                   now: datetime | None = None,
                   account: str = DEFAULT_ACCOUNT) -> SnapshotAuthority:
    """Ask the database about each address and carry the answers.

    **This is how a SnapshotAuthority is made for every prober this registry
    decides for, and that is the point.** Every entry in the result got there
    because `may_probe` allowed it, so a snapshot cannot widen what the
    registry permits. An address the database refuses is simply absent, and
    absence is a refusal. The one other maker, `snapshot_for_prober_api`, is
    for a batch to our prober API, where our registry decides.
    """
    moment = _as_utc(now)
    targets: dict[str, datetime] = {}
    for address in addresses:
        # The allow decision has exactly one owner and this is not it. Asking
        # `may_probe` rather than querying here is what stops a second, drifting
        # copy of "may I probe this" existing on the snapshot path.
        decision = may_probe(con, address, now=moment, account=account)
        if not decision.allowed or decision.target is None:
            continue
        # `Decision` deliberately carries no expiry, so the row is read
        # separately and only for targets already allowed. A target whose row
        # cannot be re-read in the instant between the two calls is dropped,
        # because a snapshot entry with no end is not something to carry off
        # the box that holds the truth.
        _target, family = normalise_target(decision.target)
        row = _active_authorization(con, decision.target, family, moment, account)
        if row is None:
            continue
        expires = live_until(row)
        if expires is None:
            # Unreachable by construction today: `may_probe` above already
            # required this same column of this same row to parse, in the same
            # instant. It stays because "the snapshot must never carry an entry
            # without an end" is the rule, and a rule enforced only by a
            # coincidence of call order is not enforced. Mutation testing
            # reports this line as uncovered and that is the honest result.
            continue
        targets[decision.target] = _as_utc(expires)
    return SnapshotAuthority(
        targets, moment + timedelta(seconds=int(valid_for_seconds)))


def snapshot_for_prober_api(con: sqlite3.Connection, addresses, ours: dict, *,
                            account: str = DEFAULT_ACCOUNT,
                            valid_for_seconds: int = SNAPSHOT_TTL_SECONDS,
                            now: datetime | None = None) -> SnapshotAuthority:
    """The snapshot a self-hosted instance sends with a batch to our prober
    API, since 2026-10-24 (docs/PRODUCT.md 5g).

    `build_snapshot` for this account, as for any batch, and beside it the
    addresses our registry holds live for this instance and this registry
    does not. `ours` is our API's listing, {canonical address: (when our
    side last proved it, when that proof ends)}
    (`dispatch.ApiTransport.live_proofs`). Our worker still builds the
    snapshot the prober carries from our registry alone, so nothing here can
    widen what our side allows (`app/proberapi_worker.py`).

    **Why ours is taken.** An agent sends its presence to its instance and to
    our API over each family apart, and an instance whose own name has no
    AAAA record never receives the IPv6 one. Its registry then held the IPv4
    proof alone while ours held both, and every IPv6 port read `not tested`
    (the second big test, finding D1).

    **What is never taken from ours**, each a test in
    `tests/test_b6_challenge.py` or `tests/test_instance_probes_what_ours_holds.py`:

      - an address on this instance's exclusion list
      - an address another workspace of this instance holds a live proof of.
        Our side has one account for the whole instance, so its proof says
        nothing about which workspace's server it was for
      - an address this registry closed after our side last proved it: an
        exclusion added, or a revoke of this account's proof, since then. So
        taking an address off the exclusion list restores nothing until our
        side proves it again, which a running agent does within a quarter of
        an hour, as it always did here

    Never used for a prober this instance drives itself: `dispatch.run_host`
    picks this one only for our API's transport.
    """
    snapshot = build_snapshot(con, addresses, valid_for_seconds=valid_for_seconds,
                              now=now, account=account)
    moment = _as_utc(now)
    targets = snapshot.targets
    for address in addresses:
        try:
            target, family = normalise_target(address)
        except TargetError:
            continue
        held = ours.get(target)
        if target in targets or held is None:
            continue
        proved, ends = held
        if ends <= moment or _excluded(con, target, family):
            continue
        if _held_here_by_another(con, target, family, account, moment):
            continue
        if _closed_here_since(con, target, family, account, proved):
            continue
        targets[target] = ends
    return SnapshotAuthority(targets, snapshot.expires_at)


def holds_alone(con: sqlite3.Connection, address: str, account: str,
                now: datetime | None = None) -> bool:
    """Whether this account holds a live proof of this address and no other
    account of this registry does. On an instance that uses our prober API,
    a revoke reaches our API only then, because our side has one account for
    the whole instance and a revoke there ends the address for every
    workspace of it (docs/PRODUCT.md 5g, 2026-10-24). Raises TargetError for
    what can never be a target."""
    moment = _as_utc(now)
    target, family = normalise_target(address)
    return (_active_authorization(con, target, family, moment, account) is not None
            and not _held_here_by_another(con, target, family, account, moment))


def proved_by_server(con: sqlite3.Connection, host_id: int,
                     now: datetime | None = None) -> list[str]:
    """The addresses this server's own proofs prove, read by their own dates
    whether the server was removed or not. What Remove and Delete end on our
    prober API, on an instance that uses it (`app/proberproofs.py`)."""
    moment = _as_utc(now)
    rows = con.execute(
        "SELECT * FROM authorizations WHERE host_id = ?"
        " AND revoked_at IS NULL AND expired_at IS NULL", (host_id,)).fetchall()
    return sorted({row["target"] for row in rows
                   if (live_until(row) or moment) > moment})


def held_by_another_server(con: sqlite3.Connection, address: str, host_id: int,
                           now: datetime | None = None) -> bool:
    """Whether a live proof of this address belongs to a server but this one,
    or to no server, in any account. Then Remove and Delete of this server
    leave the address on our prober API, which has one account for the whole
    instance."""
    moment = _as_utc(now)
    target, family = normalise_target(address)
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.target = ? AND a.family = ?"
        "   AND a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR (a.host_id != ? AND h.revoked_at IS NULL))",
        (target, family, host_id)).fetchall()
    return any((live_until(row) or moment) > moment for row in rows)


def _held_here_by_another(con: sqlite3.Connection, target: str, family: str,
                          account: str, now: datetime) -> bool:
    """Whether another account of this registry holds a live proof of this
    address, read the way the gate reads live. Unlike `_held_by_another`,
    workspace 1 counts: on an instance it is a workspace like any other."""
    rows = con.execute(
        "SELECT a.* FROM authorizations a"
        " LEFT JOIN hosts h ON h.id = a.host_id"
        " WHERE a.target = ? AND a.family = ? AND a.account != ?"
        "   AND a.revoked_at IS NULL AND a.expired_at IS NULL"
        "   AND (a.host_id IS NULL OR h.revoked_at IS NULL)",
        (target, family, account)).fetchall()
    for row in rows:
        ends = live_until(row)
        if ends is not None and ends > now:
            return True
    return False


def _closed_here_since(con: sqlite3.Connection, target: str, family: str,
                       account: str, since) -> bool:
    """Whether this registry closed this address after `since`: an exclusion
    added, or this account's proof of it revoked. A time that cannot be read
    counts as closed, the safe way round."""
    if not isinstance(since, datetime):
        return True
    since = _as_utc(since)
    stamps = [row[0] for row in con.execute(
        "SELECT added_at FROM authz_exclusions WHERE target = ? AND family = ?",
        (target, family))]
    stamps += [row[0] for row in con.execute(
        "SELECT revoked_at FROM authorizations WHERE target = ? AND family = ?"
        " AND account = ? AND revoked_at IS NOT NULL", (target, family, account))]
    for stamp in stamps:
        closed = _parse(stamp)
        if closed is None or closed > since:
            return True
    return False


# ------------------------------------------------- the snapshot on the wire
#
# A snapshot is only useful if it can reach another machine, and the moment it
# is text somebody could hand us one. So parsing is written the way the host
# document is: every unexpected shape is a refusal, and no path returns a
# snapshot that authorises more than the text said.

SNAPSHOT_VERSION = 1


def snapshot_to_json(snapshot: SnapshotAuthority) -> dict:
    """The wire form. Timestamps are ISO 8601 in UTC, the same spelling the
    database stores, so nothing reformats a time on the way past."""
    return {
        "version": SNAPSHOT_VERSION,
        "expires_at": snapshot.expires_at.isoformat(),
        "targets": {target: until.isoformat()
                    for target, until in sorted(snapshot.targets.items())},
    }


def snapshot_from_json(payload) -> SnapshotAuthority:
    """Rebuild a snapshot from text, refusing anything that is not one.

    **Raises `SnapshotUnreadable` rather than returning an empty snapshot.** An
    empty one authorises nothing, which sounds safe, but it would let a garbled
    batch look like a completed run that measured nothing. A prober that cannot
    read its instructions has to stop rather than report silence.
    """
    if not isinstance(payload, dict):
        raise SnapshotUnreadable("the snapshot is not an object")
    if payload.get("version") != SNAPSHOT_VERSION:
        raise SnapshotUnreadable(
            f"the snapshot is version {payload.get('version')!r} and this build"
            f" reads version {SNAPSHOT_VERSION}")

    expires_at = _parse(payload.get("expires_at"))
    if expires_at is None:
        raise SnapshotUnreadable("the snapshot has no readable expiry")

    raw = payload.get("targets")
    if not isinstance(raw, dict):
        raise SnapshotUnreadable("the snapshot has no targets object")

    targets: dict[str, datetime] = {}
    for target, until in raw.items():
        if not isinstance(target, str):
            raise SnapshotUnreadable("a snapshot target is not text")
        # The same door every candidate goes through. A snapshot cannot smuggle
        # an address past the address rules by spelling it differently, and a
        # target that arrives non canonical is stored canonical so the lookup
        # in `require` finds it.
        try:
            canonical, _family = normalise_target(target)
        except TargetError as exc:
            raise SnapshotUnreadable(
                f"a snapshot target is not a probeable address: {exc}") from None
        parsed = _parse(until)
        if parsed is None:
            raise SnapshotUnreadable(
                f"the snapshot entry for {canonical} has no readable expiry")
        targets[canonical] = parsed
    return SnapshotAuthority(targets, expires_at)
