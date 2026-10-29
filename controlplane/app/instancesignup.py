"""Open signup for the self-hosted beta: an address, a code, an instance.

    python -m pytest tests/test_instancesignup.py

docs/SPEC-open-beta.md, the owner's decision of 26 October 2026 to open the
beta to anybody with a mailbox (record 4.465 has the first word of it), and
of 28 October to sign up from the installer with a mailed code (record
4.470). Until then an instance existed because the owner ran
`instances_cli add` and sent its invite line himself. With signup open, the
self-hosted installer sends the address it already asks and a claim it
keeps on its server, our API mails that address eight digits, and the
person types them at the installer, which collects the invite line with
its claim. This file owns the rules and what is kept.
`app/instancesignup_routes.py` is the installer's two routes.

## Three steps, and what each may never do

1. **The installer signs up** (`request_code`), with an address and a
   claim, 32 random bytes as 64 hex characters that never leave its server
   but in these requests. The answer is `sent` for every address that is
   not refused outright: a new one, one with a code waiting, one with a
   live instance. The claim is kept, as a hash, for every one of them, so a
   collect never says whether an address has an instance or a code. A code
   comes back only when a mail should go.
2. **One code goes out**, eight random digits, the address's one mail of
   the day, lasting `CODE_TTL`. The mail carries no key and no link. The
   code's hash is kept, never the code.
3. **The installer collects** (`collect`) with its claim and the code the
   person typed. Only that makes the instance, with origin `signup`, so its
   agents never prove an address by presence (`authz.proves_by_presence`,
   docs/PRODUCT.md 5, the clauses of 2026-10-20): it proves by DNS TXT or a
   token file, which the address's own reverse zone or its own web server
   has to answer. The keys exist in the answer and nowhere else, as hashes
   in the database. Every way a collect does not work is the one answer
   `wrong`.

So the keys go to whoever reads the mailbox and runs the installer: the
code reaches only the mailbox, and only a claim the installer holds
collects with it.

## The tries

- **`WRONG_CODES_PER_CLAIM` wrong codes, then the claim answers `wrong` to
  everything.** At most `CLAIMS_PER_ADDRESS` live claims for one address,
  each living `CLAIM_TTL`, so whoever guesses at somebody's address has 15
  tries a day at one chance in a hundred million each.
- **The code is the address's**, so any live claim of the address collects
  with it, which spends it: an address has one live instance.
- **A collected claim may collect again inside its day**, with no code, and
  that reissues both keys of the instance it made, ending the first pair.
  So a line lost between the answer and the write is mended by running the
  installer again that day, which keeps its claim file as long. `done`
  ends the claim sooner, once the line is written.

## The caps, and the switch

**Closed unless `WHICHPORTS_INSTANCE_SIGNUP` reads `open`**, spaces and case
aside, the way `app/signup.py` reads its own switch. Closed, an address is
answered `closed` and a collect makes nothing. Closing ends no instance.

**Full** is the answer when a cap is spent, the same for every address, in
two words. `full_today` when `SIGNUPS_PER_DAY` signups came today or
`INSTANCES_PER_DAY` instances were made today, which tomorrow ends. Every
new claim counts as a signup, mailed or not, so the count moves the same
for every address and the moment it reads full says nothing about any one
of them (the code's challenge of 28 October). `full`
when `LIVE_SIGNUP_INSTANCES` signup instances are live, which no day ends:
it is one plain refusal and promises no place in a line, as decided on
27 October 2026. The first time a day is full either way, the answer
says to tell the owner, once that day. A collect checks every cap again,
and a full answer there spends nothing: no wrong try, and the code still
works inside its hours.

A day is a UTC day. Its counts are one row with no address, kept
`DAYS_KEPT` days.

## What is kept, and for how long

- **A waiting code**: the address, the code's hash, when it was sent and
  when it expires. Until the code is used or `CODE_TTL` passes.
- **A claim**: its hash, its address, its wrong tries, when it was made,
  when it collected and the instance it made, and when it ends. Until
  `done`, or `CLAIM_TTL` after it was made.
- Both are deleted by `sweep`, which the five minute sweep and every
  request run, and left out of the nightly snapshots
  (`backup.LEFT_OUT_OF_A_SNAPSHOT`): eight digits under SHA-256 are worked
  out from a copy in seconds.
- **The instance's address**, on its row (`instances.contact_email`), while
  it is live and for `instances.CONTACT_KEPT_AFTER_REVOKE` after its revoke.
- **Each day's counts**, codes sent, instances made, whether the owner was
  told, with no address.

Nothing typed reaches a log line here or in the routes: an address, a claim
and a code are data from a stranger (SI-8).
"""
import dataclasses
import hashlib
import hmac
import logging
import os
import re
import secrets
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from . import authz, betasignup, instances, notify

log = logging.getLogger(__name__)

MODE_ENV = "WHICHPORTS_INSTANCE_SIGNUP"
OPEN = "open"
CLOSED = "closed"

# How long a mailed code works: the address's one mail of the day. A
# shorter code would leave somebody who missed it with nothing until the
# next day, since a second mail that day is refused. The tries bound the
# guessing instead. The number the mail says out loud
# (`notify.SIGNUP_CODE_LASTS`) is held equal to this by a test.
CODE_TTL = timedelta(hours=24)

# How long a claim lives, collected or not: the day the installer keeps its
# claim file (selfhost/install.sh, CLAIM_MINUTES), so the two agree.
CLAIM_TTL = timedelta(hours=24)

WRONG_CODES_PER_CLAIM = 5
CLAIMS_PER_ADDRESS = 3

CODE_DIGITS = 8

# The claim is 32 random bytes the installer wrote as hex.
_CLAIM_RE = re.compile(r"[0-9a-f]{64}")
_CODE_RE = re.compile(r"[0-9]{8}")

# First guesses of docs/SPEC-open-beta.md, the owner's to change. The mails
# went from 20 to 10 on 27 October: anybody can spend them on other people's
# addresses, each is a mail through our relay, and a mail to an address
# that does not exist comes back against it.
SIGNUPS_PER_DAY = 10
INSTANCES_PER_DAY = 10

# How many signup instances may be live at once. One, until the finer locks
# are built and measured (docs/SPEC-probe-locks.md), decided 27 October 2026.
# A stranger's instance can send the longest batch nonstop, and the cap of
# seconds still lets it hold the lock 763 s of an hour, the cap and one
# batch past it. The synthetic run of that on 27 October (docs/PRODUCT.md
# 5g) left an invited instance of 5 servers 77% of its passes beside one
# such instance, 43% beside two and 21% beside three.
LIVE_SIGNUP_INSTANCES = 1

DAYS_KEPT = 2

# A signup instance that has sent no batch and made no proof for this long
# is revoked by the sweep, and its address told once, decided 27 October
# 2026. A place on our probers is scarce (`LIVE_SIGNUP_INSTANCES`), and an
# instance nobody runs holds it for nothing. Signing up again gives a new one.
UNUSED_FOR = timedelta(days=14)

# A name that holds nothing of the address: a fixed word and twelve random
# hex digits. `instances.NAME_RE` takes it.
NAME_PREFIX = "signup-"

SENT = "sent"
FULL = "full"
FULL_TODAY = "full_today"
MADE = "made"
WRONG = "wrong"

SCHEMA = """
CREATE TABLE IF NOT EXISTS instance_signups (
    id          INTEGER PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    code_hash   TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS instance_signup_claims (
    id            INTEGER PRIMARY KEY,
    claim_hash    TEXT NOT NULL UNIQUE,
    email         TEXT NOT NULL,
    wrong         INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    collected_at  TEXT,
    instance_id   INTEGER,
    expires_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_instance_signup_claims_email
    ON instance_signup_claims(email);

CREATE TABLE IF NOT EXISTS instance_signup_days (
    day        TEXT PRIMARY KEY,
    signups    INTEGER NOT NULL DEFAULT 0,
    made       INTEGER NOT NULL DEFAULT 0,
    told_full  INTEGER NOT NULL DEFAULT 0
);
"""


class InvalidEmail(ValueError):
    """Not an address this takes. The message never repeats it."""


class InvalidClaim(ValueError):
    """Not a claim the installer makes. The message never repeats it."""


@dataclass(frozen=True)
class Asked:
    """What `request_code` decided. `code` only when a mail should go."""
    answer: str
    code: str | None = None
    tell_owner: bool = False


@dataclass(frozen=True)
class Collected:
    """What `collect` decided. `issued` only when keys were made, and
    `again` when they replace the keys of the claim's first collect."""
    answer: str
    issued: instances.Issued | None = None
    tell_owner: bool = False
    again: bool = False


def init(con: sqlite3.Connection) -> None:
    """Idempotent and additive, the rule every other init follows."""
    con.executescript(SCHEMA)
    con.commit()


def mode(environ=None) -> str:
    """`open` only when the setting says exactly that, otherwise `closed`."""
    environ = os.environ if environ is None else environ
    value = (environ.get(MODE_ENV) or "").strip().lower()
    return OPEN if value == OPEN else CLOSED


def is_open(environ=None) -> bool:
    return mode(environ) == OPEN


def normalise_email(value) -> str:
    """The address the beta list would take, trimmed and lowercased, or
    InvalidEmail. The installer holds an address to this same rule
    (selfhost/install.sh, signup_email_ok)."""
    try:
        return betasignup.normalise_email(value)
    except betasignup.InvalidEmail:
        raise InvalidEmail("not an address this takes") from None


def claim_ok(value) -> bool:
    """Whether this is a claim as the installer makes it: 64 lowercase hex."""
    return isinstance(value, str) and _CLAIM_RE.fullmatch(value) is not None


def new_code() -> str:
    """Eight random digits, drawn here and never from the claim, so nothing
    has to be computed alike by the installer's shell and by this."""
    return f"{secrets.randbelow(10 ** CODE_DIGITS):0{CODE_DIGITS}d}"


def _utc(moment: datetime) -> datetime:
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _stamp(moment: datetime) -> str:
    """Fixed width, so stamps compare as text by when they are."""
    return _utc(moment).astimezone(timezone.utc).isoformat(timespec="microseconds")


def _day(moment: datetime) -> str:
    return _utc(moment).astimezone(timezone.utc).date().isoformat()


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _counts(con, day: str) -> tuple[int, int, int]:
    row = con.execute(
        "SELECT signups, made, told_full FROM instance_signup_days WHERE day = ?",
        (day,)).fetchone()
    return (row[0], row[1], row[2]) if row else (0, 0, 0)


def _count(con, day: str, column: str) -> None:
    """Add one to a day's count. `column` is one of two names written here."""
    if column not in ("signups", "made"):
        raise ValueError(column)
    con.execute("INSERT OR IGNORE INTO instance_signup_days (day) VALUES (?)", (day,))
    con.execute(f"UPDATE instance_signup_days SET {column} = {column} + 1"
                " WHERE day = ?", (day,))


def _tell_once(con, day: str) -> bool:
    """True the first time a day is full, and never again that day."""
    con.execute("INSERT OR IGNORE INTO instance_signup_days (day) VALUES (?)", (day,))
    changed = con.execute(
        "UPDATE instance_signup_days SET told_full = 1"
        " WHERE day = ? AND told_full = 0", (day,)).rowcount
    return changed == 1


def _full(con, day: str, *, for_a_signup: bool) -> str | None:
    """`FULL`, `FULL_TODAY` or None. The live cap first: when both are spent,
    tomorrow is no answer."""
    if instances.live_count(con, authz.ORIGIN_SIGNUP) >= LIVE_SIGNUP_INSTANCES:
        return FULL
    signups, made, _told = _counts(con, day)
    if made >= INSTANCES_PER_DAY or (for_a_signup and signups >= SIGNUPS_PER_DAY):
        return FULL_TODAY
    return None


def _forget_expired(con, now: datetime) -> tuple[int, int]:
    """Delete the waiting codes and the claims whose time is over. Returns
    how many of each."""
    stamp = _stamp(now)
    codes = con.execute("DELETE FROM instance_signups WHERE expires_at <= ?",
                        (stamp,)).rowcount
    claims = con.execute("DELETE FROM instance_signup_claims WHERE expires_at <= ?",
                         (stamp,)).rowcount
    return codes, claims


def request_code(con: sqlite3.Connection, email, claim,
                 now: datetime | None = None) -> Asked:
    """The installer signs up with an address and a claim. Raises
    InvalidEmail or InvalidClaim before anything is written or counted.
    Otherwise one write transaction, so two signups for one address at once
    mail one code."""
    moment = _utc(now or datetime.now(timezone.utc))
    address = normalise_email(email)
    if not claim_ok(claim):
        raise InvalidClaim("not a claim the installer makes")
    if not is_open():
        return Asked(CLOSED)
    day = _day(moment)
    claim_hash = _hash(claim)
    con.execute("BEGIN IMMEDIATE")
    try:
        _forget_expired(con, moment)
        full = _full(con, day, for_a_signup=True)
        if full:
            tell = _tell_once(con, day)
            con.commit()
            return Asked(full, tell_owner=tell)
        known = con.execute("SELECT 1 FROM instance_signup_claims WHERE claim_hash = ?",
                            (claim_hash,)).fetchone()
        if known is not None:
            # The same installer again. It has its claim: nothing changes.
            con.commit()
            return Asked(SENT)
        _count(con, day, "signups")
        claims = con.execute("SELECT COUNT(*) FROM instance_signup_claims WHERE email = ?",
                             (address,)).fetchone()[0]
        if claims >= CLAIMS_PER_ADDRESS:
            # The same answer, and nothing kept or mailed: this claim will
            # collect nothing, which is how a fourth guesser gets no tries.
            con.commit()
            return Asked(SENT)
        # Kept for every address, whatever its state, so that no collect
        # can tell an address with a code or an instance from a new one.
        con.execute(
            "INSERT INTO instance_signup_claims"
            " (claim_hash, email, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (claim_hash, address, _stamp(moment), _stamp(moment + CLAIM_TTL)))
        waiting = con.execute("SELECT 1 FROM instance_signups WHERE email = ?",
                              (address,)).fetchone()
        # A code waiting, a live instance, or one he revoked by hand while
        # its address is kept: the same answer, and no mail
        # (`instances.address_taken`).
        if waiting is not None or instances.address_taken(con, address):
            con.commit()
            return Asked(SENT)
        code = new_code()
        con.execute(
            "INSERT INTO instance_signups (email, code_hash, created_at, expires_at)"
            " VALUES (?, ?, ?, ?)",
            (address, _hash(code), _stamp(moment), _stamp(moment + CODE_TTL)))
    except BaseException:
        con.rollback()
        raise
    con.commit()
    return Asked(SENT, code=code)


def _new_name(con) -> str:
    while True:
        name = NAME_PREFIX + secrets.token_hex(6)
        if instances.by_name(con, name) is None:
            return name


def _live_name(con, instance_id) -> str | None:
    """The name of the instance a claim made, while it is live, or None."""
    instance = instances.by_id(con, instance_id) if instance_id is not None else None
    return None if instance is None or instance.revoked_at else instance.name


def _code_matches(stored_hash: str, code) -> bool:
    if not isinstance(code, str) or _CODE_RE.fullmatch(code) is None:
        return False
    return hmac.compare_digest(stored_hash, _hash(code))


def collect(con: sqlite3.Connection, claim, code,
            now: datetime | None = None) -> Collected:
    """The installer sends its claim and the code the person typed: make the
    instance, once, or give fresh keys to a claim that collected within the
    hour.

    `wrong` for every way it does not work, whatever the reason, so a
    collect answers nothing about anybody's address. `closed`, `full` and
    `full_today` spend nothing: no wrong try is counted, and the code still
    works inside its hours. The code is deleted and the instance made in
    one write transaction, so two collects of one code make one instance.
    """
    moment = _utc(now or datetime.now(timezone.utc))
    if not claim_ok(claim):
        return Collected(WRONG)
    if not is_open():
        return Collected(CLOSED)
    day = _day(moment)
    con.execute("BEGIN IMMEDIATE")
    try:
        _forget_expired(con, moment)
        row = con.execute(
            "SELECT id, email, wrong, collected_at, instance_id FROM instance_signup_claims"
            " WHERE claim_hash = ?", (_hash(claim),)).fetchone()
        if row is None or row[2] >= WRONG_CODES_PER_CLAIM:
            con.commit()
            return Collected(WRONG)
        claim_id, address, collected_at, made_id = row[0], row[1], row[3], row[4]

        if collected_at is not None:
            # Inside its day, since an older one was just deleted. Fresh
            # keys for the instance it made, which ends the first pair.
            name = _live_name(con, made_id)
            if name is None:
                con.commit()
                return Collected(WRONG)
            issued = instances.reissue_both(con, name, now=moment)
            return Collected(MADE, issued=issued, again=True)

        full = _full(con, day, for_a_signup=False)
        if full:
            tell = _tell_once(con, day)
            con.commit()
            return Collected(full, tell_owner=tell)

        waiting = con.execute("SELECT id, code_hash FROM instance_signups WHERE email = ?",
                              (address,)).fetchone()
        if waiting is None or not _code_matches(waiting[1], code) \
                or instances.address_taken(con, address):
            con.execute("UPDATE instance_signup_claims SET wrong = wrong + 1"
                        " WHERE id = ?", (claim_id,))
            con.commit()
            return Collected(WRONG)

        con.execute("DELETE FROM instance_signups WHERE id = ?", (waiting[0],))
        _count(con, day, "made")
        # The code spent, the instance made and the claim naming it land in
        # one commit, so two collects of one code make one instance, and an
        # instance is never there without the claim that may reissue it.
        issued = instances.add(con, _new_name(con), now=moment,
                               origin=authz.ORIGIN_SIGNUP, contact=address,
                               commit=False)
        con.execute(
            "UPDATE instance_signup_claims SET collected_at = ?, instance_id = ?"
            " WHERE id = ?", (_stamp(moment), issued.instance.id, claim_id))
        con.commit()
    except BaseException:
        con.rollback()
        raise
    return Collected(MADE, issued=issued)


def done(con: sqlite3.Connection, claim, now: datetime | None = None) -> bool:
    """The installer wrote its line: end the claim's hour. True when a claim
    was ended. A claim that never collected is left to its 24 hours, so
    `done` cannot hand whoever guesses at an address a fresh claim and five
    more tries."""
    moment = _utc(now or datetime.now(timezone.utc))
    if not claim_ok(claim):
        return False
    con.execute("BEGIN IMMEDIATE")
    try:
        _forget_expired(con, moment)
        ended = con.execute(
            "DELETE FROM instance_signup_claims"
            " WHERE claim_hash = ? AND collected_at IS NOT NULL",
            (_hash(claim),)).rowcount
    except BaseException:
        con.rollback()
        raise
    con.commit()
    return ended == 1


def _when(value) -> datetime | None:
    """A stamp read back as a time, or None when there is none to read."""
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _last_use(con, instance_id: int, created_at: str) -> datetime | None:
    """When this instance was last of use: made, a batch our probers ran
    for it (the abuse log, kept thirty days), or a proof its verify made.
    A proof's daily reading by our side is not its use, so the challenge's
    own verified time is read and not the proof's."""
    stamps = [created_at]
    # A database the prober API never made its tables in has run no batch.
    if con.execute("SELECT 1 FROM sqlite_schema WHERE type = 'table'"
                   " AND name = 'prober_api_log'").fetchone() is not None:
        stamps.append(con.execute(
            "SELECT MAX(last_at) FROM prober_api_log WHERE instance_id = ?",
            (instance_id,)).fetchone()[0])
    stamps.append(authz.last_proof_made(con, authz.account_for_instance(instance_id)))
    times = [moment for moment in map(_when, stamps) if moment is not None]
    return max(times) if times else None


def end_unused(con: sqlite3.Connection, now: datetime | None = None) -> list:
    """Revoke every live signup instance that has sent no batch and made no
    proof for `UNUSED_FOR`. Returns the addresses to tell, never logged.
    An instance made by hand is never ended here."""
    moment = _utc(now or datetime.now(timezone.utc))
    rows = con.execute(
        "SELECT id, name, created_at FROM probe_instances"
        " WHERE origin = ? AND revoked_at IS NULL",
        (authz.ORIGIN_SIGNUP,)).fetchall()
    ended = []
    for instance_id, name, created_at in rows:
        last = _last_use(con, instance_id, created_at)
        # A row whose times nothing can read is left alone: ending an
        # instance is not done on a guess.
        if last is None or moment - last < UNUSED_FOR:
            continue
        instances.revoke(con, name, now=moment, unused=True)
        address = instances.contact_of(con, instance_id)
        if address:
            ended.append(address)
    return ended


def tell_ended(addresses) -> int:
    """One mail to each address whose instance ended unused, its one button
    to the landing's Install page, since running the install again signs up
    anew. Returns how many the relay took. None at all without the landing
    page's address, which the button needs, or without a relay. A failure is a
    journal line with its class and no address."""
    try:
        landing = betasignup.landing()
    except betasignup.LandingMisconfigured:
        landing = None
    config = notify.config_from_env()
    if not landing or not config.host:
        return 0
    subject, body, html = notify.format_signup_ended(f"{landing}/#docs-install",
                                                     UNUSED_FOR.days)
    told = 0
    for address in addresses:
        one = dataclasses.replace(config, to=address, sender=config.sender or address)
        sent, reason = notify.send(subject, body, one, html)
        if sent:
            told += 1
        else:
            log.warning("instance signup: an ended mail did not go out: %s", reason)
    return told


def today(con: sqlite3.Connection, now: datetime | None = None) -> dict:
    """Today's counts, for the owner's mail. No address is in them."""
    signups, made, told = _counts(con, _day(_utc(now or datetime.now(timezone.utc))))
    return {"signups": signups, "made": made, "told_full": bool(told)}


def sweep(con: sqlite3.Connection, now: datetime | None = None) -> dict:
    """End what has outlived its purpose: a signup instance unused for
    `UNUSED_FOR`, expired codes and claims, day counts older than
    `DAYS_KEPT`, and the address of an instance revoked longer ago than
    `instances.CONTACT_KEPT_AFTER_REVOKE`. `ended` is the addresses of the
    instances it ended, for `tell_ended`, and never for a log."""
    moment = _utc(now or datetime.now(timezone.utc))
    ended = end_unused(con, moment)
    codes, claims = _forget_expired(con, moment)
    oldest = _day(moment - timedelta(days=DAYS_KEPT))
    days = con.execute("DELETE FROM instance_signup_days WHERE day < ?",
                       (oldest,)).rowcount
    con.commit()
    contacts = instances.forget_contacts(con, moment)
    return {"codes": codes, "claims": claims, "days": days, "contacts": contacts,
            "ended": ended}
