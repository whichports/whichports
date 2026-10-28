"""Links that work once and expire.

    python -m pytest tests/test_onetime.py

Four kinds, and they are the four mails `app/notify.py` already writes
(`docs/screens/mails/SPEC.md`): a hand-made account choosing its first
password, a password reset, a confirmed email, and an invitation into a
workspace. Every one of them is the same shape, so they are one table and one
set of rules rather than four half-copies of the same idea.

## What a link is, and what it is not

**It is a bearer credential with a purpose, an expiry and one use.** Anybody
holding the token can do the one thing that purpose names, until it expires or
is spent, whichever comes first. That is why the four TTLs differ: a reset is
the shortest because it is the one anybody can ask for about somebody else's
address, and an invitation is the longest because it is sent to somebody who
was not expecting it and may read mail once a week.

**It is not a session and it is not a way past the second factor.** Redeeming
one hands the caller back to the ordinary sign-in path, which is where an
account with two-factor on is asked for a code like any other.

## Why the token is hashed and the row is not deleted

The token is 32 random bytes and never stored: the row holds its SHA-256, the
same reasoning `accounts._hash_token` gives for a session. A copy of this
table is not a set of working links.

A spent link is stamped rather than deleted, so "this link was already used"
and "this link never existed" stay different facts. The first is worth saying
plainly to somebody who clicked a mail twice. The second is not worth saying
at all, and `look_up` answers None to both, because the page above it must not
become a way to ask questions about somebody else's account.

## Issuing invalidates the older ones

Asking for a second reset kills the first link. Two live links to one account
is one more thing that can be found in an old mailbox, and nobody expects the
first one to still work after they asked again.
"""

import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

# The four purposes. The strings are stored, so they are named here once and
# every caller uses these rather than a literal.
SET_PASSWORD = "set_password"
RESET = "reset"
CONFIRM = "confirm"
INVITE = "invite"
PURPOSES = (SET_PASSWORD, RESET, CONFIRM, INVITE)

# How long each lasts. These are the numbers the mails say out loud
# (`notify.ACCOUNT_LINK_LASTS` and its three siblings), and the two have to
# agree or the mail is lying about the link it carries. `tests/test_onetime.py`
# compares them.
TTL = {
    SET_PASSWORD: timedelta(hours=24),
    RESET: timedelta(minutes=30),
    CONFIRM: timedelta(hours=24),
    INVITE: timedelta(days=7),
}

# 32 bytes from `secrets`, URL-safe, so it survives a mail client that turns
# the link into text and back.
TOKEN_BYTES = 32

SCHEMA = """
CREATE TABLE IF NOT EXISTS one_time_links (
    id           INTEGER PRIMARY KEY,
    purpose      TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    email        TEXT NOT NULL,
    user_id      INTEGER REFERENCES users(id),
    workspace_id INTEGER,
    role         TEXT,
    invited_by   TEXT,
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    used_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_one_time_links_live
    ON one_time_links(purpose, email, used_at);
"""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the additive rule every other init in this package follows.

    Run it after `accounts.init`: a link row points at an account, so the
    table it references has to exist first. `web_auth._connect` opens in that
    order and so does `app/users_cli.py`.
    """
    con.executescript(SCHEMA)
    con.commit()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat()


def _hash(token: str) -> str:
    """SHA-256, no salt and no stretching, for the reason
    `accounts._hash_token` gives: a token this long has nothing to guess."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def issue(con: sqlite3.Connection, purpose: str, email: str, *,
          user_id: int | None = None, workspace_id: int | None = None,
          role: str | None = None, invited_by: str | None = None,
          now: datetime | None = None) -> tuple[str, datetime]:
    """Mint one link and return (token, expires_at).

    The token is returned once, for the mail, and never stored. Older unspent
    links of the same purpose for the same address are spent on the way, so
    asking again really does replace the last one.
    """
    if purpose not in PURPOSES:
        raise ValueError(f"no such purpose: {purpose!r}")
    moment = now or _now()
    email = (email or "").strip().lower()
    if not email:
        raise ValueError("A link is always about an address.")
    # A link row holds a mail address, so old rows are deleted here, each
    # time a new link is made. This is the same place the sessions and the
    # sign-in attempts clear their own old rows, so no timer exists to forget.
    purge_expired(con, now=moment)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    con.execute(
        "UPDATE one_time_links SET used_at = ? WHERE purpose = ? AND email = ?"
        " AND used_at IS NULL", (_iso(moment), purpose, email))
    expires_at = moment + TTL[purpose]
    con.execute(
        "INSERT INTO one_time_links (purpose, token_hash, email, user_id,"
        " workspace_id, role, invited_by, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (purpose, _hash(token), email, user_id, workspace_id, role, invited_by,
         _iso(moment), _iso(expires_at)))
    con.commit()
    return token, expires_at


def look_up(con: sqlite3.Connection, purpose: str, token: str,
            now: datetime | None = None) -> sqlite3.Row | None:
    """The live link this token names, or None.

    None for every reason there is: no such token, the wrong purpose, expired,
    already spent. The page above this one says the same thing to all four,
    because telling them apart would answer questions about somebody else's
    account for anybody willing to guess.

    Reading does not spend it. A GET renders the form and the POST behind it
    spends the link, so a mail client that fetches the link to preview it does
    not burn it before the person clicks.
    """
    if not token or purpose not in PURPOSES:
        return None
    row = con.execute(
        "SELECT * FROM one_time_links WHERE purpose = ? AND token_hash = ?",
        (purpose, _hash(token))).fetchone()
    if row is None or row["used_at"]:
        return None
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except (TypeError, ValueError):
        # A stamp nothing can read is not a link anybody may use. Refusing is
        # the safe half of the two, and a row like this can only come from
        # somebody editing the database by hand.
        return None
    if expires_at.tzinfo is None:
        return None
    return row if expires_at > (now or _now()) else None


def spend(con: sqlite3.Connection, link_id: int,
          now: datetime | None = None) -> bool:
    """Mark one link used, and say whether this call is the one that did it.

    The `used_at IS NULL` in the statement is the whole of the once-only
    guarantee: two requests racing on the same link both run this, SQLite
    serialises them, and exactly one sees a row change. The caller does the
    real work only when this returns True.
    """
    cur = con.execute(
        "UPDATE one_time_links SET used_at = ? WHERE id = ? AND used_at IS NULL",
        (_iso(now or _now()), link_id))
    con.commit()
    return cur.rowcount == 1


def purge_expired(con: sqlite3.Connection, now: datetime | None = None) -> int:
    """Delete links that expired more than a week ago, and say how many.

    A week rather than immediately, so "that link has expired" can still be
    told from "that link never existed" for as long as anybody is likely to
    click an old mail. `issue` calls it each time a link is made, so a row
    stays in this table until the first new link after that week.
    """
    cutoff = _iso((now or _now()) - timedelta(days=7))
    cur = con.execute("DELETE FROM one_time_links WHERE expires_at < ?", (cutoff,))
    con.commit()
    return cur.rowcount
