"""Which provider account is allowed to sign in as which operator account.

**This module is the answer to the one question the login design left open: how
an OAuth identity binds to the one org account.** The answer is that it never
binds itself. Somebody already trusted says so, either from the box or from a
signed-in browser, and until then a perfectly valid Google or Microsoft token
signs nobody in.

Two rules hold that up, and they are the whole security argument here.

**1. The key is the provider's subject, never an email address.** A row is
`(provider, subject)`, and `subject` is what the provider's own documentation
names as immutable. Matching an incoming token to a local account by email is a
known account-takeover pattern rather than a shortcut: Microsoft published an
advisory about it in June 2023 saying "An attacker can falsify the email claim
in tokens issued to applications", and that the fix is "fully removing any
business logic where email claims are used for authorization". Microsoft's own
claim reference says of `email` that it "isn't guaranteed to be correct and is
mutable over time. Never use it for authorization", and Google's says "you
shouldn't use the `email` field in the ID token as a unique identifier for a
user. Always use the `sub` field." All read on 2026-08-22.

So the address a provider sends is stored to be *shown*, in a column whose name
says so, and it is never read to decide anything.

**2. A link is an act, not a coincidence.** There are exactly two ways a row
gets created. An operator who is already signed in links a provider to their own
account. Or somebody with a shell on the box mints a single-use ticket with
`python -m app.users_cli link`, which is the deliberately gated first sign-in
the design called for. There is no path where arriving with a token nobody
expected creates anything.

What follows from those two, and is worth saying out loud: **an unlinked
identity is refused, and the refusal says the same thing every time.** It does
not say whether the address has an account here, because that would be the
enumeration oracle the password login is already careful not to be.
"""

import hashlib
import hmac
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from . import accounts, db, signup

# A sign-in attempt is a few seconds of a person looking at a consent screen.
# Ten minutes is generous for that and short enough that an abandoned attempt is
# not lying around.
FLOW_TTL = timedelta(minutes=10)

# A link ticket is walked from a terminal to a browser by a person, so it gets
# longer, and it is single use besides.
TICKET_TTL = timedelta(minutes=15)

# Greppable in a log or a paste, the same convention `whp_sess_` follows.
TICKET_PREFIX = "whp_link_"

SCHEMA = """
CREATE TABLE IF NOT EXISTS oidc_identities (
    id           INTEGER PRIMARY KEY,
    provider     TEXT NOT NULL,
    subject      TEXT NOT NULL,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    email_shown  TEXT,
    UNIQUE (provider, subject)
);

CREATE INDEX IF NOT EXISTS idx_identities_user ON oidc_identities(user_id);

CREATE TABLE IF NOT EXISTS oidc_flows (
    id           INTEGER PRIMARY KEY,
    state_hash   TEXT NOT NULL UNIQUE,
    provider     TEXT NOT NULL,
    nonce        TEXT NOT NULL,
    verifier     TEXT NOT NULL,
    binding_hash TEXT NOT NULL,
    next_path    TEXT NOT NULL,
    link_user_id INTEGER REFERENCES users(id),
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_link_tickets (
    id         INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    provider   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);
"""


class LinkError(Exception):
    """A problem with linking whose message is safe to show."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init and accounts.init follow."""
    con.executescript(SCHEMA)
    con.commit()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _hash(value: str) -> str:
    """SHA-256, no salt and no stretching, for the same reason
    `accounts._hash_token` gives: these are random tokens from `secrets`, so
    there is nothing to guess and a slow hash would protect nothing. It is a
    lookup key a database copy cannot be turned back into a usable value."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


# --------------------------------------------------------- the attempt state

def start_flow(con: sqlite3.Connection, provider: str, state: str, nonce: str,
               verifier: str, binding: str, next_path: str,
               link_user_id: int | None = None,
               now: datetime | None = None) -> None:
    """Remember one sign-in attempt, keyed on the state we are about to send.

    State, nonce and verifier live here rather than in a cookie. A cookie would
    work and the earlier project used one, but a row is single use for free:
    `take_flow`
    below deletes it, so a replayed callback finds nothing rather than finding
    something still valid.

    **`binding` is the half that makes this attempt belong to one browser.**
    Its hash is stored here and the value itself goes out as a cookie, so the
    callback can require both. Without it the state proves only that somebody
    started an attempt, and login CSRF works: an attacker starts a flow in their
    own browser, gets a callback URL carrying their own code and state, and
    tricks the victim into visiting it. The victim ends up signed in as the
    attacker, in the attacker's account, which is where anything they do next
    goes. RFC 9700 section 4.7.1 is about exactly this, and the fix is that the
    state has to be tied to the browser rather than only to the server.
    """
    now = now or now_utc()
    purge_expired(con, now=now)
    con.execute(
        "INSERT INTO oidc_flows (state_hash, provider, nonce, verifier,"
        " binding_hash, next_path, link_user_id, created_at, expires_at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (_hash(state), provider, nonce, verifier, _hash(binding), next_path,
         link_user_id, _iso(now), _iso(now + FLOW_TTL)))
    con.commit()


def take_flow(con: sqlite3.Connection, provider: str, state: str, binding: str,
              now: datetime | None = None) -> sqlite3.Row | None:
    """The attempt this callback answers, removed as it is read.

    **Single use, and that is the point.** Deleting on the way out means the
    same state cannot be presented twice, so a callback URL out of somebody's
    browser history or a proxy log is spent. It is deleted before the binding is
    checked, so a wrong browser also burns the attempt rather than getting
    another go at it.

    The provider is part of the lookup, so a state minted for one provider
    cannot be handed to another's callback. The binding is checked with
    `compare_digest` over the hashes, so this browser has to be the browser the
    attempt started in.
    """
    now = now or now_utc()
    row = con.execute(
        "SELECT * FROM oidc_flows WHERE state_hash = ? AND provider = ?",
        (_hash(state), provider)).fetchone()
    if row is None:
        return None
    con.execute("DELETE FROM oidc_flows WHERE id = ?", (row["id"],))
    con.commit()
    if not hmac.compare_digest(row["binding_hash"], _hash(binding or "")):
        return None
    expires = datetime.fromisoformat(row["expires_at"])
    if expires <= now:
        return None
    return row


def purge_expired(con: sqlite3.Connection, now: datetime | None = None) -> int:
    """Drop attempts and tickets nothing can use again. Called when a new one
    starts, so no timer exists to forget to install."""
    stamp = _iso(now or now_utc())
    cur = con.execute("DELETE FROM oidc_flows WHERE expires_at < ?", (stamp,))
    con.execute("DELETE FROM oidc_link_tickets WHERE expires_at < ?", (stamp,))
    con.commit()
    return cur.rowcount


# ------------------------------------------------------------- the identity

def find_user_id(con: sqlite3.Connection, provider: str, subject: str) -> int | None:
    """The account this provider identity signs in as, or None.

    **`subject` and nothing else.** No fallback to an email match, not even when
    exactly one account has that address. That fallback is the account-takeover
    pattern this module's docstring quotes Microsoft on.
    """
    row = con.execute(
        "SELECT user_id FROM oidc_identities WHERE provider = ? AND subject = ?",
        (provider, subject)).fetchone()
    return int(row["user_id"]) if row else None


def mark_used(con: sqlite3.Connection, provider: str, subject: str,
              email_shown: str | None = None, now: datetime | None = None) -> None:
    """Stamp a successful sign-in, and refresh the address we display.

    `email_shown` is a label. The column is named for what it is so that nobody
    reading a query later mistakes it for something a decision could rest on.
    """
    con.execute(
        "UPDATE oidc_identities SET last_used_at = ?, email_shown = ?"
        " WHERE provider = ? AND subject = ?",
        (_iso(now or now_utc()), email_shown, provider, subject))
    con.commit()


def link(con: sqlite3.Connection, provider: str, subject: str, user_id: int,
         email_shown: str | None = None, now: datetime | None = None) -> None:
    """Bind a provider identity to an account.

    Refuses when that identity is already bound to a different account, rather
    than moving it. Moving would mean one consent screen could take an identity
    away from the account it already signs in as.

    One account may hold one identity per provider, which is what "one user
    account per organisation" means here. Linking a second Google account to the
    same operator is refused, because the operator would have two ways in and no
    screen anywhere shows that.
    """
    now = now or now_utc()
    existing = con.execute(
        "SELECT user_id FROM oidc_identities WHERE provider = ? AND subject = ?",
        (provider, subject)).fetchone()
    if existing is not None:
        if int(existing["user_id"]) == user_id:
            return
        raise LinkError(f"That {provider} account already signs in as somebody else.")
    taken = con.execute(
        "SELECT id FROM oidc_identities WHERE provider = ? AND user_id = ?",
        (provider, user_id)).fetchone()
    if taken is not None:
        raise LinkError(f"This account already has a {provider} sign-in. "
                        f"Unlink it first.")
    con.execute(
        "INSERT INTO oidc_identities (provider, subject, user_id, created_at,"
        " last_used_at, email_shown) VALUES (?, ?, ?, ?, ?, ?)",
        (provider, subject, user_id, _iso(now), _iso(now), email_shown))
    con.commit()


def unlink(con: sqlite3.Connection, provider: str, user_id: int) -> bool:
    """Remove an account's identity for one provider. True when there was one."""
    cur = con.execute("DELETE FROM oidc_identities WHERE provider = ? AND user_id = ?",
                      (provider, user_id))
    con.commit()
    return cur.rowcount == 1


def for_user(con: sqlite3.Connection, user_id: int) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM oidc_identities WHERE user_id = ?"
                       " ORDER BY provider", (user_id,)).fetchall()


# --------------------------------------------------------- the link ticket

def issue_ticket(con: sqlite3.Connection, user_id: int, provider: str,
                 now: datetime | None = None) -> str:
    """Mint the single-use ticket `users_cli link` prints.

    This is the deliberately gated first sign-in. The person minting it already
    has a shell on the box, which is the same trust `users_cli add` runs on, and
    the ticket says which account and which provider before any browser is
    involved. So the consent screen proves who the provider thinks you are, and
    the ticket proves which local account that is allowed to be. Neither half
    decides on its own.
    """
    now = now or now_utc()
    purge_expired(con, now=now)
    token = TICKET_PREFIX + secrets.token_urlsafe(32)
    con.execute(
        "INSERT INTO oidc_link_tickets (token_hash, user_id, provider,"
        " created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
        (_hash(token), user_id, provider, _iso(now), _iso(now + TICKET_TTL)))
    con.commit()
    return token


def take_ticket(con: sqlite3.Connection, token: str,
                now: datetime | None = None) -> sqlite3.Row | None:
    """The ticket behind this token, spent as it is read, or None.

    Spending it here rather than after the provider answers is deliberate. It
    means a ticket buys exactly one trip to a consent screen, so a link URL that
    leaked cannot be tried repeatedly against whoever is signed in to a browser.
    """
    if not token or not token.startswith(TICKET_PREFIX):
        return None
    now = now or now_utc()
    row = con.execute("SELECT * FROM oidc_link_tickets WHERE token_hash = ?",
                      (_hash(token),)).fetchone()
    if row is None or row["used_at"]:
        return None
    con.execute("UPDATE oidc_link_tickets SET used_at = ? WHERE id = ?",
                (_iso(now), row["id"]))
    con.commit()
    if datetime.fromisoformat(row["expires_at"]) <= now:
        return None
    return row


# ------------------------------------------------------------ signing up

def provision(con: sqlite3.Connection, provider: str, subject: str,
              email: str | None, now: datetime | None = None) -> int:
    """First sign-in with a provider nobody has seen before: create a workspace,
    create the account that owns it, bind the identity, and return the user id.

    **This is what makes "Sign in with Google" behave the way every other site
    behaves**, and it replaced a single-use URL minted on the box. That design
    was safe and nobody could use it. The owner, 2026-08-23, asked for a normal
    register and login page. He is
    right, and the reason it is safe to do the normal thing now is workspaces: a
    new arrival lands in a workspace of their own with nothing in it, exactly as
    `/register` puts them, rather than in somebody else's fleet.

    **The rule that does not move is that an email address never merges two
    accounts.** If the address this provider reports already belongs to an
    account here, this refuses rather than attaching. Attaching would be the
    account-takeover pattern the module docstring quotes Microsoft on, and it
    would be worse here than there: it would hand a stranger an existing
    workspace instead of an empty one. Somebody in that position signs in with
    their password and connects the provider from inside.
    """
    now = now or now_utc()
    if not email:
        # Nothing to name the account with. Both providers send an address when
        # asked for the scope, so this is a misconfigured application rather
        # than an ordinary person, and guessing a placeholder would make a
        # login nobody could ever sign into again.
        raise LinkError(f"{provider} did not share an email address, so there is "
                        "nothing to name the account with.")
    email = accounts.normalize_email(email)
    if not signup.may_sign_up(email):
        # The gate, and it has to be here rather than only on the register
        # page: a provider sign-in is the other way an account comes into
        # being, and a banner that only covers the form is not a gate.
        raise LinkError(signup.CLOSED_NOTICE)
    if accounts.get_user_by_email(con, email) is not None:
        raise LinkError("An account with that email already exists here. Sign in "
                        "with your password, then connect this from your account.")
    workspace_id = db.create_workspace(con, email)
    user_id = accounts.create_user(con, email, accounts.random_password(),
                                   workspace_id=workspace_id)
    # The password is random and is never shown to anybody, here or anywhere.
    # The account is reached by the provider, and `users_cli passwd` is how it
    # gains a password if its owner ever wants one.
    link(con, provider, subject, user_id, email_shown=email, now=now)
    return user_id
