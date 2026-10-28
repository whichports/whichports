"""Operator accounts and server-side sessions.

The owner pulled accounts into v1 on 2026-08-15 (docs/RECORD.md 4.44 decision 1).
The reasoning that matters here: the V1 gate is a month of dogfooding before
anyone pays, so the first paying customer arrives with v1 and auth that does
not exist by then is what blocks the invoice.

The design is reviewed from an earlier project of the author's rather
than copied. What came across is the shape, and what did
not is the storage layer: that project runs SQLAlchemy on Postgres with Alembic
migrations, this runs stdlib sqlite3 with the additive CREATE TABLE IF NOT
EXISTS pattern `db.py` and `alerts.py` already use.

The properties this module is responsible for, each of them tested:

  - **Passwords are scrypt hashes, never anything reversible.** The parameters
    are written into every stored hash, so raising them later does not
    invalidate the passwords already set.
  - **Unknown email and wrong password cost the same.** A missing user still
    pays for one full hash, because an early return lets response timing
    enumerate which addresses have accounts.
  - **Sessions live in the database, so every cookie is revocable.** The cookie
    carries a random token, the row stores only its SHA-256, and logging out
    writes a revocation the very next request sees. A copied cookie stops
    working the moment the real owner signs out.
  - **Session lifetime is absolute, never sliding.** A stolen cookie expires on
    schedule however busy the thief keeps it.
  - **A session that still owes a second factor is not a session.** It is a
    separate, short-lived row that `resolve_session` refuses, so every gate in
    the application treats a half-finished login as signed out.

There is no self-serve signup here on purpose. Users are created by
`app.users_cli`, the way hosts are created by `app.hosts_cli`, so no account
creation surface exists on the internet before anyone decides one should.

**Every account belongs to exactly one workspace**, and that is the only thing
deciding which servers it can ever see. `app/db.py` owns the table and the
reasoning about where scoping happens. The column is read through
`workspace_of` below rather than by indexing the row, so there is one place
that decides what an unreadable or absent value means.
"""

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from . import channels, db, signup, totp

# scrypt, from hashlib, so no dependency is added for the one thing a
# dependency would be tempting for. n=2^14 blocks of r=8 costs about 16 MiB and
# roughly a tenth of a second per hash on this class of machine: slow enough to
# blunt offline guessing of a stolen database, fast enough that a login never
# queues. The numbers are OWASP's recommended shape for scrypt.
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32

# Length only, deliberately. Composition rules (one capital, one digit, one
# symbol) push people to "Password1!" and buy nothing. The maximum exists so a
# megabyte of input cannot turn a memory-hard hash into a denial of service.
PASSWORD_MIN_CHARS = 12
PASSWORD_MAX_CHARS = 128

# Good enough to catch a typo, deliberately not RFC 5322. The address is not a
# security boundary here: it is a label the operator recognises.
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
EMAIL_MAX_CHARS = 255

# The token prefix makes a leaked session token greppable in a log or a paste,
# the same convention `whp_` gives host credentials in store.py.
SESSION_PREFIX = "whp_sess_"

# Twelve hours, absolute. There is no "remember me" and no sliding renewal in
# this version: both are features, and a login that has to be repeated once a
# day is the honest starting point for a tool that shows a fleet's open ports.
SESSION_TTL = timedelta(hours=12)

# Writing last_used_at on every request would be a database write per page
# load. Every few minutes is plenty for answering "when was this session last
# used", which is all the column is for.
_LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)

# Revoked and expired rows are kept this long before deletion, so "when did
# that session end" is still answerable shortly after the fact.
_SESSION_KEEP_AFTER_EXPIRY = timedelta(days=30)

# A session that has passed the password and still owes a code. Ten minutes,
# because it is a step in a login and not a login: it exists only for as long
# as it takes somebody to read six digits off a phone. The full SESSION_TTL
# starts when the code lands.
PENDING_SESSION_TTL = timedelta(minutes=10)

# How many single-use recovery codes an enrolment prints.
RECOVERY_CODE_COUNT = 10

# Lowercase letters and digits with the lookalikes removed: no 0 or o, no 1 or
# l or i. These get read off a printout and typed by somebody who has just lost
# their phone. Two groups of four from a 31 character alphabet is about 39
# bits, which is far past online guessing behind the rate limit, and each code
# works once.
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"
_RECOVERY_GROUP = 4

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    disabled_at   TEXT,
    last_login_at TEXT,
    workspace_id  INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    created_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT,
    user_agent   TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, revoked_at);

CREATE TABLE IF NOT EXISTS totp_recovery_codes (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    code_hash  TEXT NOT NULL,
    created_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE INDEX IF NOT EXISTS idx_recovery_user ON totp_recovery_codes(user_id, used_at);
"""

# Columns added after the first release. SQLite has no ADD COLUMN IF NOT
# EXISTS, so the duplicate-column error is the idempotence check, which is the
# pattern db.init and alerts.init already use.
_ADDED_COLUMNS = (
    ("users", "workspace_id INTEGER NOT NULL DEFAULT 1"),
    ("users", "totp_secret TEXT"),
    ("users", "totp_enabled_at TEXT"),
    ("users", "totp_last_step INTEGER"),
    ("users", "display_name TEXT"),
    ("users", "is_admin INTEGER NOT NULL DEFAULT 0"),
    ("sessions", "totp_pending INTEGER NOT NULL DEFAULT 0"),
    # when the password was last set, for the account Settings screen
    # (docs/screens/account-settings). NULL on an account whose password
    # predates the column, which the screen shows as no date.
    ("users", "password_changed_at TEXT"),
    # when the address was confirmed by a link from the confirm mail
    # (docs/screens/sign-in). Nothing refuses an unconfirmed account: this
    # records the fact, and the gate is the beta's to add with the sign-up
    # flow that issues those links.
    ("users", "email_confirmed_at TEXT"),
)

# A display name is a label a person reads, like a workspace name, so the only
# checks are a trim and a bound. The bound exists so a paste of a whole
# document cannot land in a column every page load reads back.
DISPLAY_NAME_MAX_CHARS = 80


class AccountError(Exception):
    """A problem with an account the person in front of the form caused, and
    whose message is safe to show them."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init and alerts.init follow.

    **Accounts that predate workspaces land in workspace 1**, the same one
    `db.init` backfills the hosts into, so an operator who signed in yesterday
    still sees their own servers after the upgrade and nobody runs anything by
    hand. SQLite fills every existing row with a new column's default as part
    of the ALTER, so the backfill is the default itself.

    `db.init` has to have run first, because workspace 1 is created there and
    an account pointing at a workspace that does not exist has nowhere to be.
    """
    con.executescript(SCHEMA)
    for table, column in _ADDED_COLUMNS:
        try:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {column}")
        except sqlite3.OperationalError as exc:
            if "duplicate column" not in str(exc):
                raise
    con.commit()


def workspace_of(user) -> int:
    """The workspace an account belongs to, as a positive integer.

    Read defensively, the way the renderer reads `paused`: a Row from a
    connection that has not run `init` yet does not carry the column at all,
    and a hand-edited row could hold text where an integer belongs. Both fall
    back to workspace 1, which is where every account predating workspaces was
    backfilled, so the fallback is the answer the migration gives rather than
    a guess.
    """
    if user is None:
        return db.DEFAULT_WORKSPACE_ID
    keys = user.keys() if hasattr(user, "keys") else ()
    if "workspace_id" not in keys:
        return db.DEFAULT_WORKSPACE_ID
    value = user["workspace_id"]
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return db.DEFAULT_WORKSPACE_ID
    return value


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat()


def _parse(value) -> datetime | None:
    """Timestamps are ISO strings in the database. A row written by hand, or by
    an older build, must not take a request down."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    # Rows written before this module existed may carry no offset. Treating a
    # naive stamp as UTC matches how everything else here writes them.
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


# ---------------------------------------------------------------- passwords

def normalize_email(email: str) -> str:
    return email.strip().lower()


def valid_email(email: str) -> bool:
    return len(email) <= EMAIL_MAX_CHARS and _EMAIL_RE.fullmatch(email) is not None


# The three rules a password has to meet, in the order the screens list them.
# Each is (key, the words on the screen, the test).
#
# **Length was the only rule until 2026-09-10**, and the sign-up page carried a
# sentence saying why: composition rules push people to Password1!, which is a
# real effect and the reason the rule was one. The owner decided otherwise that
# day: twelve characters, with a number and a special character. The
# trade is his to make and it is recorded (`docs/RECORD.md` 4.163). What the
# screens do about the failure mode is show all three rules while somebody
# types, so the answer is visible before the form is submitted rather than
# after.
#
# Anything that is not a letter or a digit counts as special, including a
# space. Naming a short list of punctuation would be a smaller alphabet than
# the one people actually use, and every character outside it would be a
# refusal nobody could explain.
PASSWORD_RULES = (
    ("length", f"At least {PASSWORD_MIN_CHARS} characters",
     lambda p: len(p) >= PASSWORD_MIN_CHARS),
    ("digit", "A number", lambda p: any(c.isdigit() for c in p)),
    ("special", "A special character",
     lambda p: any(not c.isalnum() for c in p)),
)


def password_rules_met(password: str) -> dict:
    """Which rules this password meets, keyed the way the screens key them.

    The one place the answer is computed. The pages draw the same three rows
    from `PASSWORD_RULES` and the browser re-checks them while somebody types,
    so what a form says before it is sent and what the server says after are
    the same three questions.
    """
    return {key: bool(test(password or "")) for key, _words, test in PASSWORD_RULES}


def check_password_shape(password: str) -> None:
    """Raise AccountError unless the password meets every rule.

    Length first, and the upper bound before the composition rules: a paste of
    a whole document is not somebody who forgot a digit, and telling them to
    add one would be answering the wrong question.
    """
    if len(password) > PASSWORD_MAX_CHARS:
        raise AccountError(f"Use at most {PASSWORD_MAX_CHARS} characters.")
    met = password_rules_met(password)
    missing = [words for key, words, _test in PASSWORD_RULES if not met[key]]
    if missing:
        # One sentence naming everything that is missing, because a form that
        # refuses three times in a row for three reasons is three round trips
        # for one mistake.
        raise AccountError("Needs " + ", ".join(w[0].lower() + w[1:] for w in missing) + ".")


def random_password() -> str:
    """A password nobody types and nobody is shown.

    An account made by a provider sign-in still needs the column filled, and
    what goes in it has to satisfy the same rules as anything else, because
    the check is one function and a bypass for machine-made values is a
    bypass somebody reuses. `token_urlsafe` is letters, digits and two
    punctuation marks and usually contains both, but usually is not a
    guarantee, so the two are appended rather than hoped for.
    """
    return secrets.token_urlsafe(32) + "9-"


def hash_password(password: str) -> str:
    """Hash a password into a self-describing string:

        scrypt$n$r$p$salt_base64$key_base64

    The parameters travel with the hash, so raising them later leaves every
    existing password still verifiable against the numbers it was made with.
    """
    salt = secrets.token_bytes(_SALT_BYTES)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                         n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=_KEY_BYTES)
    return "$".join(("scrypt", str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P),
                     base64.b64encode(salt).decode("ascii"),
                     base64.b64encode(key).decode("ascii")))


def verify_password(password: str, stored: str) -> bool:
    """Check a password against a stored hash, using the parameters the hash
    itself carries. A malformed or foreign hash is False, never an exception,
    because it must not be distinguishable from a wrong password."""
    try:
        scheme, n_s, r_s, p_s, salt_b64, key_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(key_b64, validate=True)
        if not salt or not expected:
            return False
        key = hashlib.scrypt(password.encode("utf-8"), salt=salt,
                             n=int(n_s), r=int(r_s), p=int(p_s), dklen=len(expected))
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(key, expected)


# Burned when the email is unknown or the account is disabled, so all three
# answers cost the same hash. Without it, response timing tells an attacker
# which addresses have accounts, which is the enumeration the identical wording
# on the login page exists to prevent.
_DUMMY_HASH = hash_password("not-a-real-password-only-here-to-equalise-timing")


def _hash_token(token: str) -> str:
    """SHA-256 with no salt and no stretching, on purpose. A session token is
    32 random bytes from secrets, so there is nothing to guess and nothing a
    slow hash would protect: this is a lookup key that a database copy cannot
    be turned back into a cookie."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# -------------------------------------------------------------------- users

def get_user_by_email(con: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return con.execute("SELECT * FROM users WHERE email = ?",
                       (normalize_email(email),)).fetchone()


def create_user(con: sqlite3.Connection, email: str, password: str,
                workspace_id: int = db.DEFAULT_WORKSPACE_ID) -> int:
    """Create an account in one workspace. Raises AccountError on a malformed
    address, a password outside the length bounds, or an address already taken.

    The workspace decides which servers this account will ever see, so it is a
    real argument rather than something derived later. It defaults to 1, the
    workspace every account and every host predating workspaces was backfilled
    into, so `users_cli add` with no `--workspace` keeps doing exactly what it
    did before.

    It also makes the account's email channel in that workspace, see
    `channels.ensure_account_email`.
    """
    email = normalize_email(email)
    if not valid_email(email):
        raise AccountError("That does not look like an email address.")
    check_password_shape(password)
    if get_user_by_email(con, email) is not None:
        raise AccountError("An account with that email already exists.")
    if db.workspace_by_id(con, workspace_id) is None:
        raise AccountError(f"There is no workspace {workspace_id}.")
    # Asked before the account is written, so an address the channel would
    # refuse is refused here and no account is left without its mail.
    if channels.check_destination(channels.TYPE_EMAIL, email):
        raise AccountError("That does not look like an email address.")
    cur = con.execute(
        "INSERT INTO users (email, password_hash, created_at, workspace_id)"
        " VALUES (?, ?, ?, ?)",
        (email, hash_password(password), _iso(now_utc()), workspace_id))
    con.commit()
    # The account's alerts go to its own address from the first minute, as an
    # ordinary channel row (the owner, 2026-09-20, `docs/RECORD.md` 4.186).
    channels.ensure_account_email(con, email, workspace_id)
    return cur.lastrowid


def set_password(con: sqlite3.Connection, user_id: int, password: str) -> None:
    """Set a new password. The caller decides what happens to live sessions;
    `users_cli passwd` revokes them all, because a password change is what
    somebody does when they think the old one is in the wrong hands."""
    check_password_shape(password)
    con.execute("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?",
                (hash_password(password), _iso(now_utc()), user_id))
    con.commit()


def set_disabled(con: sqlite3.Connection, email: str, disabled: bool) -> bool:
    """Disable or re-enable an account. Disabling is a timestamp rather than a
    deleted row, the same way host revocation is, so it stays visible history.
    Sessions are not touched here: `users_cli disable` revokes them, and
    authenticate() refuses a disabled account either way."""
    cur = con.execute(
        "UPDATE users SET disabled_at = ? WHERE email = ?",
        (_iso(now_utc()) if disabled else None, normalize_email(email)))
    con.commit()
    return cur.rowcount == 1


def set_display_name(con: sqlite3.Connection, user_id: int, name: str) -> None:
    """Store the name the account menu shows, or clear it with empty text.

    Nothing invents a name. An account whose operator never set one has none,
    the stored value is NULL rather than a guess derived from the email, and
    everything that reads it falls back to the email on its own.
    """
    name = (name or "").strip()
    if len(name) > DISPLAY_NAME_MAX_CHARS:
        raise AccountError(f"Use at most {DISPLAY_NAME_MAX_CHARS} characters.")
    con.execute("UPDATE users SET display_name = ? WHERE id = ?",
                (name or None, user_id))
    con.commit()


def mark_email_confirmed(con: sqlite3.Connection, user_id: int) -> None:
    """Stamp the address as confirmed. Re-confirming leaves the first stamp
    alone, so the column keeps saying when it was really confirmed rather than
    when somebody last clicked an old mail."""
    con.execute("UPDATE users SET email_confirmed_at = ? WHERE id = ?"
                " AND email_confirmed_at IS NULL", (_iso(now_utc()), user_id))
    con.commit()


def email_confirmed_at(user) -> str:
    """When the address was confirmed, or empty for an account from before the
    column or one that never confirmed."""
    keys = user.keys() if hasattr(user, "keys") else ()
    if "email_confirmed_at" not in keys:
        return ""
    return user["email_confirmed_at"] or ""


def password_changed_at(user) -> str:
    """When the password was last set, as stored, or empty for an account
    from before the column or whose password was never changed."""
    keys = user.keys() if hasattr(user, "keys") else ()
    if "password_changed_at" not in keys:
        return ""
    return user["password_changed_at"] or ""


def display_name_of(user) -> str:
    """The stored display name, or empty when there is nothing to show.

    Read defensively, the way `workspace_of` reads its column: a Row from a
    connection that has not run `init` yet does not carry the column at all,
    and a hand-edited row could hold something other than text. Empty is the
    honest answer in every such case, never a guess.
    """
    if user is None:
        return ""
    keys = user.keys() if hasattr(user, "keys") else ()
    if "display_name" not in keys:
        return ""
    value = user["display_name"]
    if not isinstance(value, str):
        return ""
    return value.strip()


# ------------------------------------------------------------------- admin
#
# A second flag beside the workspace, and it answers a different question. The
# workspace decides which servers an account sees. This decides whether the
# account also sees the whole service: how many accounts exist, how many of
# them ever added a server, how many servers ever reported.
#
# **It is granted on the box and nowhere else**, the same rule that already
# makes `users_cli` the only way an account or a second factor comes into
# being. There is no route, no form and no environment variable that turns it
# on, so the surface for getting it wrong is one command run by somebody who
# already has a shell.
#
# **No address is special in the code.** Writing an email address into a
# constant here would mean the flag could not be taken away without a deploy,
# and it would keep being true on a database restored anywhere. The column is
# the whole of it.


def is_admin(user) -> bool:
    """Whether this account sees the service-wide numbers.

    Read defensively, the way `workspace_of` and `display_name_of` read their
    columns: a Row from a connection that has not run `init` yet does not carry
    the column at all, and a hand-edited row could hold text where an integer
    belongs. **Every one of those cases answers False**, which is the safe way
    round for a flag that opens a screen: a column nobody can read is not a
    grant.
    """
    if user is None:
        return False
    keys = user.keys() if hasattr(user, "keys") else ()
    if "is_admin" not in keys:
        return False
    value = user["is_admin"]
    if isinstance(value, bool):
        return value
    if not isinstance(value, int):
        return False
    return value == 1


def set_admin(con: sqlite3.Connection, email: str, admin: bool) -> bool:
    """Grant or take away the admin flag. False when there is no such account.

    Sessions are left alone deliberately, in both directions. The flag is read
    from the users row on every request, so a grant reaches the next page load
    and a revocation takes the screen away just as fast. Signing somebody out
    to change what one screen shows them would be a bigger hammer than the
    change deserves.
    """
    cur = con.execute("UPDATE users SET is_admin = ? WHERE email = ?",
                      (1 if admin else 0, normalize_email(email)))
    con.commit()
    return cur.rowcount == 1


def list_users(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM users ORDER BY email").fetchall()


def authenticate(con: sqlite3.Connection, email: str, password: str) -> sqlite3.Row | None:
    """The user when the email and password match and the account is enabled,
    otherwise None, after the same amount of hashing work in all three cases.

    The equalisation is the point of the dummy hash above: an unknown address
    that returned early would answer in a millisecond while a real one takes a
    tenth of a second, and that difference is a working account-enumeration
    oracle no matter how careful the wording on the page is.
    """
    user = get_user_by_email(con, email)
    if user is None:
        verify_password(password, _DUMMY_HASH)
        return None
    if user["disabled_at"]:
        verify_password(password, _DUMMY_HASH)
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


# ----------------------------------------------------------------- sessions

def issue_session(con: sqlite3.Connection, user_id: int,
                  user_agent: str | None = None,
                  now: datetime | None = None,
                  totp_pending: bool = False) -> tuple[str, datetime]:
    """Create a session row and return (token, expires_at).

    The token is returned once, for the cookie, and never stored: the row holds
    its SHA-256. So a copy of this database hands an attacker the inventory
    (PRODUCT.md section 6 says so plainly) but not one usable cookie.

    `totp_pending=True` is the login's half-way house: the password is proved
    and a code is still owed. It is a session row so the browser has something
    to carry to the second page, and nothing else: `resolve_session` refuses
    it, so every gate in the application still says signed out. It expires in
    PENDING_SESSION_TTL rather than SESSION_TTL, and it does not touch
    last_login_at, because nobody has logged in yet.
    """
    now = now or now_utc()
    token = SESSION_PREFIX + secrets.token_urlsafe(32)
    expires_at = now + (PENDING_SESSION_TTL if totp_pending else SESSION_TTL)
    con.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at,"
        " last_used_at, user_agent, totp_pending) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (_hash_token(token), user_id, _iso(now), _iso(expires_at), _iso(now),
         (user_agent or "")[:255] or None, 1 if totp_pending else 0))
    if not totp_pending:
        con.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (_iso(now), user_id))
    # Opportunistic hygiene. Logins are rare, dead rows have no reader, and
    # doing it here means no extra timer exists to forget to install.
    purge_expired_sessions(con, now=now)
    con.commit()
    return token, expires_at


def resolve_session(con: sqlite3.Connection, token: str,
                    now: datetime | None = None) -> sqlite3.Row | None:
    """The request-time lookup: a live session token to its user, or None.

    None covers every reason equally: no such token, revoked, expired, the
    account behind it disabled, or a second factor still owed. The caller only
    ever needs to know whether somebody is signed in.

    **The pending case is the one worth reading twice.** A session that has
    passed the password and not yet passed the code resolves to None here, and
    that is what makes the second factor a gate rather than a suggestion: every
    caller in the application asks this one function, so there is no route that
    could accidentally accept a half-finished login.
    """
    if not token or not token.startswith(SESSION_PREFIX):
        return None
    now = now or now_utc()
    row = con.execute("SELECT * FROM sessions WHERE token_hash = ?",
                      (_hash_token(token),)).fetchone()
    if row is None or row["revoked_at"] or row["totp_pending"]:
        return None
    expires_at = _parse(row["expires_at"])
    if expires_at is None or expires_at <= now:
        return None
    user = con.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if user is None or user["disabled_at"]:
        return None
    last_used = _parse(row["last_used_at"])
    if last_used is None or now - last_used > _LAST_USED_WRITE_INTERVAL:
        con.execute("UPDATE sessions SET last_used_at = ? WHERE id = ?",
                    (_iso(now), row["id"]))
        con.commit()
    return user


def revoke_session(con: sqlite3.Connection, token: str,
                   now: datetime | None = None) -> bool:
    """Sign out: revoke the one session behind this token. Idempotent, and
    False when there was nothing live to revoke."""
    if not token or not token.startswith(SESSION_PREFIX):
        return False
    cur = con.execute(
        "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
        (_iso(now or now_utc()), _hash_token(token)))
    con.commit()
    return cur.rowcount == 1


def revoke_all_sessions(con: sqlite3.Connection, user_id: int,
                        now: datetime | None = None) -> int:
    """Revoke every live session of one account, and return how many. This is
    what a password change and a disable both use."""
    cur = con.execute(
        "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
        (_iso(now or now_utc()), user_id))
    con.commit()
    return cur.rowcount


def live_sessions(con: sqlite3.Connection, user_id: int,
                  now: datetime | None = None) -> list[sqlite3.Row]:
    """The sessions that would still resolve, newest first. The CLI prints
    these so "who is signed in" has an answer from a terminal.

    A pending session is left out, because it would not resolve and nobody is
    signed in on it. `revoke_all_sessions` still kills those rows: only this
    listing hides them.
    """
    return con.execute(
        "SELECT * FROM sessions WHERE user_id = ? AND revoked_at IS NULL"
        " AND totp_pending = 0 AND expires_at > ? ORDER BY created_at DESC",
        (user_id, _iso(now or now_utc()))).fetchall()


def purge_expired_sessions(con: sqlite3.Connection, now: datetime | None = None) -> int:
    """Delete rows nothing can ever resolve again. Kept for a while past expiry
    so a question about a session can still be answered shortly afterwards."""
    horizon = (now or now_utc()) - _SESSION_KEEP_AFTER_EXPIRY
    cur = con.execute("DELETE FROM sessions WHERE expires_at < ?", (_iso(horizon),))
    return cur.rowcount


# ------------------------------------------------------- the second factor

# The RFC 6238 arithmetic is app/totp.py and has no state at all. This section
# is the half that does: the secret on the user row, the replay floor, the
# recovery codes, and the pending session a login parks in while it waits for
# six digits.


def totp_enabled(user: sqlite3.Row) -> bool:
    """Whether the second factor is on. A secret alone is not enough: an
    enrolment that was started and never confirmed counts as off, so an
    abandoned attempt can never lock somebody out of their own account."""
    return bool(user["totp_secret"]) and bool(user["totp_enabled_at"])


def begin_totp_enrollment(con: sqlite3.Connection, user_id: int) -> str:
    """Mint the secret and return it, once, for the operator to type into an
    authenticator app. Nothing is enabled yet.

    Re-running this replaces an unconfirmed secret, so an abandoned enrolment
    never wedges the next attempt. It refuses to touch a confirmed one, because
    that would silently invalidate the app the operator is already using.
    """
    user = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise AccountError("No such account.")
    if totp_enabled(user):
        raise AccountError("Two-factor authentication is already on for this account.")
    secret = totp.generate_secret()
    con.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
    con.commit()
    return secret


def confirm_totp_enrollment(con: sqlite3.Connection, user_id: int, code: str,
                            at_time: float) -> list[str]:
    """Turn the second factor on, once a code proves the authenticator really
    holds the secret. Returns the recovery codes, which is the only moment they
    exist in readable form anywhere.

    Confirming with a code and not with a button is the whole point. It is what
    stops an operator locking themselves out with a secret their phone never
    actually stored.
    """
    user = con.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        raise AccountError("No such account.")
    if totp_enabled(user):
        raise AccountError("Two-factor authentication is already on for this account.")
    if not user["totp_secret"]:
        raise AccountError("Start the enrolment first.")
    step = totp.verify_code(user["totp_secret"], code, at_time)
    if step is None:
        raise AccountError("That code is not right. Check the app and try again.")
    # The confirming code is spent the moment it is accepted, so it can never
    # be replayed at the login page a few seconds later.
    con.execute("UPDATE users SET totp_enabled_at = ?, totp_last_step = ? WHERE id = ?",
                (_iso(now_utc()), step, user_id))
    codes = _issue_recovery_codes(con, user_id)
    con.commit()
    return codes


def disable_totp(con: sqlite3.Connection, user_id: int) -> None:
    """Turn the second factor off: the secret, the enabled marker, the replay
    floor and every recovery code row. This is the lockout path, so it is
    deliberately reachable only from `app.users_cli` on the box, by somebody
    who already has a shell there."""
    con.execute("UPDATE users SET totp_secret = NULL, totp_enabled_at = NULL,"
                " totp_last_step = NULL WHERE id = ?", (user_id,))
    con.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?", (user_id,))
    con.commit()


def _issue_recovery_codes(con: sqlite3.Connection, user_id: int) -> list[str]:
    """Replace this account's recovery codes with a fresh set. They are stored
    as scrypt hashes and nowhere in readable form, the same as a password: a
    copy of the database is not a way in."""
    con.execute("DELETE FROM totp_recovery_codes WHERE user_id = ?", (user_id,))
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        halves = ("".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP))
                  for _ in range(2))
        code = "-".join(halves)
        codes.append(code)
        con.execute("INSERT INTO totp_recovery_codes (user_id, code_hash, created_at)"
                    " VALUES (?, ?, ?)", (user_id, hash_password(code), _iso(now_utc())))
    return codes


def reset_recovery_codes(con: sqlite3.Connection, user_id: int) -> list[str]:
    """Throw away this account's recovery codes and return a fresh set. Used
    when the operator has spent some, or thinks the printout went astray."""
    codes = _issue_recovery_codes(con, user_id)
    con.commit()
    return codes


def recovery_codes_remaining(con: sqlite3.Connection, user_id: int) -> int:
    row = con.execute("SELECT COUNT(*) AS n FROM totp_recovery_codes"
                      " WHERE user_id = ? AND used_at IS NULL", (user_id,)).fetchone()
    return int(row["n"])


def verify_second_factor(con: sqlite3.Connection, user: sqlite3.Row, code: str,
                         at_time: float) -> str | None:
    """The second factor check, in both its flavours. Returns "totp" or
    "recovery" on success, so the caller can say which was used, and None
    otherwise. State moves only on success.

    Six digits are read as a TOTP code and anything else is tried as a recovery
    code, which is unambiguous because a recovery code carries a hyphen and
    letters.
    """
    secret = user["totp_secret"]
    if not secret or not user["totp_enabled_at"]:
        return None
    submitted = code.strip().replace(" ", "")
    # totp._is_ascii_digits, not str.isdigit, and the docstring there says why.
    if len(submitted) == totp.DIGITS and totp._is_ascii_digits(submitted):
        step = totp.verify_code(secret, submitted, at_time)
        if step is None:
            return None
        # The replay guard, and the reason the accepted step is stored rather
        # than the code. A code stays valid for ninety seconds across the
        # verify window, which is ninety seconds in which somebody reading it
        # over a shoulder could type it in a second browser. Each acceptance
        # raises the floor, so the same step never works twice.
        last_step = user["totp_last_step"]
        if last_step is not None and step <= last_step:
            return None
        con.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
        con.commit()
        return "totp"
    return _redeem_recovery_code(con, user["id"], submitted.lower())


def _redeem_recovery_code(con: sqlite3.Connection, user_id: int,
                          submitted: str) -> str | None:
    """Try a submitted string against this account's unused recovery codes, and
    mark the one that matches as used.

    Every row is checked and none is skipped after a match, so the work done
    does not depend on which code matched or on whether any did. That costs one
    scrypt hash per unused code, which is around a second for a full set. It is
    a rare path behind a rate limit, and paying it flat is what keeps the
    timing from saying anything.
    """
    rows = con.execute("SELECT * FROM totp_recovery_codes"
                       " WHERE user_id = ? AND used_at IS NULL", (user_id,)).fetchall()
    matched = None
    for row in rows:
        if verify_password(submitted, row["code_hash"]) and matched is None:
            matched = row
    if matched is None:
        return None
    con.execute("UPDATE totp_recovery_codes SET used_at = ? WHERE id = ?",
                (_iso(now_utc()), matched["id"]))
    con.commit()
    return "recovery"


def resolve_pending_session(con: sqlite3.Connection, token: str,
                            now: datetime | None = None) -> sqlite3.Row | None:
    """The account behind a session that has passed the password and still owes
    a code, or None. The mirror image of `resolve_session`: that one refuses a
    pending row and this one accepts nothing else."""
    if not token or not token.startswith(SESSION_PREFIX):
        return None
    now = now or now_utc()
    row = con.execute("SELECT * FROM sessions WHERE token_hash = ?",
                      (_hash_token(token),)).fetchone()
    if row is None or row["revoked_at"] or not row["totp_pending"]:
        return None
    expires_at = _parse(row["expires_at"])
    if expires_at is None or expires_at <= now:
        return None
    user = con.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if user is None or user["disabled_at"]:
        return None
    return user


def complete_pending_session(con: sqlite3.Connection, token: str,
                             user_agent: str | None = None,
                             now: datetime | None = None) -> tuple[str, datetime] | None:
    """The code checked out: revoke the pending session and issue a real one.
    Returns the new (token, expires_at), or None when there was nothing pending.

    **The token changes, and that is deliberate.** The cookie the browser
    carried through the challenge is not the cookie it leaves with, so a value
    that was planted in the browser before the login cannot become a signed-in
    session after it. It costs one row and it removes a whole class of question
    about where the first cookie came from.
    """
    now = now or now_utc()
    user = resolve_pending_session(con, token, now=now)
    if user is None:
        return None
    revoke_session(con, token, now=now)
    return issue_session(con, user["id"], user_agent=user_agent, now=now)


# --------------------------------------------------------------- signing up

# The one place an account comes into being from the internet rather than from
# a shell on the box. `app.users_cli add` is still there and still makes an
# account inside an existing workspace, which is what the operator on the
# production box wants. This is the other shape: somebody arrives, and both a
# workspace and the account that owns it are created together.


def register(con: sqlite3.Connection, email: str, password: str,
             now: datetime | None = None) -> int:
    """Create a workspace and the first account in it. Returns the user id.

    **The workspace is created first and the account is put inside it**, so a
    new arrival never lands in somebody else's fleet. That is the whole reason
    this function exists rather than callers using `create_user`, whose
    workspace defaults to 1 because that is right for the command line and
    exactly wrong here.

    Raises AccountError on a malformed address, a password outside the length
    bounds, or an address already taken. The address check happens before the
    workspace is made, so a refused signup leaves nothing behind.
    """
    email = normalize_email(email)
    if not valid_email(email):
        raise AccountError("That does not look like an email address.")
    if not signup.may_sign_up(email):
        # Checked before the password so a refused signup does no hashing, and
        # before the address lookup so a closed server does not answer whether
        # an address is taken.
        raise AccountError(signup.CLOSED_NOTICE)
    check_password_shape(password)
    if get_user_by_email(con, email) is not None:
        # The same words `create_user` uses. This one endpoint does tell a
        # visitor that an address is taken, and it has to: a signup form that
        # refused without saying why would be unusable. What it must never do
        # is become a cheaper oracle than the signup itself, which is why it
        # costs a full request behind the same rate limit the login uses.
        raise AccountError("An account with that email already exists.")
    workspace_id = db.create_workspace(con, email)
    return create_user(con, email, password, workspace_id=workspace_id)
