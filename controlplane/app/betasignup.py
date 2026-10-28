"""The beta list: who asked for an invitation.

`untilbeta.md`, "Meanwhile": the signup on the landing page is the signal of
who is waiting while the beta gets built. This module owns what is kept about
each of them and the rules for taking it in. `app/betasignup_routes.py` is the
HTTP half and `app/betasignup_cli.py` reads and removes from the box.

## What is kept, and what never is

Three things per person: the address, one of four sizes of fleet if they said
one, and when they joined. **Never the address the request came from**, and no
free text of any kind: the two fields are checked to a closed shape before
anything is written, so nothing a stranger types reaches the database, a log
line or a mail.

The addresses are contact data. They live in the database on the box and
nowhere in this repository, so every test here uses the
reserved example domains and no fixture holds a real one. The nightly backup
carries the table like every other.

## Off unless the landing page's address is set

`WHICHPORTS_BETA_LANDING` names where the form lives, `https://whichports.com`
on our box. Unset, the route answers 404, so a self-hosted instance, which
serves the same code under the same `/api/v1/*`, never collects anybody's
address. Set, it is also where a form post without JavaScript is sent back
to, so the redirect goes to an address we configured and never to one a
request named. It is held to the same shape as the control plane's own
address (`app/publicurl.py`).

## The same answer for a new address and a known one

Joining twice is the same `200` as joining once, and the row the first time
made is not touched. Otherwise the route would answer "is this person on your
list" for anybody who asked, and a second submit could rewrite a stranger's
row.
"""
import os
import re
import sqlite3
import urllib.parse
from datetime import datetime, timezone

LANDING_ENV = "WHICHPORTS_BETA_LANDING"

# The four sizes the form offers. A closed set: anything else is refused, not
# stored as text.
BUCKETS = ("1-5", "6-20", "21-100", "100+")

# RFC 5321 section 4.5.3.1.3 bounds a path at 256 octets including its angle
# brackets, which leaves 254 for the address, and 4.5.3.1.1 gives the local
# part 64.
MAX_EMAIL = 254
MAX_LOCAL = 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS beta_signups (
    email      TEXT PRIMARY KEY,
    servers    TEXT,
    created_at TEXT NOT NULL
);
"""

# The local part as an unquoted dot-atom: RFC 5322's atext, with dots between
# atoms. A quoted local part is legal and nobody signing up for a beta has
# one, so it is refused rather than parsed.
_LOCAL_RE = re.compile(r"[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
# A host name: labels of letters, digits and hyphens, no hyphen at either
# end, at least two labels, and a last label that is not a number, so an
# address literal is not taken for a domain. An internationalised name passes
# in its xn-- form.
_LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
# The same shape `app/publicurl.py` holds the control plane's address to.
_NETLOC_RE = re.compile(r"[A-Za-z0-9.:\[\]-]+")


class InvalidEmail(ValueError):
    """Not an address this list takes."""


class InvalidServers(ValueError):
    """Not one of the four sizes."""


class LandingMisconfigured(ValueError):
    """The setting is there and is not an https address with nothing after
    the host."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule every other module's init follows."""
    con.executescript(SCHEMA)
    con.commit()


def landing(environ=None) -> str | None:
    """`https://host` of the landing page, or None when the list is off."""
    environ = os.environ if environ is None else environ
    value = environ.get(LANDING_ENV, "").strip()
    if not value:
        return None
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname \
            or parsed.path not in ("", "/") or parsed.query \
            or parsed.fragment or parsed.username or parsed.password \
            or not _NETLOC_RE.fullmatch(parsed.netloc):
        raise LandingMisconfigured(
            f"{LANDING_ENV} is an https address with nothing after the host,"
            f" such as https://whichports.com. {value!r} is not")
    return f"https://{parsed.netloc}"


def normalise_email(value) -> str:
    """The address, trimmed and lowercased, or InvalidEmail.

    Lowercased whole, the local part included. A mail server may tell
    `Jan@` from `jan@`, almost none do, and one person joining twice under
    two spellings is the case that actually happens.
    """
    if not isinstance(value, str):
        raise InvalidEmail("not text")
    email = value.strip().lower()
    if not email or len(email) > MAX_EMAIL:
        raise InvalidEmail("empty or too long")
    local, at, domain = email.rpartition("@")
    if not at or not local or len(local) > MAX_LOCAL \
            or not _LOCAL_RE.fullmatch(local):
        raise InvalidEmail("the part before the @ is not one this list takes")
    labels = domain.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.fullmatch(label) for label in labels) \
            or labels[-1].isdigit():
        raise InvalidEmail("the part after the @ is not a domain name")
    return email


def normalise_servers(value) -> str | None:
    """One of the four sizes, None when nothing was chosen, or InvalidServers."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidServers("not text")
    chosen = value.strip()
    if not chosen:
        return None
    if chosen not in BUCKETS:
        raise InvalidServers("not one of the four sizes")
    return chosen


def add(con: sqlite3.Connection, email: str, servers: str | None,
        now: datetime | None = None) -> bool:
    """Put one checked address on the list. True when it was not there.

    `email` and `servers` are what `normalise_email` and `normalise_servers`
    returned, never what a request held. An address already on the list keeps
    the row it has.
    """
    stamp = (now or datetime.now(timezone.utc)).isoformat()
    cursor = con.execute(
        "INSERT OR IGNORE INTO beta_signups (email, servers, created_at)"
        " VALUES (?, ?, ?)", (email, servers, stamp))
    con.commit()
    return cursor.rowcount == 1


def count(con: sqlite3.Connection) -> int:
    return con.execute("SELECT COUNT(*) FROM beta_signups").fetchone()[0]


def list_all(con: sqlite3.Connection) -> list:
    """Everybody on the list, oldest first."""
    return con.execute(
        "SELECT email, servers, created_at FROM beta_signups"
        " ORDER BY created_at, email").fetchall()


def remove(con: sqlite3.Connection, email: str) -> bool:
    """Take one address off the list. True when it was on it. For somebody
    who writes to ask, which is the way off the page promises."""
    cursor = con.execute("DELETE FROM beta_signups WHERE email = ?", (email,))
    con.commit()
    return cursor.rowcount == 1
