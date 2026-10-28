"""A message a person sends from the Feedback window: its shape, its table,
and what is done to the words before they are kept.

## The one exception to "no free text"

SI-8 says error classes only and no free text on any wire. It has one
exception, decided on 2026-10-06 (docs/record 4.425): the words a person
types into the Feedback window and sends with a click, shown whole before
they leave and sent at no other time. This file is where that exception is
held to its size.

**What a message is:** five fields and nothing else, `FIELDS`. A body with a
sixth is refused, so nothing can ride along: no server's name, no address,
no path of a page. The screen is a word from a list and never the address
bar, because a path holds a server's name.

**Nothing an agent sends.** The routes in `app/feedback_routes.py` take an
instance's API key only. The other key an instance has is in every agent's
install command and is refused there like a key nobody issued.

## Two places a message is checked, and why they differ

An instance checks the screen word against `SCREENS`, the closed list: there
the page and this code are one commit. Our own box takes any word of
`SCREEN_SHAPE`, because an instance and our box are at different commits
most of the time, and the day a screen is added a report from it must still
arrive. `parse(payload, closed_list=...)` is that one difference.

## The words

`clean` takes out every control character but the newline, and the marks
that turn the direction of a line. The second kind survives escaping and
can make a row in the console read as something it is not. The page takes
the same characters out of the field as they are typed, so the person has
seen the words without them before sending. Both servers do it again, which
changes nothing for an honest page.

The words are stored as cleaned, drawn escaped, never interpreted and never
written to a log: nothing in this file or in the routes passes them to a
logger, and a test listens to every logger while messages come in.

## What is kept

A row holds who it is from, an instance's id on our box or a workspace's id
when written locally, the kind, the words, the screen, the version and the
time it arrived. **No address is written**, as the prober API writes none.
A row stays until it is deleted in the console. `mark_done` and `delete` are
the console's two writes.

## The pace

Twenty messages in the last 24 hours, for an instance on our box and for a
workspace on an instance. Counted from the rows stored, done ones included.
A first guess (the brief says so) and one number, `PER_DAY`.
"""
import dataclasses
import re
import sqlite3
import unicodedata
from datetime import datetime, timedelta, timezone

# The body's fields, in the order they are sent. The page's own test holds
# its side to this tuple.
FIELDS = ("version", "kind", "words", "screen", "instance_version")
BODY_VERSION = 1
KINDS = ("feature", "bug")

# Refused before it is parsed. 2,000 characters of UTF-8 are 8,000 bytes at
# most, and the other four fields with JSON's own punctuation are under 150.
MAX_BODY_BYTES = 8192
MAX_WORDS = 2000

# Every screen the Feedback button can be pressed on.
SCREENS = (
    "fleet", "host", "host/services", "host/evidence", "host/rules",
    "host/path", "host/changes", "host/settings", "alerts", "integrations",
    "settings", "admin",
)
# What our own box takes where it cannot know the list.
SCREEN_SHAPE = re.compile(r"[a-z][a-z/-]{0,39}")
VERSION_SHAPE = re.compile(r"[0-9a-f]{7,40}")
VERSION_UNKNOWN = "unknown"

# The classes a message can be refused with: five of the prober API's closed
# set (`proberapi.ERRORS`), and this file adds none to it.
REFUSALS = ("unknown_key", "malformed_request", "unsupported_version",
            "too_large", "over_instance_pace")

PER_DAY = 20
A_DAY = timedelta(hours=24)

# The marks that turn the direction of a line: the embeddings and overrides,
# U+202A to U+202E, and the isolates, U+2066 to U+2069.
DIRECTION_MARKS = frozenset(
    [chr(code) for code in range(0x202A, 0x202F)]
    + [chr(code) for code in range(0x2066, 0x206A)])


class NotAMessage(ValueError):
    """A body that is not a message. `error` is one of `REFUSALS`."""

    def __init__(self, error: str):
        if error not in REFUSALS:
            raise ValueError(f"{error!r} is not a class a message is refused with")
        super().__init__(error)
        self.error = error


@dataclasses.dataclass(frozen=True)
class Message:
    kind: str
    words: str
    screen: str
    instance_version: str

    def as_body(self) -> dict:
        """The five fields, in the order of `FIELDS`."""
        return {"version": BODY_VERSION, "kind": self.kind, "words": self.words,
                "screen": self.screen, "instance_version": self.instance_version}


def clean(words: str) -> str:
    """The words without what must not be kept. A newline typed on Windows
    arrives as two characters and becomes one."""
    kept = []
    for character in words.replace("\r\n", "\n"):
        if character == "\n":
            kept.append(character)
        elif unicodedata.category(character) == "Cc" or character in DIRECTION_MARKS:
            continue
        else:
            kept.append(character)
    return "".join(kept)


def parse(payload, *, closed_list: bool) -> Message:
    """The message in a parsed body, or `NotAMessage` with the class.

    `closed_list` is True on an instance, where the screen must be one of
    `SCREENS`, and False on our box, where a word of the right shape is
    enough. The module's docstring says why.
    """
    if not isinstance(payload, dict) or set(payload) != set(FIELDS):
        raise NotAMessage("malformed_request")
    version = payload["version"]
    # bool is an int in Python, and True is not a version.
    if not isinstance(version, int) or isinstance(version, bool):
        raise NotAMessage("malformed_request")
    if version != BODY_VERSION:
        raise NotAMessage("unsupported_version")
    kind, words = payload["kind"], payload["words"]
    screen, instance_version = payload["screen"], payload["instance_version"]
    if kind not in KINDS:
        raise NotAMessage("malformed_request")
    if not isinstance(words, str):
        raise NotAMessage("malformed_request")
    words = clean(words)
    if not words.strip():
        raise NotAMessage("malformed_request")
    if len(words) > MAX_WORDS:
        raise NotAMessage("too_large")
    if not isinstance(screen, str):
        raise NotAMessage("malformed_request")
    if closed_list and screen not in SCREENS:
        raise NotAMessage("malformed_request")
    if not SCREEN_SHAPE.fullmatch(screen):
        raise NotAMessage("malformed_request")
    if not isinstance(instance_version, str):
        raise NotAMessage("malformed_request")
    if instance_version != VERSION_UNKNOWN \
            and not VERSION_SHAPE.fullmatch(instance_version):
        raise NotAMessage("malformed_request")
    return Message(kind=kind, words=words, screen=screen,
                   instance_version=instance_version)


SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback (
    id               INTEGER PRIMARY KEY,
    instance_id      INTEGER,
    workspace_id     INTEGER,
    kind             TEXT NOT NULL CHECK (kind IN ('feature', 'bug')),
    words            TEXT NOT NULL,
    screen           TEXT NOT NULL,
    instance_version TEXT NOT NULL,
    received_at      TEXT NOT NULL,
    done_at          TEXT,
    -- From an instance on our box, or from a workspace when written
    -- locally. Exactly one of the two.
    CHECK ((instance_id IS NULL) <> (workspace_id IS NULL))
);
CREATE INDEX IF NOT EXISTS feedback_instance_day ON feedback (instance_id, received_at);
CREATE INDEX IF NOT EXISTS feedback_workspace_day ON feedback (workspace_id, received_at);
"""


def init(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


def _stamp(now: datetime | None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()


def _sender(instance_id, workspace_id) -> tuple[str, int]:
    """The column that says who a row is from, and its value."""
    if (instance_id is None) == (workspace_id is None):
        raise ValueError("a message is from an instance or from a workspace,"
                         " exactly one of the two")
    if instance_id is not None:
        return "instance_id", instance_id
    return "workspace_id", workspace_id


def sent_in_the_last_day(con: sqlite3.Connection, *, instance_id: int | None = None,
                         workspace_id: int | None = None,
                         now: datetime | None = None) -> int:
    """How many messages this sender has stored in the last 24 hours. Done
    ones count: marking a message done does not buy another."""
    column, value = _sender(instance_id, workspace_id)
    moment = now or datetime.now(timezone.utc)
    since = _stamp(moment - A_DAY)
    return con.execute(
        f"SELECT COUNT(*) FROM feedback WHERE {column} = ? AND received_at > ?",
        (value, since)).fetchone()[0]


def store(con: sqlite3.Connection, message: Message, *,
          instance_id: int | None = None, workspace_id: int | None = None,
          now: datetime | None = None) -> int:
    """Keep one message and return its row's id. The caller has asked
    `sent_in_the_last_day` first."""
    column, value = _sender(instance_id, workspace_id)
    cursor = con.execute(
        f"INSERT INTO feedback ({column}, kind, words, screen,"
        " instance_version, received_at) VALUES (?, ?, ?, ?, ?, ?)",
        (value, message.kind, message.words, message.screen,
         message.instance_version, _stamp(now)))
    con.commit()
    return cursor.lastrowid


# ------------------------------------------------------------ his console

def listing(con: sqlite3.Connection, *, done: bool) -> list:
    """The open messages or the done ones, newest first, as plain dicts with
    the table's own column names."""
    which = "IS NOT NULL" if done else "IS NULL"
    cursor = con.execute(
        "SELECT id, instance_id, workspace_id, kind, words, screen,"
        " instance_version, received_at, done_at FROM feedback"
        f" WHERE done_at {which} ORDER BY received_at DESC, id DESC")
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def count_open(con: sqlite3.Connection) -> int:
    return con.execute(
        "SELECT COUNT(*) FROM feedback WHERE done_at IS NULL").fetchone()[0]


def mark_done(con: sqlite3.Connection, row_id: int,
              now: datetime | None = None) -> bool:
    """Mark an open message done. False when there is no such open message,
    so a second Done does not move the time of the first."""
    cursor = con.execute(
        "UPDATE feedback SET done_at = ? WHERE id = ? AND done_at IS NULL",
        (_stamp(now), row_id))
    con.commit()
    return cursor.rowcount == 1


def delete(con: sqlite3.Connection, row_id: int) -> bool:
    """Delete one message, for the person who typed something they should
    not have (docs/record 4.436). The row is gone from this table. Whether
    there was one to delete is what comes back."""
    cursor = con.execute("DELETE FROM feedback WHERE id = ?", (row_id,))
    con.commit()
    return cursor.rowcount == 1
