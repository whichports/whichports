"""The vantage registry: every machine the outside view is taken from, as rows.

    python -m app.vantages_cli list
    python -m app.vantages_cli add --name probe1 --via root@78.141.210.130 \
        --address 78.141.210.130 --address 2a05:f480:1400:2015:5400:6ff:fe94:df5

`docs/PRODUCT.md` section 3a point 2 calls two vantage points on different
providers in different countries the thing that makes "we are being blocked"
distinguishable from "the port closed". Until 2026-09-08 the product had one
vantage and nothing in the code iterated a list: the timers passed one
`--vantage` and one `--via` read from `/etc/whichports/prober.env`. This is
the list.

## What a row holds, and the one thing it never holds

A row is a name, the ssh destination the control plane reaches the box at,
whether it is enabled, and the addresses the box probes from. **No row holds a
credential.** The ssh key stays in `~/.ssh` on the control plane and is found
by plain `ssh` through `~/.ssh/config`, exactly as `ops/RUNBOOK.md` describes
for probe1, so the registry can be read by the sweep, the metrics endpoint and
the admin numbers without any of them touching a secret. A destination is
`user@host` and is validated to be nothing else.

## Why a table and not a file

Three things have to read the list and none of them reads a configuration
file: the dead-man sweep, which has to watch every vantage, `/metrics`, which
has to say when each one last ran, and the admin numbers behind the Admin
screen. All three already read the database. A file would be a fourth place
that every one of those has to be taught to find, on a box where the units run
under different environments, which is the exact shape `app/cli.py`'s docstring
records going wrong. The environment file stays for nothing: once the registry
carries probe1 the units need no vantage from their environment at all.

## Why the addresses are here

Two rules need them and both are about our own network. **A vantage never
probes its own address**, measured on 2026-08-18 (`docs/RECORD.md` 4.62): a
box connecting to its own public address does not traverse its firewall the
way the internet does, and reported `connect_refused` on ports the internet
sees time out. `app/probe_runner.py` refuses that on the box itself, reading
its own interfaces. And **a vantage never probes another vantage's address**
either, because measuring probe2 from probe1 is measuring ourselves and
storing it as a finding about a customer. The runner cannot know the other
box's address, so the control plane has to, and this is where.

The addresses are also what `site/probers.py` publishes. The two lists live in
two programs on purpose (the site is built, the control plane runs) and the
ordering rule in `ops/RUNBOOK.md` is what keeps them in step: an address goes
on the published list before it goes in here, and nothing probes from an
address absent from that list.

## What is refused at the door

A name is the same shape `prober_cli.chosen_vantage` has always required,
because it is stored with every result and printed on the published list. A
destination that starts with a dash is refused because `ssh` would read it as
an option (`dispatch.SshTransport` puts the destination before `--`, and the
dash is the only way a stored string could become a flag). An address that is
not globally routable is refused through `authz.normalise_target`, the same
door every probe target goes through, so a vantage address is spelled the way
a target is and the two can be compared. An address held by one vantage cannot
be given to another. A vantage with no address cannot be added, because a
vantage whose address is unknown is a vantage whose own address cannot be kept
out of its targets.
"""

import dataclasses
import re
import sqlite3
from datetime import datetime, timezone

from . import authz

# The same shape a vantage name has had since docs/PRODUCT.md 5e: lowercase
# letters, digits, dot, dash and underscore, at most 64 characters. It is
# stored with every result, printed, and appears on the published list of
# addresses we probe from, so it is restricted here rather than escaped in
# three places later.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# An ssh destination, `user@host`. The host may be a name, a v4 address or a
# bracketed v6 address. No whitespace and no leading dash, because the string
# becomes one element of an argv array and a dash would make it an option.
DESTINATION_RE = re.compile(r"^(?!-)[A-Za-z0-9._@:\[\]-]{1,253}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS vantages (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    destination TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    added_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vantage_addresses (
    id         INTEGER PRIMARY KEY,
    vantage_id INTEGER NOT NULL REFERENCES vantages(id),
    address    TEXT NOT NULL UNIQUE,
    family     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vantage_addresses_vantage
    ON vantage_addresses(vantage_id);
"""


class VantageError(ValueError):
    """The registry refused to write what it was asked. The message is for a
    person at a terminal and names what to fix."""


def init(con: sqlite3.Connection) -> None:
    """Idempotent, the same additive rule db.init, authz.init and prober.init
    follow. Nothing here references hosts, so it can run in any order."""
    con.executescript(SCHEMA)
    con.commit()


def table_exists(con: sqlite3.Connection) -> bool:
    """Whether the registry has ever been created. Readers that open the
    database read-only, the metrics and the admin numbers, ask this first so
    a database from before the registry existed reads as no vantages rather
    than as a failed page."""
    row = con.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vantages'"
    ).fetchone()
    return row is not None


@dataclasses.dataclass(frozen=True)
class Vantage:
    id: int
    name: str
    destination: str
    enabled: bool
    added_at: str
    addresses: tuple[str, ...]


# ------------------------------------------------------------------- checks

def check_name(name) -> str:
    if not isinstance(name, str) or not NAME_RE.fullmatch(name.strip()):
        raise VantageError(
            "a vantage name is lowercase letters, digits, dot, dash and"
            " underscore, starting with a letter or digit, at most 64"
            f" characters. {name!r} is not")
    return name.strip()


def check_destination(destination) -> str:
    if not isinstance(destination, str) or not DESTINATION_RE.fullmatch(
            destination.strip()):
        raise VantageError(
            "an ssh destination is user@host with no spaces and no leading"
            f" dash. {destination!r} is not")
    return destination.strip()


def check_addresses(addresses) -> list[tuple[str, str]]:
    """Every address canonical and globally routable, deduplicated, as
    (address, family) pairs. Raises for an empty list, because a vantage
    with no known address cannot be kept out of its own targets."""
    if isinstance(addresses, (str, bytes)):
        raise VantageError("addresses must be a list, not one string")
    found: list[tuple[str, str]] = []
    for address in addresses:
        try:
            target, family = authz.normalise_target(address)
        except authz.TargetError as exc:
            raise VantageError(f"not a vantage address: {exc}") from None
        if (target, family) not in found:
            found.append((target, family))
    if not found:
        raise VantageError("a vantage needs at least one address, the one its"
                           " probes leave from")
    return found


# ------------------------------------------------------------------ writing

def _now(now: datetime | None) -> str:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat()


def add(con: sqlite3.Connection, name: str, destination: str, addresses,
        now: datetime | None = None) -> Vantage:
    """One vantage, enabled, with its addresses. Every check runs before the
    first write, so a refused add leaves nothing behind."""
    name = check_name(name)
    destination = check_destination(destination)
    pairs = check_addresses(addresses)
    if by_name(con, name) is not None:
        raise VantageError(f"a vantage called {name!r} already exists")
    _refuse_addresses_held_elsewhere(con, pairs, vantage_id=None)
    cur = con.execute(
        "INSERT INTO vantages (name, destination, enabled, added_at)"
        " VALUES (?, ?, 1, ?)", (name, destination, _now(now)))
    vantage_id = cur.lastrowid
    con.executemany(
        "INSERT INTO vantage_addresses (vantage_id, address, family)"
        " VALUES (?, ?, ?)",
        [(vantage_id, address, family) for address, family in pairs])
    con.commit()
    return by_name(con, name)


def _refuse_addresses_held_elsewhere(con, pairs, vantage_id) -> None:
    for address, _family in pairs:
        row = con.execute(
            "SELECT v.name FROM vantage_addresses a JOIN vantages v"
            " ON v.id = a.vantage_id WHERE a.address = ?", (address,)).fetchone()
        if row is not None and (vantage_id is None
                                or _id_of(con, row["name"]) != vantage_id):
            raise VantageError(
                f"{address} is already the address of vantage {row['name']!r}")


def _id_of(con, name) -> int | None:
    row = con.execute("SELECT id FROM vantages WHERE name = ?", (name,)).fetchone()
    return None if row is None else row["id"]


def _require(con, name: str) -> int:
    vantage_id = _id_of(con, check_name(name))
    if vantage_id is None:
        raise VantageError(f"no vantage called {name!r}")
    return vantage_id


def remove(con: sqlite3.Connection, name: str) -> None:
    """Take a vantage out of the registry, addresses and all. Its stored runs
    stay, because they are measurements that were taken and the vantage name
    on each of them still says where."""
    vantage_id = _require(con, name)
    con.execute("DELETE FROM vantage_addresses WHERE vantage_id = ?", (vantage_id,))
    con.execute("DELETE FROM vantages WHERE id = ?", (vantage_id,))
    con.commit()


def set_enabled(con: sqlite3.Connection, name: str, enabled: bool) -> None:
    """A disabled vantage is not driven and its addresses stay excluded from
    every target list, because a box we are not using is still our box."""
    vantage_id = _require(con, name)
    con.execute("UPDATE vantages SET enabled = ? WHERE id = ?",
                (1 if enabled else 0, vantage_id))
    con.commit()


def set_destination(con: sqlite3.Connection, name: str, destination: str) -> None:
    vantage_id = _require(con, name)
    con.execute("UPDATE vantages SET destination = ? WHERE id = ?",
                (check_destination(destination), vantage_id))
    con.commit()


def set_addresses(con: sqlite3.Connection, name: str, addresses) -> None:
    """Replace a vantage's addresses, which is what a rebuild needs when the
    provider hands the box a new one."""
    vantage_id = _require(con, name)
    pairs = check_addresses(addresses)
    _refuse_addresses_held_elsewhere(con, pairs, vantage_id)
    con.execute("DELETE FROM vantage_addresses WHERE vantage_id = ?", (vantage_id,))
    con.executemany(
        "INSERT INTO vantage_addresses (vantage_id, address, family)"
        " VALUES (?, ?, ?)",
        [(vantage_id, address, family) for address, family in pairs])
    con.commit()


def sync_from_api(con: sqlite3.Connection, listed) -> list[str]:
    """Make this registry exactly the vantages our prober API lists. For a
    self-hosted instance, which drives no box of its own and asks for our
    vantages by name (`dispatch.ApiTransport`). Returns a sentence per change.

    **The destination of each row is the vantage's own name**, because that is
    what the API is asked for, where on our control plane it is `user@host`.
    Every address is kept, including a switched-off vantage's, because a
    vantage never probes itself or another vantage and the instance's passes
    take every address here out of their targets. A row the API no longer
    lists is removed: asking for it would only be refused.

    Every entry is checked before the first write, so a listing with one bad
    entry changes nothing.
    """
    if not isinstance(listed, list):
        raise VantageError("the prober API's listing is not a list")
    wanted = {}
    for entry in listed:
        if not isinstance(entry, dict):
            raise VantageError("an entry in the prober API's listing is not an object")
        name = check_name(entry.get("name"))
        pairs = check_addresses(entry.get("addresses") or [])
        enabled = entry.get("enabled")
        if not isinstance(enabled, bool):
            raise VantageError(f"the prober API does not say whether {name} is on")
        if name in wanted:
            raise VantageError(f"the prober API lists {name} twice")
        wanted[name] = ([address for address, _family in pairs], enabled)
    owners = {}
    for name, (addresses, _enabled) in wanted.items():
        for address in addresses:
            if address in owners:
                raise VantageError(
                    f"the prober API gives {address} to {owners[address]} and {name}")
            owners[address] = name

    # One transaction, so there is no moment where a vantage is in the
    # registry without its addresses: a vantage whose address is unknown is a
    # vantage whose address cannot be kept out of every target list.
    before = {v.name: v for v in list_all(con)}
    changes = []
    stamp = _now(None)
    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute("DELETE FROM vantage_addresses")
        for name in sorted(set(before) - set(wanted)):
            con.execute("DELETE FROM vantages WHERE name = ?", (name,))
            changes.append(f"removed {name}, the prober API no longer lists it")
        for name, (addresses, enabled) in sorted(wanted.items()):
            old = before.get(name)
            if old is None:
                cur = con.execute(
                    "INSERT INTO vantages (name, destination, enabled, added_at)"
                    " VALUES (?, ?, ?, ?)", (name, name, int(enabled), stamp))
                vantage_id = cur.lastrowid
                changes.append(f"added {name}, {'on' if enabled else 'off'}")
            else:
                vantage_id = old.id
                con.execute("UPDATE vantages SET destination = ?, enabled = ?"
                            " WHERE id = ?", (name, int(enabled), vantage_id))
                if old.enabled != enabled:
                    changes.append(f"{name} is {'on' if enabled else 'off'}")
                if sorted(old.addresses) != sorted(addresses):
                    changes.append(f"{name} has new addresses")
            con.executemany(
                "INSERT INTO vantage_addresses (vantage_id, address, family)"
                " VALUES (?, ?, ?)",
                [(vantage_id, address, authz.normalise_target(address)[1])
                 for address in addresses])
    except BaseException:
        con.rollback()
        raise
    con.commit()
    return changes


# ------------------------------------------------------------------ reading

def _vantage(con, row) -> Vantage:
    addresses = tuple(
        r["address"] for r in con.execute(
            "SELECT address FROM vantage_addresses WHERE vantage_id = ?"
            " ORDER BY family, address", (row["id"],)))
    return Vantage(id=row["id"], name=row["name"], destination=row["destination"],
                   enabled=bool(row["enabled"]), added_at=row["added_at"],
                   addresses=addresses)


def by_name(con: sqlite3.Connection, name: str) -> Vantage | None:
    row = con.execute("SELECT * FROM vantages WHERE name = ?", (name,)).fetchone()
    return None if row is None else _vantage(con, row)


def list_all(con: sqlite3.Connection) -> list[Vantage]:
    """Every vantage, enabled or not, by name. By name rather than by id so
    two passes drive the list in the same order and a stored run's
    neighbours are predictable."""
    return [_vantage(con, row) for row in
            con.execute("SELECT * FROM vantages ORDER BY name")]


def enabled(con: sqlite3.Connection) -> list[Vantage]:
    """The vantages a pass drives, by name."""
    return [v for v in list_all(con) if v.enabled]


def all_addresses(con: sqlite3.Connection) -> frozenset[str]:
    """Every address of every vantage, enabled or not, canonical.

    This is the set no pass may probe. It includes disabled vantages on
    purpose: a box that is switched off in the registry is still our box,
    and measuring it would still be measuring ourselves.
    """
    return frozenset(r["address"] for r in
                     con.execute("SELECT address FROM vantage_addresses"))
