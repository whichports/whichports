"""Whether a distribution's own security data says an installed version is
affected, read from records in the OSV format.

OSV publishes each distribution's own data, keyed on the source package and
the release: Debian's as ecosystem "Debian:12", Canonical's as
"Ubuntu:24.04:LTS" and, for a release without long-term support,
"Ubuntu:25.10" (read off OSV's records on 2026-10-03). The decision to use it,
downloaded per release, is Jerome's of 2026-10-03 (`docs/RECORD.md` 4.274).

The evaluation is the OSV schema's own, `IsVulnerable` in its "Evaluation"
section (schema 1.9.1, read 2026-10-03), with ECOSYSTEM ranges compared by
`debversion`. Three answers, never two: affected, not affected, and cannot be
evaluated, for a record whose versions this code does not read or whose range
type it does not evaluate. The third names no finding and is counted, so a
record that is never evaluated is visible rather than read as not affected.
"""

import re

from . import debversion

AFFECTED = "affected"
NOT_AFFECTED = "not affected"
UNREADABLE = "cannot be evaluated"

_CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")
_DEBIAN_RELEASE = re.compile(r"[0-9]+\Z")
_UBUNTU_RELEASE = re.compile(r"[0-9]{2}\.[0-9]{2}\Z")


def ecosystems(distribution) -> tuple[str, ...]:
    """The OSV ecosystems a host's distribution may be published under, from
    the os-release ID and VERSION_ID the agent sends. Empty when there is none
    to look in: another distribution, or Debian testing and unstable, which
    carry no VERSION_ID.

    An Ubuntu release is looked for under both names, with and without
    ":LTS", because os-release's VERSION_ID does not say which it is and the
    data carries only one of the two."""
    if not isinstance(distribution, dict):
        return ()
    ident, release = distribution.get("id"), distribution.get("version_id")
    if not isinstance(release, str):
        return ()
    if ident == "debian" and _DEBIAN_RELEASE.match(release):
        return (f"Debian:{release}",)
    if ident == "ubuntu" and _UBUNTU_RELEASE.match(release):
        return (f"Ubuntu:{release}:LTS", f"Ubuntu:{release}")
    return ()


def evaluate(record, ecosystem_names, source: str, version: str) -> str:
    """One record against one source package at one version, in the given
    ecosystems. AFFECTED, NOT_AFFECTED or UNREADABLE."""
    if not isinstance(record, dict) or record.get("withdrawn"):
        return NOT_AFFECTED
    readable_miss = True
    for affected in record.get("affected") or ():
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        if not isinstance(package, dict):
            continue
        if package.get("ecosystem") not in ecosystem_names or package.get("name") != source:
            continue
        versions = affected.get("versions") or ()
        if isinstance(versions, list) and version in versions:
            return AFFECTED
        answer = _in_ranges(version, affected.get("ranges") or ())
        if answer == AFFECTED:
            return AFFECTED
        if answer == UNREADABLE:
            readable_miss = False
    return NOT_AFFECTED if readable_miss else UNREADABLE


def _in_ranges(version: str, ranges) -> str:
    """IncludedInRanges, for ECOSYSTEM ranges. A range of another type, or one
    whose versions do not read, makes the answer UNREADABLE unless another
    range says AFFECTED."""
    unreadable = False
    for rng in ranges if isinstance(ranges, list) else ():
        if not isinstance(rng, dict) or rng.get("type") != "ECOSYSTEM":
            unreadable = True
            continue
        try:
            if _range_affects(version, rng.get("events") or []):
                return AFFECTED
        except (debversion.VersionError, TypeError, ValueError):
            unreadable = True
    return UNREADABLE if unreadable else NOT_AFFECTED


def _range_affects(version: str, events: list) -> bool:
    """BeforeLimits, then the walk over the events in version order. "0" as
    introduced sorts before every version, and a limit containing "*" is
    infinity (the schema's special values)."""
    parsed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise ValueError("an event holds exactly one of the four kinds")
        (kind, value), = event.items()
        if kind not in ("introduced", "fixed", "last_affected", "limit") or not isinstance(value, str):
            raise ValueError(f"not an event: {event!r}")
        parsed.append((kind, value))
    limits = [value for kind, value in parsed if kind == "limit"]
    if limits and not any("*" in value or debversion.compare(version, value) < 0 for value in limits):
        return False
    walk = [(kind, value) for kind, value in parsed if kind != "limit"]
    walk.sort(key=_EventOrder)
    vulnerable = False
    for kind, value in walk:
        if kind == "introduced" and (value == "0" or debversion.compare(version, value) >= 0):
            vulnerable = True
        elif kind == "fixed" and debversion.compare(version, value) >= 0:
            vulnerable = False
        elif kind == "last_affected" and debversion.compare(version, value) > 0:
            vulnerable = False
    return vulnerable


class _EventOrder:
    """Sorts events by their version, "0" first, keeping the record's order
    between events at one version (Python's sort is stable)."""

    def __init__(self, event):
        self.value = event[1]

    def __lt__(self, other):
        if self.value == other.value:
            return False
        if self.value == "0":
            return True
        if other.value == "0":
            return False
        return debversion.compare(self.value, other.value) < 0


def cve_ids(record) -> tuple[str, ...]:
    """The CVE identifiers a record is about, sorted: its own id when it is a
    distribution's copy of one, "DEBIAN-CVE-2025-26465" or
    "UBUNTU-CVE-2024-6387", and every CVE among its aliases and upstream ids.
    A Debian security advisory, "DSA-5868-1", names its CVEs in upstream."""
    found = set()
    if not isinstance(record, dict):
        return ()
    ident = record.get("id")
    if isinstance(ident, str):
        for prefix in ("DEBIAN-", "UBUNTU-"):
            if ident.startswith(prefix) and _CVE.match(ident[len(prefix):]):
                found.add(ident[len(prefix):])
    for key in ("aliases", "upstream"):
        for other in record.get(key) or ():
            if isinstance(other, str) and _CVE.match(other):
                found.add(other)
    return tuple(sorted(found))
