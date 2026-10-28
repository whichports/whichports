"""The slim extract of a distribution's own security data: one small file per
release, holding only what the matcher reads.

**Why it exists.** The CVE check matches the version of an installed package
against the distribution's own security data, downloaded and never asked of
an API, so nothing about a server's packages goes to a third party
(`docs/RECORD.md` 4.274). The data as the vendors publish it is 9 to 46 MB
compressed and unpacks to 80 MB and more, and OSV's whole Ubuntu file is 772
MB, which was found too much (4.280). The decision of 2026-10-03 (4.285):
a slim file per release that our control plane builds from the vendors'
files, and each vendor's own file for an instance that will not ask us. Both
ways run this builder, which is why it reads the vendors' files and nothing
of ours.

**A row** is a source package, a CVE, the version that fixes it in that
release or nothing, and the vendor's own urgency or priority word.

**The switch.** `ONLY_FIXABLE` is the answer of the same day to whether
a CVE with no fix counts: only a CVE an update fixes. A fully updated openssh
on Debian 12 matched 20 records, none with a fixed version (4.280), and a
count nothing the operator does can change is not a finding. It is one
setting, used in one place, `select`, so the other answer is a change of that
line and not of this file.

**The two inputs, as measured on 2026-10-03.**

Debian: the security tracker's "All information in JSON format",
security-tracker.debian.org/tracker/data/json, last modified that day at
14:07 UTC. Source package, then id, then `releases`, then the release's
codename. In bookworm and trixie the status was `resolved` 109,155 times,
always with a `fixed_version`, `open` 18,680 times and `undetermined` 87
times, never with one. A `fixed_version` of "0" stood in 14,799 resolved
entries: the release never carried the affected code. Of the 94,356 others
one was not a version at all ("1:0.23.0+dfsg-"), and each of the 94,355 that
are was no newer than a version the release's own repositories carry, so a
row with a fixed version is a row an update fixes. 820 ids, across every
release, were TEMP- and not CVE-.

Ubuntu: Canonical's own OSV tarball,
security-metadata.canonical.com/osv/osv-all.tar.xz, last modified
2026-10-02 18:10 UTC, 61,216 records under osv/cve/. Canonical's
documentation ("Ubuntu OSV data", read the same day): "the introduced field
is always 0. Whenever the team patches a vulnerability, the source package
version is listed in fixed", a package that still needs evaluation or is
vulnerable is "Listed under affected and fixed is not set", and "we use the
withdrawn field to indicate that the CVE record has been removed". In the
file, every entry for Ubuntu 24.04 and 26.04 had exactly one range of type
ECOSYSTEM whose events were an introduced "0" alone, 417,178 times, or
followed by one fixed version, 141,603 times. 3,643 records were withdrawn.
60,631 named exactly one CVE under `upstream` and 585 named none, where the
record's own id carries it.

**Anything outside those shapes is left out and counted by its reason**,
never guessed at, and the counts go to whoever ran the build. A file this
code does not read whole is refused whole (`load`), because half an extract
read as all of it is a confident wrong answer.

Canonical's data is CC-BY-SA 4.0, which the page has to say the day this
ships (4.280).
"""

import collections
import dataclasses
import gzip
import io
import json
import lzma
import re
import tarfile

from . import debversion

FORMAT = 1
MAGIC = "whichports-cve-extract"

# Decided 2026-10-03, question 6 of the CVE card, answer (a): count only a
# CVE an update fixes (docs/RECORD.md 4.285).
ONLY_FIXABLE = True

# The releases an extract is built for, by the distribution's ID and
# VERSION_ID as os-release gives them and the agent reports them, and the
# name each vendor's file uses for that release.
DEBIAN_CODENAMES = {"12": "bookworm", "13": "trixie"}
UBUNTU_ECOSYSTEMS = {"24.04": "Ubuntu:24.04:LTS", "26.04": "Ubuntu:26.04:LTS"}

# The vendors' own words, closed lists, as they stood in the files measured.
DEBIAN_URGENCIES = ("unimportant", "low", "medium", "high", "not yet assigned", "end-of-life")
UBUNTU_PRIORITIES = ("negligible", "low", "medium", "high", "critical")

# Why an entry of a vendor's file is not a row. One closed list, in the
# order the builder checks them.
NOT_A_CVE = "not a CVE id"
WITHDRAWN = "withdrawn by the vendor"
NOT_AFFECTED = "release never affected"
UNDETERMINED = "undetermined by the vendor"
NOT_UNDERSTOOD = "shape not understood"
# A fixed version that only Ubuntu Pro's archives offer, told by Pro's own
# mark in it, `~esm1` or `+esm1`. For a server without Pro it is no update,
# so it counts as no fixed version. Canonical's data of 2026-10-02 holds
# such versions under the plain names of 16.04 and 18.04 and none under
# 24.04's. Pro's own data set has a name of its own, which is never read.
PRO_ONLY = "fixed only by Ubuntu Pro"
_PRO_MARK = re.compile(r"[~+]esm\d")
LEFT_OUT = (NOT_A_CVE, WITHDRAWN, NOT_AFFECTED, UNDETERMINED, NOT_UNDERSTOOD)
# Kept as a row, with the word left empty, and counted: a vendor's new word
# for an urgency is no reason to lose the CVE.
URGENCY_NOT_KNOWN = "urgency word not known"

# One record of Canonical's tarball. The largest on 2026-10-03 was 2.8 MB.
MAX_RECORD_BYTES = 16 << 20
# Every record of the tarball together, unpacked. On 2026-10-03 the 61,216
# records were 11.2 GB, from a download of 46 MB, so they are read one at a
# time and never kept or written out, and past this the file is refused.
MAX_TARBALL_BYTES = 48 << 30
# An extract unpacked. The largest built on 2026-10-03 was 19.7 MB, every
# row of Ubuntu 24.04.
MAX_EXTRACT_BYTES = 256 << 20

_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_UBUNTU_ID = re.compile(r"UBUNTU-(CVE-[0-9]{4}-[0-9]{4,})\Z")
# deb-control(5): a source package name is lowercase letters, digits, +, -
# and ., at least two characters, starting with a letter or digit.
_SOURCE = re.compile(r"[a-z0-9][a-z0-9+.-]+\Z")
_MODIFIED = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")


class ExtractError(ValueError):
    """An extract that is not read. The message says why."""


@dataclasses.dataclass(frozen=True, order=True)
class Row:
    """One CVE of one source package in one release. `fixed` is the version
    that fixes it there, or empty when the vendor names none. `urgency` is
    the vendor's own word, or empty."""
    source: str
    cve: str
    fixed: str
    urgency: str


@dataclasses.dataclass(frozen=True)
class Header:
    """What an extract says about itself. `source_modified` is when the
    vendor's file it was built from last changed, or empty when the builder
    was not told. `built` is when it was built from a download of that file
    that had just succeeded, or empty for an extract built from files on
    disk. The two are different facts: a vendor that publishes nothing over
    a weekend leaves the first on Friday while the second is this morning."""
    distribution: str
    version_id: str
    only_fixable: bool
    source_modified: str
    built: str = ""


def _row(source, cve, fixed, urgency, known_urgencies, left_out):
    """A row whose every field is what it should be, or None with the reason
    counted. Checked here once, for both vendors and for `load`."""
    if not isinstance(source, str) or not _SOURCE.match(source):
        left_out[NOT_UNDERSTOOD] += 1
        return None
    if not isinstance(fixed, str):
        left_out[NOT_UNDERSTOOD] += 1
        return None
    if fixed:
        try:
            debversion.parse(fixed)
        except debversion.VersionError:
            left_out[NOT_UNDERSTOOD] += 1
            return None
    if urgency not in known_urgencies:
        if urgency:
            left_out[URGENCY_NOT_KNOWN] += 1
        urgency = ""
    return Row(source, cve, fixed, urgency)


class _Rows:
    """Rows by source package and CVE. The same pair seen twice with two
    different answers is in neither vendor's file as measured, so it is left
    out both times rather than one of the two being picked."""

    def __init__(self, left_out):
        self._rows = {}
        self._conflicted = set()
        self._left_out = left_out

    def add(self, row):
        key = (row.source, row.cve)
        if key in self._conflicted:
            self._left_out[NOT_UNDERSTOOD] += 1
            return
        seen = self._rows.get(key)
        if seen is None:
            self._rows[key] = row
        elif seen != row:
            del self._rows[key]
            self._conflicted.add(key)
            self._left_out[NOT_UNDERSTOOD] += 2

    def sorted(self):
        return sorted(self._rows.values())


def debian_rows(tracker, codename: str) -> tuple[list[Row], dict[str, int]]:
    """The rows of one Debian release, from the security tracker's JSON as
    parsed, and how many entries were left out for each reason."""
    left_out = collections.Counter()
    rows = _Rows(left_out)
    if not isinstance(tracker, dict):
        raise ExtractError("the tracker's data is not an object of source packages")
    for source, issues in tracker.items():
        if not isinstance(issues, dict):
            left_out[NOT_UNDERSTOOD] += 1
            continue
        for ident, issue in issues.items():
            releases = issue.get("releases") if isinstance(issue, dict) else None
            if not isinstance(releases, dict):
                left_out[NOT_UNDERSTOOD] += 1
                continue
            entry = releases.get(codename)
            if entry is None:
                # The package is not in this release, or the issue is not.
                continue
            if not isinstance(ident, str) or not _CVE.match(ident):
                left_out[NOT_A_CVE] += 1
                continue
            row = _debian_row(source, ident, entry, left_out)
            if row is not None:
                rows.add(row)
    return rows.sorted(), dict(left_out)


def _debian_row(source, cve, entry, left_out):
    if not isinstance(entry, dict):
        left_out[NOT_UNDERSTOOD] += 1
        return None
    status = entry.get("status")
    fixed = entry.get("fixed_version")
    if status == "undetermined":
        left_out[UNDETERMINED] += 1
        return None
    if status == "open" and fixed is None:
        fixed = ""
    elif status == "resolved" and fixed == "0":
        left_out[NOT_AFFECTED] += 1
        return None
    elif status == "resolved" and isinstance(fixed, str) and fixed:
        pass
    else:
        left_out[NOT_UNDERSTOOD] += 1
        return None
    return _row(source, cve, fixed, entry.get("urgency", ""), DEBIAN_URGENCIES, left_out)


def ubuntu_rows(records, ecosystem: str) -> tuple[list[Row], dict[str, int]]:
    """The rows of one Ubuntu release, from Canonical's OSV records as parsed,
    and how many were left out for each reason. `records` may hold None for a
    record that could not be read (`ubuntu_records`)."""
    return ubuntu_rows_for(records, [ecosystem])[ecosystem]


def ubuntu_rows_for(records, ecosystems) -> dict[str, tuple[list[Row], dict[str, int]]]:
    """The rows of several Ubuntu releases in one pass over the records, by
    ecosystem name. One pass, because the records are 11 GB unpacked and are
    read one at a time: nothing here keeps a record once its rows are taken.
    A record that is left out whole is counted once for every release."""
    ecosystems = list(ecosystems)
    left_out = {name: collections.Counter() for name in ecosystems}
    rows = {name: _Rows(left_out[name]) for name in ecosystems}

    def every(reason):
        for name in ecosystems:
            left_out[name][reason] += 1

    for record in records:
        if not isinstance(record, dict) or not isinstance(record.get("affected"), list):
            every(NOT_UNDERSTOOD)
            continue
        if "withdrawn" in record:
            every(WITHDRAWN)
            continue
        cve = _ubuntu_cve(record)
        if cve is None:
            every(NOT_A_CVE)
            continue
        priority = _ubuntu_priority(record)
        for affected in record["affected"]:
            package = affected.get("package") if isinstance(affected, dict) else None
            if not isinstance(package, dict):
                every(NOT_UNDERSTOOD)
                continue
            name = package.get("ecosystem")
            if name not in rows:
                continue
            fixed = _ubuntu_fixed(affected.get("ranges"))
            if fixed is None:
                left_out[name][NOT_UNDERSTOOD] += 1
                continue
            if _PRO_MARK.search(fixed):
                left_out[name][PRO_ONLY] += 1
                fixed = ""
            row = _row(package.get("name"), cve, fixed, priority, UBUNTU_PRIORITIES,
                       left_out[name])
            if row is not None:
                rows[name].add(row)
    return {name: (rows[name].sorted(), dict(left_out[name])) for name in ecosystems}


def _ubuntu_cve(record):
    """The one CVE a record is about: the only CVE id under `upstream`, or
    the one in the record's own id when `upstream` names none."""
    upstream = record.get("upstream", [])
    if not isinstance(upstream, list):
        return None
    named = [u for u in upstream if isinstance(u, str) and _CVE.match(u)]
    if len(named) == 1:
        return named[0]
    if named:
        return None
    own = _UBUNTU_ID.match(record.get("id", "")) if isinstance(record.get("id"), str) else None
    return own.group(1) if own else None


def _ubuntu_priority(record):
    """Canonical's own priority word, which the record carries as a severity
    of type Ubuntu, or empty when it carries none."""
    severity = record.get("severity", [])
    if not isinstance(severity, list):
        return ""
    words = [s.get("score") for s in severity
             if isinstance(s, dict) and s.get("type") == "Ubuntu"]
    return words[0] if len(words) == 1 and isinstance(words[0], str) else ""


def _ubuntu_fixed(ranges):
    """The fixed version of one affected entry, empty when it names none, or
    None when the entry is not one of the two shapes Canonical documents:
    one ECOSYSTEM range whose events are an introduced "0", alone or followed
    by one fixed version."""
    if not isinstance(ranges, list) or len(ranges) != 1 or not isinstance(ranges[0], dict):
        return None
    if ranges[0].get("type") != "ECOSYSTEM":
        return None
    events = ranges[0].get("events")
    if events == [{"introduced": "0"}]:
        return ""
    if (isinstance(events, list) and len(events) == 2 and events[0] == {"introduced": "0"}
            and isinstance(events[1], dict) and list(events[1]) == ["fixed"]
            and isinstance(events[1]["fixed"], str) and events[1]["fixed"]):
        return events[1]["fixed"]
    return None


def ubuntu_records(path):
    """Every CVE record of Canonical's tarball, parsed, one at a time. None
    in place of a record that is too large or is not JSON, so `ubuntu_rows`
    counts it. Nothing is unpacked to disk: each member is read in memory and
    only regular files under osv/cve/ are looked at. `path` is a file's name
    or an open file. A file that is no tarball, or is cut, or whose records
    are larger in all than MAX_TARBALL_BYTES, is refused where that is met."""
    opened = {"name": path} if isinstance(path, (str, bytes)) or hasattr(path, "__fspath__") \
        else {"fileobj": path}
    read = 0
    try:
        with tarfile.open(mode="r:*", **opened) as archive:
            for member in archive:
                if not member.isfile():
                    continue
                if not member.name.startswith("osv/cve/") or not member.name.endswith(".json"):
                    continue
                if member.size > MAX_RECORD_BYTES:
                    yield None
                    continue
                read += member.size
                if read > MAX_TARBALL_BYTES:
                    raise ExtractError("the tarball's records are larger than a tarball's are")
                try:
                    yield json.loads(archive.extractfile(member).read())
                except ValueError:
                    yield None
    except (tarfile.TarError, lzma.LZMAError, EOFError) as exc:
        # The class and never the message: what a damaged file says about
        # itself is not ours to pass on.
        raise ExtractError(f"not a tarball that can be read: {type(exc).__name__}") from None


def select(rows, only_fixable: bool = ONLY_FIXABLE) -> list[Row]:
    """The rows an extract holds. This is the switch: with `only_fixable`
    only the rows an update fixes, without it every row."""
    if only_fixable:
        return [row for row in rows if row.fixed]
    return list(rows)


def dump(rows, distribution: str, version_id: str, only_fixable: bool = ONLY_FIXABLE,
         source_modified: str = "", built: str = "") -> bytes:
    """One release's extract as bytes: a header line, then one line per row,
    tab separated and sorted, gzipped. The same rows and the same two times
    always give the same bytes. The header's last field is when it was
    built, and is left off when the builder does not say."""
    if distribution == "debian" and version_id in DEBIAN_CODENAMES:
        urgencies = DEBIAN_URGENCIES
    elif distribution == "ubuntu" and version_id in UBUNTU_ECOSYSTEMS:
        urgencies = UBUNTU_PRIORITIES
    else:
        raise ExtractError(f"no extract is built for {distribution!r} {version_id!r}")
    if source_modified and not _MODIFIED.match(source_modified):
        raise ExtractError("source_modified is not a time like 2026-10-03T14:07:28Z")
    if built and not _MODIFIED.match(built):
        raise ExtractError("built is not a time like 2026-10-03T14:07:28Z")
    kept = select(rows, only_fixable)
    refused = collections.Counter()
    for row in kept:
        if (not _CVE.match(row.cve)
                or _row(row.source, row.cve, row.fixed, row.urgency, urgencies, refused) != row):
            raise ExtractError(f"not a row of {distribution} {version_id}: {row!r}")
    head = "\t".join((MAGIC, str(FORMAT), distribution, version_id,
                      "fixable" if only_fixable else "all", source_modified) + ((built,) if built else ()))
    lines = [head] + ["\t".join(dataclasses.astuple(row)) for row in sorted(set(kept))]
    return gzip.compress(("\n".join(lines) + "\n").encode("ascii"), 9, mtime=0)


def load(data: bytes) -> tuple[Header, list[Row]]:
    """An extract's header and rows, or a refusal. Every line is checked the
    way the builder checked it, and one line that is not a row refuses the
    whole file."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as unpacked:
            raw = unpacked.read(MAX_EXTRACT_BYTES + 1)
    except (OSError, EOFError) as exc:
        raise ExtractError(f"not a gzip file: {exc}") from None
    if len(raw) > MAX_EXTRACT_BYTES:
        raise ExtractError("larger than an extract is")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise ExtractError("not ASCII") from None
    if not text.endswith("\n"):
        raise ExtractError("the last line is cut")
    lines = text[:-1].split("\n")
    head = lines[0].split("\t")
    if len(head) not in (6, 7) or head[0] != MAGIC:
        raise ExtractError("not an extract")
    if head[1] != str(FORMAT):
        raise ExtractError(f"format {head[1]} is not read, this reads {FORMAT}")
    distribution, version_id, kind, source_modified = head[2:6]
    built = head[6] if len(head) == 7 else ""
    if len(head) == 7 and not _MODIFIED.match(built):
        raise ExtractError("the time it was built is not a time")
    if distribution == "debian" and version_id in DEBIAN_CODENAMES:
        urgencies = DEBIAN_URGENCIES
    elif distribution == "ubuntu" and version_id in UBUNTU_ECOSYSTEMS:
        urgencies = UBUNTU_PRIORITIES
    else:
        raise ExtractError(f"an extract for {distribution!r} {version_id!r} is not read")
    if kind not in ("fixable", "all"):
        raise ExtractError("neither fixable nor all")
    if source_modified and not _MODIFIED.match(source_modified):
        raise ExtractError("the time of the vendor's file is not a time")
    rows = []
    refused = collections.Counter()
    for number, line in enumerate(lines[1:], start=2):
        fields = line.split("\t")
        row = None
        if len(fields) == 4 and _CVE.match(fields[1]):
            row = _row(fields[0], fields[1], fields[2], fields[3], urgencies, refused)
        if row is None or refused or (kind == "fixable" and not row.fixed):
            raise ExtractError(f"line {number} is not a row of this extract")
        rows.append(row)
    if rows != sorted(set(rows)):
        raise ExtractError("the rows are not sorted, or one stands twice")
    return Header(distribution, version_id, kind == "fixable", source_modified, built), rows
