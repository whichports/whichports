"""Which of two Debian package versions is the newer, the way dpkg decides it.

Written from the manual's own description, deb-version(7) of dpkg 1.21.22, read
on 2026-10-03, and from nothing else. A version is

    [epoch:]upstream-version[-debian-revision]

"Dpkg will break the version number apart at the last hyphen in the string (if
there is one) to determine the upstream-version and debian-revision." The
epoch is "a single (generally small) unsigned integer", and when it is omitted
"zero is assumed". Epochs are compared as numbers, then the upstream versions,
then the revisions, each of the last two by the sorting algorithm below.

This is what the CVE check stands on: a version that is older than the one a
fix arrived in is affected. So a version this module cannot read is refused,
never guessed at: `compare` raises and the caller names no finding.
"""

import re

# The characters each part may hold (deb-version(7)). The upstream version may
# hold a colon only when there is an epoch and a hyphen only when there is a
# revision, which the splitting below makes true by construction: the epoch
# is cut at the first colon and the revision at the last hyphen.
_EPOCH = re.compile(r"[0-9]+\Z")
_UPSTREAM = re.compile(r"[A-Za-z0-9.+~:-]+\Z")
_REVISION = re.compile(r"[A-Za-z0-9+.~]+\Z")


class VersionError(ValueError):
    """The text is not a Debian version this module will compare."""


def parse(version) -> tuple[int, str, str]:
    """(epoch, upstream version, revision), the revision empty when there is
    none. Raises VersionError for anything that is not a version."""
    if not isinstance(version, str) or not version or version != version.strip():
        raise VersionError(f"not a version: {version!r}")
    epoch, upstream = 0, version
    if ":" in version:
        head, upstream = version.split(":", 1)
        if not _EPOCH.match(head):
            raise VersionError(f"the epoch is not a number: {version!r}")
        epoch = int(head)
    revision = ""
    if "-" in upstream:
        upstream, revision = upstream.rsplit("-", 1)
        if not _REVISION.match(revision):
            raise VersionError(f"not a revision: {version!r}")
    if not upstream or not _UPSTREAM.match(upstream):
        raise VersionError(f"not an upstream version: {version!r}")
    return epoch, upstream, revision


def _order(char: str) -> int:
    """A character's place in the lexical step: "all the letters sort earlier
    than all the non-letters and ... a tilde sorts before anything, even the
    end of a part". The end of a part is 0, so a tilde is below it, letters
    sit above it in ASCII order, and every other character above the letters."""
    if char == "~":
        return -1
    if "A" <= char <= "Z" or "a" <= char <= "z":
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    """The sorting algorithm deb-version(7) gives for an upstream version and
    for a revision: "The strings are compared from left to right", first the
    longest run of non-digits on each side, lexically, then the longest run
    of digits, as numbers, "an empty string ... counts as zero", repeated
    "until a difference is found or both strings are exhausted"."""
    i = j = 0
    while i < len(a) or j < len(b):
        # the non-digit run, one character at a time, an exhausted run
        # counting as the end of the part
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            left = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            right = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if left != right:
                return -1 if left < right else 1
            if i < len(a) and not a[i].isdigit():
                i += 1
            if j < len(b) and not b[j].isdigit():
                j += 1
        # the digit run, as a number
        start_i, start_j = i, j
        while i < len(a) and a[i].isdigit():
            i += 1
        while j < len(b) and b[j].isdigit():
            j += 1
        left = int(a[start_i:i] or "0")
        right = int(b[start_j:j] or "0")
        if left != right:
            return -1 if left < right else 1
    return 0


def compare(a, b) -> int:
    """-1 when version a is older than b, 0 when dpkg holds them equal, 1 when
    a is newer. Raises VersionError when either is not a version."""
    ea, ua, ra = parse(a)
    eb, ub, rb = parse(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)
