"""Which CVEs of a release's extract an installed package is open to.

The extract (`app/cveextract.py`) is a distribution's own security data cut
to what this reads: for a source package, a CVE and the version that fixes it
in that release, or no version. An installed version older than the fixed
one is open to the CVE. Older means older by Debian's version ordering
(`app/debversion.py`), which both Debian and Ubuntu use.

A row with no fixed version is in an extract only when it was built with the
switch the other way (`cveextract.ONLY_FIXABLE`), and then it matches every
version: the vendor says the package is affected and names no fix.

**The package and the version compared are the source package's.** Both
vendors' data is keyed on it, and `app/packagerule.py` hands it over as
`Named.source` and `Named.source_version`.

Three answers, never two, as `app/osvmatch.py` gives them: the CVEs, none,
and cannot be evaluated, which is an installed version that is no version
and is raised rather than read as "nothing found".
"""

import dataclasses

from . import cveextract, debversion


@dataclasses.dataclass(frozen=True, order=True)
class Match:
    """One CVE an installed package is open to. `fixed` is the version an
    update brings, or empty when the vendor names none."""
    cve: str
    fixed: str
    urgency: str


def release_of(distribution) -> tuple[str, str] | None:
    """The release an extract is built for, from the os-release ID and
    VERSION_ID the agent sends, or None when there is no extract for it:
    another distribution, another release, or fields that are not text."""
    if not isinstance(distribution, dict):
        return None
    ident, version_id = distribution.get("id"), distribution.get("version_id")
    if ident == "debian" and version_id in cveextract.DEBIAN_CODENAMES:
        return ident, version_id
    if ident == "ubuntu" and version_id in cveextract.UBUNTU_ECOSYSTEMS:
        return ident, version_id
    return None


def by_source(rows) -> dict[str, tuple[cveextract.Row, ...]]:
    """An extract's rows under their source package, so one package's CVEs
    are one lookup."""
    out: dict[str, list] = {}
    for row in rows:
        out.setdefault(row.source, []).append(row)
    return {source: tuple(found) for source, found in out.items()}


def open_cves(indexed, source: str, source_version: str) -> list[Match]:
    """The CVEs of `by_source(rows)` that this version of this source package
    is open to, sorted. Raises `debversion.VersionError` when the installed
    version is not a version, so that is never read as no CVE."""
    debversion.parse(source_version)
    found = []
    for row in indexed.get(source, ()):
        if not row.fixed or debversion.compare(source_version, row.fixed) < 0:
            found.append(Match(row.cve, row.fixed, row.urgency))
    return sorted(found)
