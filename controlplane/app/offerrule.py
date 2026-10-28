"""What a named package's port may say about CVEs, held against what the
server's own package lists offer.

`app/packagerule.py` names the package behind a port and `app/cvematch.py`
says which CVEs of the release's data its version is open to. That is not
yet a claim a screen may make, because the data is the distribution's and
the package may not be: nginx from nginx.org carries the distribution's own
source name, and so do a backport, MariaDB's own build and Proxmox's
(measured on 2026-10-06, `docs/RECORD.md` 4.418). So the agent also reports
what the server's apt lists offer for the package
(`agent/internal/hostdoc/packages.go`, `Offers`), and this module holds the
rule that reads it: `docs/SPEC-cve-check.md`, section 8.1, point 2, said yes
to on 2026-10-07 (4.437).

**The rule does not do apt's choosing again.** It needs no weights, no pins
and no holds. A CVE the release's data says is fixed in F is said for a
package when:

1. the installed version is below F, which is `cvematch`'s answer
2. an archive of the distribution's own that is not flagged offers a version
   at or past F. Then the server's own update fixes it. When none does, the
   CVE is said apart, as fixed in a version these lists do not offer, and no
   cause is named, because none was read
3. the installed version is not one another archive, or a flagged one,
   offers, unless one of the distribution's own offers it too
4. the installed version is not above every version the distribution's own
   archives offer
5. where another archive offers the package at all, one of the
   distribution's own offers the very version that is installed

When 3, 4 or 5 fails nothing is checked, and the reason says what was read
and no more. Only 3 reads whose build it is: the installed version stands
in another archive's list. 4 and 5 read that it could not be told. The
distribution's own security build on a server whose lists hold the release
alone stands above everything those lists offer, and it is the
distribution's. And another archive's build that is behind on its own
updates stands in no list at all, below what the distribution offers:
MariaDB's archive lists its two newest and no older one. Both were found by
the challenge of 2026-10-11, the second drawn as the distribution's own
before 5 was there.

**`none` is said only where no other archive offers the package.** A
server with Ubuntu Pro has Pro's archive in its lists, which is another
archive to the agent, and a fix only Pro offers is in no extract
(`app/cveextract.py`). There an update in the server's own lists fixes a
CVE this rule cannot see, so it does not say that none does.

**Flagged** is an archive whose Release file says `NotAutomatic` or
`ButAutomaticUpgrades`, which is what tells Ubuntu's backports from its
updates. apt installs nothing from such an archive by itself, so what it
offers is no update here. Debian's backports are one too since the agent
release after 27 October: before it the agent counted them as another
archive, and on a Debian server with backports in its lists every service
with a backport was never checked (`docs/SPEC-cve-check.md`, 8.1, point 1).

**The lists offer binary versions and the data names source versions.** The
two are held against each other only for a package whose binary version is
its source's, or that with the mark of a rebuild, `+b1`. In the reports
kept from the installs measured that is all 54 packages behind a listening
service, six of them with the mark. A package whose binary version goes its
own way, as `gcc` does from `gcc-defaults`, is not checked. That the
versions the lists offer follow their sources the same way is taken from
the installed one and was not measured apart.

**A report is JSON a server sent.** Every field is checked for what the
agent's own marshaller lets through, and an entry that is anything else is
read as lists that were not read: never as "nothing found", and never as an
error that takes a page down.

Four reasons when nothing is checked, a closed list, so a screen never has
to read a sentence to know which.
"""

import dataclasses
import functools
import re

from . import cvematch, debversion

# Why a named package is not checked. A closed list: these six and nothing
# else. `packagerule.REASONS` are the four before them, for a port with no
# package named at all.
NOT_THE_DISTRIBUTIONS = "not the distribution's package"
ANOTHER_ARCHIVE_OFFERS = "another archive offers this package"
NEWER_THAN_THE_LISTS = "newer than this server's package lists offer"
NOT_IN_THE_LISTS = "not in this server's package lists"
VERSION_NOT_COMPARABLE = "version not comparable"
LISTS_NOT_READ = "package lists not read"
REASONS = (NOT_THE_DISTRIBUTIONS, ANOTHER_ARCHIVE_OFFERS, NEWER_THAN_THE_LISTS, NOT_IN_THE_LISTS,
           VERSION_NOT_COMPARABLE, LISTS_NOT_READ)

# The words the agent gives an archive, by the distribution of the server it
# runs on. It gives one only on a server of that distribution
# (agent/internal/collect/aptlists.go), so any other pairing is not its.
ARCHIVE_WORDS = {"debian": ("debian", "debian-security"), "ubuntu": ("ubuntu",)}

# The mark Debian puts on a binary it rebuilt from an unchanged source: `+b`
# and a number, any number. Debian's Developer's Reference, "Recompilation or
# binary-only NMU", read on 2026-10-11: "a suffix appended to the package
# version number, following the form bnumber. For instance, if the latest
# version you are recompiling against was version 2.9-3, your binary-only NMU
# should carry a version of 2.9-3+b1. If the latest version was 3.4+b1 [...]
# your binary-only NMU should have a version number of 3.4+b2."
_REBUILD = re.compile(r"\+b\d+")


@dataclasses.dataclass(frozen=True)
class Checked:
    """A package held against its release's data and the server's lists.

    `update_fixes` are the CVEs the lists' own update fixes, and `update_to`
    is the highest version an archive of the distribution's own that is not
    flagged offers. `not_offered` are the CVEs fixed only in a version these
    lists do not offer, and `fixed_in` the highest of their fixed versions,
    at which each of them is fixed, or empty when there are none."""
    update_fixes: tuple
    update_to: str
    not_offered: tuple
    fixed_in: str

    @property
    def none(self) -> bool:
        """Checked, and no newer version fixes a CVE. The only thing a
        screen may show as `none`."""
        return not self.update_fixes and not self.not_offered


@dataclasses.dataclass(frozen=True)
class NotChecked:
    """Nothing was held against anything, and which of REASONS is why."""
    reason: str

    def __post_init__(self):
        if self.reason not in REASONS:
            raise ValueError(f"not a reason: {self.reason!r}")


@dataclasses.dataclass(frozen=True)
class _Lists:
    """One package's entry, read and checked: the versions the distribution's
    own archives offer, apart by whether the archive is flagged, and the two
    facts about every other archive."""
    own: tuple
    flagged: tuple
    other: bool
    other_installed: bool


def held(doc, named, indexed) -> Checked | NotChecked:
    """What may be said for `named`, a `packagerule.Named`, from the report
    `doc` and `cvematch.by_source(rows)` of its release's extract.

    Raises `debversion.VersionError` when the installed version is not a
    version, so that is never read as no CVE. `packagerule` names no such
    package."""
    lists = _lists_for(doc, named.name)
    if lists is None:
        return NotChecked(LISTS_NOT_READ)
    if not _follows_its_source(named):
        return NotChecked(VERSION_NOT_COMPARABLE)
    installed = named.version
    among_own = any(_same(version, installed) for version in lists.own)
    elsewhere = lists.other_installed or any(_same(version, installed) for version in lists.flagged)
    if elsewhere and not among_own:
        # The one case that reads whose build it is: the installed version
        # stands in another archive's list and in none of the distribution's.
        return NotChecked(NOT_THE_DISTRIBUTIONS)
    if lists.other and not among_own:
        # Another archive offers the package, and no list of the
        # distribution's holds what is installed. Whose build it is cannot
        # be told: another archive's build behind on its own updates is in
        # no list either. So nothing is held against the distribution's data.
        #
        # A flagged archive of the distribution's own is not asked here. A
        # backport is a newer upstream version than the release carries, so
        # an old build of one stands above everything the release offers
        # and the fourth condition answers for it.
        return NotChecked(ANOTHER_ARCHIVE_OFFERS)
    if not lists.own:
        # No archive of the distribution's that apt installs from by itself
        # offers it. A flagged one that does is still another archive than
        # those.
        return NotChecked(ANOTHER_ARCHIVE_OFFERS if lists.flagged else NOT_IN_THE_LISTS)
    top = _highest(lists.own)
    if debversion.compare(installed, top) > 0:
        # Above everything these lists offer from the distribution. It may
        # be the distribution's own build from an archive this server's
        # lists do not hold, so it is not called anybody else's.
        return NotChecked(NEWER_THAN_THE_LISTS)
    # A row with no fixed version is a CVE no update fixes. Nothing is said
    # of it here, whatever switch the extract was built with.
    open_to = [match for match in cvematch.open_cves(indexed, named.source, named.source_version)
               if match.fixed]
    update_fixes = tuple(m for m in open_to if debversion.compare(top, m.fixed) >= 0)
    not_offered = tuple(m for m in open_to if debversion.compare(top, m.fixed) < 0)
    fixed_in = _highest(m.fixed for m in not_offered) if not_offered else ""
    if lists.other and not update_fixes and not not_offered:
        # Nothing in the distribution's data, and another archive in this
        # server's lists offers the package. What that archive's build fixes
        # is not in the data, so "none" would say more than was read.
        return NotChecked(ANOTHER_ARCHIVE_OFFERS)
    return Checked(update_fixes=update_fixes, update_to=top, not_offered=not_offered, fixed_in=fixed_in)


def _same(a: str, b: str) -> bool:
    return debversion.compare(a, b) == 0


def _highest(versions) -> str:
    return max(versions, key=functools.cmp_to_key(debversion.compare))


def _follows_its_source(named) -> bool:
    """Whether the package's binary version is its source's, or that with a
    rebuild's mark."""
    if named.version == named.source_version:
        return True
    if not named.version.startswith(named.source_version):
        return False
    return _REBUILD.fullmatch(named.version[len(named.source_version):]) is not None


def _lists_for(doc, name: str) -> _Lists | None:
    """The one entry the report holds for this package, or None when the
    lists were not read whole, when the report says nothing of the package,
    or when what it says is not what the agent's marshaller lets through."""
    section = doc.get("packages") if isinstance(doc, dict) else None
    if not isinstance(section, dict):
        return None
    sources = section.get("sources")
    lists = sources.get("apt_lists") if isinstance(sources, dict) else None
    if not isinstance(lists, dict) or lists.get("status") != "collected":
        return None
    distribution = section.get("distribution")
    ident = distribution.get("id") if isinstance(distribution, dict) else None
    words = ARCHIVE_WORDS.get(ident) if isinstance(ident, str) else None
    entries = section.get("offers")
    if words is None or not isinstance(entries, list):
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        return None
    mine = [entry for entry in entries if entry.get("name") == name]
    if len(mine) != 1:
        return None
    return _checked_entry(mine[0], words)


def _checked_entry(entry: dict, words) -> _Lists | None:
    """One entry, every field held to its type, or None."""
    other, other_installed = entry.get("other_offers"), entry.get("other_offers_installed")
    if not isinstance(other, bool) or not isinstance(other_installed, bool):
        return None
    if other_installed and not other:
        return None
    # The agent leaves `offered` and `offered_cut` out when there is nothing
    # to say. Cut offers are not the whole of the lists.
    if entry.get("offered_cut", False) is not False:
        return None
    offered = entry.get("offered", [])
    if not isinstance(offered, list):
        return None
    own, flagged = [], []
    for offer in offered:
        if not isinstance(offer, dict) or offer.get("archive") not in words:
            return None
        version = offer.get("version")
        flags = (offer.get("not_automatic"), offer.get("but_automatic_upgrades"))
        if not isinstance(version, str) or not all(isinstance(flag, bool) for flag in flags):
            return None
        try:
            debversion.parse(version)
        except debversion.VersionError:
            return None
        (flagged if any(flags) else own).append(version)
    return _Lists(own=tuple(own), flagged=tuple(flagged), other=other, other_installed=other_installed)
