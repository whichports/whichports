"""What a port's card says about CVEs: its lines, in the words that were
drawn, and whether the check's own mark stands.

`docs/SPEC-cve-check.md`, sections 3 and 8.1. This module joins the three
that know something: `app/packagerule.py` names the package behind a port,
`app/cvestore.py` keeps the release's security data, and `app/offerrule.py`
holds the one against the other and against what the server's own package
lists offer. What comes out is the card a page draws and nothing else: a
match is worked out each time and kept nowhere.

**Checked and found nothing is one value, not checked is another.** `none`
is said only when a package was named, is the distribution's own, the
release's data is there and no older than three days, and no newer version
fixes anything. Every other way is `not checked`, with why on the first
line where the package stands.

**The words say what was read.** `installed`, never running: the version is
the installed one, and nothing here measured what runs or what answers. An
update the server's own lists offer is `update fixes` and `update to`. A fix
in a version those lists do not offer is `fixed in` and `it fixes`, and no
cause is named, because none was read. No word of ours is said about the
server's condition, and the vendor's urgency word is not carried.

**A CVE is the source package's, and the card says so.** The
distributions' data names a source package and the version that fixes a CVE
in it, and no binary package anywhere: Debian's tracker file, read on
2026-10-07, holds a description, a scope, a bug number and the releases for
each CVE of a source, and nothing else. So for openssh-server the count
holds flaws its own text places in `ssh` and `scp`, which other binary
packages of that source carry. The count's line therefore names the source
package, and nothing here says a CVE is in the program behind the port
(the second challenge, section 7.12, lead a).

**The mark is the check's own, and quiet.** It stands for a port when a
newer version fixes at least one CVE. It is not the warn triangle and a port
that carries only it is not counted under Needs a decision
(`docs/RECORD.md` 4.446): a server some weeks behind on its updates has a
fix waiting for nearly every package, and the one count that asks for an
answer must not start to say "you have updates".
"""

import dataclasses
from datetime import datetime, timedelta, timezone

from . import cvematch, cvestore, offerrule, packagerule

# The labels and the fixed values, as drawn on 2026-10-07 (4.437).
INSTALLED = "installed"
UPDATE_FIXES = "update fixes"
UPDATE_TO = "update to"
FIXED_IN = "fixed in"
IT_FIXES = "it fixes"
DATA_OF = "data of"
NONE = "none"
NOT_CHECKED = "not checked"
IN_THE_LISTS = "in this server's package lists"
NOT_OFFERED = "not offered by this server's package lists"

# What stands where the package would, when none is named.
NOT_DETERMINED = "package not determined"
UNKNOWN = "unknown"
# Why a named package is not checked, beyond `offerrule.REASONS`.
NO_DATA = "no security data for this release"
UNKNOWN_AGE = "security data of unknown age"
# A port whose two address families are held by two packages. One strip
# cannot say both, and saying one would be silent about the other.
TWO_PACKAGES = "two packages hold this port"
# A port one package holds over one address family, and something no package
# was named for over the other: two units, a program outside a service, a
# unit whose package is not determined.
ALSO_HELD = "another program also holds this port"

# Data older than this may lack a fix that came out since, so a clean port
# would be a guess (docs/SPEC-cve-check.md section 7.3, decided 2026-10-07).
# Its age is counted from when the extract was built from a download that
# succeeded, and from the vendor's own stamp only where the extract does not
# say: Canonical's file did not change from a Friday evening to a Monday
# morning, and counted from that stamp every Ubuntu port read not checked on
# the Monday evening (section 7.12, lead c).
# The same holds for the other side: a report older than this says what was
# installed then, and what is installed today was not read (the challenge of
# 2026-10-11, a server silent for a month that read "update fixes none").
OLD_AFTER = timedelta(days=3)

# Whose data an extract is, as the card says it.
DATA_NAMES = {"debian": "Debian security tracker", "ubuntu": "Ubuntu security data"}

# **Canonical's data is shared under its licence.** Canonical publishes its
# OSV data under CC BY-SA 4.0: the README of
# github.com/canonical/ubuntu-security-notices, the repository the OSV page
# links, says "This work is licensed under a Creative Commons
# Attribution-ShareAlike 4.0 International License" (read 2026-10-14, with
# the licence's text beside it in that repository). The licence's section
# 3(a) asks whoever shares the data for who made it, a link to it, a note
# that it was changed, and the licence with its link, in any reasonable
# manner for the medium. A card showing Ubuntu's CVEs shares them, adapted
# to one package of one server, so its data line says all of it, and the
# source and the licence are links. The line is Ubuntu's alone: Debian's
# tracker states no terms for its data and asks for no line, by its page and
# its repository as read on 2026-10-14 (docs/SPEC-cve-check.md, section 5).
OSV_SOURCE = "https://security-metadata.canonical.com/osv/"
CC_BY_SA = "https://creativecommons.org/licenses/by-sa/4.0/"
ATTRIBUTION = {"ubuntu": ("by Canonical, adapted, CC BY-SA 4.0",
                          (("Ubuntu security data", OSV_SOURCE), ("CC BY-SA 4.0", CC_BY_SA)))}


@dataclasses.dataclass(frozen=True)
class Line:
    """One line of the card: a label and a value, what stands after the
    value behind a dot, and the CVE ids listed under it."""
    label: str
    value: str
    note: str = ""
    ids: tuple = ()


@dataclasses.dataclass(frozen=True)
class Card:
    """A port's card. `mark` is the words of the check's own mark, or empty
    when there is none, `cves` every CVE the mark stands for, and `apart`
    those of them whose fix this server's lists do not offer. `links` are
    the texts on the card a page draws as links, as (text, address): the
    source and the licence of data shared under one (ATTRIBUTION)."""
    lines: tuple
    mark: str = ""
    cves: tuple = ()
    apart: tuple = ()
    links: tuple = ()

    @property
    def checked(self) -> bool:
        """Whether the port was held against its release's data at all. A
        checked card ends with whose data it is, and no other card does."""
        return self.lines[-1].label == DATA_OF


def count_of(number: int) -> str:
    return "1 CVE" if number == 1 else f"{number} CVEs"


def counted_for(number: int, source: str) -> str:
    """A count as a card's line says it: whose CVEs they are."""
    return f"{count_of(number)} in source package {source}"


def card_for(doc, protocol: str, family: str, port: int, extract_for=cvestore.read, now=None,
             reported_at=None) -> Card:
    """The card of one port of one report. `extract_for` answers a release's
    extract or None, `cvestore.read` unless a test hands in its own.
    `reported_at` is when the report arrived, or None when the caller holds
    a report of now."""
    package = packagerule.package_for_port(doc, protocol, family, port)
    if isinstance(package, packagerule.Unnamed):
        first = NOT_DETERMINED if package.reason == packagerule.NOT_DETERMINED else UNKNOWN
        return _not_checked(first)
    installed = f"{package.name} {package.version}"
    now = now or datetime.now(timezone.utc)
    if reported_at is not None and now - reported_at > OLD_AFTER:
        return _not_checked(installed, f"report {(now - reported_at).days} days old")
    section = doc.get("packages") if isinstance(doc, dict) else None
    release = cvematch.release_of(section.get("distribution") if isinstance(section, dict) else None)
    stored = extract_for(*release) if release is not None else None
    # An extract with no row in it is not a release with no CVE: every
    # release the check covers has tens of thousands. Believing it would
    # make every port read none (the challenge of 2026-10-11).
    if stored is None or not stored.by_source:
        return _not_checked(installed, NO_DATA)
    modified = _when(stored.header.source_modified)
    if modified is None:
        return _not_checked(installed, UNKNOWN_AGE)
    age = now - (_when(stored.header.built) or modified)
    if age > OLD_AFTER:
        return _not_checked(installed, f"security data {age.days} days old")
    got = offerrule.held(doc, package, stored.by_source)
    if isinstance(got, offerrule.NotChecked):
        return _not_checked(installed, got.reason)
    return _checked(installed, package.source, got, stored.header, modified)


def server_mark(cards) -> str:
    """The mark's words for a whole server, from its ports' cards: every CVE
    its ports' marks stand for, each counted once. "An update" only when
    every one of those marks says so."""
    marked = [card for card in cards if card.mark]
    ids = {cve for card in marked for cve in card.cves}
    if not ids:
        return ""
    if all(card.mark.startswith("an update fixes ") for card in marked):
        return f"an update fixes {count_of(len(ids))}"
    return f"a newer version fixes {count_of(len(ids))}"


# The address families a port is asked about, in order.
FAMILIES = ("v4", "v6")


def cards_of(doc, extract_for=cvestore.read, now=None, reported_at=None) -> dict:
    """The card of every listening port of one report, as {(protocol, port):
    card}. One place, so a page and a message cannot hold two answers for
    one port.

    **Empty for a report that carries no packages section**, which is every
    report of the published agent (`docs/RECORD.md` 4.385): nothing of the
    check is said about it at all.

    **A port is one card, and it is checked only where one package holds
    it over every address family it listens on.** Each family is asked.
    Where they name two packages, nginx over IPv4 and Apache over IPv6, one
    strip cannot say both and saying the first would be silent about the
    second, so the port is not checked and says why. The same holds where
    one family names a package and the other names none: port 53 held over
    IPv4 by two units and over IPv6 by bind9 alone read bind9's `none` (the
    second challenge, section 7.12). The package is still named, with why
    it is not checked beside it.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("packages"), dict):
        return {}
    sockets = doc.get("sockets")
    listening = sockets.get("listening") if isinstance(sockets, dict) else None
    families = {}
    for sock in listening if isinstance(listening, list) else ():
        if not isinstance(sock, dict):
            continue
        protocol, port = sock.get("protocol"), sock.get("port")
        if isinstance(protocol, str) and isinstance(port, int) and not isinstance(port, bool):
            families.setdefault((protocol, port), set()).add(sock.get("family"))
    cards = {}
    for (protocol, port), listens_on in sorted(families.items()):
        asked = [family for family in FAMILIES if family in listens_on] or [FAMILIES[0]]
        answers = [card_for(doc, protocol, family, port, extract_for, now, reported_at) for family in asked]
        named = [card for card in answers if card.lines[0].value not in (UNKNOWN, NOT_DETERMINED)]
        if len({card.lines[0].value for card in named}) > 1:
            cards[(protocol, port)] = _not_checked(TWO_PACKAGES)
        elif named and len(named) < len(answers) and named[0].checked:
            cards[(protocol, port)] = _not_checked(named[0].lines[0].value, ALSO_HELD)
        else:
            cards[(protocol, port)] = (named or answers)[0]
    return cards


def _not_checked(first: str, why: str = "") -> Card:
    return Card(lines=(Line(INSTALLED, first, note=why), Line(UPDATE_FIXES, NOT_CHECKED)))


def _checked(installed: str, source: str, got, header, modified) -> Card:
    lines = [Line(INSTALLED, installed)]
    offered = tuple(match.cve for match in got.update_fixes)
    apart = tuple(match.cve for match in got.not_offered)
    if offered:
        lines.append(Line(UPDATE_FIXES, counted_for(len(offered), source), ids=offered))
        lines.append(Line(UPDATE_TO, got.update_to, note=IN_THE_LISTS))
    if apart:
        lines.append(Line(FIXED_IN, got.fixed_in, note=NOT_OFFERED))
        lines.append(Line(IT_FIXES, counted_for(len(apart), source), ids=apart))
    if got.none:
        lines.append(Line(UPDATE_FIXES, NONE))
    whose = DATA_NAMES[header.distribution]
    attribution, links = ATTRIBUTION.get(header.distribution, ("", ()))
    lines.append(Line(DATA_OF, f"{whose}, {modified:%Y-%m-%d %H:%M} UTC", note=attribution))
    cves = tuple(sorted(offered + apart))
    return Card(lines=tuple(lines), mark=_mark(len(offered), len(apart)), cves=cves, apart=apart, links=links)


def _mark(offered: int, apart: int) -> str:
    """The mark's words. "An update" only when this server's lists offer
    every fix: where one is not offered that would say more than was read."""
    if apart:
        return f"a newer version fixes {count_of(offered + apart)}"
    if offered:
        return f"an update fixes {count_of(offered)}"
    return ""


def _when(source_modified):
    """When the vendor's file last changed, as the extract's header says it,
    `2026-10-03T14:07:28Z`, or None when it does not say."""
    if not isinstance(source_modified, str):
        return None
    try:
        return datetime.strptime(source_modified, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
