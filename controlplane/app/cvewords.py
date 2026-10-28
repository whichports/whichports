"""What the CVE check's message says: one description, drawn by every
channel as every other alert is (`app/alertwords.py`).

One message for a workspace when a newer version fixes a CVE that was not
told before, every checked port of every server in the one message
(`docs/SPEC-cve-check.md`, section 2, point 7, and `docs/RECORD.md` 4.338).
The shape is the one every alert has: a title a person would say aloud,
labelled values, the line that nothing else will be sent, one button.

**What it never says**: a CVE's id, a version, a date, a word of ours about
the server's condition, or a vendor's urgency word. The first CVE mail said
all of those and was refused for it (4.338). The count is here, and the ids
are on the server's page.

**"An update" is said only where it was read.** When every server's own
package lists offer every fix, the title says an update fixes. Where one fix
is not offered it says a newer version fixes, as the mark on the page does
(`app/cvecard.py`), because an update would say more than was read.

**The count is the page's, and what is new is said beside it.** `CVEs` is
what the mark on the server's page stands for, which is what the button
opens, and `new` is how many of them this message is about. The title
follows that mark too. A message that said only its new ones read "CVEs: 1"
over a page that said 3 (the second challenge, section 7.12). That mark
leaves out a dismissed port and a silenced one, so the count does too.

**The last line promises what is kept.** A CVE is told once for a port of a
server (`app/cvetell.py`), so the line names the ports. The same CVE on
another port is another message.

This module builds the description and decides nothing: which ports are
told, and that each CVE is told once for a port, is the sweep's.
"""

import dataclasses

from . import alertwords, publicurl

# Every label this message may carry. A closed list of its own, beside
# `alertwords.LABELS`, which holds the labels of what the probers measured.
LABELS = ("server", "port", "ports", "servers", "CVEs", "new")

CLOSING_PORT = "Nothing else will be sent about these CVEs on the same port."
CLOSING_PORTS = "Nothing else will be sent about these CVEs on the same ports."
UPDATE_FIXES = "An update fixes CVEs on"
NEWER_FIXES = "A newer version fixes CVEs on"


@dataclasses.dataclass(frozen=True)
class Told:
    """One server's part of a message: the ports told as (protocol, port),
    the CVE ids that are new on them, and whether this server's own lists
    offer every one of their fixes. `display` is the server's display name
    when it has one.

    `marked` is every CVE the mark on the server's page stood for, and
    `mark_offered` whether that mark said an update. A part that does not
    say them is read as standing for what it tells."""
    host_name: str
    ports: tuple
    cves: frozenset
    offered: bool
    display: str = ""
    marked: frozenset = frozenset()
    mark_offered: bool | None = None


def said(told) -> alertwords.Said:
    """The message for these servers. Raises ValueError for a message about
    no server, no port or no CVE."""
    told = sorted(told, key=lambda one: (one.display or one.host_name, one.host_name))
    if not told or any(not one.ports or not one.cves for one in told):
        raise ValueError("a message about no server, no port or no CVE")
    new = set().union(*(one.cves for one in told))
    standing = new.union(*(one.marked for one in told))
    start = UPDATE_FIXES if all(_says_an_update(one) for one in told) else NEWER_FIXES
    counts = (("CVEs", str(len(standing))), ("new", str(len(new))))
    if len(told) == 1:
        one = told[0]
        shown = one.display or one.host_name
        ports = _ports(one.ports)
        one_port = len(set(one.ports)) == 1
        return alertwords.Said(
            title=f"{start} {shown}",
            fields=(("server", _server(one)), ("port" if one_port else "ports", ports)) + counts,
            closing=CLOSING_PORT if one_port else CLOSING_PORTS,
            button=f"Open {shown}", link=publicurl.server(one.host_name))
    names = [one.display or one.host_name for one in told]
    return alertwords.Said(
        title=f"{start} {len(told)} servers",
        fields=(("servers", _listed(names)),) + counts,
        closing=CLOSING_PORTS, button="Open Fleet", link=publicurl.dashboard())


def _says_an_update(one: Told) -> bool:
    """Whether the mark on this server's page says an update."""
    return one.offered if one.mark_offered is None else one.mark_offered


def _server(one: Told) -> str:
    """The `server` field: a display name with the name the server is found
    by beside it, since two servers may carry one display name (4.255)."""
    if one.display and one.display != one.host_name:
        return f"{one.display} ({one.host_name})"
    return one.host_name


def _ports(ports) -> str:
    """The ports in order, each once. The probers connect over TCP, so a bare
    number is a TCP port and any other protocol is said."""
    ordered = sorted(set(ports), key=lambda port: (port[1], port[0] != "tcp", port[0]))
    return _listed([str(number) if protocol == "tcp" else f"{number}/{protocol}"
                    for protocol, number in ordered])


def _listed(entries) -> str:
    """Five at most, then how many more, as every other message lists."""
    shown = ", ".join(entries[:alertwords.LIST_SHOWS])
    more = len(entries) - alertwords.LIST_SHOWS
    return f"{shown} and {more} more" if more > 0 else shown
