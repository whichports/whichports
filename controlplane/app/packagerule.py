"""Which package runs behind a port, named from what the agent's records say,
or the reason none is named.

The agent reports evidence and stops: for each service behind a listening
socket, which packages dpkg's records say own its unit file, the program its
ExecStart names, and where that program leads when it is a link, with a typed
finding where a step had no answer (`agent/internal/hostdoc/packages.go`, the
section `packages`). This module holds the rule that turns that into a
package, agreed on 2026-10-02 and recorded in `docs/RECORD.md` 4.274. It is
here and not in the agent so that it can change without an agent release.

**A package is named only when every link holds.** The finding is
`complete`, the program is a compiled one (`elf`) or one of the wrappers in
`KNOWN_WRAPPERS`, the unit file, the program and its link target each have
exactly one owner, each owner is installed, no path is diverted, all of them
come from one source package, and the version is one `debversion` reads.
Anything else names nothing, because a wrong package is worse than none: it
would be matched against another package's security data. PostgreSQL on
Debian is the case this refuses on purpose. Its unit file and the script it
starts belong to postgresql-common, not to the server's package.

**A script names a package only from a short list, never by a general
rule.** A unit that starts a script of its own package, which then starts
the server, is common: Apache does it. Naming every such script's package
was measured on 2026-10-03 over 24 services on Debian 12 and Ubuntu 24.04
and was right for the three in the list. It would be wrong for PostgreSQL's
shape, in silence, and a list fails by saying nothing.

**A finding this module does not know names nothing**, never an error and
never a match. The agent's list of findings can grow in a later release, and
an older control plane must read a newer agent's report without guessing.

The port-level answer has four reasons when no package is named, as a closed
list, so a screen or an alert never has to read a sentence to know which.
"""

import dataclasses

from . import debversion

# A unit that starts a script of its own package, by the unit's name and the
# script ExecStart names. Each line was measured on 2026-10-03 on Debian 12
# and on Ubuntu 24.04, in a clean container with the package from the
# distribution's own archive: the program that holds the socket, read as root
# from /proc, comes from the source package the script's package comes from,
# at the version the agent sent for it.
#
#   apache2.service   port 80 is held by /usr/sbin/apache2 of apache2-bin,
#                     source apache2
#   ntpsec.service    udp 123 is held by /usr/sbin/ntpd of ntpsec
#   dnsmasq.service   port 53 is held by /usr/sbin/dnsmasq of dnsmasq-base,
#                     source dnsmasq
#
# A line is the pair, not the unit's name: a unit of that name that starts
# another script is somebody's own and is not named.
KNOWN_WRAPPERS = (
    ("apache2.service", "/usr/sbin/apachectl"),
    ("ntpsec.service", "/usr/libexec/ntpsec/ntp-systemd-wrapper"),
    ("dnsmasq.service", "/usr/share/dnsmasq/systemd-helper"),
)

# Why no package is named for a port. A closed list: these four and nothing else.
NO_UNIT = "no unit behind the port"
CONTAINER = "a container's port"
NOT_READ = "package records not read"
NOT_DETERMINED = "package not determined"
REASONS = (NO_UNIT, CONTAINER, NOT_READ, NOT_DETERMINED)


@dataclasses.dataclass(frozen=True)
class Named:
    """The package that runs behind a port. `source` and `source_version` are
    what the distribution's security data is keyed on."""
    name: str
    version: str
    source: str
    source_version: str
    architecture: str


@dataclasses.dataclass(frozen=True)
class Unnamed:
    """No package named, and which of REASONS is why."""
    reason: str

    def __post_init__(self):
        if self.reason not in REASONS:
            raise ValueError(f"not a reason: {self.reason!r}")


# ------------------------------------------------------------ one entry

def name_from_entry(entry) -> Named | None:
    """The package one entry of the section names, or None. Every field is
    checked for its type, because a report is JSON a host sent."""
    if not isinstance(entry, dict) or entry.get("finding") != "complete":
        return None
    if entry.get("program_kind") == "script":
        program = entry.get("program")
        path = program.get("path") if isinstance(program, dict) else None
        if (entry.get("unit"), path) not in KNOWN_WRAPPERS:
            return None
    elif entry.get("program_kind") != "elf":
        return None
    unit_owner = _sole_owner(entry.get("unit_file"))
    program_owner = _sole_owner(entry.get("program"))
    if unit_owner is None or program_owner is None:
        return None
    owners = [unit_owner, program_owner]
    runs = program_owner
    if entry.get("program_target") is not None:
        # The link's target is the file that runs, so its package is the one
        # named, and it has to come from the same source as the rest.
        runs = _sole_owner(entry.get("program_target"))
        if runs is None:
            return None
        owners.append(runs)
    if len({_source_of(owner) for owner in owners}) != 1:
        return None
    version = runs["version"]
    source_version = runs.get("source_version") or version
    try:
        debversion.parse(version)
        debversion.parse(source_version)
    except debversion.VersionError:
        return None
    return Named(name=runs["name"], version=version, source=_source_of(runs),
                 source_version=source_version,
                 architecture=runs.get("architecture") or "")


def _sole_owner(owned) -> dict | None:
    """The one installed owner of a path that is not diverted, or None."""
    if not isinstance(owned, dict):
        return None
    if owned.get("diverted", False) is not False:
        return None
    owners = owned.get("owners")
    if not isinstance(owners, list) or len(owners) != 1:
        return None
    owner = owners[0]
    if not isinstance(owner, dict) or owner.get("installed") is not True:
        return None
    for key in ("name", "version"):
        if not isinstance(owner.get(key), str) or not owner[key]:
            return None
    for key in ("source", "source_version", "architecture"):
        if key in owner and not isinstance(owner[key], str):
            return None
    return owner


def _source_of(owner: dict) -> str:
    """deb-control(5): the Source field names the source package "if it is
    different than the name of the package itself", so no Source field means
    the package's own name."""
    return owner.get("source") or owner["name"]


# -------------------------------------------------------------- one port

def package_for_port(doc, protocol: str, family: str, port: int) -> Named | Unnamed:
    """The package behind one port of one report, or why none is named.

    In this order: a port a container publishes is the container's, and the
    host's own packages say nothing about what runs inside it. Then the unit:
    a system service the kernel says holds the socket, or failing that the
    service a socket unit hands that port to. Then the section's entry for
    that unit, read by `name_from_entry`.
    """
    if not isinstance(doc, dict):
        return Unnamed(NOT_READ)
    if _published_by_a_container(doc, protocol, port):
        return Unnamed(CONTAINER)
    unit = _unit_for(doc, protocol, family, port)
    if unit is None:
        return Unnamed(NO_UNIT)
    section = doc.get("packages")
    if not isinstance(section, dict) or not _collected(section):
        return Unnamed(NOT_READ)
    entries = section.get("units")
    if not isinstance(entries, list):
        entries = []
    for entry in entries:
        if isinstance(entry, dict) and entry.get("unit") == unit:
            named = name_from_entry(entry)
            return named if named is not None else Unnamed(NOT_DETERMINED)
    return Unnamed(NOT_DETERMINED)


def _collected(section: dict) -> bool:
    """The agent lists entries only when every file list was read, which is
    the dpkg_info verdict."""
    sources = section.get("sources")
    if not isinstance(sources, dict):
        return False
    info = sources.get("dpkg_info")
    return isinstance(info, dict) and info.get("status") == "collected"


def _published_by_a_container(doc: dict, protocol: str, port: int) -> bool:
    containers = doc.get("containers")
    if not isinstance(containers, dict):
        return False
    for runtime in ("docker", "podman"):
        for container in containers.get(runtime) or ():
            if not isinstance(container, dict):
                continue
            for published in container.get("ports") or ():
                if (isinstance(published, dict) and published.get("host_port") == port
                        and published.get("protocol") == protocol):
                    return True
    return False


def _system_service(cgroup, unit) -> bool:
    """A service directly inside slices, "/system.slice/nginx.service". The
    same rule the agent uses to pick its entries: a user's service sits under
    user@<uid>.service and a container's own systemd under a scope, and
    neither is the host's service of that name."""
    if not isinstance(cgroup, str) or not isinstance(unit, str) or not unit.endswith(".service"):
        return False
    parts = cgroup.strip("/").split("/")
    return parts[-1] == unit and all(p.endswith(".slice") for p in parts[:-1])


def _unit_for(doc: dict, protocol: str, family: str, port: int) -> str | None:
    """The one service unit behind the port, or None when there is none or
    more than one."""
    found = set()
    sockets = doc.get("sockets")
    listening = sockets.get("listening") if isinstance(sockets, dict) else None
    for sock in listening or ():
        if not isinstance(sock, dict):
            continue
        if (sock.get("protocol"), sock.get("family"), sock.get("port")) != (protocol, family, port):
            continue
        if _system_service(sock.get("cgroup"), sock.get("unit")):
            found.add(sock["unit"])
    if not found:
        found = _socket_activated(doc, protocol, port)
    return found.pop() if len(found) == 1 else None


def _socket_activated(doc: dict, protocol: str, port: int) -> set[str]:
    """The services socket units hand this port to. The manager holds such a
    socket, so the kernel names init and not the service (the agent's
    socketunits.go)."""
    directive = {"tcp": "ListenStream", "udp": "ListenDatagram"}.get(protocol)
    out = set()
    section = doc.get("socket_units")
    units = section.get("units") if isinstance(section, dict) else None
    for unit in units or ():
        if not isinstance(unit, dict) or not unit.get("parsed"):
            continue
        if unit.get("masked") or unit.get("template") or unit.get("alias_of"):
            continue
        service = unit.get("service_unit")
        if not isinstance(service, str) or not service.endswith(".service"):
            continue
        for listen in unit.get("listen") or ():
            if (isinstance(listen, dict) and listen.get("directive") == directive
                    and listen.get("port") == port):
                out.add(service)
    return out
