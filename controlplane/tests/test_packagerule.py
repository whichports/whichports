"""The rule that names the package behind a port from the agent's evidence.

    python -m pytest tests/test_packagerule.py

`docs/RECORD.md` 4.274. The entries below have the shape the agent writes
(agent/internal/hostdoc/packages.go) and the owners the collector read on
Debian 12 and Ubuntu 24.04 on 2026-10-03, with made-up versions. Most of this
file is about when no package may be named.
"""
import copy

import pytest

from app import packagerule
from app.packagerule import (CONTAINER, NO_UNIT, NOT_DETERMINED, NOT_READ, Named, Unnamed,
                             name_from_entry, package_for_port)


def owner(name, version="1.0-1", source=None, arch="arm64", installed=True, **more):
    o = {"name": name, "architecture": arch, "installed": installed, "version": version}
    if source:
        o["source"] = source
    o.update(more)
    return o


def owned(path, *owners, diverted=None):
    o = {"path": path, "owners": list(owners)}
    if diverted is not None:
        o["diverted"] = diverted
    return o


SSH = {"unit": "ssh.service", "finding": "complete",
       "unit_file": owned("/usr/lib/systemd/system/ssh.service", owner("openssh-server", "1:9.0p1-1", "openssh")),
       "program": owned("/usr/sbin/sshd", owner("openssh-server", "1:9.0p1-1", "openssh")),
       "program_kind": "elf"}

NGINX = {"unit": "nginx.service", "finding": "complete",
         "unit_file": owned("/usr/lib/systemd/system/nginx.service", owner("nginx-common", "1.22.1-9", "nginx", arch="all")),
         "program": owned("/usr/sbin/nginx", owner("nginx", "1.22.1-9")),
         "program_kind": "elf"}

REDIS = {"unit": "redis-server.service", "finding": "complete",
         "unit_file": owned("/usr/lib/systemd/system/redis-server.service", owner("redis-server", "5:7.0.15-1", "redis")),
         "program": owned("/usr/bin/redis-server", owner("redis-server", "5:7.0.15-1", "redis")),
         "program_kind": "elf",
         "program_target": owned("/usr/bin/redis-check-rdb", owner("redis-tools", "5:7.0.15-1", "redis"))}

POSTGRES = {"unit": "postgresql@15-main.service", "finding": "exec_start_prefixed",
            "unit_file": owned("/usr/lib/systemd/system/postgresql@.service",
                               owner("postgresql-common", "248", arch="all"))}


def changed(entry, path=None, **fields):
    """A copy of an entry with some fields replaced, or with fields of one
    of its paths replaced."""
    out = copy.deepcopy(entry)
    if path is None:
        out.update(fields)
    else:
        out[path].update(fields)
    return out


# Three services whose unit starts a script of their own package, which then
# starts the server. Owners and versions as the agent reported them from
# Debian 12 on 2026-10-03.
APACHE = {"unit": "apache2.service", "finding": "complete",
          "unit_file": owned("/usr/lib/systemd/system/apache2.service", owner("apache2", "2.4.68-1~deb12u1")),
          "program": owned("/usr/sbin/apachectl", owner("apache2", "2.4.68-1~deb12u1")),
          "program_kind": "script"}

NTPSEC = {"unit": "ntpsec.service", "finding": "complete",
          "unit_file": owned("/usr/lib/systemd/system/ntpsec.service", owner("ntpsec", "1.2.2+dfsg1-1+deb12u1")),
          "program": owned("/usr/libexec/ntpsec/ntp-systemd-wrapper", owner("ntpsec", "1.2.2+dfsg1-1+deb12u1")),
          "program_kind": "script"}

DNSMASQ = {"unit": "dnsmasq.service", "finding": "complete",
           "unit_file": owned("/usr/lib/systemd/system/dnsmasq.service", owner("dnsmasq", "2.90-4~deb12u2", arch="all")),
           "program": owned("/usr/share/dnsmasq/systemd-helper", owner("dnsmasq", "2.90-4~deb12u2", arch="all")),
           "program_kind": "script"}


# ------------------------------------------------------------ named

def test_openssh_names_its_one_package():
    assert name_from_entry(SSH) == Named("openssh-server", "1:9.0p1-1", "openssh", "1:9.0p1-1", "arm64")


def test_nginx_names_the_programs_package_of_the_same_source():
    """nginx's stanza has no Source field, so its source is its own name, which
    is nginx-common's source too (deb-control(5))."""
    assert name_from_entry(NGINX) == Named("nginx", "1.22.1-9", "nginx", "1.22.1-9", "arm64")


def test_redis_names_the_package_of_the_file_that_runs():
    assert name_from_entry(REDIS) == Named("redis-tools", "5:7.0.15-1", "redis", "5:7.0.15-1", "arm64")


def test_a_binnmu_keeps_its_source_version():
    entry = changed(SSH)
    for path in ("unit_file", "program"):
        entry[path]["owners"] = [owner("openssh-server", "1:9.0p1-1+b1", "openssh",
                                       source_version="1:9.0p1-1")]
    named = name_from_entry(entry)
    assert named.version == "1:9.0p1-1+b1" and named.source_version == "1:9.0p1-1"


# -------------------------------------------------------- not named

def test_postgresql_names_nothing():
    assert name_from_entry(POSTGRES) is None


@pytest.mark.parametrize("finding", [
    "no_unit_file", "unit_file_not_read", "drop_in_not_read", "drop_in_sets_exec_start",
    "no_exec_start", "several_exec_start", "exec_start_prefixed", "exec_start_not_a_path",
    "over_cap", "record_malformed",
])
def test_every_finding_but_complete_names_nothing(finding):
    assert name_from_entry(changed(SSH, finding=finding)) is None


@pytest.mark.parametrize("finding", ["a_finding_from_a_later_agent", "", None, 7, "COMPLETE", ["complete"]])
def test_a_finding_this_module_does_not_know_names_nothing_and_raises_nothing(finding):
    assert name_from_entry(changed(SSH, finding=finding)) is None


@pytest.mark.parametrize("kind", ["script", "other", "not_read", "", None, "ELF", "binary"])
def test_only_a_compiled_program_names_a_package(kind):
    assert name_from_entry(changed(SSH, program_kind=kind)) is None


def test_two_sources_name_nothing():
    """The PostgreSQL shape, with a compiled program: unit file from one
    source, program from another."""
    entry = changed(SSH)
    entry["unit_file"]["owners"] = [owner("postgresql-common", "248", arch="all")]
    assert name_from_entry(entry) is None


def test_a_link_target_from_another_source_names_nothing():
    entry = copy.deepcopy(REDIS)
    entry["program_target"]["owners"] = [owner("some-other", "1.0")]
    assert name_from_entry(entry) is None


@pytest.mark.parametrize("path", ["unit_file", "program", "program_target"])
def test_no_owner_names_nothing(path):
    """A file installed by hand has no owner, and is version unknown."""
    entry = copy.deepcopy(REDIS)
    entry[path]["owners"] = []
    assert name_from_entry(entry) is None


@pytest.mark.parametrize("path", ["unit_file", "program", "program_target"])
def test_two_owners_name_nothing(path):
    entry = copy.deepcopy(REDIS)
    entry[path]["owners"] = entry[path]["owners"] * 2
    assert name_from_entry(entry) is None


@pytest.mark.parametrize("path", ["unit_file", "program", "program_target"])
@pytest.mark.parametrize("diverted", [True, "yes", 1, None])
def test_a_diverted_path_names_nothing(path, diverted):
    entry = copy.deepcopy(REDIS)
    entry[path]["diverted"] = diverted
    assert name_from_entry(entry) is None


@pytest.mark.parametrize("installed", [False, None, "true", 1])
def test_an_owner_that_is_not_installed_names_nothing(installed):
    entry = copy.deepcopy(SSH)
    entry["program"]["owners"][0]["installed"] = installed
    assert name_from_entry(entry) is None


@pytest.mark.parametrize("version", ["", None, "not a version", "1.0 1", 1.0])
def test_a_version_that_does_not_read_names_nothing(version):
    entry = copy.deepcopy(SSH)
    entry["program"]["owners"][0]["version"] = version
    assert name_from_entry(entry) is None


def test_a_source_version_that_does_not_read_names_nothing():
    entry = copy.deepcopy(SSH)
    entry["program"]["owners"][0]["source_version"] = "1.0 (bad)"
    assert name_from_entry(entry) is None


@pytest.mark.parametrize("entry", [None, [], "ssh.service", {}, {"finding": "complete"},
                                   {"finding": "complete", "program_kind": "elf"},
                                   {"finding": "complete", "program_kind": "elf",
                                    "unit_file": "x", "program": []}])
def test_a_malformed_entry_names_nothing_and_raises_nothing(entry):
    assert name_from_entry(entry) is None


# ---------------------------------------------------------- one port

def report(*entries, sockets=None, socket_units=None, containers=None, info="collected"):
    doc = {"schema_version": 1, "hostname": "h",
           "sockets": {"status": "collected", "listening": sockets if sockets is not None else [
               {"protocol": "tcp", "family": "v4", "port": 22, "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"},
               {"protocol": "tcp", "family": "v6", "port": 22, "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"},
               {"protocol": "tcp", "family": "v4", "port": 80, "cgroup": "/system.slice/nginx.service", "unit": "nginx.service"},
               {"protocol": "tcp", "family": "v4", "port": 5432,
                "cgroup": "/system.slice/system-postgresql.slice/postgresql@15-main.service",
                "unit": "postgresql@15-main.service"},
           ]},
           "packages": {"status": "collected", "sources": {"dpkg_info": {"status": info}},
                        "units": list(entries)}}
    if socket_units is not None:
        doc["socket_units"] = {"status": "collected", "units": socket_units}
    if containers is not None:
        doc["containers"] = {"status": "collected", "docker": containers}
    return doc


def test_a_port_held_by_a_system_service_names_its_package():
    doc = report(SSH, NGINX, POSTGRES)
    assert package_for_port(doc, "tcp", "v4", 22) == name_from_entry(SSH)
    assert package_for_port(doc, "tcp", "v6", 22) == name_from_entry(SSH)
    assert package_for_port(doc, "tcp", "v4", 80) == name_from_entry(NGINX)


def test_postgresql_reads_not_determined():
    assert package_for_port(report(POSTGRES), "tcp", "v4", 5432) == Unnamed(NOT_DETERMINED)


def test_an_entry_with_an_unknown_finding_reads_not_determined():
    doc = report(changed(SSH, finding="a_finding_from_a_later_agent"))
    assert package_for_port(doc, "tcp", "v4", 22) == Unnamed(NOT_DETERMINED)


def test_a_unit_with_no_entry_reads_not_determined():
    """The agent cut it past its cap, or a later agent leaves it out."""
    assert package_for_port(report(NGINX), "tcp", "v4", 22) == Unnamed(NOT_DETERMINED)


def test_a_port_nothing_holds_reads_no_unit():
    assert package_for_port(report(SSH), "tcp", "v4", 443) == Unnamed(NO_UNIT)
    assert package_for_port(report(SSH), "udp", "v4", 22) == Unnamed(NO_UNIT)


@pytest.mark.parametrize("cgroup, unit", [
    ("/user.slice/user-1000.slice/user@1000.service/app.slice/web.service", "web.service"),
    ("/system.slice/docker-0123.scope/system.slice/nginx.service", "nginx.service"),
    ("/init.scope", "init.scope"),
    ("/user.slice/user-1000.slice/session-3.scope", "session-3.scope"),
    ("", ""),
    (None, None),
])
def test_a_socket_that_is_not_the_hosts_own_service_reads_no_unit(cgroup, unit):
    doc = report(SSH, NGINX, sockets=[{"protocol": "tcp", "family": "v4", "port": 22,
                                       "cgroup": cgroup, "unit": unit}])
    assert package_for_port(doc, "tcp", "v4", 22) == Unnamed(NO_UNIT)


def test_a_port_two_services_hold_is_not_guessed():
    doc = report(SSH, NGINX, sockets=[
        {"protocol": "tcp", "family": "v4", "port": 22, "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"},
        {"protocol": "tcp", "family": "v4", "port": 22, "cgroup": "/system.slice/nginx.service", "unit": "nginx.service"}])
    assert package_for_port(doc, "tcp", "v4", 22) == Unnamed(NO_UNIT)


def test_a_socket_activated_port_reads_the_service_its_socket_unit_names():
    """systemd holds the socket, so the kernel names init.scope, and ssh.socket
    hands port 22 to ssh.service."""
    doc = report(SSH, sockets=[{"protocol": "tcp", "family": "v4", "port": 22,
                                "cgroup": "/init.scope", "unit": "init.scope"}],
                 socket_units=[{"name": "ssh.socket", "parsed": True, "service_unit": "ssh.service",
                                "listen": [{"directive": "ListenStream", "kind": "port_only", "port": 22}]}])
    assert package_for_port(doc, "tcp", "v4", 22) == name_from_entry(SSH)
    # a datagram listener is not a TCP port
    doc["socket_units"]["units"][0]["listen"][0]["directive"] = "ListenDatagram"
    assert package_for_port(doc, "tcp", "v4", 22) == Unnamed(NO_UNIT)


@pytest.mark.parametrize("unusable", [{"masked": True}, {"template": True}, {"alias_of": "x.socket"},
                                      {"parsed": False}, {"service_unit": ""}, {"service_unit": "x.target"}])
def test_a_socket_unit_that_does_not_hand_over_the_port_names_nothing(unusable):
    unit = {"name": "ssh.socket", "parsed": True, "service_unit": "ssh.service",
            "listen": [{"directive": "ListenStream", "kind": "port_only", "port": 22}]}
    unit.update(unusable)
    doc = report(SSH, sockets=[], socket_units=[unit])
    assert package_for_port(doc, "tcp", "v4", 22) == Unnamed(NO_UNIT)


def test_a_port_a_container_publishes_reads_as_the_containers():
    """docker-proxy holds it in docker.service's cgroup, and docker.service's
    package says nothing about what runs inside the container."""
    docker = {"unit": "docker.service", "finding": "complete",
              "unit_file": owned("/usr/lib/systemd/system/docker.service", owner("docker.io", "26.1.5+dfsg1-1")),
              "program": owned("/usr/sbin/dockerd", owner("docker.io", "26.1.5+dfsg1-1")),
              "program_kind": "elf"}
    sockets = [{"protocol": "tcp", "family": "v4", "port": 8080, "cgroup": "/system.slice/docker.service", "unit": "docker.service"},
               {"protocol": "tcp", "family": "v4", "port": 2375, "cgroup": "/system.slice/docker.service", "unit": "docker.service"}]
    doc = report(docker, sockets=sockets,
                 containers=[{"id": "abc", "ports": [{"host_port": 8080, "container_port": 80, "protocol": "tcp"}]}])
    assert package_for_port(doc, "tcp", "v4", 8080) == Unnamed(CONTAINER)
    # the daemon's own port is the daemon's package
    assert package_for_port(doc, "tcp", "v4", 2375) == name_from_entry(docker)


@pytest.mark.parametrize("change", [
    lambda d: d.pop("packages"),
    lambda d: d.update(packages="not a section"),
    lambda d: d["packages"]["sources"].update(dpkg_info={"status": "permission_denied"}),
    lambda d: d["packages"].pop("sources"),
    lambda d: d["packages"]["sources"].update(dpkg_info="collected"),
])
def test_records_that_were_not_read_say_so(change):
    """An older agent sends no section, and a host whose file lists could not
    be read has no entries. Both read differently from not determined."""
    doc = report(SSH)
    change(doc)
    assert package_for_port(doc, "tcp", "v4", 22) == Unnamed(NOT_READ)


@pytest.mark.parametrize("doc", [None, [], "x", {}, {"sockets": "x"}, {"sockets": {"listening": [None, 3, "x"]}},
                                 {"containers": {"docker": [None, {"ports": [None, "x"]}]}}])
def test_a_malformed_report_answers_and_raises_nothing(doc):
    assert isinstance(package_for_port(doc, "tcp", "v4", 22), Unnamed)


def test_the_reasons_are_one_closed_list():
    assert packagerule.REASONS == (NO_UNIT, CONTAINER, NOT_READ, NOT_DETERMINED)
    with pytest.raises(ValueError):
        Unnamed("probably fine")


# ------------------------------------------------- the wrappers on the list

@pytest.mark.parametrize("entry, name, version", [
    (APACHE, "apache2", "2.4.68-1~deb12u1"),
    (NTPSEC, "ntpsec", "1.2.2+dfsg1-1+deb12u1"),
    (DNSMASQ, "dnsmasq", "2.90-4~deb12u2"),
])
def test_a_wrapper_on_the_list_names_the_scripts_package(entry, name, version):
    """Measured on Debian 12 and Ubuntu 24.04 on 2026-10-03 against the
    program that holds the socket: /usr/sbin/apache2, /usr/sbin/ntpd and
    /usr/sbin/dnsmasq each come from the source the script's package comes
    from, at the same version."""
    named = name_from_entry(entry)
    assert named is not None
    assert (named.name, named.source, named.version, named.source_version) == (name, name, version, version)


def test_the_list_is_the_three_measured_lines_and_nothing_else():
    """A line is added with its measurement and its day, never because a
    script looks like the others."""
    assert set(packagerule.KNOWN_WRAPPERS) == {
        ("apache2.service", "/usr/sbin/apachectl"),
        ("ntpsec.service", "/usr/libexec/ntpsec/ntp-systemd-wrapper"),
        ("dnsmasq.service", "/usr/share/dnsmasq/systemd-helper")}


def test_a_listed_wrapper_from_another_source_than_its_unit_file_names_nothing():
    other = changed(APACHE, "program", owners=[owner("apache2-utils", "2.4.68-1~deb12u1", "apache-tools")])
    assert name_from_entry(other) is None


def test_a_unit_on_the_list_that_starts_another_script_names_nothing():
    """The unit's name alone is not the measurement: somebody's own
    apache2.service that starts a script of theirs is not named."""
    for elsewhere in ("/usr/local/sbin/start-apache", "/usr/sbin/apache2ctl"):
        theirs = copy.deepcopy(APACHE)
        theirs["program"]["path"] = elsewhere
        assert name_from_entry(theirs) is None


def test_a_script_on_the_list_started_by_another_unit_names_nothing():
    assert name_from_entry(changed(APACHE, unit="my-site.service")) is None
    assert name_from_entry(changed(APACHE, unit="apache2@blue.service")) is None
    assert name_from_entry(changed(NTPSEC, unit="dnsmasq.service")) is None


def test_a_unit_on_the_list_that_starts_a_compiled_program_is_named_as_any_other_is():
    direct = changed(APACHE, program_kind="elf")
    direct["program"] = owned("/usr/sbin/apache2", owner("apache2-bin", "2.4.68-1~deb12u1", "apache2"))
    named = name_from_entry(direct)
    assert (named.name, named.source) == ("apache2-bin", "apache2")


def test_postgresqls_shape_is_named_by_nothing():
    """The shape the list exists to keep out: a unit and a script that both
    belong to a -common package, while the server is another source. Read
    as it would be if the agent sent the path after the "-" prefix. Naming
    it would name postgresql-common, and the security data files the
    server's CVEs under postgresql-15."""
    with_its_path = {
        "unit": "postgresql@15-main.service", "finding": "complete",
        "unit_file": owned("/usr/lib/systemd/system/postgresql@.service",
                           owner("postgresql-common", "248", arch="all")),
        "program": owned("/usr/bin/pg_ctlcluster", owner("postgresql-common", "248", arch="all")),
        "program_kind": "script"}
    assert name_from_entry(with_its_path) is None


@pytest.mark.parametrize("break_it", [
    lambda e: e["program"].update(owners=[]),
    lambda e: e["program"].update(owners=e["program"]["owners"] * 2),
    lambda e: e["program"].update(diverted=True),
    lambda e: e["unit_file"].update(diverted=True),
    lambda e: e["program"]["owners"][0].update(installed=False),
    lambda e: e["program"]["owners"][0].update(version="2.4.68-"),
    lambda e: e.update(finding="over_cap"),
    lambda e: e.update(program_kind="other"),
])
def test_a_listed_wrapper_still_needs_every_other_link_to_hold(break_it):
    entry = copy.deepcopy(APACHE)
    break_it(entry)
    assert name_from_entry(entry) is None


def test_a_port_behind_a_listed_wrapper_names_its_package():
    doc = report(APACHE, sockets=[{"protocol": "tcp", "family": "v4", "port": 80,
                                    "cgroup": "/system.slice/apache2.service", "unit": "apache2.service"}])
    answer = package_for_port(doc, "tcp", "v4", 80)
    assert isinstance(answer, packagerule.Named) and answer.source == "apache2"

