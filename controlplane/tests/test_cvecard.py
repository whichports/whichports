"""What a port's card says about CVEs, line by line, and when the check's
own mark stands.

    python -m pytest tests/test_cvecard.py

`docs/SPEC-cve-check.md`, sections 3 and 8.1. The words are the ones drawn
for him on 2026-10-07 and said yes to (`docs/RECORD.md` 4.437 and 4.446).
The server and the CVE numbers are made up, the versions are those of the
installs measured on 2026-10-06.
"""
from datetime import datetime, timezone

import pytest

from app import cvecard, cveextract, cvematch, cvestore
from app.cvecard import Card, Line, card_for
from app.cveextract import Row

NOW = datetime(2026, 10, 4, 9, 0, tzinfo=timezone.utc)
DATA_OF = "Debian security tracker, 2026-10-03 14:07 UTC"
ROWS = [
    Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),
    Row("openssh", "CVE-2025-00002", "1:9.2p1-2+deb12u8", "low"),
    Row("openssh", "CVE-2026-00003", "1:9.2p1-2+deb12u10", "low"),
    Row("nginx", "CVE-2026-00004", "1.22.1-9+deb12u10", "low"),
]


def stored(rows=ROWS, modified="2026-10-03T14:07:28Z", distribution="debian", version_id="12", built=""):
    header = cveextract.Header(distribution, version_id, True, modified, built)
    return cvestore.Stored(header, cvematch.by_source(rows))


def extracts(*kept):
    """What `cvestore.read` would answer, from extracts made for the test."""
    by_release = {(s.header.distribution, s.header.version_id): s for s in kept}
    return lambda distribution, version_id: by_release.get((distribution, version_id))


def owner(name, version, source=None, arch="arm64"):
    out = {"name": name, "architecture": arch, "installed": True, "version": version}
    if source:
        out["source"] = source
    return out


def unit(name, program, package):
    return {"unit": name, "finding": "complete", "program_kind": "elf",
            "unit_file": {"path": "/usr/lib/systemd/system/" + name, "owners": [package]},
            "program": {"path": program, "owners": [package]}}


SSH = unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.2p1-2+deb12u3", "openssh"))
NGINX = unit("nginx.service", "/usr/sbin/nginx", owner("nginx", "1.22.1-9"))
MARIADB = unit("mariadb.service", "/usr/sbin/mariadbd",
               owner("mariadb-server", "1:11.4.13+maria~deb12", "mariadb"))
POSTGRES = {"unit": "postgresql@15-main.service", "finding": "exec_start_prefixed",
            "unit_file": {"path": "/usr/lib/systemd/system/postgresql@.service",
                          "owners": [owner("postgresql-common", "248", arch="all")]}}
PORTS = {22: "ssh.service", 80: "nginx.service", 3306: "mariadb.service",
         5432: "postgresql@15-main.service"}


def offer(version, archive="debian", flagged=False):
    return {"version": version, "archive": archive,
            "not_automatic": flagged, "but_automatic_upgrades": flagged}


def offers(name, *offered, other=False, other_installed=False):
    return {"name": name, "offered": list(offered),
            "other_offers": other, "other_offers_installed": other_installed}


# The three cases as they were drawn, each on a port of its own.
OFFERS = (
    offers("openssh-server", offer("1:9.2p1-2+deb12u10"), offer("1:9.2p1-2+deb12u9", "debian-security")),
    offers("nginx", offer("1.22.1-9")),
    offers("mariadb-server", offer("1:10.11.14-0+deb12u2"), other=True, other_installed=True),
)


def report(*entries, lists="collected", distribution=None, units=(SSH, NGINX, MARIADB, POSTGRES)):
    listening = [{"protocol": "tcp", "family": "v4", "port": port,
                  "cgroup": "/system.slice/" + name, "unit": name} for port, name in PORTS.items()]
    listening.append({"protocol": "tcp", "family": "v4", "port": 8080, "cgroup": "/docker/abc", "unit": ""})
    return {"schema_version": 1, "hostname": "web-07",
            "sockets": {"status": "collected", "listening": listening},
            "packages": {"status": "collected",
                         "sources": {"dpkg_info": {"status": "collected"}, "apt_lists": {"status": lists}},
                         "distribution": distribution or {"id": "debian", "version_id": "12",
                                                          "version_codename": "bookworm"},
                         "units": list(units), "offers": list(entries or OFFERS)}}


def card(port, doc=None, kept=None, now=NOW):
    return card_for(doc or report(), "tcp", "v4", port, extracts(*(kept or [stored()])), now)


# --------------------------------------------------- the cases as drawn

def test_an_update_the_lists_offer_is_drawn_with_its_cves():
    assert card(22) == Card(
        lines=(Line("installed", "openssh-server 1:9.2p1-2+deb12u3"),
               Line("update fixes", "3 CVEs in source package openssh",
                    ids=("CVE-2025-00001", "CVE-2025-00002", "CVE-2026-00003")),
               Line("update to", "1:9.2p1-2+deb12u10", note="in this server's package lists"),
               Line("data of", DATA_OF)),
        mark="an update fixes 3 CVEs",
        cves=("CVE-2025-00001", "CVE-2025-00002", "CVE-2026-00003"))


def test_a_fix_the_lists_do_not_offer_says_what_was_read_and_names_no_cause():
    got = card(80)
    assert got.lines == (
        Line("installed", "nginx 1.22.1-9"),
        Line("fixed in", "1.22.1-9+deb12u10", note="not offered by this server's package lists"),
        Line("it fixes", "1 CVE in source package nginx", ids=("CVE-2026-00004",)),
        Line("data of", DATA_OF))
    assert got.mark == "a newer version fixes 1 CVE"
    said = " ".join(line.value + " " + line.note for line in got.lines)
    for cause in ("older", "yet", "stale", "out of date", "outdated", "not fetched"):
        assert cause not in said


def test_a_card_with_both_groups_holds_the_offered_one_first():
    lists = report(offers("openssh-server", offer("1:9.2p1-2+deb12u8")))
    got = card(22, lists)
    assert got.lines == (
        Line("installed", "openssh-server 1:9.2p1-2+deb12u3"),
        Line("update fixes", "2 CVEs in source package openssh", ids=("CVE-2025-00001", "CVE-2025-00002")),
        Line("update to", "1:9.2p1-2+deb12u8", note="in this server's package lists"),
        Line("fixed in", "1:9.2p1-2+deb12u10", note="not offered by this server's package lists"),
        Line("it fixes", "1 CVE in source package openssh", ids=("CVE-2026-00003",)),
        Line("data of", DATA_OF))
    # The mark's words hold for both groups, and it stands for all three.
    assert got.mark == "a newer version fixes 3 CVEs"
    assert got.cves == ("CVE-2025-00001", "CVE-2025-00002", "CVE-2026-00003")


def test_another_archives_package_is_not_checked_and_says_whose_it_is_not():
    assert card(3306) == Card(lines=(
        Line("installed", "mariadb-server 1:11.4.13+maria~deb12", note="not the distribution's package"),
        Line("update fixes", "not checked")))


def test_a_fully_updated_package_reads_none_with_whose_data_it_is():
    updated = unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.2p1-2+deb12u10", "openssh"))
    got = card(22, report(units=(updated, NGINX, MARIADB, POSTGRES)))
    assert got == Card(lines=(Line("installed", "openssh-server 1:9.2p1-2+deb12u10"),
                              Line("update fixes", "none"),
                              Line("data of", DATA_OF)))


# -------------------------------------------- not checked is never none

def not_checked(got):
    return got.lines[-1] == Line("update fixes", "not checked") and got.mark == "" and got.cves == ()


def test_a_port_with_no_package_named_says_which_and_is_not_checked():
    """PostgreSQL is `package not determined`. A container's port, and a
    port with no unit behind it, read `unknown`."""
    assert card(5432) == Card(lines=(Line("installed", "package not determined"),
                                     Line("update fixes", "not checked")))
    assert card(8080) == Card(lines=(Line("installed", "unknown"), Line("update fixes", "not checked")))
    assert card(9999) == Card(lines=(Line("installed", "unknown"), Line("update fixes", "not checked")))


def test_a_program_installed_by_hand_under_a_unit_reads_package_not_determined():
    """The second big test, finding G6: listeners copied by hand and run
    under systemd units read `package not determined`, where the spec said
    `unknown`. The card is right and the spec was put right: a system
    service unit holds the port, so the reason is that no package was
    named for it, whether its unit file and program belong to no package
    or the agent sent no entry for the unit at all, as for a transient unit
    `systemd-run` writes under /run/systemd/transient. `unknown` stays for a
    container's port, a port with no unit and records that were not read."""
    by_hand = {"unit": "tool.service", "finding": "complete", "program_kind": "elf",
               "unit_file": {"path": "/etc/systemd/system/tool.service", "owners": []},
               "program": {"path": "/usr/local/bin/tool", "owners": []}}
    doc = report(units=(SSH, NGINX, MARIADB, POSTGRES, by_hand))
    for port, name in ((7000, "tool.service"), (7001, "tool-3030.service")):
        doc["sockets"]["listening"].append({"protocol": "tcp", "family": "v4", "port": port,
                                            "cgroup": "/system.slice/" + name, "unit": name})
        assert card(port, doc) == Card(lines=(Line("installed", "package not determined"),
                                              Line("update fixes", "not checked"))), port


@pytest.mark.parametrize("lists", ["read_error", "permission_denied", "not_present", "not_collected"])
def test_lists_that_were_not_read_are_not_checked_and_never_none(lists):
    got = card(22, report(lists=lists))
    assert got.lines[0] == Line("installed", "openssh-server 1:9.2p1-2+deb12u3", note="package lists not read")
    assert not_checked(got)


def test_a_package_in_no_list_says_that():
    got = card(22, report(offers("openssh-server")))
    assert got.lines[0].note == "not in this server's package lists" and not_checked(got)


def test_a_release_with_no_data_says_so():
    """A release the check keeps no extract for, and one whose extract is
    not there."""
    bullseye = {"id": "debian", "version_id": "11", "version_codename": "bullseye"}
    for got in (card(22, report(distribution=bullseye)), card(22, kept=[stored(version_id="13")])):
        assert got.lines[0] == Line("installed", "openssh-server 1:9.2p1-2+deb12u3",
                                    note="no security data for this release")
        assert not_checked(got)


def test_an_extract_older_than_three_days_reads_not_checked_and_never_none():
    """Data that old may lack the fix that came out since, so a clean port
    would be a guess. Three days and a minute is old, three days is not."""
    updated = unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.2p1-2+deb12u10", "openssh"))
    doc = report(units=(updated, NGINX, MARIADB, POSTGRES))
    old = card(22, doc, now=datetime(2026, 10, 6, 14, 8, 28, tzinfo=timezone.utc))
    assert old.lines[0] == Line("installed", "openssh-server 1:9.2p1-2+deb12u10", note="security data 3 days old")
    assert not_checked(old)
    edge = card(22, doc, now=datetime(2026, 10, 6, 14, 7, 28, tzinfo=timezone.utc))
    assert edge.lines[1] == Line("update fixes", "none")


def test_old_data_draws_no_mark_and_says_how_old():
    got = card(22, now=datetime(2026, 10, 8, 15, 0, tzinfo=timezone.utc))
    assert got.lines[0].note == "security data 5 days old"
    assert not_checked(got)


@pytest.mark.parametrize("modified", ["", "yesterday", "2026-10-03", "2026-13-40T99:00:00Z"])
def test_data_that_does_not_say_how_old_it_is_is_not_checked(modified):
    got = card(22, kept=[stored(modified=modified)])
    assert got.lines[0].note == "security data of unknown age" and not_checked(got)


def test_data_from_after_now_is_not_old():
    """A control plane whose clock runs behind the builder's."""
    assert card(22, now=datetime(2026, 10, 3, 14, 0, tzinfo=timezone.utc)).mark == "an update fixes 3 CVEs"


# ------------------------------------------------------------- the words

def test_ubuntus_data_is_named_as_ubuntus():
    ssh = unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh", "amd64"))
    noble = {"id": "ubuntu", "version_id": "24.04", "version_codename": "noble"}
    doc = report(offers("openssh-server", offer("1:9.6p1-3ubuntu13.19", "ubuntu")),
                 distribution=noble, units=(ssh,))
    kept = stored([Row("openssh", "CVE-2026-00005", "1:9.6p1-3ubuntu13.19", "medium")],
                  modified="2026-10-02T18:10:09Z", distribution="ubuntu", version_id="24.04")
    got = card(22, doc, [kept])
    assert got.lines[-1] == Line("data of", "Ubuntu security data, 2026-10-02 18:10 UTC",
                                 note="by Canonical, adapted, CC BY-SA 4.0")
    assert got.mark == "an update fixes 1 CVE"


def test_a_card_of_ubuntus_data_says_whose_it_is_and_under_which_licence():
    """Canonical publishes its OSV data under CC BY-SA 4.0 (the README of
    github.com/canonical/ubuntu-security-notices, which the OSV page links,
    read 2026-10-14). Its section 3(a) asks whoever shares the data for the
    source, a note that it was changed, and the licence with its link. A
    card showing Ubuntu's CVEs shares them, so its data line says all three,
    and the source and the licence are links."""
    ssh = unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh", "amd64"))
    noble = {"id": "ubuntu", "version_id": "24.04", "version_codename": "noble"}
    doc = report(offers("openssh-server", offer("1:9.6p1-3ubuntu13.19", "ubuntu")), distribution=noble, units=(ssh,))
    kept = stored([Row("openssh", "CVE-2026-00005", "1:9.6p1-3ubuntu13.19", "medium")],
                  modified="2026-10-02T18:10:09Z", distribution="ubuntu", version_id="24.04")
    got = card(22, doc, [kept])
    assert got.links == (("Ubuntu security data", "https://security-metadata.canonical.com/osv/"),
                         ("CC BY-SA 4.0", "https://creativecommons.org/licenses/by-sa/4.0/"))
    # Each linked text stands on the line it links.
    shown = got.lines[-1].value + " " + got.lines[-1].note
    assert all(text in shown for text, _url in got.links)
    # A card with none of Ubuntu's data carries no such line and no link.
    assert card(22).lines[-1].note == "" and card(22).links == ()
    month = datetime(2026, 9, 4, 9, 0, tzinfo=timezone.utc)
    old = cvecard.cards_of(doc, extracts(kept), NOW, reported_at=month)[("tcp", 22)]
    assert not old.checked and old.links == ()


def every_card():
    yield from (card(port) for port in (22, 80, 3306, 5432, 8080))
    yield card(22, report(lists="read_error"))
    yield card(22, report(offers("openssh-server", offer("1:9.2p1-2+deb12u8"))))
    yield card(22, now=datetime(2026, 10, 9, tzinfo=timezone.utc))


def test_the_card_says_installed_and_no_card_says_running():
    """The version is the installed one. Nothing here measured what runs or
    what answers, and no word of ours is said about the server's condition."""
    banned = ("running", "answers", "vulnerable", "secure", "safe", "at risk", "patched", "critical",
              "severity", "score", "exposed")
    for got in every_card():
        assert got.lines[0].label == "installed"
        text = " ".join(f"{line.label} {line.value} {line.note}" for line in got.lines) + " " + got.mark
        for word in banned:
            assert word not in text.lower(), (word, text)


def test_not_checked_and_none_are_two_values_on_every_card():
    values = [line.value for got in every_card() for line in got.lines if line.label == "update fixes"]
    assert "not checked" in values and "none" not in values
    assert cvecard.NOT_CHECKED != cvecard.NONE


def test_one_cve_is_said_in_the_singular():
    assert cvecard.count_of(1) == "1 CVE" and cvecard.count_of(2) == "2 CVEs"


def test_a_card_is_worked_out_and_changes_nothing():
    """The same report and the same data give the same card, and neither is
    touched: nothing about a match is kept anywhere."""
    doc, kept = report(), stored()
    before = repr(doc), repr(kept)
    assert card(22, doc, [kept]) == card(22, doc, [kept])
    assert (repr(doc), repr(kept)) == before


# -------------------------------------------------------- a whole server

def test_a_servers_mark_counts_each_cve_of_its_ports_once():
    both = report(offers("openssh-server", offer("1:9.2p1-2+deb12u10")), offers("nginx", offer("1.22.1-9")),
                  OFFERS[2])
    cards = [card(port, both) for port in (22, 80, 3306, 5432)]
    assert cvecard.server_mark(cards) == "a newer version fixes 4 CVEs"
    assert cvecard.server_mark([cards[0]]) == "an update fixes 3 CVEs"
    assert cvecard.server_mark([cards[0], cards[0]]) == "an update fixes 3 CVEs"
    assert cvecard.server_mark(cards[2:]) == "" and cvecard.server_mark([]) == ""


# ------------------------------------------------- every port of a report

def test_a_report_with_no_packages_section_has_no_card_at_all():
    """Every report of the published agent. Not a card that says unknown for
    every port of every server."""
    old = report()
    del old["packages"]
    assert cvecard.cards_of(old, extracts(stored()), NOW) == {}
    for broken in ({}, None, "a report", {"packages": "collected"}):
        assert cvecard.cards_of(broken, extracts(stored()), NOW) == {}


def test_every_listening_port_has_one_card():
    cards = cvecard.cards_of(report(), extracts(stored()), NOW)
    assert sorted(cards) == [("tcp", 22), ("tcp", 80), ("tcp", 3306), ("tcp", 5432), ("tcp", 8080)]
    assert cards[("tcp", 22)] == card(22) and cards[("tcp", 8080)] == card(8080)


def test_a_port_bound_over_ipv6_alone_is_asked_about_over_ipv6():
    """Its IPv4 socket does not exist, so over IPv4 there is no unit behind
    the port and the answer would be unknown."""
    doc = report()
    for sock in doc["sockets"]["listening"]:
        if sock["port"] == 22:
            sock["family"] = "v6"
    cards = cvecard.cards_of(doc, extracts(stored()), NOW)
    assert cards[("tcp", 22)].mark == "an update fixes 3 CVEs"
    # And a port on both families is one card, the same one.
    doc["sockets"]["listening"].append({"protocol": "tcp", "family": "v4", "port": 22,
                                        "cgroup": "/system.slice/ssh.service", "unit": "ssh.service"})
    assert cvecard.cards_of(doc, extracts(stored()), NOW)[("tcp", 22)].mark == "an update fixes 3 CVEs"


def test_a_socket_that_names_no_port_is_no_card():
    doc = report()
    doc["sockets"]["listening"] += [{"protocol": "tcp", "family": "v4", "port": "22"},
                                    {"protocol": 6, "family": "v4", "port": 23}, "a socket", None]
    assert sorted(cvecard.cards_of(doc, extracts(stored()), NOW)) == [
        ("tcp", 22), ("tcp", 80), ("tcp", 3306), ("tcp", 5432), ("tcp", 8080)]


def test_a_card_says_which_cves_the_lists_do_not_offer_a_fix_for():
    """What a message needs to know before it says "an update"."""
    assert card(22).apart == () and card(80).apart == ("CVE-2026-00004",)
    both = card(22, report(offers("openssh-server", offer("1:9.2p1-2+deb12u8"))))
    assert both.apart == ("CVE-2026-00003",) and set(both.apart) < set(both.cves)


# ------------------------------------------- found by the challenge, 2026-10-11

def test_a_port_two_packages_hold_is_not_checked_and_says_so():
    """nginx over IPv4 with every update installed, Apache over IPv6 behind
    on one. One strip cannot say both, and `none` for the first would be
    silent about the second."""
    doc = report(offers("nginx", offer("1.22.1-9+deb12u10")), offers("apache2-bin", offer("2.4.68-1~deb12u1")),
                 units=(unit("nginx.service", "/usr/sbin/nginx", owner("nginx", "1.22.1-9+deb12u10")),
                        unit("apache2.service", "/usr/sbin/apache2", owner("apache2-bin", "2.4.62-1~deb12u1", "apache2"))))
    doc["sockets"]["listening"] = [
        {"protocol": "tcp", "family": "v4", "port": 80, "cgroup": "/system.slice/nginx.service", "unit": "nginx.service"},
        {"protocol": "tcp", "family": "v6", "port": 80, "cgroup": "/system.slice/apache2.service", "unit": "apache2.service"}]
    got = cvecard.cards_of(doc, extracts(stored()), NOW)[("tcp", 80)]
    assert got == Card(lines=(Line("installed", "two packages hold this port"), Line("update fixes", "not checked")))
    # The same package over both families is one package and one card.
    doc["sockets"]["listening"][1].update(cgroup="/system.slice/nginx.service", unit="nginx.service")
    assert cvecard.cards_of(doc, extracts(stored()), NOW)[("tcp", 80)].lines[0] == Line(
        "installed", "nginx 1.22.1-9+deb12u10")


# ------------------------------------------- the second challenge, 2026-10-12

def test_a_count_on_the_card_names_the_source_package_it_is_counted_for():
    """The data names a source package and no binary. openssh-server is one
    of the binary packages of the source openssh, and Debian's own text
    places some of that source's CVEs in `ssh` and `scp`. So every line
    with a count says whose CVEs they are, and the first line still says
    what is installed."""
    both = card(22, report(offers("openssh-server", offer("1:9.2p1-2+deb12u8"))))
    assert both.lines[0] == Line("installed", "openssh-server 1:9.2p1-2+deb12u3")
    counted = [line.value for line in both.lines if line.ids]
    assert counted == ["2 CVEs in source package openssh", "1 CVE in source package openssh"]
    # The mark says what an update does and names no program.
    assert both.mark == "a newer version fixes 3 CVEs"



def _port_53(bind9="1:9.18.33-1~deb12u2", offered="1:9.18.33-1~deb12u2"):
    """Port 53: over IPv4 two units hold it, so no one unit is behind it
    there, and over IPv6 bind9 alone."""
    doc = report(offers("bind9", offer(offered)),
                 units=(unit("named.service", "/usr/sbin/named", owner("bind9", bind9)),))
    over = lambda family, name: {"protocol": "udp", "family": family, "port": 53,  # noqa: E731
                                 "cgroup": f"/system.slice/{name}", "unit": name}
    doc["sockets"]["listening"] = [over("v4", "named.service"), over("v4", "dnsmasq.service"),
                                   over("v6", "named.service")]
    return doc


def test_a_port_a_package_holds_over_one_family_only_never_reads_none():
    """bind9 has every update installed. `none` for the port would be silent
    about whatever else holds it over IPv4, which nothing named."""
    got = cvecard.cards_of(_port_53(), extracts(stored()), NOW)[("udp", 53)]
    assert got == Card(lines=(
        Line("installed", "bind9 1:9.18.33-1~deb12u2", note="another program also holds this port"),
        Line("update fixes", "not checked")))
    assert not got.checked and not got.mark
    # Over IPv6 alone the same package is the port's and it is checked.
    alone = _port_53()
    alone["sockets"]["listening"] = alone["sockets"]["listening"][2:]
    assert cvecard.cards_of(alone, extracts(stored()), NOW)[("udp", 53)].lines[-2:] == (
        Line("update fixes", "none"), Line("data of", "Debian security tracker, 2026-10-03 14:07 UTC"))


def test_a_port_held_in_part_by_something_unnamed_draws_no_mark_either():
    """The same port with bind9 behind on an update. One strip cannot say a
    package's CVEs for a port that is not that package's alone."""
    rows = [Row("bind9", "CVE-2026-00031", "1:9.18.41-1~deb12u1", "low")]
    doc = _port_53(offered="1:9.18.41-1~deb12u1")
    got = cvecard.cards_of(doc, extracts(stored(rows=rows)), NOW)[("udp", 53)]
    assert got.lines[-1] == Line("update fixes", "not checked") and not got.mark and not got.cves
    assert got.lines[0].note == "another program also holds this port"


def test_a_package_that_is_not_checked_anyway_keeps_its_own_reason():
    month = datetime(2026, 9, 4, 9, 0, tzinfo=timezone.utc)
    got = cvecard.cards_of(_port_53(), extracts(stored()), NOW, reported_at=month)[("udp", 53)]
    assert got.lines[0] == Line("installed", "bind9 1:9.18.33-1~deb12u2", note="report 30 days old")


def test_a_vendor_file_that_did_not_change_over_a_weekend_is_not_old_data():
    """Canonical's file last changed on Friday 2026-10-09 at 18:41:58 UTC and
    next on Monday 2026-10-12 at 06:13:45 UTC, both read from its own
    Last-Modified. The daily job runs at 04:41 UTC, so Monday's extract is
    built from Friday's file, and at 18:41:58 UTC that file is three days
    old. Held against the vendor's stamp every port of the release read not
    checked from then until Tuesday's job. The data is not old: it was
    fetched that morning and is the newest the vendor has."""
    monday_evening = datetime(2026, 10, 12, 19, 0, tzinfo=timezone.utc)
    weekend = stored(modified="2026-10-09T18:41:58Z", built="2026-10-12T04:41:00Z")
    got = cvecard.cards_of(report(), extracts(weekend), monday_evening,
                           reported_at=monday_evening)[("tcp", 22)]
    assert got.mark == "an update fixes 3 CVEs" and got.checked
    # The card still says whose data it is and when the vendor last changed it.
    assert got.lines[-1] == Line("data of", "Debian security tracker, 2026-10-09 18:41 UTC")


def test_an_extract_not_built_for_more_than_three_days_is_old_data():
    """The daily job failed since Thursday. What a fix published since would
    say is not in the file, so no port of the release reads none."""
    monday_evening = datetime(2026, 10, 12, 19, 0, tzinfo=timezone.utc)
    stale = stored(modified="2026-10-08T03:00:00Z", built="2026-10-08T04:41:00Z")
    for port, got in cvecard.cards_of(report(), extracts(stale), monday_evening,
                                      reported_at=monday_evening).items():
        assert not got.checked and not got.mark, port
    assert cvecard.cards_of(report(), extracts(stale), monday_evening, reported_at=monday_evening)[
        ("tcp", 22)].lines[0].note == "security data 4 days old"


def test_an_extract_that_does_not_say_when_it_was_built_is_held_to_the_vendors_stamp():
    """An extract built from files on disk says no build time
    (`cveextract_cli`), and the vendor's stamp is then the newest thing
    known about it."""
    monday_evening = datetime(2026, 10, 12, 19, 0, tzinfo=timezone.utc)
    got = cvecard.cards_of(report(), extracts(stored(modified="2026-10-09T18:41:58Z")), monday_evening,
                           reported_at=monday_evening)[("tcp", 22)]
    assert got.lines[0].note == "security data 3 days old" and not got.checked


def test_a_report_older_than_three_days_is_not_checked_and_never_none():
    """What is installed today was not read. The report says what was
    installed then."""
    updated = unit("ssh.service", "/usr/sbin/sshd", owner("openssh-server", "1:9.2p1-2+deb12u10", "openssh"))
    doc = report(units=(updated, NGINX, MARIADB, POSTGRES))
    month = datetime(2026, 9, 4, 9, 0, tzinfo=timezone.utc)
    old = cvecard.cards_of(doc, extracts(stored()), NOW, reported_at=month)
    assert old[("tcp", 22)] == Card(lines=(
        Line("installed", "openssh-server 1:9.2p1-2+deb12u10", note="report 30 days old"),
        Line("update fixes", "not checked")))
    assert all(not got.mark and not got.checked for got in old.values())
    # A port with no package named says what it said: there is nothing of a
    # report's age to add to "unknown".
    assert old[("tcp", 8080)].lines[0] == Line("installed", "unknown")
    fresh = cvecard.cards_of(doc, extracts(stored()), NOW, reported_at=datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc))
    assert fresh[("tcp", 22)].lines[1] == Line("update fixes", "none")


def test_an_extract_with_no_row_in_it_is_no_data():
    got = card(22, kept=[stored(rows=[])])
    assert got.lines[0].note == "no security data for this release" and not_checked(got)
