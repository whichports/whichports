"""The rule that holds a named package against its release's security data
and against what the server's own package lists offer.

    python -m pytest tests/test_offerrule.py

`docs/SPEC-cve-check.md`, section 8.1, point 2. The cases are the eight rows
measured on six installs on 2026-10-06 (`docs/RECORD.md` 4.418), with the
versions those installs had, and the four that were only reasoned on paper.
The CVE numbers are made up. Most of this file is about when nothing may be
said.
"""
import pytest

from app import cveextract, cvematch, offerrule
from app.cveextract import Row
from app.offerrule import (ANOTHER_ARCHIVE_OFFERS, LISTS_NOT_READ, NEWER_THAN_THE_LISTS, NOT_IN_THE_LISTS,
                           NOT_THE_DISTRIBUTIONS, VERSION_NOT_COMPARABLE, Checked, NotChecked, held)
from app.packagerule import Named

OPENSSH = Named("openssh-server", "1:9.2p1-2+deb12u3", "openssh", "1:9.2p1-2+deb12u3", "arm64")
# Four CVEs fixed up to u8 and two after it, the shape of the real ten.
ROWS = [
    Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),
    Row("openssh", "CVE-2025-00002", "1:9.2p1-2+deb12u6", "low"),
    Row("openssh", "CVE-2025-00003", "1:9.2p1-2+deb12u8", "low"),
    Row("openssh", "CVE-2025-00004", "1:9.2p1-2+deb12u8", "low"),
    Row("openssh", "CVE-2026-00005", "1:9.2p1-2+deb12u9", "low"),
    Row("openssh", "CVE-2026-00006", "1:9.2p1-2+deb12u10", "low"),
    # Fixed long before the installed version, so never open.
    Row("openssh", "CVE-2023-00007", "1:9.2p1-2+deb12u2", "low"),
    Row("nginx", "CVE-2026-00008", "1.22.1-9+deb12u10", "low"),
    Row("smartmontools", "CVE-2026-00009", "7.3-2", "low"),
]
INDEX = cvematch.by_source(ROWS)
DEBIAN = {"id": "debian", "version_id": "12", "version_codename": "bookworm"}
UBUNTU = {"id": "ubuntu", "version_id": "24.04", "version_codename": "noble"}


def offer(version, archive="debian", flagged=False):
    return {"version": version, "archive": archive,
            "not_automatic": flagged, "but_automatic_upgrades": flagged}


def offers(name, *offered, other=False, other_installed=False, **more):
    entry = {"name": name, "offered": list(offered),
             "other_offers": other, "other_offers_installed": other_installed}
    entry.update(more)
    return entry


def doc(*entries, lists="collected", distribution=DEBIAN, **more):
    """A report's packages section, with the offers the agent's lists reader
    sends (agent/internal/hostdoc/packages.go, `Offers`)."""
    section = {"status": "collected", "distribution": distribution,
               "sources": {"apt_lists": {"status": lists}}, "offers": list(entries)}
    section.update(more)
    return {"packages": section}


def cves(matches):
    return [m.cve for m in matches]


# What apt itself printed on the Debian 12 install that was behind on its
# updates: u10 from the release, u9 from security, u7 from updates.
BEHIND = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10"), offer("1:9.2p1-2+deb12u7"),
                    offer("1:9.2p1-2+deb12u9", "debian-security")))


# ------------------------------------------------------------- what is drawn

def test_a_package_behind_on_updates_whose_lists_offer_the_fix_is_drawn():
    got = held(BEHIND, OPENSSH, INDEX)
    assert isinstance(got, Checked)
    assert cves(got.update_fixes) == ["CVE-2025-00001", "CVE-2025-00002", "CVE-2025-00003",
                                      "CVE-2025-00004", "CVE-2026-00005", "CVE-2026-00006"]
    assert got.update_to == "1:9.2p1-2+deb12u10"
    assert got.not_offered == () and got.fixed_in == ""


def test_a_fix_the_lists_do_not_offer_is_said_and_not_left_out():
    """The lists offer u8 and nothing newer. What was read is that, and it is
    said as that: four CVEs the lists' update fixes, two it does not, and the
    version that fixes those two."""
    stale = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u8"), offer("1:9.2p1-2+deb12u7")))
    got = held(stale, OPENSSH, INDEX)
    assert cves(got.update_fixes) == ["CVE-2025-00001", "CVE-2025-00002", "CVE-2025-00003", "CVE-2025-00004"]
    assert got.update_to == "1:9.2p1-2+deb12u8"
    assert cves(got.not_offered) == ["CVE-2026-00005", "CVE-2026-00006"]
    assert got.fixed_in == "1:9.2p1-2+deb12u10"


def test_when_the_lists_offer_no_fix_at_all_every_cve_is_in_the_second_group():
    """The lists offer the installed version itself and nothing newer."""
    got = held(doc(offers("openssh-server", offer("1:9.2p1-2+deb12u3"))), OPENSSH, INDEX)
    assert got.update_fixes == () and got.update_to == "1:9.2p1-2+deb12u3"
    assert len(got.not_offered) == 6 and got.fixed_in == "1:9.2p1-2+deb12u10"


def test_none_is_what_a_fully_updated_package_reads():
    updated = Named("openssh-server", "1:9.2p1-2+deb12u10", "openssh", "1:9.2p1-2+deb12u10", "arm64")
    got = held(BEHIND, updated, INDEX)
    assert got == Checked(update_fixes=(), update_to="1:9.2p1-2+deb12u10", not_offered=(), fixed_in="")
    assert got.none


def test_none_is_not_what_a_package_with_open_cves_reads():
    assert not held(BEHIND, OPENSSH, INDEX).none


def test_older_and_newer_are_debians_ordering():
    """u10 is newer than u9, and the highest offer is not the last one."""
    got = held(doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10"), offer("1:9.2p1-2+deb12u9"))),
               OPENSSH, INDEX)
    assert got.update_to == "1:9.2p1-2+deb12u10" and got.not_offered == ()


def test_a_row_with_no_fixed_version_is_in_neither_group():
    """An extract built to keep the CVEs no update fixes holds such rows. No
    update fixes them, so the rule says nothing of them."""
    index = cvematch.by_source(ROWS + [Row("openssh", "CVE-2026-00099", "", "low")])
    got = held(BEHIND, OPENSSH, index)
    assert "CVE-2026-00099" not in cves(got.update_fixes) + cves(got.not_offered)


# ------------------------------------------------- not the distribution's own

def test_a_version_another_archive_offers_is_not_checked():
    """nginx.org's nginx, MariaDB's own MariaDB: the installed version is one
    another archive offers and none of the distribution's does."""
    nginx = Named("nginx", "1.30.5-1~bookworm", "nginx", "1.30.5-1~bookworm", "arm64")
    theirs = doc(offers("nginx", offer("1.22.1-9+deb12u10", "debian-security"), other=True, other_installed=True))
    assert held(theirs, nginx, INDEX) == NotChecked(NOT_THE_DISTRIBUTIONS)


def test_a_version_above_everything_the_distribution_offers_is_not_checked():
    """The same nginx after its archive was taken off the server: no list
    holds the installed version, and it stands above all the distribution
    offers. Until the challenge of 2026-10-11 this read `not the
    distribution's package`, which names a cause nobody read: the
    distribution's own security build reads the same way on a server whose
    lists hold the release alone."""
    nginx = Named("nginx", "1.30.5-1~bookworm", "nginx", "1.30.5-1~bookworm", "arm64")
    gone = doc(offers("nginx", offer("1.22.1-9+deb12u10", "debian-security")))
    assert held(gone, nginx, INDEX) == NotChecked(NEWER_THAN_THE_LISTS)


def test_another_archives_build_is_not_checked_though_the_distribution_offers_a_newer_one():
    """The third condition alone. Another archive's build that is older than
    what the distribution offers would pass every other test, and every CVE
    the distribution fixed since would be said of a build that is not the
    distribution's."""
    theirs = Named("nginx", "1.20.2-1~theirs", "nginx", "1.20.2-1~theirs", "arm64")
    lists = doc(offers("nginx", offer("1.22.1-9+deb12u10", "debian-security"), other=True, other_installed=True))
    assert held(lists, theirs, INDEX) == NotChecked(NOT_THE_DISTRIBUTIONS)
    # And when that archive no longer lists the installed version, whose
    # build it is cannot be told, and it is not checked either.
    unlisted = doc(offers("nginx", offer("1.22.1-9+deb12u10", "debian-security"), other=True))
    assert held(unlisted, theirs, INDEX) == NotChecked(ANOTHER_ARCHIVE_OFFERS)
    # And the same from a flagged archive of the distribution's own.
    flagged = doc(offers("nginx", offer("1.22.1-9+deb12u10", "debian-security"),
                         offer("1.20.2-1~theirs", "debian", flagged=True)))
    assert held(flagged, theirs, INDEX) == NotChecked(NOT_THE_DISTRIBUTIONS)


def test_the_distributions_own_build_is_checked_beside_another_archive():
    """Proxmox's list offers Debian's own smartmontools beside its own. A
    server with Debian's build installed is held against Debian's data."""
    debians = Named("smartmontools", "7.3-1+b1", "smartmontools", "7.3-1", "arm64")
    both = doc(offers("smartmontools", offer("7.3-1+b1"), other=True, other_installed=True))
    got = held(both, debians, INDEX)
    assert isinstance(got, Checked) and cves(got.not_offered) == ["CVE-2026-00009"]
    proxmoxs = Named("smartmontools", "7.3-pve1", "smartmontools", "7.3-pve1", "arm64")
    assert held(both, proxmoxs, INDEX) == NotChecked(NOT_THE_DISTRIBUTIONS)


def test_a_backport_is_not_an_update():
    """Ubuntu's backports say they are Ubuntu's and carry both flags. What
    they offer is no update apt installs by itself, so it fixes nothing
    here, and a CVE only a backport fixes is not offered."""
    ssh = Named("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh", "1:9.6p1-3ubuntu13.5", "amd64")
    rows = cvematch.by_source([Row("openssh", "CVE-2026-00010", "1:9.6p1-3ubuntu13.19", "medium"),
                               Row("openssh", "CVE-2026-00011", "1:10.0p1-1", "medium")])
    noble = doc(offers("openssh-server", offer("1:9.6p1-3ubuntu13", "ubuntu"),
                       offer("1:9.6p1-3ubuntu13.19", "ubuntu"),
                       offer("1:10.0p1-1~bpo24.04.1", "ubuntu", flagged=True)), distribution=UBUNTU)
    got = held(noble, ssh, rows)
    assert got.update_to == "1:9.6p1-3ubuntu13.19"
    assert cves(got.update_fixes) == ["CVE-2026-00010"] and cves(got.not_offered) == ["CVE-2026-00011"]


@pytest.mark.parametrize("flags", [(True, True), (True, False), (False, True)])
def test_either_flag_makes_an_archive_a_flagged_one(flags):
    ssh = Named("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh", "1:9.6p1-3ubuntu13.5", "amd64")
    flagged = {"version": "1:9.6p1-3ubuntu13.19", "archive": "ubuntu",
               "not_automatic": flags[0], "but_automatic_upgrades": flags[1]}
    rows = cvematch.by_source([Row("openssh", "CVE-2026-00010", "1:9.6p1-3ubuntu13.19", "medium")])
    got = held(doc(offers("openssh-server", offer("1:9.6p1-3ubuntu13.5", "ubuntu"), flagged),
                   distribution=UBUNTU), ssh, rows)
    assert got.update_fixes == () and cves(got.not_offered) == ["CVE-2026-00010"]


def test_a_package_installed_from_a_backport_is_not_checked():
    """The installed version is one only a flagged archive offers."""
    curl = Named("curl", "8.14.1-2~bpo24.04.1", "curl", "8.14.1-2~bpo24.04.1", "amd64")
    noble = doc(offers("curl", offer("8.5.0-2ubuntu10.6", "ubuntu"),
                       offer("8.14.1-2~bpo24.04.1", "ubuntu", flagged=True)), distribution=UBUNTU)
    assert held(noble, curl, INDEX) == NotChecked(NOT_THE_DISTRIBUTIONS)


def test_a_package_another_archive_offers_and_the_distribution_does_not():
    """A package only another archive carries, at a version that archive no
    longer lists."""
    theirs = Named("caddy", "2.9.0", "caddy", "2.9.0", "amd64")
    assert held(doc(offers("caddy", other=True)), theirs, INDEX) == NotChecked(ANOTHER_ARCHIVE_OFFERS)


def test_a_package_no_list_offers_at_all_says_that_and_no_more():
    """Built in house and installed by hand, or the lists were emptied. What
    was read is that no list offers the package. Whose it is was not read."""
    theirs = Named("ourapp", "3.1-1", "ourapp", "3.1-1", "amd64")
    assert held(doc(offers("ourapp")), theirs, INDEX) == NotChecked(NOT_IN_THE_LISTS)


# -------------------------------------------- the binary's version, the source's

def test_a_rebuilt_binary_follows_its_source():
    """Debian rebuilds a binary without a new source and marks it `+b1`. Six
    of the 54 packages behind a listening service on the installs measured
    carry such a mark, and no other difference from their source's version."""
    rows = cvematch.by_source([Row("prometheus-node-exporter", "CVE-2026-00012", "1.5.0-1+deb12u1", "low")])
    lists = doc(offers("prometheus-node-exporter", offer("1.5.0-1+deb12u1")))
    # `+b` and a number, any number: Debian's own text gives +b1 and +b2
    # (Developer's Reference, read on 2026-10-11), and the installs showed +b6.
    for mark in ("+b1", "+b2", "+b6", "+b12"):
        exporter = Named("prometheus-node-exporter", "1.5.0-1" + mark, "prometheus-node-exporter", "1.5.0-1", "arm64")
        assert cves(held(lists, exporter, rows).update_fixes) == ["CVE-2026-00012"], mark


@pytest.mark.parametrize("binary,source", [("4:12.2.0-3", "1.203"), ("1.5.0-1+b", "1.5.0-1"),
                                           ("1.5.0-1+b6x", "1.5.0-1"), ("1.5.0-1+c1", "1.5.0-1"),
                                           ("1.5.0-2", "1.5.0-1")])
def test_a_binary_version_that_does_not_follow_its_source_is_not_checked(binary, source):
    """The lists offer binary versions and the security data names source
    versions. The two can be held against each other only where a package's
    binary version is its source's, or that with a rebuild's mark. `gcc` is
    `4:12.2.0-3` from the source `gcc-defaults` at `1.203`."""
    package = Named("gcc", binary, "gcc-defaults", source, "arm64")
    lists = doc(offers("gcc", offer(binary)))
    assert held(lists, package, INDEX) == NotChecked(VERSION_NOT_COMPARABLE)


# ------------------------------------------------- lists that were not read

@pytest.mark.parametrize("lists", ["read_error", "permission_denied", "not_present", "not_collected", "", None])
def test_lists_that_were_not_read_whole_read_not_checked_and_never_none(lists):
    report = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10")), lists=lists)
    assert held(report, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


def test_a_report_with_no_word_about_the_package_is_not_checked():
    """An agent that sends no offers, an older report, or a package the
    agent's cap cut off: nothing was read about it."""
    assert held(doc(), OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)
    assert held(doc(offers("nginx", offer("1.22.1-9"))), OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)
    assert held({"packages": {"status": "collected"}}, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)
    assert held({}, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


def test_offers_the_agent_cut_are_not_the_whole_of_the_lists():
    cut = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10"), offered_cut=True))
    assert held(cut, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


@pytest.mark.parametrize("broken", [
    {"offered": "1:9.2p1-2+deb12u10"},
    {"offered": [["1:9.2p1-2+deb12u10", "debian"]]},
    {"offered": [{"version": "1:9.2p1-2+deb12u10"}]},
    {"offered": [{"version": "1:9.2p1-2+deb12u10", "archive": "other", "not_automatic": False, "but_automatic_upgrades": False}]},
    {"offered": [{"version": "1:9.2p1-2+deb12u10", "archive": "Acme", "not_automatic": False, "but_automatic_upgrades": False}]},
    {"offered": [{"version": "not a version", "archive": "debian", "not_automatic": False, "but_automatic_upgrades": False}]},
    {"offered": [{"version": 9, "archive": "debian", "not_automatic": False, "but_automatic_upgrades": False}]},
    {"offered": [{"version": "1:9.2p1-2+deb12u10", "archive": "debian", "not_automatic": "no", "but_automatic_upgrades": False}]},
    {"offered": [{"version": "1:9.2p1-2+deb12u10", "archive": "debian", "not_automatic": False}]},
    {"other_offers": "yes"},
    {"other_offers_installed": 1},
    {"other_offers": False, "other_offers_installed": True},
    {"offered_cut": "no"},
])
def test_a_report_that_does_not_keep_the_agents_own_contract_is_not_believed(broken):
    """A report is JSON a server sent. An entry that is not what the agent's
    own marshaller lets through is read as nothing, never as none and never
    as an error that would take the page down."""
    entry = offers("openssh-server", offer("1:9.2p1-2+deb12u10"))
    entry.update(broken)
    assert held(doc(entry), OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


@pytest.mark.parametrize("section", ["a string", ["a", "list"], 7, None,
                                     {"sources": "collected"}, {"sources": {"apt_lists": "collected"}},
                                     {"sources": {"apt_lists": {"status": "collected"}}, "offers": {"name": "x"}},
                                     {"sources": {"apt_lists": {"status": "collected"}}, "offers": ["openssh-server"]}])
def test_a_packages_section_of_another_shape_is_not_believed(section):
    assert held({"packages": section}, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


def test_an_archives_word_of_another_distribution_is_not_believed():
    """The agent gives a word only on a server of that distribution. A report
    that says `ubuntu` on a Debian server did not come from that agent."""
    report = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10", "ubuntu")))
    assert held(report, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)
    report = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10", "debian-security")), distribution=UBUNTU)
    assert held(report, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)
    report = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10")), distribution="debian")
    assert held(report, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


def test_neither_entry_of_a_name_said_twice_is_picked():
    """The agent's marshaller refuses a package twice, so a report that has
    one twice is not the agent's, and neither entry is believed."""
    twice = doc(offers("openssh-server", offer("1:9.2p1-2+deb12u10")),
                offers("openssh-server", offer("1:9.2p1-2+deb12u3")))
    assert held(twice, OPENSSH, INDEX) == NotChecked(LISTS_NOT_READ)


# ------------------------------------------------------------- the two ends

def test_the_reasons_are_one_closed_list():
    assert offerrule.REASONS == (NOT_THE_DISTRIBUTIONS, ANOTHER_ARCHIVE_OFFERS, NEWER_THAN_THE_LISTS,
                                 NOT_IN_THE_LISTS, VERSION_NOT_COMPARABLE, LISTS_NOT_READ)
    with pytest.raises(ValueError):
        NotChecked("probably fine")


def test_an_installed_version_that_is_no_version_is_raised_and_never_read_as_none():
    """`packagerule` names no package whose version is not one, so this does
    not happen. If it did, it must not look like a clean port."""
    broken = Named("openssh-server", "not a version", "openssh", "not a version", "arm64")
    with pytest.raises(Exception):
        held(BEHIND, broken, INDEX)


def test_a_fix_only_ubuntu_pro_offers_is_never_drawn_as_not_offered_by_the_lists():
    """From Canonical's own record to the rule's answer. A fix a server can
    get only with Ubuntu Pro is no fix for a server without it, so it is in
    no extract (`test_a_fix_only_ubuntu_pro_offers_is_no_fix_for_the_extract`)
    and the rule cannot say of it that this server's lists do not offer it:
    the lists never could."""
    def affected(name, fixed):
        return {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": name},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                "versions": []}

    def record(number, entry):
        return {"id": f"UBUNTU-CVE-2026-{number}", "upstream": [f"CVE-2026-{number}"],
                "severity": [{"type": "Ubuntu", "score": "medium"}], "affected": [entry]}

    records = [record("00021", affected("openssh", "1:9.6p1-3ubuntu13.19")),
               record("00022", affected("openssh", "1:9.6p1-3ubuntu13.20+esm1")),
               record("00023", affected("openssh", "1:9.6p1-3ubuntu13.20~esm2"))]
    rows, _left_out = cveextract.ubuntu_rows_for(records, ["Ubuntu:24.04:LTS"])["Ubuntu:24.04:LTS"]
    index = cvematch.by_source(cveextract.select(rows))
    ssh = Named("openssh-server", "1:9.6p1-3ubuntu13.5", "openssh", "1:9.6p1-3ubuntu13.5", "amd64")
    noble = doc(offers("openssh-server", offer("1:9.6p1-3ubuntu13", "ubuntu"),
                       offer("1:9.6p1-3ubuntu13.19", "ubuntu")), distribution=UBUNTU)
    got = held(noble, ssh, index)
    assert cves(got.update_fixes) == ["CVE-2026-00021"]
    assert got.not_offered == () and got.fixed_in == ""
    # And the same records with an extract that keeps what no update fixes:
    # the two are rows with no fixed version, and still in neither group.
    got = held(noble, ssh, cvematch.by_source(cveextract.select(rows, only_fixable=False)))
    assert cves(got.update_fixes) == ["CVE-2026-00021"] and got.not_offered == ()


def test_debians_backport_beside_the_installed_build_does_not_stop_the_check():
    """Debian 13's OpenSSH as the second big test read it on 24 October,
    with trixie-backports in the lists, and as the agent sends Debian's
    backports since 27 October: Debian's word and both flags. The backport is
    no update, so the check holds the installed build against the release's
    data and the update its own archives offer."""
    trixie = {"id": "debian", "version_id": "13", "version_codename": "trixie"}
    ssh = Named("openssh-server", "1:10.0p1-7+deb13u4", "openssh", "1:10.0p1-7+deb13u4", "amd64")
    rows = cvematch.by_source([Row("openssh", "CVE-2026-00012", "1:10.0p1-7+deb13u3", "medium"),
                               Row("openssh", "CVE-2026-00013", "1:10.3p1-1", "medium")])
    lists = doc(offers("openssh-server", offer("1:10.0p1-7+deb13u4"),
                       offer("1:10.0p1-7+deb13u2", "debian-security"),
                       offer("1:10.3p1-1~bpo13+1", "debian", flagged=True)), distribution=trixie)
    got = held(lists, ssh, rows)
    assert isinstance(got, Checked)
    assert got.update_to == "1:10.0p1-7+deb13u4"
    assert got.update_fixes == ()
    assert cves(got.not_offered) == ["CVE-2026-00013"]
    # And with nothing open the card may read none, which it never could
    # while the backport was another archive.
    assert held(lists, ssh, cvematch.by_source(rows_fixed_before(ssh))).none
    # An installed backport stays not checked.
    backport = Named("openssh-server", "1:10.3p1-1~bpo13+1", "openssh", "1:10.3p1-1~bpo13+1", "amd64")
    assert held(lists, backport, rows) == NotChecked(NOT_THE_DISTRIBUTIONS)


def rows_fixed_before(named):
    """One CVE of the package's source, fixed before its installed version."""
    return [Row(named.source, "CVE-2026-00014", "1:9.2p1-2", "low")]
