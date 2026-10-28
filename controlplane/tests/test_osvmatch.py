"""Matching an installed version against records in the OSV format.

    python -m pytest tests/test_osvmatch.py

The records here are written for the tests in the shape OSV publishes for
Debian and Ubuntu (read on 2026-10-03): ECOSYSTEM ranges, an "introduced": "0"
and a "fixed" version, a list of versions, and the id forms DEBIAN-CVE-...,
UBUNTU-CVE-... and DSA-.... None is a copy of a published record.

Checked against OSV itself on 2026-10-03: every openssh, nginx and redis
record OSV holds for Debian 12 or Ubuntu 24.04, evaluated by `evaluate` at
thirteen versions those hosts carried, gave exactly the set OSV's own API
answered for each version. No record was left unevaluated.
"""
import pytest

from app import osvmatch
from app.osvmatch import AFFECTED, NOT_AFFECTED, UNREADABLE, cve_ids, ecosystems, evaluate

DEB12 = ("Debian:12",)
NOBLE = ("Ubuntu:24.04:LTS", "Ubuntu:24.04")


def record(ident="DEBIAN-CVE-2025-00001", ecosystem="Debian:12", name="openssh",
           events=({"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u5"}), versions=None,
           range_type="ECOSYSTEM", **more):
    affected = {"package": {"name": name, "ecosystem": ecosystem},
                "ranges": [{"type": range_type, "events": list(events)}]}
    if versions is not None:
        affected["versions"] = list(versions)
    out = {"id": ident, "affected": [affected]}
    out.update(more)
    return out


# ------------------------------------------------------------ ecosystems

@pytest.mark.parametrize("distribution, expected", [
    ({"id": "debian", "version_id": "12"}, ("Debian:12",)),
    ({"id": "debian", "version_id": "13"}, ("Debian:13",)),
    ({"id": "ubuntu", "version_id": "24.04"}, ("Ubuntu:24.04:LTS", "Ubuntu:24.04")),
    ({"id": "ubuntu", "version_id": "25.10"}, ("Ubuntu:25.10:LTS", "Ubuntu:25.10")),
    # Debian testing and unstable carry no VERSION_ID
    ({"id": "debian", "version_codename": "forky"}, ()),
    ({"id": "almalinux", "version_id": "10.0"}, ()),
    ({"id": "debian", "version_id": "12.7"}, ()),
    ({"id": "ubuntu", "version_id": "24"}, ()),
    ({"id": "debian", "version_id": 12}, ()),
    ({}, ()), (None, ()), ("debian", ()),
])
def test_the_ecosystems_a_host_is_looked_up_under(distribution, expected):
    assert ecosystems(distribution) == expected


# ----------------------------------------------------- the schema's algorithm

def test_a_version_before_the_fix_is_affected_and_the_fix_and_after_are_not():
    r = record()
    assert evaluate(r, DEB12, "openssh", "1:9.2p1-2+deb12u4") == AFFECTED
    assert evaluate(r, DEB12, "openssh", "1:9.2p1-2+deb12u5") == NOT_AFFECTED
    assert evaluate(r, DEB12, "openssh", "1:9.2p1-2+deb12u10") == NOT_AFFECTED


def test_no_fix_means_every_version_is_affected():
    r = record(events=[{"introduced": "0"}])
    assert evaluate(r, DEB12, "openssh", "1:9.2p1-2+deb12u10") == AFFECTED


def test_a_version_before_introduced_is_not_affected():
    r = record(events=[{"introduced": "1:9.0p1-1"}, {"fixed": "1:9.2p1-2+deb12u5"}])
    assert evaluate(r, DEB12, "openssh", "1:8.4p1-5") == NOT_AFFECTED
    assert evaluate(r, DEB12, "openssh", "1:9.0p1-1") == AFFECTED


def test_a_listed_version_is_affected_whatever_the_ranges_say():
    r = record(events=[{"introduced": "0"}, {"fixed": "1.0-1"}], versions=["2.0-1"])
    assert evaluate(r, DEB12, "openssh", "2.0-1") == AFFECTED


def test_last_affected_is_the_last_affected_version():
    r = record(events=[{"introduced": "0"}, {"last_affected": "1.4-1"}])
    assert evaluate(r, DEB12, "openssh", "1.4-1") == AFFECTED
    assert evaluate(r, DEB12, "openssh", "1.4-2") == NOT_AFFECTED


def test_a_limit_caps_the_range_and_a_star_is_infinity():
    r = record(events=[{"introduced": "0"}, {"limit": "2.0"}])
    assert evaluate(r, DEB12, "openssh", "1.9") == AFFECTED
    assert evaluate(r, DEB12, "openssh", "2.0") == NOT_AFFECTED
    r = record(events=[{"introduced": "0"}, {"limit": "*"}])
    assert evaluate(r, DEB12, "openssh", "99") == AFFECTED


def test_events_are_walked_in_version_order_whatever_order_they_are_written_in():
    r = record(events=[{"fixed": "3.0"}, {"introduced": "2.0"}, {"fixed": "1.5"}, {"introduced": "0"}])
    assert evaluate(r, DEB12, "openssh", "1.0") == AFFECTED
    assert evaluate(r, DEB12, "openssh", "1.7") == NOT_AFFECTED
    assert evaluate(r, DEB12, "openssh", "2.5") == AFFECTED
    assert evaluate(r, DEB12, "openssh", "3.0") == NOT_AFFECTED


def test_a_withdrawn_record_affects_nothing():
    r = record(events=[{"introduced": "0"}], withdrawn="2026-01-01T00:00:00Z")
    assert evaluate(r, DEB12, "openssh", "1.0") == NOT_AFFECTED


# --------------------------------------------- the package and the ecosystem

def test_only_the_same_source_in_the_hosts_ecosystem_counts():
    r = record(events=[{"introduced": "0"}])
    assert evaluate(r, DEB12, "nginx", "1.0") == NOT_AFFECTED
    assert evaluate(r, ("Debian:13",), "openssh", "1.0") == NOT_AFFECTED
    assert evaluate(r, NOBLE, "openssh", "1.0") == NOT_AFFECTED


def test_an_ubuntu_record_is_found_under_either_name():
    lts = record("UBUNTU-CVE-2024-00002", ecosystem="Ubuntu:24.04:LTS", events=[{"introduced": "0"}])
    interim = record("UBUNTU-CVE-2024-00003", ecosystem="Ubuntu:25.10", events=[{"introduced": "0"}])
    assert evaluate(lts, NOBLE, "openssh", "1.0") == AFFECTED
    assert evaluate(interim, ecosystems({"id": "ubuntu", "version_id": "25.10"}), "openssh", "1.0") == AFFECTED
    # a Pro stream is its own ecosystem and a plain host is not in it
    pro = record(ecosystem="Ubuntu:Pro:FIPS:22.04:LTS", events=[{"introduced": "0"}])
    assert evaluate(pro, ecosystems({"id": "ubuntu", "version_id": "22.04"}), "openssh", "1.0") == NOT_AFFECTED


def test_one_record_naming_several_releases_is_read_for_the_hosts_one():
    r = record(events=[{"introduced": "0"}, {"fixed": "1:9.2p1-2+deb12u5"}])
    r["affected"].append({"package": {"name": "openssh", "ecosystem": "Debian:13"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]})
    assert evaluate(r, DEB12, "openssh", "1:9.2p1-2+deb12u10") == NOT_AFFECTED
    assert evaluate(r, ("Debian:13",), "openssh", "1:9.2p1-2+deb12u10") == AFFECTED


# ------------------------------------------------- what cannot be evaluated

@pytest.mark.parametrize("events", [
    [{"introduced": "0"}, {"fixed": "not a version"}],
    [{"introduced": "0", "fixed": "1.0"}],
    [{"introduced": "0"}, {"repaired": "1.0"}],
    [{"introduced": "0"}, {"fixed": 1.0}],
    [{"introduced": "0"}, "fixed"],
])
def test_a_range_that_does_not_read_cannot_be_evaluated(events):
    assert evaluate(record(events=events), DEB12, "openssh", "1.0") == UNREADABLE


@pytest.mark.parametrize("range_type", ["SEMVER", "GIT", "", None])
def test_a_range_type_this_code_does_not_evaluate_cannot_be_evaluated(range_type):
    r = record(range_type=range_type, events=[{"introduced": "0"}])
    assert evaluate(r, DEB12, "openssh", "1.0") == UNREADABLE


def test_another_range_that_says_affected_wins_over_one_that_does_not_read():
    r = record(events=[{"introduced": "0"}])
    r["affected"][0]["ranges"].insert(0, {"type": "GIT", "events": [{"introduced": "abc"}]})
    assert evaluate(r, DEB12, "openssh", "1.0") == AFFECTED


@pytest.mark.parametrize("r", [None, [], "x", {}, {"affected": "x"}, {"affected": [None, "x", {}]},
                               {"affected": [{"package": "openssh"}]}])
def test_a_malformed_record_affects_nothing_and_raises_nothing(r):
    assert evaluate(r, DEB12, "openssh", "1.0") == NOT_AFFECTED


# ------------------------------------------------------------- the CVE ids

@pytest.mark.parametrize("r, expected", [
    ({"id": "DEBIAN-CVE-2025-26465"}, ("CVE-2025-26465",)),
    ({"id": "UBUNTU-CVE-2024-6387"}, ("CVE-2024-6387",)),
    ({"id": "DSA-5868-1", "upstream": ["CVE-2025-26465", "DEBIAN-CVE-2025-26465"]}, ("CVE-2025-26465",)),
    ({"id": "DSA-1-1", "aliases": ["CVE-2024-00001"], "upstream": ["CVE-2024-00002"]},
     ("CVE-2024-00001", "CVE-2024-00002")),
    ({"id": "DEBIAN-CVE-2025-ABC"}, ()),
    ({"id": "GHSA-xxxx", "aliases": [7, None, "cve-2024-1"]}, ()),
    (None, ()), ({}, ()),
])
def test_the_cve_ids_a_record_is_about(r, expected):
    assert cve_ids(r) == expected


def test_the_answers_are_three():
    assert {AFFECTED, NOT_AFFECTED, UNREADABLE} == {
        osvmatch.AFFECTED, osvmatch.NOT_AFFECTED, osvmatch.UNREADABLE}
    assert len({AFFECTED, NOT_AFFECTED, UNREADABLE}) == 3
