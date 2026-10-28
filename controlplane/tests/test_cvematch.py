"""Matching an installed version against a release's extract.

    python -m pytest tests/test_cvematch.py

The rows here are written for the tests, with made-up CVE numbers.
"""
import pytest

from app import cvematch, debversion
from app.cveextract import Row
from app.cvematch import Match, by_source, open_cves, release_of

ROWS = [
    Row("nginx", "CVE-2025-00030", "", "unimportant"),
    Row("openssh", "CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),
    Row("openssh", "CVE-2025-00002", "1:9.2p1-2+deb12u3", "not yet assigned"),
    Row("openssh", "CVE-2025-00003", "", "unimportant"),
]
INDEX = by_source(ROWS)


def cves(source, version):
    return [m.cve for m in open_cves(INDEX, source, version)]


def test_a_version_older_than_the_fix_is_open_to_the_cve():
    assert open_cves(INDEX, "openssh", "1:9.2p1-2+deb12u4") == [
        Match("CVE-2025-00001", "1:9.2p1-2+deb12u5", "low"),
        Match("CVE-2025-00003", "", "unimportant")]


def test_the_fixed_version_itself_and_anything_newer_is_not():
    assert cves("openssh", "1:9.2p1-2+deb12u5") == ["CVE-2025-00003"]
    assert cves("openssh", "1:9.2p1-2+deb12u10") == ["CVE-2025-00003"]


def test_older_is_debians_ordering_and_not_the_alphabets():
    """u10 is newer than u5, and an epoch outranks everything after it."""
    assert "CVE-2025-00001" not in cves("openssh", "1:9.2p1-2+deb12u10")
    assert "CVE-2025-00001" in cves("openssh", "9.9p1-1")
    assert "CVE-2025-00001" not in cves("openssh", "2:1.0-1")


def test_a_row_with_no_fixed_version_matches_every_version():
    assert cves("nginx", "1.22.1-9+deb12u10") == ["CVE-2025-00030"]
    assert cves("nginx", "99.0-1") == ["CVE-2025-00030"]


def test_an_extract_of_only_fixable_rows_gives_only_what_an_update_fixes():
    fixable = by_source([row for row in ROWS if row.fixed])
    assert [m.cve for m in open_cves(fixable, "openssh", "1:9.2p1-2")] == [
        "CVE-2025-00001", "CVE-2025-00002"]
    assert open_cves(fixable, "nginx", "1.22.1-9") == []


def test_a_package_the_extract_does_not_know_is_open_to_nothing():
    assert open_cves(INDEX, "postgresql-15", "15.14-0+deb12u1") == []


def test_the_matches_come_sorted_by_cve():
    assert cves("openssh", "1:9.2p1-2") == ["CVE-2025-00001", "CVE-2025-00002", "CVE-2025-00003"]


@pytest.mark.parametrize("version", ["", "1:9.2p1-", "not a version", "1.0 1"])
def test_an_installed_version_that_is_no_version_is_never_read_as_no_cve(version):
    with pytest.raises(debversion.VersionError):
        open_cves(INDEX, "openssh", version)


@pytest.mark.parametrize("distribution, expected", [
    ({"id": "debian", "version_id": "12", "version_codename": "bookworm"}, ("debian", "12")),
    ({"id": "debian", "version_id": "13"}, ("debian", "13")),
    ({"id": "ubuntu", "version_id": "24.04"}, ("ubuntu", "24.04")),
    ({"id": "ubuntu", "version_id": "26.04"}, ("ubuntu", "26.04")),
    ({"id": "debian", "version_id": "11"}, None),
    ({"id": "ubuntu", "version_id": "22.04"}, None),
    ({"id": "debian"}, None),                      # testing and unstable carry no VERSION_ID
    ({"id": "almalinux", "version_id": "10"}, None),
    ({"id": "debian", "version_id": 12}, None),
    ({"id": ["debian"], "version_id": "12"}, None),
    (None, None),
    ("debian 12", None),
])
def test_a_release_has_an_extract_or_it_does_not(distribution, expected):
    assert release_of(distribution) == expected


def test_the_index_keeps_every_row_of_a_package_together():
    assert set(INDEX) == {"nginx", "openssh"}
    assert len(INDEX["openssh"]) == 3
    assert cvematch.by_source([]) == {}
