"""Debian version ordering, deb-version(7).

    python -m pytest tests/test_debversion.py

The CVE check says a version is affected when it is older than the one a fix
arrived in, so an ordering mistake here is a wrong finding. The cases are the
manual's own examples first, then versions read from Debian 12 and Ubuntu
24.04 status files on 2026-10-02 and 2026-10-03, with their neighbours.

Checked against dpkg itself on 2026-10-03: every ordered pair of the 49
versions these tests use, 2,401 pairs, through `dpkg --compare-versions` in a
Debian 12 container (dpkg 1.21.23), and `compare` gave dpkg's answer for every
one of them.
"""
import pytest

from app import debversion
from app.debversion import VersionError, compare


def ordered(*versions):
    """Each version strictly older than the next, checked both ways round."""
    for older, newer in zip(versions, versions[1:]):
        assert compare(older, newer) == -1, (older, newer)
        assert compare(newer, older) == 1, (newer, older)


# ------------------------------------------------------- the manual's examples

def test_the_manuals_own_order_of_parts():
    """ "the following parts are in sorted order: '~~', '~~a', '~', the empty
    part, 'a'" """
    ordered("1~~", "1~~a", "1~", "1", "1a")


def test_letters_sort_before_everything_that_is_not_a_letter():
    ordered("1.0a", "1.0+")
    ordered("1.0z", "1.0.")
    ordered("1.0A", "1.0a")   # ASCII order among letters


def test_digit_runs_compare_as_numbers():
    ordered("1.9", "1.10")
    ordered("2", "10")
    assert compare("1.01", "1.1") == 0
    assert compare("1.000", "1.0") == 0


def test_an_empty_digit_run_counts_as_zero():
    """ "an empty string (which can only occur at the end of one or both
    version strings being compared) counts as zero" """
    assert compare("1.", "1.0") == 0
    # while the end of a part still sorts before a non-digit character
    ordered("1.0", "1.0.0")


def test_a_missing_epoch_is_zero_and_an_epoch_outranks_everything():
    assert compare("0:1.0", "1.0") == 0
    ordered("2.0", "1:0.1")
    ordered("1:9.9", "2:0.0")
    ordered("9:1", "10:0")    # epochs are numbers, not text


def test_the_absence_of_a_revision_compares_earlier_than_one():
    """"The absence of a debian-revision compares earlier than the presence of
    one", and the revision is the least significant part."""
    ordered("1.0", "1.0-1")
    ordered("1.0-9", "1.1")


def test_the_revision_is_split_at_the_last_hyphen():
    assert debversion.parse("1.0-beta-2") == (0, "1.0-beta", "2")
    assert debversion.parse("1:2.0") == (1, "2.0", "")
    assert debversion.parse("2:1.0:x-1") == (2, "1.0:x", "1")


# ----------------------------------------------- versions read off real hosts

def test_security_updates_order_by_their_number():
    ordered("1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u10")
    ordered("1.22.1-9+deb12u2", "1.22.1-9+deb12u10")


def test_a_backport_tilde_sorts_before_the_release_it_backports():
    ordered("5:7.0.15-1~deb12u1", "5:7.0.15-1")
    ordered("5:7.0.15-1~deb12u9", "5:7.0.15-1~deb12u10")


def test_ubuntu_versions():
    ordered("1:10.11.14-0ubuntu0.24.04.1", "1:10.11.14-0ubuntu0.24.04.2")
    ordered("1.24.0-2ubuntu7.9", "1.24.0-2ubuntu7.18")
    ordered("1:9.6p1-3ubuntu13.5", "1:9.6p1-3ubuntu13.19")
    ordered("257build1", "257build1.1")


def test_a_binnmu_is_newer_than_its_source_version():
    """bash's binary version 5.2.15-2+b13 beside its source 5.2.15-2 (Debian 12):
    the binary is newer, which is why the CVE check compares source versions."""
    ordered("5.2.15-2", "5.2.15-2+b13")


def test_equal_versions_are_equal():
    for v in ("1:9.2p1-2+deb12u10", "248", "5:7.0.15-1~deb12u10", "1.0~rc1-1"):
        assert compare(v, v) == 0


# ------------------------------------------------------------ what is refused

@pytest.mark.parametrize("bad", [
    "", " 1.0", "1.0 ", "a:1.0", "-1:1.0", "1:", ":1.0", "1.0-", "1.0-a_b",
    "1.0/2", "1.0_1", "1 0", "1.0-rév", None, 1, 1.0, b"1.0",
])
def test_what_is_not_a_version_is_refused(bad):
    with pytest.raises(VersionError):
        debversion.parse(bad)
    with pytest.raises(VersionError):
        compare(bad, "1.0")
    with pytest.raises(VersionError):
        compare("1.0", bad)


def test_the_ordering_is_total_and_consistent_over_a_mixed_list():
    versions = ["1~~", "1~~a", "1~", "1", "1a", "1.0", "1.0-1", "1.0+", "1.9", "1.10",
                "2.0", "1:0.1", "1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u10", "2:0"]
    for a in versions:
        for b in versions:
            assert compare(a, b) == -compare(b, a), (a, b)
    for i, a in enumerate(versions):
        for b in versions[i + 1:]:
            assert compare(a, b) == -1, (a, b)
