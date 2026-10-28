"""What a fetch of CVE data refuses, and what it hands back.

    python -m pytest tests/test_cvefetch.py

No test here opens a socket or resolves a name: the resolver and the opener
are handed in, as in test_webhook.py.
"""
import gzip
import urllib.error

import pytest

from app import cvefetch
from app.cvefetch import FetchError

# The address test_webhook.py uses for a globally routable one.
PUBLIC = ["185.199.108.153"]
TRACKER = cvefetch.DEBIAN_TRACKER_URL
HOSTS = cvefetch.VENDOR_HOSTS


def public(host):
    return PUBLIC


class FakeOpener:
    """Answers with a status, a body and headers, and keeps the requests."""

    def __init__(self, body=b"", status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}
        self.requests = []
        self.timeouts = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        outer = self

        class Response:
            status = outer.status
            headers = outer.headers

            def read(self, n=None):
                return outer.body if n is None else outer.body[:n]

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return Response()


class RefusingOpener:
    """An opener that must never be called."""

    def open(self, request, timeout=None):
        raise AssertionError("a request was made, and this test exists because it must not be")


# ------------------------------------------------------------ what is asked

def test_the_two_vendor_files_are_fetched_from_the_vendors_own_hosts():
    assert cvefetch.check_url(cvefetch.DEBIAN_TRACKER_URL, HOSTS, public) == ""
    assert cvefetch.check_url(cvefetch.UBUNTU_OSV_URL, HOSTS, public) == ""


@pytest.mark.parametrize("url", [
    "http://security-tracker.debian.org/tracker/data/json",      # not https
    "ftp://security-tracker.debian.org/tracker/data/json",
    "https://example.org/tracker/data/json",                     # not a named host
    "https://security-tracker.debian.org.example.org/x",         # a name that only starts like one
    "https://user:secret@" + cvefetch.VENDOR_HOSTS[0] + "/x",      # a login in the address
    "https:///tracker/data/json",                                # no host
    "security-tracker.debian.org/tracker/data/json",             # no scheme
    "https://[::1/x",                                            # not an address at all
])
def test_an_address_outside_the_rules_is_refused_before_anything_is_asked(url):
    assert cvefetch.check_url(url, HOSTS, public) != ""
    with pytest.raises(FetchError) as refused:
        cvefetch.fetch(url, HOSTS, 100, resolver=public, opener=RefusingOpener())
    assert refused.value.reason == cvefetch.REFUSED


@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.0.0.5", "192.168.1.10", "169.254.169.254", "100.64.0.1",
    "::1", "fe80::1", "fd00::1", "::ffff:10.0.0.5", "0.0.0.0",
])
def test_a_host_that_resolves_to_an_address_not_globally_routable_is_not_followed(address):
    """The guard webhook.py has, for the same reason: this runs on the box
    that holds the database."""
    with pytest.raises(FetchError) as refused:
        cvefetch.fetch(TRACKER, HOSTS, 100, resolver=lambda h: [address], opener=RefusingOpener())
    assert refused.value.reason == cvefetch.REFUSED


def test_every_address_of_a_name_has_to_pass_and_not_the_first_alone():
    assert cvefetch.check_url(TRACKER, HOSTS, lambda h: PUBLIC + ["10.0.0.5"]) != ""


def test_a_name_that_does_not_resolve_or_resolves_to_nothing_is_refused():
    def fails(host):
        raise OSError("no such name")
    assert cvefetch.check_url(TRACKER, HOSTS, fails) != ""
    assert cvefetch.check_url(TRACKER, HOSTS, lambda h: []) != ""


# ------------------------------------------------------------ what comes back

def test_a_fetch_hands_back_the_bytes_and_when_the_host_says_they_changed():
    opener = FakeOpener(b"the file", headers={"Last-Modified": "Sat, 03 Oct 2026 14:07:28 GMT"})
    body, modified = cvefetch.fetch(TRACKER, HOSTS, 100, resolver=public, opener=opener,
                                    headers={"Accept-Encoding": "gzip"})
    assert body == b"the file"
    assert modified == "2026-10-03T14:07:28Z"
    request = opener.requests[0]
    assert request.full_url == TRACKER and request.get_method() == "GET"
    assert request.get_header("User-agent") == cvefetch.USER_AGENT
    assert request.get_header("Accept-encoding") == "gzip"
    assert opener.timeouts == [cvefetch.TIMEOUT_SECONDS]


def test_a_file_larger_than_its_cap_is_refused_and_one_exactly_at_it_is_not():
    with pytest.raises(FetchError) as refused:
        cvefetch.fetch(TRACKER, HOSTS, 7, resolver=public, opener=FakeOpener(b"12345678"))
    assert refused.value.reason == cvefetch.TOO_LARGE
    assert cvefetch.fetch(TRACKER, HOSTS, 8, resolver=public, opener=FakeOpener(b"12345678"))[0] == b"12345678"


@pytest.mark.parametrize("status", [204, 206, 301, 404, 500])
def test_any_status_but_200_is_a_refusal(status):
    with pytest.raises(FetchError) as refused:
        cvefetch.fetch(TRACKER, HOSTS, 100, resolver=public, opener=FakeOpener(b"x", status=status))
    assert refused.value.reason == cvefetch.BAD_STATUS


def test_a_redirect_is_a_refusal_and_never_a_hop():
    """The real opener is built with authz._NoRedirects, which leaves urllib
    to raise the 3xx. This is that error arriving."""
    class Redirects:
        def open(self, request, timeout=None):
            raise urllib.error.HTTPError(request.full_url, 302, "Found", {}, None)
    with pytest.raises(FetchError) as refused:
        cvefetch.fetch(TRACKER, HOSTS, 100, resolver=public, opener=Redirects())
    assert refused.value.reason == cvefetch.BAD_STATUS
    assert refused.value.detail == "302"


def test_a_host_that_cannot_be_reached_says_the_class_and_never_the_message():
    class Broken:
        def open(self, request, timeout=None):
            raise urllib.error.URLError("connection refused by 10.0.0.5, said: go away")
    with pytest.raises(FetchError) as refused:
        cvefetch.fetch(TRACKER, HOSTS, 100, resolver=public, opener=Broken())
    assert refused.value.reason == cvefetch.NOT_REACHED
    assert refused.value.detail == "URLError"
    assert "go away" not in str(refused.value)


def test_a_reason_outside_the_list_cannot_be_given():
    with pytest.raises(ValueError):
        FetchError("something else")
    assert set(cvefetch.REASONS) == {cvefetch.REFUSED, cvefetch.NOT_REACHED,
                                     cvefetch.BAD_STATUS, cvefetch.TOO_LARGE}


@pytest.mark.parametrize("value, expected", [
    ("Sat, 03 Oct 2026 14:07:28 GMT", "2026-10-03T14:07:28Z"),
    ("Fri, 02 Oct 2026 20:10:09 +0200", "2026-10-02T18:10:09Z"),
    ("", ""), (None, ""), ("yesterday", ""), (12, ""),
])
def test_the_time_a_file_changed_is_a_time_in_utc_or_nothing(value, expected):
    assert cvefetch.modified_time(value) == expected


# ---------------------------------------------------------------- unpacking

def test_a_gzipped_file_is_unpacked_and_a_plain_one_is_left_alone():
    assert cvefetch.unpacked(gzip.compress(b'{"a": 1}'), 100) == b'{"a": 1}'
    assert cvefetch.unpacked(b'{"a": 1}', 100) == b'{"a": 1}'


def test_a_file_that_unpacks_to_more_than_its_cap_is_refused():
    """A small download that is a large file: the cap is on what comes out."""
    bomb = gzip.compress(b"0" * 100_000)
    assert len(bomb) < 1000
    with pytest.raises(FetchError) as refused:
        cvefetch.unpacked(bomb, 50_000)
    assert refused.value.reason == cvefetch.TOO_LARGE
    with pytest.raises(FetchError):
        cvefetch.unpacked(b"0" * 51, 50)


def test_a_gzip_file_that_is_cut_is_refused():
    with pytest.raises(FetchError):
        cvefetch.unpacked(gzip.compress(b"0" * 10_000)[:-20], 50_000)
