"""The one place the CVE check fetches anything from.

Three kinds of file are ever asked for, each from a host named in advance:
Debian's security tracker JSON, Canonical's OSV tarball, and a slim extract
(`app/cveextract.py`) from wherever ours are served. Nothing here runs until
the check ships, and each of these requests is named on the page that day
(`docs/RECORD.md` 4.274).

**What a fetch refuses, before and after it asks.**

- Anything but https.
- A host that is not on the list the caller passes. A vendor's file comes
  from the vendor's host and from nowhere a redirect points: any 3xx is a
  refusal (`authz._NoRedirects`), never a hop.
- A host any of whose addresses is not globally routable, the predicate
  `app/webhook.py` uses for the same reason: this runs on the box that holds
  the database, and a name that resolves somewhere odd is not followed. What
  that does not stop is said in webhook.py, DNS rebinding, and it holds here
  as it does there.
- A status other than 200.
- A body larger than the cap the caller passes. The caps on what a file
  unpacks to are the builder's (`cveextract.MAX_TARBALL_BYTES`) and
  `unpacked` below.

A refusal is an exception carrying one of four fixed reasons. The text of a
vendor's error page is never read and never logged.
"""

import datetime
import email.utils
import gzip
import http.client
import io
import urllib.error
import urllib.parse
import urllib.request

from . import authz, webhook

DEBIAN_TRACKER_URL = "https://security-tracker.debian.org/tracker/data/json"
UBUNTU_OSV_URL = "https://security-metadata.canonical.com/osv/osv-all.tar.xz"
VENDOR_HOSTS = ("security-tracker.debian.org", "security-metadata.canonical.com")

# Measured 2026-10-03: the tracker 12.9 MB as served with gzip and 79.8 MB
# unpacked, the tarball 46.3 MB, the largest extract 1.44 MB.
MAX_TRACKER_BYTES = 64 << 20
MAX_TRACKER_UNPACKED_BYTES = 512 << 20
MAX_TARBALL_DOWNLOAD_BYTES = 256 << 20
MAX_EXTRACT_DOWNLOAD_BYTES = 16 << 20

TIMEOUT_SECONDS = 120
USER_AGENT = "whichports-cve-data/1"

REFUSED = "the address is refused"
NOT_REACHED = "the host could not be reached"
BAD_STATUS = "the host did not answer 200"
TOO_LARGE = "the file is larger than its cap"
REASONS = (REFUSED, NOT_REACHED, BAD_STATUS, TOO_LARGE)


class FetchError(Exception):
    """A file that was not fetched. `reason` is one of REASONS, `detail` says
    which rule or which status, in our words."""

    def __init__(self, reason: str, detail: str = ""):
        if reason not in REASONS:
            raise ValueError(f"not a reason: {reason!r}")
        super().__init__(reason + (f": {detail}" if detail else ""))
        self.reason = reason
        self.detail = detail


def check_url(url: str, allowed_hosts, resolver=None) -> str:
    """"" when this URL may be fetched, or the rule it breaks."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "the address cannot be parsed"
    if parts.scheme != "https":
        return "only https is fetched"
    if not parts.hostname or parts.hostname not in tuple(allowed_hosts):
        return "the host is not one this fetches from"
    if parts.username or parts.password:
        return "an address with a login in it is not fetched"
    try:
        addresses = webhook._addresses(parts.hostname, resolver)
    except OSError:
        return "the host did not resolve"
    if not addresses:
        return "the host resolved to no address"
    # Every one of them, not the first, as webhook.check_url does.
    for ip in addresses:
        if not authz._is_probeable(ip):
            return "the host resolves to an address that is not globally routable"
    return ""


def modified_time(value) -> str:
    """A Last-Modified header as the time an extract carries,
    2026-10-03T14:07:28Z, or empty when there is none or it is no date."""
    if not isinstance(value, str) or not value:
        return ""
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return ""
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch(url: str, allowed_hosts, max_bytes: int, resolver=None, opener=None,
          headers=None) -> tuple[bytes, str]:
    """The file at `url` and when its host says it last changed, or a
    FetchError. `resolver` and `opener` are arguments so the tests drive the
    real logic without a socket, as in `webhook.send`."""
    complaint = check_url(url, allowed_hosts, resolver)
    if complaint:
        raise FetchError(REFUSED, complaint)
    request = urllib.request.Request(
        url, method="GET", headers={"User-Agent": USER_AGENT, **(headers or {})})
    opener = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), authz._NoRedirects())
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            if response.status != 200:
                raise FetchError(BAD_STATUS, str(response.status))
            body = response.read(max_bytes + 1)
            modified = modified_time(response.headers.get("Last-Modified"))
    except urllib.error.HTTPError as exc:
        # A 3xx arrives here because redirects are refused.
        raise FetchError(BAD_STATUS, str(exc.code)) from None
    except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
        # The class and never the message, as webhook.send does. A file cut
        # short is `http.client.IncompleteRead`, which is none of the first
        # three: the host said how long the file is and the connection ended
        # before that (the challenge of 2026-10-11).
        raise FetchError(NOT_REACHED, type(exc).__name__) from None
    if len(body) > max_bytes:
        raise FetchError(TOO_LARGE, f"more than {max_bytes} bytes")
    return body, modified


def unpacked(data: bytes, max_bytes: int) -> bytes:
    """`data` as it is, or unpacked when it is gzip, told by its first two
    bytes. A file that unpacks to more than `max_bytes` is refused."""
    if data[:2] != b"\x1f\x8b":
        if len(data) > max_bytes:
            raise FetchError(TOO_LARGE, f"more than {max_bytes} bytes")
        return data
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as packed:
            out = packed.read(max_bytes + 1)
    except (OSError, EOFError):
        raise FetchError(NOT_REACHED, "the file is cut or is not gzip") from None
    if len(out) > max_bytes:
        raise FetchError(TOO_LARGE, f"more than {max_bytes} bytes unpacked")
    return out
