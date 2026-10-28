"""Where this control plane answers, for every line that carries a link out.

The install command a server pastes, the link at the bottom of an alert, and
the link in an invitation all name the dashboard. They used to name
`https://app.whichports.com` in six places. That is right for our own box and
wrong for a self-hosted instance (`untilbeta.md`): its servers would enrol to
us and its mail would send people to our login page.

**The setting is `WHICHPORTS_BASE_URL`, the one sign-in already reads**
(`app/oidc.py`), because it already means "where this control plane answers"
and two settings for one fact drift. Unset, every line is exactly what it was
before, `https://app.whichports.com`, and `tests/test_publicurl.py` holds that.
Our box sets it to that same address (`ops/RUNBOOK.md`, Google sign-in), so
nothing our own customers see changes either way.

**Read when a link is built, never at import.** A command run from a shell
loads `/etc/whichports/controlplane.env` after its imports (`app/cli.py`), so
a value read at import would be the one from before the file was read.

**Only `https://` and a host, and anything else is refused, not repaired.**
The value goes into a line somebody pastes into a root shell, so it is held to
a shape with no space and no shell character in it, the same shape
`dispatch.prober_enroll_flags` holds the prober address to. A malformed value
raises rather than falling back to ours, because a self-hosted instance that
quietly enrolled its servers to our control plane is the failure this module
exists to prevent.
"""
import os
import re
import urllib.parse

ENV = "WHICHPORTS_BASE_URL"
DEFAULT = "https://app.whichports.com"

# Letters, digits, dots, hyphens, and the brackets and colons of an IPv6
# literal or a port. Nothing a shell gives a meaning to.
_NETLOC_RE = re.compile(r"[A-Za-z0-9.:\[\]-]+")


class PublicUrlError(ValueError):
    """The setting is there and is not an https address with nothing after
    the host."""


def base(environ=None) -> str:
    """`https://host`, without a trailing slash."""
    environ = os.environ if environ is None else environ
    value = environ.get(ENV, "").strip()
    if not value:
        return DEFAULT
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname \
            or parsed.path not in ("", "/") or parsed.query \
            or parsed.fragment or parsed.username or parsed.password \
            or not _NETLOC_RE.fullmatch(parsed.netloc):
        raise PublicUrlError(
            f"{ENV} is an https address with nothing after the host, such as"
            f" https://whichports.example.com. {value!r} is not")
    return f"https://{parsed.netloc}"


def host(environ=None) -> str:
    """The host as a sentence names it: `app.whichports.com`."""
    return base(environ)[len("https://"):]


def dashboard(environ=None) -> str:
    """The dashboard's address, with the slash a mail client links."""
    return base(environ) + "/"


def server(host_name: str, environ=None) -> str:
    """One server's own page, which is where a message about that server
    sends its reader (docs/screens/mails/SPEC-alert-messages.md).

    The dashboard gives a server's page the address `/host/<the name it is
    found by>` (site/app/page.js, `viewToPath`), and the control plane
    answers it (app/web_auth.py). The name is quoted whole, so one holding a
    slash or a question mark is still one path segment and can carry nothing
    past the server's page.

    A server that is gone, or one of another workspace, has no view on the
    reader's page, and the page falls back to the Fleet. So an old message
    opens the Fleet and never somebody else's server.
    """
    return f"{base(environ)}/host/{urllib.parse.quote(host_name, safe='')}"


def integrations(environ=None) -> str:
    """The Integrations screen, where a workspace's alert destinations are
    and Send test is pressed (docs/screens/alerts/SPEC-layout-b.md)."""
    return base(environ) + "/integrations"
