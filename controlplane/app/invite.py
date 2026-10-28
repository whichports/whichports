"""The invite to our probers as one line, and the three settings inside it.

    whpinvite1_<host>_<API key>_<proof key>

A self-hosted instance that uses our probers has always read three settings:
`WHICHPORTS_PROBER_API`, the address of our prober API, and the two keys
`app/instances.py` issues for it. A tester used to get them as three values
and put each on its own line of `selfhost/.env`. Since 16 October 2026 the
invite is one line that holds all three, which `instances_cli add` prints and
the self-hosted installer asks for once (the shorter install, counted in
docs/record 4.461).

**Where the line is taken apart.** In `selfhost/.env` it is one setting,
`WHICHPORTS_PROBER_INVITE`. `selfhost/worker.py` starts every process of the
stack, and before anything else it turns that one setting into the three,
with `settings()` below. So nothing past the worker knows the invite exists:
the transport, the Add server line, the feedback route and the prober list
read the same three names they always did, and an instance that set the three
lines by hand keeps working as it was. Setting both is refused, because one
value in two places is a value that can disagree with itself.

## The two keys stay apart (SI-6)

The line carries both keys, to the instance and nowhere else. After the split
they go where they always went. **The API key** stays in the instance's own
control plane, which uses it to send batches and read their answers. **The
proof key**, and only that key, goes on to every server the instance enrols,
in the line Add server prints (`dispatch.prober_enroll_flags`), so the agent
can prove the address it reports from. A proof key copied off a server can
prove only the address its sender holds and can send no batch, which is the
whole reason there are two keys (`app/instances.py`, "Two keys per instance,
and why not one"). Putting both in one line changes nothing of that: the line
is never handed to an agent, and the test suite holds the enrol line to the
proof key alone.

## The shape, and why this one

`whpinvite1_` says what the line is, the way `whpi_` and `whpp_` say what a
key is, and the `1` lets a later shape be told apart from this one. Then the
host, then the two keys, joined by `_`. A host name never holds `_`, and each
key has a fixed length after its prefix, so the line splits one way only.

The host is a plain DNS name: lowercase labels of letters, digits and hyphens,
at least two of them, and a letter in the last so an address is never taken
for a name. No port and no scheme: the API is always `https://` on 443. Every
character of the line is one a shell and an env file leave alone, and the
whole line selects as one word.

This file imports nothing of the control plane, because the worker loads it
by its path, as it loads `app/publicurl.py`. So the three names are written
again below, and `tests/test_invite.py` holds them equal to the names
`app/dispatch.py` reads and the keys to the ones `app/instances.py` issues.
`selfhost/install.sh` checks the same shape before it changes anything, and
`selfhost/test_install.py` holds the two checks to the same answers.
"""
import re

INVITE_ENV = "WHICHPORTS_PROBER_INVITE"

# The three settings the line becomes, as `app/dispatch.py` names them.
PROBER_API_ENV = "WHICHPORTS_PROBER_API"
PROBER_API_KEY_ENV = "WHICHPORTS_PROBER_API_KEY"
PROBER_PROOF_KEY_ENV = "WHICHPORTS_PROBER_PROOF_KEY"

PREFIX = "whpinvite1_"

# Each key as `instances.new_key` makes it: its prefix and 64 hex characters.
# Every pattern here is used with fullmatch, never match: a $ also matches
# before a final newline, and a part with a newline in it is not that part.
API_KEY_RE = re.compile(r"whpi_[0-9a-f]{64}")
PROOF_KEY_RE = re.compile(r"whpp_[0-9a-f]{64}")

LINE_RE = re.compile(
    r"whpinvite1_(?P<host>[a-z0-9.-]+)"
    r"_(?P<api>whpi_[0-9a-f]{64})_(?P<proof>whpp_[0-9a-f]{64})")

LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
HOST_MAX = 253


class InviteError(ValueError):
    """The invite setting is there and is not a whole line. The message names
    the setting and never repeats the value, which holds two keys."""


def host_ok(host) -> bool:
    """A plain DNS name: two labels or more, each of lowercase letters,
    digits and inner hyphens, at most 253 characters, and a letter in the
    last label."""
    if not isinstance(host, str) or not host or len(host) > HOST_MAX:
        return False
    labels = host.split(".")
    if len(labels) < 2 or not all(LABEL_RE.fullmatch(label) for label in labels):
        return False
    return any(c.isalpha() for c in labels[-1])


def line(host: str, api_key: str, proof_key: str) -> str:
    """The invite line for one instance. Refuses anything it could not read
    back, so a line that is printed is a line that splits."""
    if not host_ok(host):
        raise InviteError("an invite names a plain host name, such as"
                          " app.whichports.com")
    if not isinstance(api_key, str) or not isinstance(proof_key, str) \
            or not API_KEY_RE.fullmatch(api_key) or not PROOF_KEY_RE.fullmatch(proof_key):
        raise InviteError("an invite holds an API key and then a proof key,"
                          " each as instances issues it")
    return f"{PREFIX}{host}_{api_key}_{proof_key}"


def split(text) -> dict:
    """The three settings inside one invite line. Spaces around it are a
    paste's, not the line's. Anything else that is not a whole line is
    refused, never half read."""
    value = text.strip() if isinstance(text, str) else ""
    match = LINE_RE.fullmatch(value)
    if not match or not host_ok(match.group("host")):
        raise InviteError(
            f"{INVITE_ENV} is not a whole invite line. It is one line that"
            f" starts with {PREFIX}, then the host, the API key and the proof"
            " key. Copy it again whole")
    return {
        PROBER_API_ENV: "https://" + match.group("host"),
        PROBER_API_KEY_ENV: match.group("api"),
        PROBER_PROOF_KEY_ENV: match.group("proof"),
    }


def settings(environ) -> dict:
    """The three settings the invite in `environ` stands for, or {} when no
    invite is set. Refuses an invite set beside any of the three lines."""
    value = (environ.get(INVITE_ENV) or "").strip()
    if not value:
        return {}
    beside = [name for name in (PROBER_API_ENV, PROBER_API_KEY_ENV, PROBER_PROOF_KEY_ENV)
              if (environ.get(name) or "").strip()]
    if beside:
        raise InviteError(
            f"{INVITE_ENV} and {', '.join(beside)} are both set. Keep one:"
            " the invite line, or the three prober lines")
    return split(value)
