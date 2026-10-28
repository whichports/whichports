"""Which addresses an alert may be sent to.

This decides where this control plane may post: a webhook, a chat channel, a
log collector. It never decides what may be probed. That is `app/authz.py`
and the registry, and nothing here loosens either.

## Two rules, and one setting between them

**The strict rule** is the one this module was written beside: an address is
sent to only when it is globally routable. It is `authz._is_probeable`,
called and not copied, so the two cannot drift.

**On an instance somebody runs themselves** their chat server or their log
collector usually sits inside their own network, and the strict rule refuses
the one destination they have. The owner decided on 2026-10-03 that such an
instance may send to a private address, through one setting our own hosted
service never sets (docs/record 4.336):

    WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES=yes

Off unless it is exactly `yes`. Any other value that is not empty is refused
by `setting_complaint`, which `selfhost/worker.py` asks at start, so a typing
error is never read as on or as off.

## What the setting lets through, by name and not by a property

Python's `is_private` is not "the private ranges". Its documentation, read
2026-10-03 (docs.python.org/3/library/ipaddress.html): "True if the address
is defined as not globally reachable by iana-ipv4-special-registry (for IPv4)
or iana-ipv6-special-registry (for IPv6)". That takes in loopback, link-local
and the documentation ranges. So the networks are named here:

    10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16   private use, RFC 1918
    fc00::/7                                    unique local, RFC 4193
    100.64.0.0/10                               shared address space, RFC 6598

The last is neither private nor global to Python. It is the range a carrier
uses behind its own address translation, and the range Tailscale numbers a
tailnet from: "This IP address is known as a Tailscale IP address and comes
from the shared address space defined in RFC6598" (tailscale.com/kb/1015,
read 2026-10-03).

## What stays refused whatever the setting says

    unspecified     is_unspecified     no machine is behind it
    loopback        is_loopback        the instance's own server, where the
                                       ingest listens. And the worker that
                                       sends an alert runs on a Docker network
                                       of its own while Send test runs on the
                                       host's, so on loopback the two would
                                       reach different machines (measured on
                                       a server, 2026-10-03)
    link-local      is_link_local      169.254.0.0/16 holds the cloud metadata
                                       address, and fe80::/10 means nothing
                                       without an interface
    multicast       is_multicast
    reserved        is_reserved
    v4 written as v6  ipv4_mapped      it would carry a v4 address past the
                                       v6 rule, as authz says of a target
    everything else that is not globally routable and not one of the five
    networks: the documentation and benchmarking ranges, fec0::/10, 0.0.0.0/8

Every address a name resolves to is asked, at the moment of sending, and one
refused address refuses the name. That is the caller's loop and it did not
change.
"""
import ipaddress
import os

SETTING = "WHICHPORTS_ALERTS_TO_PRIVATE_ADDRESSES"
ON = "yes"

PRIVATE_NETWORKS = tuple(ipaddress.ip_network(text) for text in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "fc00::/7",                                        # RFC 4193
))
# Its own constant so that one line takes it out again: the owner's yes to a
# tailnet address is of 2026-10-03, and a carrier's customers share the range.
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")   # RFC 6598
LET_THROUGH_WITH_THE_SETTING = PRIVATE_NETWORKS + (SHARED_ADDRESS_SPACE,)

# What a refusal says. Both show on a screen, so neither names the setting:
# a screen names none of our machinery, and on the hosted service the reader
# could not set it anyway. An operator reads `OPERATOR_NOTE`.
REFUSED_AS_PRIVATE = ("which is inside a private network. Alerts are sent to"
                      " public addresses only.")
REFUSED_ALWAYS = "which is not an address an alert can be sent to."
OPERATOR_NOTE = (f"On an instance of your own, {SETTING}={ON} in its .env"
                 " lets an alert go to a private address")


def strict(ip) -> bool:
    """Globally routable and nothing else. Today's rule, by the function
    that has always decided it."""
    # Imported here and not at the top: `selfhost/worker.py` loads this file
    # by its path at start, to ask `setting_complaint`, and never puts the
    # control plane on its import path.
    from . import authz
    return authz._is_probeable(ip)


def _never(ip) -> bool:
    """Refused whatever the setting says. The docstring above gives the
    reason for each."""
    if ip.is_unspecified or ip.is_loopback or ip.is_link_local:
        return True
    if ip.is_multicast or ip.is_reserved:
        return True
    return ip.version == 6 and ip.ipv4_mapped is not None


def in_a_private_network(ip) -> bool:
    """One of the five named networks, and nothing that is refused always."""
    if _never(ip):
        return False
    return any(ip.version == network.version and ip in network
               for network in LET_THROUGH_WITH_THE_SETTING)


def private_too(ip) -> bool:
    """The strict rule, and the five named networks beside it."""
    return strict(ip) or in_a_private_network(ip)


def setting_complaint(environ=None) -> str:
    """"" when the setting is absent, empty or exactly `yes`. Otherwise a
    sentence, so that a wrong value stops a start and is never guessed at."""
    environ = os.environ if environ is None else environ
    value = (environ.get(SETTING) or "").strip()
    if value in ("", ON):
        return ""
    return (f"{SETTING} is set to something other than {ON}. Set it to {ON}"
            " to let alerts go to private addresses, or take the line out")


def guard(environ=None):
    """The rule in force: `private_too` when the setting is exactly `yes`,
    `strict` in every other case, a wrong value included."""
    environ = os.environ if environ is None else environ
    if (environ.get(SETTING) or "").strip() == ON:
        return private_too
    return strict


def refusal(ip) -> str:
    """The end of the sentence for an address the rule in force refused."""
    return REFUSED_AS_PRIVATE if in_a_private_network(ip) else REFUSED_ALWAYS


def operator_note(reason: str) -> str:
    """What an operator is told beside a refusal, and a screen is not:
    which setting lets a private address through. Empty for any other
    refusal."""
    return OPERATOR_NOTE if REFUSED_AS_PRIVATE in (reason or "") else ""
