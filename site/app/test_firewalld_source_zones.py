"""A firewalld zone entered only for some sources says so on the Rules tab:
its rows are from those sources, never from anywhere.

    Run from site/: python3 -m pytest app/test_firewalld_source_zones.py

docs/PRODUCT.md 8d: the jumps that lead to a rule count with it. A zone
entered through `ip saddr 192.0.2.0/24 jump filter_IN_internal` takes that
range and nobody else, and on v6 it takes nothing, since an `ip saddr` jump
cannot be taken by a v6 packet.

The second big test, 24 October 2026, an AlmaLinux 10.2 server with
firewalld 2.4.3 and rootful Podman (case C6).
"""
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402
from test_firewalld_zones_in_effect import kernel, text_of, zone  # noqa: E402


def document(zones, dispatch):
    return {"firewalld": {"status": "collected", "conf": {"DefaultZone": "public"},
                          "sources": {"etc_zones": {"status": "collected"},
                                      "vendor_zones": {"status": "collected"}},
                          "zones": zones},
            "nftables": kernel(dispatch)}


def rows_of(doc):
    """The firewalld block's rows in effect as a person reads each across,
    on the Rules tab as it is built for the page."""
    html = rl.rules_tab_body(doc, "box")
    block = html[html.index("firewalld"):]
    block = block.partition("<details")[0]
    return [text_of(label) for label in re.findall(r'<label class="fwr".*?</label>', block, re.S)]


# ------------------------------------------------- a zone's source from the kernel
#
# Netavark puts the container network, 10.88.0.0/16, into firewalld's trusted
# zone as its source while it runs, so the trusted zone's file holds no source
# and the kernel's way into the zones does. The row read "ACCEPT any port
# anywhere, target, zone trusted": the server open to everyone, where the
# probes found 9100 and 9102 unreachable from both probers.

PODMAN_DISPATCH = ["ip saddr 10.88.0.0/16 jump filter_IN_trusted",
                   'iifname "eth0" jump filter_IN_public',
                   "jump filter_IN_public", "[reject]"]


def podman_server():
    return document([zone("public", services=("ssh", "dhcpv6-client", "cockpit"), origin="etc"),
                     zone("trusted", target="ACCEPT")], PODMAN_DISPATCH)


def test_a_zone_entered_only_for_a_source_shows_its_target_from_that_source():
    rows = rows_of(podman_server())
    trusted = [row for row in rows if "zone trusted" in row]
    assert trusted == ["4 accept any port 10.88.0.0/16 target, zone trusted"]
    assert not any("anywhere" in row for row in trusted)


def test_a_zone_entered_for_everybody_keeps_anywhere():
    rows = rows_of(podman_server())
    assert [row for row in rows if "zone public" in row] == [
        "1 allow ssh anywhere service, zone public on eth0",
        "2 allow dhcpv6-client anywhere service, zone public on eth0",
        "3 allow cockpit anywhere service, zone public on eth0"]


def test_a_zone_entered_for_two_sources_says_some_addresses():
    doc = podman_server()
    doc["nftables"]["tables"][0]["chains"][1]["rules"][0:1] = [
        {"text": "ip saddr 10.88.0.0/16 jump filter_IN_trusted", "rendered": "full"},
        {"text": "ip saddr 10.89.0.0/16 jump filter_IN_trusted", "rendered": "full"}]
    trusted = [row for row in rows_of(doc) if "zone trusted" in row]
    assert trusted == [f"4 accept any port {rl.SOME_ADDRESSES} target, zone trusted"]


def test_a_zone_also_entered_on_an_interface_is_from_anywhere_on_it():
    """Entered on an interface as well, it takes whatever arrives there,
    so its sources are not the whole of who it takes."""
    doc = podman_server()
    doc["nftables"]["tables"][0]["chains"][1]["rules"].insert(
        1, {"text": 'iifname "podman0" jump filter_IN_trusted', "rendered": "full"})
    trusted = [row for row in rows_of(doc) if "zone trusted" in row]
    assert trusted == ["4 accept any port podman0 target, zone trusted"]


# ------------------------------ one file a zone, and v4 alone for a v4 source
#
# The same server's zone internal, entered only for 192.0.2.0/24, was listed
# twice: its rules from 192.0.2.0/24, then its services again from anywhere,
# and zone public's three services twice too. The agent reports a zone's
# file from /etc/firewalld/zones and the one of the same name from
# /usr/lib/firewalld/zones, and firewalld reads the first: "The files will
# overload the default configuration files" (firewalld(1), DIRECTORIES, at
# firewalld.org, read 2026-10-26). The second set was the vendor files. And
# a v4 source jump is never taken by a v6 packet, so such a zone's rules are
# v4 alone.

def c6_server():
    internal = zone("internal", services=("ssh", "mdns", "samba-client", "dhcpv6-client", "cockpit"),
                    ports=(("9100", "tcp"),), origin="etc")
    internal["source_addrs"] = ["192.0.2.0/24"]
    return document(
        [zone("public", services=("ssh", "dhcpv6-client", "cockpit"), origin="etc"), internal,
         zone("internal", services=("ssh", "mdns", "samba-client", "dhcpv6-client", "cockpit")),
         zone("public", services=("ssh", "dhcpv6-client", "cockpit")),
         zone("trusted", target="ACCEPT")],
        ["ip saddr 192.0.2.0/24 jump filter_IN_internal",
         "ip saddr 10.88.0.0/16 jump filter_IN_trusted",
         'iifname "eth0" jump filter_IN_public', "jump filter_IN_public", "[reject]"])


def test_each_zone_is_listed_once_from_the_file_firewalld_reads():
    rows = rows_of(c6_server())
    public = [row for row in rows if "zone public" in row]
    internal = [row for row in rows if "zone internal" in row]
    assert len(public) == 3 and len(internal) == 6
    assert [row for row in rows if "zone trusted" in row] == [
        "10 accept any port 10.88.0.0/16 target, zone trusted"]
    assert len(rows) == 10


def test_a_zone_entered_only_for_a_v4_source_is_from_it_and_v4_alone():
    internal = [row for row in rows_of(c6_server()) if "zone internal" in row]
    assert all("192.0.2.0/24" in row and "anywhere" not in row for row in internal)
    assert internal[0] == "4 allow ssh v4 192.0.2.0/24 service, zone internal"
    assert internal[-1] == "9 allow 9100 tcp/ v4 192.0.2.0/24 zone internal"


def test_a_zone_for_everybody_names_no_family():
    public = [row for row in rows_of(c6_server()) if "zone public" in row]
    assert public[0] == "1 allow ssh anywhere service, zone public on eth0"
    assert not any(" v4 " in row for row in public)


def test_a_vendor_file_alone_is_still_read():
    """No /etc copy: the vendor file is the one firewalld reads."""
    doc = podman_server()
    assert [row for row in rows_of(doc) if "zone public" in row][0] == \
        "1 allow ssh anywhere service, zone public on eth0"
    doc["firewalld"]["zones"][0]["origin"] = "vendor"
    assert len([row for row in rows_of(doc) if "zone public" in row]) == 3
