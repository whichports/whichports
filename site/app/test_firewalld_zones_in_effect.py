"""The Rules tab draws the firewalld zones that are in effect (docs/RECORD.md 4.342).

firewalld keeps a file for every zone it ships. On a Fedora 44 server that is
thirteen files, of which two are in effect: `public` on the server's
interface and `docker` on Docker's bridge. Until 2026-10-03 the tab listed the
rules of every file as if all applied: 27 rows, one of them the whole port
range of a zone nothing used (4.223).

Which zones are in effect is in the kernel's ruleset, in the same document.
The shapes below are the lines firewalld writes there, read from real
firewalld with nft:

  - a Fedora 44 server with Docker, firewalld 2.4.4, 2026-10-03
  - firewalld 0.9.11, 1.3.4, 2.1.2 and 2.4.3 run in containers, 2026-10-03
  - a zone entered for a source, firewalld 2.4.0 on a server, 2026-09-30 (4.213)

    Run from site/: python3 -m pytest app/test_firewalld_zones_in_effect.py
"""
import pathlib
import re
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import render_live as rl  # noqa: E402


def zone(name, services=(), ports=(), target="", origin="vendor"):
    z = {"file": f"{name}.xml", "origin": origin, "name": name, "parsed": True}
    if services:
        z["services"] = list(services)
    if ports:
        z["ports"] = [{"port": port, "protocol": protocol} for port, protocol in ports]
    if target:
        z["target"] = target
    return z


# The thirteen zone files of the Fedora 44 server, as the agent reported them.
FEDORA_ZONES = [
    zone("docker", target="ACCEPT", origin="etc"),
    zone("FedoraServer", services=("cockpit", "dhcpv6-client", "ssh")),
    zone("FedoraWorkstation", services=("dhcpv6-client", "samba-client", "ssh"),
         ports=(("1025-65535", "udp"), ("1025-65535", "tcp"))),
    zone("block", target="%%REJECT%%"),
    zone("dmz", services=("ssh",)),
    zone("drop", target="DROP"),
    zone("external", services=("ssh",)),
    zone("home", services=("dhcpv6-client", "mdns", "samba-client", "ssh")),
    zone("internal", services=("dhcpv6-client", "mdns", "samba-client", "ssh")),
    zone("nm-shared", services=("dhcp", "dns", "ssh"), target="ACCEPT"),
    zone("public", services=("dhcpv6-client", "mdns", "ssh")),
    zone("trusted", target="ACCEPT"),
    zone("work", services=("dhcpv6-client", "mdns", "ssh")),
]

# filter_INPUT_POLICIES on that server, line for line.
FEDORA_DISPATCH = [
    'iifname "docker0" jump filter_IN_policy_allow-host-ipv6',
    'iifname "docker0" jump filter_IN_docker',
    'iifname "docker0" accept',
    'iifname "eth0" jump filter_IN_policy_allow-host-ipv6',
    'iifname "eth0" jump filter_IN_public',
    'iifname "eth0" [reject]',
    "jump filter_IN_policy_allow-host-ipv6",
    "jump filter_IN_public",
    "[reject]",
]


# One zone in effect and no Docker: the public zone on its interface and as
# the default.
PUBLIC_ALONE = ['iifname "eth0" jump filter_IN_policy_allow-host-ipv6',
                'iifname "eth0" jump filter_IN_public',
                "jump filter_IN_policy_allow-host-ipv6",
                "jump filter_IN_public", "[reject]"]


def rules(lines):
    return [{"text": line, "rendered": "partial" if "[" in line else "full"} for line in lines]


def kernel(lines, chain="filter_INPUT_POLICIES", table=("inet", "firewalld")):
    return {"status": "collected", "tables": [{
        "family": table[0], "name": table[1],
        "chains": [
            {"name": "filter_INPUT", "type": "filter", "hook": "input", "priority": 10,
             "policy": "accept", "rules": rules([f"jump {chain}", "[reject]"])},
            {"name": chain, "rules": rules(lines)},
        ]}]}


def document(zones=None, dispatch=None, **kernel_shape):
    doc = {"firewalld": {"status": "collected", "conf": {"DefaultZone": "public"},
                         "sources": {"etc_zones": {"status": "collected"},
                                     "vendor_zones": {"status": "collected"}},
                         "zones": FEDORA_ZONES if zones is None else zones}}
    if dispatch is not None:
        doc["nftables"] = kernel(dispatch, **kernel_shape)
    return doc


def text_of(html):
    """What a person reads, tags and icons taken out."""
    return " ".join(re.sub(r"<[^>]+>", " ", re.sub(r"<svg.*?</svg>", "", html, flags=re.S)).split())


def block(doc):
    """The firewalld block as the Rules tab builds it, and its rule count."""
    return rl.firewalld_block("web-01", doc["firewalld"], "3m",
                              rl.firewalld_zones_in_effect(doc))


def halves(html):
    """The block's rows in effect, and what is inside its fold."""
    before, _, inside = html.partition("<details")
    return before, inside


def rows_in(html):
    return html.count('class="fwr"')


def notes_in(html):
    """The small words beside each row's from column, one per row that has any."""
    return re.findall(r'<span class="rfr[^"]*">[^<]*<small>([^<]*)</small>', html)


# ------------------------------------------------- which zones the kernel enters

def test_the_fedora_server_has_two_zones_in_effect_each_on_its_interface():
    assert rl.firewalld_zones_in_effect(document(dispatch=FEDORA_DISPATCH)) == {
        "docker": ["docker0"], "public": ["eth0"]}


@pytest.mark.parametrize("chain, lines", [
    # firewalld 2.1.2, 2.4.3 and 2.4.4
    ("filter_INPUT_POLICIES", ['iifname "eth0" jump filter_IN_policy_allow-host-ipv6',
                               'iifname "eth0" jump filter_IN_public',
                               "jump filter_IN_policy_allow-host-ipv6",
                               "jump filter_IN_public"]),
    # firewalld 0.9.11 and 1.3.4
    ("filter_INPUT_ZONES", ['iifname "eth0" goto filter_IN_public',
                            "goto filter_IN_public"]),
])
def test_every_measured_version_names_the_zone_and_its_interface(chain, lines):
    assert rl.firewalld_zones_in_effect(document(dispatch=lines, chain=chain)) == {
        "public": ["eth0"]}


def test_a_zone_entered_only_as_the_default_is_in_effect_with_no_interface():
    doc = document(dispatch=["jump filter_IN_policy_allow-host-ipv6", "jump filter_IN_public"])
    assert rl.firewalld_zones_in_effect(doc) == {"public": []}


def test_a_zone_entered_for_a_source_is_in_effect_with_no_interface():
    """4.213, firewalld 2.4.0: the line is a source and not an interface. The
    zone applies, and the tab's from column already carries the source out of
    the zone's own file."""
    doc = document(dispatch=["ip saddr 192.0.2.0/24 jump filter_IN_internal",
                             'iifname "eno1" jump filter_IN_public',
                             "jump filter_IN_public"])
    assert rl.firewalld_zones_in_effect(doc) == {"internal": [], "public": ["eno1"]}


def test_the_older_source_chain_counts_as_well():
    """firewalld 0.9.11 keeps a chain of its own for sources. Its lines were
    not measured, so only this is held: a line there that enters a zone puts
    the zone in effect."""
    doc = document(dispatch=["ip saddr 192.0.2.0/24 goto filter_IN_internal"],
                   chain="filter_INPUT_ZONES_SOURCE")
    assert rl.firewalld_zones_in_effect(doc) == {"internal": []}


def test_a_zone_on_two_interfaces_names_both_once_in_the_kernels_order():
    doc = document(dispatch=['iifname "eth1" jump filter_IN_public',
                             'iifname "eth0" jump filter_IN_public',
                             'iifname "eth1" jump filter_IN_public',
                             "jump filter_IN_public"])
    assert rl.firewalld_zones_in_effect(doc) == {"public": ["eth1", "eth0"]}


def test_a_policy_is_not_a_zone():
    doc = document(dispatch=['iifname "eth0" jump filter_IN_policy_allow-host-ipv6',
                             "jump filter_IN_policy_allow-host-ipv6"])
    assert rl.firewalld_zones_in_effect(doc) is None


@pytest.mark.parametrize("line", [
    'iifname "eth0" accept',
    "[reject]",
    "jump filter_INPUT_POLICIES",
    "jump filter_FWD_public",
    "tcp dport 22 accept",
    "",
])
def test_a_line_that_enters_no_zone_puts_nothing_in_effect(line):
    assert rl.firewalld_zones_in_effect(document(dispatch=[line])) is None


@pytest.mark.parametrize("doc", [
    {},
    {"nftables": None},
    {"nftables": "collected"},
    {"nftables": {"status": "permission_denied", "tables": []}},
    {"nftables": {"status": "collected"}},
    {"nftables": {"status": "collected", "tables": "none"}},
    {"nftables": {"status": "collected", "tables": [None, 7, "x"]}},
    {"nftables": {"status": "collected", "tables": [{"family": "inet", "name": "firewalld"}]}},
    {"nftables": {"status": "collected", "tables": [
        {"family": "inet", "name": "firewalld", "chains": [None, {"name": "filter_INPUT_POLICIES"}]}]}},
    {"nftables": {"status": "collected", "tables": [
        {"family": "inet", "name": "firewalld", "chains": [
            {"name": "filter_INPUT_POLICIES", "rules": [None, {"text": None}, {"text": 5}]}]}]}},
])
def test_a_kernel_that_does_not_say_is_none_and_never_raises(doc):
    assert rl.firewalld_zones_in_effect(doc) is None


def test_a_kernel_section_that_was_not_collected_is_none_whatever_it_holds():
    doc = document(dispatch=FEDORA_DISPATCH)
    doc["nftables"]["status"] = "permission_denied"
    assert rl.firewalld_zones_in_effect(doc) is None


@pytest.mark.parametrize("table", [("ip", "firewalld"), ("inet", "filter"),
                                   ("inet", "firewalld_policy_drop")])
def test_only_firewallds_own_table_is_read(table):
    """The same chain names in somebody else's table say nothing about
    firewalld."""
    assert rl.firewalld_zones_in_effect(document(dispatch=FEDORA_DISPATCH, table=table)) is None


def test_the_same_lines_in_another_chain_of_firewallds_table_are_not_read():
    doc = document(dispatch=FEDORA_DISPATCH, chain="filter_FORWARD_POLICIES")
    assert rl.firewalld_zones_in_effect(doc) is None


# ------------------------------------------------------------- what the tab draws

def test_only_the_zone_in_effect_is_listed_and_counted():
    html, count = block(document(dispatch=PUBLIC_ALONE))
    shown, _folded = halves(html)

    assert count == 3
    assert rows_in(shown) == 3
    said = text_of(shown)
    for service in ("dhcpv6-client", "mdns", "ssh"):
        assert service in said
    # The whole port range of a zone nothing uses is the row 4.223 was about.
    assert "1025-65535" not in said
    assert "FedoraWorkstation" not in said


def test_the_blocks_own_line_names_the_zone_and_its_interface():
    html, _count = block(document(dispatch=PUBLIC_ALONE))
    head = html.split('class="rh"', 1)[0]
    assert "zone public on eth0" in text_of(head)
    # One zone in effect holds rules, so no row repeats its name.
    shown, _folded = halves(html)
    assert notes_in(shown) == ["service", "service", "service"]


def test_the_other_zones_are_behind_one_fold_that_says_how_many():
    html, _count = block(document(dispatch=FEDORA_DISPATCH))
    shown, folded = halves(html)

    assert html.count("<details") == 1
    assert "8 zones not in effect" in text_of(folded)
    assert "not in effect" not in text_of(shown)
    # Their rules are all there, one click down, each row naming its zone
    # beside it, since a fold holds the rows of several.
    assert rows_in(folded) == 24
    notes = notes_in(folded)
    assert len(notes) == 24
    assert notes.count("service, zone FedoraWorkstation") == 3
    assert notes.count("zone FedoraWorkstation") == 2      # its two port ranges
    for name in ("FedoraServer", "FedoraWorkstation", "dmz", "external", "home",
                 "internal", "nm-shared", "work"):
        assert f"service, zone {name}" in notes, name
    said = text_of(folded)
    assert "1025-65535" in said
    # A zone in effect is never in the fold, and neither is a zone that holds
    # no rule: the three with a target alone have nothing to list.
    for name in ("public", "docker", "block", "drop", "trusted"):
        assert f"zone {name}" not in said, name
    # The fold comes after the rules in effect and inside the block.
    assert html.index("<details") > html.rindex('class="fwr"', 0, html.index("<details"))
    assert html.endswith("</details></div>")


def test_the_column_titles_are_drawn_once():
    """The fold's rows stand under the block's own titles. With no rule in
    effect there are none above, so the fold carries them."""
    html, _count = block(document(dispatch=FEDORA_DISPATCH))
    assert html.count('class="rh"') == 1
    assert html.index('class="rh"') < html.index("<details")

    # The one zone in effect holds neither a rule nor a target.
    nothing_listed = document([zone("empty"), zone("work", services=("ssh",))],
                              ['iifname "eth0" jump filter_IN_empty'])
    html, count = block(nothing_listed)
    assert count == 0
    assert html.count('class="rh"') == 1
    assert html.index('class="rh"') > html.index("<details")


def test_the_strip_counts_the_rules_in_effect():
    doc = document(dispatch=PUBLIC_ALONE)
    said = text_of(rl.rules_tab_body(doc, "web-01"))
    assert "Rules 3 across them" in said
    assert "Firewalls active 1 on this server" in said


def test_every_row_has_an_id_of_its_own_in_and_out_of_the_fold():
    html, _count = block(document(dispatch=PUBLIC_ALONE))
    ids = re.findall(r'<input type="checkbox" class="rsel" id="([^"]+)"', html)
    assert len(ids) == 27 and len(set(ids)) == 27


def test_an_opened_row_says_the_interface():
    html, _count = block(document(dispatch=PUBLIC_ALONE))
    shown, folded = halves(html)
    assert "interface eth0" in text_of(shown)
    assert "interface" not in text_of(folded)


def test_a_kernel_that_does_not_say_leaves_the_tab_as_it_was():
    """No nftables section, firewalld on its iptables backend, a table this
    page cannot read: every zone is drawn, as before, and nothing is called
    in effect or not."""
    html, count = block(document(dispatch=None))

    assert count == 27 and rows_in(html) == 27
    assert "<details" not in html
    said = text_of(html)
    assert "not in effect" not in said and " on eth0" not in said
    assert "zone FedoraWorkstation" in said and "1025-65535" in said


def test_two_zones_in_effect_name_themselves_on_their_rows():
    zones = [zone("public", services=("ssh",)),
             zone("internal", services=("samba",)),
             zone("work", services=("ssh",))]
    doc = document(zones, ["ip saddr 192.0.2.0/24 jump filter_IN_internal",
                           'iifname "eno1" jump filter_IN_public',
                           "jump filter_IN_public"])
    html, count = block(doc)
    shown, folded = halves(html)

    assert count == 2
    assert notes_in(shown) == ["service, zone public on eno1", "service, zone internal"]
    # Two zones hold rules, so the block's own line names neither.
    assert "zone" not in text_of(html.split('class="rh"', 1)[0])
    assert "1 zone not in effect" in text_of(folded) and "zone work" in text_of(folded)


def test_a_zone_the_kernel_names_and_no_file_holds_draws_nothing_and_breaks_nothing():
    doc = document([zone("public", services=("ssh",))],
                   ['iifname "eth0" jump filter_IN_ghost', "jump filter_IN_public"])
    html, count = block(doc)

    assert count == 1 and "<details" not in html
    assert "ghost" not in text_of(html)


def test_no_zone_out_of_effect_draws_no_fold():
    doc = document([zone("public", services=("ssh",))], ["jump filter_IN_public"])
    html, count = block(doc)
    assert count == 1 and "<details" not in html
    assert "zone public" in text_of(html) and " on " not in text_of(html.split('class="rh"', 1)[0])


def test_a_name_from_the_kernel_is_text_and_never_markup():
    """An interface's name is the host's own word. It goes on the block's
    line and into a row's card, escaped both times."""
    doc = document([zone("public", services=("ssh",))],
                   ['iifname "<b>x</b>" jump filter_IN_public'])
    html, _count = block(doc)
    assert "<b>x</b>" not in html
    assert "&lt;b&gt;x&lt;/b&gt;" in html


def test_zone_files_that_could_not_be_read_still_say_so():
    """The guard the block already had: a refused zone directory is not a
    firewalld with no rules, whatever the kernel says is in effect."""
    doc = document([], FEDORA_DISPATCH)
    doc["firewalld"]["sources"]["etc_zones"] = {"status": "permission_denied"}
    html, count = block(doc)
    assert count == 0 and "not readable" in text_of(html)
