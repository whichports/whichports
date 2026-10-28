"""Which of the provider's servers is this host. By proved address first.

The owner, 2026-09-20: a Hetzner token read six servers and the Integrations
screen said "0 in your fleet", the host page said "server not found", and the
Hetzner firewall he then attached showed nowhere. The match was whole-name
equality in three places and never looked at an address. His Hetzner server
is not called what his whichports server is called, which is the ordinary
case and not a mistake of his.

The address is the fact both sides hold. The provider states the server's
public IPv4 and its IPv6 network. The registry holds the addresses this host
proved, each one observed on a completed connection and corroborated by the
host's own document (docs/PRODUCT.md 5). A proved address that is the
server's, or lies inside its network, names the server. The name is the
fallback, as it was, for a host that has proved nothing yet.
"""

import pytest

from app import hetzner


def server(id, name, ipv4=None, network=None):
    return hetzner.Server(id=id, name=name, status="running", ipv4=ipv4,
                          ipv6_network=network, firewalls=())


def inventory(*servers):
    return hetzner.Inventory(servers=tuple(servers), firewalls=())


STUDENT = server(7, "ubuntu-4gb-nbg1-2", "192.88.99.179", "2001:20:1c19:d085::/64")
OTHER = server(8, "web", "203.0.113.9", "2001:db8:1::/64")


def test_a_proved_v4_address_names_the_server_whatever_it_is_called():
    got = hetzner.match_server(inventory(OTHER, STUDENT), "student-net",
                               ["192.88.99.179"])
    assert got is STUDENT


def test_a_proved_v6_address_inside_the_servers_network_names_it():
    """What student-net had on the day: only its v6 address proved."""
    got = hetzner.match_server(inventory(OTHER, STUDENT), "Student-Net",
                               ["2001:20:1c19:d085::1"])
    assert got is STUDENT


def test_a_v6_address_outside_every_network_names_nothing():
    assert hetzner.match_server(inventory(OTHER, STUDENT), "student-net",
                                ["2001:20:1c19:d086::1"]) is None


def test_the_address_wins_over_a_name_that_points_elsewhere():
    """A host called `web` whose proved address is the other server's. The
    address was observed. The name was typed."""
    assert hetzner.match_server(inventory(OTHER, STUDENT), "web",
                                ["192.88.99.179"]) is STUDENT


def test_with_no_proved_address_the_name_still_matches_as_before():
    assert hetzner.match_server(inventory(OTHER, STUDENT), "WEB", []) is OTHER
    assert hetzner.match_server(inventory(OTHER, STUDENT), "we", []) is None
    assert hetzner.match_server(inventory(OTHER, STUDENT), "", []) is None
    assert hetzner.match_server(inventory(OTHER, STUDENT), None, []) is None


def test_a_proved_address_that_is_nobodys_falls_back_to_the_name():
    assert hetzner.match_server(inventory(OTHER, STUDENT), "web",
                                ["198.51.100.1"]) is OTHER


def test_addresses_that_name_two_different_servers_name_neither():
    """It cannot happen on one machine. If the data ever says it, the answer
    is no match and never a guess, and the name does not get to break the tie:
    a firewall attached to the wrong host is worse than none shown."""
    assert hetzner.match_server(inventory(OTHER, STUDENT), "web",
                                ["192.88.99.179", "203.0.113.9"]) is None


def test_two_addresses_of_the_same_server_are_one_match():
    got = hetzner.match_server(inventory(OTHER, STUDENT), "x",
                               ["192.88.99.179", "2001:20:1c19:d085::1"])
    assert got is STUDENT


@pytest.mark.parametrize("junk", ["", "not an address", "192.88.99.179/32",
                                  None, 7, "::ffff:192.88.99.179"])
def test_an_address_that_does_not_parse_matches_nothing(junk):
    assert hetzner.match_server(inventory(STUDENT), "nobody", [junk]) is None


@pytest.mark.parametrize("bad_network", ["", "not a network", None, "2001:20::1/200"])
def test_a_network_the_provider_wrote_badly_matches_nothing(bad_network):
    odd = server(9, "odd", None, bad_network)
    assert hetzner.match_server(inventory(odd), "nobody",
                                ["2001:20:1c19:d085::1"]) is None


def test_a_v4_address_never_matches_a_v6_network_and_the_reverse():
    only6 = server(9, "six", None, "::/0")
    assert hetzner.match_server(inventory(only6), "nobody", ["192.88.99.179"]) is None
    only4 = server(9, "four", "192.88.99.179", None)
    assert hetzner.match_server(inventory(only4), "nobody",
                                ["2001:20:1c19:d085::1"]) is None


# ------------------------------------------------ across several projects
#
# Since 2026-09-27 a workspace may hold one token per project, and each token's
# snapshot stays its own inventory (docs/RECORD.md 4.206). The first outside
# workspace had a server in a project its only token did not read, so the
# rule has to look in every project and keep the one order it always had.

CHAT = server(9, "chat-prod", "203.0.113.20", "2001:db8:2::/64")


def test_a_host_in_the_second_project_is_found_there():
    got = hetzner.match_in_projects((inventory(STUDENT, OTHER), inventory(CHAT)),
                                    "mattermost", ["203.0.113.20"])
    assert got == (1, CHAT)


def test_a_proved_address_in_one_project_outranks_a_name_in_another():
    named_like_it = server(10, "mattermost", "198.51.100.4")
    got = hetzner.match_in_projects((inventory(named_like_it), inventory(CHAT)),
                                    "mattermost", ["2001:db8:2::1"])
    assert got == (1, CHAT)


def test_the_same_server_read_through_two_tokens_is_one_server():
    """One project connected twice lists every server twice, under the id the
    provider gave it. That is not two servers."""
    got = hetzner.match_in_projects((inventory(CHAT), inventory(CHAT)),
                                    "mattermost", ["203.0.113.20"])
    assert got == (0, CHAT)
    by_name = hetzner.match_in_projects((inventory(CHAT), inventory(CHAT)),
                                        "chat-prod", [])
    assert by_name == (0, CHAT)


def test_two_servers_in_two_projects_holding_the_hosts_addresses_is_no_match():
    """One machine cannot be two servers, and which token came first does not
    decide which of them it is."""
    impostor = server(11, "elsewhere", None, "2001:db8:2::/64")
    got = hetzner.match_in_projects((inventory(CHAT), inventory(impostor)),
                                    "mattermost", ["203.0.113.20", "2001:db8:2::1"])
    assert got is None


def test_one_name_in_two_projects_is_no_match():
    twin = server(12, "chat-prod", "198.51.100.8")
    assert hetzner.match_in_projects((inventory(CHAT), inventory(twin)),
                                     "chat-prod", []) is None


def test_a_name_in_one_project_is_found_when_no_address_names_anything():
    got = hetzner.match_in_projects((inventory(STUDENT), inventory(CHAT)),
                                    "Chat-Prod", ["192.0.2.1"])
    assert got == (1, CHAT)


@pytest.mark.parametrize("projects, hostname, addresses", [
    ((), "chat-prod", ["203.0.113.20"]),
    ((inventory(),), "chat-prod", ["203.0.113.20"]),
    ((inventory(CHAT),), "", []),
    ((inventory(CHAT),), None, None),
    ((inventory(CHAT),), "chat-prod-2", ["not an address"]),
])
def test_nothing_to_match_is_no_match(projects, hostname, addresses):
    assert hetzner.match_in_projects(projects, hostname, addresses) is None


def test_one_project_answers_exactly_as_match_server_does():
    """`match_server` is this rule's one-project case, so the two can never
    disagree about a server."""
    cases = [(inventory(OTHER, STUDENT), "student-net", ["192.88.99.179"]),
             (inventory(OTHER, STUDENT), "web", []),
             (inventory(OTHER, STUDENT), "nobody", ["192.0.2.9"])]
    for inv, name, addresses in cases:
        found = hetzner.match_in_projects((inv,), name, addresses)
        assert hetzner.match_server(inv, name, addresses) == (found[1] if found else None)
