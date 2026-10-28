"""What the probe aims at, and the reason a port that was not probed carries.

Measured on the live fleet on 2026-08-27, against three real host documents:

  - the only globally routable **bind** address on any of the three was the
    DHCP client's, on udp/68. Every service binds the wildcard, which names no
    address, so v4 was probed by the accident of DHCP and a statically
    addressed host would have yielded nothing at all.
  - **no host offered a v6 target**, because nothing binds a specific v6
    address. Two of the three hold a global v6 address, say so in their own
    documents, and answer on 22, 80 and 443 from the internet. Every v6 port
    read `not_tested` with the reason `no_address_in_family`.

That reason is the reason this is a fix rather than a widening: it states that
the host has no address in that family, and the host's own document said the
opposite.

**Nothing here loosens the gate**, and the last group is what pins that: an
address nobody proved is still refused, and the only thing that changes is
which refusal it gets.
"""
import pytest

from app import authz, db, prober, prober_cli, store

# github.com's pages range, the same addresses the neighbouring authz tests
# use, so nothing here can be mistaken for a real customer address.
V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"


def socket(port, family="v4", bind="0.0.0.0", protocol="tcp"):
    return {"protocol": protocol, "family": family, "bind_address": bind,
            "port": port}


def document(*, listening=(), addresses=None, interface_status="collected"):
    doc = {
        "schema_version": 1,
        "hostname": "box",
        "collected_at_unix": 1_700_000_000,
        "sockets": {"status": "collected", "listening": list(listening)},
    }
    if addresses is not None:
        doc["interface_addresses"] = {"status": interface_status,
                                      "addresses": list(addresses)}
    return doc


def interface(address, family, name="eth0", is_global=True):
    return {"interface": name, "family": family, "address": address,
            "global": is_global}


# ------------------------------------------- the shape the whole fleet has

def test_a_wildcard_bound_host_with_an_interface_address_is_still_a_target():
    """The measured shape of every host on the fleet: every service binds the
    wildcard, and the address is only on the interface."""
    doc = document(listening=[socket(22), socket(443, "v6", "::")],
                   addresses=[interface(V4, "v4"), interface(V6, "v6")])
    targets, _refused = prober_cli.candidate_targets(doc)
    assert targets == [V4, V6]


def test_both_families_are_offered_from_the_interface_alone():
    """The half that was missing. A host binding only `::` still has its v6
    address offered, so the engine can answer for that family at all."""
    doc = document(listening=[socket(443, "v6", "::")],
                   addresses=[interface(V6, "v6")])
    targets, _refused = prober_cli.candidate_targets(doc)
    assert targets == [V6]


def test_a_bind_address_still_wins_its_place_first():
    """Order is not a security property and it is a comparison property: a
    run's output is compared with the last one, so the order has to be
    deterministic and it has to keep the shape it had."""
    doc = document(listening=[socket(22, bind=V4)],
                   addresses=[interface(V6, "v6"), interface(V4, "v4")])
    targets, _refused = prober_cli.candidate_targets(doc)
    assert targets == [V4, V6]


def test_one_address_in_both_halves_is_one_target():
    doc = document(listening=[socket(22, bind=V4)],
                   addresses=[interface(V4, "v4")])
    targets, refused = prober_cli.candidate_targets(doc)
    assert targets == [V4]
    assert refused == []


# --------------------------------------------------- what is still refused

@pytest.mark.parametrize("address", [
    "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.1.1",
    "100.64.0.1", "fd7a:115c:a1e0::1", "fe80::1", "224.0.0.1",
])
def test_an_address_that_can_never_be_a_target_is_refused_from_either_half(address):
    """The interface list is the host's own text exactly as the socket list
    is, so it goes through the same door. Tailscale's carrier-NAT and unique
    local addresses are in here on purpose: they are what the fleet's home box
    actually holds."""
    from_socket = document(listening=[socket(22, bind=address)])
    from_interface = document(addresses=[interface(address, "v4")])
    assert prober_cli.candidate_targets(from_socket)[0] == []
    assert prober_cli.candidate_targets(from_interface)[0] == []


def test_the_same_text_refused_twice_is_reported_once():
    """A wildcard bind and a wildcard in the interface list are one problem,
    and a dry run listing it twice reads as two."""
    doc = document(listening=[socket(22), socket(80)],
                   addresses=[interface("0.0.0.0", "v4")])
    _targets, refused = prober_cli.candidate_targets(doc)
    assert [text for text, _why in refused] == ["0.0.0.0"]


@pytest.mark.parametrize("section", [
    None, "not a dict", {"status": "permission_denied"},
    {"status": "collected", "addresses": "not a list"},
    {"status": "collected", "addresses": [None, 7, "text"]},
    {"status": "collected", "addresses": [{"address": None}, {"nope": 1}]},
])
def test_an_unreadable_interface_section_costs_nothing(section):
    """A host document is hostile input. An interface section of any shape
    must never lose the sockets beside it, and must never raise."""
    doc = document(listening=[socket(22, bind=V4)])
    if section is not None:
        doc["interface_addresses"] = section
    targets, _refused = prober_cli.candidate_targets(doc)
    assert targets == [V4]


def test_a_document_from_an_agent_that_predates_the_section_still_works():
    doc = document(listening=[socket(22, bind=V4)])
    assert "interface_addresses" not in doc
    assert prober_cli.candidate_targets(doc)[0] == [V4]


# ------------------------------------------------ the gate is not loosened

@pytest.fixture()
def con(tmp_path):
    c = db.connect(str(tmp_path / "p.db"))
    db.init(c)
    authz.init(c)
    prober.init(c)
    yield c
    c.close()


def test_an_offered_address_nobody_proved_is_still_refused(con):
    """The property this change must not buy anything at the expense of.
    `candidate_targets` decides what is offered and `authz.may_probe` decides
    what is allowed, and only the first one moved."""
    assert not authz.may_probe(con, V6).allowed
    doc = document(listening=[socket(443, "v6", "::")],
                   addresses=[interface(V6, "v6")])
    targets, _refused = prober_cli.candidate_targets(doc)
    assert targets == [V6]
    # Offered, and still refused.
    assert not authz.may_probe(con, targets[0]).allowed


def test_the_refusal_a_port_carries_is_now_the_true_one(con):
    """The reason string is the point of the fix.

    Before, an unauthorised v6 address was never offered, so the engine was
    handed no v6 target and said `no_address_in_family`, which the document
    contradicts. Now it is offered, refused by the gate, and the port says
    `no_authorization`, which is what happened.
    """
    import asyncio
    store.add_host(con, "box")
    doc = document(listening=[socket(443, "v6", "::")],
                   addresses=[interface(V6, "v6")])
    targets, _refused = prober_cli.candidate_targets(doc)

    engine = prober.Prober(connect=_never_connects, vantage="test")
    run = asyncio.run(engine.measure(authz.DatabaseAuthority(con), targets, [443]))
    v6 = [r for r in run.results if r.family == "v6"]
    assert [r.state for r in v6] == [prober.STATE_NOT_TESTED]
    assert v6[0].reason == prober.REASON_NO_AUTHORIZATION
    assert v6[0].reason != prober.REASON_NO_ADDRESS_IN_FAMILY


def test_a_family_the_host_really_has_no_address_in_still_says_so(con):
    """The reason has not simply been replaced. A host with no v6 address
    anywhere still gets `no_address_in_family` for v6, because that is then
    the true answer."""
    import asyncio
    doc = document(listening=[socket(22, bind=V4)], addresses=[interface(V4, "v4")])
    targets, _refused = prober_cli.candidate_targets(doc)
    engine = prober.Prober(connect=_never_connects, vantage="test")
    run = asyncio.run(engine.measure(authz.DatabaseAuthority(con), targets, [22]))
    v6 = [r for r in run.results if r.family == "v6"]
    assert v6[0].reason == prober.REASON_NO_ADDRESS_IN_FAMILY


async def _never_connects(target, family, port):
    """A connect primitive that fails the test if anything reaches it. Every
    case here is refused by the gate before a socket exists."""
    raise AssertionError(
        f"the engine tried to connect to {target} port {port}, and every"
        " address in this file is unauthorised")
