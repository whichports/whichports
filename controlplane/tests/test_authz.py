"""The probe authorisation registry.

    python -m pytest tests/test_authz.py

SI-6 says an address is probed only after proof of control, recorded, and
expiring when the evidence goes away. This file is where that is enforced
rather than promised, so the tests that matter most are the ones about
refusing:

  - a target that authorises itself by asserting a bind address
  - a report that arrived through NAT
  - evidence that came back through a redirect
  - an authorisation that has lapsed, or been revoked, or belongs to a
    revoked host
  - the v6 address of a host whose v4 address was proved

No test here touches a real resolver, a real web server or a real socket. The
resolver and the fetcher are injected, which is the reason they are arguments
at all.

The last section is the adversarial pass, added after `docs/RECORD.md` 4.46
found a guard that was documented, in CI, and not guarding. Everything in it
is written from the position of a caller trying to get an address probed that
it has not proved, and three of its tests were red against the code as it
stood.
"""

import ipaddress
import json
import pathlib
import re
import sqlite3
import threading
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import itertools

import pytest

from app import alerts, authz, db, store

NOW = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)

# Python's ipaddress module marks the documentation ranges (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) private, and this registry
# refuses anything that is not globally routable on purpose. So the tests use
# addresses that are globally routable. Nothing here ever connects to one.
V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.109.153"


@pytest.fixture()
def db_file(tmp_path):
    """The database file itself. The concurrency tests need a second
    connection to it, which is how a second process sees the same rows."""
    return str(tmp_path / "cp.db")


@pytest.fixture()
def con(db_file):
    connection = db.connect(db_file)
    db.init(connection)
    authz.init(connection)
    yield connection
    connection.close()


def add_host(con, name="box"):
    host_id, _ = store.add_host(con, name)
    return host_id


def document(bind_addresses, family_override=None, interfaces=None,
             interface_section=None):
    """A host document carrying exactly these listening sockets, and optionally
    an interface_addresses section.

    `interfaces` is a list of address strings, shaped into entries the way the
    agent's collector shapes them. `interface_section` replaces the whole
    section with whatever is handed in, which is how the malformed cases are
    written.
    """
    listening = []
    for address in bind_addresses:
        family = family_override or ("v6" if ":" in address else "v4")
        listening.append({"protocol": "tcp", "family": family,
                          "bind_address": address, "port": 443})
    doc = {"schema_version": 1, "hostname": "box", "collected_at_unix": 0,
           "sockets": {"status": "ok", "listening": listening}}
    if interfaces is not None:
        doc["interface_addresses"] = {
            "status": "collected",
            "addresses": [interface_entry(address, family_override)
                          for address in interfaces],
        }
    if interface_section is not None:
        doc["interface_addresses"] = interface_section
    return json.dumps(doc)


def interface_entry(address, family_override=None, **overrides):
    """One interface_addresses entry, shaped the way the agent's collector
    shapes it. Overrides let a test write a deliberately wrong one."""
    try:
        parsed = ipaddress.ip_address(str(address).split("%")[0])
    except ValueError:
        parsed = None
    entry = {
        "interface": "eth0",
        "family": family_override or ("v6" if ":" in str(address) else "v4"),
        "address": address,
        "global": bool(parsed is not None and parsed.is_global),
    }
    entry.update(overrides)
    return entry


# Sockets that say nothing about which addresses the host holds, which is what
# a real server looks like: every service on it binds the wildcard.
WILDCARD_ONLY = ["0.0.0.0", "::"]


def rows(con):
    return con.execute("SELECT * FROM authorizations ORDER BY id").fetchall()


# =========================================================== what may be a target

def test_an_address_is_stored_in_one_spelling():
    """Two spellings of one v6 address must not become two rows, or revoking
    one would leave the other live."""
    long_form = "2606:50c0:8000:0000:0000:0000:0000:0153"
    assert authz.normalise_target(long_form) == authz.normalise_target(V6)


def test_the_family_comes_from_the_address():
    assert authz.normalise_target(V4)[1] == authz.FAMILY_V4
    assert authz.normalise_target(V6)[1] == authz.FAMILY_V6


@pytest.mark.parametrize("address", [
    "0.0.0.0", "127.0.0.1", "10.1.2.3", "192.168.1.1", "172.16.0.1",
    "169.254.1.1", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "100.64.0.1",                       # carrier NAT, shared with strangers
    "::", "::1", "fe80::1", "fc00::1", "ff02::1", "fec0::1",
    "::ffff:185.199.108.153",           # a v4 address wearing a v6 costume
    "not an address", "", "1.2.3.4.5", "185.199.108.153/32", " ",
])
def test_an_address_that_cannot_be_probed_is_refused_at_the_door(address):
    with pytest.raises(authz.TargetError):
        authz.normalise_target(address)


@pytest.mark.parametrize("address", [None, 12345, b"185.199.108.153", ["1.2.3.4"]])
def test_something_that_is_not_text_is_refused(address):
    with pytest.raises(authz.TargetError):
        authz.normalise_target(address)


# ================================================================== the gate

def test_an_address_nobody_proved_is_refused(con):
    decision = authz.may_probe(con, V4, now=NOW)
    assert decision.allowed is False
    assert authz.NO_PROOF in decision.reason


@pytest.mark.parametrize("address", [
    "", "not an address", "127.0.0.1", "10.0.0.1", "100.64.0.1", "::1",
    "0.0.0.0", None, 12345,
])
def test_the_gate_refuses_anything_not_positively_proved(con, address):
    """The default is no, for every shape of input, including the ones that
    are not addresses at all."""
    assert authz.may_probe(con, address, now=NOW).allowed is False


def test_the_raising_form_raises(con):
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(con, V4, now=NOW)


def test_the_raising_form_returns_the_canonical_address(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V6, document([V6]), now=NOW)
    long_form = "2606:50c0:8000:0000:0000:0000:0000:0153"
    assert authz.require_probe_authorization(con, long_form, now=NOW) == V6


def test_an_unreadable_expiry_refuses_rather_than_allows(con):
    """A row written by hand, or by a build that is not this one. Refusing to
    probe because a timestamp cannot be read is the only safe way round."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    con.execute("UPDATE authorizations SET expires_at = 'whenever'")
    con.commit()
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_naive_expiry_is_read_as_utc(con):
    """Rows written without an offset must not make the comparison raise, and
    must not silently be read as local time."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    naive = (NOW + timedelta(days=1)).replace(tzinfo=None).isoformat()
    con.execute("UPDATE authorizations SET expires_at = ?", (naive,))
    con.commit()
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    assert authz.may_probe(con, V4, now=NOW + timedelta(days=2)).allowed is False


def test_a_caller_passing_a_naive_clock_gets_an_answer_not_a_crash(con):
    """Comparing a naive datetime with an aware one raises, and a TypeError
    out of the gate in the middle of a prober run is worse than reading the
    naive one as UTC, which is what the stored stamps are anyway."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]),
                             now=NOW.replace(tzinfo=None))
    assert authz.may_probe(con, V4, now=NOW.replace(tzinfo=None)).allowed is True
    lapsed = (NOW + timedelta(days=30)).replace(tzinfo=None)
    assert authz.may_probe(con, V4, now=lapsed).allowed is False


def test_the_timestamp_reader_agrees_with_the_sweep_module(con):
    """`authz._parse` is deliberately the same helper as `alerts._parse`,
    duplicated rather than moved because lifting a shared helper out is its
    own PR. This pins that the two never drift apart."""
    for value in ["", None, "not a date", "2026-13-45T99:99:99",
                  "2026-08-15T12:00:00+00:00", "2026-08-15T12:00:00",
                  "2026-08-15T14:00:00+02:00"]:
        assert authz._parse(value) == alerts._parse(value)


# ====================================================== agent-derived proof

def test_a_report_from_an_address_the_host_also_binds_is_proof(con):
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert result.recorded is True
    assert authz.may_probe(con, V4, now=NOW).allowed is True


def test_a_host_cannot_authorise_an_address_by_claiming_to_bind_it(con):
    """The trap this whole module exists to avoid. The document is written by
    the host, so a bind address is an assertion and never proof. Only the
    address we observed the report arriving from can be authorised, and only
    when the host says it holds that one too."""
    host_id = add_host(con)
    claimed = "1.1.1.1"
    result = authz.record_agent_proof(con, host_id, V4, document([claimed]), now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, claimed, now=NOW).allowed is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_report_through_nat_authorises_nothing(con):
    """The host is on 10.0.0.5 and the report arrives from the gateway. The
    gateway is not the host's address to give away, and behind carrier NAT it
    belongs to strangers."""
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, V4, document(["10.0.0.5"]),
                                      now=NOW)
    assert result.recorded is False
    assert "NAT" in result.reason
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_wildcard_bind_is_not_a_claim_to_any_address(con):
    """Most services bind 0.0.0.0, which says nothing about which addresses
    the host holds. This fails closed rather than reading the wildcard as
    "every address"."""
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, V4, document(["0.0.0.0", "::"]),
                                      now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_the_observed_address_must_itself_be_probeable(con):
    """A report that arrives from a private address, which happens when the
    control plane and the host are on one network, proves nothing anybody
    outside could use."""
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, "10.0.0.5",
                                      document(["10.0.0.5"]), now=NOW)
    assert result.recorded is False


def test_the_documents_own_family_has_to_agree_with_its_address(con):
    """A document whose family field disagrees with the address it carries is
    a document we cannot read confidently, so it proves nothing."""
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, V4,
                                      document([V4], family_override="v6"),
                                      now=NOW)
    assert result.recorded is False


@pytest.mark.parametrize("doc", [
    "", "not json", "[]", "null", "{}",
    '{"sockets": null}', '{"sockets": {}}', '{"sockets": {"listening": "no"}}',
    '{"sockets": {"listening": [null, 3, "x"]}}',
    '{"sockets": {"listening": [{"bind_address": 5}]}}',
    '{"sockets": {"listening": [{"bind_address": "not an address"}]}}',
])
def test_a_malformed_document_proves_nothing_and_raises_nothing(con, doc):
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, V4, doc, now=NOW)
    assert result.recorded is False


def test_an_unknown_host_proves_nothing(con):
    result = authz.record_agent_proof(con, 9999, V4, document([V4]), now=NOW)
    assert result.recorded is False
    assert rows(con) == []


def test_a_revoked_host_proves_nothing(con):
    host_id = add_host(con)
    store.revoke_host(con, "box")
    result = authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert result.recorded is False


def test_revoking_the_host_withdraws_what_its_agent_proved(con):
    """The credential is gone, so the evidence is gone with it. Leaving the
    address probeable because a row has not expired yet would be exactly the
    "evidence went away" case SI-6 names."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    store.revoke_host(con, "box")
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_reporting_agent_refreshes_one_row_rather_than_filling_the_table(con):
    """Fifteen minute reports for a week is 672 of them. One row per report
    would bury the history instead of being it."""
    host_id = add_host(con)
    for minute in range(0, 120, 15):
        authz.record_agent_proof(con, host_id, V4, document([V4]),
                                 now=NOW + timedelta(minutes=minute))
    assert len(rows(con)) == 1
    assert rows(con)[0]["verified_at"] == (NOW + timedelta(minutes=105)).isoformat()


def test_the_evidence_records_what_was_observed_and_what_matched(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4, "0.0.0.0"]), now=NOW)
    evidence = json.loads(rows(con)[0]["evidence"])
    assert evidence["observed_source"] == V4
    assert [entry["bind_address"] for entry in evidence["matching_sockets"]] == [V4]


# ============================== the host's interface addresses, added 2026-08-17

# Decided by the owner, RECORD.md 4.55 item 3. The host-side half of the
# agent-derived proof reads the addresses the host says it holds on its
# interfaces as well as the addresses its sockets are bound to.
#
# **Why that does not weaken SI-6, which is what every test below is really
# about.** An interface address is asserted by the host exactly as a bind
# address is. The security comes entirely from the address we observed the
# report arriving from, which the host cannot forge because the connection
# completed and the credential authenticated it. The host-side list only
# corroborates that the host knows it holds the address we already saw.
# Widening that list does not move the anchor, and the tests here are written
# to fail if it ever does.

def test_a_report_from_an_address_the_host_holds_on_an_interface_is_proof(con):
    """The case the whole change exists for. Every socket binds the wildcard,
    which is what an ordinary server looks like, and the host reports the
    address on an interface. Before this, such a host could never
    auto-authorise."""
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interfaces=[V4]), now=NOW)
    assert result.recorded is True
    assert authz.may_probe(con, V4, now=NOW).allowed is True


def test_a_host_cannot_authorise_an_address_by_claiming_it_on_an_interface(con):
    """The anchor, restated for the new half. The document is written by the
    host, so an interface address is an assertion and never proof. Only the
    address we observed the report arriving from can be authorised."""
    host_id = add_host(con)
    claimed = "1.1.1.1"
    result = authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interfaces=[claimed]), now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, claimed, now=NOW).allowed is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_an_interface_address_list_cannot_reach_past_the_observed_address(con):
    """A host holding several addresses proves only the one its report arrived
    from. The others are real addresses it really holds, and they are still not
    addresses this control plane observed anything from."""
    host_id = add_host(con)
    others = [OTHER_V4, V6, "185.199.110.153"]
    result = authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interfaces=[V4] + others),
        now=NOW)
    assert result.recorded is True
    for other in others:
        assert authz.may_probe(con, other, now=NOW).allowed is False


def test_a_host_behind_nat_still_auto_authorises_nothing(con):
    """The interface list is exactly where a NAT'd host's private address shows
    up, so this is the case that would break if the widening were done
    carelessly. The report arrives from the gateway, the host holds 10.0.0.5,
    and the two do not agree."""
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interfaces=["10.0.0.5"]),
        now=NOW)
    assert result.recorded is False
    assert "NAT" in result.reason
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    assert authz.may_probe(con, "10.0.0.5", now=NOW).allowed is False


@pytest.mark.parametrize("address", [
    "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.1.1", "127.0.0.1",
    "100.64.0.1", "100.127.255.254", "fe80::1", "fc00::1", "::1", "0.0.0.0",
    "::", "224.0.0.1",
])
def test_an_interface_address_nobody_could_probe_authorises_nothing(con, address):
    """The address is both what the host claims on an interface and what the
    report appears to arrive from, so the two halves agree and it is still
    refused: none of these is one operator's address to authorise, and
    carrier-NAT space is shared with strangers by definition."""
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, address, document(WILDCARD_ONLY, interfaces=[address]),
        now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, address, now=NOW).allowed is False


def test_an_interface_address_with_a_zone_index_is_not_a_match(con):
    """`2606:50c0:8000::153%eth0` names an interface on one machine. The target
    it appears to match is refused a zone index by name, so an entry carrying
    one must not match the same address without one, or one address would
    become two rows and revoking one would leave the other live."""
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, V6, document(WILDCARD_ONLY, interfaces=[V6 + "%eth0"]),
        now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V6, now=NOW).allowed is False


def test_the_zone_index_refusal_is_written_down_rather_than_inherited():
    """Structural, and it exists because deleting the refusal above leaves the
    suite green.

    The functional answer comes from CPython: `IPv6Address.__eq__` has compared
    scope ids since 3.9, so `::1%eth0` is already not equal to `::1` and the
    match already fails without any code of ours. That is somebody else's
    behaviour to keep, and this registry refuses a zone index in
    `normalise_target` by name rather than leaning on it. So the check in
    `_entry_claims_address` is written out too, and this pins both halves: the
    line is there, and the language behaviour it stands in for still holds. The
    same shape as the constant-time and redirect-handler canaries below, for
    the same reason: no functional assertion can see the difference.
    """
    source = pathlib.Path(authz.__file__).read_text(encoding="utf-8")
    assert 'if getattr(parsed, "scope_id", None):' in source, \
        "a zone-indexed claim is no longer refused explicitly"
    zoned = ipaddress.ip_address(V6 + "%eth0")
    assert zoned != ipaddress.ip_address(V6), \
        "this Python compares zone indexes differently, the explicit refusal is now load-bearing"
    assert authz._entry_claims_address(
        {"address": V6 + "%eth0", "family": "v6"}, "address",
        ipaddress.ip_address(V6), "v6") is False


def test_a_v4_interface_claim_cannot_authorise_a_v6_target(con):
    """v4 and v6 are separate targets (PRODUCT.md 4b rule 3). A host holding a
    v4 address says nothing about the v6 address a report arrived from."""
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, V6, document(WILDCARD_ONLY, interfaces=[V4]), now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V6, now=NOW).allowed is False


def test_the_documents_own_family_has_to_agree_with_its_interface_address(con):
    """A document that disagrees with itself proves nothing, the same rule the
    bind addresses get. Both spellings of the disagreement are refused."""
    host_id = add_host(con)
    wrong_family = {"status": "collected",
                    "addresses": [interface_entry(V4, family_override="v6")]}
    assert authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interface_section=wrong_family),
        now=NOW).recorded is False

    missing_family = {"status": "collected",
                      "addresses": [{"interface": "eth0", "address": V4}]}
    assert authz.record_agent_proof(
        con, host_id, V4,
        document(WILDCARD_ONLY, interface_section=missing_family),
        now=NOW).recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_the_global_flag_in_the_document_decides_nothing(con):
    """The agent computes a `global` flag for a person reading the document at
    a terminal. **Two rulesets for one fact is how documentation drifts**, so
    this pins that the flag is not one of them: probeability is re-derived here
    from the address text, and flipping the flag either way changes no answer.
    """
    host_id = add_host(con)
    # Marked not global, and still authorised, because the address is the one
    # we observed and it is globally routable.
    lying_false = {"status": "collected",
                   "addresses": [interface_entry(V4, **{"global": False})]}
    assert authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interface_section=lying_false),
        now=NOW).recorded is True

    # Marked global, and still refused, because a private address is not a
    # target no matter what the host calls it.
    lying_true = {"status": "collected",
                  "addresses": [interface_entry("10.0.0.5", **{"global": True})]}
    assert authz.record_agent_proof(
        con, host_id, "10.0.0.5",
        document(WILDCARD_ONLY, interface_section=lying_true),
        now=NOW).recorded is False
    assert authz.may_probe(con, "10.0.0.5", now=NOW).allowed is False


def test_the_sections_own_status_does_not_decide_the_match(con):
    """A section whose read was denied still carries the addresses that were
    read (agent/internal/collect/interfaces.go), and they are still assertions
    by the host. The anchor is the observed address either way, so the status
    is information for a person and never a gate. Pinned so nobody later makes
    a host's own label decide whether its claim counts."""
    host_id = add_host(con)
    denied = {"status": "permission_denied", "cause": "permission",
              "addresses": [interface_entry(V4)]}
    assert authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interface_section=denied),
        now=NOW).recorded is True


def test_a_document_from_an_older_agent_still_proves_what_it_used_to(con):
    """Every host on the fleet runs a build with no interface_addresses section
    at all, and will until a package is published. Such a document has to keep
    working exactly as it did."""
    host_id = add_host(con)
    old = document([V4])
    assert "interface_addresses" not in old
    assert authz.record_agent_proof(con, host_id, V4, old, now=NOW).recorded is True
    assert authz.may_probe(con, V4, now=NOW).allowed is True


@pytest.mark.parametrize("section", [
    None, "", "not a section", [], 0, True,
    {}, {"status": "collected"},
    {"addresses": None}, {"addresses": "no"}, {"addresses": {}},
    {"addresses": [None, 3, "x", []]},
    {"addresses": [{"address": 5, "family": "v4"}]},
    {"addresses": [{"address": "not an address", "family": "v4"}]},
    {"addresses": [{"address": "185.199.108.153/24", "family": "v4"}]},
    {"addresses": [{"family": "v4"}]},
])
def test_a_malformed_interface_section_proves_nothing_and_raises_nothing(
        con, section):
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, V4,
        document(WILDCARD_ONLY, interface_section=section), now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_malformed_interface_section_never_costs_a_valid_socket_match(con):
    """Sections are read independently here for the same reason the agent
    collects them independently: one unreadable half must not lose the other."""
    host_id = add_host(con)
    result = authz.record_agent_proof(
        con, host_id, V4,
        document([V4], interface_section={"addresses": "rubbish"}), now=NOW)
    assert result.recorded is True
    assert authz.may_probe(con, V4, now=NOW).allowed is True


def test_the_evidence_says_which_interface_addresses_matched(con):
    host_id = add_host(con)
    authz.record_agent_proof(
        con, host_id, V4,
        document(WILDCARD_ONLY, interfaces=[V4, OTHER_V4, "10.0.0.5"]), now=NOW)
    evidence = json.loads(rows(con)[0]["evidence"])
    assert evidence["observed_source"] == V4
    assert [entry["address"] for entry
            in evidence["matching_interface_addresses"]] == [V4]
    # The socket half is still its own key, so a reader can tell which half of
    # the document proved the address.
    assert evidence["matching_sockets"] == []


def test_both_halves_appear_in_the_evidence_when_both_match(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4,
                             document([V4], interfaces=[V4]), now=NOW)
    evidence = json.loads(rows(con)[0]["evidence"])
    assert [entry["bind_address"] for entry in evidence["matching_sockets"]] == [V4]
    assert [entry["address"] for entry
            in evidence["matching_interface_addresses"]] == [V4]


def test_an_interface_address_expires_like_any_other_agent_proof(con):
    """Nothing about the new half changes the lifetime. A running agent
    re-proves every fifteen minutes, so a week means the agent stopped
    reporting from that address."""
    host_id = add_host(con)
    doc = document(WILDCARD_ONLY, interfaces=[V4])
    authz.record_agent_proof(con, host_id, V4, doc, now=NOW)
    lapsed = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS + 60)
    assert authz.may_probe(con, V4, now=lapsed).allowed is False


def test_revoking_the_host_withdraws_an_interface_proof_too(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4,
                             document(WILDCARD_ONLY, interfaces=[V4]), now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    store.revoke_host(con, "box")
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_document_cannot_smuggle_a_target_through_the_interface_section(con):
    """Only `interface_addresses.addresses[].address` is read, so a section
    adding fields that look like the ones this module writes changes nothing."""
    host_id = add_host(con)
    section = {
        "status": "collected",
        "observed_source": "1.1.1.1",
        "matching_interface_addresses": [{"address": "1.1.1.1", "family": "v4"}],
        "addresses": [interface_entry("10.0.0.5", target="1.1.1.1",
                                      observed_source=V4)],
    }
    result = authz.record_agent_proof(
        con, host_id, V4, document(WILDCARD_ONLY, interface_section=section),
        now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, "1.1.1.1", now=NOW).allowed is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


# ================================================ v4 and v6 are separate targets

def test_authorising_v4_does_not_authorise_v6(con):
    """PRODUCT.md 4b rule 3, at the registry level: they are different rows
    for different addresses and one says nothing about the other."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4, V6]), now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    assert authz.may_probe(con, V6, now=NOW).allowed is False


def test_each_family_is_proved_on_its_own(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    authz.record_agent_proof(con, host_id, V6, document([V6]), now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    assert authz.may_probe(con, V6, now=NOW).allowed is True
    assert len(rows(con)) == 2


def test_revoking_one_family_leaves_the_other_alone(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    authz.record_agent_proof(con, host_id, V6, document([V6]), now=NOW)
    authz.revoke(con, V4, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    assert authz.may_probe(con, V6, now=NOW).allowed is True


# ============================================================ the DNS TXT proof

def resolver_returning(*strings):
    def resolve(name):
        resolve.asked = name
        return list(strings)
    resolve.asked = None
    return resolve


def test_the_dns_proof_names_the_reverse_dns_name(con):
    """The one name in DNS that only the holder of the address delegation can
    write. A forward name would prove control of a name, not of an address."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    assert challenge.publish_at == "153.108.199.185.in-addr.arpa"
    v6_challenge = authz.start_proof(con, V6, authz.METHOD_DNS_TXT, now=NOW)
    assert v6_challenge.publish_at.endswith(".ip6.arpa")


def test_a_published_txt_token_is_proof(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    resolve = resolver_returning("something else", challenge.token)
    result = authz.verify_proof(con, challenge.id, now=NOW, resolver=resolve)
    assert result.recorded is True
    assert resolve.asked == challenge.publish_at
    assert authz.may_probe(con, V4, now=NOW).allowed is True


def test_the_token_may_carry_surrounding_whitespace(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    resolve = resolver_returning(f"  {challenge.token}\n")
    assert authz.verify_proof(con, challenge.id, now=NOW, resolver=resolve).recorded


def test_a_wrong_token_proves_nothing(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    resolve = resolver_returning("whpa_" + "0" * 64)
    result = authz.verify_proof(con, challenge.id, now=NOW, resolver=resolve)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_name_holding_nothing_proves_nothing(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    result = authz.verify_proof(con, challenge.id, now=NOW,
                                resolver=resolver_returning())
    assert result.recorded is False


def test_a_resolver_that_cannot_answer_proves_nothing(con):
    from app import dnstxt

    def resolve(name):
        raise dnstxt.DnsError("no resolver answered")

    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    result = authz.verify_proof(con, challenge.id, now=NOW, resolver=resolve)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_token_proves_only_the_address_it_was_minted_for(con):
    """Replay. The token is public once published, so what stops it being
    used elsewhere is that it is bound to one target in its own row."""
    first = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    second = authz.start_proof(con, OTHER_V4, authz.METHOD_DNS_TXT, now=NOW)
    result = authz.verify_proof(con, second.id, now=NOW,
                                resolver=resolver_returning(first.token))
    assert result.recorded is False
    assert authz.may_probe(con, OTHER_V4, now=NOW).allowed is False


def test_only_the_hash_of_a_pending_token_is_stored(con):
    """The same posture as the host credential in app/store.py: a copy of the
    database must never contain something that can complete a proof."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    stored = con.execute("SELECT * FROM authz_challenges").fetchone()
    assert challenge.token not in json.dumps(dict(stored))
    assert stored["token_hash"] == authz.token_hash(challenge.token)


def test_two_proofs_never_share_a_token(con):
    first = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    second = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    assert first.token != second.token
    assert first.token.startswith(authz.TOKEN_PREFIX)
    assert len(first.token) == len(authz.TOKEN_PREFIX) + 64


def test_a_proof_cannot_be_started_for_an_address_that_cannot_be_a_target(con):
    with pytest.raises(authz.TargetError):
        authz.start_proof(con, "10.0.0.1", authz.METHOD_DNS_TXT, now=NOW)


def test_the_agent_method_is_not_something_anyone_can_start(con):
    """Agent proof is something we observe, never something requested."""
    with pytest.raises(ValueError):
        authz.start_proof(con, V4, authz.METHOD_AGENT, now=NOW)


def test_an_unfinished_proof_closes(con):
    """A token published at a name and then forgotten must not stay live for
    ever."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    later = NOW + timedelta(seconds=authz.CHALLENGE_TTL_SECONDS + 1)
    result = authz.verify_proof(con, challenge.id, now=later,
                                resolver=resolver_returning(challenge.token))
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=later).allowed is False


def test_a_proof_that_does_not_exist_is_refused(con):
    assert authz.verify_proof(con, 4242, now=NOW).recorded is False


# ========================================================= the HTTP token proof

class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, size):
        return self._body[:size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Stands in for the urllib opener, so no request is ever made."""

    def __init__(self, status=200, body=b"", error=None):
        self.status, self.body, self.error = status, body, error
        self.opened = None
        self.timeout = None
        self.handlers = []

    def open(self, request, timeout=None):
        self.opened = request
        self.timeout = timeout
        if self.error is not None:
            raise self.error
        return FakeResponse(self.status, self.body)


def install_opener(monkeypatch, opener):
    """The handlers are kept rather than thrown away. Dropping them let the
    module's own redirect handler be deleted with the suite staying green,
    which is what `test_the_fetch_builds_its_opener_with_the_no_redirect_handler`
    now catches."""
    def build(*handlers):
        opener.handlers = list(handlers)
        return opener

    monkeypatch.setattr(authz.urllib.request, "build_opener", build)


def test_the_http_proof_names_a_url_built_from_the_address(con):
    v4 = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    assert v4.publish_at == f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}"
    v6 = authz.start_proof(con, V6, authz.METHOD_HTTP_TOKEN, now=NOW)
    assert v6.publish_at == f"http://[{V6}]:80{authz.HTTP_WELL_KNOWN_PATH}"


def test_a_served_token_is_proof(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    asked = []

    def fetch(url):
        asked.append(url)
        return challenge.token + "\n"

    result = authz.verify_proof(con, challenge.id, now=NOW, fetcher=fetch)
    assert result.recorded is True
    assert asked == [challenge.publish_at]
    assert authz.may_probe(con, V4, now=NOW).allowed is True


def test_a_wrong_served_token_proves_nothing(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    result = authz.verify_proof(con, challenge.id, now=NOW,
                                fetcher=lambda url: "whpa_" + "0" * 64)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_file_that_cannot_be_read_proves_nothing(con):
    def fetch(url):
        raise authz.ProofError("could not read the token file: URLError")

    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    result = authz.verify_proof(con, challenge.id, now=NOW, fetcher=fetch)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_redirect_is_refused_rather_than_followed(con, monkeypatch):
    """A redirect means the bytes would have come from somewhere other than
    the address being proved, which is the one thing this check is for. The
    agent's report client refuses redirects for the neighbouring reason."""
    for code in authz.REDIRECT_CODES:
        error = urllib.error.HTTPError(
            "http://185.199.108.153/x", code, "Found",
            {"Location": "http://elsewhere.example/token"}, None)
        install_opener(monkeypatch, FakeOpener(error=error))
        with pytest.raises(authz.ProofError) as raised:
            authz.fetch_token_file("http://185.199.108.153/x")
        assert "redirect" in str(raised.value)


def test_a_redirect_never_becomes_a_proof(con, monkeypatch):
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    error = urllib.error.HTTPError(challenge.publish_at, 302, "Found",
                                   {"Location": "http://elsewhere.example/"}, None)
    install_opener(monkeypatch, FakeOpener(error=error))
    result = authz.verify_proof(con, challenge.id, now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_the_opener_has_no_handler_that_would_follow_a_redirect():
    """Structural, because the behaviour above depends on which handler
    urllib ends up with. Every redirect handler in the opener has to be ours."""
    opener = urllib.request.build_opener(authz._NoRedirects())
    redirect_handlers = [h for h in opener.handlers
                         if isinstance(h, urllib.request.HTTPRedirectHandler)]
    assert redirect_handlers
    assert all(isinstance(h, authz._NoRedirects) for h in redirect_handlers)
    assert authz._NoRedirects().redirect_request(
        None, None, 302, "Found", {}, "http://elsewhere.example/") is None


def test_a_served_token_is_read_and_capped(monkeypatch):
    install_opener(monkeypatch, FakeOpener(body=b"whpa_token\n"))
    assert authz.fetch_token_file("http://185.199.108.153/x") == "whpa_token\n"

    install_opener(monkeypatch, FakeOpener(body=b"x" * (authz.MAX_TOKEN_BYTES + 1)))
    with pytest.raises(authz.ProofError):
        authz.fetch_token_file("http://185.199.108.153/x")


@pytest.mark.parametrize("status", [201, 204, 404, 500])
def test_only_a_200_is_a_token_file(monkeypatch, status):
    install_opener(monkeypatch, FakeOpener(status=status, body=b"whpa_token"))
    with pytest.raises(authz.ProofError):
        authz.fetch_token_file("http://185.199.108.153/x")


def test_a_dead_address_is_a_refusal_not_an_exception(monkeypatch):
    install_opener(monkeypatch, FakeOpener(error=urllib.error.URLError("refused")))
    with pytest.raises(authz.ProofError):
        authz.fetch_token_file("http://185.199.108.153/x")


def test_the_fetch_identifies_itself_and_times_out(monkeypatch):
    opener = FakeOpener(body=b"whpa_token")
    install_opener(monkeypatch, opener)
    authz.fetch_token_file("http://185.199.108.153/x")
    assert opener.opened.get_header("User-agent") == authz.USER_AGENT
    assert opener.timeout == authz.HTTP_TIMEOUT_SECONDS


# ============================================================ expiry and re-proof

def test_an_authorisation_stops_counting_when_it_lapses(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    still_live = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS - 60)
    lapsed = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS + 60)
    assert authz.may_probe(con, V4, now=still_live).allowed is True
    assert authz.may_probe(con, V4, now=lapsed).allowed is False


def test_expiry_holds_even_though_the_sweep_never_ran(con):
    """The property that makes expiry real rather than scheduled: the gate
    compares the stored expiry with the clock every time it is asked, so a
    sweep that is not running cannot leave a lapsed authorisation usable."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    lapsed = NOW + timedelta(days=365)
    assert con.execute(
        "SELECT expired_at FROM authorizations").fetchone()["expired_at"] is None
    assert authz.may_probe(con, V4, now=lapsed).allowed is False


def test_the_sweep_writes_down_what_lapsed(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    lapsed = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS + 60)
    result = authz.sweep(con, now=lapsed)
    assert result["expired"] == [V4]
    assert con.execute(
        "SELECT expired_at FROM authorizations").fetchone()["expired_at"] is not None


def test_the_sweep_leaves_a_live_authorisation_alone(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.sweep(con, now=NOW + timedelta(minutes=5))["expired"] == []
    assert authz.may_probe(con, V4, now=NOW + timedelta(minutes=5)).allowed is True


def test_the_sweep_runs_twice_without_expiring_anything_twice(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    lapsed = NOW + timedelta(days=30)
    assert authz.sweep(con, now=lapsed)["expired"] == [V4]
    assert authz.sweep(con, now=lapsed)["expired"] == []


def test_re_proof_restores_a_lapsed_authorisation(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    lapsed = NOW + timedelta(days=30)
    authz.sweep(con, now=lapsed)
    assert authz.may_probe(con, V4, now=lapsed).allowed is False
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=lapsed)
    assert authz.may_probe(con, V4, now=lapsed).allowed is True
    # The lapsed row stays, as the record of what went away and when.
    assert len(rows(con)) == 2
    assert rows(con)[0]["expired_at"] is not None


def test_a_published_proof_is_re_read_rather_than_re_published(con):
    """Re-proof reads the same record again, which is what checks the
    operator still controls the address. Nobody has to edit DNS twice."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    resolve = resolver_returning(challenge.token)
    authz.verify_proof(con, challenge.id, now=NOW, resolver=resolve)
    lapsed = NOW + timedelta(seconds=authz.PUBLISHED_TTL_SECONDS + 60)
    assert authz.may_probe(con, V4, now=lapsed).allowed is False
    again = authz.verify_proof(con, challenge.id, now=lapsed, resolver=resolve)
    assert again.recorded is True
    assert authz.may_probe(con, V4, now=lapsed).allowed is True


def test_re_proof_fails_when_the_record_has_been_taken_down(con):
    """The evidence going away is exactly the case SI-6 names."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       resolver=resolver_returning(challenge.token))
    lapsed = NOW + timedelta(seconds=authz.PUBLISHED_TTL_SECONDS + 60)
    again = authz.verify_proof(con, challenge.id, now=lapsed,
                               resolver=resolver_returning())
    assert again.recorded is False
    assert authz.may_probe(con, V4, now=lapsed).allowed is False


# ================================================================= revocation

def test_revocation_is_immediate(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.revoke(con, V4, now=NOW) == 1
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_revocation_closes_every_live_row_for_the_address(con):
    """Two proofs of one address is two rows. Revoking has to close both, or
    revocation would depend on which one the gate happened to pick."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       fetcher=lambda url: challenge.token)
    assert len(rows(con)) == 2
    assert authz.revoke(con, V4, now=NOW) == 2
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_revocation_cancels_a_proof_in_progress(con):
    """Otherwise a verification a second later would re-authorise the address
    somebody has just revoked, which is not a revocation."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.revoke(con, V4, now=NOW)
    result = authz.verify_proof(con, challenge.id, now=NOW,
                                resolver=resolver_returning(challenge.token))
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_new_proof_after_a_revocation_authorises_again(con):
    authz.revoke(con, V4, now=NOW)
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT,
                                  now=NOW + timedelta(minutes=1))
    result = authz.verify_proof(con, challenge.id, now=NOW + timedelta(minutes=2),
                                resolver=resolver_returning(challenge.token))
    assert result.recorded is True
    assert authz.may_probe(con, V4, now=NOW + timedelta(minutes=2)).allowed is True


def test_an_address_revoke_is_undone_by_the_agents_next_report(con):
    """ops/RUNBOOK.md, "Answering an abuse report": for an address a
    server's agent proved, `authz_cli revoke` is not the stop, because the
    next report proves it again. Revoking the host is."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    authz.revoke(con, V4, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    later = NOW + timedelta(minutes=15)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=later)
    assert authz.may_probe(con, V4, now=later).allowed is True


def test_revoking_an_address_that_was_never_authorised_is_not_an_error(con):
    assert authz.revoke(con, V4, now=NOW) == 0


def test_revoking_something_that_is_not_an_address_is_refused(con):
    with pytest.raises(authz.TargetError):
        authz.revoke(con, "10.0.0.1", now=NOW)


# ============================ never proved, lapsed and revoked read identically

def test_lapsed_revoked_and_never_proved_are_one_answer(con):
    """"An expired authorisation must be indistinguishable from never having
    existed, as far as any future prober is concerned." The dates are in the
    listing, which is where a person looks."""
    host_id = add_host(con, "one")
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    lapsed_at = NOW + timedelta(days=30)
    lapsed = authz.may_probe(con, V4, now=lapsed_at)

    revoked_host = add_host(con, "two")
    authz.record_agent_proof(con, revoked_host, OTHER_V4, document([OTHER_V4]),
                             now=lapsed_at)
    authz.revoke(con, OTHER_V4, now=lapsed_at)
    revoked = authz.may_probe(con, OTHER_V4, now=lapsed_at)

    never = authz.may_probe(con, "185.199.110.153", now=lapsed_at)

    assert lapsed.allowed is revoked.allowed is never.allowed is False
    reasons = {lapsed.reason.replace(V4, "X"),
               revoked.reason.replace(OTHER_V4, "X"),
               never.reason.replace("185.199.110.153", "X")}
    assert len(reasons) == 1, f"the three refusals are distinguishable: {reasons}"


# ================================================== the gate is the only door

# The exclusion list joined the two on 2026-10-20: it decides what is never
# proved, so nothing but the registry may read or write it either.
TABLE_SQL = re.compile(
    r"\b(from|into|update|join|table)\s+(authorizations|authz_challenges"
    r"|authz_exclusions)\b",
    re.IGNORECASE)

# Skipped by name relative to the repo root, never by absolute path part. A
# checkout inside a hidden directory, which is where a worktree lives,
# once made this whole scan match nothing and pass without reading a file.
SKIPPED_DIRECTORIES = {".venv", "node_modules", ".git", ".web", "dist", "__pycache__"}


def _repository_sources():
    root = pathlib.Path(__file__).resolve().parents[2]
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if set(relative.parts) & SKIPPED_DIRECTORIES:
            continue
        if path.name == "authz.py" or "tests" in relative.parts:
            continue
        yield relative, path


def test_the_scan_below_actually_reads_this_repository():
    """The scan is worthless if it matches nothing, and a vacuous pass is
    invisible. This is the canary for it."""
    found = {str(relative) for relative, _ in _repository_sources()}
    assert "controlplane/app/ingest.py" in found
    assert "controlplane/app/authz_cli.py" in found
    assert TABLE_SQL.search('con.execute("SELECT * FROM authorizations")')
    assert TABLE_SQL.search('con.execute("DELETE FROM authz_exclusions")')
    assert not TABLE_SQL.search("authz.list_authorizations(con)")


def test_no_other_python_file_reads_the_authorisation_tables():
    """The part with teeth. `may_probe` is only the one door if nothing else
    can open the tables, so this fails the moment another module writes its
    own query. A prober written in another language needs the same rule
    enforced there, and this cannot see that.
    """
    offenders = [str(relative) for relative, path in _repository_sources()
                 if TABLE_SQL.search(path.read_text(encoding="utf-8",
                                                    errors="replace"))]
    assert offenders == [], (
        "these files query the authorisation tables directly instead of going"
        f" through app.authz: {offenders}")


# ======================================================================= shape

def test_init_is_idempotent(con):
    authz.init(con)
    authz.init(con)
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert len(rows(con)) == 1


def test_a_foreign_key_is_enforced_on_the_host(con):
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(
            "INSERT INTO authorizations (target, family, method, evidence,"
            " account, host_id, verified_at, expires_at)"
            " VALUES ('185.199.108.153', 'v4', 'agent', '{}', 'default', 9999,"
            " '2026-08-15T12:00:00+00:00', '2026-08-16T12:00:00+00:00')")


def test_verifying_evidence_writes_no_report(con):
    """The boundary this module is built around: reading a token file from a
    web server somebody nominated is proof, and it is never a measurement."""
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    before = con.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    authz.verify_proof(con, challenge.id, now=NOW,
                       fetcher=lambda url: challenge.token)
    assert con.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == before


def test_the_listing_shows_lapsed_and_revoked_rows(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    authz.revoke(con, V4, now=NOW)
    listed = authz.list_authorizations(con)
    assert len(listed) == 1
    assert listed[0]["host_name"] == "box"
    assert listed[0]["revoked_at"] is not None


# =========================================================== the adversarial pass
#
# Everything below is written as a hostile caller rather than as a user, and
# the reason it exists is `docs/RECORD.md` 4.46: a guard nobody has tried to
# break is not evidence. Three of these were red against the code as it stood
# and each is named in the PR that fixed it.
#
# The first one is the canary for the rest. Almost every test here asserts a
# refusal, and a registry that had stopped authorising anything at all would
# pass every one of them, which is exactly the vacuous pass 4.46 found.


def test_the_registry_still_authorises_something(con):
    """The canary. Refusal tests are worthless if nothing can ever be
    authorised, so this fails first if the recording path breaks."""
    host_id = add_host(con)
    assert authz.record_agent_proof(con, host_id, V4, document([V4]),
                                    now=NOW).recorded is True
    assert authz.may_probe(con, V4, now=NOW).allowed is True

    challenge = authz.start_proof(con, OTHER_V4, authz.METHOD_DNS_TXT, now=NOW)
    assert authz.verify_proof(con, challenge.id, now=NOW,
                              resolver=resolver_returning(challenge.token)).recorded
    assert authz.may_probe(con, OTHER_V4, now=NOW).allowed is True


# --------------------------------------------------- 1. nothing proved at all

# Globally routable, so they get past the door and are refused by the gate
# rather than by the address rules. Nothing here ever connects to one.
UNPROVED = ["1.1.1.1", "8.8.8.8", "185.199.110.153", "2001:20::1111",
            "2001:20:4001:80f::200e"]


@pytest.mark.parametrize("address", UNPROVED)
def test_an_address_nobody_proved_is_refused_however_it_is_asked(con, address):
    """One authorised address in the same database, so this cannot pass by the
    registry having nothing in it."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.may_probe(con, address, now=NOW).allowed is False
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(con, address, now=NOW)


def test_a_challenge_on_its_own_authorises_nothing(con):
    """Starting a proof is asking a question. Only reading the published
    evidence answers it."""
    authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    assert rows(con) == []


# ------------------------------------------------ 2. expired, with no sweep

def test_an_authorisation_is_dead_the_instant_its_expiry_is_reached(con):
    """The boundary. Equal is expired, so a row cannot be probeable during the
    second it lapses."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    at_expiry = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS)
    assert authz.may_probe(con, V4, now=at_expiry - timedelta(seconds=1)).allowed is True
    assert authz.may_probe(con, V4, now=at_expiry).allowed is False


def test_an_unrun_sweep_cannot_leave_a_lapsed_row_usable(con):
    """PRODUCT.md section 5 and RECORD 4.46 both say expiry is decided against
    the clock rather than by a sweep. This is that claim broken on purpose: the
    sweep is never called, so every `expired_at` is still null, and the gate
    still has to refuse."""
    host_id = add_host(con)
    for index, address in enumerate([V4, OTHER_V4, V6]):
        authz.record_agent_proof(con, host_id, address,
                                 document([address]),
                                 now=NOW + timedelta(minutes=index))
    # Past the expiry of the last of the three, not just the first.
    lapsed = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS, minutes=3)
    stamps = [row["expired_at"] for row in rows(con)]
    assert stamps == [None, None, None], "the sweep must not have run"
    for address in [V4, OTHER_V4, V6]:
        assert authz.may_probe(con, address, now=lapsed).allowed is False
        with pytest.raises(authz.NotAuthorized):
            authz.require_probe_authorization(con, address, now=lapsed)


def test_a_row_the_sweep_wrote_off_stays_off_if_the_clock_steps_back(con):
    """The listing says "expired" once the sweep has written it down, and a
    person acts on that. A clock that steps backwards, which is one NTP
    correction, must not make the gate disagree with what the listing shows."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    lapsed = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS + 1)
    assert authz.sweep(con, now=lapsed)["expired"] == [V4]
    assert authz.list_authorizations(con)[0]["expired_at"] is not None
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_an_expired_challenge_cannot_be_verified_at_its_own_boundary(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    at_expiry = NOW + timedelta(seconds=authz.CHALLENGE_TTL_SECONDS)
    result = authz.verify_proof(con, challenge.id, now=at_expiry,
                                resolver=resolver_returning(challenge.token))
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=at_expiry).allowed is False


# ------------------------------------------- 3. one family is not the other

def test_a_v4_proof_does_not_authorise_the_v6_address(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.may_probe(con, V6, now=NOW).allowed is False
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(con, V6, now=NOW)


def test_a_v6_proof_does_not_authorise_the_v4_address(con):
    """The reverse of the case the suite already had. Holding one is holding
    one."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V6, document([V6]), now=NOW)
    assert authz.may_probe(con, V6, now=NOW).allowed is True
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(con, V4, now=NOW)


def test_a_published_proof_of_one_family_does_not_carry_to_the_other(con):
    """Same rule on the DNS path, where the two families share a host and a
    token could look like it belonged to the machine rather than the
    address."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       resolver=resolver_returning(challenge.token))
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    assert authz.may_probe(con, V6, now=NOW).allowed is False
    # And the token minted for the v4 address proves nothing at the v6 one.
    other = authz.start_proof(con, V6, authz.METHOD_DNS_TXT, now=NOW)
    replay = authz.verify_proof(con, other.id, now=NOW,
                                resolver=resolver_returning(challenge.token))
    assert replay.recorded is False
    assert authz.may_probe(con, V6, now=NOW).allowed is False


def test_revoking_one_family_does_not_touch_a_challenge_for_the_other(con):
    v4_challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    v6_challenge = authz.start_proof(con, V6, authz.METHOD_DNS_TXT, now=NOW)
    authz.revoke(con, V4, now=NOW)
    assert authz.verify_proof(
        con, v4_challenge.id, now=NOW,
        resolver=resolver_returning(v4_challenge.token)).recorded is False
    assert authz.verify_proof(
        con, v6_challenge.id, now=NOW,
        resolver=resolver_returning(v6_challenge.token)).recorded is True


# ------------------------------------------------------ 4. NAT and 5. asserting

def test_a_host_behind_nat_that_says_nothing_authorises_nothing(con):
    """The honest NAT host. It binds a private address, the report arrives from
    the gateway, and neither address becomes probeable."""
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, V4,
                                      document(["192.168.1.20", "0.0.0.0"]),
                                      now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    assert authz.may_probe(con, "192.168.1.20", now=NOW).allowed is False
    assert rows(con) == []


def test_a_second_host_behind_one_gateway_gets_nothing_from_the_first(con):
    """Two machines, one egress address. The first legitimately holds it and
    proves it. The second must not inherit anything, and revoking the first
    must not leave the second holding a proof."""
    holder = add_host(con, "holder")
    neighbour = add_host(con, "neighbour")
    assert authz.record_agent_proof(con, holder, V4, document([V4]),
                                    now=NOW).recorded is True
    result = authz.record_agent_proof(con, neighbour, V4,
                                      document(["10.0.0.9"]), now=NOW)
    assert result.recorded is False
    assert len(rows(con)) == 1
    assert rows(con)[0]["host_id"] == holder
    store.revoke_host(con, "holder")
    assert authz.may_probe(con, V4, now=NOW).allowed is False


@pytest.mark.parametrize("gateway", ["100.64.0.1", "100.127.255.254"])
def test_a_carrier_nat_gateway_is_refused_even_when_the_host_claims_it(con, gateway):
    """Carrier NAT is shared with strangers by definition, so this one cannot
    be reached even by a host that claims to bind it."""
    host_id = add_host(con)
    result = authz.record_agent_proof(con, host_id, gateway, document([gateway]),
                                      now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, gateway, now=NOW).allowed is False


def test_a_document_cannot_authorise_a_third_partys_address(con):
    """A host asserting a bind address it does not hold. The document is the
    host's own writing, so the extra address must not reach the gate, and must
    not reach the evidence either."""
    host_id = add_host(con)
    victim = "185.199.110.153"
    result = authz.record_agent_proof(con, host_id, V4,
                                      document([V4, victim, "1.1.1.1"]), now=NOW)
    assert result.recorded is True
    assert authz.may_probe(con, victim, now=NOW).allowed is False
    assert authz.may_probe(con, "1.1.1.1", now=NOW).allowed is False
    evidence = json.loads(rows(con)[0]["evidence"])
    assert [entry["bind_address"] for entry in evidence["matching_sockets"]] == [V4]


def test_a_document_cannot_smuggle_a_target_in_a_field_of_its_own(con):
    """Only `sockets.listening[].bind_address` is read, so a document adding
    fields that look like the ones this module writes changes nothing."""
    host_id = add_host(con)
    payload = json.dumps({
        "schema_version": 1, "hostname": "box", "collected_at_unix": 0,
        "observed_source": "1.1.1.1",
        "authorizations": [{"target": "1.1.1.1", "method": "agent"}],
        "sockets": {"status": "ok", "listening": [
            {"protocol": "tcp", "family": "v4", "bind_address": "10.0.0.5",
             "port": 443, "observed_source": V4},
        ]},
    })
    assert authz.record_agent_proof(con, host_id, V4, payload, now=NOW).recorded is False
    assert authz.may_probe(con, "1.1.1.1", now=NOW).allowed is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_auto_authorisation_reaches_only_the_address_the_report_came_from(con):
    """The limit of agent-derived proof, pinned so it is visible rather than
    assumed.

    A host that claims to bind the address its own report arrived from is
    authorised for that one address, and behind NAT that address is the
    gateway. Both halves agreeing does not make the two halves independent: the
    host writes one of them and can copy the other into it. What it cannot do
    is reach any address other than the one we observed, and that bound is what
    this asserts. Tightening it is a change to PRODUCT.md section 5, not to a
    test.
    """
    host_id = add_host(con)
    assert authz.record_agent_proof(con, host_id, V4, document([V4]),
                                    now=NOW).recorded is True
    for other in [OTHER_V4, V6, "1.1.1.1", "185.199.110.153"]:
        assert authz.may_probe(con, other, now=NOW).allowed is False


# --------------------------------------------------------- 6. the forward path

def test_a_forward_dns_name_cannot_be_a_target(con):
    """PRODUCT.md section 5: the TXT record goes at the reverse name because a
    forward name proves control of a name and not of an address. So a name
    cannot enter this module at all."""
    for name in ["whichports.com", "proof.whichports.com", "localhost",
                 "153.108.199.185.in-addr.arpa", "example.com."]:
        with pytest.raises(authz.TargetError):
            authz.normalise_target(name)
        with pytest.raises(authz.TargetError):
            authz.start_proof(con, name, authz.METHOD_DNS_TXT, now=NOW)
        with pytest.raises(authz.TargetError):
            authz.revoke(con, name, now=NOW)
        assert authz.may_probe(con, name, now=NOW).allowed is False


@pytest.mark.parametrize("address", [V4, V6, OTHER_V4, "1.1.1.1", "2001:20::1111"])
def test_a_dns_challenge_can_only_ever_name_a_reverse_zone(con, address):
    """The name is derived from the address, so nobody chooses it."""
    challenge = authz.start_proof(con, address, authz.METHOD_DNS_TXT, now=NOW)
    assert challenge.publish_at == ipaddress.ip_address(address).reverse_pointer
    assert challenge.publish_at.endswith((".in-addr.arpa", ".ip6.arpa"))


@pytest.mark.parametrize("address", [V4, V6, OTHER_V4, "1.1.1.1", "2001:20::1111"])
def test_an_http_challenge_can_only_ever_name_the_literal_address(con, address):
    challenge = authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN, now=NOW)
    parts = urllib.parse.urlsplit(challenge.publish_at)
    assert parts.scheme == "http"
    assert parts.hostname == challenge.target
    assert parts.port == authz.HTTP_PORT
    assert parts.path == authz.HTTP_WELL_KNOWN_PATH
    assert parts.query == "" and parts.fragment == ""


def test_a_challenge_naming_a_forward_name_is_never_even_asked(con):
    """Defence in depth on the same rule. `publish_at` is stored, and a stored
    string that does not match the address it claims to prove must be a refusal
    rather than a lookup. Otherwise the one name this module reads evidence
    from is whatever is in a column."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    con.execute("UPDATE authz_challenges SET publish_at = ? WHERE id = ?",
                ("proof.whichports.com", challenge.id))
    con.commit()
    resolve = resolver_returning(challenge.token)
    result = authz.verify_proof(con, challenge.id, now=NOW, resolver=resolve)
    assert result.recorded is False
    assert resolve.asked is None, "a forward name was resolved"
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_nothing_in_the_module_turns_a_name_into_an_address():
    """Structural, and the canary is the last two lines. If this module ever
    resolves a name, the forward path is back."""
    source = pathlib.Path(authz.__file__).read_text(encoding="utf-8")
    for forbidden in ["getaddrinfo", "gethostbyname", "create_connection",
                      "import socket"]:
        assert forbidden not in source, f"{forbidden} appeared in app/authz.py"
    assert "def may_probe" in source
    assert "reverse_pointer" in source


# ----------------------------------------------------- 7. revocation is now

def test_revocation_needs_no_sweep(con):
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.revoke(con, V4, now=NOW) == 1
    assert authz.list_authorizations(con)[0]["expired_at"] is None
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(con, V4, now=NOW)


def test_a_revoke_landing_while_the_evidence_is_read_is_not_lost(con, db_file):
    """The HTTP read has a ten second timeout and the DNS read has five, so a
    revocation can land inside the window between the challenge being checked
    and the authorisation being written. The fetcher below revokes from a
    second connection, which is what a second process does.

    Without this the address ends up authorised for thirty days *after* the
    revocation, and the operator is told nothing: revoke reports zero
    authorisations closed, because at that moment there were none.
    """
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    revoked = []

    def fetch(url):
        other = db.connect(db_file)
        try:
            revoked.append(authz.revoke(other, V4, now=NOW))
        finally:
            other.close()
        return challenge.token

    result = authz.verify_proof(con, challenge.id, now=NOW, fetcher=fetch)
    assert revoked == [0], "the revoke has to happen during the read"
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_revoke_landing_during_a_dns_read_is_not_lost(con, db_file):
    """The same window on the other proof method."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)

    def resolve(name):
        other = db.connect(db_file)
        try:
            authz.revoke(other, V4, now=NOW)
        finally:
            other.close()
        return [challenge.token]

    assert authz.verify_proof(con, challenge.id, now=NOW,
                              resolver=resolve).recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_revoke_during_a_re_proof_is_not_lost(con, db_file):
    """A verified challenge is the standing re-proof record, so the same window
    reopens every thirty days for as long as the address is authorised."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       resolver=resolver_returning(challenge.token))
    later = NOW + timedelta(seconds=authz.PUBLISHED_TTL_SECONDS + 60)

    def resolve(name):
        other = db.connect(db_file)
        try:
            authz.revoke(other, V4, now=later)
        finally:
            other.close()
        return [challenge.token]

    assert authz.verify_proof(con, challenge.id, now=later,
                              resolver=resolve).recorded is False
    assert authz.may_probe(con, V4, now=later).allowed is False


# ------------------------------------------------------- 8. the HTTP path

def test_an_oversized_file_holding_the_right_token_still_proves_nothing(monkeypatch,
                                                                        con):
    """A server padding the token past the cap. The cap is not a convenience,
    it is what stops us reading a response somebody chose the size of."""
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    body = challenge.token.encode() + b"\n" + b"x" * authz.MAX_TOKEN_BYTES
    install_opener(monkeypatch, FakeOpener(body=body))
    result = authz.verify_proof(con, challenge.id, now=NOW)
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_200_holding_the_wrong_content_proves_nothing_through_the_real_fetch(
        monkeypatch, con):
    """The whole path, opener included, rather than an injected fetcher."""
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    for body in [b"", b"\n", b"whpa_" + b"0" * 64, b"OK", b"<html>404</html>",
                 challenge.token.encode()[:-1], challenge.token.upper().encode()]:
        install_opener(monkeypatch, FakeOpener(body=body))
        assert authz.verify_proof(con, challenge.id, now=NOW).recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    # And the same opener with the right body does record, so the loop above
    # is not passing because the fetch was broken.
    install_opener(monkeypatch, FakeOpener(body=challenge.token.encode()))
    assert authz.verify_proof(con, challenge.id, now=NOW).recorded is True


def test_the_right_token_at_the_wrong_url_proves_nothing(con):
    """"Serving content from an address is control of that address" only holds
    if the URL is the one this module built. A stored `publish_at` pointing
    anywhere else must be refused before anything is fetched, or this becomes a
    request-forgery path out of the control plane."""
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    asked = []

    def fetch(url):
        asked.append(url)
        return challenge.token

    for wrong in [f"http://{OTHER_V4}:80{authz.HTTP_WELL_KNOWN_PATH}",
                  f"http://{V4}:80/tokens/anything",
                  f"http://{V4}:8080{authz.HTTP_WELL_KNOWN_PATH}",
                  f"https://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}",
                  f"http://127.0.0.1:80{authz.HTTP_WELL_KNOWN_PATH}",
                  f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}?to=elsewhere"]:
        con.execute("UPDATE authz_challenges SET publish_at = ? WHERE id = ?",
                    (wrong, challenge.id))
        con.commit()
        result = authz.verify_proof(con, challenge.id, now=NOW, fetcher=fetch)
        assert result.recorded is False, wrong
        assert asked == [], f"{wrong} was fetched"
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_challenge_whose_family_disagrees_with_its_target_proves_nothing(con):
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    con.execute("UPDATE authz_challenges SET family = 'v6' WHERE id = ?",
                (challenge.id,))
    con.commit()
    result = authz.verify_proof(con, challenge.id, now=NOW,
                                resolver=resolver_returning(challenge.token))
    assert result.recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_challenge_row_naming_the_agent_method_verifies_nothing(con):
    """Agent proof is observed, never published, so a challenge row claiming
    it has no evidence to read."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    for method in [authz.METHOD_AGENT, "", "https_token", "dns-txt"]:
        con.execute("UPDATE authz_challenges SET method = ? WHERE id = ?",
                    (method, challenge.id))
        con.commit()
        assert authz.verify_proof(
            con, challenge.id, now=NOW,
            resolver=resolver_returning(challenge.token)).recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


class TimingOutResponse(FakeResponse):
    """A server that answers and then stops sending."""

    def read(self, size):
        raise TimeoutError("timed out")


@pytest.mark.parametrize("error", [
    TimeoutError("timed out"),
    urllib.error.URLError(TimeoutError("timed out")),
    OSError("connection reset"),
])
def test_a_slow_server_is_a_refusal_rather_than_a_hang_or_a_crash(monkeypatch,
                                                                  con, error):
    opener = FakeOpener(error=error)
    install_opener(monkeypatch, opener)
    with pytest.raises(authz.ProofError):
        authz.fetch_token_file(f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}")
    assert opener.timeout == authz.HTTP_TIMEOUT_SECONDS

    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    assert authz.verify_proof(con, challenge.id, now=NOW).recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_server_that_stops_sending_mid_body_proves_nothing(monkeypatch, con):
    class Opener(FakeOpener):
        def open(self, request, timeout=None):
            self.timeout = timeout
            return TimingOutResponse(200, b"")

    install_opener(monkeypatch, Opener())
    with pytest.raises(authz.ProofError):
        authz.fetch_token_file(f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}")
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    assert authz.verify_proof(con, challenge.id, now=NOW).recorded is False


def test_the_fetch_builds_its_opener_with_the_no_redirect_handler(monkeypatch):
    """Found by mutation, and it is the 4.46 shape exactly. Every redirect test
    in this file either injected an opener or built one of its own, so deleting
    `_NoRedirects()` from `fetch_token_file` left the whole suite green while
    the fetch would follow a redirect anywhere. This asserts on the opener the
    module builds."""
    opener = FakeOpener(body=b"whpa_token")
    install_opener(monkeypatch, opener)
    authz.fetch_token_file(f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}")
    assert opener.handlers, "fetch_token_file built an opener with no handlers"
    assert any(isinstance(handler, authz._NoRedirects)
               for handler in opener.handlers)


def test_the_fetch_builds_its_opener_with_proxies_turned_off(monkeypatch):
    """The same shape as the redirect test above, and the same hole. This proof
    is worth something only because the bytes came from the address being
    proved, and a proxy in the way means they came from the proxy.

    `urllib.request.build_opener` installs a bare `ProxyHandler()` unless it is
    handed one, and a bare one reads `http_proxy` from the environment. So the
    hole opens without anybody touching this code: one `http_proxy` in the
    sweep unit's environment.
    """
    opener = FakeOpener(body=b"whpa_token")
    install_opener(monkeypatch, opener)
    authz.fetch_token_file(f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}")
    proxy_handlers = [h for h in opener.handlers
                      if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy_handlers, "fetch_token_file did not hand build_opener a ProxyHandler"
    assert all(h.proxies == {} for h in proxy_handlers), (
        "the ProxyHandler carries proxies, so a proof fetch can be rerouted")


def test_an_http_proxy_in_the_environment_does_not_reroute_a_proof_fetch(monkeypatch):
    """The behaviour the structural test above stands in for, measured on the
    real opener rather than a fake one.

    No socket is opened. `http.client.HTTPConnection` is replaced, so what is
    asserted is the host urllib decided to connect to. With a bare
    `ProxyHandler` that host is the proxy, and this test was red against the
    code as it stood.
    """
    monkeypatch.setenv("http_proxy", "http://198.51.100.9:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://198.51.100.9:3128")
    connected = []

    class RecordingConnection:
        # urllib reads this off the class before it builds one.
        debuglevel = 0

        def __init__(self, host, timeout=None, **kwargs):
            connected.append(host)
            self.host = host
            self.sock = None

        def set_debuglevel(self, level):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            raise OSError("nothing is served here, the host is the assertion")

        def close(self):
            pass

    monkeypatch.setattr(urllib.request.http.client, "HTTPConnection",
                        RecordingConnection)
    with pytest.raises(authz.ProofError):
        authz.fetch_token_file(f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}")
    assert connected == [f"{V4}:80"], (
        f"the proof fetch connected to {connected}, not to the address being proved")


# ------------------------------------------------------- the account is the question

def test_an_address_proved_by_another_account_is_not_probeable(con):
    """v1 has one account, so this changes no answer today. It is here because
    the day a second account exists is the wrong day to discover that the gate
    answered "somebody proved this address" when the question was "did this
    account prove it"."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    assert authz.may_probe(con, V4, now=NOW, account="someone-else").allowed is False


def test_the_refusal_for_another_account_is_the_refusal_for_never_proved(con):
    """Same words, so a caller cannot tell an address it may not probe from an
    address nobody has proved. That rule already covers expired, revoked and
    belonging to a revoked host, and this joins it."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    theirs = authz.may_probe(con, V4, now=NOW, account="someone-else")
    unknown = authz.may_probe(con, "185.199.109.153", now=NOW)  # nobody proved this one
    assert theirs.reason.split(":")[0] == unknown.reason.split(":")[0]
    assert theirs.target is None


def test_the_raising_form_refuses_another_accounts_address(con):
    """The gate a prober actually calls, not only the reporting one."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(con, V4, now=NOW, account="someone-else")
    assert authz.require_probe_authorization(con, V4, now=NOW) == V4


def test_the_default_account_is_what_the_recorders_write(con):
    """The filter is only safe because both sides use the same default. If a
    recorder ever wrote a different string the gate would refuse everything,
    so this pins the two together rather than trusting they match."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    stored = con.execute("SELECT account FROM authorizations").fetchall()
    assert stored and all(row["account"] == authz.DEFAULT_ACCOUNT for row in stored)
    assert authz.may_probe(con, V4, now=NOW, account=authz.DEFAULT_ACCOUNT).allowed is True


def test_a_cancelled_challenge_is_refused_before_anything_is_read(con):
    """A revoked address must not even cause a lookup. The refusal after the
    read is the one that closes the race, and this is the one that stops us
    reading evidence for something already revoked."""
    challenge = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    authz.revoke(con, V4, now=NOW)
    resolve = resolver_returning(challenge.token)
    assert authz.verify_proof(con, challenge.id, now=NOW,
                              resolver=resolve).recorded is False
    assert resolve.asked is None, "evidence was read for a cancelled challenge"


def test_a_redirect_to_the_right_address_is_still_a_refusal(monkeypatch, con):
    """Even a redirect pointing back at the address being proved is refused.
    The rule is about where the bytes came from, and following one hop would
    mean following any."""
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    error = urllib.error.HTTPError(challenge.publish_at, 301, "Moved",
                                   {"Location": challenge.publish_at}, None)
    install_opener(monkeypatch, FakeOpener(error=error))
    assert authz.verify_proof(con, challenge.id, now=NOW).recorded is False
    assert authz.may_probe(con, V4, now=NOW).allowed is False


# ------------------------------------------------ 9. addresses at the door

# Measured against this Python's `ipaddress` on 2026-08-15 rather than assumed,
# because the classification of several of these has moved between versions.
NOT_A_TARGET = [
    "0.0.0.0", "255.255.255.255", "127.0.0.1", "127.255.255.254",
    "10.0.0.1", "172.31.255.254", "192.168.0.1",
    "169.254.169.254",                  # link local, and the cloud metadata one
    "224.0.0.1", "239.255.255.255", "232.1.2.3",
    "100.64.0.1", "100.127.255.254",    # carrier NAT, shared with strangers
    "192.0.0.1",                        # IETF protocol assignments
    "198.18.0.1", "198.19.255.254",     # benchmarking
    "192.0.2.1", "198.51.100.1", "203.0.113.1",
    "240.0.0.1", "255.0.0.1",
    "::", "::1", "fe80::1", "fe80::1%eth0", "fc00::1", "fd00::1",
    "ff02::1", "ff05::2", "fec0::1",
    "2001:db8::1", "3fff::1",           # both documentation ranges
    "2001::1",                          # Teredo
    "2002:c000:204::1",                 # 6to4
    "64:ff9b::c000:204",                # NAT64, a v4 address in disguise
    "100::1",                           # discard only
    "::ffff:185.199.108.153", "::ffff:8.8.8.8",
]


@pytest.mark.parametrize("address", NOT_A_TARGET)
def test_an_address_that_cannot_be_a_target_is_refused_by_every_entry_point(
        con, address):
    """Refusing at the door is what stops the HTTP proof being aimed at this
    control plane's own network, so every way in has to refuse it and not only
    `normalise_target`."""
    with pytest.raises(authz.TargetError):
        authz.normalise_target(address)
    with pytest.raises(authz.TargetError):
        authz.start_proof(con, address, authz.METHOD_DNS_TXT, now=NOW)
    with pytest.raises(authz.TargetError):
        authz.start_proof(con, address, authz.METHOD_HTTP_TOKEN, now=NOW)
    with pytest.raises(authz.TargetError):
        authz.revoke(con, address, now=NOW)
    assert authz.may_probe(con, address, now=NOW).allowed is False
    host_id = add_host(con)
    assert authz.record_agent_proof(con, host_id, address, document([address]),
                                    now=NOW).recorded is False
    assert rows(con) == []


SCOPED_V6 = V6 + "%eth0"


def test_a_scope_id_is_not_a_second_spelling_of_an_address(con):
    """A zone index is a local interface name. `ipaddress` keeps it in the
    canonical text, so `2606:50c0:8000::153%eth0` and `2606:50c0:8000::153`
    become two rows for one address, which is the split the suite already says
    must not happen: revoking one leaves the other live. The reverse-pointer
    form of a scoped address also raises rather than returning a name.
    """
    with pytest.raises(authz.TargetError):
        authz.normalise_target(SCOPED_V6)
    for method in [authz.METHOD_DNS_TXT, authz.METHOD_HTTP_TOKEN]:
        with pytest.raises(authz.TargetError):
            authz.start_proof(con, SCOPED_V6, method, now=NOW)
    with pytest.raises(authz.TargetError):
        authz.revoke(con, SCOPED_V6, now=NOW)
    assert authz.may_probe(con, SCOPED_V6, now=NOW).allowed is False
    host_id = add_host(con)
    assert authz.record_agent_proof(con, host_id, SCOPED_V6,
                                    document([SCOPED_V6]), now=NOW).recorded is False


def test_a_scope_id_cannot_survive_a_revocation(con):
    """The consequence, stated as the property that matters: one revoke closes
    the address in every spelling, because there is only one spelling."""
    challenge = authz.start_proof(con, V6, authz.METHOD_HTTP_TOKEN, now=NOW)
    authz.verify_proof(con, challenge.id, now=NOW,
                       fetcher=lambda url: challenge.token)
    assert authz.revoke(con, V6, now=NOW) == 1
    for spelling in [V6, SCOPED_V6, "2606:50c0:8000:0000:0000:0000:0000:0153"]:
        assert authz.may_probe(con, spelling, now=NOW).allowed is False


# --------------------------------------------------------- 10. concurrency

def run_together(work, count):
    """Run `work(index)` in `count` threads and return what each returned.

    Anything raised is returned rather than swallowed, so a test can assert no
    thread crashed instead of the crash disappearing into a thread.
    """
    results = [None] * count

    def runner(index):
        # Everything is caught on purpose. An exception inside a thread is
        # printed and forgotten by default, which would turn a crash into a
        # pass.
        try:
            results[index] = work(index)
        except BaseException as exc:
            results[index] = exc

    threads = [threading.Thread(target=runner, args=(index,))
               for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not any(thread.is_alive() for thread in threads), "a thread hung"
    return results


def test_verifying_one_challenge_from_several_threads_stays_consistent(con, db_file):
    """Two operators clicking verify, or a retry landing on top of the first
    attempt. The address ends authorised once, nothing raises, and one revoke
    still closes everything."""
    challenge = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)

    def verify(_index):
        worker = db.connect(db_file)
        try:
            return authz.verify_proof(worker, challenge.id, now=NOW,
                                      fetcher=lambda url: challenge.token)
        finally:
            worker.close()

    results = run_together(verify, 8)
    assert not [r for r in results if isinstance(r, BaseException)], results
    assert any(r.recorded for r in results)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    authz.revoke(con, V4, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_verifying_several_challenges_for_one_target_at_once_stays_consistent(
        con, db_file):
    challenges = [authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
                  for _ in range(6)]

    def verify(index):
        challenge = challenges[index]
        worker = db.connect(db_file)
        try:
            return authz.verify_proof(worker, challenge.id, now=NOW,
                                      fetcher=lambda url: challenge.token)
        finally:
            worker.close()

    results = run_together(verify, len(challenges))
    assert not [r for r in results if isinstance(r, BaseException)], results
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    # However many rows the race produced, one revoke closes every one of them.
    authz.revoke(con, V4, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False
    assert all(row["revoked_at"] for row in rows(con))


def test_revoking_while_verifications_run_ends_with_the_address_refused(con, db_file):
    """The threaded form of the revoke window. The ordering is the scheduler's,
    so what is asserted is the property that has to hold in every ordering: no
    thread crashes, and once the last revoke has run the address is refused."""
    challenges = [authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
                  for _ in range(6)]

    def work(index):
        worker = db.connect(db_file)
        try:
            if index % 2:
                return authz.revoke(worker, V4, now=NOW)
            challenge = challenges[index]
            return authz.verify_proof(worker, challenge.id, now=NOW,
                                      fetcher=lambda url: challenge.token)
        finally:
            worker.close()

    results = run_together(work, len(challenges))
    assert not [r for r in results if isinstance(r, BaseException)], results
    authz.revoke(con, V4, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_recording_agent_proof_from_several_threads_stays_consistent(con, db_file):
    """A report arriving at two ingest workers at once."""
    host_id = add_host(con)
    payload = document([V4])

    def record(_index):
        worker = db.connect(db_file)
        try:
            return authz.record_agent_proof(worker, host_id, V4, payload, now=NOW)
        finally:
            worker.close()

    results = run_together(record, 8)
    assert not [r for r in results if isinstance(r, BaseException)], results
    assert any(r.recorded for r in results)
    assert authz.may_probe(con, V4, now=NOW).allowed is True
    authz.revoke(con, V4, now=NOW)
    assert authz.may_probe(con, V4, now=NOW).allowed is False


# ============================ boundaries a mutation pass left open
#
# A second adversarial pass mutated the guards in `app/authz.py` one at a time
# and re-ran this suite. Four mutations stayed green, which means four guards
# had no test that turned red when they were wrong. Each one below fails against
# its mutation and passes against the code as written, the same standard the
# rest of the adversarial section holds to.


def test_the_sweep_writes_a_row_off_at_the_exact_instant_it_expires(con):
    """The gate calls equal-to-expiry expired, because `expires > now` is
    strict. The sweep has to agree at that same instant. If the sweep used `<`
    where the gate uses `>`, a row at exactly its expiry would be refused by the
    gate but left with `expired_at` still null, and then a clock stepping back
    one second would revive it, which is the backwards-clock hole the
    `expired_at` check exists to close. So the sweep boundary is part of that
    fix, not a cosmetic detail, and it needs its own boundary test.
    """
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    at_expiry = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS)
    assert authz.sweep(con, now=at_expiry)["expired"] == [V4]
    assert authz.list_authorizations(con)[0]["expired_at"] is not None
    # Written off at the boundary, so a clock stepping back cannot revive it.
    assert authz.may_probe(con, V4, now=NOW).allowed is False


def test_a_body_of_exactly_the_cap_is_read_rather_than_rejected(monkeypatch):
    """The cap refuses a body *larger* than a token, so a body of exactly
    `MAX_TOKEN_BYTES` is still read. This pins the boundary as `>` and not `>=`,
    so the cap cannot quietly start refusing a body one byte inside the limit,
    which would make a proof at the edge unreadable rather than more strict."""
    body = b"x" * authz.MAX_TOKEN_BYTES
    install_opener(monkeypatch, FakeOpener(body=body))
    read = authz.fetch_token_file(f"http://{V4}:80{authz.HTTP_WELL_KNOWN_PATH}")
    assert read == body.decode()


def test_the_token_is_matched_in_constant_time(con):
    """The token material is matched with `secrets.compare_digest`, never `==`.
    The comparison is over SHA-256 hashes, so a timing leak would leak nothing
    an attacker could use, but the constant-time habit is pinned here so it is
    not quietly dropped. Structural, like the redirect-handler and forward-name
    canaries above, because the difference `==` makes is a timing one no
    functional assertion can see."""
    source = pathlib.Path(authz.__file__).read_text(encoding="utf-8")
    assert "secrets.compare_digest" in source, "token matching is no longer constant time"
    assert "def _token_matches" in source
    assert authz._token_matches("whpa_right", authz.token_hash("whpa_right")) is True
    assert authz._token_matches("whpa_wrong", authz.token_hash("whpa_right")) is False


def test_two_published_proofs_of_one_address_are_two_rows(con):
    """A DNS proof and an HTTP proof for one address are two independent
    records, not one folded into the other. `_record` refreshes a live row only
    when both the method and the host match, so a second method for the same
    address stands as its own row. Folding them together would overwrite one
    proof's evidence with the other's while leaving the first method's name on
    it, and would make one revoke count read as one when it closed two."""
    dns = authz.start_proof(con, V4, authz.METHOD_DNS_TXT, now=NOW)
    assert authz.verify_proof(con, dns.id, now=NOW,
                              resolver=resolver_returning(dns.token)).recorded
    http = authz.start_proof(con, V4, authz.METHOD_HTTP_TOKEN, now=NOW)
    assert authz.verify_proof(con, http.id, now=NOW,
                              fetcher=lambda url: http.token).recorded
    methods = sorted(row["method"] for row in rows(con))
    assert methods == [authz.METHOD_DNS_TXT, authz.METHOD_HTTP_TOKEN]
    # And one revoke closes both, so the count is honest about what it did.
    assert authz.revoke(con, V4, now=NOW) == 2
    assert authz.may_probe(con, V4, now=NOW).allowed is False


# ============================================ carrying the gate to the prober
#
# These attack the snapshot rather than demonstrate it. The property that has
# to hold is one sentence: a snapshot can only ever say no more often than the
# database it was built from, never yes more often.


_authorised = itertools.count(1)


def authorise(con, address, now=NOW):
    """An address the registry genuinely allows, by the ordinary agent path.

    The host name is a counter rather than the address, because an address is
    not a legal host name and building one out of it fails inside store rather
    than in anything under test.
    """
    host_id = add_host(con, name=f"probe-box-{next(_authorised)}")
    result = authz.record_agent_proof(
        con, host_id, address, document(WILDCARD_ONLY, interfaces=[address]),
        now=now)
    assert result.recorded is True, result.reason
    return host_id


def test_a_snapshot_allows_exactly_what_the_database_allows(con):
    authorise(con, V4)
    snap = authz.build_snapshot(con, [V4, V6], now=NOW)
    assert snap.require(V4, now=NOW) == V4
    with pytest.raises(authz.NotAuthorized):
        snap.require(V6, now=NOW)
    assert authz.may_probe(con, V6, now=NOW).allowed is False


def test_a_snapshot_cannot_carry_an_address_the_database_refused(con):
    """The property the whole design rests on. Asking for the world does not
    widen what comes back."""
    authorise(con, V4)
    snap = authz.build_snapshot(con, [V4, V6, "8.8.8.8", "1.1.1.1"], now=NOW)
    for address in (V6, "8.8.8.8", "1.1.1.1"):
        with pytest.raises(authz.NotAuthorized):
            snap.require(address, now=NOW)


def test_an_address_never_asked_about_is_not_in_the_snapshot(con):
    """Even an authorised address is absent if the control plane did not put it
    in, because a snapshot is a list rather than a rule."""
    authorise(con, V4)
    snap = authz.build_snapshot(con, [], now=NOW)
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=NOW)


def test_a_stale_snapshot_authorises_nothing_at_all(con):
    """The bound on how long a revoked target stays probeable."""
    authorise(con, V4)
    snap = authz.build_snapshot(con, [V4], now=NOW)
    assert snap.require(V4, now=NOW) == V4
    later = NOW + timedelta(seconds=authz.SNAPSHOT_TTL_SECONDS)
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=later)


def test_the_snapshot_expiry_boundary_is_exclusive(con):
    """One second before is usable and the instant itself is not, so the window
    is closed rather than ajar."""
    authorise(con, V4)
    snap = authz.build_snapshot(con, [V4], now=NOW)
    edge = NOW + timedelta(seconds=authz.SNAPSHOT_TTL_SECONDS)
    assert snap.require(V4, now=edge - timedelta(seconds=1)) == V4
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=edge)


def test_a_per_target_expiry_is_carried_and_enforced(con):
    """The snapshot being fresh does not make an authorisation inside it
    fresh. An agent proof lasts a week, so a long-lived snapshot must still
    refuse it afterwards."""
    authorise(con, V4)
    snap = authz.build_snapshot(
        con, [V4], valid_for_seconds=30 * 24 * 60 * 60, now=NOW)
    after = NOW + timedelta(seconds=authz.AGENT_TTL_SECONDS + 1)
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=after)


def test_the_snapshot_canonicalises_the_address_the_same_way(con):
    """`2001:db8::1` and its expanded spelling must not be two answers, or an
    address could be revoked in one form and probed in the other."""
    authorise(con, V6)
    snap = authz.build_snapshot(con, [V6], now=NOW)
    expanded = "2606:50c0:8000:0000:0000:0000:0000:0153"
    assert snap.require(expanded, now=NOW) == V6


def test_the_snapshot_returns_the_canonical_target_not_the_text_given(con):
    """The address connected to is the one the gate approved."""
    authorise(con, V6)
    snap = authz.build_snapshot(con, [V6], now=NOW)
    assert snap.require(V6.upper(), now=NOW) == V6


@pytest.mark.parametrize("address", [
    "10.0.0.1", "127.0.0.1", "192.168.1.1", "100.64.0.1",
    "fe80::1", "not-an-address", "", "185.199.108.153%eth0",
])
def test_a_snapshot_refuses_what_normalise_target_refuses(con, address):
    """The same door every candidate goes through. A snapshot is not a way
    round the address rules."""
    authorise(con, V4)
    snap = authz.build_snapshot(con, [V4], now=NOW)
    with pytest.raises(authz.NotAuthorized):
        snap.require(address, now=NOW)


def test_a_revoked_target_is_absent_from_the_next_snapshot(con):
    """What makes the window one batch long rather than unbounded."""
    authorise(con, V4)
    assert authz.build_snapshot(con, [V4], now=NOW).require(V4, now=NOW) == V4
    authz.revoke(con, V4, now=NOW)
    with pytest.raises(authz.NotAuthorized):
        authz.build_snapshot(con, [V4], now=NOW).require(V4, now=NOW)


def test_a_malformed_expiry_is_a_refusal_and_never_an_exception(con):
    """A prober must not crash on a bad snapshot, and must not treat it as
    permission either."""
    snap = authz.SnapshotAuthority({V4: "not a timestamp"},
                                   NOW + timedelta(minutes=5))
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=NOW)


def test_the_database_authority_is_the_gate_unchanged(con):
    """The control plane path must behave exactly as it always has."""
    authorise(con, V4)
    authority = authz.DatabaseAuthority(con)
    assert authority.require(V4, now=NOW) == authz.require_probe_authorization(
        con, V4, now=NOW)
    with pytest.raises(authz.NotAuthorized):
        authority.require(V6, now=NOW)


def test_the_database_authority_sees_a_revoke_immediately(con):
    """The difference between the two authorities, pinned so nobody has to
    infer it. This is what the snapshot trades away."""
    authorise(con, V4)
    authority = authz.DatabaseAuthority(con)
    assert authority.require(V4, now=NOW) == V4
    authz.revoke(con, V4, now=NOW)
    with pytest.raises(authz.NotAuthorized):
        authority.require(V4, now=NOW)


def test_a_snapshot_entry_with_no_expiry_is_refused_not_treated_as_now(con):
    """Found by mutation. `_as_utc(None)` answers with the current time, so an
    absent expiry would read as "expires now", and a caller passing an earlier
    clock would be told yes. An absent expiry has to be a refusal in its own
    right, before any clock arithmetic happens."""
    snap = authz.SnapshotAuthority({V4: None}, NOW + timedelta(minutes=5))
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=NOW - timedelta(days=1))
    with pytest.raises(authz.NotAuthorized):
        snap.require(V4, now=NOW)


# DELIBERATELY NOT TESTED, and saying so is the point.
#
# `build_snapshot` drops a target whose expiry `_parse` cannot read. There was a
# test here that monkeypatched `_parse` to return None and asserted a refusal.
# It passed, and it passed for the wrong reason: breaking `_parse` makes
# `may_probe` refuse first, so the snapshot came back empty and the branch the
# test named was never reached. A green test that proves nothing is worse than
# an absent one, so it is gone rather than left to reassure somebody.
#
# The branch is unreachable by construction today, because `may_probe` and
# `build_snapshot` parse the same column of the same row in the same instant,
# so an expiry that survives the first parse survives the second. It stays as a
# guard for the day that stops being true, and mutation testing correctly
# reports it as surviving. See the PR for the reasoning.


# ============================================================ workspaces
#
# SI-6 with a second workspace in the picture. The account column and its
# filter in `_active_authorization` already existed and already worked; what
# these prove is that the account is now the *workspace*, so proving an address
# in one workspace authorises it there and nowhere else.
#
# The direction that matters is the refusing one. Every test below is written
# from the position of workspace 1 trying to probe an address only workspace 2
# ever proved.


def test_workspace_one_keeps_the_account_string_already_on_the_box():
    """Every authorisation on the production box carries `account = 'default'`.
    If workspace 1 mapped to anything else, this deploy would make every one of
    those rows stop matching and the prober would quietly refuse the owner's three
    hosts."""
    assert authz.account_for_workspace(db.DEFAULT_WORKSPACE_ID) == authz.DEFAULT_ACCOUNT


def test_every_other_workspace_gets_its_own_account():
    assert authz.account_for_workspace(2) == "w2"
    assert authz.account_for_workspace(2) != authz.account_for_workspace(3)


def test_a_proof_is_recorded_under_the_reporting_hosts_workspace(con):
    second = db.create_workspace(con, "second")
    host_id, _ = store.add_host(con, "theirs", workspace_id=second)
    result = authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    assert result.recorded is True
    stored = con.execute("SELECT account FROM authorizations").fetchall()
    assert [row["account"] for row in stored] == [authz.account_for_workspace(second)]


def test_a_host_in_one_workspace_cannot_authorise_an_address_for_another(con):
    """The whole point. Workspace 2's host proves an address from its own
    report, and workspace 1 is told exactly what it is told about an address
    nobody ever proved."""
    second = db.create_workspace(con, "second")
    theirs, _ = store.add_host(con, "theirs", workspace_id=second)
    assert authz.record_agent_proof(con, theirs, V4, document([V4]),
                                    now=NOW).recorded is True

    refused = authz.may_probe(con, V4, now=NOW,
                              account=authz.account_for_workspace(1))
    assert refused.allowed is False
    assert authz.NO_PROOF in refused.reason
    assert refused.reason == authz.may_probe(
        con, OTHER_V4, now=NOW,
        account=authz.account_for_workspace(1)).reason.replace(OTHER_V4, V4)

    allowed = authz.may_probe(con, V4, now=NOW,
                              account=authz.account_for_workspace(second))
    assert allowed.allowed is True


def test_the_raising_form_refuses_another_workspaces_address(con):
    """The gate a prober actually calls, not only the reporting one."""
    second = db.create_workspace(con, "second")
    theirs, _ = store.add_host(con, "theirs", workspace_id=second)
    authz.record_agent_proof(con, theirs, V4, document([V4]), now=NOW)
    with pytest.raises(authz.NotAuthorized):
        authz.require_probe_authorization(
            con, V4, now=NOW, account=authz.account_for_workspace(1))
    assert authz.require_probe_authorization(
        con, V4, now=NOW, account=authz.account_for_workspace(second)) == V4


def test_a_snapshot_carries_nothing_from_another_workspace(con):
    """The snapshot is what leaves the box for the vantage host, so an entry
    that should not be in it is an authorisation that travelled."""
    second = db.create_workspace(con, "second")
    theirs, _ = store.add_host(con, "theirs", workspace_id=second)
    authz.record_agent_proof(con, theirs, V4, document([V4]), now=NOW)

    mine = authz.build_snapshot(con, [V4], now=NOW,
                                account=authz.account_for_workspace(1))
    assert mine.targets == {}
    with pytest.raises(authz.NotAuthorized):
        mine.require(V4, now=NOW)

    ours = authz.build_snapshot(con, [V4], now=NOW,
                                account=authz.account_for_workspace(second))
    assert ours.require(V4, now=NOW) == V4


def test_two_workspaces_can_each_prove_the_same_address_independently(con):
    """Two rows, two accounts, and revoking is still per address. Nothing here
    merges them into one answer."""
    second = db.create_workspace(con, "second")
    mine, _ = store.add_host(con, "mine", workspace_id=1)
    theirs, _ = store.add_host(con, "theirs", workspace_id=second)
    authz.record_agent_proof(con, mine, V4, document([V4]), now=NOW)
    authz.record_agent_proof(con, theirs, V4, document([V4]), now=NOW)
    assert authz.may_probe(con, V4, now=NOW,
                           account=authz.account_for_workspace(1)).allowed is True
    assert authz.may_probe(con, V4, now=NOW,
                           account=authz.account_for_workspace(second)).allowed is True


def test_a_published_proof_is_bound_to_the_workspace_that_started_it(con):
    """DNS and HTTP proofs carry the account from the challenge, so the same
    boundary holds for the proofs an agent never makes."""
    second = db.create_workspace(con, "second")
    challenge = authz.start_proof(
        con, V4, authz.METHOD_DNS_TXT, now=NOW,
        account=authz.account_for_workspace(second))
    result = authz.verify_proof(con, challenge.id, now=NOW,
                                resolver=lambda name: [challenge.token])
    assert result.recorded is True
    assert authz.may_probe(con, V4, now=NOW,
                           account=authz.account_for_workspace(1)).allowed is False
    assert authz.may_probe(con, V4, now=NOW,
                           account=authz.account_for_workspace(second)).allowed is True


def test_account_for_host_reads_the_column_off_the_row(con):
    second = db.create_workspace(con, "second")
    store.add_host(con, "mine", workspace_id=1)
    store.add_host(con, "theirs", workspace_id=second)
    rows = {row["name"]: row for row in store.list_hosts(con)}
    assert authz.account_for_host(rows["mine"]) == authz.DEFAULT_ACCOUNT
    assert authz.account_for_host(rows["theirs"]) == f"w{second}"


@pytest.mark.parametrize("value", [None, 0, -1, "2", True, 1.5])
def test_account_for_host_falls_back_to_workspace_one_on_anything_unreadable(value):
    """A hand-edited row answers workspace 1, which is where the migration puts
    everything. It is the only fallback that is a real workspace, so nothing
    ever gets an account no gate would recognise."""
    assert authz.account_for_host({"workspace_id": value}) == authz.DEFAULT_ACCOUNT


def test_account_for_host_handles_a_row_from_before_the_column_existed():
    assert authz.account_for_host({"name": "old"}) == authz.DEFAULT_ACCOUNT


def test_live_proof_counts_agree_with_live_for_account_per_account(con):
    """One query over every account, the same answer `live_for_account` gives
    for each: a live proof counts, a revoked one, an expired one and one on a
    revoked host do not, and an account with none is absent."""
    host_id = add_host(con)
    authz.record_agent_proof(con, host_id, V4, document([V4]), now=NOW)
    other = add_host(con, name="other")
    authz.record_agent_proof(con, other, V6, document([V6]), now=NOW)
    con.execute("UPDATE hosts SET revoked_at = ? WHERE id = ?", (NOW.isoformat(), other))
    con.commit()
    counts = authz.live_proof_counts(con, now=NOW)
    accounts = {row["account"] for row in con.execute("SELECT account FROM authorizations")}
    for account in accounts:
        assert counts.get(account, 0) == len(authz.live_for_account(con, account, now=NOW)), account
    assert sum(counts.values()) == 1


# ================================ a token file that could not be read, in words
#
# The second big test, 2026-10-25, case D13: a token file published behind a
# firewall that dropped port 80. The address window said "could not read the
# token file: URLError" in the fail tone, a Python class name on a screen, and
# nothing a person could tell a firewall from a server that is down by. The
# sentence names what happened in words, and still carries no text out of
# the exception (SI-8): only which of a few cases it was.

def _refused():
    return ConnectionRefusedError(111, "Connection refused")


def _unreachable():
    import errno
    return OSError(errno.EHOSTUNREACH, "No route to host")


@pytest.mark.parametrize("error,words", [
    (TimeoutError("timed out"), "the token file could not be read: no answer on port 80"),
    (urllib.error.URLError(TimeoutError("timed out")),
     "the token file could not be read: no answer on port 80"),
    (_refused(), "the token file could not be read: port 80 refused the connection"),
    (urllib.error.URLError(_refused()),
     "the token file could not be read: port 80 refused the connection"),
    (_unreachable(), "the token file could not be read: no route to the address"),
    (urllib.error.URLError(_unreachable()),
     "the token file could not be read: no route to the address"),
    (urllib.error.URLError("something else"), "the token file could not be read"),
    (ConnectionResetError(104, "Connection reset by peer"), "the token file could not be read"),
    (ValueError("bad"), "the token file could not be read"),
])
def test_a_token_file_that_could_not_be_read_says_what_happened_in_words(
        monkeypatch, error, words):
    install_opener(monkeypatch, FakeOpener(error=error))
    with pytest.raises(authz.ProofError) as raised:
        authz.fetch_token_file("http://185.199.108.153/x")
    said = str(raised.value)
    assert said == words
    assert "Error" not in said and "Exception" not in said
    assert raised.value.answered is False
