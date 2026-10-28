"""The address a report arrived from, and who is allowed to say what it is.

    python -m pytest tests/test_ingest_proof.py

SI-6 says an address is probed only after proof of control. Half of the
agent-derived proof is the address the report arrived from, and `app/authz.py`
is explicit that it "must be an address we observed, never one a request
asserted in a header, or the whole proof is worth nothing". The ingest sits
behind Caddy, so the socket it sees belongs to the proxy and the agent's
address only reaches it in a header. This file is where that header is turned
into evidence, and where it is refused.

**The attacker these tests are written from.** Somebody holding a valid host
credential. That is not a high bar: anyone who can enrol a host has one, and a
stolen one is a stolen one. Their goal is to get an address they do not
control authorised, so that the prober will later send packets at somebody
else's machine on their behalf. Every test below is one way they might try it:

  - forge the header on a connection that did not come through the proxy
  - send a list, hoping the first or the last entry is taken
  - send two headers, hoping one is read and the other ignored
  - name an address the document does not bind
  - name a private, loopback, carrier-NAT or link-local address
  - name this control plane's own address
  - hang a port, some whitespace or a zone index off it

Every one of them must end with no authorisation row. A missing proof leaves
an address unauthorised, which is the safe direction and the only direction
this code is allowed to fail in.

The ordinary path is proved too, and it is proved against a real host document
taken from the production database on 2026-08-16 rather than one written to
pass.
"""

import json
import logging

import pytest
from fastapi.testclient import TestClient

from app import authz, db, ingest, store

# Globally routable, because the registry refuses anything else on purpose and
# these tests would otherwise pass for the wrong reason. Nothing here opens a
# socket to any of them.
AGENT_V4 = "185.199.108.153"
AGENT_V6 = "2606:50c0:8000::153"
SOMEBODY_ELSE = "185.199.109.153"

# The production box's own public address. An attacker aiming the prober at the
# control plane itself is the case worth naming out loud.
CONTROL_PLANE_V4 = "192.88.99.198"


@pytest.fixture()
def enrolled(tmp_path, monkeypatch):
    """A host called box1 behind a trusted proxy, returning (client, credential).

    The client address is loopback because that is what the production box
    actually presents: the ingest binds 127.0.0.1:8410 and Caddy is the only
    thing that can reach it. TestClient's own default is the string
    "testclient", which is not an address at all, so a test that forgets to
    ask for loopback gets the untrusted-peer behaviour rather than a pass.
    """
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    _, credential = store.add_host(con, "box1")
    con.close()
    client = TestClient(ingest.app, client=("127.0.0.1", 40000))
    return client, credential


@pytest.fixture()
def untrusted(tmp_path, monkeypatch):
    """The same host, on a connection that did not come from loopback."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    _, credential = store.add_host(con, "box1")
    con.close()
    client = TestClient(ingest.app, client=(SOMEBODY_ELSE, 40000))
    return client, credential


def document(bind_addresses=(AGENT_V4,), hostname="box1"):
    """A host document binding exactly these addresses, in the shape the agent
    really sends (agent/internal/hostdoc.ListeningSocket)."""
    listening = []
    for address in bind_addresses:
        listening.append({"protocol": "tcp",
                          "family": "v6" if ":" in address else "v4",
                          "bind_address": address, "port": 443,
                          "process_name": "nginx", "pid": 100})
    return {"schema_version": 1, "collected_at_unix": 1755000000,
            "hostname": hostname,
            "sockets": {"status": "collected", "listening": listening}}


def post(client, credential, body, forwarded=None, raw_headers=None):
    """One report. `forwarded` is a single X-Forwarded-For value, `raw_headers`
    is the escape hatch for sending two of them."""
    headers = [(b"content-type", b"application/json"),
               (b"authorization", f"Bearer {credential}".encode())]
    if forwarded is not None:
        headers.append((b"x-forwarded-for", forwarded.encode()))
    if raw_headers:
        headers.extend(raw_headers)
    return client.post("/api/v1/reports", content=json.dumps(body),
                       headers=[(k.decode(), v.decode("latin1"))
                                for k, v in headers])


def authorised(tmp_path):
    """Every address this database currently says may be probed."""
    con = db.connect()
    try:
        authz.init(con)
        return {row["target"] for row in authz.list_authorizations(con)
                if authz.may_probe(con, row["target"]).allowed}
    finally:
        con.close()


def stored_reports():
    con = db.connect()
    try:
        return con.execute("SELECT count(*) AS n FROM reports").fetchone()["n"]
    finally:
        con.close()


# ============================================================ the ordinary path

def test_a_report_through_the_proxy_authorises_the_address_it_came_from(
        enrolled, tmp_path):
    client, credential = enrolled
    resp = post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    assert resp.status_code == 204
    assert resp.content == b""  # the ack still carries nothing (SI-2)
    assert authorised(tmp_path) == {AGENT_V4}


def test_the_proof_authorises_that_family_and_no_other(enrolled, tmp_path):
    """v4 and v6 are separate targets (PRODUCT.md 4b rule 3). A host that
    proved its v4 address has proved nothing about its v6 address."""
    client, credential = enrolled
    post(client, credential, document([AGENT_V4, AGENT_V6]), forwarded=AGENT_V4)
    assert authorised(tmp_path) == {AGENT_V4}


def test_a_v6_report_authorises_the_v6_address(enrolled, tmp_path):
    client, credential = enrolled
    post(client, credential, document([AGENT_V4, AGENT_V6]), forwarded=AGENT_V6)
    assert authorised(tmp_path) == {AGENT_V6}


def test_the_v6_address_is_stored_in_one_spelling(enrolled, tmp_path):
    """The header could carry either spelling and they must not become two
    rows, or revoking one would leave the other live."""
    client, credential = enrolled
    long_form = "2606:50c0:8000:0000:0000:0000:0000:0153"
    post(client, credential, document([AGENT_V6]), forwarded=long_form)
    assert authorised(tmp_path) == {AGENT_V6}


def test_the_authorisation_tables_exist_after_a_report(enrolled):
    """`authz.init` has to run where `db.init` runs. It never had, which is why
    the production database taken on 2026-08-16 held no authorizations table at
    all and no address on the fleet was authorised."""
    client, credential = enrolled
    post(client, credential, document(), forwarded=AGENT_V4)
    con = db.connect()
    try:
        names = {row["name"] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
    finally:
        con.close()
    assert {"authorizations", "authz_challenges"} <= names


def test_re_reporting_refreshes_one_row_rather_than_piling_them_up(
        enrolled, tmp_path):
    """An agent re-proves every fifteen minutes and a row per quarter of an
    hour would bury the history instead of being it."""
    client, credential = enrolled
    for _ in range(3):
        post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    con = db.connect()
    try:
        assert len(authz.list_authorizations(con)) == 1
    finally:
        con.close()


# =================================================== the peer is the whole gate

def test_a_forged_header_from_an_untrusted_peer_authorises_nothing(
        untrusted, tmp_path):
    """The attack this file exists for. The connection did not come from
    loopback, so the header is a claim by whoever opened the socket and is not
    evidence of anything, even when the document backs it up."""
    client, credential = untrusted
    resp = post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    assert resp.status_code == 204
    assert authorised(tmp_path) == set()


def test_an_untrusted_peer_does_not_fall_back_to_its_own_socket_address(
        untrusted, tmp_path):
    """Never fall back to the socket address. Behind any proxy at all that
    address is the proxy's, and here it is the attacker's own."""
    client, credential = untrusted
    post(client, credential, document([SOMEBODY_ELSE]))
    assert authorised(tmp_path) == set()


def test_the_default_test_client_peer_is_not_trusted(tmp_path, monkeypatch):
    """A peer that is not an IP address at all, which is what a unix socket or
    a bare hostname looks like in the ASGI scope. Not loopback, so not
    trusted."""
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    con = db.connect()
    db.init(con)
    _, credential = store.add_host(con, "box1")
    con.close()
    client = TestClient(ingest.app)  # its default peer is the string "testclient"
    post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    assert authorised(tmp_path) == set()


def test_a_missing_peer_is_not_trusted():
    """The ASGI scope may carry no client at all, for instance on a unix
    socket. None is not loopback."""
    assert ingest._peer_is_loopback(None) is False


@pytest.mark.parametrize("host", [
    "", "testclient", "not an address", "127.0.0.1 ", "localhost",
    "185.199.108.153", "10.0.0.5", "::ffff:10.0.0.5",
])
def test_a_peer_that_is_not_a_loopback_address_is_not_trusted(host):
    """A private peer is in the list on purpose. Loopback is the boundary, not
    "somewhere on the local network", because the ingest binds loopback and
    anything else arriving means something is in front of us that we did not
    put there."""
    class FakeAddress:
        def __init__(self, host):
            self.host = host
    assert ingest._peer_is_loopback(FakeAddress(host)) is False


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.53", "::1",
                                  "::ffff:127.0.0.1"])
def test_a_loopback_peer_is_trusted(host):
    """`::ffff:127.0.0.1` is trusted, and it is trusted because `ingest` maps
    the embedded address itself rather than because the standard library does.

    **The stdlib answer moved and this test caught it.** CPython 3.12.3 says
    `IPv6Address("::ffff:127.0.0.1").is_loopback` is False and 3.12.13 says it
    is True, and both call themselves Python 3.12. This test failed on Ubuntu
    24.04 on 2026-08-21 while passing on the machine it was written on, which is
    how the difference was found. An earlier version of this docstring asserted
    the delegation as a fact about "Python 3.12", and that was wrong.

    A dual-stack socket spells a loopback peer this way and it still names this
    machine. The peer is written by the kernel from getpeername, not by the
    client, so there is nothing here to spoof.

    Note the deliberate asymmetry with `authz.normalise_target`, which refuses
    a v4-mapped address outright. That is answering "may this be a probe
    target", where two spellings of one address would become two rows. This is
    answering "is the other end of this socket on this machine", which is a
    different question with a different right answer.
    """
    class FakeAddress:
        def __init__(self, host):
            self.host = host
    assert ingest._peer_is_loopback(FakeAddress(host)) is True


@pytest.mark.parametrize("host,expected", [
    # The embedded address decides, so a mapped address that is not loopback
    # must still be refused. Without the explicit mapping these two answers
    # come from whichever interpreter happens to be installed.
    ("::ffff:127.0.0.1", True),
    ("::ffff:127.0.0.53", True),
    ("::ffff:8.8.8.8", False),
    ("::ffff:10.0.0.5", False),
    ("::ffff:0.0.0.0", False),
])
def test_a_v4_mapped_peer_is_judged_on_the_address_inside_it(host, expected):
    """Both directions, because a check that only ever says yes is not a check.

    This exists so the mapping stays explicit. If someone simplifies the
    function back to a bare `peer.is_loopback`, these keep passing on a new
    interpreter and fail on an old one, which is the failure this pins.
    """
    class FakeAddress:
        def __init__(self, host):
            self.host = host
    assert ingest._peer_is_loopback(FakeAddress(host)) is expected


# =========================================== the function on its own, layer by layer
#
# The tests above drive the whole endpoint, which is the honest way to test a
# contract, but it means the registry's own checks stand behind the ingest's.
# A mutation pass showed that: removing the ingest's `normalise_target` call
# entirely changed no end-to-end outcome, because `record_agent_proof`
# normalises again and refuses. That is defence in depth working, and it is
# also a guard with no test of its own. These are the tests of its own.


def fake_request(peer, forwarded=()):
    """A real Starlette request built from an ASGI scope, so the thing under
    test is the thing that runs, with no mock in the middle."""
    from starlette.requests import Request as StarletteRequest
    return StarletteRequest({
        "type": "http", "method": "POST", "path": "/api/v1/reports",
        "query_string": b"", "scheme": "http", "root_path": "",
        "client": tuple(peer) if peer else None,
        "headers": [(b"x-forwarded-for", value.encode()) for value in forwarded],
    })


def test_no_header_means_no_address_rather_than_the_socket_address():
    """**Never fall back to the socket address.** Behind a proxy it is the
    proxy's address, and recording it would authorise the control plane's own
    machine. It happens to be loopback here, which the registry would refuse
    anyway, so only this test says the fallback does not exist."""
    assert ingest.observed_source_address(
        fake_request(("127.0.0.1", 40000))) is None


def test_the_function_itself_refuses_an_address_that_cannot_be_a_target():
    """The ingest's own `normalise_target` call, pinned here rather than
    through the endpoint, where the registry's identical check hides it."""
    for value in ["10.0.0.5", "127.0.0.1", "100.64.0.1", "::1", "fe80::1",
                  "185.199.108.153:443", "2606:50c0:8000::153%eth0",
                  "example.com", "", "unknown"]:
        assert ingest.observed_source_address(
            fake_request(("127.0.0.1", 40000), [value])) is None, value


def test_a_refused_header_value_never_reaches_the_log(caplog):
    """SI-8: what this service writes to the journal about a request is the
    class of what went wrong, never text the request carried. A refused
    X-Forwarded-For value is that text, written by whoever sent the report,
    so the line names the header and the error's class and leaves the value
    out. Each value here is one the registry refuses for its own reason."""
    trusted = ("127.0.0.1", 40000)
    caplog.set_level(logging.DEBUG, logger="app.ingest")
    for value in ["10.0.0.5", "185.199.108.153:443", "2606:50c0:8000::153%eth0",
                  "written by the client", "unknown"]:
        caplog.clear()
        assert ingest.observed_source_address(
            fake_request(trusted, [value])) is None, value
        logged = "\n".join(record.getMessage() for record in caplog.records)
        assert value not in logged, value
        assert "TargetError" in logged, value


def test_the_function_itself_canonicalises_what_it_returns():
    long_form = "2606:50c0:8000:0000:0000:0000:0000:0153"
    assert ingest.observed_source_address(
        fake_request(("127.0.0.1", 40000), [long_form])) == AGENT_V6


def test_the_function_itself_refuses_a_list_and_a_second_header():
    trusted = ("127.0.0.1", 40000)
    assert ingest.observed_source_address(
        fake_request(trusted, [f"{AGENT_V4}, {SOMEBODY_ELSE}"])) is None
    assert ingest.observed_source_address(
        fake_request(trusted, [AGENT_V4, SOMEBODY_ELSE])) is None
    assert ingest.observed_source_address(
        fake_request(trusted, [AGENT_V4])) == AGENT_V4


def test_the_registry_is_never_asked_about_an_address_we_do_not_have(
        tmp_path, monkeypatch):
    """`_record_observed_proof` returns before touching the registry when there
    is no observed address. Handing it None would work by accident, because
    `normalise_target` refuses a non-string, but a guard that relies on the
    next layer's accident is not a guard."""
    asked = []
    monkeypatch.setattr(ingest.authz, "record_agent_proof",
                        lambda *a, **k: asked.append(a))
    ingest._record_observed_proof(None, 1, "{}", None)
    assert asked == []


# ============================================== what the header is allowed to be

def test_a_list_of_addresses_authorises_nothing(enrolled, tmp_path):
    """Taking the first entry trusts whatever the client prepended. Taking the
    last trusts a header shape we never configured. Both entries here name an
    address the document binds, so anything but a flat refusal authorises
    something the agent did not prove."""
    client, credential = enrolled
    doc = document([AGENT_V4, SOMEBODY_ELSE])
    post(client, credential, doc, forwarded=f"{SOMEBODY_ELSE}, {AGENT_V4}")
    assert authorised(tmp_path) == set()
    post(client, credential, doc, forwarded=f"{AGENT_V4}, {SOMEBODY_ELSE}")
    assert authorised(tmp_path) == set()


def test_a_trailing_comma_authorises_nothing(enrolled, tmp_path):
    """A one-entry list is still a list, and reading it as a bare address would
    mean the comma decides which parser runs."""
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]), forwarded=f"{AGENT_V4},")
    assert authorised(tmp_path) == set()


def test_two_forwarded_headers_authorise_nothing(enrolled, tmp_path):
    """Two headers, one of them ours. There is no way to tell which, so
    neither is evidence.

    **The document binds both addresses deliberately.** An earlier version of
    this test bound only one, so a build that read the wrong header still
    refused, for the wrong reason, and the test passed. It was a mutation that
    exposed it: taking the first entry survived the whole suite. With both
    addresses bound, reading either header authorises something, so any
    outcome but an empty set is a failure.
    """
    client, credential = enrolled
    resp = post(client, credential, document([AGENT_V4, SOMEBODY_ELSE]),
                forwarded=SOMEBODY_ELSE,
                raw_headers=[(b"x-forwarded-for", AGENT_V4.encode())])
    assert resp.status_code == 204
    assert authorised(tmp_path) == set()


def test_three_forwarded_headers_authorise_nothing(enrolled, tmp_path):
    client, credential = enrolled
    post(client, credential, document([AGENT_V4, SOMEBODY_ELSE, AGENT_V6]),
         forwarded=SOMEBODY_ELSE,
         raw_headers=[(b"x-forwarded-for", AGENT_V4.encode()),
                      (b"x-forwarded-for", AGENT_V6.encode())])
    assert authorised(tmp_path) == set()


def test_an_absent_header_authorises_nothing(enrolled, tmp_path):
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]))
    assert authorised(tmp_path) == set()


def test_an_empty_header_authorises_nothing(enrolled, tmp_path):
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]), forwarded="")
    assert authorised(tmp_path) == set()


def test_a_header_naming_an_address_the_document_does_not_bind_authorises_nothing(
        enrolled, tmp_path):
    """The half `authz.record_agent_proof` already enforces, checked from the
    outside so a future change to the wiring cannot skip it."""
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]), forwarded=SOMEBODY_ELSE)
    assert authorised(tmp_path) == set()


def test_a_document_that_only_asserts_an_address_authorises_nothing(
        enrolled, tmp_path):
    """The other half. A host writes its own document, so a target must never
    be able to authorise itself by saying it binds an address."""
    client, credential = enrolled
    post(client, credential, document([SOMEBODY_ELSE]), forwarded=AGENT_V4)
    assert authorised(tmp_path) == set()


@pytest.mark.parametrize("forwarded", [
    "10.0.0.5", "192.168.1.1", "172.16.0.1",    # private
    "127.0.0.1", "0.0.0.0",                     # loopback and the wildcard
    "169.254.1.1",                              # link local
    "100.64.0.1",                               # carrier NAT, shared with strangers
    "224.0.0.1", "255.255.255.255",             # multicast and broadcast
    "::1", "::", "fe80::1", "fc00::1", "ff02::1",
    "::ffff:185.199.108.153",                   # a v4 address in a v6 costume
])
def test_an_address_that_cannot_be_a_target_authorises_nothing(
        enrolled, tmp_path, forwarded):
    """The observed address is data from outside, so it goes through
    `authz.normalise_target` like every other candidate target. A carrier-NAT
    address is the one that matters most in practice: it is shared with
    strangers, so probing it probes somebody else."""
    client, credential = enrolled
    post(client, credential, document([forwarded]), forwarded=forwarded)
    assert authorised(tmp_path) == set()


@pytest.mark.parametrize("forwarded", [
    "185.199.108.153:443",                      # a port, the common proxy spelling
    "[2606:50c0:8000::153]:443",
    "2606:50c0:8000::153%eth0",                 # a zone index names one machine's NIC
    "fe80::1%eth0",
    "185.199.108.153/32",
    "example.com",                              # a name is not an address
    "185.199.108.153 185.199.109.153",
    "unknown", "_hidden",                       # RFC 7239 obfuscated identifiers
])
def test_a_header_that_is_not_a_bare_address_authorises_nothing(
        enrolled, tmp_path, forwarded):
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]), forwarded=forwarded)
    assert authorised(tmp_path) == set()


def test_surrounding_whitespace_is_read_through(enrolled, tmp_path):
    """Pinned rather than assumed. Leading and trailing whitespace around a
    header value is the HTTP parser's to strip, and stripping it lets no
    address through that a bare address would not."""
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]), forwarded=f"  {AGENT_V4}  ")
    assert authorised(tmp_path) == {AGENT_V4}


def test_the_control_planes_own_address_is_not_authorised_by_asserting_it(
        enrolled, tmp_path):
    """Aiming the prober at the control plane. The document claims the address
    and the header claims it too, but the connection did not arrive from it, so
    there is nothing observed to agree with the claim.

    On a trusted peer the header is believed, so this case rests on the
    attacker not being able to make Caddy write an address it did not accept a
    connection from. That is the same boundary as every other test here, and it
    is why the peer check is the gate rather than a hint.
    """
    client, credential = enrolled
    post(client, credential, document([CONTROL_PLANE_V4]),
         forwarded=SOMEBODY_ELSE)
    assert authorised(tmp_path) == set()


def test_a_report_that_reaches_caddy_over_loopback_authorises_nothing(
        enrolled, tmp_path):
    """A process on the box posting to Caddy over the loopback interface. Caddy
    forwards 127.0.0.1, which is not a target, so nothing is recorded even
    though the peer is trusted. Anything else would authorise an address that
    means a different machine to every reader."""
    client, credential = enrolled
    post(client, credential, document(["127.0.0.1"]), forwarded="127.0.0.1")
    assert authorised(tmp_path) == set()


# ============================== storing the report is never the proof's business

def test_the_report_is_stored_even_when_no_proof_can_be_recorded(
        enrolled, tmp_path):
    client, credential = enrolled
    body = document([AGENT_V4])
    resp = post(client, credential, body, forwarded=SOMEBODY_ELSE)
    assert resp.status_code == 204
    assert stored_reports() == 1
    assert authorised(tmp_path) == set()


def test_a_recorded_proof_and_a_refused_one_look_identical_to_the_agent(
        enrolled, tmp_path):
    """SI-2. The response is an acknowledgement and carries nothing an agent
    could act on, so it must not become a side channel that says whether an
    address was authorised. An attacker probing for that answer gets the same
    bytes either way."""
    client, credential = enrolled
    recorded = post(client, credential, document([AGENT_V4]),
                    forwarded=AGENT_V4)
    refused = post(client, credential, document([AGENT_V4]),
                   forwarded=SOMEBODY_ELSE)
    assert authorised(tmp_path) == {AGENT_V4}  # the two really did differ
    assert recorded.status_code == refused.status_code == 204
    assert recorded.content == refused.content == b""
    ignored = {"date", "server"}
    assert {k: v for k, v in recorded.headers.items() if k not in ignored} == \
        {k: v for k, v in refused.headers.items() if k not in ignored}


def test_a_proof_that_raises_never_fails_the_report(enrolled, tmp_path,
                                                    monkeypatch):
    """Storing the document is the ingest's job and an authorisation is a side
    effect. A registry that throws must cost us the authorisation, never the
    evidence."""
    def explode(*args, **kwargs):
        raise RuntimeError("the registry fell over")

    monkeypatch.setattr(ingest.authz, "record_agent_proof", explode)
    client, credential = enrolled
    resp = post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    assert resp.status_code == 204
    assert resp.content == b""
    assert stored_reports() == 1


def test_a_proof_is_never_recorded_for_a_report_that_was_refused(
        enrolled, tmp_path):
    """A bad envelope is a 400 and stores nothing, so it must authorise nothing
    either. The proof is a side effect of a report we accepted."""
    client, credential = enrolled
    resp = post(client, credential, {"schema_version": "one"},
                forwarded=AGENT_V4)
    assert resp.status_code == 400
    assert stored_reports() == 0
    assert authorised(tmp_path) == set()


def test_a_wrong_credential_authorises_nothing(enrolled, tmp_path):
    client, _ = enrolled
    resp = post(client, store.new_credential(), document([AGENT_V4]),
                forwarded=AGENT_V4)
    assert resp.status_code == 401
    assert authorised(tmp_path) == set()


def test_a_revoked_host_authorises_nothing(enrolled, tmp_path):
    client, credential = enrolled
    post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    con = db.connect()
    store.revoke_host(con, "box1")
    con.close()
    post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4)
    # The live row is closed by the host revocation the gate already joins on.
    assert authorised(tmp_path) == set()


# =============================================== replayed from the real database

# The listening sockets of ubuntu-vps, copied verbatim out of report 832 in
# the production database on 2026-08-16. It is here rather than paraphrased
# because a document written to pass a test proves nothing about the shape the
# agent really sends.
#
# Worth reading before trusting it: the only globally routable address this
# host binds a socket to is the DHCP client's, on udp/68. Its ssh listener is
# on the wildcard, which names no address, so agent-derived proof for this host
# hangs entirely on systemd-networkd holding that socket.
UBUNTU_VPS_LISTENING = [
    {"protocol": "tcp", "family": "v4", "bind_address": "0.0.0.0",
     "port": 22, "process_name": "systemd", "pid": 1},
    {"protocol": "tcp", "family": "v4", "bind_address": "127.0.0.53",
     "port": 53, "process_name": "systemd-resolve", "pid": 2300339},
    {"protocol": "tcp", "family": "v4", "bind_address": "127.0.0.54",
     "port": 53, "process_name": "systemd-resolve", "pid": 2300339},
    {"protocol": "tcp", "family": "v6", "bind_address": "::",
     "port": 22, "process_name": "systemd", "pid": 1},
    {"protocol": "udp", "family": "v4", "bind_address": "127.0.0.53",
     "port": 53, "process_name": "systemd-resolve", "pid": 2300339},
    {"protocol": "udp", "family": "v4", "bind_address": "127.0.0.54",
     "port": 53, "process_name": "systemd-resolve", "pid": 2300339},
    {"protocol": "udp", "family": "v4", "bind_address": "192.88.99.215",
     "port": 68, "process_name": "systemd-network", "pid": 2300086},
]
UBUNTU_VPS_V4 = "192.88.99.215"

# almabox, from report 833 the same day. It is the owner's home box behind NAT,
# and every address it binds is either the wildcard, loopback, a Tailscale
# carrier-NAT address or link local. It is the NAT case the design is built
# around, using real data.
ALMABOX_BINDS = ["0.0.0.0", "100.64.3.4", "127.0.0.1",
                   "::", "::1", "fd7a:115c:a1e0::c534:b871",
                   "fe80::eeb1:d7ff:fe4b:df98"]


def real_document(listening, hostname):
    return {"schema_version": 1, "collected_at_unix": 1755000000,
            "hostname": hostname,
            "sockets": {"status": "collected", "listening": listening}}


def test_a_real_report_authorises_the_address_it_binds_and_nothing_else(
        enrolled, tmp_path):
    client, credential = enrolled
    body = real_document(UBUNTU_VPS_LISTENING, "ubuntu-vps")
    resp = post(client, credential, body, forwarded=UBUNTU_VPS_V4)
    assert resp.status_code == 204
    assert authorised(tmp_path) == {UBUNTU_VPS_V4}


def test_a_real_report_does_not_authorise_its_wildcard_or_loopback_binds(
        enrolled, tmp_path):
    """The same document, replayed with each of its other bind addresses in the
    header. A wildcard names no address and loopback names a different machine
    to every reader."""
    client, credential = enrolled
    body = real_document(UBUNTU_VPS_LISTENING, "ubuntu-vps")
    for address in ["0.0.0.0", "127.0.0.53", "127.0.0.54", "::"]:
        post(client, credential, body, forwarded=address)
    assert authorised(tmp_path) == set()


def test_a_real_report_from_a_host_behind_nat_authorises_nothing(
        enrolled, tmp_path):
    """almabox's real bind addresses, with the header naming the public
    address its home router would present. Nothing matches, which is the
    correct answer: that address belongs to the router, not the host."""
    client, credential = enrolled
    listening = [{"protocol": "tcp", "family": "v6" if ":" in a else "v4",
                  "bind_address": a, "port": 443,
                  "process_name": "tailscaled", "pid": 900}
                 for a in ALMABOX_BINDS]
    post(client, credential, real_document(listening, "almabox"),
         forwarded=SOMEBODY_ELSE)
    assert authorised(tmp_path) == set()


def test_a_real_report_does_not_authorise_its_own_carrier_nat_address(
        enrolled, tmp_path):
    """almabox binds a Tailscale address in 100.64.0.0/10. Both halves of the
    proof would agree on it, and it is still refused, because that range is
    shared between a carrier's customers and probing it probes a stranger."""
    client, credential = enrolled
    listening = [{"protocol": "tcp", "family": "v4",
                  "bind_address": "100.64.3.4", "port": 443,
                  "process_name": "tailscaled", "pid": 900}]
    post(client, credential, real_document(listening, "almabox"),
         forwarded="100.64.3.4")
    assert authorised(tmp_path) == set()


# ================================================ the deployment is part of this

def test_the_ingest_unit_turns_uvicorn_proxy_headers_off():
    """The teeth, and the reason this test exists at all.

    uvicorn installs `ProxyHeadersMiddleware` by default (`proxy_headers: bool
    = True` in uvicorn 0.52.2 `config.py`, trusted hosts defaulting to
    127.0.0.1). That middleware overwrites the ASGI scope's client with an
    address it reads out of `X-Forwarded-For` itself, so with it on,
    `request.client` is no longer the socket peer and the peer check above is
    asking the header about the header.

    Turning it off is what makes `_peer_is_loopback` mean what it says. It is a
    flag in a unit file, which is exactly the kind of thing that gets dropped
    in a rewrite, so it is pinned here.
    """
    import pathlib
    unit = pathlib.Path(__file__).resolve().parents[1] / "ops" / \
        "whichports-ingest.service"
    exec_start = [line for line in unit.read_text().splitlines()
                  if line.startswith("ExecStart=")]
    assert len(exec_start) == 1, exec_start
    assert "--no-proxy-headers" in exec_start[0]
    assert "--host 127.0.0.1" in exec_start[0]


# ================================================ presence, since agent 0.1.11
#
# A dual-stack host reaches the control plane over one family, so its report
# proved one address and the other read no_authorization for good, which is
# what the first outside server showed (docs/RECORD.md 4.184). The agent follows
# every report with one empty request per family, and this route proves the
# address it arrived from against the newest document, by the same rule.

def presence(client, credential, forwarded=None):
    headers = [("authorization", f"Bearer {credential}")]
    if forwarded is not None:
        headers.append(("x-forwarded-for", forwarded))
    return client.post("/api/v1/reports/presence", headers=headers)


def test_presence_over_the_other_family_proves_the_other_address(enrolled, tmp_path):
    """The report came over v6 and proved the v6 address. The presence over
    v4 proves the v4 address, corroborated by the same stored document."""
    client, credential = enrolled
    body = document([AGENT_V4, AGENT_V6])
    assert post(client, credential, body, forwarded=AGENT_V6).status_code == 204
    assert authorised(tmp_path) == {AGENT_V6}
    assert presence(client, credential, forwarded=AGENT_V4).status_code == 204
    assert authorised(tmp_path) == {AGENT_V4, AGENT_V6}
    # nothing was stored for it
    assert stored_reports() == 1


def test_presence_from_an_address_the_host_does_not_hold_proves_nothing(enrolled, tmp_path):
    client, credential = enrolled
    assert post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4).status_code == 204
    assert presence(client, credential, forwarded="198.51.100.9").status_code == 204
    assert authorised(tmp_path) == {AGENT_V4}


def test_presence_before_any_report_proves_nothing(enrolled, tmp_path):
    """Nothing to corroborate with, so nothing is recorded, and the request
    still answers 204: the agent acts on nothing in the answer anyway."""
    client, credential = enrolled
    assert presence(client, credential, forwarded=AGENT_V4).status_code == 204
    assert authorised(tmp_path) == set()
    assert stored_reports() == 0


def test_presence_refuses_a_bad_or_missing_credential(enrolled):
    client, _credential = enrolled
    assert presence(client, "whp_" + "0" * 64, forwarded=AGENT_V4).status_code == 401
    assert client.post("/api/v1/reports/presence").status_code == 401


def test_presence_with_no_trusted_address_records_nothing(enrolled, tmp_path):
    client, credential = enrolled
    assert post(client, credential, document([AGENT_V4]), forwarded=AGENT_V4).status_code == 204
    # no forwarded header: the address was never seen, so nothing is proved
    assert presence(client, credential).status_code == 204
    assert authorised(tmp_path) == {AGENT_V4}
