"""The self-hosted side of the prober API: `dispatch.ApiTransport`, the
settings that choose it, and `vantages_cli sync-api`.

The promise it has to keep is the brief's: **same batch shape, same answers,
same refusals.** So the last part of this file runs one pass from a
self-hosted instance's own database, through the real routes of our ingest
and the real worker, to the real runner in process, and compares what the
instance stored row for row with what the same pass over ssh stores.
"""
import http.server
import io
import json
import threading
import time
import urllib.error
import urllib.parse
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import (authz, db, dispatch, ingest, instances, prober, prober_cli,
                 proberapi, proberapi_worker, store, vantages, vantages_cli)

from test_proberapi_worker import Far

V4 = "185.199.108.153"
V6 = "2606:50c0:8000::153"
OTHER_V4 = "185.199.108.154"
PROBE1_V4 = "78.141.210.130"
PROBE2_V4 = "185.199.110.7"
BASE = "https://app.whichports.test"
KEY = "whpi_" + "a" * 64


# ================================================= a scripted API, no network

class Scripted:
    """An opener that answers from a list, and records what it was asked."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.asked = []

    def open(self, request, timeout=None):
        self.asked.append(request)
        status, body = self.answers.pop(0)
        if isinstance(body, Exception):
            raise body
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, "", {},
                                         io.BytesIO(raw))
        return _Response(status, raw)


class _Response:
    def __init__(self, status, raw):
        self.status = status
        self._raw = raw

    def read(self, n=-1):
        return self._raw if n < 0 else self._raw[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def transport(opener, **kwargs):
    return dispatch.ApiTransport("probe1", base_url=BASE, key=KEY, opener=opener,
                                 sleep=lambda s: None, **kwargs)


def a_batch(vantage="their-name-for-it"):
    return json.dumps({"version": 1, "vantage": vantage, "addresses": [V4],
                       "ports": [22], "tls_ports": [], "snapshot": {}})


ANSWER = {"vantage": "probe1", "started_at": "x", "finished_at": "y",
          "results": [], "certificates": []}


def test_a_batch_is_queued_waited_for_and_its_answer_returned():
    opener = Scripted((202, {"id": "b1", "state": "queued"}),
                      (202, {"state": "queued"}),
                      (202, {"state": "running"}),
                      (200, {"state": "done", "answer": ANSWER}))
    assert json.loads(transport(opener)(a_batch())) == ANSWER
    methods = [(r.get_method(), urllib.parse.urlsplit(r.full_url).path)
               for r in opener.asked]
    assert methods == [("POST", "/api/v1/prober/batches")] + \
        [("GET", "/api/v1/prober/batches/b1")] * 3


def test_the_batch_goes_as_it_was_built_with_our_name_for_the_vantage():
    opener = Scripted((202, {"id": "b1"}), (200, {"state": "done", "answer": ANSWER}))
    transport(opener)(a_batch())
    sent = json.loads(opener.asked[0].data)
    assert sent == {**json.loads(a_batch()), "vantage": "probe1"}


def test_the_key_travels_in_the_header_and_nowhere_else():
    opener = Scripted((202, {"id": "b1"}), (200, {"state": "done", "answer": ANSWER}))
    transport(opener)(a_batch())
    for request in opener.asked:
        assert request.get_header("Authorization") == f"Bearer {KEY}"
        assert KEY not in request.full_url
        assert KEY.encode() not in (request.data or b"")


def test_the_route_constant_is_the_servers():
    assert dispatch.PROBER_API_PATH == proberapi.PATH_PREFIX


def test_a_batch_id_is_quoted_into_the_path():
    opener = Scripted((202, {"id": "a/b?c"}), (200, {"state": "done", "answer": ANSWER}))
    transport(opener)(a_batch())
    assert urllib.parse.urlsplit(opener.asked[1].full_url).path.endswith("/a%2Fb%3Fc")


@pytest.mark.parametrize("error", sorted(dispatch.API_UNREACHABLE_ERRORS - {
    "vantage_unreachable"}))
def test_a_refusal_about_the_api_or_the_vantage_stops_the_vantage(error):
    opener = Scripted((proberapi.ERRORS[error], {"error": error}))
    with pytest.raises(dispatch.VantageUnreachable, match=error):
        transport(opener)(a_batch())


@pytest.mark.parametrize("error", sorted(set(proberapi.ERRORS)
                                         - dispatch.API_UNREACHABLE_ERRORS))
def test_a_refusal_about_this_batch_fails_this_host_only(error):
    opener = Scripted((proberapi.ERRORS[error], {"error": error}))
    with pytest.raises(dispatch.DispatchFailed, match=error) as caught:
        transport(opener)(a_batch())
    assert not isinstance(caught.value, dispatch.VantageUnreachable)


@pytest.mark.parametrize("failure, raised", [
    ("vantage_unreachable", dispatch.VantageUnreachable),
    ("prober_refused", dispatch.DispatchFailed),
    ("prober_answer_unreadable", dispatch.DispatchFailed),
    ("names_a_vantage_address", dispatch.DispatchFailed),
    ("interrupted", dispatch.DispatchFailed),
])
def test_a_failed_batch_raises_what_ssh_would(failure, raised):
    opener = Scripted((202, {"id": "b1"}), (200, {"state": "failed", "error": failure}))
    with pytest.raises(raised, match=failure):
        transport(opener)(a_batch())


def test_every_failure_class_the_server_has_is_mapped():
    """A class the client does not know is read as unreachable. That is safe
    and it is also a pass that stops early for no reason, so every class the
    server can send is one this test has seen above."""
    known = {"vantage_unreachable", "prober_refused", "prober_answer_unreadable",
             "names_a_vantage_address", "interrupted"}
    assert proberapi.FAILURES == known


@pytest.mark.parametrize("status, body", [
    (502, b"<html>Bad Gateway</html>"),
    (500, b""),
    (503, {"error": "made up class"}),
    (400, {"error": "x" * 65}),
    (400, {"error": 7}),
    (400, [1, 2]),
])
def test_an_error_that_carries_no_class_of_ours_is_the_api_being_unreachable(status, body):
    with pytest.raises(dispatch.VantageUnreachable) as caught:
        transport(Scripted((status, body)))(a_batch())
    assert "made up" not in str(caught.value)
    assert "Bad Gateway" not in str(caught.value)


def test_nothing_the_api_says_beyond_the_class_reaches_the_message():
    opener = Scripted((409, {"error": "batch_in_flight",
                             "detail": "the secret thing a server said"}))
    with pytest.raises(dispatch.VantageUnreachable) as caught:
        transport(opener)(a_batch())
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("raised", [
    urllib.error.URLError("no route"), TimeoutError("timed out"),
    ConnectionRefusedError(), OSError("down"),
])
def test_an_api_that_cannot_be_reached_stops_the_vantage(raised):
    with pytest.raises(dispatch.VantageUnreachable):
        transport(Scripted((0, raised)))(a_batch())


@pytest.mark.parametrize("answers", [
    [(200, {"id": "b1"})],
    [(202, {"state": "queued"})],
    [(202, b"not json")],
    [(202, {"id": "b1"}), (200, {"state": "done", "answer": "text"})],
    [(202, {"id": "b1"}), (200, {"state": "weird"})],
    [(202, {"id": "b1"}), (200, b"[]")],
])
def test_an_answer_that_is_not_the_apis_shape_is_never_a_measurement(answers):
    with pytest.raises(dispatch.DispatchFailed):
        transport(Scripted(*answers))(a_batch())


def test_a_batch_that_is_never_answered_gives_up_at_the_deadline():
    ticks = iter(range(0, 10_000, 100))
    opener = Scripted((202, {"id": "b1"}), *[(202, {"state": "queued"})] * 20)
    with pytest.raises(dispatch.VantageUnreachable, match="did not answer"):
        transport(opener, deadline_seconds=900, clock=lambda: next(ticks))(a_batch())
    assert len(opener.asked) < 20


def test_the_deadline_is_the_fifteen_minutes_ssh_gets():
    assert dispatch.API_DEADLINE_SECONDS == dispatch.SshTransport("x").timeout


def test_a_batch_that_is_not_json_is_not_sent():
    opener = Scripted()
    with pytest.raises(dispatch.DispatchFailed):
        transport(opener)("{")
    assert opener.asked == []


# ================================================================ settings

@pytest.mark.parametrize("url", [
    "http://app.whichports.com", "https://", "ftp://app.whichports.com",
    "https://app.whichports.com/api", "https://app.whichports.com/?x=1",
    "https://user:pw@app.whichports.com", "app.whichports.com", None, 7,
])
def test_the_api_address_is_https_and_a_host_and_nothing_else(url):
    with pytest.raises(dispatch.TransportConfigError):
        dispatch.ApiTransport("probe1", base_url=url, key=KEY)


def test_a_trailing_slash_is_fine_and_a_key_is_required():
    assert dispatch.ApiTransport("p", base_url=BASE + "/", key=KEY).base_url == BASE
    for key in ("", "  ", None):
        with pytest.raises(dispatch.TransportConfigError):
            dispatch.ApiTransport("p", base_url=BASE, key=key)


def test_with_nothing_set_a_pass_uses_ssh_as_it_always_has():
    assert dispatch.default_transport_factory({}) is dispatch.SshTransport


def test_with_both_set_a_pass_uses_the_api():
    factory = dispatch.default_transport_factory({
        dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_API_KEY_ENV: KEY})
    made = factory("probe2")
    assert isinstance(made, dispatch.ApiTransport)
    assert made.destination == "probe2"
    assert made.base_url == BASE


@pytest.mark.parametrize("environ", [
    {dispatch.PROBER_API_ENV: BASE},
    {dispatch.PROBER_API_KEY_ENV: KEY},
    {dispatch.PROBER_API_ENV: "http://app.whichports.com",
     dispatch.PROBER_API_KEY_ENV: KEY},
])
def test_half_a_setting_is_refused_rather_than_falling_back_to_ssh(environ):
    with pytest.raises(dispatch.TransportConfigError):
        dispatch.default_transport_factory(environ)


def test_a_pass_on_a_half_configured_instance_exits_two_and_sends_nothing(
        tmp_path, monkeypatch, capsys):
    con = db.connect(":memory:")
    for module in (db, authz, prober, vantages):
        module.init(con)
    vantages.add(con, "probe1", "probe1", [PROBE1_V4])
    monkeypatch.setenv(dispatch.PROBER_API_ENV, BASE)
    monkeypatch.delenv(dispatch.PROBER_API_KEY_ENV, raising=False)
    code = prober_cli._probe_registry(con, [], tls_ports=())
    assert code == 2
    assert dispatch.PROBER_API_KEY_ENV in capsys.readouterr().err


# ============================================ the real urllib, on loopback

class Handler(http.server.BaseHTTPRequestHandler):
    """A tiny API: answers from `script`, records every request."""
    script = []
    seen = []

    def log_message(self, *args):
        pass

    def _answer(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        Handler.seen.append((self.command, self.path,
                             self.headers.get("Authorization"), body))
        status, headers, payload = Handler.script.pop(0)
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        raw = json.dumps(payload).encode()
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    do_GET = _answer
    do_POST = _answer


@pytest.fixture()
def loopback():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Handler.script, Handler.seen = [], []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()
    server.server_close()


def real(base):
    return dispatch.ApiTransport("probe1", base_url=base, key=KEY, allow_http=True,
                                 sleep=lambda s: None)


def test_the_real_client_follows_the_two_steps(loopback):
    Handler.script = [(202, {}, {"id": "b1", "state": "queued"}),
                      (202, {}, {"state": "queued"}),
                      (200, {}, {"state": "done", "answer": ANSWER})]
    assert json.loads(real(loopback)(a_batch())) == ANSWER
    assert [(m, p, a) for m, p, a, _ in Handler.seen] == [
        ("POST", "/api/v1/prober/batches", f"Bearer {KEY}"),
        ("GET", "/api/v1/prober/batches/b1", f"Bearer {KEY}"),
        ("GET", "/api/v1/prober/batches/b1", f"Bearer {KEY}")]


def test_the_real_client_reads_a_class_from_an_http_error(loopback):
    Handler.script = [(409, {}, {"error": "batch_in_flight"})]
    with pytest.raises(dispatch.VantageUnreachable, match="batch_in_flight"):
        real(loopback)(a_batch())


def test_the_real_client_never_follows_a_redirect_with_the_key(loopback):
    """urllib keeps the Authorization header across a redirect, so following
    one would send the key wherever it pointed."""
    Handler.script = [(302, {"Location": loopback + "/elsewhere"}, {})]
    with pytest.raises(dispatch.VantageUnreachable):
        real(loopback)(a_batch())
    assert [p for _, p, _, _ in Handler.seen] == ["/api/v1/prober/batches"]


def test_the_real_client_reaches_nothing_and_says_so():
    with pytest.raises(dispatch.VantageUnreachable):
        real("http://127.0.0.1:9")(a_batch())


# ============================================== the pass, whole, both ways

class ThroughTheIngest:
    """An opener that hands each request to our real ingest app instead of the
    network, so the instance's client talks to our real routes."""

    def __init__(self, client):
        self.client = client

    def open(self, request, timeout=None):
        url = urllib.parse.urlsplit(request.full_url)
        response = self.client.request(request.get_method(), url.path,
                                       headers=dict(request.header_items()),
                                       content=request.data)
        if response.status_code >= 400:
            raise urllib.error.HTTPError(request.full_url, response.status_code,
                                         "", response.headers,
                                         io.BytesIO(response.content))
        return _Response(response.status_code, response.content)


@pytest.fixture()
def two_sides(tmp_path, monkeypatch):
    """Our control plane (the ingest's database, two vantages, one instance)
    and the instance's own control plane (a host that reported and proved V4
    and V6 to it). Returns (ours, theirs, issued, client)."""
    ours = str(tmp_path / "ours.db")
    monkeypatch.setenv(db.DB_ENV, ours)
    con = db.connect(ours)
    for module in (db, authz, prober, vantages, instances, proberapi):
        module.init(con)
    vantages.add(con, "probe1", "root@" + PROBE1_V4, [PROBE1_V4])
    vantages.add(con, "probe2", "root@" + PROBE2_V4, [PROBE2_V4])
    issued = instances.add(con, "freedom", origin=authz.ORIGIN_INVITED)
    con.close()

    theirs = db.connect(str(tmp_path / "theirs.db"))
    for module in (db, authz, prober, vantages):
        module.init(theirs)
    host_id, _ = store.add_host(theirs, "web1")
    document = json.dumps({
        "sockets": {"listening": [
            {"protocol": "tcp", "port": port, "bind_address": "0.0.0.0",
             "family": "v4"} for port in (22, 80, 443)]},
        "interface_addresses": {"addresses": [
            {"interface": "eth0", "family": "v4", "address": V4, "global": True},
            {"interface": "eth0", "family": "v6", "address": V6, "global": True}]}})
    store.insert_report(theirs, host_id, 1, 1, document)
    for address in (V4, V6):
        assert authz.record_agent_proof(theirs, host_id, address, document,
                                        now=datetime.now(timezone.utc)).recorded
    client = TestClient(ingest.app, client=("127.0.0.1", 40000))
    yield ours, theirs, issued, client
    theirs.close()


def serve_the_queue(path, stop):
    con = db.connect(path)
    try:
        while not stop.is_set():
            proberapi_worker.run_round(con, transport_factory=Far().factory,
                                       lock_wait_seconds=5)
            time.sleep(0.01)
    finally:
        con.close()


def through_the_api(client, issued):
    opener = ThroughTheIngest(client)
    return lambda destination: dispatch.ApiTransport(
        destination, base_url=BASE, key=issued.api_key, opener=opener,
        poll_seconds=0.01)


def a_pass(con, factory):
    plan = prober_cli._with_joined_ports(con, prober_cli.plan_for(
        con, store.list_hosts(con)[0]))
    return dispatch.run_pass(con, [plan], vantages.enabled(con),
                             transport_factory=factory,
                             exclude=vantages.all_addresses(con))


def rows(con, run):
    return sorted((r["family"], r["target"], r["port"], r["state"], r["reason"])
                  for r in prober.run_results(con, run.id))


def test_sync_api_takes_our_vantages_by_name(two_sides, capsys):
    _ours, theirs, issued, client = two_sides
    code = vantages_cli._sync_api(
        theirs, environ={dispatch.PROBER_API_ENV: BASE,
                         dispatch.PROBER_API_KEY_ENV: issued.api_key},
        opener=ThroughTheIngest(client))
    assert code == 0
    listed = [(v.name, v.destination, v.enabled, v.addresses)
              for v in vantages.list_all(theirs)]
    assert listed == [("probe1", "probe1", True, (PROBE1_V4,)),
                      ("probe2", "probe2", True, (PROBE2_V4,))]
    assert "added probe1" in capsys.readouterr().out


def test_sync_api_refuses_without_both_settings(two_sides, capsys):
    _ours, theirs, _issued, _client = two_sides
    assert vantages_cli._sync_api(theirs, environ={}) == 2
    assert vantages.list_all(theirs) == []


def test_a_pass_through_the_api_stores_what_a_pass_over_ssh_stores(two_sides):
    """Same batch shape, same answers, same refusals. The instance proved V4
    to us and V6 only to itself, so V4 is measured and V6 is refused, and the
    rows it stores are the rows an ssh pass whose snapshot allowed only V4
    would store, from both vantages."""
    ours, theirs, issued, client = two_sides
    vantages_cli._sync_api(theirs, environ={
        dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_API_KEY_ENV: issued.api_key},
        opener=ThroughTheIngest(client))
    presence = client.post(f"{proberapi.PATH_PREFIX}/presence", headers={
        "Authorization": f"Bearer {issued.proof_key}", "X-Forwarded-For": V4},
        content=json.dumps({"interface_addresses": [V4, V6]}))
    assert presence.status_code == 204

    stop = threading.Event()
    worker = threading.Thread(target=serve_the_queue, args=(ours, stop))
    worker.start()
    try:
        via_api = a_pass(theirs, through_the_api(client, issued))
    finally:
        stop.set()
        worker.join()
    assert [o.measured for o in via_api] == [True, True]

    # The same pass over "ssh", its snapshot allowing what ours allowed.
    authz.revoke(theirs, V6)
    via_ssh = a_pass(theirs, Far().factory)

    for api, ssh in zip(via_api, via_ssh):
        assert api.run.vantage == ssh.run.vantage
        assert rows(theirs, api.run) == rows(theirs, ssh.run)
    stored = rows(theirs, via_api[0].run)
    assert {r[3] for r in stored if r[1] == V4} == {prober.STATE_CONNECTED}
    assert {(r[3], r[4]) for r in stored if r[1] == V6} == {
        (prober.STATE_NOT_TESTED, prober.REASON_NO_AUTHORIZATION)}


def test_a_revoked_key_stops_both_vantages_for_the_pass(two_sides):
    ours, theirs, issued, client = two_sides
    vantages_cli._sync_api(theirs, environ={
        dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_API_KEY_ENV: issued.api_key},
        opener=ThroughTheIngest(client))
    con = db.connect(ours)
    instances.revoke(con, "freedom")
    con.close()
    outcomes = a_pass(theirs, through_the_api(client, issued))
    assert [o.measured for o in outcomes] == [False, False]
    assert all("unknown_key" in o.failure for o in outcomes)
    assert prober.latest_run(theirs, store.list_hosts(theirs)[0]["id"]) is None


# ============================================================ sync_from_api

@pytest.fixture()
def registry():
    con = db.connect(":memory:")
    for module in (db, vantages):
        module.init(con)
    yield con
    con.close()


def listing(*entries):
    return [{"name": n, "enabled": e, "addresses": a} for n, e, a in entries]


def test_sync_makes_the_registry_exactly_the_listing(registry):
    vantages.add(registry, "probe1", "probe1", [PROBE1_V4])
    vantages.add(registry, "old", "old", [OTHER_V4])
    changes = vantages.sync_from_api(registry, listing(
        ("probe1", True, [PROBE1_V4, "2a05:f480:1400:2015:5400:6ff:fe94:df5"]),
        ("probe2", False, [PROBE2_V4])))
    assert [(v.name, v.destination, v.enabled) for v in vantages.list_all(registry)] == [
        ("probe1", "probe1", True), ("probe2", "probe2", False)]
    assert "removed old, the prober API no longer lists it" in changes
    assert "probe1 has new addresses" in changes
    # A switched-off vantage's address is still never a target.
    assert PROBE2_V4 in vantages.all_addresses(registry)
    assert OTHER_V4 not in vantages.all_addresses(registry)


def test_an_address_can_move_from_one_vantage_to_another(registry):
    vantages.add(registry, "probe1", "probe1", [PROBE1_V4])
    vantages.add(registry, "probe2", "probe2", [PROBE2_V4])
    vantages.sync_from_api(registry, listing(("probe1", True, [PROBE2_V4]),
                                             ("probe2", True, [PROBE1_V4])))
    assert vantages.by_name(registry, "probe1").addresses == (PROBE2_V4,)


def test_a_sync_that_changes_nothing_says_nothing(registry):
    entries = listing(("probe1", True, [PROBE1_V4]))
    vantages.sync_from_api(registry, entries)
    assert vantages.sync_from_api(registry, entries) == []


@pytest.mark.parametrize("bad", [
    "not a list",
    [["probe1"]],
    listing(("Probe1", True, [PROBE1_V4])),
    listing(("probe1", "yes", [PROBE1_V4])),
    listing(("probe1", True, [])),
    listing(("probe1", True, ["10.0.0.1"])),
    listing(("probe1", True, [PROBE1_V4]), ("probe1", True, [PROBE2_V4])),
    listing(("probe1", True, [PROBE1_V4]), ("probe2", True, [PROBE1_V4])),
    listing(("probe1", True, [PROBE1_V4]), ("-x", True, [PROBE2_V4])),
])
def test_one_bad_entry_changes_nothing(registry, bad):
    vantages.add(registry, "probe1", "probe1", [PROBE1_V4])
    before = vantages.list_all(registry)
    with pytest.raises(vantages.VantageError):
        vantages.sync_from_api(registry, bad)
    assert vantages.list_all(registry) == before


# ================================================= the install command

PROOF = "whpp_" + "0123456789abcdef" * 4


def test_the_proof_key_shape_is_the_one_instances_issue():
    assert dispatch.PROOF_KEY_RE.fullmatch(instances.new_key(instances.KIND_PROOF))
    assert not dispatch.PROOF_KEY_RE.fullmatch(instances.new_key(instances.KIND_API))


def test_with_both_settings_the_agent_is_told_where_to_prove():
    flags = dispatch.prober_enroll_flags({dispatch.PROBER_API_ENV: BASE + "/",
                                          dispatch.PROBER_PROOF_KEY_ENV: PROOF})
    assert flags == f" --prober-server={BASE} --prober-proof-key={PROOF}"


@pytest.mark.parametrize("environ", [
    {},
    {dispatch.PROBER_API_ENV: BASE},
    {dispatch.PROBER_PROOF_KEY_ENV: PROOF},
    {dispatch.PROBER_API_ENV: "http://app.whichports.com",
     dispatch.PROBER_PROOF_KEY_ENV: PROOF},
    {dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_PROOF_KEY_ENV: KEY},
    {dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_PROOF_KEY_ENV: PROOF + ";id"},
    {dispatch.PROBER_API_ENV: BASE, dispatch.PROBER_PROOF_KEY_ENV: "whpp_ $(id)"},
    {dispatch.PROBER_API_ENV: "https://a.test$(id)",
     dispatch.PROBER_PROOF_KEY_ENV: PROOF},
])
def test_anything_less_than_both_right_adds_nothing_to_a_root_shell_line(environ):
    assert dispatch.prober_enroll_flags(environ) == ""


def test_our_own_install_command_is_unchanged_with_nothing_set(monkeypatch):
    for name in (dispatch.PROBER_API_ENV, dispatch.PROBER_PROOF_KEY_ENV):
        monkeypatch.delenv(name, raising=False)
    assert ingest._install_commands("whp_x")["install_command"] == (
        "curl -fsSL https://get.whichports.com/install.sh | sudo sh -s --"
        " enroll --server=https://app.whichports.com"
        " --credential=whp_x")


def test_every_flag_on_the_install_command_is_one_the_installer_passes_on(monkeypatch):
    """The line is built here and run by `agent/packaging/install.sh`, which
    refuses every argument it does not know before it fetches anything. So a
    flag added to this line and not to the installer is a command the Add
    server window hands out and no server can run. The installer's own list
    is read from its source, the `--name=?*)` cases of its argument check,
    and the fullest line this control plane can build is held to it."""
    import pathlib
    import re
    installer = (pathlib.Path(__file__).resolve().parents[2]
                 / "agent" / "packaging" / "install.sh").read_text()
    accepted = set(re.findall(r"--([a-z-]+)=\?\*", installer))
    assert {"server", "credential"} <= accepted, (
        f"read only {sorted(accepted)} from install.sh, so this reader no "
        "longer matches the script")

    monkeypatch.setenv(dispatch.PROBER_API_ENV, BASE)
    monkeypatch.setenv(dispatch.PROBER_PROOF_KEY_ENV, PROOF)
    command = ingest._install_commands("whp_x")["install_command"]
    download, pipe, arguments = command.partition(" | sudo sh -s -- ")
    assert pipe, command
    assert download == "curl -fsSL https://get.whichports.com/install.sh"
    words = arguments.split(" ")
    assert words[0] == "enroll"
    for word in words[1:]:
        # The installer takes `--name=value` as one word and nothing else.
        assert re.fullmatch(r"--[a-z-]+=\S+", word), word
    used = {word[2:].split("=", 1)[0] for word in words[1:]}
    assert used <= accepted, f"{sorted(used - accepted)} would be refused by install.sh"
    assert used == {"server", "credential", "prober-server", "prober-proof-key"}


def test_an_instance_on_our_api_hands_its_servers_the_proof_key(monkeypatch):
    monkeypatch.setenv(dispatch.PROBER_API_ENV, BASE)
    monkeypatch.setenv(dispatch.PROBER_PROOF_KEY_ENV, PROOF)
    command = ingest._install_commands("whp_x")["install_command"]
    # The two flags are the last thing on the line: nothing follows the pipe.
    assert command.endswith(
        f" --credential=whp_x --prober-server={BASE} --prober-proof-key={PROOF}")
    # The API key never goes onto a server.
    monkeypatch.setenv(dispatch.PROBER_API_KEY_ENV, KEY)
    assert KEY not in ingest._install_commands("whp_x")["install_command"]
