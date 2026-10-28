"""The beta list's route, storage and CLI.

The one route a stranger can write through, so the tests go at it the way a
stranger would: malformed, oversized, twice, in a burst, and in both content
types. Every address here is on a reserved example domain (RFC 2606). No
fixture and no test may hold a real one.
"""
import json
import logging
import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import (betasignup, betasignup_cli, betasignup_routes, db, ingest,
                 notify, ratelimit)

LANDING = "https://whichports.example"
PATH = betasignup_routes.PATH
FORM = {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture()
def database(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv(db.DB_ENV, str(path))
    return path


@pytest.fixture()
def mails(monkeypatch):
    """Every operator mail that would have gone out, and a relay configured
    so one can."""
    sent = []
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", "operator@example.net")
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example.net")
    monkeypatch.setattr(notify, "send",
                        lambda subject, body, config, html=None:
                        (sent.append((subject, body, config.to)) or (True, "")))
    return sent


def make_app(peer_is_loopback=lambda client: True):
    """The route on an application of its own, with its own buckets, and a
    connection that counts as coming from our proxy unless a test says not."""
    app = FastAPI()
    app.state.limiters = ratelimit.Limiters()
    app.include_router(betasignup_routes.build_router(peer_is_loopback))
    return app


@pytest.fixture()
def on(database, mails, monkeypatch):
    monkeypatch.setenv(betasignup.LANDING_ENV, LANDING)
    app = make_app()
    client = TestClient(app, follow_redirects=False)
    client.app_under_test = app
    return client


def rows(database):
    con = sqlite3.connect(database)
    con.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in con.execute(
            "SELECT * FROM beta_signups ORDER BY created_at, email")]
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()


def join(client, email="ann@example.org", servers=None, **headers):
    payload = {"email": email}
    if servers is not None:
        payload["servers"] = servers
    return client.post(PATH, json=payload, headers=headers)


# ------------------------------------------------------------ off by default

@pytest.mark.parametrize("kwargs", [
    {"json": {"email": "ann@example.org"}},
    {"content": "email=ann%40example.org", "headers": FORM},
])
def test_off_unless_the_landing_address_is_set(database, monkeypatch, kwargs):
    """A self-hosted instance serves this code and never sets it, so it never
    collects an address."""
    monkeypatch.delenv(betasignup.LANDING_ENV, raising=False)
    resp = TestClient(make_app()).post(PATH, **kwargs)
    assert resp.status_code == 404
    assert rows(database) == []


def test_the_real_application_carries_the_route_and_it_is_off(database, monkeypatch):
    monkeypatch.delenv(betasignup.LANDING_ENV, raising=False)
    assert TestClient(ingest.app).post(
        PATH, json={"email": "ann@example.org"}).status_code == 404
    monkeypatch.setenv(betasignup.LANDING_ENV, LANDING)
    monkeypatch.setattr(ingest.app.state, "limiters", ratelimit.Limiters())
    assert TestClient(ingest.app).post(
        PATH, json={"email": "ann@example.org"}).status_code == 200


def test_a_malformed_landing_address_is_off_and_says_so_in_the_log(
        database, monkeypatch, caplog):
    monkeypatch.setenv(betasignup.LANDING_ENV, "http://whichports.example")
    with caplog.at_level(logging.ERROR, logger="app.betasignup_routes"):
        resp = TestClient(make_app()).post(PATH, json={"email": "ann@example.org"})
    assert resp.status_code == 404
    assert any(betasignup.LANDING_ENV in r.getMessage() for r in caplog.records)
    assert rows(database) == []


@pytest.mark.parametrize("value,expected", [
    ("https://whichports.example", "https://whichports.example"),
    ("https://whichports.example/", "https://whichports.example"),
    ("", None), ("   ", None),
])
def test_landing_accepted(value, expected):
    assert betasignup.landing({betasignup.LANDING_ENV: value}) == expected


@pytest.mark.parametrize("value", [
    "http://whichports.example", "whichports.example",
    "https://whichports.example/beta", "https://whichports.example/?x=1",
    "https://user:pw@whichports.example", "https://whichports.example/#x",
    "https://whichports.example evil", "javascript:alert(1)",
])
def test_landing_refused(value):
    with pytest.raises(betasignup.LandingMisconfigured):
        betasignup.landing({betasignup.LANDING_ENV: value})


# ------------------------------------------------------------------ joining

def test_a_json_join_is_stored_lowercased_with_its_size(on, database):
    resp = join(on, "  Ann.Smith+Beta@Example.ORG ", "6-20")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert resp.headers["cache-control"] == "no-store"
    (row,) = rows(database)
    assert row["email"] == "ann.smith+beta@example.org"
    assert row["servers"] == "6-20"
    assert row["created_at"].endswith("+00:00")


def test_the_table_holds_three_things_and_nothing_about_the_client(on, database):
    join(on, "ann@example.org", "1-5",
         **{"CF-Connecting-IP": "198.51.100.77", "X-Forwarded-For": "198.51.100.78",
            "User-Agent": "a-very-particular-browser"})
    (row,) = rows(database)
    assert set(row) == {"email", "servers", "created_at"}
    stored = database.read_bytes()
    for leaked in (b"198.51.100.77", b"198.51.100.78", b"a-very-particular-browser"):
        assert leaked not in stored


def test_nothing_else_in_the_body_is_read_or_stored(on, database):
    resp = on.post(PATH, json={"email": "ann@example.org", "servers": "1-5",
                               "name": "Ann Smith", "note": "free text here",
                               "company": {"nested": True}})
    assert resp.status_code == 200
    (row,) = rows(database)
    assert set(row) == {"email", "servers", "created_at"}
    assert b"free text here" not in database.read_bytes()
    assert b"Ann Smith" not in database.read_bytes()


@pytest.mark.parametrize("servers", list(betasignup.BUCKETS))
def test_each_of_the_four_sizes(on, database, servers):
    assert join(on, "ann@example.org", servers).status_code == 200
    assert rows(database)[0]["servers"] == servers


@pytest.mark.parametrize("servers", [None, "", "   "])
def test_no_size_is_fine(on, database, servers):
    assert join(on, "ann@example.org", servers).status_code == 200
    assert rows(database)[0]["servers"] is None


def test_the_sizes_are_the_four_and_only_those():
    assert betasignup.BUCKETS == ("1-5", "6-20", "21-100", "100+")


# ---------------------------------------------------------------- duplicates

def test_joining_twice_is_the_same_answer_and_the_first_row_stays(on, database, mails):
    first = join(on, "ann@example.org", "1-5")
    second = join(on, "ANN@example.org", "100+")
    assert (first.status_code, first.content) == (second.status_code, second.content)
    assert dict(first.headers) == dict(second.headers)
    (row,) = rows(database)
    assert row["servers"] == "1-5", "a second submit must not rewrite the row"
    assert len(mails) == 1, "and tells the operator nothing new"


def test_joining_twice_by_form_is_the_same_redirect(on, database):
    first = on.post(PATH, content="email=ann%40example.org", headers=FORM)
    second = on.post(PATH, content="email=ann%40example.org", headers=FORM)
    assert first.status_code == second.status_code == 303
    assert first.headers["location"] == second.headers["location"]
    assert len(rows(database)) == 1


# ------------------------------------------------------------- content types

def test_a_plain_form_post_goes_back_to_the_landing_page_joined(on, database):
    resp = on.post(PATH, content="email=ann%40example.org&servers=21-100",
                   headers=FORM)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"{LANDING}/#beta-joined"
    (row,) = rows(database)
    assert (row["email"], row["servers"]) == ("ann@example.org", "21-100")


def test_a_form_post_that_asks_for_json_gets_json(on):
    resp = on.post(PATH, content="email=ann%40example.org",
                   headers={**FORM, "Accept": "application/json"})
    assert resp.status_code == 200 and resp.json() == {"ok": True}


def test_a_form_post_with_a_charset_is_still_a_form(on, database):
    resp = on.post(PATH, content="email=ann%40example.org", headers={
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    assert resp.status_code == 303
    assert len(rows(database)) == 1


def test_the_redirect_never_goes_where_the_request_says(on):
    """The landing address is configuration. A Host header, a next field or
    a Referer change nothing."""
    resp = on.post(PATH, content="email=ann%40example.org&next=https://evil.example/",
                   headers={**FORM, "Host": "evil.example",
                            "Referer": "https://evil.example/"})
    assert resp.headers["location"] == f"{LANDING}/#beta-joined"


@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_only_post(on, method):
    assert getattr(on, method)(PATH).status_code == 405


# ------------------------------------------------------------ invalid email

BAD_EMAILS = [
    "", "   ", "plain", "a@b", "a@b.", "@example.org", "ann@", "ann@@example.org",
    "a b@example.org", "ann@exa mple.org", "ann@-mail.example.org", "ann@mail-.example.org",
    "ann@example.123", "a..b@example.org", ".ann@example.org", "ann.@example.org",
    "ann@example..org", "ann@.example.org", "jörg@example.org", "ann@exämple.org",
    "ann@[192.0.2.1]", "ann@192.0.2.1", '"ann smith"@example.org',
    "ann@example.org\nBcc: other@example.org", "ann\r\n@example.org",
    "<script>@example.org", "ann@example.org,bob@example.org",
    "ann@example.org;bob@example.org", "ann@exam_ple.org",
    "a" * 65 + "@example.org", "ann@" + "a" * 64 + ".org",
    "a" * 60 + "@" + ".".join(["b" * 60] * 3) + ".example.org",
]


@pytest.mark.parametrize("email", BAD_EMAILS)
def test_an_address_that_does_not_look_right(on, database, email):
    resp = join(on, email)
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_email"}
    assert rows(database) == []


@pytest.mark.parametrize("email", [None, 5, True, ["ann@example.org"],
                                   {"address": "ann@example.org"}])
def test_an_address_that_is_not_text(on, database, email):
    resp = on.post(PATH, json={"email": email})
    assert resp.status_code == 400 and resp.json() == {"error": "invalid_email"}
    assert rows(database) == []


def test_no_address_at_all(on):
    assert on.post(PATH, json={}).json() == {"error": "invalid_email"}
    assert on.post(PATH, json={"servers": "1-5"}).json() == {"error": "invalid_email"}


@pytest.mark.parametrize("email", [
    "ann@example.org", "a@mail.example.org", "ann.smith+tag@sub.example.org",
    "o'brien@example.org", "ann_smith-1@example.org", "ann@xn--exmple-cua.example",
    "a" * 64 + "@example.org", "ann@" + "a" * 63 + ".org",
])
def test_an_address_that_does(on, database, email):
    assert join(on, email).status_code == 200
    assert rows(database)[0]["email"] == email.lower()


def test_space_around_an_address_is_trimmed_and_never_stored(on, database):
    assert join(on, "\t ann@example.org\r\n").status_code == 200
    assert rows(database)[0]["email"] == "ann@example.org"


# The longest address there is: a 64 character local part and a 189 character
# domain, 254 in all.
LONGEST = "a" * 64 + "@" + "b" * 63 + "." + "b" * 63 + "." + "b" * 57 + ".org"


def test_the_length_boundary_is_254():
    assert len(LONGEST) == 254
    assert betasignup.normalise_email(LONGEST) == LONGEST
    one_more = "a" * 64 + "@" + "b" * 63 + "." + "b" * 63 + "." + "b" * 58 + ".org"
    assert len(one_more) == 255
    with pytest.raises(betasignup.InvalidEmail):
        betasignup.normalise_email(one_more)


def test_an_invalid_address_by_form_goes_back_invalid(on, database):
    resp = on.post(PATH, content="email=not-an-address", headers=FORM)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"{LANDING}/#beta-invalid"
    assert rows(database) == []


# ------------------------------------------------------------ the wrong size

@pytest.mark.parametrize("servers", ["1 to 5", "More than 100", "5", "100",
                                     "1-6", "many", "1-5; DROP TABLE", "0",
                                     5, True, ["1-5"], {"n": 5}])
def test_a_size_that_is_not_one_of_the_four(on, database, servers):
    resp = on.post(PATH, json={"email": "ann@example.org", "servers": servers})
    assert resp.status_code == 400
    assert resp.json() == {"error": "invalid_servers"}
    assert rows(database) == [], "a wrong size is not stored as no size"


# ----------------------------------------------------------------- malformed

@pytest.mark.parametrize("kwargs", [
    {"content": "{not json", "headers": {"Content-Type": "application/json"}},
    {"content": "[]", "headers": {"Content-Type": "application/json"}},
    {"content": '"ann@example.org"', "headers": {"Content-Type": "application/json"}},
    {"content": b"\xff\xfe\x00", "headers": {"Content-Type": "application/json"}},
    {"content": b"email=\xff\xfe", "headers": FORM},
    {"content": "email=a%40example.org&email=b%40example.org", "headers": FORM},
    {"content": "email=a%40example.org&servers=1-5&servers=100%2B", "headers": FORM},
    {"content": "&".join(f"f{i}=x" for i in range(20)), "headers": FORM},
    {"content": "email=ann@example.org", "headers": {"Content-Type": "text/plain"}},
    {"content": "email=ann@example.org", "headers": {
        "Content-Type": "multipart/form-data; boundary=x"}},
    {"content": ""},
])
def test_a_body_that_is_not_one_of_the_two_shapes(on, database, kwargs):
    headers = {**kwargs.get("headers", {}), "Accept": "application/json"}
    resp = on.post(PATH, content=kwargs["content"], headers=headers)
    assert resp.status_code == 400
    assert resp.json() == {"error": "malformed_request"}
    assert rows(database) == []


# ----------------------------------------------------------------- oversized

def test_a_body_that_says_it_is_too_large(on, database):
    big = json.dumps({"email": "ann@example.org", "pad": "x" * 5000})
    resp = on.post(PATH, content=big, headers={"Content-Type": "application/json"})
    assert resp.status_code == 413 and resp.json() == {"error": "too_large"}
    assert rows(database) == []


def test_a_body_that_does_not_say_and_is_too_large(on, database):
    """Chunked, so there is no Content-Length to believe: the cap is applied
    while the body is read."""
    def chunks():
        yield b'{"email": "ann@example.org", "pad": "'
        for _ in range(40):
            yield b"x" * 200
        yield b'"}'

    resp = on.post(PATH, content=chunks(),
                   headers={"Content-Type": "application/json"})
    assert resp.status_code == 413 and resp.json() == {"error": "too_large"}
    assert rows(database) == []


def test_the_largest_honest_request_fits(on, database):
    from urllib.parse import urlencode
    # Every character percent-encoded is three bytes, the worst a form does.
    assert 3 * len(LONGEST) + len("email=&servers=21-100") \
        < betasignup_routes.MAX_BODY_BYTES
    resp = on.post(PATH, content=urlencode({"email": LONGEST, "servers": "21-100"}),
                   headers={**FORM, "Accept": "application/json"})
    assert resp.status_code == 200
    assert rows(database)[0]["email"] == LONGEST


def test_too_large_by_form_goes_back_invalid(on):
    resp = on.post(PATH, content="email=" + "x" * 5000, headers=FORM)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"{LANDING}/#beta-invalid"


# -------------------------------------------------------------------- a burst

def test_one_client_in_a_loop_is_slowed_and_another_is_not(on, database):
    one = {"CF-Connecting-IP": "198.51.100.10"}
    answers = [join(on, f"a{i}@example.org", **one).status_code for i in range(8)]
    assert answers == [200] * 5 + [429] * 3
    assert len(rows(database)) == 5, "a refused request stores nothing"
    other = join(on, "other@example.org", **{"CF-Connecting-IP": "198.51.100.11"})
    assert other.status_code == 200


def test_slow_down_says_when_to_come_back(on):
    one = {"CF-Connecting-IP": "198.51.100.10"}
    for i in range(5):
        join(on, f"a{i}@example.org", **one)
    resp = join(on, "late@example.org", **one)
    assert resp.status_code == 429 and resp.json() == {"error": "slow_down"}
    assert 1 <= int(resp.headers["retry-after"]) <= 60


def test_slow_down_by_form_goes_back_slow(on):
    headers = {**FORM, "CF-Connecting-IP": "198.51.100.10"}
    for i in range(5):
        on.post(PATH, content=f"email=a{i}%40example.org", headers=headers)
    resp = on.post(PATH, content="email=late%40example.org", headers=headers)
    assert resp.status_code == 303
    assert resp.headers["location"] == f"{LANDING}/#beta-slow"


def test_invalid_requests_spend_the_allowance_too(on):
    one = {"CF-Connecting-IP": "198.51.100.10"}
    for _ in range(5):
        assert join(on, "nope", **one).status_code == 400
    assert join(on, "ann@example.org", **one).status_code == 429


def test_the_global_bucket_bounds_every_client_together(on, database):
    """The per-client key is a header, and a header can be typed. This is
    the bucket that holds when it is."""
    on.app_under_test.state.limiters.beta_global = ratelimit.TokenBucket(3.0, 0.0)
    answers = [join(on, f"a{i}@example.org",
                    **{"CF-Connecting-IP": f"198.51.100.{i + 1}"}).status_code
               for i in range(6)]
    assert answers == [200] * 3 + [429] * 3
    assert len(rows(database)) == 3


def test_a_refused_client_does_not_spend_the_global_allowance(on):
    limiters = on.app_under_test.state.limiters
    limiters.beta_global = ratelimit.TokenBucket(6.0, 0.0)
    one = {"CF-Connecting-IP": "198.51.100.10"}
    for i in range(20):
        join(on, f"a{i}@example.org", **one)
    assert join(on, "other@example.org",
                **{"CF-Connecting-IP": "198.51.100.11"}).status_code == 200


# ------------------------------------------------------------ the client key

class FakeRequest:
    def __init__(self, peer, headers=()):
        from starlette.datastructures import Address, Headers
        self.client = Address(peer, 1234) if peer else None
        self.headers = Headers(raw=[(k.lower().encode(), v.encode())
                                    for k, v in headers])


def key(peer, headers=(), loopback=True):
    return betasignup_routes.client_key(FakeRequest(peer, headers),
                                        lambda client: loopback)


def test_behind_our_proxy_cloudflares_header_is_the_client():
    assert key("127.0.0.1", [("CF-Connecting-IP", "198.51.100.7"),
                             ("X-Forwarded-For", "203.0.113.9")]) == "198.51.100.7"


def test_without_cloudflare_the_forwarded_address_is_the_client():
    assert key("127.0.0.1", [("X-Forwarded-For", "203.0.113.9")]) == "203.0.113.9"


def test_a_connection_not_from_our_proxy_is_counted_as_itself():
    """Whatever headers it types. Otherwise anybody reaching the port
    directly would pick their own bucket."""
    assert key("198.51.100.200", [("CF-Connecting-IP", "198.51.100.7")],
               loopback=False) == "198.51.100.200"


@pytest.mark.parametrize("headers", [
    [("X-Forwarded-For", "198.51.100.7, 203.0.113.9")],
    [("X-Forwarded-For", "198.51.100.7"), ("X-Forwarded-For", "203.0.113.9")],
    [("CF-Connecting-IP", "not an address")],
    [("CF-Connecting-IP", "198.51.100.7:443")],
])
def test_a_header_that_is_not_one_address_falls_back_to_the_peer(headers):
    assert key("127.0.0.1", headers) == "127.0.0.1"


def test_an_ipv6_client_is_counted_by_its_64():
    a = key("127.0.0.1", [("CF-Connecting-IP", "2001:db8:1:2:aaaa::1")])
    b = key("127.0.0.1", [("CF-Connecting-IP", "2001:db8:1:2:bbbb::2")])
    c = key("127.0.0.1", [("CF-Connecting-IP", "2001:db8:1:3::1")])
    assert a == b == "2001:db8:1:2::/64"
    assert c != a


def test_a_v4_mapped_address_is_its_v4():
    assert key("::ffff:198.51.100.7", loopback=False) == "198.51.100.7"


@pytest.mark.parametrize("peer", [None, "", "testclient", "/run/ingest.sock"])
def test_an_unreadable_peer_shares_one_bucket(peer):
    assert key(peer, loopback=False) == "unknown"


# ------------------------------------------------------------ the log lines

OUTCOMES = {"beta signup: joined", "beta signup: already on the list",
            "beta signup: mail sent", "beta signup: mail not sent",
            "beta signup: no mail, none is configured"} \
    | {f"beta signup: {error}" for error in betasignup_routes.ERRORS}


def test_a_log_line_holds_the_class_of_the_outcome_and_nothing_else(on, caplog):
    one = {"CF-Connecting-IP": "198.51.100.10", "User-Agent": "particular"}
    with caplog.at_level(logging.INFO, logger="app.betasignup_routes"):
        join(on, "ann@example.org", "1-5", **one)
        join(on, "ann@example.org", **one)
        join(on, "not an address", **one)
        join(on, "bob@example.org", "wrong", **one)
        on.post(PATH, content="{", headers={"Content-Type": "application/json", **one})
        on.post(PATH, content="x" * 5000, headers={**FORM, **one})
        join(on, "late@example.org", **one)
    lines = [r.getMessage() for r in caplog.records]
    assert len(lines) >= 7
    for line in lines:
        assert line in OUTCOMES, line
    said = "\n".join(lines)
    for leaked in ("@", "198.51.100.10", "particular", "ann", "wrong"):
        assert leaked not in said


def test_the_refusals_are_a_closed_set():
    assert betasignup_routes.ERRORS == {
        "invalid_email": 400, "invalid_servers": 400, "malformed_request": 400,
        "too_large": 413, "slow_down": 429}


# ------------------------------------------------------- the operator's mail

def test_a_join_mails_the_operator_the_size_and_the_count_only(on, mails):
    join(on, "ann@example.org", "6-20")
    join(on, "bob@example.org")
    assert len(mails) == 2
    subject, body, to = mails[0]
    assert to == "operator@example.net"
    assert subject == "[whichports] The beta list has 1"
    assert "servers:  6-20" in body and "on the list now:  1" in body
    subject, body, _to = mails[1]
    assert subject == "[whichports] The beta list has 2"
    assert "servers:  not said" in body and "on the list now:  2" in body
    for _subject, body, _to in mails:
        assert "ann" not in body and "bob" not in body and "example.org" not in body
        assert "@" not in body


def test_no_mail_for_a_refusal(on, mails):
    join(on, "not an address")
    join(on, "ann@example.org", "wrong")
    assert mails == []


def test_no_relay_means_no_mail_and_the_join_still_counts(on, database, monkeypatch):
    called = []
    monkeypatch.delenv("WHICHPORTS_SMTP_HOST")
    monkeypatch.setattr(notify, "send", lambda *a, **k: called.append(a) or (True, ""))
    assert join(on, "ann@example.org").status_code == 200
    assert called == [] and len(rows(database)) == 1


def test_no_operator_address_means_no_mail(on, database, monkeypatch):
    called = []
    monkeypatch.delenv("WHICHPORTS_ALERT_TO")
    monkeypatch.setattr(notify, "send", lambda *a, **k: called.append(a) or (True, ""))
    assert join(on, "ann@example.org").status_code == 200
    assert called == [] and len(rows(database)) == 1


def test_a_burst_of_joins_is_a_handful_of_mails(on, database, mails):
    limiters = on.app_under_test.state.limiters
    limiters.beta_mail = ratelimit.TokenBucket(2.0, 0.0)
    for i in range(5):
        assert join(on, f"a{i}@example.org",
                    **{"CF-Connecting-IP": f"198.51.100.{i + 1}"}).status_code == 200
    assert len(rows(database)) == 5, "every join is stored"
    assert len(mails) == 2, "and only the first two mailed"


def test_a_relay_that_refuses_does_not_fail_the_join(on, database, monkeypatch):
    monkeypatch.setattr(notify, "send", lambda *a, **k: (False, "relay said no"))
    resp = join(on, "ann@example.org")
    assert resp.status_code == 200 and len(rows(database)) == 1


# -------------------------------------------------------------------- storage

def test_add_says_whether_it_was_new(database):
    con = db.connect()
    betasignup.init(con)
    assert betasignup.add(con, "ann@example.org", "1-5") is True
    assert betasignup.add(con, "ann@example.org", "100+") is False
    assert betasignup.count(con) == 1
    assert betasignup.remove(con, "ann@example.org") is True
    assert betasignup.remove(con, "ann@example.org") is False
    assert betasignup.count(con) == 0
    con.close()


def test_init_twice_is_fine(database):
    con = db.connect()
    betasignup.init(con)
    betasignup.init(con)
    con.close()


# ------------------------------------------------------------------------ CLI

@pytest.fixture()
def listed(on, database):
    join(on, "ann@example.org", "1-5", **{"CF-Connecting-IP": "198.51.100.1"})
    join(on, "bob@example.org", **{"CF-Connecting-IP": "198.51.100.2"})
    return database


def test_cli_count_and_list(listed, capsys):
    assert betasignup_cli.main(["count"]) == 0
    assert capsys.readouterr().out.strip() == "2"
    assert betasignup_cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "ann@example.org" in out and "1-5" in out
    assert "bob@example.org" in out
    assert out.strip().endswith("2 on the list")


def test_cli_remove_takes_one_address_off(listed, capsys):
    assert betasignup_cli.main(["remove", "  ANN@example.org "]) == 0
    assert "1 left on the list" in capsys.readouterr().out
    assert [r["email"] for r in rows(listed)] == ["bob@example.org"]


def test_cli_remove_of_somebody_not_on_it(listed, capsys):
    assert betasignup_cli.main(["remove", "carol@example.org"]) == 1
    assert "no such address" in capsys.readouterr().err
    assert len(rows(listed)) == 2


def test_cli_remove_of_something_that_is_not_an_address(listed, capsys):
    assert betasignup_cli.main(["remove", "% OR 1=1"]) == 1
    assert len(rows(listed)) == 2


def test_a_removed_address_can_join_again(on, listed):
    betasignup_cli.main(["remove", "ann@example.org"])
    assert join(on, "ann@example.org", "100+",
                **{"CF-Connecting-IP": "198.51.100.3"}).status_code == 200
    assert {r["email"]: r["servers"] for r in rows(listed)}["ann@example.org"] == "100+"


def test_cli_refuses_a_database_that_is_not_there(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "absent.db"))
    with pytest.raises(SystemExit):
        betasignup_cli.main(["count"])
    assert not (tmp_path / "absent.db").exists()
