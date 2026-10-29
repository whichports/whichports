"""The open signup's two routes for the installer, and the end of its
collect (`app/instancesignup_routes.py`).

A stranger's way in, so the tests go at it the way a stranger would: off,
closed, full, twice, in a burst, with a typed header, guessing, and by
reading every mail and every journal line for what must never be in one.
Every address is on a reserved example domain (RFC 2606).
"""
import logging
import re
import secrets
import sqlite3
from collections import namedtuple

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import (authz, betasignup, db, ingest, instances, instancesignup,
                 instancesignup_routes, invite, notify, publicurl, ratelimit,
                 web_auth, web_pages)

LANDING = "https://whichports.example"
BASE = "https://app.whichports.example"
PATH = instancesignup_routes.PATH
COLLECT = instancesignup_routes.COLLECT_PATH
DONE = instancesignup_routes.DONE_PATH
ANN = "ann@example.org"
OWNER = "owner@example.net"

Asked = namedtuple("Asked", "status text headers claim")


@pytest.fixture()
def database(tmp_path, monkeypatch):
    path = tmp_path / "test.db"
    monkeypatch.setenv(db.DB_ENV, str(path))
    return path


@pytest.fixture()
def mails(monkeypatch):
    """Every mail that would have gone out, to the person or the owner."""
    sent = []

    def fake_send(subject, body, config=None, html=""):
        sent.append({"subject": subject, "body": body, "html": html,
                     "to": getattr(config, "to", "")})
        return True, ""

    monkeypatch.setattr(notify, "send", fake_send)
    monkeypatch.setenv("WHICHPORTS_SMTP_HOST", "relay.example.net")
    monkeypatch.setenv("WHICHPORTS_ALERT_TO", OWNER)
    return sent


@pytest.fixture()
def on(database, mails, monkeypatch):
    monkeypatch.setenv(betasignup.LANDING_ENV, LANDING)
    monkeypatch.setenv(publicurl.ENV, BASE)
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)
    ingest.app.state.limiters = ratelimit.Limiters()
    return TestClient(ingest.app, follow_redirects=False)


def ask(client, email=ANN, claim=None, **headers):
    """One signup as the installer sends it: the address and a fresh claim."""
    claim = claim or secrets.token_hex(32)
    answer = client.post(PATH, json={"email": email, "claim": claim}, headers=headers)
    return Asked(answer.status_code, answer.text, answer.headers, claim)


def collect(client, claim, code, **headers):
    return client.post(COLLECT, json={"claim": claim, "code": code}, headers=headers)


def done(client, claim):
    return client.post(DONE, json={"claim": claim})


def code_mails(mails):
    return [m for m in mails if m["to"] != OWNER]


def owner_mails(mails):
    return [m for m in mails if m["to"] == OWNER]


def code_of(mail):
    found = re.findall(r"\b[0-9]{8}\b", mail["body"])
    assert len(found) == 1, found
    return found[0]


def signed_up(client, mails, email=ANN):
    """A signup whose code was mailed: its claim and that code."""
    asked = ask(client, email)
    assert asked.text == "sent"
    return asked.claim, code_of(code_mails(mails)[-1])


def instance_rows(database):
    con = sqlite3.connect(database)
    try:
        return con.execute("SELECT name, origin, contact_email, revoked_at"
                           " FROM probe_instances").fetchall()
    except sqlite3.OperationalError:
        return []
    finally:
        con.close()


# =========================================================== off and closed

def test_off_without_the_landing(database, mails, monkeypatch):
    monkeypatch.delenv(betasignup.LANDING_ENV, raising=False)
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    ingest.app.state.limiters = ratelimit.Limiters()
    client = TestClient(ingest.app, follow_redirects=False)
    assert ask(client).status == 404
    assert collect(client, "a" * 64, "12345678").status_code == 404
    assert done(client, "a" * 64).status_code == 404
    assert mails == []


def test_closed_answers_closed_and_mails_nobody(on, mails, monkeypatch, database):
    monkeypatch.setenv(instancesignup.MODE_ENV, "closed")
    asked = ask(on)
    assert (asked.status, asked.text) == (200, "closed")
    assert collect(on, asked.claim, "12345678").text == "closed"
    assert mails == []
    assert instance_rows(database) == []


def test_no_relay_reads_as_closed(on, mails, monkeypatch):
    monkeypatch.delenv("WHICHPORTS_SMTP_HOST", raising=False)
    assert ask(on).text == "closed"
    assert mails == []


@pytest.mark.parametrize("path", [PATH, COLLECT, DONE])
@pytest.mark.parametrize("method", ["get", "put", "delete"])
def test_only_post(on, path, method):
    assert getattr(on, method)(path).status_code == 405


def test_there_is_no_invite_page(on, mails):
    """The code reaches only the mailbox, and only the installer's claim
    collects with it: no page shows a line, and nothing is clicked."""
    assert on.get("/invite").status_code == 404
    assert on.post("/invite", data={"token": "x", "csrf": "y"}).status_code in (404, 405)
    for name in ("INVITE_PATH", "link_for", "FRAGMENTS"):
        assert not hasattr(instancesignup_routes, name), name
    for name in ("invite_page", "invite_submit", "_invite_submit", "_invite_ended"):
        assert not hasattr(web_auth, name), name
    for name in ("invite_page", "invite_line_page", "invite_ended_page", "_TOKEN_SCRIPT"):
        assert not hasattr(web_pages, name), name
    for name in ("redeem", "request_link"):
        assert not hasattr(instancesignup, name), name


# ========================================================== what is refused

@pytest.mark.parametrize("email", ["", "not an address", "a@b", "@example.org",
                                   None, 5, ["ann@example.org"], "ann@-x.example.org",
                                   "a,b@example.org", "admin@[192.0.2.1]"])
def test_an_address_that_does_not_look_right(on, mails, email):
    asked = ask(on, email)
    assert (asked.status, asked.text) == (200, "invalid_email")
    assert mails == []


@pytest.mark.parametrize("claim", ["", "abc", "A" * 64, None, 5, "a" * 64 + "\n"])
def test_a_claim_that_is_not_one_is_malformed(on, mails, claim):
    answer = on.post(PATH, json={"email": ANN, "claim": claim})
    assert (answer.status_code, answer.text) == (400, "malformed_request")
    assert mails == []


@pytest.mark.parametrize("path", [PATH, COLLECT, DONE])
@pytest.mark.parametrize("content,kind", [
    ("email=a%40example.org&claim=" + "a" * 64, "application/x-www-form-urlencoded"),
    ("{not json", "application/json"),
    ("[]", "application/json"),
    ('{"email": "a@example.org"}', "text/plain"),
])
def test_a_body_that_is_not_one_json_object(on, mails, path, content, kind):
    answer = on.post(path, content=content, headers={"Content-Type": kind})
    assert (answer.status_code, answer.text) == (400, "malformed_request")
    assert mails == []


@pytest.mark.parametrize("path", [PATH, COLLECT, DONE])
def test_a_body_too_large(on, path):
    answer = on.post(path, content='{"email": "' + "a" * 4000 + '"}',
                     headers={"Content-Type": "application/json"})
    assert (answer.status_code, answer.text) == (413, "too_large")


def test_every_answer_is_plain_text_and_never_stored(on, mails):
    claim, code = signed_up(on, mails)
    for answer in (on.post(PATH, json={"email": ANN, "claim": "zz"}),
                   collect(on, claim, "00000000"), collect(on, claim, code),
                   done(on, claim)):
        assert answer.headers["content-type"].startswith("text/plain")
        assert answer.headers["cache-control"] == "no-store"
        assert "\n" not in answer.text


# ============================================ the same answer, whoever asks

def test_same_answer_for_new_waiting_and_instance_address(on, mails, database):
    first, second = ask(on), ask(on)
    assert (first.status, first.text) == (200, "sent")
    assert (second.status, second.text) == (200, "sent")
    assert len(code_mails(mails)) == 1
    assert collect(on, first.claim, code_of(code_mails(mails)[0])).text.startswith(
        invite.PREFIX)
    third = ask(on)
    assert (third.status, third.text) == (200, "sent")
    assert len(code_mails(mails)) == 1


# ================================================================ the limits

def make_app(peer_is_loopback):
    app = FastAPI()
    app.state.limiters = ratelimit.Limiters()
    app.include_router(instancesignup_routes.build_router(peer_is_loopback))
    return app


@pytest.fixture()
def plain(database, mails, monkeypatch):
    monkeypatch.setenv(betasignup.LANDING_ENV, LANDING)
    monkeypatch.setenv(publicurl.ENV, BASE)
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)


def test_slow_down_per_client(plain):
    client = TestClient(make_app(lambda c: True))
    headers = {"X-Forwarded-For": "203.0.113.7"}
    answers = [ask(client, f"p{n}@example.org", **headers)
               for n in range(int(ratelimit.SIGNUP_CLIENT_CAPACITY) + 1)]
    assert [a.status for a in answers[:-1]] == [200] * int(ratelimit.SIGNUP_CLIENT_CAPACITY)
    assert (answers[-1].status, answers[-1].text) == (429, "slow_down")
    assert int(answers[-1].headers["Retry-After"]) >= 1
    # Another client is not held back by the first one's count.
    assert ask(client, "q@example.org", **{"X-Forwarded-For": "203.0.113.8"}).status == 200


def test_client_key_ignores_a_typed_header(plain):
    """A connection that is not from our proxy on loopback is counted by its
    own peer, whatever header it typed, so a fresh header each time buys no
    fresh count."""
    client = TestClient(make_app(lambda c: False))
    answers = [ask(client, f"p{n}@example.org",
                   **{"CF-Connecting-IP": f"203.0.113.{n + 1}",
                      "X-Forwarded-For": f"198.51.100.{n + 1}"})
               for n in range(int(ratelimit.SIGNUP_CLIENT_CAPACITY) + 1)]
    assert answers[-1].status == 429


def test_the_collect_bucket_lets_a_person_retype(plain, mails):
    """Five wrong codes, the right one and done, from one client, are never
    slowed, and spend nothing of the signup's own count. The bucket ends a
    guesser's burst at ten."""
    client = TestClient(make_app(lambda c: True))
    headers = {"X-Forwarded-For": "203.0.113.9"}
    claim, code = signed_up(client, mails)
    for _ in range(instancesignup.WRONG_CODES_PER_CLAIM - 1):
        assert collect(client, claim, other_than(code), **headers).text == "wrong"
    assert collect(client, claim, code, **headers).text.startswith(invite.PREFIX)
    assert client.post(DONE, json={"claim": claim}, headers=headers).text == "done"
    used = instancesignup.WRONG_CODES_PER_CLAIM + 1
    for _ in range(int(ratelimit.COLLECT_CLIENT_CAPACITY) - used):
        assert collect(client, claim, "00000000", **headers).status_code == 200
    slowed = collect(client, claim, "00000000", **headers)
    assert (slowed.status_code, slowed.text) == (429, "slow_down")
    assert int(slowed.headers["Retry-After"]) >= 1
    # The signup's count is the signup's: the collects spent none of it.
    for n in range(int(ratelimit.SIGNUP_CLIENT_CAPACITY) - 1):
        assert ask(client, f"r{n}@example.org", **headers).status == 200
    assert ratelimit.COLLECT_CLIENT_CAPACITY == 10
    assert ratelimit.COLLECT_CLIENT_REFILL_PER_SECOND == 1 / 10


def test_collect_and_done_have_a_bucket_in_all(plain, monkeypatch):
    """Past ten thousand clients the per-client count forgets the oldest,
    so a crowd of addresses is held by one count in all, as every other
    route a stranger reaches is."""
    monkeypatch.setattr(ratelimit, "COLLECT_GLOBAL_CAPACITY", 3)
    client = TestClient(make_app(lambda c: True))
    answers = [client.post(COLLECT, json={"claim": "a" * 64, "code": "12345678"},
                           headers={"X-Forwarded-For": f"203.0.113.{n + 1}"}).status_code
               for n in range(3)]
    assert answers == [200, 200, 200]
    over = client.post(DONE, json={"claim": "a" * 64},
                       headers={"X-Forwarded-For": "203.0.113.99"})
    assert (over.status_code, over.text) == (429, "slow_down")
    assert ratelimit.COLLECT_GLOBAL_CAPACITY == 3
    monkeypatch.undo()
    assert (ratelimit.COLLECT_GLOBAL_CAPACITY, ratelimit.COLLECT_GLOBAL_REFILL_PER_SECOND) == (300, 1)


def other_than(code):
    return f"{(int(code) + 1) % 10 ** 8:08d}"


def test_spent_cap_answers_full_and_mails_him_once(on, mails, monkeypatch):
    monkeypatch.setattr(instancesignup, "SIGNUPS_PER_DAY", 2)
    assert ask(on, "a@example.org").text == "sent"
    assert ask(on, "b@example.org").text == "sent"
    full = ask(on, "c@example.org")
    assert (full.status, full.text) == (200, "full_today")
    assert ask(on, "d@example.org").text == "full_today"
    told = owner_mails(mails)
    assert len(told) == 1
    assert "full" in told[0]["subject"]
    assert "signups today:           2" in told[0]["body"]
    assert "@" not in told[0]["body"]
    assert len(code_mails(mails)) == 2


# ================================================================== the mail

def test_the_mail_carries_the_code_and_no_link(on, mails):
    ask(on)
    mail = code_mails(mails)[0]
    assert mail["to"] == ANN
    code = code_of(mail)
    assert code in mail["html"]
    for words in (mail["body"], mail["html"]):
        assert "http" not in words.replace("http://www.w3.org", "")
        assert "<a " not in words and "href" not in words
    assert mail["body"].count("\n") <= 1


def test_the_mail_says_how_long_the_code_works(on, mails):
    from datetime import timedelta
    assert instancesignup.CODE_TTL == timedelta(hours=24)
    assert notify.SIGNUP_CODE_LASTS == "24 hours"
    ask(on)
    assert "24 hours" in code_mails(mails)[0]["body"]


def test_no_key_in_any_mail(on, mails):
    claim, code = signed_up(on, mails)
    line = collect(on, claim, code).text
    parts = invite.split(line)
    for mail in mails:
        for key in (parts[invite.PROBER_API_KEY_ENV], parts[invite.PROBER_PROOF_KEY_ENV]):
            assert key not in mail["body"] and key not in mail["html"]
        assert "whpi_" not in mail["body"] and "whpp_" not in mail["body"]


def test_no_address_claim_code_or_key_in_any_log_line(on, mails, caplog, capfd):
    with caplog.at_level(logging.DEBUG):
        claim, code = signed_up(on, mails)
        ask(on)
        collect(on, claim, other_than(code))
        line = collect(on, claim, code).text
        again = collect(on, claim, code).text
        done(on, claim)
        ask(on, "nope")
    printed = capfd.readouterr()
    journal = "\n".join(r.getMessage() for r in caplog.records) + printed.out + printed.err
    assert "instance signup" in journal
    for secret in (ANN, "example.org", claim, code, line, again, line.split("_")[-1]):
        assert secret not in journal, secret


# =============================================================== the collect

def test_collect_answers_the_invite_line_as_plain_text(on, mails, database):
    claim, code = signed_up(on, mails)
    answer = collect(on, claim, code)
    assert answer.status_code == 200
    line = answer.text
    parts = invite.split(line)
    assert line == line.strip()
    assert parts[invite.PROBER_API_ENV] == BASE
    rows = instance_rows(database)
    assert len(rows) == 1
    name, origin, contact, revoked = rows[0]
    assert (origin, contact, revoked) == (authz.ORIGIN_SIGNUP, ANN, None)
    # The keys work, and only their hashes are stored.
    con = db.connect()
    try:
        made = instances.instance_for_key(con, parts[invite.PROBER_API_KEY_ENV],
                                          instances.KIND_API)
        assert made is not None and made.name == name
        stored = " ".join(str(v) for row in con.execute(
            "SELECT * FROM probe_instance_keys") for v in tuple(row))
        assert parts[invite.PROBER_API_KEY_ENV] not in stored
    finally:
        con.close()
    # Ended by done: nothing more comes for this claim.
    assert done(on, claim).text == "done"
    assert collect(on, claim, code).text == "wrong"
    assert len(instance_rows(database)) == 1


def test_a_recollect_answers_a_new_line_and_ends_the_first(on, mails, database):
    claim, code = signed_up(on, mails)
    first = invite.split(collect(on, claim, code).text)
    second = invite.split(collect(on, claim, code).text)
    assert first[invite.PROBER_API_KEY_ENV] != second[invite.PROBER_API_KEY_ENV]
    con = db.connect()
    try:
        assert instances.instance_for_key(con, first[invite.PROBER_API_KEY_ENV],
                                          instances.KIND_API) is None
        assert instances.instance_for_key(con, second[invite.PROBER_API_KEY_ENV],
                                          instances.KIND_API) is not None
    finally:
        con.close()
    assert len(instance_rows(database)) == 1


def test_every_failure_to_collect_answers_wrong(on, mails):
    claim, code = signed_up(on, mails)
    for answer in (collect(on, claim, other_than(code)),
                   collect(on, secrets.token_hex(32), code),
                   collect(on, claim, "1234"),
                   collect(on, claim, None),
                   collect(on, "nope", code),
                   on.post(COLLECT, json={"claim": claim})):
        assert (answer.status_code, answer.text) == (200, "wrong")


def test_the_owner_is_mailed_per_new_instance_without_the_address(on, mails):
    claim, code = signed_up(on, mails)
    collect(on, claim, code)
    collect(on, claim, code)
    told = owner_mails(mails)
    assert len(told) == 1
    assert told[0]["subject"] == "[whichports] An instance signed up"
    assert "live signup instances:  1" in told[0]["body"]
    assert ANN not in told[0]["body"] and "signup-" not in told[0]["body"]


def test_done_answers_done_for_any_claim(on, mails):
    for claim in ("a" * 64, secrets.token_hex(32)):
        answer = done(on, claim)
        assert (answer.status_code, answer.text) == (200, "done")


def test_a_spent_live_cap_is_one_plain_refusal(on, mails, database, monkeypatch):
    """No day ends it, so nothing says tomorrow, and nothing promises a place
    in a line."""
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1)
    claim, code = signed_up(on, mails)
    collect(on, claim, code)
    assert ask(on, "b@example.org").text == "full"


def test_the_owner_hears_full_and_not_tomorrow_when_the_live_cap_is_spent(
        on, mails, monkeypatch):
    """The live cap clears when an instance is revoked, not at midnight, so
    the owner's mail must not tell him it ends tomorrow."""
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1)
    claim, code = signed_up(on, mails)
    collect(on, claim, code)
    assert ask(on, "b@example.org").text == "full"
    told = [m for m in owner_mails(mails) if "full" in m["subject"].lower()]
    assert len(told) == 1
    # The subject and the sentence. The counts under them are today's and
    # say so, which is true.
    said = (told[0]["subject"] + " " + told[0]["body"].splitlines()[0]).lower()
    assert "today" not in said and "tomorrow" not in said
    assert "live signup instances:   1" in told[0]["body"]


def test_the_owner_hears_full_today_when_a_day_cap_is_spent(on, mails, monkeypatch):
    monkeypatch.setattr(instancesignup, "SIGNUPS_PER_DAY", 1)
    ask(on)
    assert ask(on, "b@example.org").text == "full_today"
    told = [m for m in owner_mails(mails) if "full" in m["subject"].lower()]
    assert len(told) == 1
    assert "today" in told[0]["subject"].lower()
    assert "tomorrow" in told[0]["body"].lower()


def test_the_sweep_ends_an_unused_signup_instance_and_tells_its_address_once(
        on, mails, database, capsys):
    from datetime import datetime, timedelta, timezone
    from app import sweep_cli
    claim, code = signed_up(on, mails)
    collect(on, claim, code)
    long_ago = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
    con = sqlite3.connect(database)
    con.execute("UPDATE probe_instances SET created_at = ?", (long_ago,))
    con.commit()
    con.close()
    before = len(code_mails(mails))
    assert sweep_cli.main([]) == 0
    told = code_mails(mails)[before:]
    assert [m["to"] for m in told] == [ANN]
    assert "ended" in told[0]["subject"].lower()
    assert f"{LANDING}/#docs-install" in told[0]["body"]
    assert [row[3] is not None for row in instance_rows(database)] == [True]
    out = capsys.readouterr()
    assert "1 unused instances ended" in out.out
    assert ANN not in out.out + out.err
    # The next sweep tells nobody again.
    assert sweep_cli.main([]) == 0
    assert code_mails(mails)[before + 1:] == []


def test_collect_when_closed_or_full_issues_nothing(on, mails, database, monkeypatch):
    claim, code = signed_up(on, mails)
    monkeypatch.setenv(instancesignup.MODE_ENV, "closed")
    assert collect(on, claim, code).text == "closed"
    monkeypatch.setenv(instancesignup.MODE_ENV, "open")
    monkeypatch.setattr(instancesignup, "INSTANCES_PER_DAY", 0)
    assert collect(on, claim, code).text == "full_today"
    assert instance_rows(database) == []
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 0)
    assert collect(on, claim, code).text == "full"
    monkeypatch.setattr(instancesignup, "LIVE_SIGNUP_INSTANCES", 1000)
    monkeypatch.setattr(instancesignup, "INSTANCES_PER_DAY", 10)
    assert collect(on, claim, code).text.startswith(invite.PREFIX)


def test_nothing_is_made_when_our_own_address_is_not_one(on, mails, database, monkeypatch):
    """An instance whose line could not be written would be an instance
    nobody holds a key of."""
    claim, code = signed_up(on, mails)
    monkeypatch.setenv(publicurl.ENV, "http://not-https.example")
    assert collect(on, claim, code).text == "closed"
    assert instance_rows(database) == []
    monkeypatch.setenv(publicurl.ENV, BASE)
    assert collect(on, claim, code).text.startswith(invite.PREFIX)
