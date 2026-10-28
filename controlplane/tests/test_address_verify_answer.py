"""What the verify route answers, for the window that adds an address
(docs/RECORD.md 4.375, 4.379).

    Run from controlplane/: python -m pytest tests/test_address_verify_answer.py

The registry's sentence for a recorded proof names the way by its code word,
`authorised by http_token`. A person reads the window, so the answer carries
two things beside `ok`: the registry's typed code, which the window acts on,
and for a recorded proof the words the address's row will carry, made by the
function the row itself is worded with. A refusal keeps the registry's own
sentence. The route records nothing: `authz.verify_proof` does.
"""
import json

import pytest

from app import authz, db, ingest, renderbridge, store
from tests.test_admin_addresses import (ADDRESS, add_address_host, client,  # noqa: F401
                                        post, signed_in, start)

__all__ = ["client"]

CODE_WORDS = ("http_token", "dns_txt", "http-token", "dns-txt")


def verify(client, challenge, name="outside-only"):
    return post(client, f"/api/admin/hosts/{name}/addresses/{challenge['id']}/verify")


def proved_row(name="outside-only"):
    con = db.connect()
    host = store.active_host_by_name(con, name)
    rows = authz.live_addresses_for_host(con, host["id"])
    con.close()
    return rows


def with_token_file(monkeypatch, body):
    monkeypatch.setattr(authz, "fetch_token_file", lambda url, timeout=0: body)


def test_a_recorded_proof_answers_with_its_code_and_the_rows_words(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    with_token_file(monkeypatch, challenge["token"])
    r = verify(client, challenge)

    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"ok", "code", "detail"}
    assert body["ok"] is True and body["code"] == "proved"
    (row,) = proved_row()
    assert body["detail"] == renderbridge.load().proof_yes_words(row)
    assert body["detail"].startswith(f"{ADDRESS} proved by token file until ")


def test_the_words_name_the_way_as_the_row_does_for_each_method(client, monkeypatch):
    """The token file and the TXT record, each in the word its row uses."""
    render_live = renderbridge.load()
    add_address_host(client)
    challenge = start(client, method="dns-txt").json()
    monkeypatch.setattr(authz.dnstxt, "query_txt", lambda name: [challenge["token"]])
    body = verify(client, challenge).json()

    assert body["ok"] is True, body
    (row,) = proved_row()
    assert row["method"] == "dns_txt"
    assert body["detail"] == f"{ADDRESS} proved by DNS until {render_live.proof_day(row['expires_at'])}"
    # And the row says the same two things: the way and the day.
    assert render_live.proof_status(row, True) == f"proved until {render_live.proof_day(row['expires_at'])}"


def test_a_refusal_answers_with_its_code_and_the_registrys_sentence(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    with_token_file(monkeypatch, "something else")
    body = verify(client, challenge).json()

    assert body["ok"] is False
    assert body["code"] == "token_not_found"
    assert body["detail"] == f"the token was not found at {challenge['publish_at']}"


def test_an_expired_challenge_answers_with_its_code(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    con = db.connect()
    con.execute("UPDATE authz_challenges SET expires_at = '2000-01-01T00:00:00+00:00'"
                " WHERE id = ?", (challenge["id"],))
    con.commit()
    con.close()
    with_token_file(monkeypatch, challenge["token"])
    body = verify(client, challenge).json()

    assert body == {"ok": False, "code": "challenge_expired",
                    "detail": "the challenge expired, start a new one"}


def test_every_code_the_route_answers_is_one_of_the_registrys(client, monkeypatch):
    add_address_host(client)
    seen = set()
    for file_body in ("something else", None):
        challenge = start(client).json()
        with_token_file(monkeypatch, file_body if file_body else challenge["token"])
        seen.add(verify(client, challenge).json()["code"])

    assert seen == {"token_not_found", "proved"}
    assert seen <= authz.PROOF_CODES


def test_no_answer_carries_a_code_word_in_its_sentence(client, monkeypatch):
    add_address_host(client)
    answers = []
    for method in ("http-token", "dns-txt"):
        for good in (False, True):
            challenge = start(client, method=method).json()
            found = challenge["token"] if good else "something else"
            with_token_file(monkeypatch, found)
            monkeypatch.setattr(authz.dnstxt, "query_txt", lambda name, found=found: [found])
            answers.append(verify(client, challenge).json())

    assert [a["ok"] for a in answers] == [False, True, False, True]
    for answer in answers:
        for word in CODE_WORDS:
            assert word not in answer["detail"], answer


def test_the_route_records_nothing_the_registry_did_not(client, monkeypatch):
    """A refused proof leaves no row, and a recorded one leaves exactly the
    one the registry wrote: the answer's words are read from it, never
    written."""
    add_address_host(client)
    challenge = start(client).json()
    with_token_file(monkeypatch, "something else")
    verify(client, challenge)
    assert proved_row() == []

    with_token_file(monkeypatch, challenge["token"])
    verify(client, challenge)
    verify(client, challenge)
    assert [row["target"] for row in proved_row()] == [ADDRESS]


def test_another_workspaces_challenge_gets_no_answer_at_all(client, monkeypatch):
    add_address_host(client)
    challenge = start(client).json()
    with_token_file(monkeypatch, challenge["token"])
    con = db.connect()
    db.init(con)
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'other', 't')")
    con.commit()
    con.close()
    other = signed_in(client, "other@example.com", 2)
    r = other.post(f"/api/admin/hosts/outside-only/addresses/{challenge['id']}/verify")

    assert r.status_code == 404
    assert "code" not in r.json() and ADDRESS not in json.dumps(r.json())
    assert proved_row() == []
