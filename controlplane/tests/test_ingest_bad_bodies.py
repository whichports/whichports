"""Every route that reads a JSON body refuses a bad one the same way.

There were ten copies of `try: json.loads(await request.body())` in
`app/ingest.py` and five of them caught only `json.JSONDecodeError`. That is
the wrong half of the pair: `json.loads` decodes bytes itself and raises
`UnicodeDecodeError` for bytes that are not UTF-8, so those five answered 500
to a body carrying one invalid byte, on a surface where every other refusal is
a status code and one sentence.

**Why nobody found it by sending rubbish.** A body of `\\xff\\xfe` on its own
answers 400 already, because `json.loads` reads those two bytes as a UTF-16
byte order mark and fails on the JSON instead. The 500 needs valid UTF-8
around an invalid byte, which is what `{"name": "\\xff\\xfe"}` is.

The routes are discovered from the application rather than listed, so a route
added tomorrow is covered the day it appears rather than the day somebody
remembers this file.
"""
import inspect
import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest
from operator_gate import gate


# Valid UTF-8 either side of a byte that is not. This is the body that used to
# answer 500.
NOT_UTF8 = b'{"name": "\xff\xfe"}'

# Bodies that are UTF-8 and still not a JSON object.
NOT_JSON = b"not json at all"
EMPTY = b""
BARE_LIST = b"[1, 2, 3]"
BARE_STRING = b'"a string"'


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    # A server exception has to reach this test as a 500 rather than as a raise,
    # because a 500 is exactly what is being asserted against.
    return TestClient(ingest.app, raise_server_exceptions=False)


def admin_post_paths():
    """Every POST route under /api/admin, read off the application's own
    routing table rather than listed here. A route added tomorrow is covered
    the day it appears."""
    found = []
    for route in ingest.app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if "POST" in methods and path.startswith("/api/admin"):
            found.append(path)
    return sorted(found)


def body_reading_paths():
    """The subset of those that actually read a JSON body.

    Decided by the handler calling `json_body`, which since this change is the
    one way this file reads one. Discovered rather than listed for the same
    reason as above, and it is why `/api/admin/signout`, which reads nothing
    and answers with a page, is not held to the refusal below.
    """
    found = []
    for route in ingest.app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        endpoint = getattr(route, "endpoint", None)
        if "POST" not in methods or not path.startswith("/api/admin"):
            continue
        try:
            source = inspect.getsource(endpoint)
        except (OSError, TypeError):
            continue
        if "json_body(" in source:
            found.append(path)
    return sorted(found)


def concrete(path: str) -> str:
    """A path with its parameters filled in with something that exists nowhere.

    Every one of these routes 404s an unknown host or label, and a 404 is a
    fine answer here: what is being asserted is that a body nobody can parse
    never becomes a 500, whichever refusal comes first.
    """
    return (path.replace("{name}", "nosuchhost")
                .replace("{label}", "nosuchlabel")
                .replace("{challenge_id}", "1")
                .replace("{protocol}", "tcp")
                .replace("{port}", "443")
                .replace("{family}", "v4"))


def test_the_route_lists_are_not_empty():
    """A discovered set that discovers nothing is a test that passes by
    accident, which is the failure mode this whole file exists to catch."""
    assert len(admin_post_paths()) >= 10
    assert len(body_reading_paths()) >= 9


@pytest.mark.parametrize("path", admin_post_paths())
@pytest.mark.parametrize("body", [NOT_UTF8, NOT_JSON, EMPTY, BARE_LIST,
                                  BARE_STRING])
def test_no_admin_route_answers_500_to_a_body_it_cannot_read(client, path, body):
    answer = client.post(concrete(path), content=body, headers=gate())
    assert answer.status_code != 500, (
        f"{path} answered 500 to {body!r}, which is this process failing rather"
        " than refusing")
    assert answer.status_code < 500


@pytest.mark.parametrize("path", body_reading_paths())
def test_bytes_that_are_not_utf8_are_refused_in_this_files_words(client, path):
    """Not only "not a 500": the answer has to be the refusal the rest of the
    surface gives, so a route cannot pass this file by answering 422 in
    FastAPI's own validation shape."""
    answer = client.post(concrete(path), content=NOT_UTF8, headers=gate())
    assert answer.status_code in (400, 404), answer.text
    if answer.status_code == 400:
        assert answer.json()["detail"] == "not JSON"


# ------------------------------------------------------ the helper on its own

def test_json_body_reads_an_object():
    assert ingest.json_body(b'{"name": "web1"}') == {"name": "web1"}


@pytest.mark.parametrize("body", [NOT_UTF8, NOT_JSON, EMPTY, b"{", b'{"a": }'])
def test_json_body_refuses_with_one_sentence(body):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as raised:
        ingest.json_body(body)
    assert raised.value.status_code == 400
    assert raised.value.detail == "not JSON"


def test_json_body_lets_a_non_object_through_for_the_caller_to_refuse():
    """A list is JSON. It is not an object, and every caller already checks
    `isinstance(payload, dict)` for its own reasons, so this helper must not
    start deciding that too: two owners of one rule is how they disagree."""
    assert ingest.json_body(BARE_LIST) == [1, 2, 3]


# --------------------------------------------------- the agent's own envelope

def test_a_report_body_that_is_not_utf8_is_refused_not_crashed(client):
    """`parse_envelope` already caught the pair. This pins it, because it is
    the one route the internet reaches and the credential check comes first,
    so a regression here would show as a 401 rather than as anything obvious.
    """
    answer = client.post("/api/v1/reports", content=NOT_UTF8,
                         headers={"Authorization": "Bearer whp_" + "a" * 64})
    # Unknown credential, refused before the body is looked at.
    assert answer.status_code == 401


def test_a_report_from_a_real_host_with_a_bad_body_is_refused(client):
    from app import store
    con = db.connect()
    db.init(con)
    _host_id, credential = store.add_host(con, "web1")
    con.close()
    headers = {"Authorization": f"Bearer {credential}"}
    assert client.post("/api/v1/reports", content=NOT_UTF8,
                       headers=headers).status_code == 400
    assert client.post("/api/v1/reports", content=NOT_JSON,
                       headers=headers).status_code == 400
    assert client.post("/api/v1/reports", content=BARE_LIST,
                       headers=headers).status_code == 400
    # And the envelope this host really sends is still accepted.
    good = json.dumps({"schema_version": 1, "collected_at_unix": 1,
                       "hostname": "web1"})
    assert client.post("/api/v1/reports", content=good,
                       headers=headers).status_code == 204
