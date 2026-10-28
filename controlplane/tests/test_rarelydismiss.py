"""Dismissing the rarely-public mark on one port of one server: the rule, the
store and the route.

    python -m pytest tests/test_rarelydismiss.py

The owner, 2026-10-03 (`docs/RECORD.md` 4.274): a marked port that truly should
be open can have its mark suppressed. The fixtures and the gate are
test_tags.py's.
"""
import datetime
import json

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, rarelydismiss, store
from operator_gate import gate
from test_admin import in_workspace

T0 = datetime.datetime(2026, 10, 3, 12, 0, tzinfo=datetime.timezone.utc)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    db.init(connection)
    rarelydismiss.init(connection)
    yield connection
    connection.close()


def post(client, name, protocol, port, dismissed, headers=None):
    return client.post(f"/api/admin/hosts/{name}/rarely/{protocol}/{port}",
                       content=json.dumps({"dismissed": dismissed}),
                       headers=gate() if headers is None else headers)


def add(client, name="box"):
    assert client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate()).status_code == 201


def stored(workspace_id=None):
    connection = db.connect()
    try:
        return rarelydismiss.dismissed_by_host(connection, workspace_id=workspace_id)
    finally:
        connection.close()


# ------------------------------------------------------------------ the rule

@pytest.mark.parametrize("protocol, port", [("tcp", 6379), ("TCP", 3306), ("tcp", 27019)])
def test_a_port_on_the_list_can_be_dismissed(protocol, port):
    assert rarelydismiss.checked_port(protocol, port) == ("tcp", port)


@pytest.mark.parametrize("protocol, port", [
    ("tcp", 5432),   # left off the list, so it never carries the mark
    ("tcp", 22), ("udp", 11211), ("tcp", 0), ("tcp", 70000), ("tcp", -6379),
])
def test_a_port_that_carries_no_mark_cannot_be_dismissed(protocol, port):
    with pytest.raises(rarelydismiss.DismissError):
        rarelydismiss.checked_port(protocol, port)


@pytest.mark.parametrize("protocol, port", [
    (None, 6379), (6379, "tcp"), ("tcp", "6379"), ("tcp", 6379.0), ("tcp", True), ("tcp", None),
])
def test_what_is_not_a_port_is_refused(protocol, port):
    with pytest.raises(rarelydismiss.DismissError):
        rarelydismiss.checked_port(protocol, port)


@pytest.mark.parametrize("dismissed", [None, "true", 1, 0, "yes", [], {}])
def test_dismissed_must_be_true_or_false(con, dismissed):
    store.add_host(con, "box")
    with pytest.raises(rarelydismiss.DismissError):
        rarelydismiss.set_dismissed(con, "box", "tcp", 6379, dismissed)
    assert rarelydismiss.dismissed_by_host(con) == {}


# ----------------------------------------------------------------- the store

def test_nothing_dismissed_is_an_empty_answer(con):
    store.add_host(con, "box")
    assert rarelydismiss.dismissed_by_host(con) == {}


def test_a_dismissal_is_stored_and_undone(con):
    store.add_host(con, "box")
    assert rarelydismiss.set_dismissed(con, "box", "tcp", 6379, True, now=T0) is True
    assert rarelydismiss.dismissed_by_host(con) == {"box": frozenset({"tcp/6379"})}
    assert rarelydismiss.set_dismissed(con, "box", "tcp", 6379, False) is False
    assert rarelydismiss.dismissed_by_host(con) == {}


def test_dismissing_twice_keeps_the_first_time(con):
    store.add_host(con, "box")
    rarelydismiss.set_dismissed(con, "box", "tcp", 6379, True, now=T0)
    rarelydismiss.set_dismissed(con, "box", "tcp", 6379, True, now=T0 + datetime.timedelta(days=1))
    rows = con.execute("SELECT dismissed_at FROM rarely_dismissed").fetchall()
    assert [r[0] for r in rows] == [T0.isoformat()]


def test_bringing_back_a_mark_that_was_never_dismissed_is_no_error(con):
    store.add_host(con, "box")
    assert rarelydismiss.set_dismissed(con, "box", "tcp", 6379, False) is False


def test_a_dismissal_is_one_port_of_one_server(con):
    store.add_host(con, "one")
    store.add_host(con, "two")
    rarelydismiss.set_dismissed(con, "one", "tcp", 6379, True)
    rarelydismiss.set_dismissed(con, "one", "tcp", 3306, True)
    rarelydismiss.set_dismissed(con, "two", "tcp", 3306, True)
    assert rarelydismiss.dismissed_by_host(con) == {
        "one": frozenset({"tcp/6379", "tcp/3306"}), "two": frozenset({"tcp/3306"})}


def test_an_unknown_server_is_none_and_nothing_is_stored(con):
    assert rarelydismiss.set_dismissed(con, "nope", "tcp", 6379, True) is None
    assert rarelydismiss.dismissed_by_host(con) == {}


def test_a_removed_server_cannot_dismiss_and_its_dismissals_are_not_read(con):
    store.add_host(con, "box")
    rarelydismiss.set_dismissed(con, "box", "tcp", 6379, True)
    store.revoke_host(con, "box")
    assert rarelydismiss.set_dismissed(con, "box", "tcp", 3306, True) is None
    assert rarelydismiss.dismissed_by_host(con) == {}


def test_deleting_a_removed_server_takes_its_dismissals(con):
    store.add_host(con, "box")
    rarelydismiss.set_dismissed(con, "box", "tcp", 6379, True)
    store.revoke_host(con, "box")
    assert store.delete_host(con, "box")
    assert con.execute("SELECT count(*) FROM rarely_dismissed").fetchone()[0] == 0


def test_a_database_from_before_dismissals_reads_as_none(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "old.db"))
    connection = db.connect()
    db.init(connection)
    try:
        assert rarelydismiss.dismissed_by_host(connection) == {}
    finally:
        connection.close()


def test_init_twice_keeps_what_is_stored(con):
    store.add_host(con, "box")
    rarelydismiss.set_dismissed(con, "box", "tcp", 6379, True)
    rarelydismiss.init(con)
    assert rarelydismiss.dismissed_by_host(con) == {"box": frozenset({"tcp/6379"})}


# ----------------------------------------------------------------- the route

def test_the_route_dismisses_and_answers_with_what_it_stored(client):
    add(client)
    answer = post(client, "box", "tcp", 6379, True)
    assert answer.status_code == 200
    assert answer.json() == {"dismissed": True}
    assert stored() == {"box": frozenset({"tcp/6379"})}


def test_the_route_brings_the_mark_back(client):
    add(client)
    post(client, "box", "tcp", 6379, True)
    answer = post(client, "box", "tcp", 6379, False)
    assert answer.status_code == 200
    assert answer.json() == {"dismissed": False}
    assert stored() == {}


def test_the_route_is_gated(client):
    add(client)
    assert post(client, "box", "tcp", 6379, True, headers={}).status_code in (401, 403)
    assert stored() == {}


def test_an_unknown_server_answers_not_found(client):
    add(client)
    assert post(client, "nope", "tcp", 6379, True).status_code == 404
    assert stored() == {}


def test_another_workspaces_server_answers_not_found_and_is_untouched(client):
    add(client, "mine")
    other = in_workspace("two@example.com", 2)
    assert other.post("/api/admin/hosts", content=json.dumps({"name": "theirs"})).status_code == 201
    assert other.post("/api/admin/hosts/theirs/rarely/tcp/6379",
                      content=json.dumps({"dismissed": True})).status_code == 200
    assert post(client, "theirs", "tcp", 6379, False).status_code == 404
    assert stored() == {"theirs": frozenset({"tcp/6379"})}
    assert other.post("/api/admin/hosts/mine/rarely/tcp/6379",
                      content=json.dumps({"dismissed": True})).status_code == 404


@pytest.mark.parametrize("protocol, port", [("tcp", 5432), ("tcp", 22), ("udp", 11211), ("tcp", 0)])
def test_a_port_that_carries_no_mark_is_a_400_in_words(client, protocol, port):
    add(client)
    answer = post(client, "box", protocol, port, True)
    assert answer.status_code == 400
    assert answer.json() == {"detail": "this port carries no mark to dismiss"}
    assert stored() == {}


def test_a_port_that_is_not_a_number_is_refused(client):
    add(client)
    assert post(client, "box", "tcp", "redis", True).status_code in (400, 422)
    assert stored() == {}


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b"{}", b'{"dismissed": "yes"}',
                                  b'{"dismiss": true}'])
def test_a_body_that_is_not_the_expected_object_is_a_400(client, body):
    add(client)
    answer = client.post("/api/admin/hosts/box/rarely/tcp/6379", content=body, headers=gate())
    assert answer.status_code == 400
    assert stored() == {}
