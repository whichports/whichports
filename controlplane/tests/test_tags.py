"""Tags on a server: the rule a tag follows, the store, and the route.

    python -m pytest tests/test_tags.py

The owner, 2026-08-18 (`docs/RECORD.md` 4.64): each server carries tags its user
makes up and applies. The fixture and the
gate pattern are test_first_look_endpoint.py's.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import db, ingest, store, tags
from operator_gate import gate
from test_admin import in_workspace


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


@pytest.fixture()
def con(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    connection = db.connect()
    db.init(connection)
    tags.init(connection)
    yield connection
    connection.close()


def post_tags(client, name, wanted, headers=None):
    return client.post(f"/api/admin/hosts/{name}/tags",
                       content=json.dumps({"tags": wanted}),
                       headers=gate() if headers is None else headers)


def add(client, name="box"):
    assert client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate()).status_code == 201


def stored(workspace_id=None):
    connection = db.connect()
    try:
        return tags.tags_by_host(connection, workspace_id=workspace_id)
    finally:
        connection.close()


# ------------------------------------------------------------------ the rule

@pytest.mark.parametrize("typed, kept", [
    ("production", "production"),
    ("Production", "production"),
    ("  web  ", "web"),
    ("eu-west_1", "eu-west_1"),
    ("7", "7"),
    ("a" * 32, "a" * 32),
])
def test_a_tag_is_trimmed_and_lowercased(typed, kept):
    assert tags.checked_tag(typed) == kept


@pytest.mark.parametrize("typed", [
    "", "   ", "a" * 33, "two words", "a,b", "-leading", "_leading",
    "café", "a/b", "a=b", "<b>", "tab\there", "new\nline", "nul\x00",
])
def test_a_tag_outside_the_name_rule_is_refused(typed):
    with pytest.raises(tags.TagError):
        tags.checked_tag(typed)


@pytest.mark.parametrize("typed", [None, 7, True, 1.5, ["production"], {"a": 1}])
def test_a_tag_that_is_not_text_is_refused(typed):
    with pytest.raises(tags.TagError):
        tags.checked_tag(typed)


def test_the_rule_is_the_server_names_rule():
    """One rule to remember: what a server may be called, a tag may be."""
    for word in ("web-07", "db_1", "x"):
        assert store.checked_name(word) == tags.checked_tag(word)


def test_a_set_keeps_the_typed_order_and_each_tag_once():
    assert tags.checked_tags(["web", "Production", "web", "production"]) == [
        "web", "production"]


def test_a_set_may_be_empty():
    assert tags.checked_tags([]) == []


def test_the_limit_is_three():
    """The owner's limit of 2026-10-03, `docs/RECORD.md` 4.274."""
    assert tags.MAX_TAGS_PER_HOST == 3


def test_three_tags_fit_and_four_do_not():
    three = ["production", "web", "hetzner"]
    assert tags.checked_tags(three) == three
    with pytest.raises(tags.TagError) as refused:
        tags.checked_tags(three + ["one-more"])
    assert str(refused.value) == "a server carries at most 3 tags"


def test_four_typed_that_are_three_different_fit():
    """The limit counts the tags kept, not the words typed."""
    assert tags.checked_tags(["web", "db", "eu", "WEB"]) == ["web", "db", "eu"]


def test_more_than_three_the_server_already_carries_are_taken():
    five = ["a", "b", "c", "d", "e"]
    assert tags.checked_tags(five, current=five) == five
    assert tags.checked_tags(["e", "a", "c", "b"], current=five) == ["e", "a", "c", "b"]


@pytest.mark.parametrize("wanted", [
    ["a", "b", "c", "d", "e", "f"],   # adds one to the five
    ["a", "b", "c", "f"],             # swaps one, still past the limit
])
def test_past_the_limit_a_new_tag_is_refused_even_on_a_server_that_has_more(wanted):
    with pytest.raises(tags.TagError):
        tags.checked_tags(wanted, current=["a", "b", "c", "d", "e"])


def test_at_the_limit_a_server_that_had_more_may_take_a_new_tag():
    assert tags.checked_tags(["a", "b", "new"], current=["a", "b", "c", "d", "e"]) == [
        "a", "b", "new"]


@pytest.mark.parametrize("typed", [None, "production", "a,b", 7, {"tags": []}])
def test_a_set_that_is_not_a_list_is_refused(typed):
    with pytest.raises(tags.TagError):
        tags.checked_tags(typed)


# ----------------------------------------------------------------- the store

def test_a_server_with_no_tags_is_not_in_the_answer(con):
    store.add_host(con, "box")
    assert tags.tags_by_host(con) == {}


def test_tags_are_stored_and_read_back_in_the_order_typed(con):
    store.add_host(con, "box")
    assert tags.set_tags(con, "box", ["web", "production"]) == ["web", "production"]
    assert tags.tags_by_host(con) == {"box": ["web", "production"]}


def test_a_save_replaces_the_set_and_an_empty_list_clears_it(con):
    store.add_host(con, "box")
    tags.set_tags(con, "box", ["web", "production"])
    tags.set_tags(con, "box", ["staging"])
    assert tags.tags_by_host(con) == {"box": ["staging"]}
    assert tags.set_tags(con, "box", []) == []
    assert tags.tags_by_host(con) == {}


def test_a_refused_set_leaves_the_server_with_the_tags_it_had(con):
    store.add_host(con, "box")
    tags.set_tags(con, "box", ["web"])
    with pytest.raises(tags.TagError):
        tags.set_tags(con, "box", ["production", "not a tag"])
    assert tags.tags_by_host(con) == {"box": ["web"]}


def test_two_servers_keep_their_own_tags(con):
    store.add_host(con, "one")
    store.add_host(con, "two")
    tags.set_tags(con, "one", ["production"])
    tags.set_tags(con, "two", ["production", "db"])
    assert tags.tags_by_host(con) == {"one": ["production"], "two": ["production", "db"]}


def test_an_unknown_server_is_none_and_nothing_is_stored(con):
    assert tags.set_tags(con, "nope", ["web"]) is None
    assert con.execute("SELECT count(*) FROM host_tags").fetchone()[0] == 0


def test_a_removed_server_cannot_be_tagged_and_its_tags_are_not_read(con):
    store.add_host(con, "box")
    tags.set_tags(con, "box", ["web"])
    assert store.revoke_host(con, "box")
    assert tags.set_tags(con, "box", ["production"]) is None
    assert tags.tags_by_host(con) == {}


def test_another_workspaces_server_is_none_and_its_tags_are_not_read(con):
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'w2', 'x')")
    store.add_host(con, "mine", workspace_id=1)
    store.add_host(con, "theirs", workspace_id=2)
    tags.set_tags(con, "theirs", ["secret-project"], workspace_id=2)
    assert tags.set_tags(con, "theirs", ["web"], workspace_id=1) is None
    assert tags.tags_by_host(con, workspace_id=1) == {}
    assert tags.tags_by_host(con, workspace_id=2) == {"theirs": ["secret-project"]}
    # None is the whole fleet, which only a background job asks for.
    assert tags.tags_by_host(con) == {"theirs": ["secret-project"]}


def test_the_report_that_names_a_server_keeps_its_tags(con):
    """The one rename left: a server's first report gives it its ID. Tags put
    on it while it was still under its placeholder stay with it."""
    host_id, _credential = store.add_host(con)
    placeholder = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()["name"]
    tags.set_tags(con, placeholder, ["web"])
    store.auto_name_from_hostname(con, host_id, "web-07")
    assert tags.tags_by_host(con) == {"web-07": ["web"]}


def test_a_database_from_before_tags_reads_as_no_tags(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "old.db"))
    connection = db.connect()
    db.init(connection)
    store.add_host(connection, "box")
    assert tags.tags_by_host(connection) == {}
    connection.close()


def test_init_twice_keeps_what_is_stored(con):
    store.add_host(con, "box")
    tags.set_tags(con, "box", ["web"])
    tags.init(con)
    assert tags.tags_by_host(con) == {"box": ["web"]}


def test_the_database_refuses_the_same_tag_twice_on_one_server(con):
    host_id, _credential = store.add_host(con, "box")
    con.execute("INSERT INTO host_tags (host_id, tag) VALUES (?, 'web')", (host_id,))
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO host_tags (host_id, tag) VALUES (?, 'web')", (host_id,))


def test_deleting_a_removed_server_takes_its_tags(con):
    store.add_host(con, "box")
    tags.set_tags(con, "box", ["web", "production"])
    assert store.revoke_host(con, "box")
    assert store.delete_host(con, "box")
    assert con.execute("SELECT count(*) FROM host_tags").fetchone()[0] == 0


# ----------------------------------------------------------------- the route

def test_the_route_stores_and_answers_with_what_it_stored(client):
    add(client)
    answer = post_tags(client, "box", ["Web", "production", "web"])
    assert answer.status_code == 200
    assert answer.json() == {"tags": ["web", "production"]}
    assert stored() == {"box": ["web", "production"]}


def test_the_route_clears_with_an_empty_list(client):
    add(client)
    post_tags(client, "box", ["web"])
    answer = post_tags(client, "box", [])
    assert answer.status_code == 200
    assert answer.json() == {"tags": []}
    assert stored() == {}


def test_the_route_is_gated(client):
    add(client)
    assert post_tags(client, "box", ["web"], headers={}).status_code in (401, 403)
    assert stored() == {}


def test_an_unknown_server_answers_not_found(client):
    add(client)
    assert post_tags(client, "nope", ["web"]).status_code == 404
    assert stored() == {}


def test_a_removed_server_answers_not_found(client):
    add(client)
    assert client.post("/api/admin/hosts/box/revoke", headers=gate()).status_code == 204
    assert post_tags(client, "box", ["web"]).status_code == 404


def test_another_workspaces_server_answers_not_found_and_is_untouched(client):
    add(client, "mine")
    other = in_workspace("two@example.com", 2)
    assert other.post("/api/admin/hosts",
                      content=json.dumps({"name": "theirs"})).status_code == 201
    assert other.post("/api/admin/hosts/theirs/tags",
                      content=json.dumps({"tags": ["db"]})).status_code == 200
    # workspace 1's operator cannot tag it, and cannot tell it exists
    assert post_tags(client, "theirs", ["web"]).status_code == 404
    assert stored() == {"theirs": ["db"]}
    # and workspace 2 cannot tag workspace 1's
    assert other.post("/api/admin/hosts/mine/tags",
                      content=json.dumps({"tags": ["db"]})).status_code == 404


@pytest.mark.parametrize("wanted", [
    ["two words"], ["a" * 33], [""], [7], [None], "production", None, 7,
    {"a": 1}, [f"t{i}" for i in range(4)],
])
def test_a_set_the_rule_refuses_is_a_400_in_words_and_stores_nothing(client, wanted):
    add(client)
    post_tags(client, "box", ["kept"])
    answer = post_tags(client, "box", wanted)
    assert answer.status_code == 400
    assert isinstance(answer.json()["detail"], str) and answer.json()["detail"]
    assert stored() == {"box": ["kept"]}


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'"tags"', b"{}",
                                  b'{"tag": ["web"]}'])
def test_a_body_that_is_not_the_expected_object_is_a_400(client, body):
    add(client)
    answer = client.post("/api/admin/hosts/box/tags", content=body, headers=gate())
    assert answer.status_code == 400
    assert stored() == {}


# ------------------------------------------------- the limit of three, 4.274

def test_the_route_takes_three(client):
    add(client)
    answer = post_tags(client, "box", ["production", "web", "hetzner"])
    assert answer.status_code == 200
    assert stored() == {"box": ["production", "web", "hetzner"]}


def test_the_route_refuses_a_fourth_in_words_and_keeps_the_three(client):
    add(client)
    post_tags(client, "box", ["production", "web", "hetzner"])
    answer = post_tags(client, "box", ["production", "web", "hetzner", "eu"])
    assert answer.status_code == 400
    assert answer.json() == {"detail": "a server carries at most 3 tags"}
    assert stored() == {"box": ["production", "web", "hetzner"]}


def tagged_before_the_limit(name="box", five=("a", "b", "c", "d", "e")):
    """A server tagged when ten were allowed: its rows written as that code
    wrote them, straight into the table."""
    connection = db.connect()
    try:
        host_id = connection.execute("SELECT id FROM hosts WHERE name = ?", (name,)).fetchone()[0]
        tags.init(connection)
        with connection:
            connection.executemany("INSERT INTO host_tags (host_id, tag) VALUES (?, ?)",
                                   [(host_id, t) for t in five])
    finally:
        connection.close()


def test_a_server_with_more_than_three_from_before_keeps_them(client):
    add(client)
    tagged_before_the_limit()
    assert stored() == {"box": ["a", "b", "c", "d", "e"]}
    # saving the field unchanged is not adding anything
    assert post_tags(client, "box", ["a", "b", "c", "d", "e"]).status_code == 200
    assert stored() == {"box": ["a", "b", "c", "d", "e"]}


def test_a_server_with_more_than_three_may_drop_some(client):
    add(client)
    tagged_before_the_limit()
    assert post_tags(client, "box", ["a", "c", "e", "d"]).json() == {"tags": ["a", "c", "e", "d"]}
    assert stored() == {"box": ["a", "c", "e", "d"]}


def test_a_server_with_more_than_three_takes_no_new_tag(client):
    add(client)
    tagged_before_the_limit()
    answer = post_tags(client, "box", ["a", "b", "c", "d", "e", "f"])
    assert answer.status_code == 400
    assert answer.json() == {"detail": "a server carries at most 3 tags"}
    assert stored() == {"box": ["a", "b", "c", "d", "e"]}


def test_a_server_with_more_than_three_takes_a_new_tag_once_at_three(client):
    add(client)
    tagged_before_the_limit()
    assert post_tags(client, "box", ["a", "b", "new"]).status_code == 200
    assert stored() == {"box": ["a", "b", "new"]}


def test_the_limit_reads_this_servers_tags_and_no_other(client):
    add(client, "one")
    add(client, "two")
    tagged_before_the_limit("one")
    # "two" carries nothing, so the five that "one" carries do not let it take five
    assert post_tags(client, "two", ["a", "b", "c", "d", "e"]).status_code == 400
    assert stored() == {"one": ["a", "b", "c", "d", "e"]}
