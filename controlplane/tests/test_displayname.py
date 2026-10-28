"""A server's display name: the rule it follows, the store, and the route.

    python -m pytest tests/test_displayname.py

Decided by the owner on 2026-10-02 (`docs/RECORD.md` 4.238). It is a label and
never the identifier, so most of this file is about what it must not change.
The fixture and the gate pattern are test_tags.py's.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from app import db, displayname, ingest, store
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
    displayname.init(connection)
    yield connection
    connection.close()


def post_name(client, name, wanted, headers=None):
    return client.post(f"/api/admin/hosts/{name}/display-name",
                       content=json.dumps({"display_name": wanted}),
                       headers=gate() if headers is None else headers)


def add(client, name="box"):
    assert client.post("/api/admin/hosts", content=json.dumps({"name": name}),
                       headers=gate()).status_code == 201


def stored(workspace_id=None):
    connection = db.connect()
    try:
        return displayname.display_names_by_host(connection, workspace_id=workspace_id)
    finally:
        connection.close()


# ------------------------------------------------------------------ the rule

@pytest.mark.parametrize("typed, kept", [
    ("Webshop", "Webshop"),
    ("CI runner", "CI runner"),
    ("  Shop API  ", "Shop API"),
    ("VPN   gateway", "VPN gateway"),
    ("db-01 (primary)", "db-01 (primary)"),
    ("R&D / lab #2", "R&D / lab #2"),
    ("Robin's box", "Robin's box"),
    ("Köln mail", "Köln mail"),
    ("x", "x"),
    ("a" * 40, "a" * 40),
])
def test_a_display_name_is_trimmed_and_keeps_its_case(typed, kept):
    assert displayname.checked(typed) == kept


@pytest.mark.parametrize("typed", ["", " ", "      "])
def test_nothing_or_only_spaces_is_no_display_name(typed):
    assert displayname.checked(typed) == ""


@pytest.mark.parametrize("typed", [
    "a" * 41,
    "<b>Webshop</b>", "<script>alert(1)</script>", 'Web"shop', "Web\\shop",
    "Web;shop", "Web`shop`", "Web|shop", "Web{shop}", "Web=shop", "50% off",
    "tab\there", "line\nbreak", "\tleading tab", "trailing newline\n",
    "nul\x00", "bell\x07", "esc\x1b[31m",
    "right‮to left", "zero​width", "é combining",
])
def test_markup_control_characters_and_too_long_are_refused(typed):
    with pytest.raises(displayname.DisplayNameError):
        displayname.checked(typed)


def test_the_length_is_counted_after_the_spaces_are_collapsed():
    assert displayname.checked("a" * 20 + "     " + "b" * 19) == "a" * 20 + " " + "b" * 19
    with pytest.raises(displayname.DisplayNameError):
        displayname.checked("a" * 20 + " " + "b" * 20)


@pytest.mark.parametrize("typed", [None, 7, True, 1.5, ["Webshop"], {"a": 1}])
def test_a_display_name_that_is_not_text_is_refused(typed):
    with pytest.raises(displayname.DisplayNameError):
        displayname.checked(typed)


def test_the_refusal_says_what_is_allowed():
    with pytest.raises(displayname.DisplayNameError) as refused:
        displayname.checked("<b>")
    assert "letters, digits, spaces" in str(refused.value)


# ----------------------------------------------------------------- the store

def test_a_server_without_one_is_not_in_the_answer(con):
    store.add_host(con, "box")
    assert displayname.display_names_by_host(con) == {}


def test_a_display_name_is_stored_replaced_and_cleared(con):
    store.add_host(con, "web-07")
    assert displayname.set_display_name(con, "web-07", "Webshop") == "Webshop"
    assert displayname.display_names_by_host(con) == {"web-07": "Webshop"}
    assert displayname.set_display_name(con, "web-07", "Shop") == "Shop"
    assert displayname.display_names_by_host(con) == {"web-07": "Shop"}
    assert displayname.set_display_name(con, "web-07", "   ") == ""
    assert displayname.display_names_by_host(con) == {}
    assert con.execute("SELECT count(*) FROM host_display_names").fetchone()[0] == 0


def test_clearing_one_that_was_never_set_is_not_an_error(con):
    store.add_host(con, "box")
    assert displayname.set_display_name(con, "box", "") == ""


def test_two_servers_may_carry_the_same_display_name(con):
    """It is a label, never the identifier: nothing is found by it."""
    store.add_host(con, "web-01")
    store.add_host(con, "web-02")
    displayname.set_display_name(con, "web-01", "Webshop")
    displayname.set_display_name(con, "web-02", "Webshop")
    assert displayname.display_names_by_host(con) == {
        "web-01": "Webshop", "web-02": "Webshop"}


def test_a_display_name_that_is_another_servers_name_finds_nobody(con):
    """A server is looked up by its name. A display name spelled like another
    server's name must not make either of them answer for the other."""
    store.add_host(con, "alpha")
    store.add_host(con, "beta")
    displayname.set_display_name(con, "alpha", "beta")
    assert store.active_host_by_name(con, "beta")["name"] == "beta"
    assert displayname.set_display_name(con, "beta", "Second") == "Second"
    assert displayname.display_names_by_host(con) == {"alpha": "beta", "beta": "Second"}


def test_the_name_a_server_is_found_by_does_not_change(con):
    host_id, credential = store.add_host(con, "web-07")
    displayname.set_display_name(con, "web-07", "Webshop")
    assert store.active_host_by_name(con, "web-07")["id"] == host_id
    assert store.active_host_by_name(con, "Webshop") is None
    assert store.host_for_credential(con, credential)["name"] == "web-07"


def test_a_refused_name_leaves_the_one_that_was_stored(con):
    store.add_host(con, "box")
    displayname.set_display_name(con, "box", "Webshop")
    with pytest.raises(displayname.DisplayNameError):
        displayname.set_display_name(con, "box", "<b>")
    assert displayname.display_names_by_host(con) == {"box": "Webshop"}


def test_an_unknown_server_is_none_and_nothing_is_stored(con):
    assert displayname.set_display_name(con, "nope", "Webshop") is None
    assert con.execute("SELECT count(*) FROM host_display_names").fetchone()[0] == 0


def test_a_removed_server_cannot_be_named_and_its_name_is_not_read(con):
    store.add_host(con, "box")
    displayname.set_display_name(con, "box", "Webshop")
    assert store.revoke_host(con, "box")
    assert displayname.set_display_name(con, "box", "Other") is None
    assert displayname.display_names_by_host(con) == {}


def test_another_workspaces_server_is_none_and_its_name_is_not_read(con):
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'w2', 'x')")
    store.add_host(con, "mine", workspace_id=1)
    store.add_host(con, "theirs", workspace_id=2)
    displayname.set_display_name(con, "theirs", "Their project", workspace_id=2)
    assert displayname.set_display_name(con, "theirs", "Mine now", workspace_id=1) is None
    assert displayname.display_names_by_host(con, workspace_id=1) == {}
    assert displayname.display_names_by_host(con, workspace_id=2) == {"theirs": "Their project"}


def test_the_report_that_names_a_server_keeps_its_display_name(con):
    """The one rename left: a server's first report gives it its ID. A display
    name set while it was still under its placeholder stays with it."""
    host_id, _credential = store.add_host(con)
    placeholder = con.execute("SELECT name FROM hosts WHERE id = ?", (host_id,)).fetchone()["name"]
    displayname.set_display_name(con, placeholder, "Webshop")
    store.auto_name_from_hostname(con, host_id, "web-07")
    assert displayname.display_names_by_host(con) == {"web-07": "Webshop"}


def test_a_database_from_before_display_names_reads_as_none(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "old.db"))
    connection = db.connect()
    db.init(connection)
    store.add_host(connection, "box")
    assert displayname.display_names_by_host(connection) == {}
    connection.close()


def test_init_twice_keeps_what_is_stored(con):
    store.add_host(con, "box")
    displayname.set_display_name(con, "box", "Webshop")
    displayname.init(con)
    assert displayname.display_names_by_host(con) == {"box": "Webshop"}


def test_the_database_holds_one_display_name_per_server(con):
    host_id, _credential = store.add_host(con, "box")
    con.execute("INSERT INTO host_display_names (host_id, display_name) VALUES (?, 'a')",
                (host_id,))
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO host_display_names (host_id, display_name) VALUES (?, 'b')",
                    (host_id,))


def test_deleting_a_removed_server_takes_its_display_name(con):
    store.add_host(con, "box")
    displayname.set_display_name(con, "box", "Webshop")
    assert store.revoke_host(con, "box")
    assert store.delete_host(con, "box")
    assert con.execute("SELECT count(*) FROM host_display_names").fetchone()[0] == 0


def test_shown_name_is_the_display_name_or_the_name():
    names = {"web-07": "Webshop"}
    assert displayname.shown_name(names, "web-07") == "Webshop"
    assert displayname.shown_name(names, "db-01") == "db-01"
    assert displayname.shown_name({}, "db-01") == "db-01"


# ----------------------------------------------------------------- the route

def test_the_route_stores_and_answers_with_what_it_stored(client):
    add(client, "web-07")
    answer = post_name(client, "web-07", "  CI   runner ")
    assert answer.status_code == 200
    assert answer.json() == {"display_name": "CI runner"}
    assert stored() == {"web-07": "CI runner"}


def test_the_route_clears_with_an_empty_name(client):
    add(client)
    post_name(client, "box", "Webshop")
    answer = post_name(client, "box", "")
    assert answer.status_code == 200
    assert answer.json() == {"display_name": ""}
    assert stored() == {}


def test_the_route_is_gated(client):
    add(client)
    assert post_name(client, "box", "Webshop", headers={}).status_code in (401, 403)
    assert stored() == {}


def test_the_route_finds_a_server_by_its_name_and_never_by_its_display_name(client):
    add(client, "web-07")
    post_name(client, "web-07", "Webshop")
    assert post_name(client, "Webshop", "Other").status_code == 404
    assert stored() == {"web-07": "Webshop"}
    # and every other route still answers on the name
    assert client.post("/api/admin/hosts/web-07/pause",
                       content=json.dumps({"paused": True}), headers=gate()).status_code == 204
    assert client.post("/api/admin/hosts/Webshop/pause",
                       content=json.dumps({"paused": True}), headers=gate()).status_code == 404


def test_an_unknown_and_a_removed_server_answer_not_found(client):
    add(client)
    assert post_name(client, "nope", "Webshop").status_code == 404
    assert client.post("/api/admin/hosts/box/revoke", headers=gate()).status_code == 204
    assert post_name(client, "box", "Webshop").status_code == 404
    assert stored() == {}


def test_another_workspaces_server_answers_not_found_and_is_untouched(client):
    add(client, "mine")
    other = in_workspace("two@example.com", 2)
    assert other.post("/api/admin/hosts",
                      content=json.dumps({"name": "theirs"})).status_code == 201
    assert other.post("/api/admin/hosts/theirs/display-name",
                      content=json.dumps({"display_name": "Their project"})).status_code == 200
    assert post_name(client, "theirs", "Mine now").status_code == 404
    assert stored() == {"theirs": "Their project"}
    assert other.post("/api/admin/hosts/mine/display-name",
                      content=json.dumps({"display_name": "x"})).status_code == 404


@pytest.mark.parametrize("wanted", [
    "<b>Webshop</b>", "a" * 41, "tab\there", 7, None, ["Webshop"], {"a": 1}, True,
])
def test_a_name_the_rule_refuses_is_a_400_in_words_and_stores_nothing(client, wanted):
    add(client)
    post_name(client, "box", "Kept")
    answer = post_name(client, "box", wanted)
    assert answer.status_code == 400
    assert isinstance(answer.json()["detail"], str) and answer.json()["detail"]
    assert stored() == {"box": "Kept"}


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'"Webshop"', b"{}",
                                  b'{"name": "Webshop"}'])
def test_a_body_that_is_not_the_expected_object_is_a_400(client, body):
    add(client)
    answer = client.post("/api/admin/hosts/box/display-name", content=body, headers=gate())
    assert answer.status_code == 400
    assert stored() == {}
