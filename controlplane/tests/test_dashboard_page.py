"""Serving the dashboard, rendered from the database per request.

    python -m pytest tests/test_dashboard_page.py

Because the owner reads every diff but has said he cannot be relied on to catch a
subtle security bug in review, these tests are the review.
The ones that carry the argument, in the order a reviewer should read them:

  - an action's result is on the very next GET. Rename a host through the
    admin route, ask for the page again, and the new name is in the HTML,
    which is the whole reason the page renders at request time instead of
    being read from a file a timer wrote a minute ago
  - a signed-in account gets its own workspace's page and never another's
  - nothing in the request decides the workspace. Not a path segment, not a
    query string, not a header
  - a signed-out browser is sent to sign in and is shown no page at all
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import accounts, dashboard, db, ingest, store, web_auth

PASSWORD = "correct-horse-battery-9"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def connect():
    con = db.connect()
    db.init(con)
    accounts.init(con)
    return con


def add_workspace(con, workspace_id):
    if db.workspace_by_id(con, workspace_id) is None:
        con.execute("INSERT INTO workspaces (id, name, created_at)"
                    " VALUES (?, ?, ?)",
                    (workspace_id, f"w{workspace_id}", db.now_utc()))
        con.commit()


def add_host(name, workspace_id):
    con = connect()
    add_workspace(con, workspace_id)
    store.add_host(con, name, workspace_id=workspace_id)
    con.close()


def signed_in(email, workspace_id):
    """A browser signed in as a real account in one workspace, carrying only
    its session cookie. Uses the database the `client` fixture pointed the
    process at, so call it from a test that takes `client`."""
    con = connect()
    add_workspace(con, workspace_id)
    user_id = accounts.create_user(con, email, PASSWORD,
                                   workspace_id=workspace_id)
    token, _ = accounts.issue_session(con, user_id)
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


# ==================================== the reason it renders per request

def test_a_name_given_is_on_the_very_next_page(client):
    """The test this change exists for. The old arrangement read a file that a
    one minute timer wrote, so the reload after an action showed the page from
    before it. Rendered per request, the admin action and the next GET meet
    the same database. It was a rename until 2026-10-03, when the ID stopped
    being changeable, and is the display name since."""
    add_host("thebox", 1)
    browser = signed_in("one@example.com", 1)
    assert "Checkout servers" not in browser.get("/").text

    resp = browser.post("/api/admin/hosts/thebox/display-name",
                        json={"display_name": "Checkout servers"})
    assert resp.status_code == 200

    page = browser.get("/").text
    assert "Checkout servers" in page
    assert "thebox" in page


def test_a_host_added_after_the_first_look_is_on_the_second(client):
    browser = signed_in("one@example.com", 1)
    assert "late-arrival" not in browser.get("/").text
    add_host("late-arrival", 1)
    assert "late-arrival" in browser.get("/").text


def test_the_stamp_is_the_request_time(client, tmp_path, monkeypatch):
    """The footer used to say when the timer last ran. Now every GET is its
    own render, so the stamp is when this page was asked for, and the commit
    half still comes from the deploy's file, read on every render."""
    build_file = tmp_path / "DEPLOYED_COMMIT"
    build_file.write_text("abc1234\n")
    monkeypatch.setenv("WHICHPORTS_BUILD_FILE", str(build_file))
    con = connect()
    add_workspace(con, 1)
    con.close()
    asked_at = datetime(2026, 8, 25, 12, 34, 56, tzinfo=timezone.utc)
    html = dashboard.page(1, now=asked_at)
    assert "rendered 2026-08-25 12:34:56 UTC" in html
    assert "built abc1234" in html


def test_a_deploy_shows_without_a_restart_between_two_gets(client, tmp_path,
                                                           monkeypatch):
    """DEPLOYED_COMMIT is read per render, so the refresh after a deploy names
    the new commit with no unit in between."""
    build_file = tmp_path / "DEPLOYED_COMMIT"
    build_file.write_text("aaaa111\n")
    monkeypatch.setenv("WHICHPORTS_BUILD_FILE", str(build_file))
    browser = signed_in("one@example.com", 1)
    assert "built aaaa111" in browser.get("/").text
    build_file.write_text("bbbb222\n")
    assert "built bbbb222" in browser.get("/").text


# ==================================== the workspace id guard

@pytest.mark.parametrize("value", [0, -1, -99, None, 1.5, True, False, b"1",
                                   [], "1", "2", " 1 ", "..", "/etc/passwd"])
def test_a_workspace_id_that_is_not_a_positive_integer_is_refused(value):
    """`True` is in this list on purpose: it is `1` in Python, so a flag that
    reached here would quietly render workspace 1's page for whoever sent it.
    A digits-only string too: the only caller reads an INTEGER column, so text
    arriving here means something upstream is not what this thinks it is, and
    converting it would hide that."""
    with pytest.raises(dashboard.WorkspaceIdError):
        dashboard.page(value)


# ==================================== the route

def test_a_signed_out_browser_is_sent_to_sign_in(client):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?next=%2F"


def test_a_signed_out_browser_is_shown_no_page(client):
    add_host("private-host", 1)
    resp = client.get("/", follow_redirects=False)
    assert "private-host" not in resp.text


def test_a_deep_link_carries_where_it_was_going(client):
    resp = client.get("/host/web1", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login?next=%2Fhost%2Fweb1"


def test_a_session_gets_its_own_workspaces_page(client):
    add_host("host-of-one", 1)
    browser = signed_in("one@example.com", 1)
    resp = browser.get("/")
    assert resp.status_code == 200
    assert "host-of-one" in resp.text


def test_a_session_never_gets_another_workspaces_page(client):
    """The whole point. Both workspaces hold a host and the account in
    workspace 2 can see exactly one of them."""
    add_host("host-of-one", 1)
    add_host("host-of-two", 2)
    browser = signed_in("two@example.com", 2)
    resp = browser.get("/")
    assert resp.status_code == 200
    assert "host-of-two" in resp.text
    assert "host-of-one" not in resp.text


@pytest.mark.parametrize("attempt", [
    "/?workspace=1",
    "/?workspace_id=1",
    "/?w=1",
    "/?next=/w/1/index.html",
])
def test_nothing_in_the_query_string_changes_which_page_is_served(client,
                                                                  attempt):
    add_host("host-of-one", 1)
    add_host("host-of-two", 2)
    browser = signed_in("two@example.com", 2)
    resp = browser.get(attempt)
    assert "host-of-two" in resp.text
    assert "host-of-one" not in resp.text


@pytest.mark.parametrize("header", [
    {"X-Workspace": "1"},
    {"X-Workspace-Id": "1"},
    {"X-Admin-Gate": "caddy"},
    {"X-Auth-User": "one@example.com"},
])
def test_no_header_changes_which_page_is_served(client, header):
    """`X-Admin-Gate` is in this list deliberately. Until 2026-09-12 it was
    enough to pass the admin gate on its own, and it must never be enough to
    move a signed-in person into another workspace."""
    add_host("host-of-one", 1)
    add_host("host-of-two", 2)
    browser = signed_in("two@example.com", 2)
    resp = browser.get("/", headers=header)
    assert "host-of-two" in resp.text
    assert "host-of-one" not in resp.text


def test_no_dashboard_route_takes_a_workspace_parameter():
    """Read from the routes themselves rather than from the source text, so a
    parameter added later is caught whatever it is called. `/host/{rest:path}`
    is the one parameter there is, and the route ignores it."""
    paths = {route.path for route in web_auth.router.routes
             if getattr(route, "endpoint", None) in
             (web_auth._dashboard, web_auth.dashboard_host)}
    assert paths == set(web_auth.DASHBOARD_PATHS) | {"/host/{rest:path}"}
    assert [p for p in paths if "{" in p] == ["/host/{rest:path}"]


def test_a_host_deep_link_answers_with_the_shell(client):
    """The page routes client side, so a refresh on a host address has to give
    back the same page rather than 404."""
    add_host("host-of-two", 2)
    browser = signed_in("two@example.com", 2)
    for path in ("/host/web1", "/host/web1/rules", "/alerts", "/settings"):
        resp = browser.get(path)
        assert resp.status_code == 200, path
        assert "host-of-two" in resp.text, path


@pytest.mark.parametrize("path", [
    "/host/../../w/1/index.html",
    "/host/..%2f..%2fw%2f1%2findex.html",
    "/host/%2e%2e/%2e%2e/w/1/index.html",
    "/host/w/1/index.html",
])
def test_a_traversal_in_the_address_reaches_no_other_workspace(client, path):
    """There is no file for these to reach any more, and the route ignores
    everything after `/host/` besides. They stay because "there is nothing to
    exploit" is a claim that should be tested rather than asserted in a
    comment."""
    add_host("host-of-one", 1)
    add_host("host-of-two", 2)
    browser = signed_in("two@example.com", 2)
    resp = browser.get(path, follow_redirects=False)
    assert "host-of-one" not in resp.text
    if resp.status_code == 200:
        assert "host-of-two" in resp.text


def test_a_workspace_with_no_hosts_gets_a_page_at_once(client):
    """The old 503-until-the-timer-came-round state is gone. A workspace made
    a moment ago renders immediately, empty."""
    browser = signed_in("new@example.com", 2)
    resp = browser.get("/")
    assert resp.status_code == 200


def test_the_page_is_never_cached(client):
    add_host("host-of-one", 1)
    browser = signed_in("one@example.com", 1)
    assert browser.get("/").headers["cache-control"] == "no-store"


def test_a_login_that_still_owes_a_code_goes_to_the_code_page(client):
    """A pending session is not a session (`accounts.resolve_session`), so the
    dashboard must not answer it, and sending it back to the password form
    would be theatre."""
    add_host("host-of-one", 1)
    con = connect()
    user_id = accounts.create_user(con, "pending@example.com", PASSWORD)
    token, _ = accounts.issue_session(con, user_id, totp_pending=True)
    con.close()
    browser = TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})
    resp = browser.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"].startswith(web_auth.TWO_FACTOR_PATH)
    assert "host-of-one" not in resp.text


def test_signing_out_stops_the_page_answering(client):
    add_host("host-of-one", 1)
    browser = signed_in("one@example.com", 1)
    assert "host-of-one" in browser.get("/").text
    browser.post("/logout", follow_redirects=False)
    assert browser.get("/", follow_redirects=False).status_code == 303
