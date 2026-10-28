"""Who gets the Admin screen served to them, end to end.

    python -m pytest tests/test_admin_screen.py

This is the gate, so these tests are the review. In the
order a reviewer should read them:

  - an account without the flag gets a page with no Admin screen in it, on
    every dashboard address including /admin itself
  - the flag is the only thing that decides it. Not a query string, not a
    header, not the path
  - a signed-out browser gets the login page and no dashboard at all
  - revoking the flag takes the screen away on the very next request
  - the numbers a real `collect()` produces really do render, which is what
    keeps the site suite's hand-written fixture honest about the shape
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app import accounts, db, ingest, store, web_auth

PASSWORD = "correct-horse-battery-9"
EMAIL = "ops@example.com"


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "test.db"))
    return TestClient(ingest.app)


def connect():
    con = db.connect()
    db.init(con)
    accounts.init(con)
    return con


def signed_in(email=EMAIL, admin=False):
    """A browser carrying only a session cookie, for an account that either
    has the flag or does not."""
    con = connect()
    user_id = accounts.create_user(con, email, PASSWORD)
    if admin:
        accounts.set_admin(con, email, True)
    token, _ = accounts.issue_session(con, user_id)
    con.close()
    return TestClient(ingest.app, cookies={web_auth.SESSION_COOKIE: token})


def has_screen(response):
    return 'id="admin"' in response.text


def has_nav(response):
    return 'data-v="admin"' in response.text


# ================================================== without the flag, nothing

def test_an_ordinary_account_gets_no_admin_screen(client):
    browser = signed_in(admin=False)
    page = browser.get("/")
    assert page.status_code == 200
    assert not has_screen(page) and not has_nav(page)


@pytest.mark.parametrize("path", ["/", "/alerts", "/integrations", "/settings",
                                  "/auth", "/admin", "/host/anything"])
def test_no_dashboard_address_leaks_it(client, path):
    """Every address that answers with the shell answers with the same shell,
    so there is no address an ordinary account can type to get the screen."""
    browser = signed_in(admin=False)
    page = browser.get(path)
    assert page.status_code == 200
    assert not has_screen(page)


def test_admin_answers_the_shell_for_an_ordinary_account(client):
    """It is a real route, so a refresh on it is not a 404. What comes back is
    the page they are allowed to have."""
    page = signed_in(admin=False).get("/admin")
    assert page.status_code == 200
    assert 'id="fleet"' in page.text


@pytest.mark.parametrize("attempt", [
    "/admin?admin=1", "/admin?is_admin=true", "/?admin=1"])
def test_nothing_in_the_query_string_turns_it_on(client, attempt):
    page = signed_in(admin=False).get(attempt)
    assert not has_screen(page)


@pytest.mark.parametrize("header", [
    {"x-admin-gate": "1"}, {"x-auth-user": EMAIL}, {"x-is-admin": "true"}])
def test_no_header_turns_it_on(client, header):
    """The headers Caddy once stamped under basic auth prove nothing since
    2026-09-12, and they never were an account. A signed-in person carrying
    one is still the person their session names, without the flag."""
    page = signed_in(admin=False).get("/admin", headers=header)
    assert not has_screen(page)


# ===================================================== with the flag, the screen

def test_an_admin_account_gets_the_screen_and_the_nav_entry(client):
    browser = signed_in(admin=True)
    page = browser.get("/")
    assert has_screen(page) and has_nav(page)


def test_the_admin_address_serves_the_same_page(client):
    browser = signed_in(admin=True)
    assert has_screen(browser.get("/admin"))


def test_the_screen_carries_the_service_wide_numbers(client):
    """One account and one server exist, and the screen says so. This is the
    end-to-end proof that `adminstats.collect` and `admin_sections` agree
    about the shape they pass between them."""
    browser = signed_in(admin=True)
    con = connect()
    store.add_host(con, "mybox")
    con.close()
    page = browser.get("/admin")
    # B's shape since 2026-10-07 (docs/screens/admin/SPEC.md): the strip's
    # four boxes, the tabs, the quiet list's word and the account's address.
    assert "Instances reporting" in page.text
    assert "Workspaces" in page.text
    assert "not watched" in page.text
    assert EMAIL in page.text


def test_an_admin_still_sees_only_their_own_workspace_on_the_fleet(client):
    """The Admin screen counts across the service. The fleet does not, and the
    flag must not widen it."""
    browser = signed_in(admin=True)
    con = connect()
    con.execute("INSERT INTO workspaces (id, name, created_at)"
                " VALUES (2, 'other', ?)", (db.now_utc(),))
    con.commit()
    store.add_host(con, "mine", workspace_id=1)
    store.add_host(con, "theirs", workspace_id=2)
    con.close()
    page = browser.get("/")
    assert 'data-host="mine"' in page.text
    assert 'data-host="theirs"' not in page.text


# ============================================================ it comes and goes

def test_revoking_takes_the_screen_away_on_the_next_request(client):
    browser = signed_in(admin=True)
    assert has_screen(browser.get("/"))
    con = connect()
    accounts.set_admin(con, EMAIL, False)
    con.close()
    assert not has_screen(browser.get("/"))


def test_granting_gives_it_on_the_next_request(client):
    browser = signed_in(admin=False)
    assert not has_screen(browser.get("/"))
    con = connect()
    accounts.set_admin(con, EMAIL, True)
    con.close()
    assert has_screen(browser.get("/"))


# ================================================================== signed out

def test_a_signed_out_browser_is_sent_to_sign_in(client):
    page = client.get("/admin", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"].startswith("/login?next=")
    assert not has_screen(page)


def test_a_disabled_admin_gets_nothing(client):
    browser = signed_in(admin=True)
    con = connect()
    accounts.set_disabled(con, EMAIL, True)
    con.close()
    page = browser.get("/admin", follow_redirects=False)
    assert page.status_code == 303


def test_the_page_is_never_cached(client):
    """One workspace's servers and the whole service's numbers. Neither may
    sit in a shared cache or be shown again after a sign-out."""
    page = signed_in(admin=True).get("/admin")
    assert "no-store" in page.headers.get("cache-control", "")


# ================================= looking into somebody else's workspace
#
# The one place in the application where a page shows a workspace other than
# the session's. It is a read, the flag is the only thing that allows it, and
# no write moves. These are the tests that say so.

def other_workspace(name="Acme", host="theirbox"):
    """A second workspace with a server in it."""
    con = connect()
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, ?, ?)",
                (name, db.now_utc()))
    con.commit()
    store.add_host(con, host, workspace_id=2)
    con.close()


def test_an_admin_sees_the_other_workspaces_servers(client):
    other_workspace()
    browser = signed_in(admin=True)
    page = browser.get("/admin/workspace/2")
    assert page.status_code == 200
    assert 'data-host="theirbox"' in page.text


def test_the_banner_names_whose_fleet_it_is(client):
    other_workspace(name="Acme")
    page = signed_in(admin=True).get("/admin/workspace/2")
    assert 'class="vbar"' in page.text
    assert "Acme" in page.text
    assert '<body data-viewing="1">' in page.text


def test_an_ordinary_account_gets_404(client):
    """404 and not 403. A 403 confirms the route exists and that some
    workspace does, which is not a signed-in stranger's to learn."""
    other_workspace()
    page = signed_in(admin=False).get("/admin/workspace/2")
    assert page.status_code == 404
    assert "theirbox" not in page.text


def test_a_signed_out_browser_is_sent_to_sign_in_not_404(client):
    page = client.get("/admin/workspace/2", follow_redirects=False)
    assert page.status_code == 303
    assert page.headers["location"].startswith("/login?next=")


@pytest.mark.parametrize("header", [
    {"x-admin-gate": "1"}, {"x-auth-user": EMAIL}])
def test_the_edge_header_does_not_open_it(client, header):
    """The headers Caddy once stamped under basic auth are text a caller can
    type. They were never an account and they open nothing here."""
    other_workspace()
    page = signed_in(admin=False).get("/admin/workspace/2", headers=header)
    assert page.status_code == 404


@pytest.mark.parametrize("bad", ["0", "-1", "abc", "1.5", "true", "%20", "1x"])
def test_a_workspace_id_that_is_not_a_positive_integer_is_404(client, bad):
    page = signed_in(admin=True).get(f"/admin/workspace/{bad}")
    assert page.status_code == 404


def test_a_workspace_that_does_not_exist_is_404(client):
    """A stale link is a 404 rather than an empty fleet, which would read as a
    customer who has no servers."""
    page = signed_in(admin=True).get("/admin/workspace/99")
    assert page.status_code == 404


def test_the_admin_screen_is_not_layered_over_somebody_elses_page(client):
    """It is the whole service's numbers and belongs on your own page."""
    other_workspace()
    page = signed_in(admin=True).get("/admin/workspace/2")
    assert 'id="admin"' not in page.text
    assert 'data-v="admin"' not in page.text


def test_your_own_workspace_is_still_reachable_this_way(client):
    """Nothing special-cases it, and it must not: workspace 1 is a workspace
    like any other, and an admin opening their own through this route gets the
    same page with the banner on it."""
    browser = signed_in(admin=True)
    con = connect()
    store.add_host(con, "mine", workspace_id=1)
    con.close()
    page = browser.get("/admin/workspace/1")
    assert page.status_code == 200
    assert 'data-host="mine"' in page.text
    assert '<body data-viewing="1">' in page.text


def test_viewing_does_not_change_what_your_own_page_shows(client):
    """The read is scoped by the id in the path and nothing about the session
    moves, so your own dashboard is exactly what it was."""
    other_workspace()
    browser = signed_in(admin=True)
    con = connect()
    store.add_host(con, "mine", workspace_id=1)
    con.close()
    browser.get("/admin/workspace/2")
    own = browser.get("/")
    assert 'data-host="mine"' in own.text
    assert 'data-host="theirbox"' not in own.text


def test_the_page_is_never_cached_either(client):
    other_workspace()
    page = signed_in(admin=True).get("/admin/workspace/2")
    assert "no-store" in page.headers.get("cache-control", "")


# ============================================ and no write follows the read

def test_a_write_still_acts_on_your_own_workspace_only(client):
    """**The invariant that does not move.** Two hosts with the same name in
    two workspaces, an admin viewing the other one, and a pause posted the way
    the page would post it. The one that changes is theirs to keep and yours to
    lose: the route reads the session, never the path. This used the rename
    until 2026-10-03, when the ID stopped being changeable."""
    con = connect()
    con.execute("INSERT INTO workspaces (id, name, created_at) VALUES (2, 'Acme', ?)",
                (db.now_utc(),))
    con.commit()
    store.add_host(con, "web-01", workspace_id=1)
    con.close()
    con = connect()
    con.execute("INSERT INTO hosts (name, token_hash, kind, created_at,"
                " workspace_id) VALUES ('web-01-theirs', 'tok2', 'agent', ?, 2)",
                (db.now_utc(),))
    con.commit()
    con.close()

    browser = signed_in(admin=True)
    browser.get("/admin/workspace/2")
    answer = browser.post("/api/admin/hosts/web-01/pause",
                          json={"paused": True})
    assert answer.status_code == 204

    con = connect()
    mine = {(r["name"], r["paused"]) for r in con.execute(
        "SELECT name, paused FROM hosts WHERE workspace_id = 1")}
    theirs = {(r["name"], r["paused"]) for r in con.execute(
        "SELECT name, paused FROM hosts WHERE workspace_id = 2")}
    con.close()
    assert mine == {("web-01", 1)}
    assert theirs == {("web-01-theirs", 0)}


def test_an_admin_cannot_pause_a_host_in_the_workspace_they_are_viewing(client):
    """The route resolves a host name inside the session's workspace, so a name
    that only exists in the viewed one is simply not found."""
    other_workspace(host="theirbox")
    browser = signed_in(admin=True)
    browser.get("/admin/workspace/2")
    answer = browser.post("/api/admin/hosts/theirbox/pause",
                          json={"paused": True})
    assert answer.status_code == 404
    con = connect()
    still = con.execute("SELECT name, paused FROM hosts WHERE workspace_id = 2"
                        ).fetchone()
    con.close()
    assert (still["name"], still["paused"]) == ("theirbox", 0)


# ============================== the address lookup, 2026-10-06 (SPEC.md, 4.425)
#
# A form that posts with the page's own token. The address is kept nowhere.

def csrf_of(browser):
    page = browser.get("/admin")
    token = browser.cookies.get(web_auth.CSRF_COOKIE)
    assert token and f'name="csrf" value="{token}"' in page.text
    return token


def test_an_admins_page_carries_the_lookup_form_and_a_token(client):
    browser = signed_in(admin=True)
    page = browser.get("/admin")
    assert 'action="/admin/lookup"' in page.text and 'method="post"' in page.text
    assert browser.cookies.get(web_auth.CSRF_COOKIE)


def test_an_ordinary_page_carries_no_form_and_no_token(client):
    browser = signed_in(admin=False)
    page = browser.get("/")
    assert 'action="/admin/lookup"' not in page.text
    assert browser.cookies.get(web_auth.CSRF_COOKIE) is None


def test_the_lookup_answers_the_rows_for_an_address_and_keeps_it_nowhere(client, tmp_path):
    from app import authz, instances, proberapi, vantages
    from datetime import datetime, timezone
    browser = signed_in(admin=True)
    con = connect()
    for module in (authz, vantages, instances, proberapi):
        module.init(con)
    issued = instances.add(con, "oakhill", origin=authz.ORIGIN_INVITED)
    now = datetime.now(timezone.utc)
    proberapi.log_sent(con, issued.instance.id, "probe1", ["185.199.108.153"], 6, now)
    con.close()
    token = csrf_of(browser)
    page = browser.post("/admin/lookup", data={"address": " 185.199.108.153 ", "csrf": token})
    assert page.status_code == 200
    assert "oakhill" in page.text and "probe1" in page.text and "1 row" in page.text
    assert page.headers["cache-control"].startswith("no-store")
    # the address is in the field and the heading of the page it answered, and nowhere else
    con = connect()
    for table in ("prober_api_log", "prober_api_batches", "prober_api_charges"):
        rows = con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        assert rows == (1 if table == "prober_api_log" else 0)
    con.close()
    assert "address=" not in str(page.url)


def test_what_is_not_an_address_gets_one_word_and_no_rows(client):
    browser = signed_in(admin=True)
    token = csrf_of(browser)
    page = browser.post("/admin/lookup", data={"address": "not-this", "csrf": token})
    assert page.status_code == 200
    assert "not an address" in page.text
    assert 'class="thead lrow"' not in page.text


def test_the_lookup_without_the_token_is_refused(client):
    browser = signed_in(admin=True)
    browser.get("/admin")
    assert browser.post("/admin/lookup", data={"address": "185.199.108.153", "csrf": ""}).status_code == 400
    assert browser.post("/admin/lookup", data={"address": "185.199.108.153",
                                               "csrf": "x" * 40}).status_code == 400


def test_the_lookup_is_404_without_the_flag_and_sign_in_without_a_session(client):
    browser = signed_in(admin=False)
    assert browser.post("/admin/lookup", data={"address": "185.199.108.153", "csrf": "x" * 40}).status_code == 404
    stranger = TestClient(ingest.app)
    answer = stranger.post("/admin/lookup", data={"address": "185.199.108.153"}, follow_redirects=False)
    assert answer.status_code == 303 and answer.headers["location"].startswith("/login")


def test_the_lookup_never_takes_a_get(client):
    browser = signed_in(admin=True)
    assert browser.get("/admin/lookup?address=185.199.108.153").status_code in (404, 405)
