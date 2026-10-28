"""The Hetzner Cloud provider leg.

    python -m pytest tests/test_hetzner.py

Nothing here touches the real API. Every test drives the client through a fake
opener that records the requests it was handed, so the suite runs offline and
against no account.

Three groups matter more than the rest:

  - **read only**, because SI-3 and SI-5 are the reason this integration is
    allowed to exist at all. There is a behaviour test that every request is a
    GET and a source test that nobody can add a write later without deleting a
    test to do it.
  - **v4 and v6 kept apart**, because PRODUCT.md 4b is a correction this
    project already had to publish. A rule that names only IPv4 must read as
    naming only IPv4.
  - **nothing invented on failure**, because a partial fetch presented as a
    whole one is the same failure in a different coat.
"""

import ast
import email.message
import io
import json
import sqlite3
import pathlib
import ssl
import urllib.error
import urllib.request

import pytest

from app import db, hetzner, hetzner_cli

TOKEN = "hcloud-token-not-a-real-one"


# ------------------------------------------------------------ the fake network

def headers(pairs=None):
    """urllib hands back an email.message.Message, so the fake does too. That
    matters: header lookup is case insensitive and a hand-rolled dict would
    make the rate limit test pass for the wrong reason."""
    message = email.message.Message()
    for key, value in (pairs or {}).items():
        message[key] = str(value)
    return message


class FakeResponse:
    def __init__(self, body, header_pairs=None, status=200):
        if not isinstance(body, (bytes, str)):
            body = json.dumps(body)
        self._body = body.encode() if isinstance(body, str) else body
        self._read = False
        self.headers = headers(header_pairs)
        self.status = status

    def read(self, size=-1):
        if size is None or size < 0:
            return self._body
        return self._body[:size]

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeOpener:
    """Records every request, answers from `responder`."""

    def __init__(self, responder):
        self.requests = []
        self._responder = responder

    def open(self, request, timeout=None):
        self.requests.append(request)
        result = self._responder(request)
        if isinstance(result, BaseException):
            raise result
        return result


def http_error(code, body=None, header_pairs=None):
    payload = body if body is not None else {"error": {"code": "x", "message": "y"}}
    return urllib.error.HTTPError(
        "https://api.hetzner.cloud/v1/servers", code, "err",
        headers(header_pairs), io.BytesIO(json.dumps(payload).encode()))


def envelope(key, items, next_page=None):
    """The documented list response: {"<key>": [...], "meta": {"pagination": ...}}."""
    return {key: list(items),
            "meta": {"pagination": {"page": 1, "per_page": 50, "previous_page": None,
                                    "next_page": next_page, "last_page": next_page,
                                    "total_entries": len(items)}}}


def opener_for(servers=(), firewalls=(), header_pairs=None):
    def respond(request):
        key = "servers" if "/servers" in request.full_url else "firewalls"
        items = servers if key == "servers" else firewalls
        return FakeResponse(envelope(key, items), header_pairs)
    return FakeOpener(respond)


def client(opener, token=TOKEN):
    return hetzner.ReadOnlyClient(hetzner.Config(token=token), opener=opener)


# ---------------------------------------------------------------- the API shapes

def server(id=1, name="box", status="running", ipv4="1.2.3.4",
           ipv6="2001:db8::/64", firewalls=()):
    """A server as GET /servers returns it, trimmed to the fields read here."""
    return {
        "id": id,
        "name": name,
        "status": status,
        "public_net": {
            "ipv4": None if ipv4 is None else {"id": 10, "ip": ipv4, "blocked": False,
                                               "dns_ptr": "box.example"},
            "ipv6": None if ipv6 is None else {"id": 11, "ip": ipv6, "blocked": False,
                                               "dns_ptr": None},
            "floating_ips": [],
            "firewalls": [{"id": fid, "status": state} for fid, state in firewalls],
        },
    }


def rule(direction="in", protocol="tcp", port="22", source_ips=(),
         destination_ips=(), description=None):
    return {"direction": direction, "protocol": protocol, "port": port,
            "source_ips": list(source_ips), "destination_ips": list(destination_ips),
            "description": description}


def firewall(id=42, name="fw", rules=(), applied_to=()):
    return {"id": id, "name": name, "labels": {}, "created": "2026-01-30T23:55:00Z",
            "rules": list(rules), "applied_to": list(applied_to)}


def applied_to_server(server_id):
    return {"type": "server", "server": {"id": server_id}, "label_selector": None,
            "applied_to_resources": []}


def applied_to_selector(selector, server_ids=()):
    return {"type": "label_selector", "server": None,
            "label_selector": {"selector": selector},
            "applied_to_resources": [{"type": "server", "server": {"id": i}}
                                     for i in server_ids]}


def fetch(opener):
    return hetzner.parse_snapshot(client(opener).fetch_snapshot())


# =========================================================== off unless configured

def test_no_token_means_no_request_at_all():
    """Merging a branch must not start talking to anybody's provider account,
    the same property test_notify pins for the mail sender."""
    opener = opener_for()
    empty = hetzner.ReadOnlyClient(hetzner.Config(), opener=opener)
    with pytest.raises(hetzner.ProviderError) as caught:
        empty.fetch_snapshot()
    assert caught.value.kind == hetzner.ERROR_NOT_CONFIGURED
    assert opener.requests == [], "a request went out with no token configured"


# --------------------------------------------------- the token, per workspace


@pytest.fixture()
def store():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    hetzner.init(con)
    yield con
    con.close()


OTHER = "other" + "q" * 59  # a second project's token
NEW = "renewed" + "w" * 57


def snap(name, when=None):
    """A snapshot listing one server, so a test can tell whose read it is."""
    when = when or datetime.now(timezone.utc)
    return hetzner.Snapshot(fetched_at=when.isoformat(),
                            servers=({"id": sum(map(ord, name)), "name": name},),
                            firewalls=())


def test_a_token_is_stored_per_workspace_and_read_back_by_the_one_reader(store):
    token_id, hint = hetzner.add_token(store, "  " + TOKEN + "  ", 2)
    assert hetzner.token_for(store, 2, token_id) == TOKEN, "whitespace around a paste is dropped"
    assert hetzner.token_for(store, 2) == TOKEN, "naming no token means the first"
    assert hetzner.token_for(store, 1) == "", "another workspace holds nothing"
    assert hetzner.token_for(store, 1, token_id) == "", "nor can it name workspace 2's token"
    assert hint == "…" + TOKEN[-4:]
    assert hetzner.tokens_to_read(store) == [(2, token_id)]


def test_what_a_screen_may_know_carries_no_token(store):
    token_id, _ = hetzner.add_token(store, TOKEN, 1,
                                    now=datetime(2026, 9, 14, tzinfo=timezone.utc))
    status = hetzner.token_status(store, 1)
    assert status == {"hint": "…" + TOKEN[-4:], "set_at": "2026-09-14T00:00:00+00:00"}
    assert hetzner.tokens(store, 1) == [{"id": token_id, "hint": "…" + TOKEN[-4:],
                                         "set_at": "2026-09-14T00:00:00+00:00"}]
    assert TOKEN not in repr(status) and TOKEN not in repr(hetzner.tokens(store, 1))
    assert hetzner.token_status(store, 2) is None and hetzner.tokens(store, 2) == []


def test_a_second_token_is_held_beside_the_first_and_replaces_nothing(store):
    """The fault of 2026-09-27 (docs/RECORD.md 4.206): a second project's
    token overwrote the first, so one project's servers lost their provider
    view whenever the other's token was connected."""
    first, _ = hetzner.add_token(store, TOKEN, 1)
    second, _ = hetzner.add_token(store, OTHER, 1)
    assert first != second
    assert hetzner.token_for(store, 1, first) == TOKEN
    assert hetzner.token_for(store, 1, second) == OTHER
    assert [t["id"] for t in hetzner.tokens(store, 1)] == [first, second]
    assert hetzner.tokens_to_read(store) == [(1, first), (1, second)]
    assert hetzner.token_status(store, 1)["hint"] == "…" + TOKEN[-4:], "the first, still"


def test_the_same_token_connected_twice_is_one_row(store):
    first, _ = hetzner.add_token(store, TOKEN, 1)
    again, hint = hetzner.add_token(store, " " + TOKEN + "\n", 1)
    assert again == first and hint == "…" + TOKEN[-4:]
    assert store.execute("SELECT COUNT(*) FROM provider_tokens").fetchone()[0] == 1
    # and the same value in another workspace is that workspace's own row
    other_ws, _ = hetzner.add_token(store, TOKEN, 2)
    assert other_ws != first


def test_replace_puts_a_new_value_in_one_tokens_place_and_forgets_what_the_old_read(store):
    now = datetime.now(timezone.utc)
    first, _ = hetzner.add_token(store, TOKEN, 1)
    second, _ = hetzner.add_token(store, OTHER, 1)
    for token_id, name in ((first, "one"), (second, "two")):
        hetzner.store_snapshot(store, snap(name), workspace_id=1, token_id=token_id)
        hetzner.record_fetch(store, now, workspace_id=1, token_id=token_id)
    assert hetzner.replace_token(store, first, NEW, 1) == "…" + NEW[-4:]
    assert hetzner.token_for(store, 1, first) == NEW
    assert hetzner.token_for(store, 1, second) == OTHER, "the other token is untouched"
    assert hetzner.latest_snapshot(store, workspace_id=1, token_id=first) is None, (
        "a snapshot the old value took is never drawn as the new one's")
    assert hetzner.latest_fetch(store, workspace_id=1, token_id=first) is None
    assert hetzner.latest_snapshot(store, workspace_id=1, token_id=second).servers[0]["name"] == "two"
    assert hetzner.latest_fetch(store, workspace_id=1, token_id=second) is not None


def test_replace_refuses_a_value_another_token_holds_and_a_token_not_held(store):
    first, _ = hetzner.add_token(store, TOKEN, 1)
    second, _ = hetzner.add_token(store, OTHER, 1)
    with pytest.raises(hetzner.TokenError) as caught:
        hetzner.replace_token(store, first, OTHER, 1)
    assert OTHER not in str(caught.value)
    assert hetzner.token_for(store, 1, first) == TOKEN
    assert hetzner.replace_token(store, second, NEW, 2) is None, "another workspace's token"
    assert hetzner.replace_token(store, 999, NEW, 1) is None, "a token nobody holds"
    assert hetzner.token_for(store, 1, second) == OTHER
    # the same value back into its own place is not a clash
    assert hetzner.replace_token(store, first, TOKEN, 1) == "…" + TOKEN[-4:]


@pytest.mark.parametrize("bad", [None, "", "   ", 7, "a" * 257, "tok en", "tok\nen", "tok\x00en", "tökén"])
def test_a_token_that_cannot_be_stored_is_refused_without_being_echoed(store, bad):
    with pytest.raises(hetzner.TokenError) as caught:
        hetzner.add_token(store, bad, 1)
    if isinstance(bad, str) and bad.strip():
        assert bad.strip() not in str(caught.value)
    assert hetzner.token_for(store, 1) == ""
    held, _ = hetzner.add_token(store, TOKEN, 1)
    with pytest.raises(hetzner.TokenError):
        hetzner.replace_token(store, held, bad, 1)
    assert hetzner.token_for(store, 1, held) == TOKEN, "a refused replacement changes nothing"


def test_a_short_token_hint_shows_nothing_of_it():
    assert hetzner.token_hint("abcdefghijk") == "…"
    assert hetzner.token_hint("abcdefghijkl") == "…ijkl"


def test_disconnect_takes_the_token_the_snapshots_and_the_fetch_of_one_workspace(store):
    now = datetime.now(timezone.utc)
    for ws in (1, 2):
        hetzner.add_token(store, TOKEN + str(ws), ws)
        hetzner.store_snapshot(store, hetzner.Snapshot(fetched_at=now.isoformat(),
                                                       servers=(), firewalls=()),
                               workspace_id=ws)
        hetzner.record_fetch(store, now, workspace_id=ws)
    assert hetzner.disconnect(store, 1) is True
    assert hetzner.token_for(store, 1) == "" and hetzner.latest_snapshot(store, workspace_id=1) is None
    assert hetzner.latest_fetch(store, workspace_id=1) is None
    # workspace 2 keeps all three
    assert hetzner.token_for(store, 2) == TOKEN + "2"
    assert hetzner.latest_snapshot(store, workspace_id=2) is not None
    assert hetzner.latest_fetch(store, workspace_id=2) is not None
    assert hetzner.disconnect(store, 1) is False, "nothing left to drop is not a second success"


def test_disconnect_takes_one_token_and_leaves_the_workspaces_others(store):
    now = datetime.now(timezone.utc)
    first, _ = hetzner.add_token(store, TOKEN, 1)
    second, _ = hetzner.add_token(store, OTHER, 1)
    for token_id, name in ((first, "one"), (second, "two")):
        hetzner.store_snapshot(store, snap(name), workspace_id=1, token_id=token_id)
        hetzner.record_fetch(store, now, workspace_id=1, token_id=token_id)
    assert hetzner.disconnect(store, 1, second) is True
    assert hetzner.token_for(store, 1, second) == ""
    assert hetzner.latest_snapshot(store, workspace_id=1, token_id=second) is None
    assert hetzner.latest_fetch(store, workspace_id=1, token_id=second) is None
    assert hetzner.token_for(store, 1, first) == TOKEN
    assert hetzner.latest_snapshot(store, workspace_id=1, token_id=first).servers[0]["name"] == "one"
    assert hetzner.latest_fetch(store, workspace_id=1, token_id=first) is not None
    assert hetzner.disconnect(store, 1, second) is False
    assert hetzner.disconnect(store, 2, first) is False, "another workspace cannot drop it"
    assert hetzner.token_for(store, 1, first) == TOKEN


def test_a_workspace_left_with_no_token_shows_nothing_read(store):
    """What was stored while no token was held sits under NO_TOKEN and is
    shown while the workspace holds none. Once a token is connected and then
    dropped, nothing read may stay on a screen with nothing connected."""
    hetzner.store_snapshot(store, snap("before-the-store"), workspace_id=1)
    assert hetzner.latest_snapshot(store, workspace_id=1).servers[0]["name"] == "before-the-store"
    held, _ = hetzner.add_token(store, TOKEN, 1)
    hetzner.store_snapshot(store, snap("read"), workspace_id=1, token_id=held)
    assert hetzner.latest_snapshot(store, workspace_id=1).servers[0]["name"] == "read"
    assert hetzner.disconnect(store, 1, held) is True
    assert hetzner.latest_snapshot(store, workspace_id=1) is None
    assert hetzner.latest_snapshots(store, 1) == []


def test_a_token_id_is_never_handed_out_twice(store):
    """A page still open from before a Disconnect names the old id. Were it
    reused, that page's Read now or Disconnect would act on the token
    connected next."""
    first, _ = hetzner.add_token(store, TOKEN, 1)
    assert hetzner.disconnect(store, 1, first) is True
    second, _ = hetzner.add_token(store, OTHER, 1)
    assert second != first


def test_latest_snapshots_gives_each_token_its_own_newest(store):
    old = datetime.now(timezone.utc) - timedelta(hours=2)
    first, _ = hetzner.add_token(store, TOKEN, 1)
    second, _ = hetzner.add_token(store, OTHER, 1)
    third, _ = hetzner.add_token(store, NEW, 1)
    hetzner.store_snapshot(store, snap("one-old", old), workspace_id=1, token_id=first)
    hetzner.store_snapshot(store, snap("one-new"), workspace_id=1, token_id=first)
    hetzner.store_snapshot(store, snap("two"), workspace_id=1, token_id=second)
    got = hetzner.latest_snapshots(store, 1)
    assert [token_id for token_id, _ in got] == [first, second, third]
    assert got[0][1].servers[0]["name"] == "one-new"
    assert got[1][1].servers[0]["name"] == "two"
    assert got[2][1] is None, "a token with nothing read yet is there, empty"
    assert hetzner.latest_snapshots(store, 2) == []


def test_each_token_is_aged_on_its_own(store):
    now = datetime.now(timezone.utc)
    first, _ = hetzner.add_token(store, TOKEN, 1)
    second, _ = hetzner.add_token(store, OTHER, 1)
    hetzner.store_snapshot(store, snap("fresh", now), workspace_id=1, token_id=first)
    hetzner.store_snapshot(store, snap("stale", now - timedelta(hours=2)),
                           workspace_id=1, token_id=second)
    assert hetzner.needs_refresh(store, now, workspace_id=1, token_id=first) is False
    assert hetzner.needs_refresh(store, now, workspace_id=1, token_id=second) is True


def test_snapshots_and_fetches_are_scoped_to_their_workspace(store):
    now = datetime.now(timezone.utc)
    hetzner.store_snapshot(store, hetzner.Snapshot(fetched_at=now.isoformat(),
                                                   servers=({"id": 1},), firewalls=()),
                           workspace_id=2)
    hetzner.record_fetch(store, now, hetzner.ProviderError("unauthorized", status=401),
                         workspace_id=2)
    assert hetzner.latest_snapshot(store, workspace_id=1) is None
    assert hetzner.latest_fetch(store, workspace_id=1) is None
    assert hetzner.latest_snapshot(store, workspace_id=2).servers == ({"id": 1},)
    assert hetzner.latest_fetch(store, workspace_id=2)["error_status"] == 401
    assert hetzner.needs_refresh(store, now, workspace_id=1) is True
    assert hetzner.needs_refresh(store, now, workspace_id=2) is False


def test_a_database_from_before_the_workspace_column_keeps_its_rows_in_workspace_one(tmp_path):
    """The shape the box had until 2026-09-14: snapshots without a workspace
    and a fetches table keyed on the provider alone."""
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript("""
        CREATE TABLE provider_snapshots (id INTEGER PRIMARY KEY, provider TEXT NOT NULL,
            fetched_at TEXT NOT NULL, servers_json TEXT NOT NULL, firewalls_json TEXT NOT NULL);
        CREATE TABLE provider_fetches (provider TEXT PRIMARY KEY, tried_at TEXT NOT NULL,
            error_kind TEXT, error_status INTEGER);
        INSERT INTO provider_snapshots VALUES (1, 'hetzner', '2026-09-01T00:00:00+00:00', '[{"id": 7}]', '[]');
        INSERT INTO provider_fetches VALUES ('hetzner', '2026-09-01T00:00:00+00:00', 'unauthorized', 401);
    """)
    con.commit()
    hetzner.init(con)
    hetzner.init(con)  # and again, because init runs on every sweep
    assert hetzner.latest_snapshot(con, workspace_id=1).servers == ({"id": 7},)
    assert hetzner.latest_fetch(con, workspace_id=1)["error_status"] == 401
    assert hetzner.latest_snapshot(con, workspace_id=2) is None
    assert hetzner.token_status(con, 1) is None
    con.close()


OLD_SHAPE_2026_09_14 = """
    CREATE TABLE provider_snapshots (id INTEGER PRIMARY KEY, provider TEXT NOT NULL,
        fetched_at TEXT NOT NULL, servers_json TEXT NOT NULL, firewalls_json TEXT NOT NULL,
        workspace_id INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE provider_fetches (workspace_id INTEGER NOT NULL DEFAULT 1,
        provider TEXT NOT NULL, tried_at TEXT NOT NULL, error_kind TEXT,
        error_status INTEGER, PRIMARY KEY (workspace_id, provider));
    CREATE TABLE provider_tokens (workspace_id INTEGER NOT NULL, provider TEXT NOT NULL,
        token TEXT NOT NULL, token_hint TEXT NOT NULL, set_at TEXT NOT NULL,
        PRIMARY KEY (workspace_id, provider));
"""


def old_shape_database(path):
    """The shape production had from 2026-09-14 to 2026-09-27: one token per
    workspace and provider, keyed by the two, and reads carrying no token.
    Workspace 3 holds a token with two snapshots and a fetch row, workspace 4
    a snapshot and a fetch row read while it held none."""
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(OLD_SHAPE_2026_09_14 + f"""
        INSERT INTO provider_tokens VALUES (3, 'hetzner', '{TOKEN}', '…{TOKEN[-4:]}',
            '2026-09-20T00:00:00+00:00');
        INSERT INTO provider_snapshots VALUES (1, 'hetzner', '2026-09-26T00:00:00+00:00',
            '[{{"id": 1, "name": "older"}}]', '[]', 3);
        INSERT INTO provider_snapshots VALUES (2, 'hetzner', '2026-09-27T00:00:00+00:00',
            '[{{"id": 2, "name": "newer"}}]', '[]', 3);
        INSERT INTO provider_snapshots VALUES (3, 'hetzner', '2026-09-01T00:00:00+00:00',
            '[{{"id": 3, "name": "no-token"}}]', '[]', 4);
        INSERT INTO provider_fetches VALUES (3, 'hetzner', '2026-09-27T00:00:00+00:00',
            'unauthorized', 401);
        INSERT INTO provider_fetches VALUES (4, 'hetzner', '2026-09-01T00:00:00+00:00',
            NULL, NULL);
    """)
    con.commit()
    return con


def test_a_database_from_before_several_tokens_keeps_its_token_and_everything_it_read(tmp_path):
    con = old_shape_database(tmp_path / "old.db")
    hetzner.init(con)
    hetzner.init(con)  # and again, because init runs on every sweep and request
    [held] = hetzner.tokens(con, 3)
    assert hetzner.token_for(con, 3, held["id"]) == TOKEN
    assert held["hint"] == "…" + TOKEN[-4:] and held["set_at"] == "2026-09-20T00:00:00+00:00"
    assert hetzner.latest_snapshot(con, workspace_id=3, token_id=held["id"]).servers[0]["name"] == "newer"
    assert hetzner.latest_fetch(con, workspace_id=3, token_id=held["id"])["error_status"] == 401
    # read while no token was held: kept under NO_TOKEN and still shown
    assert hetzner.latest_snapshot(con, workspace_id=4).servers[0]["name"] == "no-token"
    assert hetzner.latest_fetch(con, workspace_id=4)["tried_at"] == "2026-09-01T00:00:00+00:00"
    assert con.execute("SELECT COUNT(*) FROM provider_snapshots").fetchone()[0] == 3
    # and the rebuilt table takes a second token beside the first
    second, _ = hetzner.add_token(con, OTHER, 3)
    assert second != held["id"] and len(hetzner.tokens(con, 3)) == 2
    con.close()


def test_a_migration_another_process_finished_while_this_one_waited_is_not_run_again():
    """After a deploy the ingest and the sweep can both open the database
    first. Each migration takes the write lock and then looks again, so the
    one that waited finds the work done. Run twice, the token rebuild keeps
    every row and renumbers the token, which leaves everything it read
    pointing at an id nobody holds, and nothing fails to say so.

    The interleaving is set here rather than hoped for: the first look says
    not done, and the look under the lock says done, as it would once another
    process finished in between."""
    con = sqlite3.connect(":memory:")
    looks = iter([False, True])
    ran = []
    hetzner._migrate_once(con, lambda: next(looks), lambda c: ran.append(1))
    assert ran == []
    assert not con.in_transaction, "the lock is let go"


def test_a_migration_that_fails_halfway_leaves_the_table_as_it_was(tmp_path):
    con = old_shape_database(tmp_path / "old.db")

    def breaks_after_the_rename(c):
        c.execute("ALTER TABLE provider_tokens RENAME TO provider_tokens_old")
        raise RuntimeError("the disk filled up")

    with pytest.raises(RuntimeError):
        hetzner._migrate_once(con, lambda: False, breaks_after_the_rename)
    assert con.execute("SELECT COUNT(*) FROM provider_tokens").fetchone()[0] == 1
    assert con.execute("SELECT name FROM sqlite_master WHERE name = 'provider_tokens_old'"
                       ).fetchone() is None
    hetzner.init(con)
    assert hetzner.token_for(con, 3) == TOKEN
    con.close()


def test_four_processes_opening_one_old_database_together_all_finish(tmp_path):
    """The same start after a deploy, with real threads and a real file. It
    does not prove the second look above, because SQLite's own locking lets
    one of them finish before the others look at all (measured 2026-09-27).
    It proves the end state: every opener finishes and the token still
    reaches what it read."""
    import threading

    path = tmp_path / "old.db"
    old_shape_database(path).close()
    start = threading.Barrier(4)
    failures = []

    def bring_forward():
        con = sqlite3.connect(path, timeout=20)
        con.row_factory = sqlite3.Row
        try:
            start.wait()
            hetzner.init(con)
        except Exception as exc:  # noqa: BLE001 - collected and asserted below
            failures.append(repr(exc))
        finally:
            con.close()

    threads = [threading.Thread(target=bring_forward) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert failures == []
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    [held] = hetzner.tokens(con, 3)
    assert hetzner.latest_snapshot(con, workspace_id=3, token_id=held["id"]).servers[0]["name"] == "newer"
    assert hetzner.latest_fetch(con, workspace_id=3, token_id=held["id"])["error_status"] == 401
    assert con.execute("SELECT COUNT(*) FROM provider_snapshots").fetchone()[0] == 3
    assert con.execute("SELECT COUNT(*) FROM provider_fetches").fetchone()[0] == 2
    con.close()


def test_a_client_built_for_a_token_carries_it_and_nothing_prints_it():
    client = hetzner.client_for(TOKEN, opener=opener_for())
    assert client.config.token == TOKEN
    assert TOKEN not in repr(client.config)


def test_a_config_never_prints_its_token():
    """A Config can land in a log line or a traceback. SI-5: it is their
    credential and it does not belong in our output."""
    cfg = hetzner.Config(token=TOKEN)
    assert TOKEN not in repr(cfg)
    assert TOKEN not in str(cfg)
    assert TOKEN not in f"{cfg}"


def test_the_authorization_header_is_the_documented_bearer_form():
    opener = opener_for(servers=[server()])
    client(opener).fetch_servers()
    assert opener.requests[0].get_header("Authorization") == f"Bearer {TOKEN}"


# ================================================================ read only

def test_every_request_is_a_get():
    opener = opener_for(servers=[server()], firewalls=[firewall()])
    client(opener).fetch_snapshot()
    assert opener.requests, "the fetch issued no request at all"
    for request in opener.requests:
        assert request.get_method() == "GET"
        assert request.data is None, "a request carried a body"


def test_every_request_goes_to_the_documented_api_over_https():
    opener = opener_for(servers=[server()], firewalls=[firewall()])
    client(opener).fetch_snapshot()
    for request in opener.requests:
        assert request.full_url.startswith("https://api.hetzner.cloud/v1/")


SOURCE = pathlib.Path(hetzner.__file__).read_text()
TREE = ast.parse(SOURCE)


def test_the_source_builds_no_request_that_is_not_a_get():
    """The structural half of SI-3. Behaviour tests prove today's code is read
    only. This one fails if somebody later adds a request with a method or a
    body, which is the change worth catching in review."""
    built = 0
    for node in ast.walk(TREE):
        if not isinstance(node, ast.Call):
            continue
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(
            node.func, "id", "")
        if name != "Request":
            continue
        built += 1
        keywords = {kw.arg: kw.value for kw in node.keywords}
        assert "data" not in keywords, "a request was built with a body"
        assert len(node.args) == 1, "a request was built with a positional body"
        method = keywords.get("method")
        assert isinstance(method, ast.Constant) and method.value == "GET", (
            "a request was built without an explicit GET")
    assert built == 1, "there should be exactly one place that builds a request"


def test_the_source_contains_no_write_verb():
    """Checked over string constants rather than the raw text, so the prose in
    the docstrings cannot make this pass or fail by accident."""
    forbidden = {"POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    for node in ast.walk(TREE):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value.strip() not in forbidden, (
                f"the module names the {node.value} method somewhere")


def test_the_source_uses_no_write_path_on_the_provider():
    """None of the provider's write endpoints may appear as a path constant.
    /firewalls/{id}/actions/set_rules is the one that would change a rule."""
    for node in ast.walk(TREE):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert "/actions" not in node.value, "a provider action endpoint appeared"


def test_a_redirect_is_not_followed():
    """PRODUCT.md 4f gives the reason on the agent side and it holds here:
    following a redirect would re-send the token to wherever the response
    points."""
    opener = FakeOpener(lambda request: http_error(302))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_REDIRECTED
    assert len(opener.requests) == 1, "the token was sent a second time"


def test_the_opener_this_module_builds_refuses_redirects():
    """The injected opener is a test seam. This checks the real one, which is
    what runs in production."""
    opener = hetzner.build_opener(ssl.create_default_context())
    handlers = [type(handler).__name__ for handler in opener.handlers]
    assert "_NoRedirect" in handlers
    assert "HTTPRedirectHandler" not in handlers


# ============================================ v4 and v6 are never merged (4b)

def test_a_rule_with_both_families_keeps_them_apart():
    """The shape PRODUCT.md 4b measured: 16 of 17 rules on the real account
    carried ::/0 alongside 0.0.0.0/0."""
    fw = firewall(rules=[rule(source_ips=["0.0.0.0/0", "::/0"])])
    inventory = fetch(opener_for(firewalls=[fw]))
    sources = inventory.firewalls[0].rules[0].source_ips
    assert sources.v4 == ("0.0.0.0/0",)
    assert sources.v6 == ("::/0",)
    assert sources.has_v4 and sources.has_v6


def test_a_rule_with_only_ipv4_says_nothing_about_ipv6():
    """The 17th rule. Reading a v6 answer out of a v4 entry is exactly the
    error 4b was written after."""
    fw = firewall(rules=[rule(source_ips=["0.0.0.0/0"])])
    sources = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].source_ips
    assert sources.v4 == ("0.0.0.0/0",)
    assert sources.v6 == ()
    assert sources.has_v4 is True
    assert sources.has_v6 is False


def test_a_rule_with_only_ipv6_says_nothing_about_ipv4():
    fw = firewall(rules=[rule(source_ips=["::/0"])])
    sources = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].source_ips
    assert sources.v6 == ("::/0",)
    assert sources.v4 == ()
    assert sources.has_v4 is False


def test_a_rule_with_no_sources_at_all_is_empty_in_both_families():
    fw = firewall(rules=[rule(source_ips=[])])
    sources = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].source_ips
    assert sources.empty is True
    assert sources.has_v4 is False and sources.has_v6 is False


def test_the_narrow_entry_and_the_wide_one_are_both_kept_in_order():
    """The firewall-mqtt finding in 4b: tcp/22 described "only SSH via Netbird"
    lists 100.64.0.0/10 AND 0.0.0.0/0, and the second makes the first do
    nothing. Both entries have to survive, in order, for anyone to see it."""
    fw = firewall(name="firewall-mqtt", rules=[
        rule(port="22", source_ips=["100.64.0.0/10", "0.0.0.0/0"],
             description="only SSH via Netbird")])
    parsed = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0]
    assert parsed.source_ips.v4 == ("100.64.0.0/10", "0.0.0.0/0")
    assert parsed.description == "only SSH via Netbird"
    assert parsed.port == "22"


def test_single_hosts_are_classified_by_family_too():
    fw = firewall(rules=[rule(source_ips=["192.0.2.1/32",
                                          "2001:db8:ff00:42::8329/128"])])
    sources = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].source_ips
    assert sources.v4 == ("192.0.2.1/32",)
    assert sources.v6 == ("2001:db8:ff00:42::8329/128",)


def test_an_entry_we_cannot_classify_is_kept_verbatim_not_dropped():
    """Dropping it would make the rule look narrower than it is, which is a
    finding nobody measured."""
    fw = firewall(rules=[rule(source_ips=["0.0.0.0/0", "something-new"])])
    sources = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].source_ips
    assert sources.unparsed == ("something-new",)
    assert sources.v4 == ("0.0.0.0/0",)


def test_an_outbound_rule_splits_its_destinations():
    fw = firewall(rules=[rule(direction="out", protocol="udp", port="53",
                              destination_ips=["0.0.0.0/0", "::/0"])])
    parsed = fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0]
    assert parsed.destination_ips.v4 == ("0.0.0.0/0",)
    assert parsed.destination_ips.v6 == ("::/0",)
    assert parsed.source_ips.empty is True


def test_a_port_range_is_kept_as_the_provider_wrote_it():
    """The range syntax is theirs. Expanding 1024-5000 here would be us
    reshaping evidence."""
    fw = firewall(rules=[rule(port="1024-5000", source_ips=["0.0.0.0/0"])])
    assert fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].port == "1024-5000"


def test_a_protocol_without_a_port_keeps_a_null_port():
    """The spec says port is "only applicable for protocols tcp and udp", so
    an icmp rule carries null and that is not a missing value."""
    fw = firewall(rules=[rule(protocol="icmp", port=None, source_ips=["::/0"])])
    assert fetch(opener_for(firewalls=[fw])).firewalls[0].rules[0].port is None


def test_a_non_string_address_entry_is_malformed_rather_than_half_read():
    fw = firewall(rules=[rule(source_ips=["0.0.0.0/0", 22])])
    with pytest.raises(hetzner.ProviderError) as caught:
        fetch(opener_for(firewalls=[fw]))
    assert caught.value.kind == hetzner.ERROR_MALFORMED


# ================================================ servers and the attachment

def test_a_server_with_no_firewall_attached():
    """PRODUCT.md 4b: four servers on the real account had "firewalls": []. An
    empty tuple means the provider said none."""
    inventory = fetch(opener_for(servers=[server(name="wazuh", firewalls=())]))
    assert inventory.servers[0].firewalls == ()
    assert inventory.firewalls_for_server(1) == []


def test_a_server_with_no_primary_ipv4_reports_none_and_keeps_its_ipv6():
    inventory = fetch(opener_for(servers=[server(ipv4=None, ipv6="2001:20::/64")]))
    assert inventory.servers[0].ipv4 is None
    assert inventory.servers[0].ipv6_network == "2001:20::/64"


def test_a_server_with_no_ipv6_reports_none_and_keeps_its_ipv4():
    inventory = fetch(opener_for(servers=[server(ipv4="1.2.3.4", ipv6=None)]))
    assert inventory.servers[0].ipv6_network is None
    assert inventory.servers[0].ipv4 == "1.2.3.4"


def test_the_ipv6_field_is_the_network_the_provider_assigned():
    """public_net.ipv6.ip is documented as the IPv6 network assigned to the
    server, example 2001:db8::/64. It is not the address a service is bound
    to, and the field name has to keep saying so."""
    inventory = fetch(opener_for(servers=[server(ipv6="2001:20:c17:1::/64")]))
    assert inventory.servers[0].ipv6_network == "2001:20:c17:1::/64"
    assert hasattr(inventory.servers[0], "ipv6_network")
    assert not hasattr(inventory.servers[0], "ipv6")


def test_one_firewall_attached_to_several_servers():
    fw = firewall(id=7, name="shared", rules=[rule(source_ips=["0.0.0.0/0"])],
                  applied_to=[applied_to_server(1), applied_to_server(2)])
    servers = [server(id=1, name="a", firewalls=[(7, "applied")]),
               server(id=2, name="b", firewalls=[(7, "applied")])]
    inventory = fetch(opener_for(servers=servers, firewalls=[fw]))
    assert [t.server_id for t in inventory.firewalls[0].applied_to] == [1, 2]
    for server_id in (1, 2):
        pairs = inventory.firewalls_for_server(server_id)
        assert len(pairs) == 1
        ref, found = pairs[0]
        assert ref.id == 7 and ref.status == "applied"
        assert found is not None and found.name == "shared"


def test_a_label_selector_attachment_names_the_servers_it_resolved_to():
    fw = firewall(applied_to=[applied_to_selector("env=prod", server_ids=[3, 4])])
    target = fetch(opener_for(firewalls=[fw])).firewalls[0].applied_to[0]
    assert target.type == "label_selector"
    assert target.label_selector == "env=prod"
    assert target.resolved_server_ids == (3, 4)
    assert target.server_id is None


def test_a_pending_attachment_is_not_read_as_applied():
    inventory = fetch(opener_for(servers=[server(firewalls=[(7, "pending")])]))
    assert inventory.servers[0].firewalls[0].status == "pending"


def test_a_firewall_id_we_did_not_fetch_reads_as_unknown_not_as_absent():
    """The two GETs are separate requests and a firewall can appear or vanish
    between them. Reporting that as "no firewall" would invent a finding."""
    inventory = fetch(opener_for(servers=[server(firewalls=[(99, "applied")])],
                                 firewalls=[]))
    (ref, found), = inventory.firewalls_for_server(1)
    assert ref.id == 99
    assert found is None


def test_a_firewall_applied_to_nothing_is_visible_as_such():
    fw = firewall(applied_to=[])
    assert fetch(opener_for(firewalls=[fw])).firewalls[0].applied_to == ()


def test_an_empty_project_parses_to_an_empty_inventory():
    inventory = fetch(opener_for())
    assert inventory.servers == () and inventory.firewalls == ()


# ================================================================== failures

@pytest.mark.parametrize("status,kind", [
    (401, hetzner.ERROR_UNAUTHORIZED),
    (403, hetzner.ERROR_FORBIDDEN),
    (429, hetzner.ERROR_RATE_LIMITED),
    (500, hetzner.ERROR_HTTP),
    (502, hetzner.ERROR_HTTP),
])
def test_a_status_becomes_a_typed_kind(status, kind):
    opener = FakeOpener(lambda request: http_error(status))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == kind
    assert caught.value.status == status


def test_an_auth_failure_stores_nothing(tmp_path, monkeypatch):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "cp.db"))
    con = db.connect()
    db.init(con)
    hetzner.init(con)
    opener = FakeOpener(lambda request: http_error(401))
    with pytest.raises(hetzner.ProviderError):
        client(opener).fetch_snapshot()
    assert con.execute("SELECT COUNT(*) c FROM provider_snapshots").fetchone()["c"] == 0
    con.close()


def test_a_rate_limit_carries_the_documented_reset_header():
    """The spec's Rate Limiting section: RateLimit-Reset is "a UNIX timestamp
    of the point in time when your rate limit will have recovered"."""
    opener = FakeOpener(lambda request: http_error(
        429, header_pairs={"RateLimit-Limit": 3600, "RateLimit-Remaining": 0,
                           "RateLimit-Reset": 1755000000}))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_RATE_LIMITED
    assert caught.value.rate_limit_reset_unix == 1755000000


def test_the_rate_limit_headers_are_read_on_a_good_response():
    opener = opener_for(servers=[server()],
                        header_pairs={"RateLimit-Limit": 3600,
                                      "RateLimit-Remaining": 3599,
                                      "RateLimit-Reset": 1755000000})
    api = client(opener)
    api.fetch_servers()
    assert api.rate_limit.limit == 3600
    assert api.rate_limit.remaining == 3599
    assert api.rate_limit.reset_unix == 1755000000


def test_missing_rate_limit_headers_are_none_rather_than_zero():
    """Zero remaining would read as "we are rate limited", which is a finding
    nobody measured."""
    api = client(opener_for(servers=[server()]))
    api.fetch_servers()
    assert api.rate_limit.remaining is None


@pytest.mark.parametrize("failure", [
    urllib.error.URLError("no route to host"),
    TimeoutError("timed out"),
    ConnectionResetError("reset"),
    ssl.SSLError("handshake"),
    OSError("something"),
])
def test_a_network_failure_is_one_typed_kind(failure):
    opener = FakeOpener(lambda request: failure)
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_NETWORK


def test_a_connection_that_dies_mid_body_is_a_network_failure():
    class Dying(FakeResponse):
        def read(self, size=-1):
            raise ConnectionResetError("reset")

    opener = FakeOpener(lambda request: Dying({}))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_NETWORK


@pytest.mark.parametrize("body", [
    "not json at all",
    "[1, 2, 3]",                                  # JSON but not an object
    '"a string"',
    "null",
    json.dumps({"meta": {}}),                     # the list key is missing
    json.dumps({"servers": "not a list"}),
    json.dumps({"servers": [1, 2]}),              # items are not objects
    b"\xff\xfe not utf-8",
])
def test_a_malformed_response_is_typed_and_never_half_parsed(body):
    opener = FakeOpener(lambda request: FakeResponse(body))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_MALFORMED


def test_a_server_row_missing_its_id_is_malformed():
    opener = FakeOpener(lambda request: FakeResponse(
        envelope("servers", [{"name": "box", "status": "running", "public_net": {}}])))
    with pytest.raises(hetzner.ProviderError) as caught:
        hetzner.parse_snapshot(hetzner.Snapshot(
            fetched_at="now", servers=tuple(client(opener).fetch_servers())))
    assert caught.value.kind == hetzner.ERROR_MALFORMED


def test_an_oversized_body_is_refused_rather_than_read_into_memory():
    huge = json.dumps({"servers": ["x" * hetzner.MAX_RESPONSE_BYTES]})
    opener = FakeOpener(lambda request: FakeResponse(huge))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_MALFORMED


def test_the_providers_own_words_never_leave_this_module():
    """SI-8 in spirit. Their `message` field is free text they wrote and it
    does not belong in our exception, our log or our database."""
    secret = "your token abc123 was rejected by node eu-central-7"
    opener = FakeOpener(lambda request: http_error(
        401, body={"error": {"code": "unauthorized", "message": secret}}))
    with pytest.raises(hetzner.ProviderError) as caught:
        client(opener).fetch_servers()
    assert secret not in str(caught.value)
    assert secret not in repr(caught.value)
    assert str(caught.value) == hetzner.ERROR_UNAUTHORIZED


def test_a_failure_on_the_second_half_discards_the_first():
    """Servers fetched, firewalls refused. An empty firewall list would read as
    "no cloud firewalls exist", and nobody measured that."""
    def respond(request):
        if "/servers" in request.full_url:
            return FakeResponse(envelope("servers", [server()]))
        return http_error(500)

    with pytest.raises(hetzner.ProviderError) as caught:
        client(FakeOpener(respond)).fetch_snapshot()
    assert caught.value.kind == hetzner.ERROR_HTTP


# ================================================================ pagination

def paged_opener(pages_by_key):
    """pages_by_key maps a list key to a list of pages, each page a list."""
    def respond(request):
        key = "servers" if "/servers" in request.full_url else "firewalls"
        page = int(dict(pair.split("=") for pair in
                        request.full_url.split("?")[1].split("&"))["page"])
        pages = pages_by_key.get(key, [[]])
        index = page - 1
        items = pages[index] if index < len(pages) else []
        next_page = page + 1 if index + 1 < len(pages) else None
        return FakeResponse(envelope(key, items, next_page=next_page))
    return FakeOpener(respond)


def test_every_page_is_fetched_and_kept_in_order():
    opener = paged_opener({"servers": [[server(id=1, name="a")],
                                       [server(id=2, name="b")],
                                       [server(id=3, name="c")]]})
    names = [s.name for s in fetch(opener).servers]
    assert names == ["a", "b", "c"]


def test_per_page_never_exceeds_the_documented_maximum():
    """The spec's Pagination section: "the maximum value is 50 except otherwise
    specified in the documentation", and neither endpoint here specifies
    otherwise. Asking for more would be rejected or silently clamped."""
    opener = opener_for(servers=[server()])
    client(opener).fetch_servers()
    assert "per_page=50" in opener.requests[0].full_url
    assert hetzner.PER_PAGE <= 50


def test_paging_starts_at_page_one():
    opener = opener_for(servers=[server()])
    client(opener).fetch_servers()
    assert "page=1" in opener.requests[0].full_url


def test_a_next_page_that_does_not_advance_stops_instead_of_looping():
    """A broken or hostile response must not be able to spin this forever."""
    opener = FakeOpener(lambda request: FakeResponse(
        envelope("servers", [server()], next_page=1)))
    items = client(opener).fetch_servers()
    assert len(items) == 1
    assert len(opener.requests) == 1


def test_a_null_next_page_ends_the_walk():
    opener = FakeOpener(lambda request: FakeResponse(
        envelope("servers", [server()], next_page=None)))
    client(opener).fetch_servers()
    assert len(opener.requests) == 1


def test_running_out_of_pages_raises_rather_than_truncating():
    """A partial inventory presented as a whole one is the failure PRODUCT.md
    4b exists to prevent."""
    counter = {"page": 0}

    def respond(request):
        counter["page"] += 1
        return FakeResponse(envelope("servers", [server(id=counter["page"])],
                                     next_page=counter["page"] + 1))

    with pytest.raises(hetzner.ProviderError) as caught:
        client(FakeOpener(respond)).fetch_servers()
    assert caught.value.kind == hetzner.ERROR_TOO_MANY_PAGES
    assert counter["page"] == hetzner.MAX_PAGES, "the cap did not stop the walk"


# =================================================================== storage

@pytest.fixture()
def con(tmp_path):
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    hetzner.init(connection)
    yield connection
    connection.close()


def test_init_is_idempotent(con):
    hetzner.init(con)
    hetzner.init(con)
    assert con.execute("SELECT COUNT(*) c FROM provider_snapshots").fetchone()["c"] == 0


def test_a_snapshot_round_trips_exactly_as_the_provider_sent_it(con):
    raw_server = server(id=5, name="almabox", firewalls=[(7, "applied")])
    raw_firewall = firewall(id=7, rules=[rule(source_ips=["0.0.0.0/0", "::/0"])])
    snapshot = client(opener_for(servers=[raw_server],
                                 firewalls=[raw_firewall])).fetch_snapshot()
    hetzner.store_snapshot(con, snapshot)

    read_back = hetzner.latest_snapshot(con)
    assert read_back.servers == (raw_server,), "the server was reshaped on the way in"
    assert read_back.firewalls == (raw_firewall,)
    assert read_back.fetched_at == snapshot.fetched_at


def test_the_newest_snapshot_wins_and_the_older_one_is_kept(con):
    older = hetzner.Snapshot(fetched_at="2026-08-15T09:00:00+00:00",
                             servers=(server(name="old"),))
    newer = hetzner.Snapshot(fetched_at="2026-08-15T10:00:00+00:00",
                             servers=(server(name="new"),))
    hetzner.store_snapshot(con, older)
    hetzner.store_snapshot(con, newer)
    assert hetzner.latest_snapshot(con).servers[0]["name"] == "new"
    assert con.execute("SELECT COUNT(*) c FROM provider_snapshots").fetchone()["c"] == 2


def test_no_snapshot_reads_as_none_rather_than_empty(con):
    """Never fetched and fetched nothing are different facts and the evidence
    panel will need to tell them apart."""
    assert hetzner.latest_snapshot(con) is None


def test_the_database_never_contains_the_token(con):
    snapshot = client(opener_for(servers=[server()])).fetch_snapshot()
    hetzner.store_snapshot(con, snapshot)
    dumped = "\n".join(con.iterdump())
    assert TOKEN not in dumped


def test_a_snapshot_for_another_provider_is_kept_apart(con):
    hetzner.store_snapshot(con, hetzner.Snapshot(fetched_at="now",
                                                 servers=(server(name="h"),)))
    assert hetzner.latest_snapshot(con, provider="somewhere-else") is None
    assert hetzner.latest_snapshot(con).servers[0]["name"] == "h"


# ======================================================================= CLI

def cli_box(tmp_path, monkeypatch, opener=None, token=TOKEN):
    """A database the CLI can open, holding workspace 1's token when one is
    given, and a provider that answers through `opener`."""
    path = tmp_path / "cp.db"
    monkeypatch.setenv(db.DB_ENV, str(path))
    connection = db.connect(str(path))
    db.init(connection)
    hetzner.init(connection)
    if token:
        hetzner.add_token(connection, token, 1)
    connection.close()
    if opener is not None:
        monkeypatch.setattr(hetzner, "client_for",
                            lambda tok, opener=None, _o=opener: client(_o))
    return path


def stored_snapshot(path):
    connection = db.connect(str(path))
    try:
        return hetzner.latest_snapshot(connection, workspace_id=1)
    finally:
        connection.close()


def test_the_cli_says_not_connected_and_writes_nothing(tmp_path, monkeypatch, capsys):
    path = cli_box(tmp_path, monkeypatch, opener=opener_for(servers=[server()]), token="")
    assert hetzner_cli.main(["fetch"]) == 0
    assert "not connected" in capsys.readouterr().out
    assert stored_snapshot(path) is None, "a snapshot was stored with no token"


def test_the_cli_prints_each_family_on_its_own_line(tmp_path, monkeypatch, capsys):
    fw = firewall(name="firewall-mqtt", rules=[
        rule(port="22", source_ips=["100.64.0.0/10", "0.0.0.0/0"])])
    cli_box(tmp_path, monkeypatch, opener_for(
        servers=[server(name="almabox", firewalls=[(42, "applied")])], firewalls=[fw]))
    assert hetzner_cli.main(["show"]) == 0
    out = capsys.readouterr().out
    assert "source ipv4: 100.64.0.0/10, 0.0.0.0/0" in out
    assert "source ipv6: none listed" in out
    assert "almabox" in out
    assert "firewall 42 applied" in out


def test_the_cli_names_a_server_with_no_firewall(tmp_path, monkeypatch, capsys):
    cli_box(tmp_path, monkeypatch, opener_for(servers=[server(name="wazuh", firewalls=())]))
    hetzner_cli.main(["show"])
    assert "no firewall attached" in capsys.readouterr().out


def test_the_cli_show_stores_nothing(tmp_path, monkeypatch, capsys):
    path = cli_box(tmp_path, monkeypatch, opener_for(servers=[server()]))
    assert hetzner_cli.main(["show"]) == 0
    capsys.readouterr()
    assert stored_snapshot(path) is None, "show wrote to the database"


def test_the_cli_fetch_stores_one_snapshot_for_the_workspace(tmp_path, monkeypatch, capsys):
    path = cli_box(tmp_path, monkeypatch, opener_for(servers=[server(name="almabox")]))
    assert hetzner_cli.main(["fetch", "--workspace", "1"]) == 0
    assert "snapshot stored for workspace 1" in capsys.readouterr().out
    assert stored_snapshot(path).servers[0]["name"] == "almabox"
    connection = db.connect(str(path))
    assert hetzner.latest_snapshot(connection, workspace_id=2) is None
    connection.close()


def test_the_cli_reads_the_workspace_it_is_told(tmp_path, monkeypatch, capsys):
    path = cli_box(tmp_path, monkeypatch, opener_for(servers=[server()]), token="")
    connection = db.connect(str(path))
    hetzner.add_token(connection, TOKEN, 2)
    connection.close()
    assert hetzner_cli.main(["fetch"]) == 0
    assert "not connected: workspace 1" in capsys.readouterr().out
    assert hetzner_cli.main(["fetch", "--workspace", "2"]) == 0
    assert "snapshot stored for workspace 2" in capsys.readouterr().out


def test_the_cli_latest_prints_what_was_stored(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "cp.db"))
    connection = db.connect(str(tmp_path / "cp.db"))
    db.init(connection)
    hetzner.init(connection)
    hetzner.store_snapshot(connection, hetzner.Snapshot(
        fetched_at="2026-08-15T10:00:00+00:00", servers=(server(name="almabox"),)))
    connection.close()
    assert hetzner_cli.main(["latest"]) == 0
    out = capsys.readouterr().out
    assert "2026-08-15T10:00:00+00:00" in out
    assert "almabox" in out


def test_the_cli_latest_with_nothing_stored(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(db.DB_ENV, str(tmp_path / "cp.db"))
    db.connect(str(tmp_path / "cp.db")).close()
    assert hetzner_cli.main(["latest"]) == 0
    assert "no snapshot stored yet" in capsys.readouterr().out


def test_the_cli_reports_a_failure_as_a_kind_and_exits_one(tmp_path, monkeypatch, capsys):
    secret = "token abc123 rejected"
    cli_box(tmp_path, monkeypatch, FakeOpener(lambda request: http_error(
        401, body={"error": {"code": "unauthorized", "message": secret}})))
    assert hetzner_cli.main(["fetch"]) == 1
    captured = capsys.readouterr()
    assert "unauthorized" in captured.err
    assert secret not in captured.err + captured.out
    assert TOKEN not in captured.err + captured.out


def test_the_cli_draws_no_conclusion(tmp_path, monkeypatch, capsys):
    """The writing rules. This prints what the provider said and stops."""
    fw = firewall(rules=[rule(source_ips=["0.0.0.0/0", "::/0"])])
    cli_box(tmp_path, monkeypatch, opener_for(servers=[server()], firewalls=[fw]))
    hetzner_cli.main(["show"])
    out = capsys.readouterr().out.lower()
    for forbidden in ("secure", "protected", "safe", "compliant", "exposed",
                      "reachable", "vulnerable", "risk", "warning"):
        assert forbidden not in out, f"the output draws a conclusion: {forbidden}"


# ======================================= the token does not go through a proxy
#
# `docs/RECORD.md` 4.83. `app/authz.py` was given this guard when it was
# written and this module was not, so every request here, each carrying the API
# token in an Authorization header, could be rerouted by one environment
# variable. `tests/test_authz.py` has the same pair of tests and they are
# deliberately the same shape, because two guards for one hole should read the
# same or the difference reads as deliberate.


def handlers_handed_to_build_opener(monkeypatch):
    """What `build_opener` was handed, which is not the same as what the opener
    ends up holding.

    **An empty `ProxyHandler` is not in `opener.handlers` at all.**
    `ProxyHandler.__init__` sets one `<scheme>_open` method per proxy in the
    dict it is given, so with `{}` it defines none, and `add_handler` only
    inserts a handler that has at least one method it recognises. Asserting
    against the built opener therefore fails whether the guard is there or not,
    which is a test that can only mislead. `tests/test_authz.py` captures the
    arguments for the same reason.
    """
    seen = []
    real = urllib.request.build_opener

    def build(*handlers):
        seen.extend(handlers)
        return real(*handlers)

    monkeypatch.setattr(hetzner.urllib.request, "build_opener", build)
    hetzner.build_opener()
    return seen


def test_the_opener_is_built_with_proxies_turned_off(monkeypatch):
    """The structural half. `urllib.request.build_opener` installs a bare
    `ProxyHandler()` unless it is handed one, and a bare one reads
    `https_proxy` from the environment."""
    handed = handlers_handed_to_build_opener(monkeypatch)
    proxy_handlers = [h for h in handed
                      if isinstance(h, urllib.request.ProxyHandler)]
    assert proxy_handlers, "build_opener was not handed a ProxyHandler"
    assert all(h.proxies == {} for h in proxy_handlers), (
        "the ProxyHandler carries proxies, so a provider read can be rerouted")


def test_the_redirect_guard_survived_the_proxy_handler(monkeypatch):
    """A second handler was added beside the redirect one. Worth an assertion
    rather than an assumption."""
    handed = handlers_handed_to_build_opener(monkeypatch)
    assert any(isinstance(h, hetzner._NoRedirect) for h in handed)


def test_an_https_proxy_in_the_environment_does_not_reroute_a_provider_read(monkeypatch):
    """The behaviour the structural test stands in for, measured on the real
    opener rather than a fake one.

    No socket is opened. `http.client.HTTPSConnection` is replaced, so what is
    asserted is the host urllib decided to connect to. With a bare
    `ProxyHandler` that host is the proxy, and this test is red against the
    code as it stood.
    """
    monkeypatch.setenv("https_proxy", "http://198.51.100.9:3128")
    monkeypatch.setenv("HTTPS_PROXY", "http://198.51.100.9:3128")
    connected = []
    tunnelled = []

    class RecordingConnection:
        # urllib reads this off the class before it builds one.
        debuglevel = 0

        def __init__(self, host, timeout=None, **kwargs):
            connected.append(host)
            self.host = host
            self.sock = None

        def set_debuglevel(self, level):
            pass

        def set_tunnel(self, host, port=None, headers=None):
            # urllib calls this only when it is tunnelling through an HTTPS
            # proxy. Recording it rather than letting the absence raise, so a
            # regression fails on the assertion below with the host named,
            # instead of on an AttributeError that has to be interpreted.
            tunnelled.append(host)

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            raise OSError("nothing is served here, the host is the assertion")

        def close(self):
            pass

    monkeypatch.setattr(urllib.request.http.client, "HTTPSConnection",
                        RecordingConnection)
    real = hetzner.ReadOnlyClient(hetzner.Config(token=TOKEN))
    with pytest.raises(hetzner.ProviderError):
        real.fetch_servers()
    assert connected == ["api.hetzner.cloud"], (
        f"the provider read connected to {connected}, not to the API."
        f" Tunnelled to {tunnelled}")
    assert tunnelled == [], (
        f"the provider read tunnelled through a proxy to {tunnelled},"
        " so the API token went to whoever answers there")


def test_the_request_names_itself():
    """An operator reading their provider's audit log should be able to tell
    our reads from anyone else's."""
    opener = opener_for()
    client(opener).fetch_servers()
    agent = opener.requests[0].get_header("User-agent")
    assert agent and "whichports" in agent


def test_naming_ourselves_did_not_disturb_the_authorization_header():
    opener = opener_for()
    client(opener).fetch_servers()
    assert opener.requests[0].get_header("Authorization") == f"Bearer {TOKEN}"


# ============================== the snapshot refreshes itself on the sweep
#
# `docs/RECORD.md` 4.90. Everything from fetch to the screen already existed
# and nothing called it on a schedule, so the provider column read "not
# connected" on every row of every host.

from datetime import datetime, timedelta, timezone  # noqa: E402

REF_NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)


def snapshot_at(when):
    return hetzner.Snapshot(fetched_at=when, servers=(), firewalls=())


def con_with_snapshot(tmp_path, when):
    from app import db
    con = db.connect(str(tmp_path / "cp.db"))
    db.init(con)
    hetzner.init(con)
    if when is not None:
        hetzner.store_snapshot(con, snapshot_at(when))
    return con


def test_no_snapshot_at_all_needs_a_refresh(tmp_path):
    con = con_with_snapshot(tmp_path, None)
    assert hetzner.needs_refresh(con, REF_NOW) is True
    con.close()


def test_a_fresh_snapshot_does_not(tmp_path):
    """Fresh is seconds since 2026-10-03, when every sweep began to read
    (docs/RECORD.md 4.340). Until then this held five minutes as fresh, under
    the hour that entry replaced. tests/test_provider_read_every_sweep.py has
    the other side: five minutes old is read again."""
    con = con_with_snapshot(tmp_path, (REF_NOW - timedelta(seconds=20)).isoformat())
    assert hetzner.needs_refresh(con, REF_NOW) is False
    con.close()


def test_an_old_snapshot_does(tmp_path):
    con = con_with_snapshot(tmp_path, (REF_NOW - timedelta(hours=2)).isoformat())
    assert hetzner.needs_refresh(con, REF_NOW) is True
    con.close()


def test_a_stamp_that_will_not_read_is_refetched_rather_than_guessed(tmp_path):
    """None is its own answer and never silently becomes fresh. Refetching
    costs one GET and guessing wrong costs a wrong answer on a screen."""
    con = con_with_snapshot(tmp_path, "not a date")
    assert hetzner.needs_refresh(con, REF_NOW) is True
    con.close()


def test_a_naive_stamp_is_refetched_too(tmp_path):
    """A stamp with no timezone cannot be compared to an aware clock, and
    assuming UTC would be inventing the thing the field was meant to carry."""
    con = con_with_snapshot(tmp_path, "2026-08-22T11:00:00")
    assert hetzner.needs_refresh(con, REF_NOW) is True
    con.close()


def test_a_database_without_the_table_needs_one(tmp_path):
    from app import db
    con = db.connect(str(tmp_path / "bare.db"))
    db.init(con)
    assert hetzner.needs_refresh(con, REF_NOW) is True
    con.close()


def test_the_age_of_an_unreadable_stamp_is_none_not_zero():
    assert hetzner.snapshot_age_seconds(snapshot_at("nonsense"), REF_NOW) is None
    assert hetzner.snapshot_age_seconds(snapshot_at(None), REF_NOW) is None
